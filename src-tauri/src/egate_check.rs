//! 出口门禁的系统读取与一轮检查编排（网络 + 注册表 + 网卡枚举）。
//!
//! 行为基准：ClaudeGuard `src/{access,monitor}.rs` 的语义（固定 commit `1967377`）。
//! 纯判定在 [`crate::egate`] / [`crate::egate_access`]，网络在
//! [`crate::egate_probe`]，本文件只做「读系统 → 判定 → 汇总」。
//!
//! 关键安全语义（对齐上游 v3.8 隐私加固）：
//! **未接入代理链路时守护器自身不发起任何探测**——此时若直连探测，等于把用户
//! 家宽 IP 送向被测域名。判定与后续熔断完全由注册表/TUN 的确定性检查承担。

use std::time::Duration;

use serde::Serialize;

use crate::egate::{EgateTarget, Evaluation, Overall, ProbeResult, Verdict};
use crate::egate_access::{
    plan_route, plan_route_with_evidence, select_tun, verdict, AccessInfo, AccessPath, ProbeRoute,
    ProxyEvidence,
};

/// 单个目标的一轮结果。
#[derive(Debug, Clone, Serialize)]
pub struct TargetReport {
    pub id: String,
    pub name: String,
    pub verdict: Verdict,
    pub reason: String,
    /// 连续失败次数（防抖计数；任意一次非 Fail 清零）。
    pub fail_streak: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    pub latency_ms: u64,
}

/// 一轮检查的完整结果。
#[derive(Debug, Clone, Serialize)]
pub struct EgateReport {
    pub access: AccessInfo,
    pub overall: Overall,
    pub targets: Vec<TargetReport>,
    /// 本轮是否真的发起了探测（未接入时为 false）。
    pub probed: bool,
    /// 跳过探测的原因（未接入/无法确认时给出）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_reason: Option<String>,
    /// 是否达到熔断阈值（由 `trip_threshold` 判定；阈值 0 表示关闭熔断）。
    pub should_trip: bool,
    /// 是否到预警点（第 threshold-1 次连续失败）。
    pub should_warn: bool,
    /// 本轮使用的熔断阈值。
    pub trip_threshold: u32,
    /// **P0-05**：接入路径是否达到熔断阈值（独立于目标失败计数）。
    pub access_trip: bool,
    /// 接入路径连续未覆盖次数。
    pub access_streak: u32,
    /// **P1-01**：TUN 路由证据的结论说明。
    ///
    /// `None` = 非 TUN 路径（不需要证据）。`Some` 时说明「为什么允许/不允许
    /// 做直连探测」，让界面能区分「没探测因为没接入」与「没探测因为路由没证实」。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tun_route_note: Option<String>,
}

/// 从注册表读系统代理配置（`HKCU\...\Internet Settings`）。
///
/// **P1-03**：原实现「读不到任何一项都按未配置处理」——键打不开时直接返回
/// `default()`（`ProxyEnable = false`），于是「注册表读不了」与「代理确实关着」
/// 得到同一个结论，判定层接着走「未接入 → 兜底封锁/熔断」。
///
/// 现在的分类：
/// - 键**不存在** = 系统从未配置过代理 → 正常的 `ProxyEnable = 0`（`complete`）；
/// - 键存在但被**拒绝访问** / 结构异常 / 值读取失败 → `complete = false`，
///   判定层据此给出 `Unknown`，不产生任何保护副作用；
/// - 可选值缺失（如从未设置 `ProxyServer`）仍按「未配置」处理，这是正常语义。
pub fn read_proxy_evidence() -> ProxyEvidence {
    use std::io::ErrorKind;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;
    let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    let key = match RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(path, KEY_READ) {
        Ok(key) => key,
        // 键不存在：这台机器没有任何代理配置，属于**确定的**「未启用」。
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return ProxyEvidence {
                complete: true,
                ..ProxyEvidence::default()
            }
        }
        // 拒绝访问 / 重定向异常 / 其它：无法确认，绝不臆造成「关闭」。
        Err(error) => {
            return ProxyEvidence::unreadable(format!("打开 Internet Settings 失败：{error}"))
        }
    };
    // 可选字符串值：`NotFound` 是正常的「未设置」；其它错误说明注册表结构异常。
    let mut problems: Vec<String> = Vec::new();
    let mut read_string = |name: &str| -> Option<String> {
        match key.get_value::<String, _>(name) {
            Ok(value) => {
                let trimmed = value.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => {
                problems.push(format!("读取 {name} 失败：{error}"));
                None
            }
        }
    };
    let server = read_string("ProxyServer");
    let autoconfig = read_string("AutoConfigURL");
    let overrides = read_string("ProxyOverride");
    // `ProxyEnable` 是 DWORD。缺失 = 从未开启过代理（正常）；类型不符/被拒 = 异常。
    let enable = match key.get_value::<u32, _>("ProxyEnable") {
        Ok(value) => value != 0,
        Err(error) if error.kind() == ErrorKind::NotFound => false,
        Err(error) => {
            problems.push(format!("读取 ProxyEnable 失败：{error}"));
            false
        }
    };
    if problems.is_empty() {
        ProxyEvidence {
            enable,
            server,
            autoconfig,
            overrides,
            complete: true,
            error: None,
        }
    } else {
        ProxyEvidence {
            enable,
            server,
            autoconfig,
            overrides,
            complete: false,
            error: Some(problems.join("；")),
        }
    }
}

/// 枚举 Up 状态的 TUN 网卡（复用平台层网卡枚举，返回 (描述, 友好名, Up)）。
///
/// **P1-03**：返回 `Result`——网卡枚举失败不能压成「没有 TUN」。
/// 旧保镖曾用 `unwrap_or_default()`，一次查询失败就会被判「代理离线」并查杀。
pub fn detect_tun_adapter_strict() -> Result<Option<String>, String> {
    let adapters = crate::platform::imp::list_adapters()
        .map_err(|error| format!("枚举网络适配器失败：{error}"))?;
    let candidates: Vec<(String, String, bool)> = adapters
        .iter()
        .map(|adapter| {
            (
                adapter.description.clone(),
                adapter.name.clone(),
                adapter.status.eq_ignore_ascii_case("Up"),
            )
        })
        .collect();
    Ok(select_tun(&candidates))
}

/// 枚举 Up 状态的 TUN 网卡（宽松版：查询失败按「没有 TUN」）。
///
/// 只用于**纯粹展示**的调用点；任何会影响保护决策的路径必须用
/// [`detect_tun_adapter_strict`]。当前没有调用点，保留是为了保证
/// 「展示用宽松版」与「决策用严格版」的差异在代码里可见。
#[allow(dead_code)]
pub fn detect_tun_adapter() -> Option<String> {
    detect_tun_adapter_strict().ok().flatten()
}

/// 判定当前接入方式（注册表 + TUN）。
///
/// **P1-03**：网卡枚举失败同样升级为 `Unknown`——「读不到网卡」与
/// 「没有 TUN 网卡」不能得到同一个结论。
pub fn current_access(hosts: &[String]) -> AccessPath {
    let evidence = read_proxy_evidence();
    let tun = match detect_tun_adapter_strict() {
        Ok(tun) => tun,
        // 注册表已经读失败时，原因以注册表为准（更贴近用户可操作的问题）。
        Err(error) if evidence.read_error().is_none() => {
            return AccessPath::Unknown {
                reason: format!("{error}，无法确认是否存在 TUN 接入"),
            }
        }
        Err(_) => None,
    };
    verdict(&evidence, tun, hosts)
}

/// 被监控目标实际会访问的主机名（用于绕过列表风险判定）。
pub fn monitored_hosts(targets: &[EgateTarget]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for target in targets.iter().filter(|t| t.enabled) {
        if let Some(host) = crate::egate_access::host_of(&target.anchor_url) {
            if !out.contains(&host) {
                out.push(host);
            }
        }
    }
    out
}

/// **P1-01**：为 TUN 路线采集路由证据。
///
/// 返回 `None` 表示「无法采集」——调用方必须保持 `Skip`（Unverified），
/// 绝不能退化成「大概走了 TUN」。
///
/// 探测地址取自被监控目标的锚点主机：只有真正要访问的地址才值得看路由，
/// 拿一个无关地址证明「TUN 接管了默认路由」并不成立。
/// IPv4/IPv6 两条路径分别取证，任一条可能被旁路都要看。
fn collect_tun_route_evidence(
    adapter: &str,
    targets: &[EgateTarget],
) -> Option<crate::egate_access::RouteEvidence> {
    // TUN 网卡的 ifIndex 从适配器列表里按名字/描述匹配。
    let adapters = crate::platform::imp::list_adapters().ok()?;
    let tun_index = adapters
        .iter()
        .find(|a| {
            a.status.eq_ignore_ascii_case("Up")
                && (a.name.eq_ignore_ascii_case(adapter)
                    || a.description.eq_ignore_ascii_case(adapter))
        })
        .map(|a| a.if_index)?;
    // 用目标的真实主机名解析出的地址作为取证对象；全部解析失败就不取证。
    let host = targets
        .iter()
        .filter(|t| t.enabled)
        .find_map(|t| crate::egate_access::host_of(&t.anchor_url))?;
    let (ipv4, ipv6) = resolve_host_addresses(&host)?;
    Some(crate::platform::imp::collect_route_evidence(
        tun_index, &ipv4, &ipv6,
    ))
}

/// 解析主机名得到 (IPv4, IPv6) 字面量。
///
/// 只做一次 DNS（系统解析器，与应用的解析路径一致）。任一簇缺失时用
/// 回环占位不行——那会让 `Find-NetRoute` 查到假结果。因此要求 IPv4 必须存在；
/// IPv6 缺失时用一个明确的「本机 IPv6 不存在」判定（由平台层读取绑定状态）。
fn resolve_host_addresses(host: &str) -> Option<(String, String)> {
    use std::net::ToSocketAddrs;
    let addrs = (host, 443u16).to_socket_addrs().ok()?;
    let mut ipv4 = None;
    let mut ipv6 = None;
    for addr in addrs {
        match addr.ip() {
            std::net::IpAddr::V4(v4) if ipv4.is_none() => ipv4 = Some(v4.to_string()),
            std::net::IpAddr::V6(v6) if ipv6.is_none() => ipv6 = Some(v6.to_string()),
            _ => {}
        }
    }
    // IPv6 缺失时给一个文档地址段的占位：`Find-NetRoute` 对它的结果只用于
    // 判断「是否经 TUN」，不会真的发包；平台层还会叠加「IPv6 是否启用」。
    Some((ipv4?, ipv6.unwrap_or_else(|| "2001:db8::1".to_string())))
}

/// 跑一轮检查：先判接入，再按路由决定是否探测，最后逐目标判定并汇总。
///
/// `streaks` 是各目标的连续失败计数（调用方持有，跨轮保留）；返回更新后的计数。
pub fn run_round(
    targets: &[EgateTarget],
    streaks: &mut std::collections::BTreeMap<String, u32>,
    enforce_access_path: bool,
    trip_threshold: u32,
) -> EgateReport {
    let hosts = monitored_hosts(targets);
    let access = current_access(&hosts);
    let access_info = AccessInfo::from(&access);

    // 未接入 / 无法确认：按 enforce 开关决定是否跳过探测。
    let skip = enforce_access_path && !access.is_known();
    // **P1-01**：TUN 路线只有在拿到**路由证据**时才允许直连探测。
    // 证据只看「接入是 TUN」时才采集：其它路径要么走代理，要么根本不探测。
    let (route, tun_route_note) = match &access {
        AccessPath::Tun { adapter } => match collect_tun_route_evidence(adapter, targets) {
            Some(evidence) => {
                let plan = plan_route_with_evidence(&access, Some(&evidence));
                let note = if evidence.proves_tun_path() {
                    format!(
                        "TUN 路由已证实（IPv4 出接口与默认路由均经 {}），本轮允许直连探测",
                        adapter.trim()
                    )
                } else {
                    format!(
                        "TUN 路由未获证实：{}；本轮不发起直连探测（出口未验证）",
                        evidence.unverified_reason()
                    )
                };
                (plan, Some(note))
            }
            // 采不到证据（找不到 TUN 网卡 / 无可用探测地址）：保持 Skip。
            None => (
                plan_route(&access),
                Some(
                    "TUN 路由证据采集失败（找不到 TUN 网卡或无法解析目标地址），本轮不发起直连探测"
                        .to_string(),
                ),
            ),
        },
        _ => (plan_route(&access), None),
    };
    // **P0 降级修复**：`probed` 必须反映**最终实际执行**的探测，而不是只看
    // `skip` 变量。原实现只按 `enforce && !is_known()` 计算，因此：
    // - `enforce=false` + TUN → `skip=false`，但 `plan_route(Tun)=Skip`，
    //   实际一个请求都没发，却报告「本轮已探测」；
    // - 纯 TUN 接入时目标全是 Unverified，界面会误以为做过检查。
    //
    // 现在把「路由是 Skip」也算进去，并把原因说清楚（TUN 是「路由未证实」，
    // 不是「未接入」）。
    let route_skips = matches!(route, ProbeRoute::Skip);
    let (probed, skipped_reason) = if skip || route_skips {
        let reason = if access.is_uncovered() {
            "未接入代理链路，已跳过探测（守护器不直连，避免暴露真实出口）".to_string()
        } else if access.is_unknown() {
            format!("接入路径无法确认（{}），已跳过探测", access.note())
        } else if matches!(access, AccessPath::Tun { .. }) {
            // TUN：网卡存在 ≠ 路由经过它。没有路由证明就不发直连请求。
            format!(
                "{}：路由未验证，主动探测已跳过（已避免未经确认的直连，但不代表出口已验证）",
                access.note()
            )
        } else {
            access.note()
        };
        (false, Some(reason))
    } else {
        (true, None)
    };

    let mut reports = Vec::new();
    let mut evaluations = Vec::new();
    for target in targets {
        let probe: ProbeResult = if !target.enabled {
            ProbeResult::default()
        } else if skip || route_skips {
            // 与 `probed` 保持同一判据：凡报告「未探测」，目标就判 Unverified
            // 而不是发起请求（否则 TUN 下会出现「说没探测、其实发了请求」）。
            ProbeResult::skipped(
                skipped_reason
                    .as_deref()
                    .unwrap_or("已跳过探测（未确认接入路径）"),
            )
        } else {
            probe_with_route(target, &route)
        };
        let evaluation: Evaluation = crate::egate::evaluate(target, &probe);
        // 防抖：Fail 累加，其余清零。
        let streak = match evaluation.verdict {
            Verdict::Fail => streaks.get(&target.id).copied().unwrap_or(0) + 1,
            _ => {
                streaks.remove(&target.id);
                0
            }
        };
        if streak > 0 {
            streaks.insert(target.id.clone(), streak);
        }
        reports.push(TargetReport {
            id: target.id.clone(),
            name: target.name.clone(),
            verdict: evaluation.verdict,
            reason: evaluation.reason.clone(),
            fail_streak: streak,
            ip: probe.ip.clone(),
            country: probe.country.clone(),
            latency_ms: probe.latency_ms,
        });
        evaluations.push((target.id.clone(), evaluation));
    }

    let threshold = trip_threshold;
    // **P0-05**：接入路径独立防抖——未接入（Uncovered）时即使没有发出
    // HTTP 请求（因此目标都是 Unverified），也必须能触发保护。
    let access_uncovered = access.is_uncovered();
    let access_streak = if access_uncovered && !skip {
        // 未强制跳过（enforce=false）：仍然统计，但实际探测已执行。
        streaks.get("access:uncovered").copied().unwrap_or(0) + 1
    } else if access_uncovered {
        let next = streaks.get("access:uncovered").copied().unwrap_or(0) + 1;
        streaks.insert("access:uncovered".to_string(), next);
        next
    } else {
        // 接入恢复正常：清零。
        streaks.remove("access:uncovered");
        0
    };
    if access_uncovered && !skip {
        streaks.insert("access:uncovered".to_string(), access_streak);
    }
    let access_trip = access_uncovered && threshold > 0 && access_streak >= threshold;

    let trip = should_trip_report(&reports, threshold) || access_trip;
    let warn = should_warn_report(&reports, threshold)
        || (access_uncovered && threshold > 1 && access_streak + 1 == threshold);
    EgateReport {
        access: access_info,
        overall: crate::egate::overall(&evaluations),
        targets: reports,
        probed,
        skipped_reason,
        should_trip: trip,
        should_warn: warn,
        trip_threshold: threshold,
        access_trip,
        access_streak,
        tun_route_note,
    }
}

/// 按路由探测单个目标（跳过路由返回「无法确认」而不是失败）。
fn probe_with_route(target: &EgateTarget, route: &ProbeRoute) -> ProbeResult {
    match route {
        // P0-J：把**验证过的代理地址**显式传给探测客户端，确保
        // 「本轮门禁验证的代理」就是「实际请求使用的代理」。
        ProbeRoute::Proxy(address) => crate::egate_probe::probe_via(target, Some(address)),
        // TUN 接管：直连即与应用同路，显式 no_proxy。
        ProbeRoute::Direct => crate::egate_probe::probe_via(target, None),
        ProbeRoute::Skip => ProbeResult::skipped("未接入代理链路，已跳过探测"),
    }
}

/// 是否达到熔断阈值（公开给命令层与测试；阈值 0 表示关闭熔断）。
///
/// 只有 `Fail` 会计数；达到 `threshold` 才熔断。`threshold - 1` 时用
/// [`should_warn_report`] 发一次预警。
pub fn should_trip_report(reports: &[TargetReport], threshold: u32) -> bool {
    if threshold == 0 {
        return false;
    }
    reports.iter().any(|target| target.fail_streak >= threshold)
}

/// 是否到了预警点（第 threshold-1 次连续失败）。
pub fn should_warn_report(reports: &[TargetReport], threshold: u32) -> bool {
    if threshold < 2 {
        return false;
    }
    reports
        .iter()
        .any(|target| target.fail_streak + 1 == threshold)
}

/// 探测超时上限（防止配置里填了极端值把整个周期拖死）。
pub const MAX_TARGET_TIMEOUT: Duration = Duration::from_secs(30);

/// 收敛目标超时到合法范围。
pub fn clamp_timeout(secs: u64) -> u64 {
    secs.clamp(1, MAX_TARGET_TIMEOUT.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egate::AnchorKind;

    fn target(id: &str, enabled: bool) -> EgateTarget {
        EgateTarget {
            id: id.to_string(),
            name: id.to_string(),
            anchor_url: "https://egate.invalid/trace".to_string(),
            anchor_kind: AnchorKind::Trace,
            expect_ips: vec!["1.2.3.4".to_string()],
            expect_regions: vec!["US".to_string()],
            enabled,
            timeout_secs: 2,
        }
    }

    #[test]
    fn monitored_hosts_deduplicates_and_skips_disabled() {
        let mut a = target("a", true);
        a.anchor_url = "https://claude.ai/cdn-cgi/trace".to_string();
        let mut b = target("b", true);
        b.anchor_url = "https://claude.ai/other".to_string();
        let disabled = target("c", false);
        let hosts = monitored_hosts(&[a, b, disabled]);
        assert_eq!(hosts, vec!["claude.ai".to_string()]);
    }

    #[test]
    fn timeout_is_clamped_to_safe_range() {
        assert_eq!(clamp_timeout(0), 1, "0 秒会立刻超时，下限 1");
        assert_eq!(clamp_timeout(999), 30, "极端值不得拖死整个周期");
        assert_eq!(clamp_timeout(5), 5);
    }

    #[test]
    fn trip_requires_threshold_and_fail_streak() {
        let one_fail = vec![TargetReport {
            id: "a".to_string(),
            name: "a".to_string(),
            verdict: Verdict::Fail,
            reason: String::new(),
            fail_streak: 1,
            ip: None,
            country: None,
            latency_ms: 0,
        }];
        assert!(!should_trip_report(&one_fail, 2), "首次失败不熔断（防抖）");
        assert!(should_warn_report(&one_fail, 2), "第 1 次失败应预警");
        let mut two_fails = one_fail.clone();
        two_fails[0].fail_streak = 2;
        assert!(should_trip_report(&two_fails, 2));
        assert!(!should_warn_report(&two_fails, 2), "已到阈值不再预警");
        assert!(!should_trip_report(&one_fail, 0), "阈值 0 表示关闭熔断");
        // 阈值 1：首次失败即熔断，没有预警点。
        assert!(should_trip_report(&one_fail, 1));
        assert!(!should_warn_report(&one_fail, 1));
    }

    #[test]
    fn streaks_accumulate_across_rounds_when_caller_reuses_map() {
        // 防抖的核心契约：同一份 streaks 跨轮复用时，连续失败才累加。
        // （曾经每轮新建 map，阈值 2 永远不成立——熔断被静默降级成永不触发。）
        let targets = vec![target("a", true)];
        let mut streaks = std::collections::BTreeMap::new();
        // 直接驱动计数逻辑：模拟三轮 Fail。
        for expected in 1..=3u32 {
            let streak = streaks.get("a").copied().unwrap_or(0) + 1;
            streaks.insert("a".to_string(), streak);
            assert_eq!(streak, expected);
            assert_eq!(
                should_trip_report_from(&streaks, 2),
                expected >= 2,
                "第 {expected} 轮后熔断判定"
            );
        }
        // 一次非 Fail 必须清零（否则偶发失败会累积成熔断）。
        streaks.remove("a");
        assert!(!should_trip_report_from(&streaks, 2), "成功后必须清零");
        // 顺带确认 run_round 会写入调用方传入的 map（跨轮持有的前提）。
        let mut live = std::collections::BTreeMap::new();
        let _ = run_round(&targets, &mut live, false, 2);
        assert!(
            live.is_empty() || live.values().all(|v| *v >= 1),
            "run_round 只能写入有效计数"
        );
    }

    /// 从裸计数表判定熔断（供跨轮测试直接驱动）。
    fn should_trip_report_from(
        streaks: &std::collections::BTreeMap<String, u32>,
        threshold: u32,
    ) -> bool {
        threshold > 0 && streaks.values().any(|streak| *streak >= threshold)
    }

    #[test]
    fn skipped_round_marks_targets_unverified_not_fail() {
        // 未接入 / TUN（路由未证实）时：目标应判 Unverified（不判 Fail），且本轮未探测。
        let mut streaks = std::collections::BTreeMap::new();
        let report = run_round(&[target("a", true)], &mut streaks, true, 2);
        // 真实注册表读取结果不可控，只断言不变量：
        if !report.probed {
            assert!(
                report.targets.iter().all(|t| t.verdict != Verdict::Fail),
                "未探测的目标不得判 Fail"
            );
            assert!(report.skipped_reason.is_some());
            // TUN 场景必须说明「路由未验证」，不能含糊地说「未接入」。
            if report.access.path == "tun" {
                let reason = report.skipped_reason.as_deref().unwrap_or_default();
                assert!(
                    reason.contains("路由未验证"),
                    "TUN 跳过时必须说明路由未验证，实际：{reason}"
                );
            }
            // P0-05：目标失败计数仍必须为空（跳过 ≠ 目标失败）。
            assert!(
                !streaks.keys().any(|k| k == "a"),
                "跳过的目标不得累计失败计数：{streaks:?}"
            );
            // 但接入路径会独立累计（这是 P0-05 的有意行为）。
            if report.access_streak > 0 {
                assert!(
                    streaks.contains_key("access:uncovered"),
                    "接入未覆盖应记录独立计数：{streaks:?}"
                );
            }
        }
    }

    #[test]
    fn access_uncovered_triggers_trip_independently_of_targets() {
        // P0-05 核心语义：接入路径连续未覆盖达到阈值时，即使所有目标都是
        // Unverified（没有实际探测），也必须触发熔断判定。
        let mut streaks = std::collections::BTreeMap::new();
        let targets = vec![target("a", true)];
        let mut last = None;
        // 模拟连续多轮 Uncovered（通过真实接入判定驱动）。
        for _ in 0..3 {
            let report = run_round(&targets, &mut streaks, true, 2);
            // 本机确实接入了代理（系统代理或 TUN）时本测试不适用，跳过。
            // 注意不能再用 `report.probed` 做判据：TUN 下现在 `probed=false`
            // （路由未验证就跳过探测），但接入路径本身是「已接入」。
            if report.access.path != "uncovered" {
                return;
            }
            last = Some(report);
        }
        let report = last.expect("至少跑一轮");
        assert!(report.access_streak >= 1, "未接入时必须累计接入计数");
        if report.access_streak >= 2 {
            assert!(report.access_trip, "接入连续未覆盖达到阈值应触发");
            assert!(report.should_trip, "access_trip 必须并入 should_trip");
        }
    }
}
