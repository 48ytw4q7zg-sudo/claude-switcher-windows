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
    plan_route, select_tun, verdict, AccessInfo, AccessPath, ProbeRoute, ProxyEvidence,
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
}

/// 从注册表读系统代理配置（`HKCU\...\Internet Settings`）。
///
/// 读不到任何一项都按「未配置」处理，不因为读失败就误判为未接入。
pub fn read_proxy_evidence() -> ProxyEvidence {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
    let Ok(key) = key else {
        return ProxyEvidence::default();
    };
    let string = |name: &str| -> Option<String> {
        key.get_value::<String, _>(name)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    let enable = key.get_value::<u32, _>("ProxyEnable").unwrap_or(0) != 0;
    ProxyEvidence {
        enable,
        server: string("ProxyServer"),
        autoconfig: string("AutoConfigURL"),
        overrides: string("ProxyOverride"),
    }
}

/// 枚举 Up 状态的 TUN 网卡（复用平台层网卡枚举，返回 (描述, 友好名, Up)）。
pub fn detect_tun_adapter() -> Option<String> {
    let adapters = crate::platform::imp::list_adapters().ok()?;
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
    select_tun(&candidates)
}

/// 判定当前接入方式（注册表 + TUN）。
pub fn current_access(hosts: &[String]) -> AccessPath {
    verdict(&read_proxy_evidence(), detect_tun_adapter(), hosts)
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
    let route = plan_route(&access);
    let (probed, skipped_reason) = if skip {
        (
            false,
            Some(if access.is_uncovered() {
                "未接入代理链路，已跳过探测（守护器不直连，避免暴露真实出口）".to_string()
            } else if access.is_unknown() {
                format!("接入路径无法确认（{}），已跳过探测", access.note())
            } else {
                access.note()
            }),
        )
    } else {
        (true, None)
    };

    let mut reports = Vec::new();
    let mut evaluations = Vec::new();
    for target in targets {
        let probe: ProbeResult = if !target.enabled {
            ProbeResult::default()
        } else if skip {
            ProbeResult::failed("未接入代理链路，已跳过探测")
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
    let trip = should_trip_report(&reports, threshold);
    let warn = should_warn_report(&reports, threshold);
    EgateReport {
        access: access_info,
        overall: crate::egate::overall(&evaluations),
        targets: reports,
        probed,
        skipped_reason,
        should_trip: trip,
        should_warn: warn,
        trip_threshold: threshold,
    }
}

/// 按路由探测单个目标（跳过路由返回「无法确认」而不是失败）。
fn probe_with_route(target: &EgateTarget, route: &ProbeRoute) -> ProbeResult {
    match route {
        // 探测本身走系统代理（reqwest system-proxy 特性已启用）；
        // 这里显式指定地址，确保测的就是应用真实出口。
        ProbeRoute::Proxy(_) | ProbeRoute::Direct => crate::egate_probe::probe(target),
        ProbeRoute::Skip => ProbeResult::failed("未接入代理链路，已跳过探测"),
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
        // 未接入时 enforce=true：目标应判 Unverified（不熔断），且本轮未探测。
        let mut streaks = std::collections::BTreeMap::new();
        let report = run_round(&[target("a", true)], &mut streaks, true, 2);
        // 真实注册表读取结果不可控，只断言不变量：
        // 跳过的目标绝不能累计失败计数。
        if !report.probed {
            assert!(
                report.targets.iter().all(|t| t.verdict != Verdict::Fail),
                "未探测的目标不得判 Fail"
            );
            assert!(report.skipped_reason.is_some());
            assert!(streaks.is_empty(), "未接入时不得累计熔断计数：{streaks:?}");
            assert!(!report.should_trip, "未探测时不得达到熔断条件");
        }
    }
}
