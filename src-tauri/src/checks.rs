//! 14 项安全检查（checkdetail）、静默总检（check）与一键修复（fix）。
//!
//! 行为基准（与上游逐行对照）：
//! - `core/claude-switch.sh` 的 `check()`（静默总检，输出 N/14）与 `checkdetail()`
//!   （逐项 `名称=ok|warn|fail:细节`）；
//! - `windows/claude-switch.ps1` 对应段落；上游 fix() 的步骤顺序：
//!   拉起内核+TUN →（必要时恢复 verge.yaml `enable_tun_mode` 并重启）→
//!   锁时区 → 关 IPv6 → 写/清置顶规则 → 重注册保镖 → 复测。
//!
//! 设计约定：
//! - 每项检查的「判定」拆成纯函数（输入探测结果，输出 `(status, detail)`），
//!   不做任何 IO，便于表驱动单测；`run_checks_blocking` 只负责收集真实数据并拼装。
//! - 所有阻塞调用（网络、PowerShell、进程枚举）只出现在 `*_blocking` 函数内，
//!   由调用方经 Tauri `blocking(...)` 调度。
//! - 状态三值：`ok` / `warn` / `fail`；fail 数为 0 即 `passed`（N/14）。

use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;

use crate::appconfig::{self, AppConfig};
use crate::egress::{self, EgressInfo};
use crate::fsx;
use crate::guard;
use crate::jsonio;
use crate::net;
use crate::paths;
use crate::platform::imp;
use crate::platform::imp::AdapterInfo;
use crate::rules::{self, WebRtcPolicy};
use crate::store;
use crate::stun::{self, StunResult};

// ────────────────────────── 输出结构 ──────────────────────────

/// 单项检查结果（前端安检仪表盘直接消费）。
#[derive(Debug, Clone, Serialize)]
pub struct CheckItem {
    /// 1..=14，固定序号。
    pub id: u32,
    /// 机器可读键名（proxy_core / tun / ...）。
    pub key: String,
    /// 人话名称（代理内核 / TUN网卡 / ...）。
    pub name: String,
    /// `ok` / `warn` / `fail`。
    pub status: String,
    /// 人话详情。
    pub detail: String,
}

/// 静默总检（对齐上游 `check` 的 N/14）。
#[derive(Debug, Clone, Serialize)]
pub struct ChecksSummary {
    pub total: u32,
    pub ok: u32,
    pub warn: u32,
    pub fail: u32,
    /// fail == 0。
    pub passed: bool,
}

/// 一键修复的单步结果。
#[derive(Debug, Clone, Serialize)]
pub struct FixStep {
    pub name: String,
    /// `ok` / `warn` / `fail`。
    pub status: String,
    pub detail: String,
}

/// 一键修复完整报告：每步结果 + 复测汇总 + 复测逐项明细。
#[derive(Debug, Clone, Serialize)]
pub struct FixReport {
    pub steps: Vec<FixStep>,
    pub summary: ChecksSummary,
    pub checks: Vec<CheckItem>,
}

// ────────────────────────── 纯判定函数 ──────────────────────────
//
// 每个 judge 函数只吃数据、吐 `(status, detail)`，不碰系统/网络。

/// 1. 代理内核：proxy_mode 对应进程是否在线（auto/other 不查进程）。
fn judge_proxy_core(mode: &str, alive: bool) -> (&'static str, String) {
    if matches!(mode, "auto" | "other") {
        return ("ok", format!("{mode}：不检查特定进程，仅依赖 TUN"));
    }
    if alive {
        ("ok", format!("{mode} 内核进程在线"))
    } else {
        ("fail", format!("{mode} 内核进程未运行，请先启动代理客户端"))
    }
}

/// 2. TUN 网卡：复用 `guard::tun_status_from_adapters`（198.18 假IP段优先）。
fn judge_tun(adapters: Result<&[AdapterInfo], &str>) -> (&'static str, String) {
    match adapters {
        Err(e) => ("fail", format!("网卡查询失败：{e}")),
        Ok(list) => {
            let (up, detail) = guard::tun_status_from_adapters(list);
            if up {
                ("ok", detail.to_string())
            } else {
                ("fail", "不在线".to_string())
            }
        }
    }
}

/// 3. 出口 IP：国家与 appconfig.country_target 一致。
fn judge_egress_country(
    egress: Option<&EgressInfo>,
    target: Option<&str>,
) -> (&'static str, String) {
    let Some(e) = egress else {
        return (
            "fail",
            "无法获取出口 IP（cloudflare/ipinfo 探测均失败）".to_string(),
        );
    };
    match target {
        Some(t) if !t.is_empty() => {
            if e.country.eq_ignore_ascii_case(t) {
                ("ok", format!("{}/{}", e.ip, e.country))
            } else {
                ("fail", format!("{}/{}（期望 {}）", e.ip, e.country, t))
            }
        }
        _ => (
            "warn",
            format!("当前 {}/{}（未锁定目标国家）", e.ip, e.country),
        ),
    }
}

/// 4. IP 一致：当前出口 IP 与 appconfig.last_egress_ip 比对（缺失即首次记录）。
fn judge_ip_consistency(current: Option<&str>, last: Option<&str>) -> (&'static str, String) {
    let Some(cur) = current else {
        return ("fail", "未获取到出口 IP".to_string());
    };
    match last {
        None => ("ok", "首次记录".to_string()),
        Some(last) if last == cur => ("ok", "与上次一致".to_string()),
        Some(last) => ("warn", format!("{last} → {cur}")),
    }
}

/// 5. 时区：Windows 时区 ID 与 appconfig.tz_target（忽略大小写）。
fn judge_timezone(current: Result<&str, &str>, target: Option<&str>) -> (&'static str, String) {
    match current {
        Err(e) => ("fail", format!("读取时区失败：{e}")),
        Ok(cur) => match target {
            Some(t) if !t.is_empty() => {
                if cur.eq_ignore_ascii_case(t) {
                    ("ok", format!("时区 {cur}"))
                } else {
                    ("fail", format!("{cur}（期望 {t}）"))
                }
            }
            _ => ("warn", format!("当前时区 {cur}（未锁定目标时区）")),
        },
    }
}

/// 6. 地区：区域格式（culture）与 appconfig.locale_target（按出口动态，不固定 en-US）。
fn judge_culture(current: Result<&str, &str>, target: Option<&str>) -> (&'static str, String) {
    match current {
        Err(e) => ("fail", format!("读取区域格式失败：{e}")),
        Ok(cur) => match target {
            Some(t) if !t.is_empty() => {
                if cur.eq_ignore_ascii_case(t) {
                    ("ok", format!("区域格式 {cur}"))
                } else {
                    ("fail", format!("{cur}（期望 {t}）"))
                }
            }
            _ => ("warn", format!("当前区域格式 {cur}（未锁定目标地区）")),
        },
    }
}

/// 7. IPv6：全部网卡 ms_tcpip6 绑定均 disabled。
fn judge_ipv6(bindings: Result<&[(String, bool)], &str>) -> (&'static str, String) {
    match bindings {
        Err(e) => ("fail", format!("IPv6 绑定查询失败：{e}")),
        Ok(list) => {
            if list.is_empty() {
                return ("warn", "未查询到网卡 IPv6 绑定信息".to_string());
            }
            let enabled: Vec<&str> = list
                .iter()
                .filter(|(_, en)| *en)
                .map(|(name, _)| name.as_str())
                .collect();
            if enabled.is_empty() {
                ("ok", "全部网卡已禁用 IPv6".to_string())
            } else {
                ("fail", format!("仍启用：{}", enabled.join("、")))
            }
        }
    }
}

/// 8. DNS：解析 claude.ai，任一结果落在 198.18.x 假IP段即走隧道；注入假列表即可单测。
fn judge_dns(resolved: Result<&[String], &str>) -> (&'static str, String) {
    match resolved {
        Err(e) => ("fail", format!("解析 claude.ai 失败：{e}")),
        Ok(ips) => {
            if ips.is_empty() {
                return ("fail", "未走隧道（解析结果为空）".to_string());
            }
            if ips.iter().any(|ip| ip.starts_with("198.18.")) {
                ("ok", format!("走隧道（{}）", ips[0]))
            } else {
                ("fail", format!("未走隧道（{}）", ips.join("、")))
            }
        }
    }
}

/// 9. WebRTC：STUN 探针结果。leaks→fail；无响应→warn（保守，不视为零暴露）。
fn judge_webrtc(result: Option<&StunResult>) -> (&'static str, String) {
    match result {
        None => ("warn", "未获取出口 IP，跳过 WebRTC 验证".to_string()),
        Some(r) if r.leaks => (
            "fail",
            format!(
                "暴露非代理 IP：探测到 {}（出口应为 {}）",
                r.probed_ip.as_deref().unwrap_or("未知"),
                r.egress_ip
            ),
        ),
        Some(r) if r.error.is_some() => (
            "warn",
            format!(
                "UDP 无响应，无法验证（{}）",
                r.error.as_deref().unwrap_or("")
            ),
        ),
        Some(r) => ("ok", format!("仅暴露代理出口 IP（{}）", r.egress_ip)),
    }
}

/// 10. 保镖：ClaudeBodyguard 计划任务是否已注册。
fn judge_guard(installed: bool) -> (&'static str, String) {
    if installed {
        (
            "ok",
            "计划任务 ClaudeBodyguard 已注册（登录时自动启动）".to_string(),
        )
    } else {
        ("fail", "保镖未安装".to_string())
    }
}

/// 11. 规则置顶的判定结果（由 `evaluate_rules` 结合真实模式/内核验证产出）。
enum RulesCheck {
    /// global / direct：规则不适用。
    ModeGlobalDirect,
    /// rule 模式且内核 /rules 验证通过。
    Verified,
    /// rule 模式但内核规则未验证通过（fail）。
    VerifyFailed(String),
    /// 控制接口不可用 / 未配置代理组（warn）。
    ApiUnavailable(String),
    /// 无法识别模式（warn；非 Clash 客户端请自行置顶）。
    UnknownMode,
}

/// 11. 规则置顶判定。
fn judge_rules_pinned(mode: &str, outcome: RulesCheck) -> (&'static str, String) {
    match outcome {
        RulesCheck::ModeGlobalDirect => {
            ("ok", format!("{mode} 模式（全部流量走代理，规则不适用）"))
        }
        RulesCheck::Verified => ("ok", "内核已加载置顶规则".to_string()),
        RulesCheck::VerifyFailed(e) => ("fail", format!("运行规则未验证：{e}")),
        RulesCheck::ApiUnavailable(e) => ("warn", format!("控制接口不可用：{e}")),
        RulesCheck::UnknownMode => (
            "warn",
            "无法识别 Clash 模式；非 Clash Verge 客户端请在客户端内自行置顶 Claude 域名规则"
                .to_string(),
        ),
    }
}

/// 12. 客户端语言：跟随系统区域格式；锁定 locale_target 后须与之一致。
fn judge_client_language(
    culture: Result<&str, &str>,
    locale_target: Option<&str>,
) -> (&'static str, String) {
    match culture {
        Err(e) => ("warn", format!("读取系统语言失败：{e}")),
        Ok(cur) => match locale_target {
            Some(t) if !t.is_empty() => {
                if cur.eq_ignore_ascii_case(t) {
                    ("ok", format!("跟随系统（{cur}）"))
                } else {
                    ("fail", format!("系统界面语言为 {cur}，与目标 {t} 不一致"))
                }
            }
            _ => {
                if cur.to_lowercase().starts_with("en") {
                    ("ok", format!("跟随系统（英文 {cur}）"))
                } else {
                    (
                        "warn",
                        format!("当前系统界面语言为 {cur}（未锁定目标地区）"),
                    )
                }
            }
        },
    }
}

/// 13. ASN 属性：org 为空→warn；命中机房启发式→warn；否则住宅 ok。
fn judge_asn(org: Option<&str>) -> (&'static str, String) {
    match org {
        None => ("warn", "未获取 ASN/组织信息".to_string()),
        Some(org) if egress::is_datacenter_org(org) => ("warn", format!("疑似机房/专线（{org}）")),
        Some(org) => ("ok", format!("住宅/宽带（{org}）")),
    }
}

/// 14. 生态可达性的单次 HTTP 探测结果。
enum Reach {
    Code(u16),
    Failed(String),
}

/// 14. 生态可达性：200/401/403 等任何 HTTP 状态码都算可达，网络失败→fail。
fn judge_ecosystem(claude: &Reach, api: &Reach) -> (&'static str, String) {
    let render = |r: &Reach| match r {
        Reach::Code(c) => c.to_string(),
        Reach::Failed(e) => format!("失败({e})"),
    };
    match (claude, api) {
        (Reach::Code(_), Reach::Code(_)) => (
            "ok",
            format!("claude.ai:{} api:{}", render(claude), render(api)),
        ),
        _ => (
            "fail",
            format!("claude.ai:{} api:{}", render(claude), render(api)),
        ),
    }
}

// ────────────────────────── 数据收集（IO） ──────────────────────────

fn build_item(
    id: u32,
    key: &str,
    name: &str,
    (status, detail): (&'static str, String),
) -> CheckItem {
    CheckItem {
        id,
        key: key.to_string(),
        name: name.to_string(),
        status: status.to_string(),
        detail,
    }
}

/// 解析 claude.ai 的全部 IPv4（走系统解析器；TUN 接管后假IP段 198.18.x 即命中）。
fn resolve_claude_ai() -> Result<Vec<String>, String> {
    use std::net::ToSocketAddrs;
    let addrs = ("claude.ai", 443)
        .to_socket_addrs()
        .map_err(|e| format!("DNS 查询失败: {e}"))?;
    Ok(addrs.map(|a| a.ip().to_string()).collect())
}

/// 结合真实模式与内核验证，产出规则置顶判定。
fn evaluate_rules(cfg: &AppConfig) -> RulesCheck {
    let mode = match rules::clash_mode() {
        Ok(m) => m,
        Err(_) => return RulesCheck::UnknownMode,
    };
    match mode.as_str() {
        "global" | "direct" => RulesCheck::ModeGlobalDirect,
        "rule" => {
            let group = effective_proxy_group(cfg);
            if group.trim().is_empty() {
                return RulesCheck::ApiUnavailable("未配置代理组".to_string());
            }
            let policy = WebRtcPolicy::parse(cfg.webrtc_policy.as_deref());
            match net::clash_api("GET", "/rules", None) {
                Ok(rules_json) => {
                    match rules::verify_pinned_rules(&rules_json, group.trim(), policy) {
                        Ok(()) => RulesCheck::Verified,
                        Err(e) => RulesCheck::VerifyFailed(e),
                    }
                }
                Err(e) => RulesCheck::ApiUnavailable(e),
            }
        }
        _ => RulesCheck::UnknownMode,
    }
}

/// 实际生效的代理组名：`appconfig.proxy_group` 优先，未配置时回落到默认组
/// （与 CLI 切节点、Script.js 写入用同一个常量，三处必须一致）。
fn effective_proxy_group(cfg: &AppConfig) -> String {
    cfg.proxy_group
        .as_deref()
        .filter(|g| !g.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| store::DEFAULT_CLASH_GROUP.to_string())
}

/// 探测 claude.ai 与 api.anthropic.com 的可达性（阻塞，约 8s 超时）。
fn probe_ecosystem() -> (Reach, Reach) {
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("客户端初始化失败: {e}");
            return (Reach::Failed(msg.clone()), Reach::Failed(msg));
        }
    };
    let one = |url: &str| match client.get(url).send() {
        Ok(resp) => Reach::Code(resp.status().as_u16()),
        Err(e) => Reach::Failed(e.to_string()),
    };
    (
        one("https://claude.ai/"),
        one("https://api.anthropic.com/v1/models"),
    )
}

// ────────────────────────── 对外主入口 ──────────────────────────

/// 运行全部 14 项检查（阻塞，必须经 Tauri `blocking(...)` 调用）。
pub fn run_checks_blocking() -> Vec<CheckItem> {
    let cfg = appconfig::load();
    let mode = cfg
        .proxy_mode
        .clone()
        .unwrap_or_else(|| "clash-verge".to_string());

    // —— 一次性收集真实数据 ——
    let adapters = imp::list_adapters();
    let egress = egress::detect_egress_blocking();
    let tz = imp::current_timezone_id();
    let culture = imp::current_culture();
    let bindings = imp::ipv6_bindings();
    let dns = resolve_claude_ai();
    let stun_result = match &egress {
        Ok(e) => {
            // STUN 探针只解析 IPv4 MAPPED-ADDRESS：出口是 IPv6 时，任何 IPv4
            // 响应都必然"不等于"IPv6 出口，会被误判成泄漏（假 fail）。
            // 这种场景跳过探测，交给 WebRTC 检查明确说明未验证。
            if e.ip.contains(':') {
                None
            } else {
                Some(stun::probe_stun_leak(&e.ip, 2000))
            }
        }
        Err(_) => None,
    };
    let guard_installed = guard::guard_installed();
    let rules_outcome = evaluate_rules(&cfg);
    let (ecosystem_claude, ecosystem_api) = probe_ecosystem();

    // —— 逐项拼装（判定纯函数不做 IO）——
    let items = vec![
        build_item(
            1,
            "proxy_core",
            "代理内核",
            judge_proxy_core(&mode, guard::client_alive(&mode)),
        ),
        build_item(
            2,
            "tun",
            "TUN网卡",
            judge_tun(adapters.as_deref().map_err(|e| e.as_str())),
        ),
        build_item(
            3,
            "egress_country",
            "出口IP",
            judge_egress_country(egress.as_ref().ok(), cfg.country_target.as_deref()),
        ),
        build_item(
            4,
            "ip_consistency",
            "IP一致",
            judge_ip_consistency(
                egress.as_ref().ok().map(|e| e.ip.as_str()),
                cfg.last_egress_ip.as_deref(),
            ),
        ),
        build_item(
            5,
            "timezone",
            "时区",
            judge_timezone(
                tz.as_deref().map_err(|e| e.as_str()),
                cfg.tz_target.as_deref(),
            ),
        ),
        build_item(
            6,
            "culture",
            "地区",
            judge_culture(
                culture.as_deref().map_err(|e| e.as_str()),
                cfg.locale_target.as_deref(),
            ),
        ),
        build_item(
            7,
            "ipv6",
            "IPv6",
            judge_ipv6(bindings.as_deref().map_err(|e| e.as_str())),
        ),
        build_item(
            8,
            "dns",
            "DNS",
            judge_dns(dns.as_deref().map_err(|e| e.as_str())),
        ),
        build_item(
            9,
            "webrtc",
            "WebRTC",
            match stun_result.as_ref() {
                Some(result) => judge_webrtc(Some(result)),
                // 出口是 IPv6：STUN 探针只解析 IPv4，比对必然不等——不能当成泄漏。
                None if egress.as_ref().is_ok_and(|e| e.ip.contains(':')) => (
                    "warn",
                    "出口为 IPv6，STUN 探针只比对 IPv4，未验证 WebRTC 泄漏".to_string(),
                ),
                None => judge_webrtc(None),
            },
        ),
        build_item(10, "guard", "保镖", judge_guard(guard_installed)),
        build_item(
            11,
            "rules_pinned",
            "规则置顶",
            judge_rules_pinned(
                &rules::clash_mode().unwrap_or_else(|_| "unknown".to_string()),
                rules_outcome,
            ),
        ),
        build_item(
            12,
            "client_language",
            "客户端语言",
            judge_client_language(
                culture.as_deref().map_err(|e| e.as_str()),
                cfg.locale_target.as_deref(),
            ),
        ),
        build_item(
            13,
            "asn",
            "ASN属性",
            judge_asn(egress.as_ref().ok().and_then(|e| e.org.as_deref())),
        ),
        build_item(
            14,
            "ecosystem",
            "生态可达性",
            judge_ecosystem(&ecosystem_claude, &ecosystem_api),
        ),
    ];

    // 与上游一致：每次检查后把最新出口 IP 写入 lastip（供下次「IP一致」比对）。
    if let Ok(e) = &egress {
        let _ = appconfig::update(|c| c.last_egress_ip = Some(e.ip.clone()));
    }

    items
}

/// 由检查明细汇总（N/14）。
pub fn check_summary(items: &[CheckItem]) -> ChecksSummary {
    let mut ok = 0u32;
    let mut warn = 0u32;
    let mut fail = 0u32;
    for item in items {
        match item.status.as_str() {
            "ok" => ok += 1,
            "warn" => warn += 1,
            _ => fail += 1,
        }
    }
    ChecksSummary {
        total: items.len() as u32,
        ok,
        warn,
        fail,
        passed: fail == 0,
    }
}

// ────────────────────────── 一键修复 ──────────────────────────

fn step(name: &str, status: &str, detail: impl Into<String>) -> FixStep {
    FixStep {
        name: name.to_string(),
        status: status.to_string(),
        detail: detail.into(),
    }
}

/// 当前 TUN 是否在线（list_adapters 失败按不在线）。
fn tun_up_now() -> bool {
    imp::list_adapters()
        .map(|list| guard::tun_status_from_adapters(&list).0)
        .unwrap_or(false)
}

/// 轮询等待内核进程 + TUN 同时在线，最多 `secs` 秒。
fn wait_for_tun_and_client(mode: &str, secs: u64) -> bool {
    for _ in 0..secs {
        if guard::client_alive(mode) && tun_up_now() {
            return true;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    false
}

/// 从常见安装位置无窗口拉起 Clash Verge，返回 exe 路径。
fn launch_clash_verge() -> Result<String, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    for var in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        if let Some(root) = std::env::var_os(var) {
            let root = PathBuf::from(root);
            candidates.push(root.join("Clash Verge\\Clash Verge.exe"));
            candidates.push(root.join("Clash Verge Rev\\Clash Verge.exe"));
            candidates.push(root.join("Programs\\clash-verge\\Clash Verge.exe"));
        }
    }
    for candidate in candidates {
        if candidate.exists() {
            imp::start_detached(&candidate.to_string_lossy(), &[])?;
            return Ok(candidate.to_string_lossy().to_string());
        }
    }
    Err("未找到 Clash Verge 可执行文件，请手动启动".to_string())
}

/// 若 verge.yaml 中 `enable_tun_mode: false`，改为 true、杀 GUI 后重新拉起。
/// 返回 Ok(true) 表示确实执行了恢复动作。
fn reenable_tun_mode() -> Result<bool, String> {
    let base = paths::clash_verge_dir()?;
    let verge = base.join("verge.yaml");
    if !verge.exists() {
        return Ok(false);
    }
    let text = jsonio::read_text_lossy_bom(&verge)?;
    if !text.contains("enable_tun_mode: false") {
        return Ok(false);
    }
    let new_text = text.replace("enable_tun_mode: false", "enable_tun_mode: true");
    fsx::write_atomically(&verge, &new_text).map_err(|e| format!("写入 verge.yaml 失败: {e}"))?;
    // 进程名必须匹配真实形态：GUI 的 ProcessName 是 "Clash Verge"（带空格，
    // exe 名 Clash Verge.exe），内核是 verge-mihomo。早期只杀不存在的
    // "clash-verge"，重启是 no-op，改完的开关永远不会被加载。
    let _ = imp::kill_processes_by_names(&["Clash Verge", "clash-verge", "verge-mihomo"]);
    std::thread::sleep(Duration::from_secs(2));
    let _ = launch_clash_verge();
    Ok(true)
}

/// 修复步骤 A：拉起 Clash Verge → 等内核+TUN → 必要时恢复 TUN 开关并重启。
fn fix_launch_and_tun(mode: &str, steps: &mut Vec<FixStep>) {
    if !guard::client_alive(mode) && mode == "clash-verge" {
        match launch_clash_verge() {
            Ok(path) => steps.push(step("启动 Clash Verge", "ok", format!("已从 {path} 拉起"))),
            Err(e) => steps.push(step("启动 Clash Verge", "fail", e)),
        }
    }

    if wait_for_tun_and_client(mode, 40) {
        steps.push(step("代理内核+TUN", "ok", "内核进程与 TUN 均在线"));
        return;
    }

    // 内核/TUN 仍不在线：检查 TUN 开关是否被「更新」关掉。
    if mode == "clash-verge" {
        match reenable_tun_mode() {
            Ok(true) => {
                steps.push(step(
                    "恢复 TUN 开关",
                    "ok",
                    "已将 verge.yaml enable_tun_mode 改为 true 并重启 Clash Verge",
                ));
                if wait_for_tun_and_client(mode, 40) {
                    steps.push(step("代理内核+TUN", "ok", "恢复后内核与 TUN 均在线"));
                    return;
                }
            }
            Ok(false) => {}
            Err(e) => steps.push(step("恢复 TUN 开关", "fail", e)),
        }
    }

    steps.push(step(
        "代理内核+TUN",
        "fail",
        "等待超时，请打开代理客户端检查节点/线路与 TUN 模式",
    ));
}

/// 一键修复（阻塞，必须经 Tauri `blocking(...)` 调用）。
///
/// 步骤：拉起内核+TUN（必要时恢复 TUN 开关）→ 锁时区 → 关 IPv6 → 按模式写/清置顶
/// 规则 → 重注册保镖 → 重跑 14 项检查给出复测结果。提权类步骤失败会标注
/// 「需管理员」，不吞错。
pub fn run_fix_blocking() -> FixReport {
    let mut steps: Vec<FixStep> = Vec::new();
    let cfg = appconfig::load();
    let mode = cfg
        .proxy_mode
        .clone()
        .unwrap_or_else(|| "clash-verge".to_string());

    // A. 代理内核 + TUN
    fix_launch_and_tun(&mode, &mut steps);

    // B. 锁时区（需要管理员）
    match &cfg.tz_target {
        Some(tz) => {
            let need = match imp::current_timezone_id() {
                Ok(cur) => !cur.eq_ignore_ascii_case(tz),
                Err(_) => true,
            };
            if need {
                match imp::set_timezone_id(tz) {
                    Ok(()) => steps.push(step("时区", "ok", format!("已锁定为 {tz}"))),
                    Err(e) => {
                        steps.push(step("时区", "fail", format!("设置失败（需管理员）：{e}")))
                    }
                }
            } else {
                steps.push(step("时区", "ok", format!("已是 {tz}")));
            }
        }
        None => steps.push(step(
            "时区",
            "warn",
            "未锁定目标时区（运行 set-region 后自动记录）",
        )),
    }

    // C. 关 IPv6（需要管理员）
    match imp::ipv6_bindings() {
        Ok(list) if list.iter().any(|(_, en)| *en) => match imp::set_ipv6_all_disabled() {
            Ok(()) => steps.push(step("IPv6", "ok", "已禁用全部网卡 IPv6 绑定")),
            Err(e) => steps.push(step("IPv6", "fail", format!("禁用失败（需管理员）：{e}"))),
        },
        Ok(_) => steps.push(step("IPv6", "ok", "已全部禁用")),
        Err(e) => steps.push(step("IPv6", "fail", format!("查询失败：{e}"))),
    }

    // D. 按模式写/清置顶规则（global/direct 只清历史 Merge）
    match rules::ensure_rules() {
        Ok(report) if report.kernel_verified => {
            steps.push(step("置顶规则", "ok", "内核已验证置顶规则"));
        }
        Ok(report) => {
            steps.push(step("置顶规则", "warn", report.messages.join("；")));
        }
        Err(e) => steps.push(step("置顶规则", "fail", e)),
    }

    // E. 确保保镖在跑（需要管理员）
    //
    // 不只判断「是否注册」：注册了但进程没起（任务被手动结束、上次启动失败）
    // 同样属于保镖缺失。ensure_guard_running 幂等——已注册就补一次启动，
    // 未注册才走完整注册流程。
    match guard::ensure_guard_running() {
        Ok(()) => steps.push(step(
            "保镖",
            "ok",
            if guard::guard_installed() {
                "保镖计划任务已注册并已启动"
            } else {
                "已注册并启动保镖计划任务"
            },
        )),
        Err(e) => steps.push(step(
            "保镖",
            "fail",
            format!("注册/启动失败（需管理员）：{e}"),
        )),
    }

    // F. 复测
    let checks = run_checks_blocking();
    let summary = check_summary(&checks);
    FixReport {
        steps,
        summary,
        checks,
    }
}

// ────────────────────────── 单测 ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(desc: &str, status: &str, ipv4: &[&str]) -> AdapterInfo {
        AdapterInfo {
            name: desc.to_string(),
            description: desc.to_string(),
            status: status.to_string(),
            if_index: 0,
            ipv4: ipv4.iter().map(|s| s.to_string()).collect(),
            ipv6: vec![],
        }
    }

    fn sample_egress() -> EgressInfo {
        EgressInfo {
            ip: "203.0.113.5".to_string(),
            country: "US".to_string(),
            iana_tz: "America/New_York".to_string(),
            org: None,
            source: "test".to_string(),
        }
    }

    #[test]
    fn proxy_core_table() {
        assert_eq!(judge_proxy_core("clash-verge", true).0, "ok");
        assert_eq!(judge_proxy_core("clash-verge", false).0, "fail");
        assert!(judge_proxy_core("clash-verge", false).1.contains("未运行"));
        // auto/other 不查进程，恒 ok。
        assert_eq!(judge_proxy_core("auto", false).0, "ok");
        assert_eq!(judge_proxy_core("other", false).0, "ok");
    }

    #[test]
    fn tun_table() {
        let tunnel = vec![adapter("Wintun", "Up", &["198.18.0.2"])];
        assert_eq!(judge_tun(Ok(&tunnel)).0, "ok");
        assert!(judge_tun(Ok(&tunnel)).1.contains("198.18"));

        let physical = vec![adapter("Realtek", "Up", &["192.168.1.5"])];
        assert_eq!(judge_tun(Ok(&physical)).0, "fail");

        assert_eq!(judge_tun(Err("powershell 超时")).0, "fail");
    }

    #[test]
    fn egress_country_table() {
        let e = sample_egress();
        assert_eq!(judge_egress_country(Some(&e), Some("US")).0, "ok");
        assert!(judge_egress_country(Some(&e), Some("US"))
            .1
            .contains("203.0.113.5/US"));
        assert_eq!(judge_egress_country(Some(&e), Some("JP")).0, "fail");
        // 未锁定目标 → warn（不 fail，避免首装误报）。
        assert_eq!(judge_egress_country(Some(&e), None).0, "warn");
        // 探测失败 → fail。
        assert_eq!(judge_egress_country(None, Some("US")).0, "fail");
    }

    #[test]
    fn ip_consistency_table() {
        assert_eq!(judge_ip_consistency(Some("1.1.1.1"), None).0, "ok");
        assert!(judge_ip_consistency(Some("1.1.1.1"), None)
            .1
            .contains("首次记录"));
        assert_eq!(
            judge_ip_consistency(Some("1.1.1.1"), Some("1.1.1.1")).0,
            "ok"
        );
        let (s, d) = judge_ip_consistency(Some("2.2.2.2"), Some("1.1.1.1"));
        assert_eq!(s, "warn");
        assert_eq!(d, "1.1.1.1 → 2.2.2.2");
        assert_eq!(judge_ip_consistency(None, Some("1.1.1.1")).0, "fail");
    }

    #[test]
    fn timezone_table() {
        assert_eq!(
            judge_timezone(Ok("Eastern Standard Time"), Some("Eastern Standard Time")).0,
            "ok"
        );
        assert_eq!(
            judge_timezone(Ok("China Standard Time"), Some("Eastern Standard Time")).0,
            "fail"
        );
        // 忽略大小写。
        assert_eq!(
            judge_timezone(Ok("eastern standard time"), Some("Eastern Standard Time")).0,
            "ok"
        );
        assert_eq!(judge_timezone(Err("访问被拒绝"), Some("UTC")).0, "fail");
        assert_eq!(judge_timezone(Ok("UTC"), None).0, "warn");
    }

    #[test]
    fn culture_table() {
        assert_eq!(judge_culture(Ok("en-US"), Some("en-US")).0, "ok");
        assert_eq!(judge_culture(Ok("zh-CN"), Some("en-US")).0, "fail");
        assert_eq!(judge_culture(Ok("ja-JP"), Some("ja-JP")).0, "ok");
        assert_eq!(judge_culture(Ok("en-US"), None).0, "warn");
    }

    #[test]
    fn ipv6_table() {
        let all_off: Vec<(String, bool)> =
            vec![("以太网".to_string(), false), ("Wintun".to_string(), false)];
        assert_eq!(judge_ipv6(Ok(&all_off)).0, "ok");

        let one_on: Vec<(String, bool)> =
            vec![("以太网".to_string(), true), ("Wintun".to_string(), false)];
        let (s, d) = judge_ipv6(Ok(&one_on));
        assert_eq!(s, "fail");
        assert!(d.contains("以太网"));

        let empty: Vec<(String, bool)> = vec![];
        assert_eq!(judge_ipv6(Ok(&empty)).0, "warn");
        assert_eq!(judge_ipv6(Err("查询失败")).0, "fail");
    }

    #[test]
    fn dns_table() {
        let tunneled: Vec<String> = vec!["198.18.0.5".to_string()];
        assert_eq!(judge_dns(Ok(&tunneled)).0, "ok");

        let direct: Vec<String> = vec!["93.184.216.34".to_string()];
        assert_eq!(judge_dns(Ok(&direct)).0, "fail");

        let empty: Vec<String> = vec![];
        assert_eq!(judge_dns(Ok(&empty)).0, "fail");
        assert_eq!(judge_dns(Err("dns error")).0, "fail");
    }

    #[test]
    fn webrtc_table() {
        let clean = StunResult {
            egress_ip: "1.2.3.4".to_string(),
            probed_ip: Some("1.2.3.4".to_string()),
            leaks: false,
            servers_responded: 3,
            error: None,
        };
        assert_eq!(judge_webrtc(Some(&clean)).0, "ok");

        let leak = StunResult {
            egress_ip: "1.2.3.4".to_string(),
            probed_ip: Some("11.0.0.9".to_string()),
            leaks: true,
            servers_responded: 2,
            error: None,
        };
        assert_eq!(judge_webrtc(Some(&leak)).0, "fail");
        assert!(judge_webrtc(Some(&leak)).1.contains("11.0.0.9"));

        let silent = StunResult {
            egress_ip: "1.2.3.4".to_string(),
            probed_ip: None,
            leaks: false,
            servers_responded: 0,
            error: Some("无任何 STUN 服务器响应".to_string()),
        };
        assert_eq!(judge_webrtc(Some(&silent)).0, "warn");
        assert_eq!(judge_webrtc(None).0, "warn");
    }

    #[test]
    fn guard_table() {
        assert_eq!(judge_guard(true).0, "ok");
        assert_eq!(judge_guard(false).0, "fail");
    }

    #[test]
    fn rules_pinned_table() {
        assert_eq!(
            judge_rules_pinned("global", RulesCheck::ModeGlobalDirect).0,
            "ok"
        );
        assert_eq!(
            judge_rules_pinned("direct", RulesCheck::ModeGlobalDirect).0,
            "ok"
        );
        assert_eq!(judge_rules_pinned("rule", RulesCheck::Verified).0, "ok");
        assert_eq!(
            judge_rules_pinned("rule", RulesCheck::VerifyFailed("bad".to_string())).0,
            "fail"
        );
        assert_eq!(
            judge_rules_pinned("rule", RulesCheck::ApiUnavailable("x".to_string())).0,
            "warn"
        );
        assert_eq!(
            judge_rules_pinned("unknown", RulesCheck::UnknownMode).0,
            "warn"
        );
    }

    #[test]
    fn client_language_table() {
        assert_eq!(judge_client_language(Ok("en-US"), Some("en-US")).0, "ok");
        assert_eq!(judge_client_language(Ok("zh-CN"), Some("en-US")).0, "fail");
        // 未锁定目标：英文跟随系统即 ok（上游 en* 判定）。
        assert_eq!(judge_client_language(Ok("en-GB"), None).0, "ok");
        assert_eq!(judge_client_language(Ok("zh-CN"), None).0, "warn");
        assert_eq!(judge_client_language(Err("访问被拒绝"), None).0, "warn");
    }

    #[test]
    fn asn_table() {
        assert_eq!(judge_asn(None).0, "warn");
        assert_eq!(judge_asn(Some("AS16509 Amazon.com")).0, "warn");
        assert_eq!(judge_asn(Some("AS1234 Comcast Cable")).0, "ok");
        assert!(judge_asn(Some("DigitalOcean LLC")).1.contains("机房"));
    }

    #[test]
    fn ecosystem_table() {
        assert_eq!(
            judge_ecosystem(&Reach::Code(200), &Reach::Code(401)).0,
            "ok"
        );
        assert_eq!(
            judge_ecosystem(&Reach::Code(200), &Reach::Code(403)).0,
            "ok"
        );
        assert_eq!(
            judge_ecosystem(&Reach::Failed("timeout".to_string()), &Reach::Code(200)).0,
            "fail"
        );
        assert_eq!(
            judge_ecosystem(
                &Reach::Failed("a".to_string()),
                &Reach::Failed("b".to_string())
            )
            .0,
            "fail"
        );
    }

    #[test]
    fn summary_counts_and_passed() {
        let items = vec![
            CheckItem {
                id: 1,
                key: "a".into(),
                name: "A".into(),
                status: "ok".into(),
                detail: String::new(),
            },
            CheckItem {
                id: 2,
                key: "b".into(),
                name: "B".into(),
                status: "warn".into(),
                detail: String::new(),
            },
            CheckItem {
                id: 3,
                key: "c".into(),
                name: "C".into(),
                status: "fail".into(),
                detail: String::new(),
            },
        ];
        let summary = check_summary(&items);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.ok, 1);
        assert_eq!(summary.warn, 1);
        assert_eq!(summary.fail, 1);
        assert!(!summary.passed);

        let mut no_fail = items.clone();
        no_fail[2].status = "ok".to_string();
        let summary2 = check_summary(&no_fail);
        assert!(summary2.passed);
    }
}
