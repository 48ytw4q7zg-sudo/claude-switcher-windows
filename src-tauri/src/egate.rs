//! 出口门禁（融合 daha1216/ClaudeGuard 的核心能力）。
//!
//! 与既有 `egress.rs` 的分工：`egress` 回答「本机出口是什么」，用于 14 项安检；
//! 本模块回答「**每个被守护目标自己的链路**出口是否符合白名单」——Claude 走
//! claude.ai 的 trace、Codex 走 chatgpt.com 的 trace、反重力只看可达性，
//! 互不牵连，谁不对谁熔断。
//!
//! 行为基准：ClaudeGuard `docs/SPEC-v3.md` §1–§3 与 `src/{anchors,policy,model}.rs`
//! （固定 commit `1967377`）。本文件只含**纯函数**：解析、判定与归一化，
//! 网络探测在 `egate_probe.rs`，熔断执行在 `guard`/`netcut` 侧按批接入。

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// 锚点类型：决定如何从响应体里取出口信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorKind {
    /// 自动识别：trace → JSON IP → Gemini 地区标记 → 仅可达性（命中即停）。
    Auto,
    /// Cloudflare trace 文本（`ip=` / `loc=` / `colo=` 行）。
    Trace,
    /// JSON 响应里的 ip / country。
    JsonIp,
    /// Gemini 页面地区标记 `,2,1,200,"XXX"`，只给地区不给 IP。
    GeminiRegion,
    /// 任何 HTTP 响应即算可达，不看响应体。
    Reachability,
}

impl AnchorKind {
    /// 界面与报告里展示的中文名。
    pub fn label(self) -> &'static str {
        match self {
            AnchorKind::Auto => "自动识别",
            AnchorKind::Trace => "Cloudflare trace",
            AnchorKind::JsonIp => "JSON IP",
            AnchorKind::GeminiRegion => "页面地区标记",
            AnchorKind::Reachability => "仅可达性",
        }
    }

    /// 存入配置用的短标签（与上游 parsed_as 对齐，便于比对证据）。
    pub fn tag(self) -> &'static str {
        match self {
            AnchorKind::Auto => "auto",
            AnchorKind::Trace => "trace",
            AnchorKind::JsonIp => "json_ip",
            AnchorKind::GeminiRegion => "gemini_region",
            AnchorKind::Reachability => "reachability",
        }
    }
}

/// 一个被监控的出口链路：名称 + 探测锚点 + 期望值 + 校验方式。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgateTarget {
    pub id: String,
    pub name: String,
    /// 探测地址（绝对 http/https URL）。
    pub anchor_url: String,
    pub anchor_kind: AnchorKind,
    /// 期望出口 IP 白名单（任一命中即放行）。
    #[serde(default)]
    pub expect_ips: Vec<String>,
    /// 期望出口地区白名单（ISO alpha-2，任一命中即放行）。
    #[serde(default)]
    pub expect_regions: Vec<String>,
    /// 是否参与判定（false 时只展示、不校验）。
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 单次探测超时秒数（下限 1 秒）。
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_enabled() -> bool {
    true
}

fn default_timeout() -> u64 {
    10
}

/// 一次探测结果（`reachable` 之外都是「拿到了什么」）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    /// 是否有 HTTP 响应（含 4xx/5xx）。网络错误/超时为 false。
    pub reachable: bool,
    /// **P0-11**：是否因安全原因主动跳过探测（区别于真实的探测失败）。
    /// 跳过时判定必须返回 Unverified，不能伪造为 Fail。
    #[serde(default)]
    pub skipped: bool,
    /// 归一后的出口 IP。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// 归一后的国家码（alpha-2）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// 归一前的地区原文（无法归一时按原样比较）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub colo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    pub latency_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// 实际按哪种锚点解析（auto 时会记录命中的那一种）。
    pub parsed_as: String,
    /// 给人看的说明。
    pub detail: String,
}

impl ProbeResult {
    /// 网络错误/超时（拿不到任何响应）。
    pub fn failed(reason: impl Into<String>) -> Self {
        Self {
            reachable: false,
            detail: reason.into(),
            ..Self::default()
        }
    }

    /// **P0-11**：因安全原因主动跳过探测（接入路径不安全/未接入）。
    /// 判定层必须据此返回 Unverified，而不是 Fail。
    pub fn skipped(reason: impl Into<String>) -> Self {
        Self {
            reachable: false,
            skipped: true,
            detail: reason.into(),
            ..Self::default()
        }
    }
}

/// 单个目标的判定结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Fail,
    /// 无法确认（探测失败、拿不到出口信息）——**不熔断**。
    Unverified,
    Disabled,
}

/// 判定结果（结论 + 原因）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evaluation {
    pub verdict: Verdict,
    pub reason: String,
}

/// alpha-3 → alpha-2 常见项（上游 `model.rs` 同表）。
const ALPHA3_TO_ALPHA2: &[(&str, &str)] = &[
    ("USA", "US"),
    ("CAN", "CA"),
    ("MEX", "MX"),
    ("BRA", "BR"),
    ("ARG", "AR"),
    ("CHL", "CL"),
    ("COL", "CO"),
    ("PER", "PE"),
    ("GBR", "GB"),
    ("IRL", "IE"),
    ("FRA", "FR"),
    ("DEU", "DE"),
    ("NLD", "NL"),
    ("BEL", "BE"),
    ("LUX", "LU"),
    ("CHE", "CH"),
    ("AUT", "AT"),
    ("ESP", "ES"),
    ("PRT", "PT"),
    ("ITA", "IT"),
    ("JPN", "JP"),
    ("KOR", "KR"),
    ("CHN", "CN"),
    ("HKG", "HK"),
    ("TWN", "TW"),
    ("SGP", "SG"),
    ("MYS", "MY"),
    ("THA", "TH"),
    ("VNM", "VN"),
    ("PHL", "PH"),
    ("IDN", "ID"),
    ("IND", "IN"),
    ("AUS", "AU"),
    ("NZL", "NZ"),
    ("RUS", "RU"),
    ("UKR", "UA"),
    ("TUR", "TR"),
    ("ARE", "AE"),
    ("SAU", "SA"),
    ("ZAF", "ZA"),
    ("NGA", "NG"),
    ("EGY", "EG"),
    ("KEN", "KE"),
    ("ISR", "IL"),
    ("PAK", "PK"),
    ("BGD", "BD"),
    ("LKA", "LK"),
    ("NPL", "NP"),
    ("KAZ", "KZ"),
    ("POL", "PL"),
    ("CZE", "CZ"),
    ("HUN", "HU"),
    ("ROU", "RO"),
    ("GRC", "GR"),
    ("SWE", "SE"),
    ("NOR", "NO"),
    ("DNK", "DK"),
    ("FIN", "FI"),
    ("ISL", "IS"),
    ("AUT2", "AT"),
];

/// 归一化地区码：alpha-2 原样大写，alpha-3 查表转 alpha-2，其余 None。
pub fn normalize_region(raw: &str) -> Option<String> {
    let up = raw.trim().to_ascii_uppercase();
    match up.len() {
        2 if up.chars().all(|c| c.is_ascii_alphabetic()) => Some(up),
        3 => ALPHA3_TO_ALPHA2
            .iter()
            .find(|(a3, _)| *a3 == up)
            .map(|(_, a2)| (*a2).to_string()),
        _ => None,
    }
}

/// 归一化 IP：必须是可解析的 IPv4/IPv6，返回规范化字符串。
pub fn normalize_ip(raw: &str) -> Option<String> {
    let text = raw.trim();
    if text.is_empty() {
        return None;
    }
    text.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

/// IP 白名单命中（两边都归一后比较）。
pub fn ip_hit(expect: &[String], ip: &str) -> bool {
    let Some(ip) = normalize_ip(ip) else {
        return false;
    };
    expect
        .iter()
        .filter_map(|e| normalize_ip(e))
        .any(|e| e == ip)
}

/// 地区白名单命中：优先归一后比较，归一不了的原文忽略大小写比较。
pub fn region_hit(expect: &[String], country: &str) -> bool {
    let Some(country) = normalize_region(country) else {
        return false;
    };
    expect.iter().any(|e| {
        normalize_region(e)
            .map(|n| n == country)
            .unwrap_or_else(|| e.trim().eq_ignore_ascii_case(country.as_str()))
    })
}

/// 判定单个目标（SPEC §3 判定矩阵）。
///
/// 关键语义：
/// - 目标禁用 → `Disabled`；
/// - 仅可达性锚点：有响应 Pass，无响应 Fail；
/// - 拿不到出口信息（不可达/无 IP 无地区）→ `Unverified`，**不熔断**；
/// - 期望 IP 与地区**都为空**却拿到了出口信息 → `Fail`（宁可错杀）；
/// - 期望里有地区但这次只有 IP → `Unverified`（防止地区锚点失效时误熔断）。
pub fn evaluate(target: &EgateTarget, probe: &ProbeResult) -> Evaluation {
    if !target.enabled {
        return Evaluation {
            verdict: Verdict::Disabled,
            reason: "目标已禁用，不参与判定".to_string(),
        };
    }

    // P0-11：主动跳过的目标直接返回 Unverified，不能因为 Reachability
    // 锚点把「安全跳过」误判成「站点不可达」。
    if probe.skipped {
        return Evaluation {
            verdict: Verdict::Unverified,
            reason: if probe.detail.trim().is_empty() {
                "因安全原因跳过探测".to_string()
            } else {
                probe.detail.clone()
            },
        };
    }

    if target.anchor_kind == AnchorKind::Reachability {
        return if probe.reachable {
            Evaluation {
                verdict: Verdict::Pass,
                reason: format!("可达 · {}ms", probe.latency_ms),
            }
        } else {
            Evaluation {
                verdict: Verdict::Fail,
                reason: "不可达".to_string(),
            }
        };
    }

    if !probe.reachable {
        return Evaluation {
            verdict: Verdict::Unverified,
            reason: if probe.detail.trim().is_empty() {
                "探测失败，无法确认出口".to_string()
            } else {
                probe.detail.clone()
            },
        };
    }

    let ip_ok = probe
        .ip
        .as_deref()
        .is_some_and(|ip| ip_hit(&target.expect_ips, ip));
    let region_ok = region_matches(target, probe);
    if ip_ok || region_ok {
        return Evaluation {
            verdict: Verdict::Pass,
            reason: if ip_ok {
                format!("出口 {} 符合白名单", egress_label(probe))
            } else {
                format!("出口地区 {} 符合白名单", region_label(probe))
            },
        };
    }

    let has_geo = probe.ip.is_some() || probe.country.is_some() || probe.raw_region.is_some();
    if target.expect_ips.is_empty() && target.expect_regions.is_empty() {
        // 白名单没配置却拿到了出口信息：宁可错杀。
        return if has_geo {
            Evaluation {
                verdict: Verdict::Fail,
                reason: "未配置白名单，按宁可错杀处理".to_string(),
            }
        } else {
            Evaluation {
                verdict: Verdict::Unverified,
                reason: NO_INFO.to_string(),
            }
        };
    }
    if !has_geo {
        return Evaluation {
            verdict: Verdict::Unverified,
            reason: NO_INFO.to_string(),
        };
    }

    // 期望里有地区、这次只拿到 IP：不拿 IP 硬判，防止地区锚点失效时误熔断。
    if probe.ip.is_some()
        && probe.country.is_none()
        && probe.raw_region.is_none()
        && !target.expect_regions.is_empty()
    {
        return Evaluation {
            verdict: Verdict::Unverified,
            reason: "只有 IP，无法核对地区".to_string(),
        };
    }

    Evaluation {
        verdict: Verdict::Fail,
        reason: fail_reason(probe),
    }
}

/// 有响应但没有任何出口信息时的统一说明。
const NO_INFO: &str = "有响应，但未识别到出口信息";

fn region_matches(target: &EgateTarget, probe: &ProbeResult) -> bool {
    if probe
        .country
        .as_deref()
        .is_some_and(|country| region_hit(&target.expect_regions, country))
    {
        return true;
    }
    probe.raw_region.as_deref().is_some_and(|raw| {
        let raw = raw.trim();
        !raw.is_empty()
            && target
                .expect_regions
                .iter()
                .any(|expect| expect.trim().eq_ignore_ascii_case(raw))
    })
}

fn fail_reason(probe: &ProbeResult) -> String {
    let has_region = probe.country.is_some() || probe.raw_region.is_some();
    match (probe.ip.as_deref(), has_region) {
        (Some(ip), true) => format!("出口 {ip}（{}）不在白名单", region_label(probe)),
        (Some(ip), false) => format!("出口 {ip} 不在白名单"),
        (None, true) => format!("出口地区 {} 不在白名单", region_label(probe)),
        (None, false) => "出口不在白名单".to_string(),
    }
}

/// 出口描述，如 `204.1.100.98（美国）` / `204.1.100.98` / `美国`。
fn egress_label(probe: &ProbeResult) -> String {
    let has_region = probe.country.is_some() || probe.raw_region.is_some();
    match (probe.ip.as_deref(), has_region) {
        (Some(ip), true) => format!("{ip}（{}）", region_label(probe)),
        (Some(ip), false) => ip.to_string(),
        (None, _) => region_label(probe),
    }
}

fn region_label(probe: &ProbeResult) -> String {
    probe
        .country
        .clone()
        .or_else(|| probe.raw_region.clone())
        .unwrap_or_else(|| "未知".to_string())
}

/// 整体判定（SPEC §3）：任一启用目标 Fail → 失败；全部 Pass → 通过；
/// 有 Unverified 但无 Fail → 部分无法确认（不算失败，也不能解除已熔断状态）。
pub fn overall(evaluations: &[(String, Evaluation)]) -> Overall {
    let mut saw_unverified = false;
    let mut saw_disabled = false;
    let mut saw_pass = false;
    for (_, evaluation) in evaluations {
        match evaluation.verdict {
            Verdict::Fail => {
                return Overall {
                    verdict: Verdict::Fail,
                    note: "有启用目标未通过出口校验".to_string(),
                };
            }
            Verdict::Unverified => saw_unverified = true,
            Verdict::Disabled => saw_disabled = true,
            Verdict::Pass => saw_pass = true,
        }
    }
    if saw_unverified {
        return Overall {
            verdict: Verdict::Unverified,
            note: "部分目标无法确认出口".to_string(),
        };
    }
    if saw_pass {
        return Overall {
            verdict: Verdict::Pass,
            note: "全部启用目标通过".to_string(),
        };
    }
    if saw_disabled {
        return Overall {
            verdict: Verdict::Disabled,
            note: "没有启用的监控目标".to_string(),
        };
    }
    Overall {
        verdict: Verdict::Unverified,
        note: "没有可判定的目标".to_string(),
    }
}

/// 整体判定结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overall {
    pub verdict: Verdict,
    pub note: String,
}

/// 解析 Cloudflare trace 文本（`ip=` / `loc=` / `colo=` 行）。
pub fn parse_trace(text: &str) -> Option<ProbeResult> {
    let mut ip = None;
    let mut loc = None;
    let mut colo = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim() {
            "ip" if ip.is_none() => ip = normalize_ip(value),
            "loc" if loc.is_none() => loc = Some(value.to_string()),
            "colo" if colo.is_none() => colo = Some(value.to_string()),
            _ => {}
        }
    }
    if ip.is_none() && loc.is_none() {
        return None;
    }
    let raw_region = loc;
    let country = raw_region.as_deref().and_then(normalize_region);
    let detail = format!(
        "trace：ip={}，地区={}，节点={}",
        ip.as_deref().unwrap_or("-"),
        raw_region.as_deref().unwrap_or("-"),
        colo.as_deref().unwrap_or("-")
    );
    Some(ProbeResult {
        reachable: true,
        skipped: false,
        ip,
        country,
        raw_region,
        colo,
        city: None,
        latency_ms: 0,
        status: None,
        parsed_as: AnchorKind::Trace.tag().to_string(),
        detail,
    })
}

/// 解析 JSON IP 响应：依次取 `ip/ip_address/query/origin` 与
/// `country/country_code/loc/region`（顶层对象优先，`data.` 子对象兜底）。
pub fn parse_json_ip(text: &str) -> Option<ProbeResult> {
    let text = text.trim_start_matches('\u{feff}').trim();
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let top = value.as_object()?;
    let mut objects: Vec<&serde_json::Map<String, serde_json::Value>> = vec![top];
    if let Some(data) = top.get("data").and_then(|value| value.as_object()) {
        objects.push(data);
    }
    let pick = |keys: &[&str]| -> Option<String> {
        for object in &objects {
            for key in keys {
                if let Some(text) = object.get(*key).and_then(|value| value.as_str()) {
                    let text = text.trim();
                    if !text.is_empty() {
                        return Some(text.to_string());
                    }
                }
            }
        }
        None
    };
    let ip = pick(&["ip", "ip_address", "query", "origin"]).and_then(|raw| normalize_ip(&raw));
    let raw_region = pick(&["country", "country_code", "loc", "region"]);
    let city = pick(&["city"]);
    if ip.is_none() && raw_region.is_none() {
        return None;
    }
    let country = raw_region.as_deref().and_then(normalize_region);
    let detail = format!(
        "JSON：ip={}，地区={}",
        ip.as_deref().unwrap_or("-"),
        raw_region.as_deref().unwrap_or("-")
    );
    Some(ProbeResult {
        reachable: true,
        skipped: false,
        ip,
        country,
        raw_region,
        colo: None,
        city,
        latency_ms: 0,
        status: None,
        parsed_as: AnchorKind::JsonIp.tag().to_string(),
        detail,
    })
}

/// 解析 Gemini 页面地区标记（等价正则 `,2,1,200,"([A-Z]{3})"`）。
/// 给地区、不给 IP；页面近 1MB，手写扫描比编译正则更轻。
pub fn parse_gemini_region(text: &str) -> Option<ProbeResult> {
    const MARKER: &str = ",2,1,200,\"";
    for (pos, _) in text.match_indices(MARKER) {
        let rest = &text[pos + MARKER.len()..];
        let bytes = rest.as_bytes();
        if bytes.len() < 4 || bytes[3] != b'"' || !bytes[..3].iter().all(u8::is_ascii_uppercase) {
            continue;
        }
        let raw = rest[..3].to_string();
        let country = normalize_region(&raw);
        let detail = match &country {
            Some(code) => format!("页面地区标记：{raw} → {code}"),
            None => format!("页面地区标记：{raw}（无法归一）"),
        };
        return Some(ProbeResult {
            reachable: true,
            skipped: false,
            ip: None,
            country,
            raw_region: Some(raw),
            colo: None,
            city: None,
            latency_ms: 0,
            status: None,
            parsed_as: AnchorKind::GeminiRegion.tag().to_string(),
            detail,
        });
    }
    None
}

/// auto 解析顺序（命中即停）：trace → json_ip → gemini_region → 仅可达性。
pub fn parse_auto(text: &str) -> ProbeResult {
    if let Some(parsed) = parse_trace(text) {
        return parsed;
    }
    if let Some(parsed) = parse_json_ip(text) {
        return parsed;
    }
    if let Some(parsed) = parse_gemini_region(text) {
        return parsed;
    }
    ProbeResult {
        reachable: true,
        parsed_as: AnchorKind::Reachability.tag().to_string(),
        detail: NO_INFO.to_string(),
        ..ProbeResult::default()
    }
}

/// 按目标声明的锚点类型解析响应体（显式类型解析失败即「有响应但无出口信息」）。
pub fn parse_anchor(kind: AnchorKind, body: &str) -> ProbeResult {
    let parsed = match kind {
        AnchorKind::Auto => return parse_auto(body),
        AnchorKind::Trace => parse_trace(body),
        AnchorKind::JsonIp => parse_json_ip(body),
        AnchorKind::GeminiRegion => parse_gemini_region(body),
        AnchorKind::Reachability => None,
    };
    parsed.unwrap_or_else(|| ProbeResult {
        reachable: true,
        parsed_as: kind.tag().to_string(),
        detail: format!("{}解析失败，未识别到出口信息", kind.label()),
        ..ProbeResult::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(kind: AnchorKind, ips: &[&str], regions: &[&str]) -> EgateTarget {
        EgateTarget {
            id: "t".to_string(),
            name: "测试目标".to_string(),
            anchor_url: "https://example.invalid/cdn-cgi/trace".to_string(),
            anchor_kind: kind,
            expect_ips: ips.iter().map(|s| s.to_string()).collect(),
            expect_regions: regions.iter().map(|s| s.to_string()).collect(),
            enabled: true,
            timeout_secs: 5,
        }
    }

    fn probe_ip(ip: &str, country: &str) -> ProbeResult {
        ProbeResult {
            reachable: true,
            ip: Some(ip.to_string()),
            country: Some(country.to_string()),
            raw_region: Some(country.to_string()),
            detail: String::new(),
            ..ProbeResult::default()
        }
    }

    // ── 归一化 ──

    #[test]
    fn normalize_region_accepts_alpha2_and_converts_alpha3() {
        assert_eq!(normalize_region("us").as_deref(), Some("US"));
        assert_eq!(normalize_region(" JP ").as_deref(), Some("JP"));
        assert_eq!(normalize_region("USA").as_deref(), Some("US"));
        assert_eq!(normalize_region("JPN").as_deref(), Some("JP"));
        assert_eq!(normalize_region("XXX").as_deref(), None);
        assert_eq!(normalize_region("USA1"), None);
    }

    #[test]
    fn normalize_ip_rejects_garbage_and_accepts_v6() {
        assert_eq!(normalize_ip(" 1.2.3.4 ").as_deref(), Some("1.2.3.4"));
        assert_eq!(normalize_ip("not-an-ip"), None);
        assert_eq!(normalize_ip(""), None);
        assert!(normalize_ip("2001:db8::1").is_some());
    }

    // ── 判定矩阵 ──

    #[test]
    fn disabled_target_never_participates() {
        let mut t = target(AnchorKind::Trace, &["1.2.3.4"], &[]);
        t.enabled = false;
        let e = evaluate(&t, &probe_ip("9.9.9.9", "CN"));
        assert_eq!(e.verdict, Verdict::Disabled);
    }

    #[test]
    fn reachability_passes_on_any_response_and_fails_on_error() {
        let t = target(AnchorKind::Reachability, &[], &[]);
        assert_eq!(
            evaluate(&t, &probe_ip("1.1.1.1", "US")).verdict,
            Verdict::Pass
        );
        assert_eq!(
            evaluate(&t, &ProbeResult::failed("timeout")).verdict,
            Verdict::Fail
        );
    }

    #[test]
    fn skipped_probe_is_unverified_not_fail_even_for_reachability() {
        // P0-11：安全跳过不能因为 Reachability 锚点被误判为「站点不可达」。
        let t = target(AnchorKind::Reachability, &[], &[]);
        let e = evaluate(&t, &ProbeResult::skipped("未接入代理链路，已跳过探测"));
        assert_eq!(e.verdict, Verdict::Unverified, "跳过探测必须是 Unverified");
        assert!(e.reason.contains("跳过"), "{}", e.reason);
        // 对照：真正探测过且不可达的 Reachability 才判 Fail。
        let real_fail = evaluate(&t, &ProbeResult::failed("连接超时"));
        assert_eq!(real_fail.verdict, Verdict::Fail);
    }

    #[test]
    fn probe_failure_is_unverified_not_fail() {
        let t = target(AnchorKind::Trace, &["1.2.3.4"], &["US"]);
        let e = evaluate(&t, &ProbeResult::failed("连接超时"));
        assert_eq!(e.verdict, Verdict::Unverified, "探测失败绝不能熔断");
    }

    #[test]
    fn empty_whitelist_with_geo_fails_closed() {
        let t = target(AnchorKind::Trace, &[], &[]);
        assert_eq!(
            evaluate(&t, &probe_ip("1.2.3.4", "US")).verdict,
            Verdict::Fail,
            "白名单为空却拿到出口信息：宁可错杀"
        );
    }

    #[test]
    fn empty_whitelist_without_geo_is_unverified() {
        let t = target(AnchorKind::Trace, &[], &[]);
        let probe = ProbeResult {
            reachable: true,
            ..ProbeResult::default()
        };
        assert_eq!(evaluate(&t, &probe).verdict, Verdict::Unverified);
    }

    #[test]
    fn ip_hit_and_region_hit_both_pass() {
        let by_ip = target(AnchorKind::Trace, &["1.2.3.4"], &["JP"]);
        assert_eq!(
            evaluate(&by_ip, &probe_ip("1.2.3.4", "CN")).verdict,
            Verdict::Pass
        );
        let by_region = target(AnchorKind::Trace, &["9.9.9.9"], &["JP"]);
        assert_eq!(
            evaluate(&by_region, &probe_ip("1.2.3.4", "JP")).verdict,
            Verdict::Pass
        );
    }

    #[test]
    fn mismatched_ip_and_region_fails() {
        let t = target(AnchorKind::Trace, &["9.9.9.9"], &["JP"]);
        let e = evaluate(&t, &probe_ip("1.2.3.4", "CN"));
        assert_eq!(e.verdict, Verdict::Fail);
        assert!(e.reason.contains("1.2.3.4"), "原因必须带上实际出口：{e:?}");
    }

    #[test]
    fn only_ip_when_region_expected_is_unverified() {
        let t = target(AnchorKind::Trace, &["9.9.9.9"], &["JP"]);
        let probe = ProbeResult {
            reachable: true,
            ip: Some("1.2.3.4".to_string()),
            detail: String::new(),
            ..ProbeResult::default()
        };
        assert_eq!(
            evaluate(&t, &probe).verdict,
            Verdict::Unverified,
            "期望地区却只拿到 IP 时不能硬判失败"
        );
    }

    #[test]
    fn ip_only_whitelist_fails_when_ip_misses() {
        let t = target(AnchorKind::Trace, &["9.9.9.9"], &[]);
        let probe = ProbeResult {
            reachable: true,
            ip: Some("1.2.3.4".to_string()),
            detail: String::new(),
            ..ProbeResult::default()
        };
        assert_eq!(evaluate(&t, &probe).verdict, Verdict::Fail);
    }

    #[test]
    fn raw_region_matches_when_normalization_fails() {
        let mut t = target(AnchorKind::Trace, &[], &["xx"]);
        let probe = ProbeResult {
            reachable: true,
            raw_region: Some("XX".to_string()),
            detail: String::new(),
            ..ProbeResult::default()
        };
        assert_eq!(evaluate(&t, &probe).verdict, Verdict::Pass);
        t.expect_regions = vec!["yy".to_string()];
        assert_eq!(evaluate(&t, &probe).verdict, Verdict::Fail);
    }

    // ── 整体判定 ──

    #[test]
    fn overall_any_fail_wins() {
        let list = vec![
            (
                "a".to_string(),
                Evaluation {
                    verdict: Verdict::Pass,
                    reason: String::new(),
                },
            ),
            (
                "b".to_string(),
                Evaluation {
                    verdict: Verdict::Unverified,
                    reason: String::new(),
                },
            ),
            (
                "c".to_string(),
                Evaluation {
                    verdict: Verdict::Fail,
                    reason: String::new(),
                },
            ),
        ];
        assert_eq!(overall(&list).verdict, Verdict::Fail);
    }

    #[test]
    fn overall_unverified_when_no_fail_but_incomplete() {
        let list = vec![
            (
                "a".to_string(),
                Evaluation {
                    verdict: Verdict::Pass,
                    reason: String::new(),
                },
            ),
            (
                "b".to_string(),
                Evaluation {
                    verdict: Verdict::Unverified,
                    reason: String::new(),
                },
            ),
        ];
        assert_eq!(overall(&list).verdict, Verdict::Unverified);
    }

    #[test]
    fn overall_pass_requires_every_enabled_target() {
        let list = vec![
            (
                "a".to_string(),
                Evaluation {
                    verdict: Verdict::Pass,
                    reason: String::new(),
                },
            ),
            (
                "b".to_string(),
                Evaluation {
                    verdict: Verdict::Disabled,
                    reason: String::new(),
                },
            ),
        ];
        assert_eq!(overall(&list).verdict, Verdict::Pass);
    }

    #[test]
    fn overall_with_no_targets_is_unverified() {
        assert_eq!(overall(&[]).verdict, Verdict::Unverified);
    }

    // ── 解析器 ──

    #[test]
    fn parse_trace_reads_ip_loc_colo() {
        let body = "fl=1\nip=204.1.100.98\nloc=US\ncolo=LAX\n";
        let parsed = parse_trace(body).expect("应解析成功");
        assert_eq!(parsed.ip.as_deref(), Some("204.1.100.98"));
        assert_eq!(parsed.country.as_deref(), Some("US"));
        assert_eq!(parsed.colo.as_deref(), Some("LAX"));
    }

    #[test]
    fn parse_trace_accepts_loc_only() {
        let parsed = parse_trace("loc=JP\n").expect("只有地区也应算解析成功");
        assert!(parsed.ip.is_none());
        assert_eq!(parsed.country.as_deref(), Some("JP"));
    }

    #[test]
    fn parse_trace_rejects_body_without_ip_or_loc() {
        assert!(parse_trace("fl=1\ncolo=LAX\n").is_none());
    }

    #[test]
    fn parse_json_ip_reads_top_level_then_data_child() {
        let parsed = parse_json_ip(r#"{"ip":"1.2.3.4","country":"US"}"#).unwrap();
        assert_eq!(parsed.ip.as_deref(), Some("1.2.3.4"));
        let nested = parse_json_ip(r#"{"data":{"query":"5.6.7.8","country_code":"JP"}}"#).unwrap();
        assert_eq!(nested.ip.as_deref(), Some("5.6.7.8"));
        assert_eq!(nested.country.as_deref(), Some("JP"));
    }

    #[test]
    fn parse_json_ip_rejects_invalid_json_and_empty_fields() {
        assert!(parse_json_ip("not json").is_none());
        assert!(parse_json_ip(r#"{"ip":"","country":""}"#).is_none());
        assert!(
            parse_json_ip(r#"{"ip":"not-an-ip","country":"US"}"#).is_some(),
            "地区可用时即使 IP 非法也应保留地区"
        );
    }

    #[test]
    fn parse_gemini_region_extracts_three_letter_code() {
        let body = "x,2,1,200,\"USA\"y";
        let parsed = parse_gemini_region(body).expect("应命中标记");
        assert!(parsed.ip.is_none());
        assert_eq!(parsed.country.as_deref(), Some("US"));
        assert_eq!(parsed.raw_region.as_deref(), Some("USA"));
    }

    #[test]
    fn parse_gemini_region_rejects_non_matching_marker() {
        assert!(parse_gemini_region(",2,1,200,\"us1\"").is_none());
        assert!(parse_gemini_region("no marker here").is_none());
    }

    #[test]
    fn parse_auto_prefers_trace_then_json_then_gemini() {
        let trace = parse_auto("ip=1.2.3.4\nloc=US\n");
        assert_eq!(trace.parsed_as, AnchorKind::Trace.tag());
        let json = parse_auto(r#"{"ip":"1.2.3.4"}"#);
        assert_eq!(json.parsed_as, AnchorKind::JsonIp.tag());
        let gemini = parse_auto("x,2,1,200,\"JPN\"y");
        assert_eq!(gemini.parsed_as, AnchorKind::GeminiRegion.tag());
        let none = parse_auto("<html>nothing</html>");
        assert_eq!(none.parsed_as, AnchorKind::Reachability.tag());
        assert!(none.ip.is_none() && none.country.is_none());
    }

    #[test]
    fn explicit_kind_parse_failure_reports_no_info() {
        // 显式声明 trace 却拿到 JSON：解析失败但不等于不可达。
        let parsed = parse_anchor(AnchorKind::Trace, r#"{"ip":"1.2.3.4"}"#);
        assert!(parsed.reachable);
        assert!(parsed.ip.is_none());
        assert!(parsed.detail.contains("未识别到出口信息"));
        // 显式 reachability 不看响应体。
        let reach = parse_anchor(AnchorKind::Reachability, "whatever");
        assert!(reach.reachable);
    }
}
