//! 出口 IP 探测（Cloudflare trace + ipinfo）。
//!
//! 安检「出口 IP」「时区」「地区」「ASN 属性」都依赖当前出口信息。
//! 纯解析函数与网络请求分离，便于表驱动单测。请求走系统默认路由（TUN 已接管），
//! reqwest 的 system-proxy 特性也会读系统代理设置。

use std::time::Duration;

use serde::Serialize;

/// 一次出口探测结果。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EgressInfo {
    /// 出口 IPv4/IPv6。
    pub ip: String,
    /// 国家码（大写，如 "US"）。
    pub country: String,
    /// IANA 时区（如 "America/New_York"）。
    pub iana_tz: String,
    /// ASN/组织描述（ipinfo org，用于住宅 vs 机房启发式）。
    pub org: Option<String>,
    /// 数据来源说明（cloudflare / ipinfo）。
    pub source: String,
}

/// Cloudflare trace 解析结果（**QW-03**：字段独立可选）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareTrace {
    pub ip: Option<String>,
    pub country: Option<String>,
    pub tz: Option<String>,
}

/// 解析 cloudflare trace。ip 或 loc 任一存在即返回——
/// 时区缺失时保留有效 IP 与国家，不再整体丢弃。
pub fn parse_cloudflare_trace(text: &str) -> Option<CloudflareTrace> {
    let mut ip = None;
    let mut loc = None;
    let mut tz = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim() {
            "ip" if ip.is_none() => ip = Some(value.to_string()),
            "loc" if loc.is_none() => loc = Some(value.to_uppercase()),
            "tz" if tz.is_none() => tz = Some(value.to_string()),
            _ => {}
        }
    }
    if ip.is_none() && loc.is_none() {
        return None;
    }
    Some(CloudflareTrace {
        ip,
        country: loc,
        tz,
    })
}

/// 解析 ipinfo JSON：(ip, country, timezone, org)。
pub fn parse_ipinfo(value: &serde_json::Value) -> Option<(String, String, String, Option<String>)> {
    let get = |k: &str| value.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let ip = get("ip")?;
    let country = get("country")?.to_uppercase();
    let timezone = get("timezone")?;
    let org = get("org");
    Some((ip, country, timezone, org))
}

/// **QW-04**：ASN 类型三态——未知不等于住宅。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsnKind {
    /// 已识别为机房/托管。
    Datacenter,
    /// 已识别为运营商/ISP 关键词。
    Isp,
    /// 无法确认（**不得**当作住宅）。
    Unknown,
}

/// **QW-04**：判定 ASN 类型。
///
/// 未命中机房关键词**不等于**住宅——只有明确命中 ISP 关键词才算运营商，
/// 其余一律 Unknown。
pub fn classify_asn(org: &str) -> AsnKind {
    let hay = org.to_lowercase();
    if hay.trim().is_empty() {
        return AsnKind::Unknown;
    }
    if is_datacenter_org(org) {
        return AsnKind::Datacenter;
    }
    const ISP_HINTS: [&str; 10] = [
        "telecom",
        "unicom",
        "mobile",
        "broadband",
        "cable",
        "dsl",
        "isp",
        "communications",
        "telephone",
        "cellular",
    ];
    if ISP_HINTS.iter().any(|hint| hay.contains(hint)) {
        return AsnKind::Isp;
    }
    AsnKind::Unknown
}

/// 机房/托管 ASN 启发式：org 含这些关键词则判为机房（非住宅）。
pub fn is_datacenter_org(org: &str) -> bool {
    let hay = org.to_lowercase();
    const HINTS: [&str; 12] = [
        "hosting",
        "datacenter",
        "data center",
        "cloud",
        "server",
        "vps",
        "colo",
        "amazon",
        "google",
        "microsoft",
        "digitalocean",
        "ovh",
    ];
    HINTS.iter().any(|h| hay.contains(h))
}

fn build_client() -> Result<reqwest::blocking::Client, String> {
    // **P1-10**：出口诊断属于「泄露即失败」的请求——它要回答的就是
    // 「外界看到我是什么 IP」，一旦代理不可用而静默直连，测出来的就是
    // 用户家宽出口，等于把真实 IP 送给被测域名。
    //
    // 因此走严格策略：只接受**已确认可用**的系统代理，拿不到就明确失败。
    // 原实现的裸 builder 会跟随系统代理，但代理挂掉时 reqwest 会直接连出去。
    let evidence = crate::egate_check::read_proxy_evidence();
    let proxy = crate::network_policy::usable_system_proxy(&evidence);
    let spec = crate::network_policy::ClientSpec::new(
        crate::network_policy::NetworkPolicy::StrictProxy,
        Duration::from_secs(10),
    );
    crate::network_policy::build_client(&spec, proxy.as_ref())
}

/// 探测出口（阻塞，必须经 `blocking()` 调用）。
/// 先取 cloudflare（ip/国家/时区），再尽力补 ipinfo 的 org（ASN）。
/// **P1-02**：只有两个来源指向**同一个 IP** 时才允许合并组织信息。
///
/// 两个请求可能走不同出口（负载均衡、节点切换），把 A 的 IP 配上 B 的 ASN
/// 会给出错误的安全结论。IP 不一致时保留各自的原始观测，不混合。
pub fn merge_org_if_same_ip(
    cloudflare: (&str, &str, &str),
    ipinfo: Option<(&str, &str, &str, Option<&str>)>,
) -> Option<String> {
    let (cf_ip, _, _) = cloudflare;
    let (ii_ip, _, _, org) = ipinfo?;
    // IP 必须完全一致（规范化后比较）。
    if cf_ip.trim() != ii_ip.trim() {
        return None;
    }
    org.map(str::to_string)
}

pub fn detect_egress_blocking() -> Result<EgressInfo, String> {
    let client = build_client()?;

    // Cloudflare trace。
    let cf_text = client
        .get("https://www.cloudflare.com/cdn-cgi/trace")
        .header("User-Agent", "claude-switcher")
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.text());

    // ipinfo（best effort，兼作 cloudflare 失败时的回退）。
    let ipinfo_value: Option<serde_json::Value> = client
        .get("https://ipinfo.io/json")
        .header("User-Agent", "claude-switcher")
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json())
        .ok();

    if let Ok(text) = &cf_text {
        if let Some(trace) = parse_cloudflare_trace(text) {
            let ip = trace.ip.unwrap_or_default();
            let country = trace.country.unwrap_or_default();
            let ipinfo_parsed = ipinfo_value.as_ref().and_then(parse_ipinfo);
            // QW-03：trace 缺 tz 时，从**同一 IP** 的 ipinfo 补齐；否则标注未验证。
            let same_ip_tz = ipinfo_parsed
                .as_ref()
                .filter(|(i, _, _, _)| i == &ip)
                .map(|(_, _, t, _)| t.clone());
            let had_tz = trace.tz.is_some();
            let iana_tz = trace.tz.or(same_ip_tz).unwrap_or_default();
            let org = merge_org_if_same_ip(
                (&ip, &country, &iana_tz),
                ipinfo_parsed
                    .as_ref()
                    .map(|(i, c, t, o)| (i.as_str(), c.as_str(), t.as_str(), o.as_deref())),
            );
            return Ok(EgressInfo {
                ip,
                country,
                iana_tz,
                org,
                source: if had_tz {
                    "cloudflare".to_string()
                } else {
                    "cloudflare（时区未验证）".to_string()
                },
            });
        }
    }

    // 回退到 ipinfo。
    if let Some(value) = ipinfo_value {
        if let Some((ip, country, tz, org)) = parse_ipinfo(&value) {
            return Ok(EgressInfo {
                ip,
                country,
                iana_tz: tz,
                org,
                source: "ipinfo".to_string(),
            });
        }
    }

    Err("无法获取出口 IP 信息（cloudflare 与 ipinfo 均失败）".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_merges_only_when_both_sources_report_same_ip() {
        // 同一 IP：允许合并。
        assert_eq!(
            merge_org_if_same_ip(
                ("1.2.3.4", "US", "America/New_York"),
                Some((
                    "1.2.3.4",
                    "US",
                    "America/New_York",
                    Some("AS123 Example ISP")
                )),
            )
            .as_deref(),
            Some("AS123 Example ISP")
        );
        // IP 不同：绝不合并（否则会把 A 的 IP 配上 B 的 ASN）。
        assert_eq!(
            merge_org_if_same_ip(
                ("1.2.3.4", "US", "America/New_York"),
                Some(("9.9.9.9", "JP", "Asia/Tokyo", Some("AS456 Other"))),
            ),
            None,
            "不同出口的 org 不能混用"
        );
        // ipinfo 缺失：无 org。
        assert_eq!(
            merge_org_if_same_ip(("1.2.3.4", "US", "America/New_York"), None),
            None
        );
        // ipinfo 有 IP 但无 org：无 org。
        assert_eq!(
            merge_org_if_same_ip(
                ("1.2.3.4", "US", "America/New_York"),
                Some(("1.2.3.4", "US", "America/New_York", None))
            ),
            None
        );
    }

    #[test]
    fn parses_cloudflare_trace() {
        let text = "fl=12\nh=example.com\nip=203.0.113.9\nts=123\nloc=us\ntz=America/New_York\n";
        let trace = parse_cloudflare_trace(text).expect("parse");
        assert_eq!(trace.ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(trace.country.as_deref(), Some("US"));
        assert_eq!(trace.tz.as_deref(), Some("America/New_York"));
        // QW-03：缺 tz 时仍保留 IP 与国家。
        let partial = parse_cloudflare_trace(
            "ip=1.2.3.4
loc=jp
",
        )
        .expect("partial");
        assert_eq!(partial.ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(partial.country.as_deref(), Some("JP"));
        assert!(partial.tz.is_none());
    }

    #[test]
    fn trace_requires_ip_or_country() {
        // QW-03：只有 loc 也算有效（保留国家），完全无线索才 None。
        let country_only = parse_cloudflare_trace(
            "loc=us
tz=America/New_York
",
        );
        assert!(country_only.is_some(), "有国家码就应保留");
        assert_eq!(country_only.unwrap().country.as_deref(), Some("US"));
        assert!(parse_cloudflare_trace(
            "ts=1234
colo=LAX
"
        )
        .is_none());
    }

    #[test]
    fn parses_ipinfo_json() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"ip":"203.0.113.9","city":"NY","country":"US","org":"AS123 Residential ISP","timezone":"America/New_York"}"#,
        )
        .expect("json");
        let (ip, country, tz, org) = parse_ipinfo(&v).expect("parse");
        assert_eq!(ip, "203.0.113.9");
        assert_eq!(country, "US");
        assert_eq!(tz, "America/New_York");
        assert_eq!(org.as_deref(), Some("AS123 Residential ISP"));
    }

    #[test]
    fn datacenter_heuristic() {
        assert!(is_datacenter_org("AS16509 Amazon.com, Inc."));
        assert!(is_datacenter_org("GOOGLE-CLOUD"));
        assert!(is_datacenter_org("DigitalOcean, LLC"));
        assert!(!is_datacenter_org("AS1234 Comcast Residential"));
    }
}
