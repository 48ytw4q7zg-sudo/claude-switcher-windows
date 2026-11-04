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

/// 解析 cloudflare trace（`key=value` 行）：(ip, loc, tz)。
pub fn parse_cloudflare_trace(text: &str) -> Option<(String, String, String)> {
    let mut ip = None;
    let mut loc = None;
    let mut tz = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "ip" if !value.is_empty() => ip = Some(value.to_string()),
            "loc" if !value.is_empty() => loc = Some(value.to_uppercase()),
            "tz" if !value.is_empty() => tz = Some(value.to_string()),
            _ => {}
        }
    }
    Some((ip?, loc?, tz?))
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
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP 客户端初始化失败: {e}"))
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
        if let Some((ip, country, tz)) = parse_cloudflare_trace(text) {
            // P1-02：只有 ipinfo 返回同一 IP 时才合并 org。
            let ipinfo_parsed = ipinfo_value.as_ref().and_then(parse_ipinfo);
            let org = merge_org_if_same_ip(
                (&ip, &country, &tz),
                ipinfo_parsed
                    .as_ref()
                    .map(|(i, c, t, o)| (i.as_str(), c.as_str(), t.as_str(), o.as_deref())),
            );
            return Ok(EgressInfo {
                ip,
                country,
                iana_tz: tz,
                org,
                source: "cloudflare".to_string(),
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
        let (ip, loc, tz) = parse_cloudflare_trace(text).expect("parse");
        assert_eq!(ip, "203.0.113.9");
        assert_eq!(loc, "US");
        assert_eq!(tz, "America/New_York");
    }

    #[test]
    fn missing_field_returns_none() {
        assert!(parse_cloudflare_trace("loc=us\ntz=America/New_York\n").is_none());
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
