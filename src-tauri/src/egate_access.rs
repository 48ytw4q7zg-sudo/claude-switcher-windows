//! 出口门禁的接入路径判定（融合 ClaudeGuard `src/access.rs`）。
//!
//! 为什么需要它：Claude 等桌面应用只认**系统代理**。系统代理没开时它们直连
//! 真实出口——此时守护器把代理出口测得再准也管不到应用本体。因此除了校验
//! 每个目标的出口，还要判定「应用此刻是否真的接在代理/TUN 上」。
//!
//! 行为基准：ClaudeGuard `src/access.rs`（固定 commit `1967377`）。语义要点：
//! - 系统代理开且地址可用 → `SystemProxy`（探测走该地址）；
//! - 系统代理关但有 Up 的 TUN 网卡 → `Tun`（直连，被 TUN 接管，与应用同路）；
//! - 两者都没有 → `Uncovered`（应用直连真实出口，**守护器自身也不探测**——
//!   任何状态下都不把家宽 IP 带出机器）；
//! - PAC / SOCKS / 缺地址 / 绕过列表命中被监控域名 → `Unknown`（不熔断但禁止启动）。
//!
//! 绕过列表判定刻意保守：只把命中被监控主机名或 AI 服务后缀的条目当作风险，
//! `127.*`、`10.*`、`192.168.*`、`<local>`、`*.local` 这类本机/私网条目一律不影响
//! 判定——Windows 上几乎每台机器都有它们，一律当「无法确认」会永远拒绝启动。

use serde::{Deserialize, Serialize};

/// TUN 虚拟网卡关键词（命中且未命中排除项即视为 TUN 接入）。
const TUN_KEYWORDS: &[&str] = &[
    "mihomo",
    "clash",
    "meta",
    "sing-box",
    "singbox",
    "wintun",
    "wireguard",
    "openvpn",
    "tap-windows",
    "tun2socks",
    "bettbox",
    "hysteria",
    "juicity",
    "v2ray",
    "xray",
];

/// 排除项：默认不是全隧道的虚拟网卡，命中不算 TUN 接入。
const TUN_EXCLUDES: &[&str] = &["tailscale"];

/// 被监控应用实际会连的服务域名后缀：绕过列表命中这些才算「可能直连」。
const SENSITIVE_SUFFIXES: &[&str] = &[
    "anthropic.com",
    "claude.ai",
    "openai.com",
    "chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "googleapis.com",
    "google.com",
];

/// 适配器描述/友好名是否像 TUN 虚拟网卡。
pub fn is_tun_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    if TUN_EXCLUDES.iter().any(|kw| lower.contains(kw)) {
        return false;
    }
    lower.starts_with("utun") || TUN_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// 从候选适配器里挑出正在 Up 的 TUN 网卡。
/// 入参为（描述，友好名，是否 Up）；返回命中的名字。
pub fn select_tun(adapters: &[(String, String, bool)]) -> Option<String> {
    for (desc, friendly, up) in adapters {
        if !*up {
            continue;
        }
        if is_tun_name(desc) {
            return Some(desc.clone());
        }
        if is_tun_name(friendly) {
            return Some(friendly.clone());
        }
    }
    None
}

/// 注册表里读到的代理配置（纯数据，便于单测）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxyEvidence {
    /// `ProxyEnable`。
    pub enable: bool,
    /// `ProxyServer` 原始值。
    pub server: Option<String>,
    /// `AutoConfigURL`（PAC 脚本地址）。
    pub autoconfig: Option<String>,
    /// `ProxyOverride`（绕过列表）。
    pub overrides: Option<String>,
}

/// 应用当前的接入方式判定（纯函数）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessPath {
    /// 系统代理开启且地址可用。
    SystemProxy { addr: String },
    /// 系统代理关闭，但存在 Up 的 TUN 虚拟网卡。
    Tun { adapter: String },
    /// 系统代理关闭且无 TUN：应用直连真实出口。
    Uncovered,
    /// 配置不足以确认应用实际走哪条路。
    Unknown { reason: String },
}

impl AccessPath {
    /// 未接入（系统代理关 + 无 TUN）。
    pub fn is_uncovered(&self) -> bool {
        matches!(self, AccessPath::Uncovered)
    }

    /// 接入路径无法确认（不熔断，但禁止启动）。
    pub fn is_unknown(&self) -> bool {
        matches!(self, AccessPath::Unknown { .. })
    }

    /// 已确认接入（系统代理或 TUN）。
    pub fn is_known(&self) -> bool {
        matches!(
            self,
            AccessPath::SystemProxy { .. } | AccessPath::Tun { .. }
        )
    }

    /// 界面与 `--check` 用的标签。
    pub fn label(&self) -> &'static str {
        match self {
            AccessPath::SystemProxy { .. } => "系统代理",
            AccessPath::Tun { .. } => "TUN 直连",
            AccessPath::Uncovered => "未接入代理",
            AccessPath::Unknown { .. } => "无法确认",
        }
    }

    /// 说明文本。
    pub fn note(&self) -> String {
        match self {
            AccessPath::SystemProxy { addr } => format!("系统代理 {addr}"),
            AccessPath::Tun { adapter } => format!("TUN 直连（{}）", adapter.trim()),
            AccessPath::Uncovered => {
                "系统代理未开启且未检测到 TUN 网卡，应用会直连真实出口".to_string()
            }
            AccessPath::Unknown { reason } => reason.clone(),
        }
    }
}

/// 由注册表证据 + TUN 探测结果判定接入方式。
pub fn verdict(
    evidence: &ProxyEvidence,
    tun_adapter: Option<String>,
    hosts: &[String],
) -> AccessPath {
    if let Some(pac) = evidence
        .autoconfig
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return AccessPath::Unknown {
            reason: format!("检测到 PAC 自动配置（{pac}），无法确认应用实际出口"),
        };
    }
    if !evidence.enable {
        return match tun_adapter {
            Some(adapter) => AccessPath::Tun { adapter },
            None => AccessPath::Uncovered,
        };
    }
    match parse_proxy_server(evidence.server.as_deref()) {
        ProxyParse::Http(addr) => {
            if bypass_all(evidence.overrides.as_deref()) {
                // 全部绕过代理 = 应用直连，与未接入同义。
                AccessPath::Uncovered
            } else if let Some(entry) = bypass_risk(evidence.overrides.as_deref(), hosts) {
                AccessPath::Unknown {
                    reason: format!("代理绕过列表含 {entry}，被监控流量可能直连"),
                }
            } else {
                AccessPath::SystemProxy { addr }
            }
        }
        ProxyParse::Unsupported(why) => AccessPath::Unknown {
            reason: format!("系统代理配置无法等价复用：{why}"),
        },
        ProxyParse::Empty => AccessPath::Unknown {
            reason: "系统代理已开启但未读到代理地址".to_string(),
        },
    }
}

/// 探测路由决定。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeRoute {
    /// 经该地址探测。
    Proxy(String),
    /// 直连探测（TUN 接管，与应用同路）。
    Direct,
    /// 不探测——守护器自身流量绝不带着家宽 IP 出机器。
    Skip,
}

/// 由接入方式决定探测路由（纯函数）。
pub fn plan_route(path: &AccessPath) -> ProbeRoute {
    match path {
        AccessPath::SystemProxy { addr } => ProbeRoute::Proxy(format!("http://{addr}")),
        AccessPath::Tun { .. } => ProbeRoute::Direct,
        AccessPath::Uncovered | AccessPath::Unknown { .. } => ProbeRoute::Skip,
    }
}

/// `ProxyServer` 解析结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyParse {
    /// HTTP 代理地址 `host:port`。
    Http(String),
    /// 已开启但读不到地址。
    Empty,
    /// 不支持的形态（socks / 只有 http 段等）。
    Unsupported(String),
}

/// 解析 `ProxyServer`：支持 `host:port` 与 `http=..;https=..` 分号形式（https 优先）。
pub fn parse_proxy_server(raw: Option<&str>) -> ProxyParse {
    let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return ProxyParse::Empty;
    };
    // 分号分段形式：取 https 段，回退 http 段。
    if raw.contains('=') {
        let mut http = None;
        let mut https = None;
        for part in raw.split(';') {
            let Some((key, value)) = part.split_once('=') else {
                continue;
            };
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            match key.trim().to_ascii_lowercase().as_str() {
                "https" => https = Some(value.to_string()),
                "http" => http = Some(value.to_string()),
                other => {
                    return ProxyParse::Unsupported(format!("不支持的代理段 {other}"));
                }
            }
        }
        return match https.or(http) {
            Some(addr) => check_addr(addr),
            None => ProxyParse::Empty,
        };
    }
    if raw.contains("://") {
        return ProxyParse::Unsupported("代理地址不应带协议前缀".to_string());
    }
    check_addr(raw.to_string())
}

/// 校验 `host:port`（端口必须显式且有效；只认 http 形态，socks 交给 Unsupported）。
fn check_addr(addr: String) -> ProxyParse {
    let Some((host, port)) = addr.rsplit_once(':') else {
        return ProxyParse::Unsupported("代理地址缺少端口".to_string());
    };
    if host.trim().is_empty() {
        return ProxyParse::Unsupported("代理地址缺少主机".to_string());
    }
    match port.trim().parse::<u16>() {
        Ok(port) if port > 0 => ProxyParse::Http(format!("{}:{port}", host.trim())),
        _ => ProxyParse::Unsupported("代理端口无效".to_string()),
    }
}

/// 拆分绕过列表条目。
pub fn bypass_entries(raw: Option<&str>) -> Vec<String> {
    raw.map(|raw| {
        raw.split(';')
            .map(|entry| entry.trim().to_string())
            .filter(|entry| !entry.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

/// 是否「全部绕过」（`*` 或空列表都意味着没有代理）。
pub fn bypass_all(raw: Option<&str>) -> bool {
    match raw.map(str::trim) {
        None => false,
        Some("") => false,
        Some(list) => bypass_entries(Some(list)).iter().any(|e| e == "*"),
    }
}

/// 去掉通配前缀，取出条目里的域名部分（`*.claude.ai`、`*claude.ai` → `claude.ai`）。
fn entry_domain(entry: &str) -> String {
    entry
        .trim()
        .trim_start_matches('*')
        .trim_start_matches('.')
        .to_string()
}

/// 条目是否只覆盖本机 / 私网 / 链路本地——这类地址不可能让公网流量直连。
pub fn bypass_local_entry(entry: &str) -> bool {
    let e = entry.trim().to_ascii_lowercase();
    match e.as_str() {
        "<local>" | "localhost" | "localhost.*" | "*.localhost" | "*.local" | "[::1]" | "::1" => {
            return true
        }
        _ => {}
    }
    let Some(prefix) = e.strip_suffix(".*") else {
        return false;
    };
    let octets: Vec<u8> = prefix
        .split('.')
        .map(|v| v.parse::<u8>().ok())
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    match octets.as_slice() {
        [10] | [127] => true,
        [192, 168] | [169, 254] => true,
        [172, second] => (16..=31).contains(second),
        _ => false,
    }
}

/// 绕过条目是否会命中给定主机名（`*` 由 `bypass_all` 单独处理）。
pub fn bypass_hits_host(entry: &str, host: &str) -> bool {
    let domain = entry_domain(entry);
    if domain.is_empty() {
        return true;
    }
    let host = host.trim().to_ascii_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// 绕过列表里是否存在会让被监控流量直连的条目；返回该条目。
pub fn bypass_risk(raw: Option<&str>, hosts: &[String]) -> Option<String> {
    for entry in bypass_entries(raw) {
        if entry == "*" || bypass_local_entry(&entry) {
            continue;
        }
        if hosts.iter().any(|h| bypass_hits_host(&entry, h)) {
            return Some(entry);
        }
        if SENSITIVE_SUFFIXES
            .iter()
            .any(|suffix| bypass_hits_host(&entry, suffix))
        {
            return Some(entry);
        }
    }
    None
}

/// 从探测地址里取主机名（小写）。
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.trim();
    let rest = rest
        .strip_prefix("https://")
        .or_else(|| rest.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // userinfo 段不是主机名（与 egate_probe 的 URL 校验同一原则）。
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// 接入快照（推给界面与 `--check`）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessInfo {
    /// system_proxy | tun | uncovered | unknown。
    pub path: String,
    pub note: String,
}

impl From<&AccessPath> for AccessInfo {
    fn from(path: &AccessPath) -> Self {
        Self {
            path: match path {
                AccessPath::SystemProxy { .. } => "system_proxy",
                AccessPath::Tun { .. } => "tun",
                AccessPath::Uncovered => "uncovered",
                AccessPath::Unknown { .. } => "unknown",
            }
            .to_string(),
            note: path.note(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(enable: bool, server: Option<&str>, overrides: Option<&str>) -> ProxyEvidence {
        ProxyEvidence {
            enable,
            server: server.map(str::to_string),
            autoconfig: None,
            overrides: overrides.map(str::to_string),
        }
    }

    // ── TUN 识别 ──

    #[test]
    fn tun_keywords_match_common_clients() {
        for name in [
            "Mihomo",
            "Clash Verge",
            "sing-box tun",
            "Wintun Userspace Tunnel",
            "WireGuard Tunnel",
            "utun3",
            "Meta",
        ] {
            assert!(is_tun_name(name), "应识别为 TUN：{name}");
        }
    }

    #[test]
    fn tailscale_is_not_treated_as_tun() {
        assert!(!is_tun_name("Tailscale"), "Tailscale 默认不是全隧道");
        assert!(!is_tun_name("Ethernet"));
    }

    #[test]
    fn select_tun_skips_down_adapters() {
        let adapters = vec![
            ("Mihomo".to_string(), "Mihomo".to_string(), false),
            ("Ethernet".to_string(), "以太网".to_string(), true),
            ("WireGuard Tunnel".to_string(), "wg0".to_string(), true),
        ];
        assert_eq!(
            select_tun(&adapters).as_deref(),
            Some("WireGuard Tunnel"),
            "只认 Up 状态的 TUN"
        );
        assert!(select_tun(&[("Mihomo".to_string(), "m".to_string(), false)]).is_none());
    }

    // ── 接入判定矩阵 ──

    #[test]
    fn system_proxy_enabled_with_address() {
        let path = verdict(&evidence(true, Some("127.0.0.1:7890"), None), None, &[]);
        assert_eq!(
            path,
            AccessPath::SystemProxy {
                addr: "127.0.0.1:7890".to_string()
            }
        );
        assert!(path.is_known());
    }

    #[test]
    fn semicolon_form_prefers_https_segment() {
        let path = verdict(
            &evidence(true, Some("http=127.0.0.1:7890;https=127.0.0.1:7891"), None),
            None,
            &[],
        );
        assert_eq!(
            path,
            AccessPath::SystemProxy {
                addr: "127.0.0.1:7891".to_string()
            }
        );
    }

    #[test]
    fn proxy_disabled_with_tun_is_tun_path() {
        let path = verdict(
            &evidence(false, None, None),
            Some("Mihomo".to_string()),
            &[],
        );
        assert_eq!(
            path,
            AccessPath::Tun {
                adapter: "Mihomo".to_string()
            }
        );
    }

    #[test]
    fn proxy_disabled_without_tun_is_uncovered() {
        let path = verdict(&evidence(false, None, None), None, &[]);
        assert!(path.is_uncovered());
        assert_eq!(plan_route(&path), ProbeRoute::Skip, "未接入时绝不探测");
    }

    #[test]
    fn pac_autoconfig_is_unknown() {
        let mut e = evidence(true, Some("127.0.0.1:7890"), None);
        e.autoconfig = Some("http://127.0.0.1:7891/pac.js".to_string());
        let path = verdict(&e, None, &[]);
        assert!(path.is_unknown());
        assert!(path.note().contains("PAC"));
    }

    #[test]
    fn wildcard_bypass_means_uncovered() {
        let path = verdict(
            &evidence(true, Some("127.0.0.1:7890"), Some("*")),
            None,
            &[],
        );
        assert!(path.is_uncovered(), "全部绕过等于没代理");
    }

    #[test]
    fn local_only_bypass_does_not_block() {
        // Windows 几乎每台机器都有这些条目：不能因此判为无法确认。
        let path = verdict(
            &evidence(
                true,
                Some("127.0.0.1:7890"),
                Some("127.*;10.*;192.168.*;172.16.*;<local>;*.local;localhost"),
            ),
            None,
            &["claude.ai".to_string()],
        );
        assert!(path.is_known(), "仅本机/私网绕过不应影响判定：{path:?}");
    }

    #[test]
    fn bypass_hitting_monitored_host_is_unknown() {
        let path = verdict(
            &evidence(true, Some("127.0.0.1:7890"), Some("*.claude.ai")),
            None,
            &["claude.ai".to_string()],
        );
        assert!(path.is_unknown(), "绕过被监控域名时无法确认出口");
    }

    #[test]
    fn bypass_hitting_ai_suffix_is_unknown_even_without_host_list() {
        let path = verdict(
            &evidence(true, Some("127.0.0.1:7890"), Some("anthropic.com")),
            None,
            &[],
        );
        assert!(path.is_unknown());
    }

    #[test]
    fn unrelated_public_bypass_entry_is_ignored() {
        let path = verdict(
            &evidence(true, Some("127.0.0.1:7890"), Some("shopping.example.com")),
            None,
            &["claude.ai".to_string()],
        );
        assert!(path.is_known(), "无关公网域名不应影响判定");
    }

    #[test]
    fn missing_address_is_unknown() {
        assert!(verdict(&evidence(true, None, None), None, &[]).is_unknown());
        assert!(verdict(&evidence(true, Some("  "), None), None, &[]).is_unknown());
    }

    #[test]
    fn socks_and_bad_port_are_unsupported() {
        assert!(verdict(
            &evidence(true, Some("socks5://127.0.0.1:7890"), None),
            None,
            &[]
        )
        .is_unknown());
        assert!(verdict(&evidence(true, Some("127.0.0.1"), None), None, &[]).is_unknown());
        assert!(verdict(&evidence(true, Some("127.0.0.1:abc"), None), None, &[]).is_unknown());
    }

    // ── 路由 ──

    #[test]
    fn route_follows_access_path() {
        assert_eq!(
            plan_route(&AccessPath::SystemProxy {
                addr: "127.0.0.1:7890".to_string()
            }),
            ProbeRoute::Proxy("http://127.0.0.1:7890".to_string())
        );
        assert_eq!(
            plan_route(&AccessPath::Tun {
                adapter: "Mihomo".to_string()
            }),
            ProbeRoute::Direct
        );
        assert_eq!(
            plan_route(&AccessPath::Unknown {
                reason: "x".to_string()
            }),
            ProbeRoute::Skip,
            "无法确认时也不探测（不把家宽 IP 带出机器）"
        );
    }

    // ── 主机名提取 ──

    #[test]
    fn host_of_strips_userinfo_and_path() {
        assert_eq!(
            host_of("https://claude.ai/cdn-cgi/trace").as_deref(),
            Some("claude.ai")
        );
        assert_eq!(
            host_of("https://user:pass@chatgpt.com:443/x?y#z").as_deref(),
            Some("chatgpt.com")
        );
        assert_eq!(host_of("not-a-url"), None);
    }

    #[test]
    fn bypass_hits_host_matches_subdomains() {
        assert!(bypass_hits_host("claude.ai", "claude.ai"));
        assert!(bypass_hits_host("*.claude.ai", "api.claude.ai"));
        assert!(!bypass_hits_host("claude.ai", "notclaude.ai"));
    }
}
