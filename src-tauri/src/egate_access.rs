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
    /// **P1-03**：本次读取是否**完整成功**。
    ///
    /// `false` 表示键打不开或某个值读失败（权限被拒、注册表结构异常、
    /// 组策略重定向）。此时其余字段只是「能读到的那部分」，
    /// 判定层必须据此给出 `Unknown`，**不能**把「读不到」当成
    /// `ProxyEnable = 0`（= 直连）——那会把用户推向未接入路径的熔断。
    pub complete: bool,
    /// **P1-03**：读取失败的具体原因（仅用于界面与日志）。
    pub error: Option<String>,
}

impl ProxyEvidence {
    /// 读取失败（含部分字段缺失）时返回原因。
    pub fn read_error(&self) -> Option<&str> {
        if self.complete {
            None
        } else {
            self.error.as_deref().or(Some("注册表读取不完整"))
        }
    }

    /// 一份「明确读失败」的证据（不臆造任何字段）。
    pub fn unreadable(reason: impl Into<String>) -> Self {
        ProxyEvidence {
            complete: false,
            error: Some(reason.into()),
            ..ProxyEvidence::default()
        }
    }
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
            AccessPath::Tun { .. } => "TUN 直连（路由未证实）",
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
///
/// **P1-03**：注册表读不出来时**不能**落回「系统代理关闭 + 无 TUN = 未接入」。
/// 那个结论会触发兜底封锁甚至熔断（结束用户正在用的桌面应用），
/// 而依据只是「查询失败」。因此读取不完整一律 `Unknown`。
pub fn verdict(
    evidence: &ProxyEvidence,
    tun_adapter: Option<String>,
    hosts: &[String],
) -> AccessPath {
    if let Some(reason) = evidence.read_error() {
        return AccessPath::Unknown {
            reason: format!("系统代理配置读取失败（{reason}），无法确认应用出口路径"),
        };
    }
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
    /// 直连探测：**已用路由证据证明**目标流量会走 TUN（与应用同路）。
    ///
    /// 只有 [`plan_route_with_evidence`] 在拿到明确路由证据时才产生它。
    /// 「看到了 TUN 网卡」本身**不够**——Clash 退出后网卡可能残留，
    /// IPv6 也可能没被接管。
    Direct,
    /// 不探测——守护器自身流量绝不带着家宽 IP 出机器。
    Skip,
}

/// **P1-01**：目标路由证据（由平台层采集，纯数据便于单测）。
///
/// 语义是「目标地址的下一跳是否确定经过 TUN 接口」。任何一项读不出来
/// 都是 **Unverified**，不是「大概走了」。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteEvidence {
    /// 目标是否 IPv4 且其路由出接口就是 TUN 的 ifIndex。
    pub ipv4_via_tun: Option<bool>,
    /// 目标是否 IPv6 且其路由出接口就是 TUN 的 ifIndex。
    pub ipv6_via_tun: Option<bool>,
    /// TUN 是否接管了默认路由（0.0.0.0/0 或 ::/0）。
    pub default_route_via_tun: Option<bool>,
    /// 采集失败的原因（用于界面说明）。
    pub error: Option<String>,
}

impl RouteEvidence {
    /// 是否**完整**证明目标流量经过 TUN。
    ///
    /// 规则刻意保守：只有 IPv4 与默认路由两项都明确为真才算证明。
    /// IPv6 允许「系统未启用 IPv6」——那种情况下不存在 IPv6 旁路，
    /// 但必须是**明确读到未启用**，不能是查询失败。
    pub fn proves_tun_path(&self) -> bool {
        self.error.is_none()
            && self.ipv4_via_tun == Some(true)
            && self.default_route_via_tun == Some(true)
            && self.ipv6_via_tun.is_some()
    }

    /// 无法证明时的人类可读原因。
    pub fn unverified_reason(&self) -> String {
        if let Some(error) = &self.error {
            return format!("路由证据采集失败：{error}");
        }
        let mut parts = Vec::new();
        if self.ipv4_via_tun != Some(true) {
            parts.push("IPv4 目标路由未经 TUN");
        }
        if self.default_route_via_tun != Some(true) {
            parts.push("默认路由未由 TUN 接管");
        }
        if self.ipv6_via_tun.is_none() {
            parts.push("IPv6 路由状态无法确认");
        }
        parts.join("；")
    }
}

/// 由接入方式决定探测路由（纯函数，**无路由证据**）。
///
/// **P0-07 / P1-01**：只检测到 TUN 网卡存在不足以证明目标流量真的经过它。
/// 因此这个入口对 TUN 一律 `Skip`；需要放行必须显式提供
/// [`RouteEvidence`]（见 [`plan_route_with_evidence`]）。
pub fn plan_route(path: &AccessPath) -> ProbeRoute {
    plan_route_with_evidence(path, None)
}

/// 带路由证据的探测决策。
///
/// 只有在「接入是 TUN」且「路由证据完整证明流量经 TUN」时才 `Direct`。
/// 其余一律 `Skip`——保持 `Unverified`，绝不冒险发直连请求。
pub fn plan_route_with_evidence(path: &AccessPath, evidence: Option<&RouteEvidence>) -> ProbeRoute {
    match path {
        AccessPath::SystemProxy { addr } => ProbeRoute::Proxy(format!("http://{addr}")),
        AccessPath::Tun { .. } => match evidence {
            Some(evidence) if evidence.proves_tun_path() => ProbeRoute::Direct,
            _ => ProbeRoute::Skip,
        },
        AccessPath::Uncovered | AccessPath::Unknown { .. } => ProbeRoute::Skip,
    }
}

/// 是否为回环地址（`127.0.0.1` / `localhost` / `[::1]`）。
///
/// 只有回环代理才适合做端口探测：对外部主机做 TCP connect 等于主动探测第三方。
pub fn is_loopback_host(addr: &str) -> bool {
    let host = match addr.rsplit_once(':') {
        Some((host, _)) => host.trim_matches(|c| c == '[' || c == ']'),
        None => addr,
    };
    let host = host.to_ascii_lowercase();
    host == "localhost" || host == "::1" || host.starts_with("127.") || host == "0.0.0.0"
}

/// **P0-13**：探测本地代理端口是否真的可连接。
///
/// 「内核进程存在」不等于「代理在监听」：Clash 崩溃重启中、端口被改、
/// 或被别的程序占用时，进程还在但代理不可用。保镖若只看进程名，
/// 就会把这种状态判成「接入正常」而放行。
///
/// 只做**一次** TCP connect（超时 300ms），不做 HTTP 请求——真实出口是否
/// 经过代理仍由门禁的显式代理探测决定，不能把"端口通"当成"出口已验证"。
pub fn proxy_port_reachable(addr: &str) -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    let Ok(mut addrs) = addr.to_socket_addrs() else {
        return false;
    };
    let Some(socket) = addrs.next() else {
        return false;
    };
    TcpStream::connect_timeout(&socket, std::time::Duration::from_millis(300)).is_ok()
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
            // 测试里的证据是「读取成功」的显式构造。
            complete: true,
            error: None,
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
        // P0-07：TUN 保守策略——路由未证实，不做直连探测。
        assert_eq!(
            plan_route(&AccessPath::Tun {
                adapter: "Mihomo".to_string()
            }),
            ProbeRoute::Skip,
            "TUN 存在不等于路由经过它，不应直连探测"
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

    // ── P0-13：本地代理端口探测 ──

    #[test]
    fn loopback_host_detection() {
        for addr in [
            "127.0.0.1:7890",
            "127.1.2.3:1080",
            "localhost:8080",
            "[::1]:7890",
        ] {
            assert!(is_loopback_host(addr), "{addr} 应判定为回环");
        }
        for addr in ["10.0.0.5:7890", "192.168.1.1:80", "proxy.example.com:8080"] {
            assert!(!is_loopback_host(addr), "{addr} 不应判定为回环");
        }
    }

    /// 关闭的端口必须判为不可达；这直接决定保镖会不会误判「代理可用」。
    ///
    /// 用一个**必然连不上**的地址：`192.0.2.0/24` 是 RFC 5737 保留的文档网段，
    /// 不会有主机响应；300ms 超时后必须返回 false。
    #[test]
    fn unreachable_endpoint_is_not_reachable() {
        // 先占一个端口再释放，得到本机上一个确定没有监听者的端口号。
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = listener.local_addr().unwrap().to_string();
        drop(listener);
        assert!(
            !proxy_port_reachable(&closed),
            "本机已关闭的端口必须判为不可达（否则保镖会把断开的代理当成可用）"
        );
        // 非法输入也不能 panic，只能返回 false。
        assert!(!proxy_port_reachable(""));
        assert!(!proxy_port_reachable("127.0.0.1"));
    }

    /// 本机实际监听的端口必须判为可达。
    #[test]
    fn listening_port_is_reachable() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        assert!(proxy_port_reachable(&addr), "{addr} 在监听，应判为可达");
        drop(listener);
    }
}
