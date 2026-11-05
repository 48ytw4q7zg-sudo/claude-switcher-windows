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
            } else {
                match bypass_verdict(evidence.overrides.as_deref(), hosts) {
                    // **P0-09 / L-10**：明确绕过风险 -> 不能当成「代理已覆盖」。
                    BypassVerdict::Risk(entry) => AccessPath::Unknown {
                        reason: format!("代理绕过列表含 {entry}，被监控流量可能绕过代理直连"),
                    },
                    // **L-10**：看不懂的绕过语法不得当成无风险。
                    BypassVerdict::Unknown(detail) => AccessPath::Unknown {
                        reason: format!(
                            "代理绕过列表含无法识别的条目（{detail}），无法确认受监控域名是否被绕过"
                        ),
                    },
                    BypassVerdict::NoRisk => AccessPath::SystemProxy { addr },
                }
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

/// **P1-01 / P0-01（v0.7.3）**：单个协议族的 IPv6 状态。
///
/// 不能再用一个 `Option<bool>` 同时表达「经过 TUN」「确认旁路」「系统没有
/// IPv6」——`Some(false).is_some()` 恒为真，会让「明确 IPv6 旁路」被当成
/// 「可以放行」。三种状态必须分开。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RouteVia {
    /// 该协议族的出接口就是 TUN，且默认路由由 TUN 接管。
    Tun,
    /// 明确**不**经过 TUN（存在可利用的旁路）。
    Bypass,
    /// 系统确实没有该协议族的可用外发路径（例如 IPv6 未绑定）。
    /// 这种情况不存在旁路，可以视为「无需检查」，但必须是**明确读到**。
    NotAvailable,
    /// 无法确认（**默认值**：未取证时的安全缺省）。
    #[default]
    Unknown,
}

impl RouteVia {
    /// 该协议族是否可以安全地直连探测。
    pub fn is_safe(self) -> bool {
        matches!(self, RouteVia::Tun | RouteVia::NotAvailable)
    }

    fn label(self, family: &str) -> Option<&'static str> {
        match self {
            RouteVia::Tun | RouteVia::NotAvailable => None,
            RouteVia::Bypass => Some(match family {
                "IPv4" => "IPv4 目标路由未经 TUN（存在旁路）",
                _ => "发现 IPv6 旁路：目标 IPv6 流量不经过 TUN",
            }),
            RouteVia::Unknown => Some(match family {
                "IPv4" => "IPv4 路由状态无法确认",
                _ => "IPv6 路由状态无法确认",
            }),
        }
    }
}

/// **P1-01**：单个目标的 TUN 路由证据（由平台层采集，纯数据便于单测）。
///
/// **P0-02（v0.7.3）**：证据从「整轮一份」改为**每个目标一份**。
/// 原来只拿第一个启用目标的主机名取证，却用这份证据放行**所有**目标的直连
/// 探测——目标 A 走 TUN、目标 B 走物理网卡时会一起被放行。
///
/// **P0-03**：证据里同时记录「解析是否可信」。目标地址来自系统 DNS，
/// 而 DNS 查询本身可能已经绕过了 TUN；无法确认 DNS 路径时不得声称
/// 「路由已证明」，因为验证的地址可能与实际连接的地址不一致。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteEvidence {
    /// 归属的目标 ID（证据不可跨目标复用）。
    pub target_id: String,
    /// IPv4 的出接口/默认路由判定。
    pub ipv4: RouteVia,
    /// IPv6 的出接口/默认路由判定。
    pub ipv6: RouteVia,
    /// 该目标的 DNS 解析是否走了可信路径（TUN/代理）。
    ///
    /// `false` 表示「解析结果不可作为安全依据」：即便 IP 路由看起来经过 TUN，
    /// 也不能证明「解析这个域名时没有把真实出口暴露给 DNS」。
    pub dns_trusted: bool,
    /// 采集失败/不可信的原因（用于界面说明）。
    pub error: Option<String>,
}

impl RouteEvidence {
    /// 一个「无法证明」的证据（任何一项缺失都用它兜底，绝不乐观推断）。
    pub fn unknown(target_id: impl Into<String>, reason: impl Into<String>) -> Self {
        RouteEvidence {
            target_id: target_id.into(),
            ipv4: RouteVia::Unknown,
            ipv6: RouteVia::Unknown,
            dns_trusted: false,
            error: Some(reason.into()),
        }
    }

    /// 是否**完整**证明该目标流量经过 TUN。
    ///
    /// 四项必须同时成立：
    /// 1. 没有采集错误；
    /// 2. IPv4 经 TUN（或明确无 IPv4 路径——实际上不可能，故要求 Tun）；
    /// 3. IPv6 经 TUN，或**明确**没有 IPv6（旁路一律拒绝）；
    /// 4. DNS 解析路径可信。
    pub fn proves_tun_path(&self) -> bool {
        self.error.is_none()
            && self.dns_trusted
            && self.ipv4 == RouteVia::Tun
            && self.ipv6.is_safe()
    }

    /// 无法证明时的人类可读原因（明确旁路必须说出「旁路」，不能返回空串）。
    pub fn unverified_reason(&self) -> String {
        if let Some(error) = &self.error {
            return format!("路由证据采集失败：{error}");
        }
        let mut parts = Vec::new();
        if !self.dns_trusted {
            parts.push("DNS 解析路径未经证实，解析结果不能作为路由依据");
        }
        for family in ["IPv4", "IPv6"] {
            let via = if family == "IPv4" {
                self.ipv4
            } else {
                self.ipv6
            };
            if let Some(label) = via.label(family) {
                parts.push(label);
            }
        }
        if parts.is_empty() {
            "路由证据不完整".to_string()
        } else {
            parts.join("；")
        }
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
///
/// **P0-01（v0.7.3）**：判据收敛到 [`RouteEvidence::proves_tun_path`] 一处，
/// 并在这里**再查一遍** `dns_trusted`——探测入口是最后一道闸门，
/// 不能因为上游改了什么就悄悄放行。
pub fn plan_route_with_evidence(path: &AccessPath, evidence: Option<&RouteEvidence>) -> ProbeRoute {
    match path {
        AccessPath::SystemProxy { addr } => ProbeRoute::Proxy(format!("http://{addr}")),
        AccessPath::Tun { .. } => match evidence {
            Some(evidence) if evidence.proves_tun_path() && evidence.dns_trusted => {
                ProbeRoute::Direct
            }
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

/// **P0-09（v0.7.6）**：`ProxyOverride` 条目的语义分类。
///
/// v0.7.5 的 `entry_domain()` 只做 `trim_start_matches('*')` 再按域名后缀
/// 匹配，于是 `*claude*` 变成 `claude*`（尾部 `*` 残留）→ 永不命中
/// `claude.ai`。而 Windows WinINet **确实支持** `*int*` / `*claude*` 这类
/// 中间通配，会让匹配域名绕过代理直连——门禁却判为「代理已覆盖」。
///
/// 现在按 Windows 认可的语法分类，不认得的一律 `Unrecognized`
/// （**不得**默认判为无风险）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum BypassEntry {
    /// `*`：全部绕过代理。
    MatchAll,
    /// `<local>`：内网主机名（无点号）绕过。
    Local,
    /// `<-loopback>`：显式声明回环**不**绕过（本身不是绕过规则）。
    NoLoopback,
    /// 含 `*` 的通配模式：`*claude*` / `*.claude.ai` / `claude.*`。
    Wildcard(String),
    /// 字面域名：按 Windows 语义匹配域名本身与子域。
    Literal(String),
    /// IP 字面量 / IP 段 / CIDR：只对**指向裸 IP** 的连接生效。
    IpRange(String),
    /// 无法理解的语法 → 调用方必须按「无法确认」处理。
    Unrecognized(String),
}

/// 解析 `ProxyOverride` 的原始串（分号分隔）。
fn parse_bypass_entries(raw: Option<&str>) -> Vec<BypassEntry> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    raw.split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(classify_bypass_entry)
        .collect()
}

/// 单条绕过条目的分类（**P0-09**：宁可标 Unrecognized，也不乐观放行）。
fn classify_bypass_entry(entry: &str) -> BypassEntry {
    let trimmed = entry.trim();
    let lower = trimmed.to_ascii_lowercase();
    match lower.as_str() {
        "*" => return BypassEntry::MatchAll,
        "<local>" | "localhost" | "localhost.*" | "*.localhost" | "*.local" => {
            return BypassEntry::Local
        }
        "<-loopback>" => return BypassEntry::NoLoopback,
        "[::1]" | "::1" => return BypassEntry::Local,
        _ => {}
    }
    // 私网 / 回环 IP 段：`10.*`、`127.*`、`192.168.*`、`172.16.*` 这类
    // 在 Windows 里等价于「内网不绕过」，对按主机名的连接不构成绕过。
    if is_local_ip_range(&lower) {
        return BypassEntry::Local;
    }
    // IP 字面量 / 段 / CIDR：只对裸 IP URL 生效。
    if looks_like_ip_range(&lower) {
        return BypassEntry::IpRange(lower);
    }
    if trimmed.contains('*') {
        return BypassEntry::Wildcard(lower);
    }
    // 字面域名：必须是合法的标签序列，否则归入 Unrecognized。
    if is_domain_like(&lower) {
        return BypassEntry::Literal(lower);
    }
    BypassEntry::Unrecognized(trimmed.to_string())
}

/// 该条目是否是「内网/回环」语义（对公网主机名不构成绕过）。
fn is_local_ip_range(entry: &str) -> bool {
    let e = entry.trim().trim_end_matches(".*");
    let octets: Vec<u8> = e
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

/// 形如 IP 字面量 / `a.b.*` / `a.b.c.d/nn` / IPv6 的条目。
fn looks_like_ip_range(entry: &str) -> bool {
    let head = entry.split('/').next().unwrap_or(entry);
    if head.contains(':') {
        // IPv6 字面量（含 `::` 缩写与方括号）。
        return head.len() >= 2
            && head.chars().all(|c| {
                c.is_ascii_hexdigit() || c == ':' || c == '.' || c == '[' || c == ']' || c == '*'
            });
    }
    let parts: Vec<&str> = head.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return false;
    }
    parts
        .iter()
        .all(|part| *part == "*" || part.parse::<u8>().is_ok())
}

/// 是否是合法的域名标签序列（字母/数字/连字符，至少一个点）。
fn is_domain_like(entry: &str) -> bool {
    let e = entry.trim_matches('.').to_ascii_lowercase();
    if e.is_empty() || !e.contains('.') {
        return false;
    }
    e.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

/// **P0-09**：Windows `*` 通配语义——`*` 匹配任意长度任意字符，
/// 其余字符大小写不敏感地字面匹配（不是正则）。
fn glob_matches(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    // 标准无回溯爆炸的通配匹配（`star` 记录最近一个 `*` 的位置）。
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            pi += 1;
            mark = ti;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// 通配条目是否可能绕过该主机（含它的子域）。
///
/// 对 `*.claude.ai` 条目要能命中 `claude.ai` 本身——受管应用连的可能是
/// `api.claude.ai`，那一条会被 WinINet 绕过。保守地认为「可能绕过」即算命中。
fn wildcard_covers_host(pattern: &str, host: &str) -> bool {
    if glob_matches(pattern, host) {
        return true;
    }
    glob_matches(pattern, &format!("any.{host}"))
}

/// 单条条目是否绕过该主机名。
fn bypass_entry_hits(entry: &BypassEntry, host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    match entry {
        BypassEntry::MatchAll => true,
        BypassEntry::NoLoopback => false,
        // `<local>` 只绕过**无点号**的内网名字；带点的公网域名不受影响。
        BypassEntry::Local => !host.contains('.'),
        BypassEntry::Wildcard(pattern) => wildcard_covers_host(pattern, &host),
        BypassEntry::Literal(domain) => host == *domain || host.ends_with(&format!(".{domain}")),
        // IP 条目只对「指向裸 IP」的连接生效；按主机名的连接不受影响。
        BypassEntry::IpRange(_) => looks_like_ip_range(&host),
        // 不认得的语法：`bypass_verdict` 会把它转成 Unknown，不落入 NoRisk。
        BypassEntry::Unrecognized(_) => false,
    }
}

/// **P0-09**：绕过判定的三态结论。
#[derive(Debug, Clone, PartialEq, Eq)]
enum BypassVerdict {
    /// 确认没有绕过风险。
    NoRisk,
    /// 发现会让受监控主机绕过代理的条目。
    Risk(String),
    /// 存在无法理解的绕过语法 → **不得**当成 NoRisk。
    Unknown(String),
}

/// 判定整条绕过列表对受监控主机的风险（**P0-09 / L-10**）。
fn bypass_verdict(raw: Option<&str>, hosts: &[String]) -> BypassVerdict {
    let entries = parse_bypass_entries(raw);
    if entries.contains(&BypassEntry::MatchAll) {
        return BypassVerdict::Risk("*".to_string());
    }
    let mut unrecognized: Vec<String> = Vec::new();
    for entry in entries {
        if let BypassEntry::Unrecognized(raw_text) = &entry {
            unrecognized.push(raw_text.clone());
            continue;
        }
        let label = match &entry {
            BypassEntry::Literal(d) => d.clone(),
            BypassEntry::Wildcard(p) => p.clone(),
            BypassEntry::Local => "<local>".to_string(),
            BypassEntry::IpRange(r) => r.clone(),
            BypassEntry::MatchAll => "*".to_string(),
            BypassEntry::NoLoopback => "<-loopback>".to_string(),
            BypassEntry::Unrecognized(u) => u.clone(),
        };
        if hosts.iter().any(|h| bypass_entry_hits(&entry, h)) {
            return BypassVerdict::Risk(label);
        }
        if SENSITIVE_SUFFIXES
            .iter()
            .any(|suffix| bypass_entry_hits(&entry, suffix))
        {
            return BypassVerdict::Risk(label);
        }
    }
    if !unrecognized.is_empty() {
        return BypassVerdict::Unknown(unrecognized.join("；"));
    }
    BypassVerdict::NoRisk
}

/// 整条列表是否「全部绕过」。
fn bypass_all(raw: Option<&str>) -> bool {
    parse_bypass_entries(raw).contains(&BypassEntry::MatchAll)
}

/// 兼容旧签名的单条命中判定（测试/诊断用）。
#[allow(dead_code)]
pub fn bypass_hits_host(entry: &str, host: &str) -> bool {
    bypass_entry_hits(&classify_bypass_entry(entry), host)
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
    /// **P1-10（v0.7.3）**：TUN 路线的安全证明是否成立。
    ///
    /// 只有 `path == "tun"` 且该值为 `true` 时，接入才算**被证明有效**——
    /// 「有 TUN 网卡」不等于「流量经过 TUN」。非 TUN 路径该值为 `false`，
    /// 判定时只看 `path`。
    #[serde(default)]
    pub tun_proven: bool,
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
            // 默认不成立：调用方（run_round）在拿到逐目标证据后显式置位。
            tun_proven: false,
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

    /// **P0-09（v0.7.6）**：Windows `ProxyOverride` 通配符语义表。
    ///
    /// 回归点：v0.7.5 的 `entry_domain()` 只剥前导 `*`，于是 `*claude*` 变成
    /// `claude*`（尾部 `*` 残留）→ 永不命中 `claude.ai`，门禁把「代理被绕过」
    /// 判成「代理已覆盖」。WinINet 确实支持 `*int*` 这类中间通配。
    #[test]
    fn proxy_override_wildcards_follow_windows_semantics() {
        // 中间通配：必须命中（这是本次回归的核心）。
        assert!(bypass_hits_host("*claude*", "claude.ai"));
        assert!(bypass_hits_host("*claude*", "api.claude.ai"));
        assert!(bypass_hits_host("*chatgpt*", "chatgpt.com"));
        // 后缀通配。
        assert!(bypass_hits_host("claude.*", "claude.ai"));
        // 前缀通配：`*.claude.ai` 对 `claude.ai` 本身也算「可能绕过」
        // （应用连的是 api.claude.ai，那条会被绕过）。
        assert!(bypass_hits_host("*.claude.ai", "claude.ai"));
        assert!(bypass_hits_host("*.claude.ai", "api.claude.ai"));
        // 字面域名 + 子域。
        assert!(bypass_hits_host("claude.ai", "claude.ai"));
        assert!(bypass_hits_host("claude.ai", "api.claude.ai"));
        // 不得误伤真正无关的域名。
        //
        // 注意：星号 claude 星号 在 WinINet 语义下**也**匹配 notclaude.invalid
        // （它含有 claude 子串），那是正确行为，不是误判。
        assert!(!bypass_hits_host("*claude*", "example.invalid"));
        assert!(!bypass_hits_host("claude.*", "example.invalid"));
        assert!(!bypass_hits_host("claude.ai", "notclaude.ai"));
        // `*` 全部绕过。
        assert!(bypass_hits_host("*", "anything.example"));
    }

    /// **P0-09 / L-10**：绕过判定必须是三态，未知语法不得当无风险。
    #[test]
    fn bypass_verdict_is_three_state_and_conservative() {
        let claude = vec!["claude.ai".to_string()];
        let chatgpt = vec!["chatgpt.com".to_string()];

        // 明确风险。
        assert_eq!(
            bypass_verdict(Some("*claude*"), &claude),
            BypassVerdict::Risk("*claude*".to_string())
        );
        assert_eq!(
            bypass_verdict(Some("claude.*"), &claude),
            BypassVerdict::Risk("claude.*".to_string())
        );
        assert_eq!(
            bypass_verdict(Some("*chatgpt*"), &chatgpt),
            BypassVerdict::Risk("*chatgpt*".to_string())
        );
        // 全部绕过。
        assert_eq!(
            bypass_verdict(Some("*"), &claude),
            BypassVerdict::Risk("*".to_string())
        );

        // 无风险：无关域名、`<local>` 对公网域名、空列表。
        assert_eq!(
            bypass_verdict(Some("example.com"), &claude),
            BypassVerdict::NoRisk
        );
        assert_eq!(
            bypass_verdict(Some("<local>"), &claude),
            BypassVerdict::NoRisk
        );
        assert_eq!(bypass_verdict(Some(""), &claude), BypassVerdict::NoRisk);
        assert_eq!(bypass_verdict(None, &claude), BypassVerdict::NoRisk);
        // 内网 IP 段对公网域名不构成绕过。
        assert_eq!(
            bypass_verdict(Some("10.*;192.168.*"), &claude),
            BypassVerdict::NoRisk
        );

        // **L-10**：看不懂的语法必须是 Unknown，绝不判为 NoRisk。
        assert!(matches!(
            bypass_verdict(Some("!!weird!!"), &claude),
            BypassVerdict::Unknown(_)
        ));
        // 未知语法即使同时有明确风险，也要报风险（更严重的优先）。
        assert!(matches!(
            bypass_verdict(Some("!!weird!!;*claude*"), &claude),
            BypassVerdict::Risk(_)
        ));
    }

    /// **P0-09**：`verdict()` 必须把绕过风险映射成「无法确认」，
    /// 而不是 SystemProxy（= 认为代理已覆盖）。
    #[test]
    fn verdict_rejects_system_proxy_when_bypass_risks_monitored_host() {
        let evidence = ProxyEvidence {
            enable: true,
            server: Some("127.0.0.1:7890".to_string()),
            autoconfig: None,
            overrides: Some("*claude*".to_string()),
            complete: true,
            error: None,
        };
        let hosts = vec!["claude.ai".to_string()];
        assert!(
            verdict(&evidence, None, &hosts).is_unknown(),
            "代理绕过列表含 *claude* 时不得判为已覆盖"
        );

        let clean = ProxyEvidence {
            overrides: Some("example.com".to_string()),
            ..evidence.clone()
        };
        assert!(
            matches!(
                verdict(&clean, None, &hosts),
                AccessPath::SystemProxy { .. }
            ),
            "无关绕过条目不应影响判定"
        );
    }

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

    /// **P0-01（v0.7.3）**：TUN 证据的判定表——审计明确要求的六种组合。
    ///
    /// 关键回归：v0.7.2 用 `ipv6_via_tun.is_some()` 判定，于是
    /// `Some(false)`（**明确 IPv6 旁路**）也能通过，直接放行直连探测。
    #[test]
    fn tun_path_requires_both_families_and_trusted_dns() {
        let tun = AccessPath::Tun {
            adapter: "Mihomo".to_string(),
        };
        let base = RouteEvidence {
            target_id: "claude".to_string(),
            ipv4: RouteVia::Tun,
            ipv6: RouteVia::Tun,
            dns_trusted: true,
            error: None,
        };

        // ① 双栈都经 TUN + DNS 可信 → 允许直连探测。
        assert!(base.proves_tun_path());
        assert_eq!(
            plan_route_with_evidence(&tun, Some(&base)),
            ProbeRoute::Direct
        );

        // ② IPv6 **确认旁路** → 必须拒绝（v0.7.2 会误放行）。
        let mut bypass = base.clone();
        bypass.ipv6 = RouteVia::Bypass;
        assert!(!bypass.proves_tun_path());
        assert_eq!(
            plan_route_with_evidence(&tun, Some(&bypass)),
            ProbeRoute::Skip,
            "明确 IPv6 旁路时不得直连探测"
        );

        // ③ IPv6 未知 → 拒绝。
        let mut unknown = base.clone();
        unknown.ipv6 = RouteVia::Unknown;
        assert!(!unknown.proves_tun_path());
        assert_eq!(
            plan_route_with_evidence(&tun, Some(&unknown)),
            ProbeRoute::Skip
        );

        // ④ IPv4 未经 TUN → 拒绝。
        let mut v4_bypass = base.clone();
        v4_bypass.ipv4 = RouteVia::Bypass;
        assert!(!v4_bypass.proves_tun_path());
        assert_eq!(
            plan_route_with_evidence(&tun, Some(&v4_bypass)),
            ProbeRoute::Skip
        );

        // ⑤ IPv6 确认不可用（系统未启用 / 目标无 AAAA）→ 可进入下一步验证。
        let mut v6_absent = base.clone();
        v6_absent.ipv6 = RouteVia::NotAvailable;
        assert!(v6_absent.proves_tun_path());
        assert_eq!(
            plan_route_with_evidence(&tun, Some(&v6_absent)),
            ProbeRoute::Direct
        );

        // ⑥ DNS 路径未证实 → 一律拒绝，即使路由看起来完全正确。
        let mut dns_untrusted = base.clone();
        dns_untrusted.dns_trusted = false;
        assert!(!dns_untrusted.proves_tun_path());
        assert_eq!(
            plan_route_with_evidence(&tun, Some(&dns_untrusted)),
            ProbeRoute::Skip,
            "DNS 可能已经暴露真实出口，不能凭 IP 路由倒推安全"
        );

        // ⑦ 采集错误 → 拒绝，且原因可读。
        let broken = RouteEvidence::unknown("claude", "RPC 失败");
        assert!(!broken.proves_tun_path());
        assert!(broken.unverified_reason().contains("RPC 失败"));
    }

    /// **L-02（v0.7.3）**：`unverified_reason` 必须对「明确旁路」说出原因，
    /// 而不是返回空字符串（空串会让界面显示「未获证实：」却没有下文）。
    #[test]
    fn unverified_reason_names_the_real_blocker() {
        let bypass = RouteEvidence {
            target_id: "a".to_string(),
            ipv4: RouteVia::Tun,
            ipv6: RouteVia::Bypass,
            dns_trusted: true,
            error: None,
        };
        let reason = bypass.unverified_reason();
        assert!(!reason.is_empty(), "明确旁路必须有可读原因");
        assert!(reason.contains("IPv6 旁路"), "{reason}");

        let dns = RouteEvidence {
            dns_trusted: false,
            ..bypass.clone()
        };
        assert!(dns.unverified_reason().contains("DNS"));

        let v4 = RouteEvidence {
            ipv4: RouteVia::Bypass,
            ..bypass
        };
        assert!(v4.unverified_reason().contains("IPv4"));
    }

    /// **P0-02（v0.7.3）**：证据必须绑定目标——不同目标的证据互不通用。
    #[test]
    fn route_evidence_is_bound_to_its_target() {
        let a = RouteEvidence {
            target_id: "target-a".to_string(),
            ipv4: RouteVia::Tun,
            ipv6: RouteVia::Tun,
            dns_trusted: true,
            error: None,
        };
        let b = RouteEvidence {
            target_id: "target-b".to_string(),
            ipv4: RouteVia::Bypass,
            ipv6: RouteVia::Tun,
            dns_trusted: true,
            error: None,
        };
        let tun = AccessPath::Tun {
            adapter: "Mihomo".to_string(),
        };
        // 同一个接入路径下，两个目标得到不同结论：A 可探测，B 不可。
        assert_eq!(plan_route_with_evidence(&tun, Some(&a)), ProbeRoute::Direct);
        assert_eq!(plan_route_with_evidence(&tun, Some(&b)), ProbeRoute::Skip);
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
