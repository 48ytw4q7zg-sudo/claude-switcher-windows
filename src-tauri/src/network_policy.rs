//! **P1-10**：统一的外发网络策略。
//!
//! 背景：本项目有 6 条互不相同的出网路径——Clash 控制器（回环）、出口探测
//! （显式代理或无代理）、出口 IP 诊断（`egress.rs`）、代理诊断、更新检查/下载、
//! Claude API。此前每条路径各自 `Client::builder()`，于是出现两类真实风险：
//!
//! 1. **静默直连回退**：reqwest 默认会读系统代理；一旦代理不可用，请求会
//!    直接走家宽出口。对「出口诊断」这类功能，这等于把用户的真实 IP 送给
//!    被测域名——恰恰是要防的事。
//! 2. **策略漂移**：某一条路径改了代理处理，其它路径保持旧行为，界面看起来
//!    「都走代理」，实际只有一部分走。
//!
//! 本模块把「哪些请求允许什么」写成**显式枚举 + 构造函数**，调用方只能经由
//! 这里拿到 `Client`，不允许再自己拼 builder。这样新增路径时会被强制选一个策略，
//! 而不是默默继承默认行为。
//!
//! 注意：策略判断在**构造期**完成（代理地址是否可用、是否允许直连），
//! 不在请求期「先试代理，失败再直连」——后者无法向用户证明哪条路走了。

use std::time::Duration;

use serde::Serialize;

use crate::egate_access::{parse_proxy_server, ProxyParse};

/// 一次外发请求所属的策略类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// 回环服务（Clash 控制器）。必须 `no_proxy`，否则会被系统代理绕一圈。
    #[allow(dead_code)]
    Loopback,
    /// 常规请求：跟随用户配置的系统代理；没有代理时走直连。
    ///
    /// 只用于「失败也不构成泄漏」的功能（更新检查的版本号查询、公开文档）。
    Standard,
    /// **严格出口请求**：只允许经**已确认可用**的显式代理。
    ///
    /// 代理缺失/不可用/地址不可解析时**直接失败**，绝不直连。
    /// 出口 IP 诊断、目标探测属于这一类。
    StrictProxy,
}

/// 从系统代理配置解析出的「可用于严格出口」的代理地址。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsableProxy {
    /// `host:port` 形式的代理地址。
    pub addr: String,
}

/// 严格的代理判定：只有**明确可复用**的 HTTP 代理才算。
///
/// - socks/PAC/缺地址 → 不可用（本项目无法保证等价复用）；
/// - `ProxyEnable = 0` → 不可用；
/// - 注册表读取不完整 → 不可用（无法确认，绝不假设）。
///
/// 这是策略层唯一的判定入口：所有「严格出口」调用点都用它，不允许各写一套。
pub fn usable_system_proxy(evidence: &crate::egate_access::ProxyEvidence) -> Option<UsableProxy> {
    if evidence.read_error().is_some() || !evidence.enable {
        return None;
    }
    match parse_proxy_server(evidence.server.as_deref()) {
        ProxyParse::Http(addr) => Some(UsableProxy { addr }),
        // `ProxyParse` 的其余变体（不支持/空）都表示「无法等价复用」。
        _ => None,
    }
}

/// 构造客户端的请求参数。
#[derive(Debug, Clone)]
pub struct ClientSpec {
    pub policy: NetworkPolicy,
    pub timeout: Duration,
    pub connect_timeout: Option<Duration>,
    pub user_agent: Option<String>,
}

impl ClientSpec {
    pub fn new(policy: NetworkPolicy, timeout: Duration) -> Self {
        ClientSpec {
            policy,
            timeout,
            connect_timeout: None,
            user_agent: None,
        }
    }

    #[allow(dead_code)]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    #[allow(dead_code)]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }
}

/// **P1-10**：按策略构造 HTTP 客户端。
///
/// `proxy` 由调用方从 [`usable_system_proxy`] 取得（或由用户显式指定）。
/// 严格策略下 `proxy` 为 `None` 时返回 `Err`——**这是本模块存在的全部意义**：
/// 宁可让功能失败并告诉用户「代理不可用」，也不悄悄用真实出口发包。
pub fn build_client(
    spec: &ClientSpec,
    proxy: Option<&UsableProxy>,
) -> Result<reqwest::blocking::Client, String> {
    let mut builder = reqwest::blocking::Client::builder().timeout(spec.timeout);
    if let Some(connect) = spec.connect_timeout {
        builder = builder.connect_timeout(connect);
    }
    if let Some(agent) = &spec.user_agent {
        builder = builder.user_agent(agent.clone());
    }
    builder = apply_policy(builder, spec.policy, proxy)?;
    builder
        .build()
        .map_err(|e| format!("HTTP 客户端初始化失败：{e}"))
}

/// 只校验策略约束、不构造客户端（供已有 builder 的调用点复用同一条规则）。
///
/// 存在的理由：`net.rs` 的控制器客户端还需要 `redirect(none)` 等自定义设置，
/// 但它必须遵守**同一套**「什么策略允许什么」的判定，否则规则会分叉。
pub fn validate(spec: &ClientSpec) -> Result<(), String> {
    apply_policy(reqwest::blocking::Client::builder(), spec.policy, None).map(|_| ())
}

/// 策略 → builder 配置的唯一实现。
fn apply_policy(
    builder: reqwest::blocking::ClientBuilder,
    policy: NetworkPolicy,
    proxy: Option<&UsableProxy>,
) -> Result<reqwest::blocking::ClientBuilder, String> {
    Ok(match policy {
        // 本机服务：明确绕过任何代理，避免「控制器请求 -> 系统代理 -> 控制器」
        // 的自我循环（代理不可用时还会超时）。
        NetworkPolicy::Loopback => builder.no_proxy(),
        // 常规：交给 reqwest 读系统代理/环境变量（默认行为），显式声明意图。
        NetworkPolicy::Standard => builder,
        // 严格：只用显式代理，且禁用一切隐式来源（系统代理、环境变量、直连）。
        NetworkPolicy::StrictProxy => {
            let proxy = proxy.ok_or_else(|| {
                "没有可用的代理通道：严格出口请求已取消（不会改用直连，以免泄露真实出口）"
                    .to_string()
            })?;
            builder.no_proxy().proxy(
                reqwest::Proxy::all(format!("http://{}", proxy.addr))
                    .map_err(|e| format!("代理配置失败：{e}"))?,
            )
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egate_access::ProxyEvidence;

    fn evidence(enable: bool, server: Option<&str>) -> ProxyEvidence {
        ProxyEvidence {
            enable,
            server: server.map(str::to_string),
            autoconfig: None,
            overrides: None,
            complete: true,
            error: None,
        }
    }

    #[test]
    fn strict_policy_refuses_to_build_without_a_proxy() {
        // 这是 P1-10 的核心断言：没有代理就**没有客户端**，绝不直连。
        let spec = ClientSpec::new(NetworkPolicy::StrictProxy, Duration::from_secs(5));
        let error = build_client(&spec, None).unwrap_err();
        assert!(error.contains("不会改用直连"), "{error}");
    }

    #[test]
    fn strict_policy_accepts_an_explicit_proxy() {
        let spec = ClientSpec::new(NetworkPolicy::StrictProxy, Duration::from_secs(5));
        let proxy = UsableProxy {
            addr: "127.0.0.1:7890".to_string(),
        };
        assert!(build_client(&spec, Some(&proxy)).is_ok());
    }

    #[test]
    fn loopback_and_standard_policies_never_require_a_proxy() {
        for policy in [NetworkPolicy::Loopback, NetworkPolicy::Standard] {
            let spec = ClientSpec::new(policy, Duration::from_secs(5));
            assert!(build_client(&spec, None).is_ok(), "{policy:?} 不应强制代理");
        }
    }

    #[test]
    fn usable_proxy_requires_an_enabled_http_proxy() {
        assert!(usable_system_proxy(&evidence(true, Some("127.0.0.1:7890"))).is_some());
        assert!(
            usable_system_proxy(&evidence(false, Some("127.0.0.1:7890"))).is_none(),
            "代理开关关闭时不得当作可用"
        );
        assert!(usable_system_proxy(&evidence(true, None)).is_none());
        // socks / PAC / 多协议串都无法等价复用。
        assert!(usable_system_proxy(&evidence(true, Some("socks5://127.0.0.1:7890"))).is_none());
        assert!(
            usable_system_proxy(&evidence(true, Some("http=127.0.0.1:1;https=127.0.0.1:2")))
                .is_some()
        );
        // 注册表读不出来：未知不等于「没有代理可用」，但严格出口只能拒绝。
        let broken = ProxyEvidence::unreadable("拒绝访问");
        assert!(usable_system_proxy(&broken).is_none());
    }

    /// `validate` 与 `build_client` 必须给出**同一套**结论，
    /// 否则已有 builder 的调用点会绕过严格策略。
    #[test]
    fn validate_and_build_agree_on_every_policy() {
        for policy in [
            NetworkPolicy::Loopback,
            NetworkPolicy::Standard,
            NetworkPolicy::StrictProxy,
        ] {
            let spec = ClientSpec::new(policy, Duration::from_secs(5));
            let validated = validate(&spec).is_ok();
            let built = build_client(&spec, None).is_ok();
            assert_eq!(validated, built, "{policy:?} 两条路径结论必须一致");
        }
        let strict = ClientSpec::new(NetworkPolicy::StrictProxy, Duration::from_secs(5));
        assert!(validate(&strict).is_err());
    }
}
