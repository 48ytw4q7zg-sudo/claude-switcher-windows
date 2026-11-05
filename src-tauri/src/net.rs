//! Clash Verge / Claude OAuth HTTP 客户端。
//!
//! 用 reqwest（rustls）替代 curl.exe：
//! - 系统代理 / 环境变量代理自动生效（国内网络、Clash TUN 场景友好）；
//! - JSON body 走 socket，不再把中文节点名放 argv（跨编码风险）；
//! - 无 PATH 依赖，也没有 Schannel 吊销检查失败问题。
//!
//! Clash 控制器设置（地址/secret/代理端口）支持在 `~/.claude-switcher/clash.json`
//! 手动覆盖（detect 出错或 portable 模式时用），文件格式：
//! `{ "controller": "http://127.0.0.1:9097", "secret": "…", "proxyPort": 7897 }`。

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde_json::{json, Value};

use crate::paths;

/// Clash 控制器运行时配置。
#[derive(Debug, Clone)]
pub struct ClashRuntimeConfig {
    pub controller: String,
    pub secret: Option<String>,
    pub proxy: Option<String>,
    controller_error: Option<String>,
}

/// 用户手动覆盖文件 `~/.claude-switcher/clash.json` 的形状。
#[derive(Debug, Clone, serde::Deserialize)]
struct ClashOverride {
    controller: Option<String>,
    secret: Option<String>,
    #[serde(rename = "proxyPort")]
    proxy_port: Option<u64>,
    #[serde(rename = "mixedPort")]
    mixed_port: Option<u64>,
}

/// 默认控制器：Clash Verge Rev 新版默认 9097（旧版 9090）。
/// 自动探测失败时依次探测 9097 → 9090（`probe_default_controller`）。
const DEFAULT_CONTROLLERS: [&str; 2] = ["http://127.0.0.1:9097", "http://127.0.0.1:9090"];

/// 探测到的默认控制器缓存（60 秒）：避免每次 detect 都付两次 HTTP 探测。
static DETECTED_DEFAULT: OnceLock<Mutex<Option<(String, std::time::Instant)>>> = OnceLock::new();

/// 依次探测默认端口（9097 → 9090），返回实际应答的那个；都失败则取第一个。
/// 探测走 `/version`（Clash 公开端点，1 秒短超时），结果缓存 60 秒。
fn probe_default_controller() -> String {
    const PROBE_TTL: Duration = Duration::from_secs(60);
    let cache = DETECTED_DEFAULT.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = cache.lock() {
        if let Some((url, at)) = guard.as_ref() {
            if at.elapsed() < PROBE_TTL {
                return url.clone();
            }
        }
    }

    let probed = DEFAULT_CONTROLLERS
        .iter()
        .find(|candidate| {
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(1))
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build();
            client
                .map(|c| {
                    c.get(format!("{candidate}/version"))
                        .send()
                        .map(|r| r.status().is_success())
                        .unwrap_or(false)
                })
                .unwrap_or(false)
        })
        .map(|s| s.to_string())
        .unwrap_or_else(|| DEFAULT_CONTROLLERS[0].to_string());

    if let Ok(mut guard) = cache.lock() {
        *guard = Some((probed.clone(), std::time::Instant::now()));
    }
    probed
}

fn read_override() -> Option<ClashOverride> {
    let path = paths::app_data_dir().ok()?.join("clash.json");
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// 探测运行时配置：手动覆盖 > Clash Verge 配置文件 > 默认端口。
///
/// 地址无效时记录错误，携带密钥的控制器请求在发送前失败。
pub fn detect_clash_runtime_config() -> ClashRuntimeConfig {
    if let Some(override_cfg) = read_override() {
        let mut controller_error = None;
        let controller = override_cfg
            .controller
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|raw| match normalize_controller(raw) {
                Ok(url) => Some(url),
                Err(e) => {
                    crate::log_error(&format!("clash.json 控制器地址被拒绝：{e}"));
                    controller_error = Some(e);
                    None
                }
            });
        let secret = override_cfg
            .secret
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);
        let proxy = override_cfg
            .proxy_port
            .or(override_cfg.mixed_port)
            .filter(|port| *port > 0)
            .map(|port| format!("http://127.0.0.1:{port}"));
        if controller.is_some() || secret.is_some() || proxy.is_some() || controller_error.is_some()
        {
            return ClashRuntimeConfig {
                controller: controller.unwrap_or_else(|| {
                    if controller_error.is_some() {
                        DEFAULT_CONTROLLERS[0].to_string()
                    } else {
                        probe_default_controller()
                    }
                }),
                secret,
                proxy,
                controller_error,
            };
        }
    }

    for path in paths::clash_config_candidates().unwrap_or_default() {
        let mut controller_error = None;
        // read_yaml_optional 取得 PathBuf 所有权，日志里还要用 path，先克隆一份。
        let path_for_log = path.clone();
        let Ok(Some(value)) = crate::jsonio::read_yaml_optional(path) else {
            continue;
        };
        // normalize_controller 把 0.0.0.0 / :: / 空主机统一改写成 127.0.0.1
        // （Windows 上 connect 0.0.0.0 必然失败），并拒绝非回环目标。
        let controller = value
            .get("external-controller")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .filter(|s| !s.trim().is_empty())
            .and_then(|raw| match normalize_controller(&raw) {
                Ok(url) => Some(url),
                Err(e) => {
                    crate::log_error(&format!(
                        "{} 的 external-controller 被拒绝（{e}），已停止控制器请求",
                        path_for_log.display()
                    ));
                    controller_error = Some(e);
                    None
                }
            })
            .unwrap_or_else(|| {
                if controller_error.is_some() {
                    DEFAULT_CONTROLLERS[0].to_string()
                } else {
                    probe_default_controller()
                }
            });
        let secret = value
            .get("secret")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let proxy = value
            .get("mixed-port")
            .and_then(|v| v.as_u64())
            .or_else(|| value.get("port").and_then(|v| v.as_u64()))
            .filter(|port| *port > 0)
            .map(|port| format!("http://127.0.0.1:{port}"));
        return ClashRuntimeConfig {
            controller,
            secret,
            proxy,
            controller_error,
        };
    }

    ClashRuntimeConfig {
        controller: probe_default_controller(),
        secret: None,
        proxy: None,
        controller_error: None,
    }
}

/// 统一的 HTTP 客户端构造。
///
/// `no_proxy_when_local`：Clash 控制器是本机服务（127.0.0.1）。若用户设了
/// `HTTP_PROXY` 却没配 `NO_PROXY`，请求会被发去代理再绕回来，轻则变慢、重则连不上。
/// **注意 `.no_proxy()` 对整个 client 生效**（不是只屏蔽回环地址）——
/// 该 client 只用来访问本机控制器，所以正合适。
fn http_client(
    timeout_secs: u64,
    no_proxy_when_local: bool,
) -> Result<reqwest::blocking::Client, String> {
    // **P1-10**：本机控制器请求统一走 `Loopback` 策略（= 强制 no_proxy），
    // 需要走代理的调用点归入 `Standard`。策略由 `network_policy` 单点解释，
    // 这样「哪些请求允许直连 / 允许跟随系统代理」不再散落在各个 builder 里。
    let policy = if no_proxy_when_local {
        crate::network_policy::NetworkPolicy::Loopback
    } else {
        crate::network_policy::NetworkPolicy::Standard
    };
    let spec = crate::network_policy::ClientSpec::new(policy, Duration::from_secs(timeout_secs));
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(3))
        .user_agent("claude-code/2.1.0");
    // 策略合法性在这里单点判定（两种策略都不需要代理参数）。
    crate::network_policy::validate(&spec)?;
    if no_proxy_when_local {
        // 整个 client 不走代理（本机服务专用），且不跟随重定向。
        builder = builder
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none());
    }
    builder
        .build()
        .map_err(|e| format!("初始化 HTTP 客户端失败: {e}"))
}

/// 把 Clash 配置里的控制器地址规范化成本机可连的形式。
///
/// `external-controller` 常写成 `0.0.0.0:9090`、`:9090`、`[::]:9090` 甚至无端口的
/// `[::1]`：在 Windows 上 connect `0.0.0.0` 会直接失败（类 Unix 系统却可以），
/// 因此把通配/空主机统一改写成 `127.0.0.1`，端口缺失时补 9097。
///
/// **只接受回环地址**：控制器是本机服务，`clash-verge.yaml` 若被改成远程主机
/// （配置被篡改 / 误贴别人的配置），把 bearer secret 发过去等于主动泄露。
/// 上游测试 `test_remote_controller_is_rejected_before_sending_secret` 同样要求
/// 先拒绝再发送。这里规范化阶段就把非回环目标拦下，`clash_api` 根本不会发起请求。
fn normalize_controller(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(DEFAULT_CONTROLLERS[0].to_string());
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("控制器地址包含无效空白字符".to_string());
    }
    let authority = if let Some((scheme, rest)) = trimmed.split_once("://") {
        if !scheme.eq_ignore_ascii_case("http") {
            return Err("控制器必须使用本机 HTTP 地址".to_string());
        }
        rest
    } else {
        trimmed
    };
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.contains(['@', '/', '\\', '?', '#']) {
        return Err("控制器地址不能包含用户信息、路径或查询参数".to_string());
    }
    let authority = if authority.starts_with(':') && !authority.starts_with("::") {
        format!("127.0.0.1{authority}")
    } else {
        authority.to_string()
    };
    let parsed = url::Url::parse(&format!("http://{authority}"))
        .map_err(|_| "控制器地址或端口格式无效".to_string())?;
    // Preserve explicit port 80: URL parsers omit the scheme's default port.
    let port_text = if authority.starts_with('[') {
        authority
            .split_once(']')
            .and_then(|(_, tail)| tail.strip_prefix(':'))
    } else {
        authority.split_once(':').map(|(_, port)| port)
    };
    let port = match port_text {
        None | Some("") => 9097,
        Some(value) => value
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| "控制器端口必须介于 1 和 65535 之间".to_string())?,
    };
    let host = match parsed.host() {
        Some(url::Host::Ipv4(ip)) if ip.is_unspecified() => "127.0.0.1".to_string(),
        Some(url::Host::Ipv4(ip)) if ip.is_loopback() => ip.to_string(),
        Some(url::Host::Ipv6(ip)) if ip.is_unspecified() => "127.0.0.1".to_string(),
        Some(url::Host::Ipv6(ip)) if ip.is_loopback() => format!("[{ip}]"),
        Some(url::Host::Domain(host)) if host.eq_ignore_ascii_case("localhost") => {
            "127.0.0.1".to_string()
        }
        _ => return Err("Clash 控制器必须是本机回环地址".to_string()),
    };
    Ok(format!("http://{host}:{port}"))
}

/// Clash RESTful API 调用。控制器是本机服务，故走 no_proxy。
pub fn clash_api(method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
    let cfg = detect_clash_runtime_config();
    clash_api_with_config(&cfg, method, path, body)
}

fn clash_api_with_config(
    cfg: &ClashRuntimeConfig,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    if let Some(error) = &cfg.controller_error {
        return Err(error.clone());
    }
    let controller = normalize_controller(&cfg.controller)?;
    let url = format!(
        "{}/{}",
        controller.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    let client = http_client(8, true)?;
    let request = match method {
        "GET" => client.get(&url),
        "PUT" => client.put(&url),
        "POST" => client.post(&url),
        other => return Err(format!("不支持的 HTTP 方法: {other}")),
    };
    let mut request = request;
    if let Some(secret) = &cfg.secret {
        request = request.bearer_auth(secret);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .map_err(|e| format!("调用 Clash 控制器失败: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "Clash 控制器返回状态码 {}",
            response.status().as_u16()
        ));
    }
    let text = response
        .text()
        .map_err(|e| format!("读取 Clash 响应失败: {e}"))?;
    if text.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(&text).map_err(|e| format!("Clash 返回 JSON 解析失败: {e}"))
}

/// Claude OAuth API（api.anthropic.com）。
/// 系统代理场景下 api.anthropic.com 常需走 Clash 混合端口；直连失败且检测到
/// Clash 代理端口时，才换代理再试一次（不开 Clash 的用户只走一次直连）。
///
/// 超时预算：直连 4s + 代理 4s = 最坏 8s。托盘 tooltip 刷新是同步调用，
/// 两次各 6s（合计 12s）会把刷新周期拖得肉眼可见，故压到 4s。
/// **P0-01 / L-01（v0.7.5）**：严格出口请求的策略。
///
/// v0.7.3 的 `strict_oauth_proxy() -> Option<String>` 把两种完全不同的含义
/// 折叠成同一个 `None`：「用户关闭了严格保护」与「严格保护已开启但没有可用
/// 代理」。调用方据此 `match None` 直接走直连分支——于是带着
/// `Authorization: Bearer …` 的请求会从真实家宽出口发出去，恰恰是严格模式
/// 要防的事。
///
/// 现在三种情况必须分开，且第三种**绝不**进入任何发送分支。
#[derive(Debug, Clone, PartialEq, Eq)]
enum OauthPolicy {
    /// 用户未启用严格保护：沿用原有「直连优先、代理兜底」。
    Unrestricted,
    /// 严格保护已开启且有可信代理：**只**允许走它。
    StrictProxy(String),
    /// 严格保护已开启但没有可信代理，**或配置无法读取**：禁止一切请求。
    StrictBlocked(String),
}

/// 纯策略判定（**P0-01**：可表驱动测试）。
///
/// `config = None` 表示配置**损坏/不可读**，此时无法确认用户是否开启了严格
/// 保护——**必须**按严格处理（`StrictBlocked`），绝不能当成「用户没开保护」。
fn oauth_policy_decide(
    config: Option<&crate::appconfig::AppConfig>,
    evidence: &crate::egate_access::ProxyEvidence,
    runtime_proxy: Option<&str>,
) -> OauthPolicy {
    let Some(config) = config else {
        return OauthPolicy::StrictBlocked(
            "无法读取应用配置，不能确认严格保护是否开启；请求已取消".to_string(),
        );
    };
    if !config.egate_enabled {
        return OauthPolicy::Unrestricted;
    }
    // 严格模式：必须有**可信**代理，否则禁止（不退回直连）。
    //
    // **L-17（v0.7.5）**：「什么算可用代理」由 `network_policy` 单点判定。
    // 原来这里自己写了一份「读得出 + 已启用 + Http 可解析」的判断，
    // 与 `network_policy::usable_system_proxy` 是两套实现——它们一旦分叉，
    // 就会出现「网络策略认为可用、OAuth 认为不可用」这种最难查的偏差。
    if let Some(proxy) = crate::network_policy::usable_system_proxy(evidence) {
        return OauthPolicy::StrictProxy(proxy.addr);
    }
    // ② Clash 控制器探测到的代理地址（TUN 不算：路由未经证明时不能凭网卡放行）。
    if let Some(addr) = runtime_proxy.map(str::trim).filter(|p| !p.is_empty()) {
        return OauthPolicy::StrictProxy(addr.to_string());
    }
    OauthPolicy::StrictBlocked(
        "严格出口保护已开启，但没有可用的代理通道；本次未发送任何请求，也未改用直连".to_string(),
    )
}

/// 取当前策略（读配置 + 注册表 + Clash 运行时）。
fn oauth_policy_current(runtime: &ClashRuntimeConfig) -> OauthPolicy {
    let config = match crate::appconfig::load_checked() {
        // Fresh = 首次安装，还没有任何配置 → `egate_enabled` 缺省为 false。
        crate::appconfig::ConfigLoad::Ok(config) => Some(*config),
        crate::appconfig::ConfigLoad::Fresh => Some(crate::appconfig::AppConfig::default()),
        // **P0-01**：配置损坏时**不能**当成「用户关闭了保护」。
        crate::appconfig::ConfigLoad::Corrupt(_) => None,
    };
    let evidence = crate::egate_check::read_proxy_evidence();
    oauth_policy_decide(config.as_ref(), &evidence, runtime.proxy.as_deref())
}

pub fn claude_oauth_api(path: &str, access_token: &str) -> Result<Value, String> {
    oauth_request("https://api.anthropic.com", path, access_token)
}

/// 策略分发的请求入口（基地址可注入，便于用本地夹具测试）。
fn oauth_request(base: &str, path: &str, access_token: &str) -> Result<Value, String> {
    let url = format!("{base}{path}");
    let runtime = detect_clash_runtime_config();
    match oauth_policy_current(&runtime) {
        // 严格保护已开启但拿不到可信代理：**直接失败**。
        //
        // 这里绝不 fall through 到下面的 `oauth_get(..., None)`——那正是
        // v0.7.3 的漏洞：`None` 被同时解释成「非严格模式」。
        OauthPolicy::StrictBlocked(reason) => Err(format!(
            "{reason}。请先恢复代理/Clash 后重试；本工具在严格保护下不会把带凭据的请求发往真实出口"
        )),
        // 严格模式：只走已确认的代理，失败就是失败（不直连、不回退、不跟随重定向）。
        OauthPolicy::StrictProxy(proxy) => {
            oauth_get_strict(&url, access_token, &proxy).map_err(|error| {
                format!("严格出口模式下请求必须经代理（{proxy}），本次未改用直连：{error}")
            })
        }
        // 非严格模式：沿用原有的直连优先 + 代理兜底（用户明确选择的普通用法）。
        OauthPolicy::Unrestricted => {
            match oauth_get(&url, access_token, None, Duration::from_secs(4)) {
                Ok(value) => Ok(value),
                Err(direct_error) => match runtime.proxy {
                    Some(proxy) => {
                        match oauth_get(&url, access_token, Some(&proxy), Duration::from_secs(4)) {
                            Ok(value) => Ok(value),
                            Err(proxy_error) => Err(format!(
                                "直连失败（{direct_error}）；走 Clash 代理也失败（{proxy_error}）"
                            )),
                        }
                    }
                    None => Err(direct_error),
                },
            }
        }
    }
}

/// 严格出口模式下的请求：**只**经指定代理。
///
/// 三处刻意的收紧（**P0-01** 要求）：
/// 1. `.no_proxy()` **必须先调用**再 `.proxy()` —— reqwest 的 `system-proxy`
///    特性会在 `build()` 时把系统代理也加进列表；顺序颠倒会让请求走系统代理
///    而不是我们指定的那个，Bearer token 也就落到了别的出口上。
/// 2. 不跟随重定向：3xx 会把带凭据的请求转到别处，宁可报错。
/// 3. 任何失败都返回 `Err`，**没有**直连回退分支。
fn oauth_get_strict(url: &str, access_token: &str, proxy: &str) -> Result<Value, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(3))
        .user_agent("claude-code/2.1.0")
        .no_proxy()
        .proxy(
            reqwest::Proxy::all(format!("http://{proxy}"))
                .map_err(|e| format!("代理配置失败: {e}"))?,
        )
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("初始化 HTTP 客户端失败: {e}"))?;
    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Accept", "application/json")
        .header("anthropic-beta", "oauth-2025-04-20")
        .send()
        .map_err(|e| format!("调用 Claude OAuth API 失败: {e}"))?;
    let status = response.status();
    let text = response
        .text()
        .map_err(|e| format!("读取 Claude OAuth API 响应失败: {e}"))?;
    if !status.is_success() {
        return Err(format!("Claude OAuth API HTTP {status}: {text}"));
    }
    serde_json::from_str(&text).map_err(|e| format!("Claude OAuth API JSON 解析失败: {e}"))
}

fn oauth_get(
    url: &str,
    access_token: &str,
    proxy: Option<&str>,
    timeout: Duration,
) -> Result<Value, String> {
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(3))
        .user_agent("claude-code/2.1.0");
    match proxy {
        Some(proxy) => {
            builder = builder
                .proxy(reqwest::Proxy::all(proxy).map_err(|e| format!("代理配置失败: {e}"))?);
        }
        None => {
            // 「直连」这一步必须显式 no_proxy：reqwest 默认会探测系统/环境代理，
            // 那样用户设了 HTTP_PROXY 时第一次尝试根本不是直连，代理回退分支
            // 也就失去意义（两次都走同一个代理）。
            builder = builder.no_proxy();
        }
    }
    let client = builder
        .build()
        .map_err(|e| format!("初始化 HTTP 客户端失败: {e}"))?;
    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Accept", "application/json")
        .header("anthropic-beta", "oauth-2025-04-20")
        .send()
        .map_err(|e| format!("调用 Claude OAuth API 失败: {e}"))?;
    let status = response.status();
    let text = response
        .text()
        .map_err(|e| format!("读取 Claude OAuth API 响应失败: {e}"))?;
    if !status.is_success() {
        return Err(format!("Claude OAuth API HTTP {status}: {text}"));
    }
    serde_json::from_str(&text).map_err(|e| format!("Claude OAuth API JSON 解析失败: {e}"))
}

pub fn clash_group_path(group: &str) -> String {
    format!("/proxies/{}", urlencoding::encode(group))
}

pub fn clash_proxy_path(node: &str) -> String {
    format!("/proxies/{}", urlencoding::encode(node))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_rejects_deceptive_hosts_userinfo_and_invalid_authorities() {
        for input in [
            "127.attacker.invalid:9090",
            "127.0.0.1:9097@attacker.invalid",
            "http://127.0.0.1:9097@attacker.invalid",
            "localhost:9097/path",
            "127.0.0.1:9097?host=example.invalid",
            "127.0.0.1:9097#fragment",
            "127.0.0.1:65536",
            "127.0.0.1:0",
            "127.0.0.1:not-a-port",
            "127.0.0.1:9097\\@example.invalid",
            "127.0.0.1:90\t97",
        ] {
            assert!(normalize_controller(input).is_err(), "accepted {input}");
        }
    }

    #[test]
    fn controller_normalization_table() {
        let cases = [
            (":9097", "http://127.0.0.1:9097"),
            (":9090", "http://127.0.0.1:9090"),
            ("0.0.0.0:9090", "http://127.0.0.1:9090"),
            ("[::]:9090", "http://127.0.0.1:9090"),
            // IPv6 字面量必须保留方括号，否则 `http://::1:9097` 无法被解析。
            ("[::1]", "http://[::1]:9097"),
            ("[::1]:9097", "http://[::1]:9097"),
            ("127.0.0.1", "http://127.0.0.1:9097"),
            ("localhost:9097", "http://127.0.0.1:9097"),
            ("http://0.0.0.0:9097", "http://127.0.0.1:9097"),
            ("127.0.0.1:9097", "http://127.0.0.1:9097"),
            ("127.0.0.5:9097", "http://127.0.0.5:9097"),
            ("localhost:80", "http://127.0.0.1:80"),
            ("http://[::1]:80/", "http://[::1]:80"),
            ("127.0.0.1:0080", "http://127.0.0.1:80"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                normalize_controller(input).as_deref(),
                Ok(expected),
                "input={input}"
            );
        }
        // 纯地址规范化不执行端口探测；运行时探测由配置解析层处理。
        assert!(normalize_controller("")
            .unwrap()
            .starts_with("http://127.0.0.1:"));

        // 非回环目标必须被拒绝：否则 bearer secret 会主动发往远程主机。
        for remote in [
            "untrusted.invalid:9090",
            "http://untrusted.invalid:9090",
            "192.168.1.50:9097",
            "10.0.0.8:9090",
            "[fe80::1]:7890",
            "https://127.0.0.1:9097",
        ] {
            assert!(
                normalize_controller(remote).is_err(),
                "远程/非 http 控制器必须被拒绝: {remote}"
            );
        }
    }

    /// **P0-01 / L-01（v0.7.5）**：严格出口策略的判定表。
    ///
    /// 核心断言：**严格模式下任何「无可用代理」的情况都必须 `StrictBlocked`，
    /// 绝不产生 `Unrestricted`** —— 那正是 v0.7.3 让带凭据请求退回直连的入口。
    #[test]
    fn strict_oauth_policy_never_allows_direct_when_gate_is_on() {
        use crate::egate_access::ProxyEvidence;
        use OauthPolicy::*;

        let evidence_ok = |enable: bool, server: Option<&str>| ProxyEvidence {
            enable,
            server: server.map(str::to_string),
            autoconfig: None,
            overrides: None,
            complete: true,
            error: None,
        };
        let on = crate::appconfig::AppConfig {
            egate_enabled: true,
            ..crate::appconfig::AppConfig::default()
        };
        let off = crate::appconfig::AppConfig::default();

        // (1) 门禁关闭 -> 允许既有普通模式。
        assert_eq!(
            oauth_policy_decide(Some(&off), &evidence_ok(false, None), None),
            Unrestricted
        );
        assert_eq!(
            oauth_policy_decide(Some(&off), &evidence_ok(false, None), Some("127.0.0.1:1")),
            Unrestricted
        );

        // (2) 门禁开启且代理有效 -> 只连接代理。
        assert_eq!(
            oauth_policy_decide(Some(&on), &evidence_ok(true, Some("127.0.0.1:7890")), None),
            StrictProxy("127.0.0.1:7890".to_string())
        );

        // (3) 门禁开启但代理缺失 -> StrictBlocked（不是 Unrestricted）。
        assert!(matches!(
            oauth_policy_decide(Some(&on), &evidence_ok(false, None), None),
            StrictBlocked(_)
        ));

        // (4) 门禁开启但代理地址不可等价复用（socks）-> 同样不允许直连。
        assert!(matches!(
            oauth_policy_decide(
                Some(&on),
                &evidence_ok(true, Some("socks5://127.0.0.1:7890")),
                None
            ),
            StrictBlocked(_)
        ));

        // (5) 注册表读取失败 -> 严格模式下不得当成「没有代理，可以直连」。
        let broken = ProxyEvidence::unreadable("拒绝访问");
        assert!(matches!(
            oauth_policy_decide(Some(&on), &broken, None),
            StrictBlocked(_)
        ));

        // (6) 配置损坏 -> 必须 StrictBlocked，不能当成普通模式。
        assert!(matches!(
            oauth_policy_decide(None, &evidence_ok(false, None), None),
            StrictBlocked(_)
        ));
        // 配置损坏且有代理：仍然只能走代理，不能退回直连。
        assert!(matches!(
            oauth_policy_decide(None, &evidence_ok(false, None), Some("127.0.0.1:1")),
            StrictBlocked(_)
        ));

        // (7) 系统代理不可用时，Clash 探测到的代理可作为兜底通道。
        assert_eq!(
            oauth_policy_decide(Some(&on), &evidence_ok(false, None), Some("127.0.0.1:7890")),
            StrictProxy("127.0.0.1:7890".to_string())
        );
        // 空白字符串不能当代理地址。
        assert!(matches!(
            oauth_policy_decide(Some(&on), &evidence_ok(false, None), Some("   ")),
            StrictBlocked(_)
        ));
    }

    /// **P0-01**：`StrictBlocked` 绝不能进入任何发送分支（零直连请求）。
    ///
    /// 用本地 TCP 夹具统计**真实连接次数**：策略被拦住时夹具必须一次请求都
    /// 收不到，而不是「请求发了但失败」。
    #[test]
    fn strict_blocked_makes_zero_outbound_connections() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::Instant;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&connections);
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(800);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        counter.fetch_add(1, Ordering::SeqCst);
                        let mut buf = [0u8; 1];
                        let _ = stream.read(&mut buf);
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                              Content-Length: 2\r\n\r\n{}",
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        // 强制走 StrictBlocked：门禁开启 + 系统代理关闭 + 无 Clash 代理。
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        std::fs::create_dir_all(dir.path().join(".claude-switcher")).unwrap();
        crate::appconfig::update(|c| c.egate_enabled = true).unwrap();

        let runtime = ClashRuntimeConfig {
            controller: format!("http://{address}"),
            secret: None,
            proxy: None,
            controller_error: None,
        };
        let policy = oauth_policy_current(&runtime);
        assert!(
            matches!(policy, OauthPolicy::StrictBlocked(_)),
            "严格保护开启但无代理时必须是 StrictBlocked，实际：{policy:?}"
        );

        // 真实发一次请求：策略拦住时应当直接 Err，且一次连接都不建立。
        let result = oauth_request(&format!("http://{address}"), "/fake", "sk-ant-test-token");
        assert!(
            result.is_err(),
            "严格模式下无代理必须失败，实际：{result:?}"
        );
        assert!(
            result.as_ref().unwrap_err().contains("未发送任何请求"),
            "错误文案应说明没有发请求：{:?}",
            result
        );

        server.join().unwrap();
        let attempts = connections.load(Ordering::SeqCst);
        assert_eq!(
            attempts, 0,
            "严格模式被拦住时不得有任何直连请求（实际发出 {attempts} 次）"
        );
    }

    /// **P0-01**：严格模式拿到代理后必须只连该代理，且拒绝跟随重定向。
    #[test]
    fn strict_proxy_path_is_used_and_redirects_are_refused() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::Instant;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&seen);
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        counter.fetch_add(1, Ordering::SeqCst);
                        let mut buf = [0u8; 4096];
                        let _ = stream.read(&mut buf);
                        // 回一个 302 到别的主机：严格模式不得跟随。
                        let _ = stream.write_all(
                            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/elsewhere\r\n\
                              Content-Length: 0\r\n\r\n",
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        let result = oauth_get_strict(
            &format!("http://{address}/v1/messages"),
            "sk-ant-test-token",
            &address.to_string(),
        );
        server.join().unwrap();

        // 302 不是 success -> 必须报错，而不是跟随到别的主机。
        assert!(result.is_err(), "严格模式必须拒绝 302，实际：{result:?}");
        assert_eq!(
            seen.load(Ordering::SeqCst),
            1,
            "应当只连了指定代理一次，不跟随重定向"
        );
    }
    #[test]
    fn invalid_override_blocks_authenticated_request_before_fallback() {
        let _env_lock = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _restore = crate::test_support::set_env("USERPROFILE", dir.path());
        let data_dir = dir.path().join(".claude-switcher");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(
            data_dir.join("clash.json"),
            r#"{"controller":"127.attacker.invalid:9097","secret":"fixture-only"}"#,
        )
        .unwrap();
        let cfg = detect_clash_runtime_config();
        assert!(cfg.controller_error.is_some());
        let result = clash_api_with_config(&cfg, "GET", "/version", None);
        assert_eq!(result.unwrap_err(), cfg.controller_error.unwrap());
    }

    #[test]
    fn controller_does_not_follow_redirect_or_forward_fixture_authorization() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Instant;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let accept_deadline = Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < accept_deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("local fixture did not receive a request: {e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0u8; 1];
                // 读超时/对端提前断开都是夹具的合法结束条件（客户端可能因重定向
                // 被拒而先关闭连接）；这里不能 unwrap，否则夹具线程 panic 会让
                // join().unwrap() 把整条测试带崩，掩盖真正的断言结果。
                match stream.read_exact(&mut byte) {
                    Ok(()) => request.push(byte[0]),
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::UnexpectedEof
                        ) =>
                    {
                        break
                    }
                    Err(e) => panic!("读取夹具请求失败: {e}"),
                }
            }
            if !String::from_utf8_lossy(&request)
                .to_ascii_lowercase()
                .contains("authorization: bearer fixture-only")
            {
                // 没收到完整请求头就写响应会误导判定；直接结束夹具，
                // 由主线程的「是否发生第二次请求」断言给出结论。
                return false;
            }
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: /redirect-target\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            drop(stream);
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_millis(500);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut unexpected, _)) => {
                        let _ = unexpected.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        );
                        return true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("local fixture failed: {e}"),
                }
            }
            false
        });
        let cfg = ClashRuntimeConfig {
            controller: format!("http://{address}"),
            secret: Some("fixture-only".into()),
            proxy: None,
            controller_error: None,
        };
        let result = clash_api_with_config(&cfg, "GET", "/version", None);
        // 核心断言：绝不能发生第二次（重定向后的）请求。
        assert!(
            !server.join().unwrap(),
            "redirect caused a second authenticated request"
        );
        // 客户端必须报错；具体文案取决于夹具退出时机——收到 302 时是状态码，
        // 连接提前关闭时是传输错误。两者都说明「没有跟随重定向」。
        let error = result.expect_err("重定向必须被当作失败，不能静默成功");
        assert!(
            error.contains("302") || error.to_lowercase().contains("error"),
            "错误应说明重定向或传输失败：{error}"
        );
    }
}
