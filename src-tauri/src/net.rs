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
pub fn detect_clash_runtime_config() -> ClashRuntimeConfig {
    if let Some(override_cfg) = read_override() {
        let controller = override_cfg
            .controller
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                if s.starts_with("http://") || s.starts_with("https://") {
                    s.to_string()
                } else {
                    format!("http://{s}")
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
        if controller.is_some() || secret.is_some() || proxy.is_some() {
            return ClashRuntimeConfig {
                controller: controller.unwrap_or_else(probe_default_controller),
                secret,
                proxy,
            };
        }
    }

    for path in paths::clash_config_candidates().unwrap_or_default() {
        let Ok(Some(value)) = crate::jsonio::read_yaml_optional(path) else {
            continue;
        };
        let controller = value
            .get("external-controller")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(probe_default_controller);
        let controller = if controller.starts_with("http://") || controller.starts_with("https://")
        {
            controller
        } else {
            format!("http://{controller}")
        };
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
        };
    }

    ClashRuntimeConfig {
        controller: probe_default_controller(),
        secret: None,
        proxy: None,
    }
}

fn http_client(timeout_secs: u64) -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(3))
        .user_agent("claude-code/2.1.0")
        .build()
        .map_err(|e| format!("初始化 HTTP 客户端失败: {e}"))
}

/// Clash RESTful API 调用。
pub fn clash_api(method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
    let cfg = detect_clash_runtime_config();
    let url = format!(
        "{}/{}",
        cfg.controller.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    let client = http_client(8)?;
    let request = match method {
        "GET" => client.get(&url),
        "PUT" => client.put(&url),
        "POST" => client.post(&url),
        other => return Err(format!("不支持的 HTTP 方法: {other}")),
    };
    let mut request = request;
    if let Some(secret) = cfg.secret {
        request = request.bearer_auth(secret);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .map_err(|e| format!("调用 Clash 控制器失败: {e}"))?;
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
pub fn claude_oauth_api(path: &str, access_token: &str) -> Result<Value, String> {
    let url = format!("https://api.anthropic.com{path}");
    let runtime = detect_clash_runtime_config();

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
    if let Some(proxy) = proxy {
        builder =
            builder.proxy(reqwest::Proxy::all(proxy).map_err(|e| format!("代理配置失败: {e}"))?);
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
