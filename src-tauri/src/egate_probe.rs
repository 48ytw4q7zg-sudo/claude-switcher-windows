//! 出口门禁的探测执行（网络只发生在本文件）。
//!
//! 行为基准：ClaudeGuard `src/anchors.rs`（固定 commit `1967377`）。语义要点：
//! - 探测流量**跟随系统代理**：Claude 等桌面应用只认系统代理，跟随它测到的
//!   才是应用真实出口（reqwest 的 system-proxy 特性读注册表，已在 Cargo 启用）；
//! - 任何 HTTP 响应（含 4xx/5xx）都算「有响应」，网络错误/超时才算不可达；
//! - 响应体上限 [`MAX_BODY_BYTES`]，超长页面不整体读入内存；
//! - **不**跟随跨主机重定向（锚点域名即被测对象，被重定向到别处就换了测量对象）；
//! - URL 只接受 http/https 绝对地址，拒绝 userinfo、控制字符与非预期 scheme。
//!
//! [`probe`] 是唯一发起网络的函数；解析与判定都在 [`crate::egate`]。

use std::time::{Duration, Instant};

use crate::egate::{parse_anchor, AnchorKind, EgateTarget, ProbeResult};

/// 响应体读取上限（Gemini 页面约 800KB，超过 3MB 的部分不再解析）。
pub const MAX_BODY_BYTES: u64 = 3 * 1024 * 1024;

/// 探测请求的 UA（代理/网关日志里能识别本工具）。
pub const USER_AGENT: &str = "claude-switcher-egate/1";

/// 单次连接超时（与总超时分开，避免慢站点拖满整个周期）。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// 探测一个目标，返回原始探测结果（判定由 [`crate::egate::evaluate`] 做）。
///
/// 不修改账号状态、不继承调用方的代理设置（由 reqwest 按系统设置决定）。
pub fn probe(target: &EgateTarget) -> ProbeResult {
    let url = match validate_anchor_url(&target.anchor_url) {
        Err(reason) => return ProbeResult::failed(reason),
        Ok(url) => url,
    };
    let started = Instant::now();
    let timeout = Duration::from_secs(target.timeout_secs.max(1));
    let client = match build_client(timeout) {
        Ok(client) => client,
        Err(error) => return ProbeResult::failed(error),
    };
    match client.get(&url).send() {
        Ok(response) => {
            let status = response.status().as_u16();
            let mut result = if target.anchor_kind == AnchorKind::Reachability {
                // 显式可达性不看响应体。
                ProbeResult {
                    reachable: true,
                    parsed_as: AnchorKind::Reachability.tag().to_string(),
                    detail: format!("有响应（HTTP {status}），按可达性判定"),
                    ..ProbeResult::default()
                }
            } else {
                let body = read_body_limited(response);
                parse_anchor(target.anchor_kind, &body)
            };
            result.reachable = true;
            result.status = Some(status);
            result.latency_ms = started.elapsed().as_millis() as u64;
            result
        }
        Err(error) => ProbeResult::failed(transport_detail(&error)),
    }
}

/// 构造跟随系统代理的阻塞客户端。
fn build_client(timeout: Duration) -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent(USER_AGENT)
        // 锚点域名就是被测对象：跨主机跳转等于换了测量对象，一律不跟随。
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 3 {
                attempt.error("锚点重定向次数过多")
            } else {
                attempt.stop()
            }
        }))
        .build()
        .map_err(|e| format!("初始化探测客户端失败: {e}"))
}

/// 读取响应体（上限 [`MAX_BODY_BYTES`]）；非法 UTF-8 用替换字符兜底。
fn read_body_limited(mut response: reqwest::blocking::Response) -> String {
    use std::io::Read;
    let mut bytes: Vec<u8> = Vec::with_capacity(16 * 1024);
    // take() 限制读取量，超长页面不会整体进内存；读失败保留已读部分。
    let _ = (&mut response)
        .take(MAX_BODY_BYTES)
        .read_to_end(&mut bytes)
        .map(|_| ());
    String::from_utf8_lossy(&bytes).into_owned()
}

/// 校验锚点 URL：只接受 http/https 绝对地址，拒绝 userinfo 与控制字符。
pub fn validate_anchor_url(raw: &str) -> Result<String, String> {
    // 先按**原始输入**查控制字符：trim 会吃掉尾部换行，之后再查就漏掉了。
    if raw.chars().any(|c| c.is_control()) {
        return Err("锚点地址含控制字符".to_string());
    }
    let text = raw.trim();
    if text.is_empty() {
        return Err("锚点地址为空".to_string());
    }
    let url = url::Url::parse(text).map_err(|_| "锚点地址不是有效 URL".to_string())?;
    match url.scheme() {
        "http" | "https" => {}
        other => return Err(format!("锚点地址协议不受支持: {other}")),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("锚点地址不允许携带账号密码".to_string());
    }
    if url.host_str().is_none() {
        return Err("锚点地址缺少主机名".to_string());
    }
    Ok(url.to_string())
}

/// 网络错误的可读说明（不把原始异常文本抛给界面）。
fn transport_detail(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "探测超时，无法确认出口".to_string()
    } else if error.is_connect() {
        "无法连接锚点地址，无法确认出口".to_string()
    } else if error.is_redirect() {
        "锚点重定向被拒绝，无法确认出口".to_string()
    } else {
        "探测失败，无法确认出口".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(url: &str, kind: AnchorKind) -> EgateTarget {
        EgateTarget {
            id: "t".to_string(),
            name: "测试".to_string(),
            anchor_url: url.to_string(),
            anchor_kind: kind,
            expect_ips: Vec::new(),
            expect_regions: Vec::new(),
            enabled: true,
            timeout_secs: 3,
        }
    }

    // ── URL 校验 ──

    #[test]
    fn validates_anchor_url_scheme_and_userinfo() {
        assert!(validate_anchor_url("https://claude.ai/cdn-cgi/trace").is_ok());
        assert!(validate_anchor_url("http://example.invalid/trace").is_ok());
        for bad in [
            "",
            "   ",
            "claude.ai/trace",
            "ftp://example.invalid/",
            "file:///c:/windows",
            "https://user:pass@example.invalid/",
            "https://example.invalid/\n",
        ] {
            assert!(
                validate_anchor_url(bad).is_err(),
                "应拒绝非法锚点地址: {bad:?}"
            );
        }
    }

    #[test]
    fn invalid_url_probe_fails_without_network() {
        // 非法 URL 必须在发起网络前就失败（否则会打到意外主机）。
        let result = probe(&target("not-a-url", AnchorKind::Auto));
        assert!(!result.reachable);
        assert!(result.detail.contains("锚点地址"), "{result:?}");
    }

    #[test]
    fn unreachable_host_probe_is_unverified_not_fail() {
        // 保留的域名不解析：必须得到 reachable=false，且不 panic。
        let result = probe(&target("https://egate.invalid/trace", AnchorKind::Auto));
        assert!(!result.reachable);
        assert!(result.detail.contains("无法确认出口"), "{result:?}");
        assert_eq!(
            crate::egate::evaluate(
                &target("https://egate.invalid/trace", AnchorKind::Trace),
                &result
            )
            .verdict,
            crate::egate::Verdict::Unverified,
            "探测失败绝不能直接判熔断"
        );
    }
}
