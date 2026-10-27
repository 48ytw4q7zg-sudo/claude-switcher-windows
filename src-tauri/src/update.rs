//! 应用内版本检查：请求 GitHub Releases latest，与当前版本比较。
//!
//! 只提示、不自动安装（未签名场景下 tauri-plugin-updater 的签名密钥方案不现实）。
//! 匿名 API 有限流（403）：失败一律静默返回「检查失败」，绝不弹错、绝不阻塞主线程。

use std::time::Duration;

use serde::Serialize;

/// GitHub 仓库的 releases/latest 端点。
const RELEASES_LATEST_URL: &str =
    "https://api.github.com/repos/48ytw4q7zg-sudo/claude-switcher-windows/releases/latest";

#[derive(Debug, Clone, Serialize)]
pub struct UpdateCheckResult {
    /// 当前版本（Cargo.toml 的 package.version）。
    pub current_version: String,
    /// 最新发布版本（tag_name 去掉前导 v）；检查失败时为 None。
    pub latest_version: Option<String>,
    /// 是否有更新（语义比较 major.minor.patch）。
    pub has_update: bool,
    /// Release 页面 URL；检查失败时为空串。
    pub release_url: String,
    /// 人话说明（检查失败原因或「已是最新」）。
    pub message: String,
}

/// 检查更新（网络请求，必须经 `blocking()` 调用，勿在主线程直接跑）。
pub fn check_for_update_blocking() -> UpdateCheckResult {
    let current = env!("CARGO_PKG_VERSION").to_string();

    // GitHub API 要求 User-Agent；限流 403 / 断网都归入「检查失败」静默。
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
    {
        Ok(client) => client,
        Err(e) => return failure(&current, format!("HTTP 客户端初始化失败: {e}")),
    };
    let response = match client
        .get(RELEASES_LATEST_URL)
        .header("User-Agent", format!("claude-switcher/{current}"))
        .header("Accept", "application/vnd.github+json")
        .send()
    {
        Ok(response) => response,
        Err(e) => return failure(&current, format!("网络请求失败: {e}")),
    };
    if !response.status().is_success() {
        // 403 = 匿名限流；404 = 尚无 Release。都不值得弹错。
        return failure(&current, format!("GitHub API 返回 {}", response.status()));
    }
    let value: serde_json::Value = match response.json() {
        Ok(value) => value,
        Err(e) => return failure(&current, format!("响应解析失败: {e}")),
    };

    let latest = value
        .get("tag_name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .trim_start_matches('v')
        .to_string();
    let url = value
        .get("html_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    if latest.is_empty() {
        return failure(&current, "响应缺少 tag_name".to_string());
    }

    let has_update = version_newer(&latest, &current);
    UpdateCheckResult {
        message: if has_update {
            format!("发现新版本 v{latest}（当前 v{current}）")
        } else {
            format!("已是最新版本（v{current}）")
        },
        current_version: current,
        latest_version: Some(latest),
        has_update,
        release_url: url,
    }
}

fn failure(current: &str, message: String) -> UpdateCheckResult {
    UpdateCheckResult {
        current_version: current.to_string(),
        latest_version: None,
        has_update: false,
        release_url: String::new(),
        message: format!("版本检查失败（不影响使用）: {message}"),
    }
}

/// 比较 `a.b.c` 形式的版本号：a 是否比 current 新。
/// 非数字段按 0 处理；格式异常时保守判「无更新」（不打断用户）。
fn version_newer(candidate: &str, current: &str) -> bool {
    let parse = |s: &str| -> [u64; 3] {
        let mut out = [0u64; 3];
        for (i, part) in s.trim().split('.').take(3).enumerate() {
            out[i] = part.parse().unwrap_or(0);
        }
        out
    };
    parse(candidate) > parse(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_newer_compares_semver_fields() {
        assert!(version_newer("0.2.0", "0.1.0"));
        assert!(version_newer("1.0.0", "0.9.9"));
        assert!(version_newer("0.1.1", "0.1.0"));
        assert!(!version_newer("0.1.0", "0.1.0"));
        assert!(!version_newer("0.0.9", "0.1.0"));
    }

    /// 格式异常（非数字）按 0 处理，绝不 panic。
    #[test]
    fn version_newer_tolerates_garbage() {
        assert!(!version_newer("abc", "0.1.0"));
        assert!(version_newer("0.2.x", "0.1.0"));
    }
}
