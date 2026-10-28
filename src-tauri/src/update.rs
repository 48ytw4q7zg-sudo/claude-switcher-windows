//! 应用内版本检查：请求 GitHub Releases latest，与当前版本比较。
//!
//! 只提示、不自动安装（未签名场景下 tauri-plugin-updater 的签名密钥方案不现实）。
//! 匿名 API 有限流（403）：失败一律静默返回「检查失败」，绝不弹错、绝不阻塞主线程。

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::fsx;
use crate::paths;

/// GitHub 仓库的 releases/latest 端点。
const RELEASES_LATEST_URL: &str =
    "https://api.github.com/repos/48ytw4q7zg-sudo/claude-switcher-windows/releases/latest";

#[derive(Debug, Clone, Serialize, Deserialize)]
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
///
/// 带磁盘缓存：匿名 GitHub API 限流是每小时 60 次**按 IP**，用户经 Clash 共享
/// 出口 IP 时很容易 403。缓存让面板反复打开不再重复请求。
///
/// **只缓存成功结果**：失败（限流/断网）也用长 TTL 的话，断网时打开一次，
/// 之后 6 小时内即使网络恢复，面板也只会返回缓存的失败——用户以为升级通道
/// 坏了。失败改用短 TTL，很快会重新尝试。
///
/// 读缓存时校验 `current_version`：用户在缓存期内升级到新版本后，旧缓存会说
/// 「发现新版本 v0.3.0（当前 v0.2.0）」——版本号已经对不上了。
pub fn check_for_update_blocking() -> UpdateCheckResult {
    let current = env!("CARGO_PKG_VERSION").to_string();

    if let Some(cached) = read_cache(&current) {
        return cached.result;
    }

    let fresh = fetch_latest(&current);
    if fresh.latest_version.is_some() {
        write_cache(&fresh);
    }
    fresh
}

/// 成功结果的缓存有效期。GitHub 匿名限流按 IP 每小时 60 次，6 小时足以把重复
/// 打开面板的请求压到接近于零，同时不会让用户隔天还看到旧版本提示。
const CACHE_TTL_SECS: i64 = 6 * 60 * 60;
/// 失败结果的缓存有效期：短到不足以让用户以为功能坏了，又足以避免连续
/// 快速重试（限流时每次打开面板都打一次 API 只会让限流更久）。
const FAILURE_TTL_SECS: i64 = 10 * 60;

#[derive(serde::Serialize, serde::Deserialize)]
struct CachedCheck {
    checked_at: i64,
    result: UpdateCheckResult,
}

fn cache_path() -> Option<std::path::PathBuf> {
    paths::app_data_dir()
        .ok()
        .map(|d| d.join("update-check.json"))
}

fn read_cache(current: &str) -> Option<CachedCheck> {
    let path = cache_path()?;
    let raw = std::fs::read_to_string(path).ok()?;
    let mut cached: CachedCheck = serde_json::from_str(&raw).ok()?;
    let age = chrono::Utc::now().timestamp() - cached.checked_at;
    // 成功用长 TTL，失败用短 TTL（见 `check_for_update_blocking` 的说明）。
    let ttl = if cached.result.latest_version.is_some() {
        CACHE_TTL_SECS
    } else {
        FAILURE_TTL_SECS
    };
    if !(0..=ttl).contains(&age) {
        return None;
    }
    // 版本已变（用户在缓存期内升级）→ 缓存作废，重新检查。
    if cached.result.current_version != current {
        return None;
    }
    // 标注这是缓存值：用户看到「有更新」时能判断信息可能不够新。
    cached.result.message = format!(
        "{}（{} 小时前检查，缓存）",
        cached.result.message,
        age / 3600
    );
    Some(cached)
}

fn write_cache(result: &UpdateCheckResult) {
    let Some(path) = cache_path() else { return };
    let cached = CachedCheck {
        checked_at: chrono::Utc::now().timestamp(),
        result: result.clone(),
    };
    if let Ok(text) = serde_json::to_string(&cached) {
        let _ = fsx::write_atomically(&path, &text);
    }
}

fn fetch_latest(current: &str) -> UpdateCheckResult {
    // GitHub API 要求 User-Agent；限流 403 / 断网都归入「检查失败」静默。
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
    {
        Ok(client) => client,
        Err(e) => return failure(current, format!("HTTP 客户端初始化失败: {e}")),
    };
    let response = match client
        .get(RELEASES_LATEST_URL)
        .header("User-Agent", format!("claude-switcher/{current}"))
        .header("Accept", "application/vnd.github+json")
        .send()
    {
        Ok(response) => response,
        Err(e) => return failure(current, format!("网络请求失败: {e}")),
    };
    if !response.status().is_success() {
        // 403 = 匿名限流；404 = 尚无 Release。都不值得弹错。
        return failure(current, format!("GitHub API 返回 {}", response.status()));
    }
    let value: serde_json::Value = match response.json() {
        Ok(value) => value,
        Err(e) => return failure(current, format!("响应解析失败: {e}")),
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
        return failure(current, "响应缺少 tag_name".to_string());
    }

    let has_update = version_newer(&latest, current);
    UpdateCheckResult {
        message: if has_update {
            format!("发现新版本 v{latest}（当前 v{current}）")
        } else {
            format!("已是最新版本（v{current}）")
        },
        current_version: current.to_string(),
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

/// 比较版本号：`candidate` 是否比 `current` 新。
///
/// 规则：
/// - 逐段比较 `major.minor.patch`，非数字段按 0；
/// - **预发布后缀参与比较**：`0.3.0-beta1` 视为比 `0.3.0` 旧（semver 语义），
///   避免把预发布当正式版推给用户。早期实现把后缀整体忽略，`0.3.0-beta1` 会被
///   判成和 `0.3.0` 相等——发预发布时用户永远收不到提示。
fn version_newer(candidate: &str, current: &str) -> bool {
    let parse = |s: &str| -> ([u64; 3], bool) {
        let mut out = [0u64; 3];
        // 取 '-' 前的数字部分；'-' 之后是预发布后缀。
        let (numeric, has_pre) = match s.split_once('-') {
            Some((n, p)) => (n, !p.is_empty()),
            None => (s, false),
        };
        for (i, part) in numeric.trim().split('.').take(3).enumerate() {
            out[i] = part.parse().unwrap_or(0);
        }
        (out, has_pre)
    };
    let (c, c_pre) = parse(candidate);
    let (cur, cur_pre) = parse(current);
    match c.cmp(&cur) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        // 数字部分相同：带预发布后缀的一方更旧。
        std::cmp::Ordering::Equal => cur_pre && !c_pre,
    }
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

    /// 预发布后缀必须参与比较：`0.3.0-beta1` 比 `0.3.0` 旧（semver 语义）。
    /// 早期实现忽略后缀，会导致发预发布时用户永远收不到更新提示。
    #[test]
    fn version_newer_treats_prerelease_as_older() {
        // 正式版 vs 同一版本的预发布：正式版算更新。
        assert!(version_newer("0.3.0", "0.3.0-beta1"));
        // 预发布 vs 同一版本的正式版：不算更新。
        assert!(!version_newer("0.3.0-beta1", "0.3.0"));
        // 预发布 vs 更老的正式版：仍然是更新。
        assert!(version_newer("0.3.0-beta1", "0.2.0"));
        // 更高版本的预发布 vs 更低的正式版：是更新。
        assert!(version_newer("0.4.0-rc1", "0.3.0"));
        // 完全相同的字符串：无更新。
        assert!(!version_newer("0.3.0-beta1", "0.3.0-beta1"));
    }
}
