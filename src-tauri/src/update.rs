//! 应用内版本检查：请求 GitHub Releases latest，与当前版本比较。
//!
//! 只提示、不自动安装（未签名场景下 tauri-plugin-updater 的签名密钥方案不现实）。
//! 匿名 API 有限流（403）：失败一律静默返回「检查失败」，绝不弹错、绝不阻塞主线程。

use std::{path::Path, time::Duration};

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
/// **成功与失败使用不同 TTL**：失败（限流/断网）也用长 TTL 的话，断网时打开一次，
/// 之后 6 小时内即使网络恢复，面板也只会返回缓存的失败——用户以为升级通道
/// 坏了。失败改用短 TTL，很快会重新尝试。
///
/// 读缓存时校验 `current_version`：用户在缓存期内升级到新版本后，旧缓存会说
/// 「发现新版本 v0.3.0（当前 v0.2.0）」——版本号已经对不上了。
pub fn check_for_update_blocking() -> UpdateCheckResult {
    let current = env!("CARGO_PKG_VERSION").to_string();
    check_for_update_with(
        &current,
        cache_path().as_deref(),
        chrono::Utc::now().timestamp(),
        || fetch_latest(&current),
    )
}

fn check_for_update_with(
    current: &str,
    path: Option<&Path>,
    now: i64,
    fetch: impl FnOnce() -> UpdateCheckResult,
) -> UpdateCheckResult {
    if let Some(cached) = path.and_then(|path| read_cache(path, current, now)) {
        return cached.result;
    }

    let fresh = fetch();
    if let Some(path) = path {
        write_cache(path, now, &fresh);
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

fn read_cache(path: &Path, current: &str, now: i64) -> Option<CachedCheck> {
    let raw = std::fs::read_to_string(path).ok()?;
    let mut cached: CachedCheck = serde_json::from_str(&raw).ok()?;
    let age = now.checked_sub(cached.checked_at)?;
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
    // 旧版本缓存里的比较结果可能不符合 SemVer；复用发布信息，重新计算结论。
    // 非法版本不能沿用六小时成功缓存，也不能冒充「已是最新」。
    if let Some(latest) = &cached.result.latest_version {
        cached.result = result_for_version(current, latest, &cached.result.release_url).ok()?;
    }
    // 标注这是缓存值：用户看到「有更新」时能判断信息可能不够新。
    let checked_ago = if age < 3600 {
        format!("{} 分钟前", age / 60)
    } else {
        format!("{} 小时前", age / 3600)
    };
    cached.result.message = format!("{}（{checked_ago}检查，缓存）", cached.result.message);
    Some(cached)
}

fn write_cache(path: &Path, now: i64, result: &UpdateCheckResult) {
    let cached = CachedCheck {
        checked_at: now,
        result: result.clone(),
    };
    if let Ok(text) = serde_json::to_string(&cached) {
        let _ = fsx::write_atomically(path, &text);
    }
}

fn fetch_latest(current: &str) -> UpdateCheckResult {
    // GitHub API 要求 User-Agent；限流 403 / 断网都归入「检查失败」静默。
    //
    // **P1-10**：版本号查询走 `Standard` 策略——它只取公开的 tag_name，
    // 不携带任何账号信息，代理不可用时直连也不构成泄漏；但策略必须显式，
    // 不能靠「用了裸 builder 所以默认行为就是这样」。
    let client = match crate::network_policy::build_client(
        &crate::network_policy::ClientSpec::new(
            crate::network_policy::NetworkPolicy::Standard,
            Duration::from_secs(8),
        ),
        None,
    ) {
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

    result_from_release(current, &value)
}

fn result_from_release(current: &str, value: &serde_json::Value) -> UpdateCheckResult {
    let tag = value
        .get("tag_name")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let latest = tag.strip_prefix('v').unwrap_or(tag);
    let url = value
        .get("html_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if latest.is_empty() {
        return failure(current, "响应缺少 tag_name".to_string());
    }

    result_for_version(current, latest, url).unwrap_or_else(|e| failure(current, e))
}

/// SemVer 优先级比较：预发布标识符参与排序，构建信息不影响新旧。
/// 非法版本不能当作 0，也不能报告为「已是最新」。
fn result_for_version(current: &str, latest: &str, url: &str) -> Result<UpdateCheckResult, String> {
    let release_url = url::Url::parse(url).map_err(|_| "发布页地址缺失或无效".to_string())?;
    let expected_path = "/48ytw4q7zg-sudo/claude-switcher-windows/releases/tag/";
    if release_url.scheme() != "https"
        || release_url.host_str() != Some("github.com")
        || !release_url.username().is_empty()
        || release_url.password().is_some()
        || release_url.port().is_some()
        || !release_url.path().starts_with(expected_path)
        || release_url.path().len() == expected_path.len()
    {
        return Err("发布页地址不属于本项目的 GitHub Release".to_string());
    }
    let candidate = parse_release_version(latest)?;
    let installed = match parse_release_version(current) {
        Ok(version) => version,
        // **P1-09**：本机装的是历史四段版本（如 `0.6.13.1`，Cargo 早已不接受
        // 这种写法，但它确实发布过）。此时不能报「版本号格式无效」让用户
        // 永久看不到更新——按 SemVer 语义把第四段当作构建号忽略。
        Err(error) => match parse_legacy_four_segment(current) {
            Some(version) => version,
            None => return Err(error),
        },
    };
    let has_update = candidate.cmp_precedence(&installed).is_gt();
    let legacy_note = if current.trim().split('.').count() == 4 {
        "（检测到旧版四段版本号，已按前三段比较）"
    } else {
        ""
    };
    Ok(UpdateCheckResult {
        message: if has_update {
            format!("发现新版本 v{latest}（当前 v{current}）{legacy_note}")
        } else {
            format!("已是最新版本（v{current}）{legacy_note}")
        },
        current_version: current.to_string(),
        latest_version: Some(latest.to_string()),
        has_update,
        release_url: url.to_string(),
    })
}

/// 解析发布版本号（必须是三段 SemVer 或带预发布的 SemVer）。
fn parse_release_version(raw: &str) -> Result<semver::Version, String> {
    let trimmed = raw.trim();
    // 只接受 `x.y.z` 与 `x.y.z-pre`：四段版本会被 semver 拒绝，而 GitHub
    // tag 里出现 `v1.2.3.4` 时应当明确报错而不是静默截断。
    if trimmed.is_empty() {
        return Err("发布版本号为空".to_string());
    }
    semver::Version::parse(trimmed).map_err(|e| format!("发布版本号格式无效: {e}"))
}

/// 把历史四段版本 `x.y.z.w` 转成可比较的 SemVer（丢弃第四段）。
///
/// **P1-09**：v0.6.13.1 是用四段号发布的；Cargo 后来不再接受四段，
/// 但用户机器上装的仍是那个版本。升级检查必须能把它读出来，
/// 否则这些用户永远看不到新版本（每次检查都是「版本号格式无效」）。
fn parse_legacy_four_segment(raw: &str) -> Option<semver::Version> {
    let parts: Vec<&str> = raw.trim().split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    if !parts
        .iter()
        .all(|p| p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty())
    {
        return None;
    }
    semver::Version::parse(&format!("{}.{}.{}", parts[0], parts[1], parts[2])).ok()
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

/// 下载 + 校验 + 安装更新的完整流程结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInstallResult {
    /// 是否成功完成下载。
    pub downloaded: bool,
    /// 是否成功校验 SHA256。
    pub verified: bool,
    /// **仅表示安装器进程已启动**（不代表安装完成或版本已替换）。
    pub installed: bool,
    /// 人话说明（含失败原因）。
    pub message: String,
    /// 下载到本地的安装包路径。
    pub local_path: Option<String>,
}

/// 计算 SHA256（纯函数）。
pub fn compute_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// 下载 + 校验 + 安装更新（完整流程）。
/// **P1-04**：更新前置检查——存在未完成的保护/恢复状态时拒绝安装。
///
/// 三类拦截：
/// 1. 断网账本存在（网络被规则挡着，安装包可能根本下载不了，恢复逻辑也会被打断）；
/// 2. 处于隔离状态（本产品防火墙规则仍在）；
/// 3. 隔离状态无法确认（查询失败）——同样不能安装。
fn ensure_no_protection_transaction() -> Result<(), String> {
    // **P1-04**：三态显式匹配。原实现 `if let Ok(Some(_))` 会让 `Err`
    // （账本损坏/不可读）直接放行——恰恰是最需要拦的情况。
    match crate::egate_netcut::load_state() {
        Ok(None) => {}
        Ok(Some(_)) => {
            return Err(
                "系统当前处于全局断网状态（存在断网账本）。请先执行「恢复网络」再更新，                 否则更新会打断恢复流程"
                    .to_string(),
            )
        }
        Err(error) => {
            return Err(format!(
                "无法读取断网账本（{error}），无法确认系统是否处于断网状态。                 为避免更新打断恢复流程，本次更新已中止"
            ))
        }
    }
    if crate::egate_monitor::is_tripped() || crate::egate_monitor::is_partial() {
        return Err("系统当前处于应用隔离状态。请先解除隔离并确认出口正常后再更新。".to_string());
    }
    if crate::egate_monitor::is_trip_state_unknown() {
        return Err(
            "无法确认当前隔离状态（防火墙查询失败）。为避免更新打断恢复流程，             请先打开保护面板核对后再更新"
                .to_string(),
        );
    }
    Ok(())
}

pub fn download_and_install_blocking(
    version: &str,
    sha256: &str,
) -> Result<UpdateInstallResult, String> {
    validate_update_params(version, sha256)?;
    // **P1-04**：更新前先确认没有正在进行的保护/恢复事务。
    //
    // 安装会替换正在运行的程序；若此刻系统处于隔离/断网/未知状态，
    // 新版启动时看到的是「半恢复」现场，比不更新更危险。
    ensure_no_protection_transaction()?;
    let asset_name = format!("ClaudeSwitcher_{version}_x64-setup.exe");
    let url = format!(
        "https://github.com/48ytw4q7zg-sudo/claude-switcher-windows/releases/download/v{version}/{asset_name}"
    );
    // **P1-04**：写入**每次新建的随机暂存目录**，不再复用固定的
    // `%TEMP%\<固定文件名>`。固定路径有两个真实风险：
    // 1. 另一个进程可先在该路径放同名文件（本地提权的经典手法）；
    // 2. 两次下载并发时会互相覆盖，校验和与文件内容可能不是同一份。
    let staging = make_staging_dir().map_err(|error| format!("创建下载暂存目录失败：{error}"))?;
    let local_path = staging.join(&asset_name);

    // **P1-10**：安装包下载走 `Standard` 策略：下载的是本项目的公开制品，
    // 地址是固定的 GitHub Release，不含用户凭据；且断网/代理不可用时
    // 下载本来就会失败，不会造成身份泄漏。策略仍显式声明，避免默认行为漂移。
    let client = crate::network_policy::build_client(
        &crate::network_policy::ClientSpec::new(
            crate::network_policy::NetworkPolicy::Standard,
            Duration::from_secs(600),
        ),
        None,
    )
    .map_err(|e| format!("初始化下载客户端失败：{e}"))?;
    let response = client
        .get(&url)
        .send()
        .map_err(|e| format!("下载安装包失败：{e}"))?;
    if !response.status().is_success() {
        return Err(format!("下载失败（HTTP {}）", response.status()));
    }
    // L-06: refuse absurdly large downloads instead of buffering them fully.
    if let Some(len) = response.content_length() {
        if len > MAX_UPDATE_BYTES {
            return Err(format!(
                "安装包体积异常（{len} 字节，上限 {MAX_UPDATE_BYTES}），已拒绝下载"
            ));
        }
    }
    let bytes = response
        .bytes()
        .map_err(|e| format!("读取下载内容失败：{e}"))?;
    std::fs::write(&local_path, &bytes).map_err(|e| format!("保存安装包失败：{e}"))?;

    let local_bytes = std::fs::read(&local_path).map_err(|e| format!("读取安装包失败：{e}"))?;
    let actual = compute_sha256(&local_bytes);
    if actual != sha256.trim().to_ascii_lowercase() {
        return Err("SHA256 校验失败，已拒绝安装".to_string());
    }

    // **P1-04**：下载可能耗时数分钟，期间状态可能变化——启动安装器**之前**
    // 必须再核验一次，并在持有系统操作锁的情况下启动，避免与恢复流程并发。
    let guard = crate::egate_lock::acquire(crate::egate_lock::SystemOperation::FullRestore)
        .map_err(|e| format!("无法获取系统维护权（{e}），已取消安装以免打断保护流程"))?;
    ensure_no_protection_transaction()?;
    crate::platform::imp::silent_command(&local_path.to_string_lossy())
        .spawn()
        .map_err(|e| format!("启动安装包失败：{e}"))?;
    drop(guard);

    Ok(UpdateInstallResult {
        downloaded: true,
        verified: true,
        // **P1-04**：仅表示安装器已启动，不表示安装完成。安装结果需要用户
        // 在向导中确认并重启应用后由版本号核验。
        installed: false,
        message: "已下载并校验安装包，安装向导已启动。请按向导完成安装并重启应用后生效（本工具不核验安装结果）"
            .to_string(),
        local_path: Some(local_path.to_string_lossy().to_string()),
    })
}

/// **P1-04**：为一次下载创建全新的随机暂存目录。
///
/// 目录名带随机后缀且**必须新建成功**（`create_dir` 而非 `create_dir_all`：
/// 已存在就失败，避免复用一个可能被别人预置过的目录）。
fn make_staging_dir() -> std::io::Result<std::path::PathBuf> {
    use rand::Rng;
    let base = std::env::temp_dir();
    // 最多重试若干次，避免随机后缀碰撞（碰撞概率极低，但不做重试就等于偶发失败）。
    for _ in 0..8 {
        let suffix: u64 = rand::thread_rng().gen();
        let dir = base.join(format!("claude-switcher-update-{suffix:016x}"));
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "无法创建唯一的下载暂存目录",
    ))
}

/// L-06 (v0.7.1): validate untrusted update parameters before touching the network
/// or building any filesystem path from them.
///
/// `version` and `sha256` come from the release feed; a crafted value such as
/// `../../x` would otherwise flow straight into the download URL and file name.
fn validate_update_params(version: &str, sha256: &str) -> Result<(), String> {
    let v = version.trim();
    if v.is_empty() || v.len() > 32 {
        return Err("更新版本号为空或过长，已拒绝".to_string());
    }
    if !v
        .chars()
        .all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c.is_ascii_alphanumeric())
        || v.contains("..")
        || v.contains('/')
        || v.contains('\\')
    {
        return Err(format!("更新版本号包含非法字符，已拒绝：{v}"));
    }
    let h = sha256.trim();
    if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("更新校验值不是合法的 SHA-256（需 64 位十六进制），已拒绝".to_string());
    }
    Ok(())
}

/// Upper bound for a downloaded installer (200 MiB).
const MAX_UPDATE_BYTES: u64 = 200 * 1024 * 1024;

/// 下载 + 校验但不安装。
pub fn download_and_verify_blocking(
    version: &str,
    sha256: &str,
) -> Result<UpdateInstallResult, String> {
    validate_update_params(version, sha256)?;
    let asset_name = format!("ClaudeSwitcher_{version}_x64-setup.exe");
    let url = format!(
        "https://github.com/48ytw4q7zg-sudo/claude-switcher-windows/releases/download/v{version}/{asset_name}"
    );
    // **P1-04**：写入**每次新建的随机暂存目录**，不再复用固定的
    // `%TEMP%\<固定文件名>`。固定路径有两个真实风险：
    // 1. 另一个进程可先在该路径放同名文件（本地提权的经典手法）；
    // 2. 两次下载并发时会互相覆盖，校验和与文件内容可能不是同一份。
    let staging = make_staging_dir().map_err(|error| format!("创建下载暂存目录失败：{error}"))?;
    let local_path = staging.join(&asset_name);

    // **P1-10**：安装包下载走 `Standard` 策略：下载的是本项目的公开制品，
    // 地址是固定的 GitHub Release，不含用户凭据；且断网/代理不可用时
    // 下载本来就会失败，不会造成身份泄漏。策略仍显式声明，避免默认行为漂移。
    let client = crate::network_policy::build_client(
        &crate::network_policy::ClientSpec::new(
            crate::network_policy::NetworkPolicy::Standard,
            Duration::from_secs(600),
        ),
        None,
    )
    .map_err(|e| format!("初始化下载客户端失败：{e}"))?;
    let response = client
        .get(&url)
        .send()
        .map_err(|e| format!("下载安装包失败：{e}"))?;
    if !response.status().is_success() {
        return Err(format!("下载失败（HTTP {}）", response.status()));
    }
    // L-06: refuse absurdly large downloads instead of buffering them fully.
    if let Some(len) = response.content_length() {
        if len > MAX_UPDATE_BYTES {
            return Err(format!(
                "安装包体积异常（{len} 字节，上限 {MAX_UPDATE_BYTES}），已拒绝下载"
            ));
        }
    }
    let bytes = response
        .bytes()
        .map_err(|e| format!("读取下载内容失败：{e}"))?;
    std::fs::write(&local_path, &bytes).map_err(|e| format!("保存安装包失败：{e}"))?;

    let local_bytes = std::fs::read(&local_path).map_err(|e| format!("读取安装包失败：{e}"))?;
    let actual = compute_sha256(&local_bytes);
    if actual != sha256.trim().to_ascii_lowercase() {
        return Err("SHA256 校验失败，已拒绝安装".to_string());
    }

    Ok(UpdateInstallResult {
        downloaded: true,
        verified: true,
        installed: false,
        message: "已下载并校验，可安装".to_string(),
        local_path: Some(local_path.to_string_lossy().to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELEASE_URL: &str =
        "https://github.com/48ytw4q7zg-sudo/claude-switcher-windows/releases/tag/v0.7.0";

    fn version_newer(candidate: &str, current: &str) -> bool {
        result_for_version(current, candidate, RELEASE_URL)
            .map(|result| result.has_update)
            .unwrap_or(false)
    }

    #[test]
    fn failed_check_is_reused_before_retry_window_expires() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("update-check.json");
        let first = check_for_update_with("0.6.0", Some(&cache), 1000, || {
            failure("0.6.0", "GitHub unavailable".into())
        });
        assert!(first.latest_version.is_none());
        let repeated = check_for_update_with("0.6.0", Some(&cache), 1001, || {
            panic!("a repeated failed check must not request GitHub again")
        });
        assert!(repeated.latest_version.is_none());
        assert!(repeated.message.contains("缓存"));
    }

    #[test]
    fn malformed_release_is_a_failed_check_not_up_to_date() {
        for tag in ["v0.7.x", "vv0.7.0", "0.7.0.1", "01.7.0", "0.7.0-rc.01", ""] {
            let result = result_from_release(
                "0.6.0",
                &serde_json::json!({"tag_name": tag, "html_url": RELEASE_URL}),
            );
            assert!(
                result.latest_version.is_none(),
                "accepted invalid tag {tag}"
            );
            assert!(!result.has_update);
            assert!(result.message.contains("检查失败"));
        }
        assert!(
            result_from_release("0.6.0", &serde_json::json!({"html_url": RELEASE_URL}))
                .latest_version
                .is_none()
        );
        assert!(result_from_release(
            "0.6.0",
            &serde_json::json!({"tag_name": 7, "html_url": RELEASE_URL})
        )
        .latest_version
        .is_none());
    }

    #[test]
    fn missing_or_untrusted_release_url_is_not_a_successful_check() {
        for url in [
            serde_json::Value::Null,
            serde_json::json!(17),
            serde_json::json!(""),
            serde_json::json!("https://example.com/download"),
            serde_json::json!("https://github.com/other/repo/releases/tag/v0.7.0"),
        ] {
            let result = result_from_release(
                "0.6.0",
                &serde_json::json!({"tag_name": "v0.7.0", "html_url": url}),
            );
            assert!(result.latest_version.is_none());
            assert!(!result.has_update);
            assert!(result.release_url.is_empty());
        }
    }

    #[test]
    fn failed_check_retries_after_ten_minutes_and_caches_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("update-check.json");
        check_for_update_with("0.6.0", Some(&cache), 1000, || {
            failure("0.6.0", "offline".into())
        });
        check_for_update_with("0.6.0", Some(&cache), 1600, || panic!("retry is too early"));
        let recovered = check_for_update_with("0.6.0", Some(&cache), 1601, || {
            result_for_version("0.6.0", "0.7.0", RELEASE_URL).unwrap()
        });
        assert!(recovered.has_update);
        let cached = check_for_update_with("0.6.0", Some(&cache), 2202, || {
            panic!("success uses the longer TTL")
        });
        assert_eq!(cached.latest_version.as_deref(), Some("0.7.0"));
    }

    #[test]
    fn successful_check_is_reused_for_six_hours_then_refetched() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("update-check.json");
        check_for_update_with("0.6.0", Some(&cache), 1000, || {
            result_for_version("0.6.0", "0.7.0", RELEASE_URL).unwrap()
        });
        let cached =
            check_for_update_with("0.6.0", Some(&cache), 22600, || panic!("cache still valid"));
        assert_eq!(cached.latest_version.as_deref(), Some("0.7.0"));
        let fresh = check_for_update_with("0.6.0", Some(&cache), 22601, || {
            result_for_version("0.6.0", "0.8.0", RELEASE_URL).unwrap()
        });
        assert_eq!(fresh.latest_version.as_deref(), Some("0.8.0"));
    }

    #[test]
    fn application_upgrade_invalidates_success_and_failure_caches() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("update-check.json");
        for old in [
            result_for_version("0.6.0", "0.7.0", RELEASE_URL).unwrap(),
            failure("0.6.0", "offline".into()),
        ] {
            check_for_update_with("0.6.0", Some(&cache), 1000, || old);
            let result = check_for_update_with("0.7.0", Some(&cache), 1001, || {
                result_for_version("0.7.0", "0.7.0", RELEASE_URL).unwrap()
            });
            assert_eq!(result.current_version, "0.7.0");
            assert!(!result.has_update);
        }
    }

    #[test]
    fn corrupt_cache_is_replaced_by_a_fresh_result() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("update-check.json");
        std::fs::write(&cache, "{incomplete").unwrap();
        let result = check_for_update_with("0.6.0", Some(&cache), 1000, || {
            result_for_version("0.6.0", "0.7.0", RELEASE_URL).unwrap()
        });
        assert!(result.has_update);
        check_for_update_with("0.6.0", Some(&cache), 1001, || {
            panic!("new cache must be usable")
        });
    }

    #[test]
    fn cache_unavailable_or_unwritable_does_not_hide_the_check_result() {
        let dir = tempfile::tempdir().unwrap();
        let parent_file = dir.path().join("file-not-directory");
        std::fs::write(&parent_file, "preserve me").unwrap();
        let cache = parent_file.join("update-check.json");
        for path in [None, Some(cache.as_path())] {
            let result = check_for_update_with("0.6.0", path, 1000, || {
                result_for_version("0.6.0", "0.7.0", RELEASE_URL).unwrap()
            });
            assert!(result.has_update);
            let failed =
                check_for_update_with("0.6.0", path, 1001, || failure("0.6.0", "offline".into()));
            assert!(failed.latest_version.is_none());
        }
        assert_eq!(std::fs::read_to_string(parent_file).unwrap(), "preserve me");
    }

    #[test]
    fn release_tag_and_build_metadata_follow_semver_precedence() {
        let result = result_from_release(
            "0.6.0+local",
            &serde_json::json!({"tag_name":"v0.6.0+release", "html_url": RELEASE_URL}),
        );
        assert_eq!(result.latest_version.as_deref(), Some("0.6.0+release"));
        assert!(!result.has_update);
        assert!(version_newer("0.6.1+release", "0.6.0+local"));
        assert!(!version_newer("0.6.0+release", "0.6.1+local"));
        assert!(version_newer("0.7.0-rc.1+build", "0.7.0-beta.11+build"));
        assert!(result_for_version("invalid", "0.7.0", RELEASE_URL).is_err());
    }

    #[test]
    fn invalid_cache_timestamps_trigger_a_fresh_check() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("update-check.json");
        for checked_at in [1001, i64::MIN] {
            write_cache(&cache, checked_at, &failure("0.6.0", "old failure".into()));
            let result = check_for_update_with("0.6.0", Some(&cache), 1000, || {
                result_for_version("0.6.0", "0.7.0", RELEASE_URL).unwrap()
            });
            assert!(result.has_update, "invalid timestamp {checked_at} reused");
        }
    }

    #[test]
    fn legacy_cache_recomputes_version_precedence_and_rejects_invalid_versions() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("update-check.json");
        let mut old = result_for_version("0.7.0-rc.2", "0.7.0-rc.10", RELEASE_URL).unwrap();
        old.has_update = false;
        old.message = "old comparison was wrong".into();
        write_cache(&cache, 1000, &old);
        let corrected = check_for_update_with("0.7.0-rc.2", Some(&cache), 1001, || {
            panic!("valid legacy cache should be reused with corrected comparison")
        });
        assert!(corrected.has_update);
        assert!(corrected.message.contains("发现新版本"));

        old.latest_version = Some("not-a-version".into());
        write_cache(&cache, 1000, &old);
        let fresh = check_for_update_with("0.7.0-rc.2", Some(&cache), 1001, || {
            result_for_version("0.7.0-rc.2", "0.7.0", RELEASE_URL).unwrap()
        });
        assert_eq!(fresh.latest_version.as_deref(), Some("0.7.0"));
    }

    #[test]
    fn version_newer_compares_semver_fields() {
        assert!(version_newer("0.2.0", "0.1.0"));
        assert!(version_newer("1.0.0", "0.9.9"));
        assert!(version_newer("0.1.1", "0.1.0"));
        assert!(!version_newer("0.1.0", "0.1.0"));
        assert!(!version_newer("0.0.9", "0.1.0"));
    }

    /// **P1-09**：历史四段版本（v0.6.13.1 时代发布过）必须仍能收到更新。
    ///
    /// 回归点：`semver` 拒绝四段号，旧实现会把它报成「版本号格式无效」，
    /// 于是一台装着 0.6.13.1 的机器永远看不到任何新版本。
    #[test]
    fn legacy_four_segment_installed_version_still_sees_updates() {
        let result = result_for_version("0.6.13.1", "0.7.2", RELEASE_URL).unwrap();
        assert!(
            result.has_update,
            "四段旧版本必须能识别出 0.7.2 更新：{}",
            result.message
        );
        assert!(result.message.contains("旧版四段版本号"));
        // 四段号本身作为「发布版本」仍然非法：不能从 tag 推断更新。
        assert!(result_for_version("0.7.1", "0.7.2.1", RELEASE_URL).is_err());
        // 非数字四段不被当成旧版兼容。
        assert!(parse_legacy_four_segment("0.6.13.beta").is_none());
        assert_eq!(
            parse_legacy_four_segment("0.6.13.1").map(|v| v.to_string()),
            Some("0.6.13".to_string())
        );
    }

    #[test]
    fn version_newer_orders_prerelease_identifiers() {
        assert!(version_newer("0.7.0-rc.10", "0.7.0-rc.2"));
        assert!(!version_newer("0.7.0-rc.2", "0.7.0-rc.10"));
    }

    /// 格式异常不构成可用更新，绝不 panic。
    #[test]
    fn version_newer_tolerates_garbage() {
        assert!(!version_newer("abc", "0.1.0"));
        assert!(!version_newer("0.2.x", "0.1.0"));
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
