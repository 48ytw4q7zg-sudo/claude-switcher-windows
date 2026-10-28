//! 凭据存取（Windows 专用）。
//!
//! 官方凭据文件 `<claude_dir>\.credentials.json`，内容与 macOS Keychain blob 相同。
//! `claude_dir` = `CLAUDE_CONFIG_DIR`（若设置）否则 `%USERPROFILE%\.claude`；
//! 注意 `CLAUDE_CONFIG_DIR` 已经指向配置目录本身，凭据就在它下面，不再多一层 `.claude`。
//!
//! 统一暴露 read / write / clear / remove_legacy 四个动作。
//! 文案统一用 [`CREDENTIAL_STORE_LABEL`]。macOS Keychain 分支已按
//! 「只做 Windows」的产品决定移除。

use std::fs;
use std::path::PathBuf;

use crate::platform::imp;

/// 凭据存储的显示名称（用户可见文案、报错信息用）。
pub const CREDENTIAL_STORE_LABEL: &str = "凭据文件";
/// store 加密主密钥的存储项名。
pub const STORE_KEY_KEYCHAIN_SERVICE: &str = "claude-switcher-store-key";

pub fn current_username() -> Result<String, String> {
    imp::current_username()
}

/// 读取当前 OAuth 凭据（明文 JSON blob）。不存在返回 Ok(None)。
pub fn read_password() -> Result<Option<String>, String> {
    let path = credentials_path()?;
    if !crate::links::path_exists_or_link(&path) {
        return Ok(None);
    }
    let text =
        fs::read_to_string(&path).map_err(|e| format!("读取 .credentials.json 失败: {e}"))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_string()))
}

/// 写入 OAuth 凭据。Windows 上原子写入凭据文件。
///
/// 配置目录被用户改到用户 profile 之外（例如 `D:\claude-alt`）时，凭据文件继承的
/// 是盘符根 ACL（同机其他本地账户可能读到）。此时额外收敛为「当前用户 + SYSTEM」。
/// 默认位置在 profile 内、本来就私有，不做多余 icacls。
pub fn write_password(password: &str) -> Result<(), String> {
    let path = credentials_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    // 覆盖而非先删后写：remove+write 的窗口期崩溃会直接丢凭据。
    crate::fsx::write_atomically(&path, password).map_err(|e| {
        format!(
            "写入 .credentials.json 失败: {}",
            crate::fsx::humanize_io_error(&e)
        )
    })?;
    if !crate::platform::imp::is_under_user_profile(&path) {
        if crate::platform::imp::secure_private_file(&path) {
            crate::log_info(&format!(
                "配置目录在用户 profile 之外，已收敛凭据文件权限：{}",
                path.to_string_lossy()
            ));
        } else {
            crate::log_error(&format!(
                "凭据文件权限收敛失败（icacls 出错），该文件可能被同机其他账户读取：{}",
                path.to_string_lossy()
            ));
        }
    }
    Ok(())
}

/// 清空凭据（best-effort；不存在也成功）。
pub fn clear_password() -> Result<(), String> {
    let path = credentials_path()?;
    if crate::links::path_exists_or_link(&path) {
        let _ = crate::fsx::remove_file_with_retry(&path);
    }
    Ok(())
}

/// 清理早期版本的遗留凭据条目。Windows 上 `.credentials.json` 是主存储，
/// 「清理遗留」是空操作，绝不能删。
pub fn clear_legacy_password() -> Result<(), String> {
    Ok(())
}

/// 删除遗留的 `~/.claude/.credentials.json`：Windows 上它是主存储，
/// 空操作（见 [`clear_legacy_password`]）。
pub fn remove_legacy_credentials_file() -> Result<(), String> {
    Ok(())
}

// ───────────────────────── 路径 ─────────────────────────

/// 手动指定 Claude 配置目录的覆盖文件：`~/.claude-switcher/claude-config-dir.txt`，
/// 内容是**一行路径**。
///
/// 为什么需要它：从开始菜单 / 开机自启启动的 GUI 程序**读不到**用户在终端里
/// `$env:CLAUDE_CONFIG_DIR=...` 临时设置的环境变量（只能看到系统/用户级变量）。
/// 用户设了该变量却从开始菜单启动本工具时，凭据会被写进 Claude Code 不读的位置，
/// 切号表面成功实际无效。这个文件让用户在界面里指定一次，永久生效。
fn manual_config_dir_override() -> Option<PathBuf> {
    let path = crate::paths::app_data_dir()
        .ok()?
        .join("claude-config-dir.txt");
    let raw = std::fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(PathBuf::from(trimmed))
}

/// Claude 配置目录解析优先级：
/// 1. 手动指定文件 `~/.claude-switcher/claude-config-dir.txt`（GUI 启动也能生效）；
/// 2. 环境变量 `CLAUDE_CONFIG_DIR`（终端启动时生效）；
/// 3. `~/.claude`。
///
/// 官方支持 CLAUDE_CONFIG_DIR 重定向配置位置；不跟随会导致「切号写进了
/// Claude Code 不读的位置」，表面成功实际无效。
pub fn claude_dir() -> Result<PathBuf, String> {
    if let Some(dir) = manual_config_dir_override() {
        return Ok(dir);
    }
    if let Some(dir) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        let trimmed = dir.to_string_lossy().trim().to_string();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    Ok(crate::paths::home_dir()?.join(".claude"))
}

/// Windows 凭据文件路径。
pub fn credentials_path() -> Result<PathBuf, String> {
    Ok(claude_dir()?.join(".credentials.json"))
}
