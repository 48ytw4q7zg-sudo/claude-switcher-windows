//! 路径解析（含 CLAUDE_CONFIG_DIR 跟随）与目录保障。

use std::fs;
use std::path::PathBuf;

use crate::platform::imp;

/// HOME 目录：`USERPROFILE` → `dirs::home_dir()`。
/// Windows 上优先 USERPROFILE（跟 Claude Code 的行为一致；Git Bash 里设置的
/// HOME 会把凭据/配置目录分叉，明确定义优先级避免歧义）。
pub fn home_dir() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            let trimmed = profile.to_string_lossy().trim().to_string();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed));
            }
        }
    }
    dirs::home_dir().ok_or_else(|| "无法定位 HOME 目录".to_string())
}

/// `~/.claude.json`（注意在 home，不在 .claude 里；CLAUDE_CONFIG_DIR 不影响它）。
pub fn claude_json_path() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(".claude.json"))
}

pub fn claude_settings_path() -> Result<PathBuf, String> {
    Ok(crate::credentials::claude_dir()?.join("settings.json"))
}

pub fn claude_projects_dir() -> Result<PathBuf, String> {
    Ok(crate::credentials::claude_dir()?.join("projects"))
}

pub fn claude_local_dir(name: &str) -> Result<PathBuf, String> {
    Ok(crate::credentials::claude_dir()?.join(name))
}

pub fn claude_config_json_path() -> Result<PathBuf, String> {
    Ok(crate::credentials::claude_dir()?.join("config.json"))
}

/// 本工具私有数据目录 `~/.claude-switcher`。
pub fn app_data_dir() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(".claude-switcher"))
}

pub fn store_path() -> Result<PathBuf, String> {
    Ok(app_data_dir()?.join("store.private.json"))
}

pub fn backups_dir() -> Result<PathBuf, String> {
    Ok(app_data_dir()?.join("backups"))
}

pub fn session_profiles_dir() -> Result<PathBuf, String> {
    Ok(app_data_dir()?.join("session-profiles"))
}

pub fn session_backups_dir() -> Result<PathBuf, String> {
    Ok(app_data_dir()?.join("session-backups"))
}

pub fn profile_sessions_dir(profile_id: &str) -> Result<PathBuf, String> {
    Ok(session_profiles_dir()?.join(profile_id).join("projects"))
}

pub fn profile_claude_local_dir(profile_id: &str, name: &str) -> Result<PathBuf, String> {
    Ok(session_profiles_dir()?.join(profile_id).join(name))
}

pub fn profile_claude_config_json_path(profile_id: &str) -> Result<PathBuf, String> {
    Ok(session_profiles_dir()?.join(profile_id).join("config.json"))
}

/// Clash Verge Rev 的配置目录（Tauri 应用，identifier 固定）：
/// - macOS:  ~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev
/// - Windows: %APPDATA%\io.github.clash-verge-rev.clash-verge-rev
/// - Linux:  ~/.config/io.github.clash-verge-rev.clash-verge-rev
pub fn clash_verge_dir() -> Result<PathBuf, String> {
    let config_dir = dirs::config_dir()
        .or_else(dirs::home_dir)
        .ok_or_else(|| "无法定位 Clash Verge 配置目录".to_string())?;
    Ok(config_dir.join("io.github.clash-verge-rev.clash-verge-rev"))
}

pub fn clash_config_candidates() -> Result<Vec<PathBuf>, String> {
    let base = clash_verge_dir()?;
    Ok(vec![
        base.join("config.yaml"),
        base.join("clash-verge.yaml"),
        base.join("clash-verge-check.yaml"),
    ])
}

/// 确保工具目录存在。**只在目录刚创建时**做一次 ACL 收敛（子项继承），
/// 不再逐文件 icacls，也绝不动 Claude Code 自己文件的 ACL。
pub fn ensure_app_dirs() -> Result<(), String> {
    let data_dir = app_data_dir()?;
    let needs_secure = !data_dir.exists();
    fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
    if needs_secure {
        imp::secure_app_data_dir(&data_dir);
    }
    for dir in [
        backups_dir()?,
        session_profiles_dir()?,
        session_backups_dir()?,
    ] {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    Ok(())
}
