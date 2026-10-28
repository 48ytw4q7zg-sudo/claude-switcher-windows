//! 路径解析（含 CLAUDE_CONFIG_DIR 跟随）与目录保障。

use std::fs;
use std::path::PathBuf;

use crate::fsx;
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
///
/// **已实证**（2026-10-26，claude 2.1.310，Windows）：设置 CLAUDE_CONFIG_DIR 后
/// 运行 claude，`.claude.json` 仍在用户主目录读写、不会搬到配置目录——
/// 与官方文档「凭据在 CLAUDE_CONFIG_DIR 下、全局配置在 home」一致。
/// 曾有第三方分析称它会跟随，实测不成立，勿改。
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

/// 切换事务日志：记录进行中的切换目标/步骤/备份 id；
/// 正常完成后删除，启动时发现残留即提示用户回滚。
pub fn switch_journal_path() -> Result<PathBuf, String> {
    Ok(app_data_dir()?.join("switch-journal.json"))
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

/// 确保工具目录存在，并在**首次创建或老目录升级**时做一次 ACL 收敛。
///
/// 为什么不能只在「目录刚创建时」做：早期版本创建过的目录永远不会被收紧，
/// 最需要升级的老用户反而被跳过。用 `~/.claude-switcher/.acl-hardened` 作为
/// 一次性迁移标记——标记存在且 ACL 已设置成功就不再重复执行。
///
/// 注意顺序：`secure_app_data_dir` 成功才写标记；失败不写，下次启动会重试。
pub fn ensure_app_dirs() -> Result<(), String> {
    let data_dir = app_data_dir()?;
    fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;

    let marker = data_dir.join(".acl-hardened");
    static HARDEN_TRIED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    // 每个进程最多尝试一次：icacls 不可用/卷不支持 ACL 时，不能让每次
    // 状态刷新都重新 spawn whoami + icacls 并刷满日志。下次启动仍会重试。
    if !marker.exists() && !HARDEN_TRIED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        if imp::secure_app_data_dir(&data_dir) {
            // 只有 ACL 真正设置成功才落标记，失败则下次启动重试。
            let _ = fs::write(&marker, b"acl hardened\n");
        } else {
            crate::log_error("ACL 加固失败（icacls 执行出错），本次运行不再重试，下次启动将重试");
        }
    }

    for dir in [
        backups_dir()?,
        session_profiles_dir()?,
        session_backups_dir()?,
    ] {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    // 清理上次进程被杀留下的原子写临时文件（`.xxx.tmp-<uuid>`）。
    cleanup_tmp_once();
    // 清理 Desktop 回存的两段式替换残留（`<id>.new` / `<id>.old`）。
    cleanup_desktop_swap_residue_once();
    Ok(())
}

/// 进程内只执行一次清理 Desktop 回存的替换残留。
///
/// 回存走「拷到 `<id>.new` → 旧目录改名 `<id>.old` → `.new` 改正式名 → 删 `.old`」。
/// 进程在中间任意一步被杀（断电、强杀）就会留下 `.new` 或 `.old`：
/// - `.old` 里装的还是**旧快照**，直接删会丢失该账号的上一次状态；
/// - `.new` 是半成品，下次回存会先被清掉。
///
/// 保守策略：只删 `.new`（半成品，无独有价值）；`.old` 保留并记日志，
/// 让用户决定——里面可能是唯一副本。它们在 `desktop-accounts/` 下，以下划线
/// 前缀不参与账号枚举。
fn cleanup_desktop_swap_residue_once() {
    static CLEANUP_ONCE: std::sync::Once = std::sync::Once::new();
    CLEANUP_ONCE.call_once(|| {
        let Ok(accounts) = app_data_dir().map(|d| d.join("desktop-accounts")) else {
            return;
        };
        let Ok(entries) = fs::read_dir(&accounts) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            // `.new` 是回存的半成品，安全删除。
            if let Some(id) = name.strip_suffix(".new") {
                let _ = fsx::retry_io(|| fs::remove_dir_all(entry.path()));
                crate::log_info(&format!(
                    "已清理上次中断的 Desktop 回存半成品（账号 {}）",
                    id
                ));
            } else if let Some(id) = name.strip_suffix(".old") {
                // `.old` 可能是唯一副本，只提示不删。
                crate::log_info(&format!(
                    "发现 Desktop 回存残留的旧快照目录（账号 {}）：{}。\
                     其中是上一次的快照状态，确认无需恢复后可手动删除。",
                    id,
                    entry.path().display()
                ));
            }
        }
    });
}

/// 进程内只执行一次的 tmp 清理（`Once`）：避免每次 `ensure_app_dirs` 都删一遍，
/// 把正在并发写入的临时文件误删（Windows 允许删除已打开的文件，随后的 rename 会失败）。
fn cleanup_tmp_once() {
    static CLEANUP_ONCE: std::sync::Once = std::sync::Once::new();
    CLEANUP_ONCE.call_once(|| {
        let _ = crate::fsx::cleanup_stale_tmp_files(&app_data_dir().unwrap_or_default());
        let _ = crate::fsx::cleanup_stale_tmp_files(&backups_dir().unwrap_or_default());
    });
}
