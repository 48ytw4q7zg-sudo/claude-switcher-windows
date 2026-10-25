//! 会话/本地状态隔离：把 ~/.claude 下的账号痕迹按 profile 接管与激活。

use std::fs;
use std::path::Path;

use chrono::Utc;
use uuid::Uuid;

use crate::fsx;
use crate::jsonio::write_json_pretty;
use crate::links::{self, LinkMode};
use crate::paths;
use serde_json::json;

#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionIsolationStatus {
    pub enabled: bool,
    pub live_path: String,
    pub target_path: Option<String>,
    pub current_profile_path: Option<String>,
    /// 当前 live 链接的模式（符号链接 / Junction / 硬链接 / 未链接）。
    pub link_mode: String,
    /// 是否处于降级模式（Junction / 硬链接）——Windows 未开开发者模式时为 true，
    /// 前端据此提示「开启开发者模式以获得符号链接」。
    pub degraded: bool,
}

fn backup_label(label: &str) -> String {
    label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn move_path_to_session_backup(path: &Path, label: &str) -> Result<std::path::PathBuf, String> {
    fs::create_dir_all(paths::session_backups_dir()?).map_err(|e| e.to_string())?;
    let backup_name = format!(
        "{}-{}-{}",
        Utc::now().format("%Y%m%d%H%M%S"),
        backup_label(label),
        Uuid::new_v4()
    );
    let backup_path = paths::session_backups_dir()?.join(backup_name);
    let renamed = fsx::retry_io(|| fs::rename(path, &backup_path));
    renamed
        .map_err(|e| {
            format!(
                "移动 session 目录到备份失败: {}",
                fsx::humanize_io_error(&e)
            )
        })
        .map(|_| backup_path)
}

// ───────────────────────── projects（目录） ─────────────────────────

pub fn adopt_live_sessions_for_profile(profile_id: &str) -> Result<Vec<String>, String> {
    paths::ensure_app_dirs()?;
    let live = paths::claude_projects_dir()?;
    let target = paths::profile_sessions_dir(profile_id)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    if !links::path_exists_or_link(&live) {
        fs::create_dir_all(&target).map_err(|e| format!("创建 profile session 目录失败: {e}"))?;
        return Ok(Vec::new());
    }

    if links::path_is_link(&live) {
        fs::create_dir_all(&target).map_err(|e| format!("创建 profile session 目录失败: {e}"))?;
        if links::is_linked_to(&live, &target) {
            return Ok(Vec::new());
        }
        let linked_to = fs::read_link(&live).ok();
        return Ok(vec![format!(
            "当前 ~/.claude/projects 已指向其他隔离目录（{}），未把它接管到当前账号",
            linked_to
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "无法读取目标".to_string())
        )]);
    }

    let mut warnings = Vec::new();
    if links::path_exists_or_link(&target) {
        let backup_path = move_path_to_session_backup(&target, "existing-profile-projects")?;
        warnings.push(format!(
            "已备份目标账号原 session 目录：{}",
            backup_path.to_string_lossy()
        ));
    }
    let renamed = fsx::retry_io(|| fs::rename(&live, &target));
    renamed.map_err(|e| {
        format!(
            "接管当前 ~/.claude/projects 到账号隔离目录失败（{} -> {}）: {}",
            live.to_string_lossy(),
            target.to_string_lossy(),
            fsx::humanize_io_error(&e)
        )
    })?;
    warnings.push(format!(
        "已把当前 Claude sessions 接管到账号隔离目录：{}",
        target.to_string_lossy()
    ));
    Ok(warnings)
}

pub fn activate_profile_sessions(profile_id: &str) -> Result<Vec<String>, String> {
    paths::ensure_app_dirs()?;
    let live = paths::claude_projects_dir()?;
    let target = paths::profile_sessions_dir(profile_id)?;
    fs::create_dir_all(&target).map_err(|e| format!("创建 profile session 目录失败: {e}"))?;
    if let Some(parent) = live.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let mut warnings = Vec::new();
    // 先全部检查/备份，最后一次性建链接。
    // 原实现只处理「live 是链接且指向别处」与「live 是普通目录」两种情况，
    // 漏掉了「live 是链接但目标已不存在」——此时 live.exists() 为 false、
    // path_is_link 为 true，旧链接不会被移除，link_path 直接失败。
    if links::path_is_link(&live) {
        if links::is_linked_to(&live, &target) {
            return Ok(warnings);
        }
        links::remove_link(&live).map_err(|e| format!("移除旧 session 链接失败: {e}"))?;
    } else if live.exists() {
        let backup_path = move_path_to_session_backup(&live, "unowned-live-projects")?;
        warnings.push(format!(
            "发现未归属的 ~/.claude/projects，已先备份：{}",
            backup_path.to_string_lossy()
        ));
    }

    links::link_path(&target, &live, "session")?;
    warnings.push(format!(
        "已启用账号 session 隔离：~/.claude/projects -> {}",
        target.to_string_lossy()
    ));
    Ok(warnings)
}

// ───────────────────────── 各本地目录（telemetry/file-history/…） ─────────────────────────

pub fn adopt_live_claude_dir_for_profile(
    profile_id: &str,
    name: &str,
) -> Result<Vec<String>, String> {
    paths::ensure_app_dirs()?;
    let live = paths::claude_local_dir(name)?;
    let target = paths::profile_claude_local_dir(profile_id, name)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    if !links::path_exists_or_link(&live) {
        fs::create_dir_all(&target).map_err(|e| format!("创建 profile {name} 目录失败: {e}"))?;
        return Ok(Vec::new());
    }

    if links::path_is_link(&live) {
        fs::create_dir_all(&target).map_err(|e| format!("创建 profile {name} 目录失败: {e}"))?;
        if links::is_linked_to(&live, &target) {
            return Ok(Vec::new());
        }
        let linked_to = fs::read_link(&live).ok();
        return Ok(vec![format!(
            "当前 ~/.claude/{name} 已指向其他隔离目录（{}），未把它接管到当前账号",
            linked_to
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "无法读取目标".to_string())
        )]);
    }

    let mut warnings = Vec::new();
    if links::path_exists_or_link(&target) {
        let backup_path =
            move_path_to_session_backup(&target, &format!("existing-profile-{name}"))?;
        warnings.push(format!(
            "已备份目标账号原 {name} 目录：{}",
            backup_path.to_string_lossy()
        ));
    }
    let renamed = fsx::retry_io(|| fs::rename(&live, &target));
    renamed.map_err(|e| {
        format!(
            "接管当前 ~/.claude/{name} 到账号隔离目录失败（{} -> {}）: {}",
            live.to_string_lossy(),
            target.to_string_lossy(),
            fsx::humanize_io_error(&e)
        )
    })?;
    warnings.push(format!(
        "已把当前 Claude {name} 接管到账号隔离目录：{}",
        target.to_string_lossy()
    ));
    Ok(warnings)
}

pub fn activate_profile_claude_dir(profile_id: &str, name: &str) -> Result<Vec<String>, String> {
    paths::ensure_app_dirs()?;
    let live = paths::claude_local_dir(name)?;
    let target = paths::profile_claude_local_dir(profile_id, name)?;
    fs::create_dir_all(&target).map_err(|e| format!("创建 profile {name} 目录失败: {e}"))?;
    if let Some(parent) = live.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let mut warnings = Vec::new();
    if links::path_is_link(&live) {
        if links::is_linked_to(&live, &target) {
            return Ok(warnings);
        }
        links::remove_link(&live).map_err(|e| format!("移除旧 {name} 链接失败: {e}"))?;
    } else if live.exists() {
        let backup_path = move_path_to_session_backup(&live, &format!("unowned-live-{name}"))?;
        warnings.push(format!(
            "发现未归属的 ~/.claude/{name}，已先备份：{}",
            backup_path.to_string_lossy()
        ));
    }

    links::link_path(&target, &live, name)?;
    warnings.push(format!(
        "已启用账号 {name} 隔离：~/.claude/{name} -> {}",
        target.to_string_lossy()
    ));
    Ok(warnings)
}

// ───────────────────────── config.json（文件，硬链接兜底） ─────────────────────────

pub fn adopt_live_claude_config_for_profile(profile_id: &str) -> Result<Vec<String>, String> {
    paths::ensure_app_dirs()?;
    let live = paths::claude_config_json_path()?;
    let target = paths::profile_claude_config_json_path(profile_id)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    if !links::path_exists_or_link(&live) {
        write_json_pretty(target, &json!({}))?;
        return Ok(Vec::new());
    }

    if links::path_is_link(&live) {
        if !target.exists() {
            write_json_pretty(target.clone(), &json!({}))?;
        }
        if links::is_linked_to(&live, &target) {
            return Ok(Vec::new());
        }
        let linked_to = fs::read_link(&live).ok();
        return Ok(vec![format!(
            "当前 ~/.claude/config.json 已指向其他隔离文件（{}），未把它接管到当前账号",
            linked_to
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "无法读取目标".to_string())
        )]);
    }

    // live 是普通文件（非链接）。先识别硬链接（Windows 无开发者模式的文件兜底）。
    if crate::platform::imp::same_file(&live, &target) {
        return Ok(Vec::new());
    }
    if crate::platform::imp::number_of_links(&live).is_some_and(|n| n > 1) {
        if !target.exists() {
            write_json_pretty(target.clone(), &json!({}))?;
        }
        return Ok(vec![
            "当前 ~/.claude/config.json 已被其他账号的硬链接占用，未把它接管到当前账号".to_string(),
        ]);
    }

    let mut warnings = Vec::new();
    if links::path_exists_or_link(&target) {
        let backup_path = move_path_to_session_backup(&target, "existing-profile-config-json")?;
        warnings.push(format!(
            "已备份目标账号原 config.json：{}",
            backup_path.to_string_lossy()
        ));
    }
    let renamed = fsx::retry_io(|| fs::rename(&live, &target));
    renamed.map_err(|e| {
        format!(
            "接管当前 ~/.claude/config.json 到账号隔离文件失败（{} -> {}）: {}",
            live.to_string_lossy(),
            target.to_string_lossy(),
            fsx::humanize_io_error(&e)
        )
    })?;
    warnings.push(format!(
        "已把当前 Claude config.json 接管到账号隔离文件：{}",
        target.to_string_lossy()
    ));
    Ok(warnings)
}

pub fn activate_profile_claude_config(profile_id: &str) -> Result<Vec<String>, String> {
    paths::ensure_app_dirs()?;
    let live = paths::claude_config_json_path()?;
    let target = paths::profile_claude_config_json_path(profile_id)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if !target.exists() {
        write_json_pretty(target.clone(), &json!({}))?;
    }
    if let Some(parent) = live.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let mut warnings = Vec::new();
    if links::path_is_link(&live) {
        if links::is_linked_to(&live, &target) {
            return Ok(warnings);
        }
        links::remove_link(&live).map_err(|e| format!("移除旧 config.json 链接失败: {e}"))?;
    } else if live.exists() {
        if crate::platform::imp::same_file(&live, &target) {
            return Ok(warnings);
        }
        if crate::platform::imp::number_of_links(&live).is_some_and(|n| n > 1) {
            links::remove_link(&live).map_err(|e| format!("移除旧 config.json 硬链接失败: {e}"))?;
        } else {
            let backup_path = move_path_to_session_backup(&live, "unowned-live-config-json")?;
            warnings.push(format!(
                "发现未归属的 ~/.claude/config.json，已先备份：{}",
                backup_path.to_string_lossy()
            ));
        }
    }

    links::link_path(&target, &live, "config.json")?;
    warnings.push(format!(
        "已启用账号 config.json 隔离：~/.claude/config.json -> {}",
        target.to_string_lossy()
    ));
    Ok(warnings)
}

// ───────────────────────── 组合入口 ─────────────────────────

pub fn adopt_live_claude_local_state_for_profile(profile_id: &str) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();
    warnings.extend(adopt_live_sessions_for_profile(profile_id)?);
    for name in [
        "telemetry",
        "file-history",
        "shell-snapshots",
        "cache",
        "debug",
        "plugins/data",
    ] {
        warnings.extend(adopt_live_claude_dir_for_profile(profile_id, name)?);
    }
    warnings.extend(adopt_live_claude_config_for_profile(profile_id)?);
    Ok(warnings)
}

pub fn activate_profile_claude_local_state(profile_id: &str) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();
    warnings.extend(activate_profile_sessions(profile_id)?);
    for name in [
        "telemetry",
        "file-history",
        "shell-snapshots",
        "cache",
        "debug",
        "plugins/data",
    ] {
        warnings.extend(activate_profile_claude_dir(profile_id, name)?);
    }
    warnings.extend(activate_profile_claude_config(profile_id)?);
    Ok(warnings)
}

pub fn session_isolation_status(
    current_profile_id: Option<&str>,
) -> Result<SessionIsolationStatus, String> {
    let live = paths::claude_projects_dir()?;
    let current_profile_path = current_profile_id
        .map(paths::profile_sessions_dir)
        .transpose()?
        .map(|path| path.to_string_lossy().to_string());
    let target_path = if links::path_is_link(&live) {
        fs::read_link(&live)
            .ok()
            .map(|path| path.to_string_lossy().to_string())
    } else {
        None
    };
    let mode = match &current_profile_path {
        Some(current) => {
            let current = std::path::PathBuf::from(current);
            if links::is_linked_to(&live, &current) {
                links::detect_link_mode(&live, &current)
            } else {
                LinkMode::NotLinked
            }
        }
        None => LinkMode::NotLinked,
    };
    let enabled = mode != LinkMode::NotLinked;
    Ok(SessionIsolationStatus {
        enabled,
        live_path: live.to_string_lossy().to_string(),
        target_path,
        current_profile_path,
        link_mode: mode.label().to_string(),
        degraded: mode.needs_developer_mode_hint(),
    })
}
