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

/// 账号本地状态目录名单（`~/.claude/<name>`）。
///
/// **唯一定义处**：接管、激活、取消激活三处都从这里取，避免改一份漏另外两份
/// 造成「接管了 6 个目录、激活时只处理 5 个」的不一致。
pub const LOCAL_STATE_DIRS: &[&str] = &[
    "projects",
    "telemetry",
    "file-history",
    "shell-snapshots",
    "cache",
    "debug",
    "plugins/data",
];

/// 取消某账号的全部 live 隔离链接（删除会话历史前调用）。
///
/// 三个安全约束：
/// 1. **只删指向该账号隔离目录的链接**——用 `is_linked_to` 判断，用户自己用
///    `mklink /J` 建的其它重定向不受影响。
/// 2. **任一项取消失败即中止**：失败后仍删目录会让链接悬空（原因从"误删"变成
///    "锁文件"），不如不删、保留现场让用户处理。
/// 3. **config.json 单独处理**：它是文件（硬链接兜底），判定方式和目录不同。
///
/// 返回被移除的链接名列表（调用方记日志，排障时能看到到底动了哪几个）。
pub fn deactivate_profile(profile_id: &str) -> Result<Vec<String>, String> {
    deactivate_in(
        &crate::credentials::claude_dir()?,
        &paths::session_profiles_dir()?.join(profile_id),
    )
}

/// [`deactivate_profile`] 的可测试版本：根目录由参数传入，
/// 测试里用临时目录即可覆盖，不需要动全局环境变量或真实 `~/.claude`。
///
/// - `claude_root`：`~/.claude` 的等价目录。
/// - `profile_root`：`~/.claude-switcher/session-profiles/<id>` 的等价目录。
pub fn deactivate_in(
    claude_root: &std::path::Path,
    profile_root: &std::path::Path,
) -> Result<Vec<String>, String> {
    let mut removed = Vec::new();
    for name in LOCAL_STATE_DIRS {
        let live = claude_root.join(name);
        let target = profile_root.join(name);
        if links::is_linked_to(&live, &target) {
            links::remove_link(&live).map_err(|e| format!("移除 {name} 隔离链接失败: {e}"))?;
            removed.push((*name).to_string());
        }
    }
    // config.json：文件，硬链接兜底也由 is_linked_to 覆盖。
    let live_cfg = claude_root.join("config.json");
    let target_cfg = profile_root.join("config.json");
    if links::is_linked_to(&live_cfg, &target_cfg) {
        links::remove_link(&live_cfg).map_err(|e| format!("移除 config.json 隔离链接失败: {e}"))?;
        removed.push("config.json".to_string());
    }
    Ok(removed)
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

/// 会话目录在 `LOCAL_STATE_DIRS` 里的名字。
/// 接管/激活对它用专用函数（`adopt_live_sessions_for_profile` /
/// `activate_profile_sessions`），所以组合入口要按名字排除，
/// 而不是 `.skip(1)`——依赖「projects 排第一」将来调整顺序就静默漏处理。
pub const SESSIONS_DIR_NAME: &str = "projects";

pub fn adopt_live_claude_local_state_for_profile(profile_id: &str) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();
    warnings.extend(adopt_live_sessions_for_profile(profile_id)?);
    for name in LOCAL_STATE_DIRS
        .iter()
        .filter(|name| **name != SESSIONS_DIR_NAME)
    {
        warnings.extend(adopt_live_claude_dir_for_profile(profile_id, name)?);
    }
    warnings.extend(adopt_live_claude_config_for_profile(profile_id)?);
    Ok(warnings)
}

pub fn activate_profile_claude_local_state(profile_id: &str) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();
    warnings.extend(activate_profile_sessions(profile_id)?);
    for name in LOCAL_STATE_DIRS
        .iter()
        .filter(|name| **name != SESSIONS_DIR_NAME)
    {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    /// 建一个目录 junction 指向 target。
    /// **junction 要求 live 的父目录已存在**，否则报
    /// 「系统找不到指定的路径」(os error 3)，所以先建父目录。
    fn make_link(target: &Path, live: &Path) {
        if let Some(parent) = live.parent() {
            fs::create_dir_all(parent).expect("创建 live 父目录失败");
        }
        crate::platform::imp::create_junction(target, live).expect("创建 junction 失败");
    }

    /// 场景：claude_root 下有指向本账号的 junction、指向别处的 junction、普通目录。
    /// 只有指向本账号的应被移除；目标目录本身不能被删。
    #[test]
    fn deactivate_in_only_removes_links_to_this_profile() {
        let dir = tempfile::tempdir().unwrap();
        let claude_root = dir.path().join("claude");
        let profile_root = dir.path().join("profile");

        let my_projects = profile_root.join("projects");
        fs::create_dir_all(&my_projects).unwrap();
        make_link(&my_projects, &claude_root.join("projects"));

        // 指向别处（模拟用户自建 junction）：必须保留。
        let elsewhere = dir.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        make_link(&elsewhere, &claude_root.join("user-projects"));

        // 普通目录（非链接）：必须保留。
        fs::create_dir_all(claude_root.join("telemetry")).unwrap();

        let removed = deactivate_in(&claude_root, &profile_root).expect("deactivate 失败");
        assert_eq!(removed, vec!["projects".to_string()]);

        assert!(!links::path_is_link(&claude_root.join("projects")));
        assert!(links::path_is_link(&claude_root.join("user-projects")));
        assert!(claude_root.join("user-projects").exists());
        assert!(claude_root.join("telemetry").is_dir());
        // 只删链接，目标目录保留。
        assert!(my_projects.exists());
    }

    /// 没有任何链接时返回空列表，且不动任何东西。
    #[test]
    fn deactivate_in_noop_without_links() {
        let dir = tempfile::tempdir().unwrap();
        let claude_root = dir.path().join("claude");
        let profile_root = dir.path().join("profile");
        fs::create_dir_all(&claude_root).unwrap();
        fs::create_dir_all(&profile_root).unwrap();
        let removed = deactivate_in(&claude_root, &profile_root).unwrap();
        assert!(removed.is_empty());
    }

    /// config.json 的真实降级形态是**硬链接**（文件不能 junction），
    /// 移除后 live 名消失、目标数据保留（另一名字仍然有效）。
    #[test]
    fn deactivate_in_removes_hard_linked_config() {
        let dir = tempfile::tempdir().unwrap();
        let claude_root = dir.path().join("claude");
        let profile_root = dir.path().join("profile");
        fs::create_dir_all(&claude_root).unwrap();
        fs::create_dir_all(&profile_root).unwrap();

        let target_cfg = profile_root.join("config.json");
        fs::write(&target_cfg, "{\"k\":1}").unwrap();
        let live_cfg = claude_root.join("config.json");
        fs::hard_link(&target_cfg, &live_cfg).unwrap();

        let removed = deactivate_in(&claude_root, &profile_root).expect("deactivate 失败");
        assert_eq!(removed, vec!["config.json".to_string()]);
        assert!(!live_cfg.exists(), "live 名应被移除");
        // 硬链接只删一个名字，profile 里的数据必须还在。
        assert_eq!(fs::read_to_string(&target_cfg).unwrap(), "{\"k\":1}");
    }

    /// 悬空 junction（目标已被删除）仍应被识别并移除。
    #[test]
    fn deactivate_in_removes_dangling_junction() {
        let dir = tempfile::tempdir().unwrap();
        let claude_root = dir.path().join("claude");
        let profile_root = dir.path().join("profile");
        let my_projects = profile_root.join("projects");
        fs::create_dir_all(&my_projects).unwrap();
        make_link(&my_projects, &claude_root.join("projects"));
        // 目标消失 → live 变悬空链接。
        fs::remove_dir_all(&my_projects).unwrap();

        let removed = deactivate_in(&claude_root, &profile_root).expect("悬空链接也应可移除");
        assert_eq!(removed, vec!["projects".to_string()]);
        assert!(!links::path_is_link(&claude_root.join("projects")));
    }

    /// 某一项取消失败 → 整体返回 Err，且**后续链接不动**（保现场让用户排障）。
    /// 对 junction 本身开一个「不允许删除」的句柄，remove_dir 必然失败。
    #[test]
    fn deactivate_in_aborts_and_keeps_other_links_when_removal_fails() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        };

        let dir = tempfile::tempdir().unwrap();
        let claude_root = dir.path().join("claude");
        let profile_root = dir.path().join("profile");

        // projects = 被锁住的 junction（移除会失败）；telemetry = 正常 junction（必须保留）。
        let my_projects = profile_root.join("projects");
        let my_telemetry = profile_root.join("telemetry");
        fs::create_dir_all(&my_projects).unwrap();
        fs::create_dir_all(&my_telemetry).unwrap();
        make_link(&my_projects, &claude_root.join("projects"));
        make_link(&my_telemetry, &claude_root.join("telemetry"));

        // 不带 FILE_SHARE_DELETE 打开 reparse point 自身 → remove_dir 报共享冲突。
        // 目录句柄必须带 FILE_FLAG_BACKUP_SEMANTICS，否则 CreateFile 直接拒。
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(claude_root.join("projects"))
            .expect("打开 junction 句柄失败");

        let err = deactivate_in(&claude_root, &profile_root).unwrap_err();
        assert!(err.contains("projects"), "错误应指明失败项: {err}");
        // 失败项与后续项都必须原样保留。
        assert!(links::path_is_link(&claude_root.join("projects")));
        assert!(links::path_is_link(&claude_root.join("telemetry")));
        assert!(my_projects.exists());
        assert!(my_telemetry.exists());

        // 解锁后重跑应全部成功。
        drop(lock);
        let removed = deactivate_in(&claude_root, &profile_root).expect("解锁后应可移除");
        assert_eq!(removed.len(), 2);
    }

    /// 全部 LOCAL_STATE_DIRS + config.json 都被正确移除。
    #[test]
    fn deactivate_in_removes_all_state_dirs_and_config() {
        let dir = tempfile::tempdir().unwrap();
        let claude_root = dir.path().join("claude");
        let profile_root = dir.path().join("profile");

        for name in LOCAL_STATE_DIRS {
            let target = profile_root.join(name);
            fs::create_dir_all(&target).unwrap();
            make_link(&target, &claude_root.join(name));
        }
        let target_cfg = profile_root.join("config.json");
        fs::write(&target_cfg, "{}").unwrap();
        make_link(&target_cfg, &claude_root.join("config.json"));

        let mut removed = deactivate_in(&claude_root, &profile_root).unwrap();
        removed.sort();
        let mut expected: Vec<String> = LOCAL_STATE_DIRS.iter().map(|s| s.to_string()).collect();
        expected.push("config.json".to_string());
        expected.sort();
        assert_eq!(removed, expected);

        for name in LOCAL_STATE_DIRS {
            assert!(
                !links::path_is_link(&claude_root.join(name)),
                "{name} 应已移除"
            );
        }
        assert!(!links::path_is_link(&claude_root.join("config.json")));
    }
}
