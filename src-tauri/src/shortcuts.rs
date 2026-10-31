//! 开始菜单快捷方式（F-2/K-5）：每个账号一个 `.lnk`，启动参数 `--switch-id <id>`。
//!
//! 目录固定在当前用户的开始菜单：
//! `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Claude Switcher\`。
//! 快捷方式文件名用 [`crate::naming::sanitize_file_name`] 合法化；NTFS 大小写不敏感，
//! 两个账号清洗后同名（a/b 与 a_b、仅大小写不同）时，给后写的附加账号 id 前 8 位。
//! 账号重命名/删除后通过整体重建保持一致；另提供全部清理（卸载撤销用）。
//!
//! K-5 加固：
//! - 参数改用账号 id（无空格/引号，改名后依然有效），不再用 `--switch "名称"`；
//! - 目标固定主 GUI 程序，即使从 cs.exe 触发也不指向控制台程序；
//! - 便携版移动 exe 后旧快捷方式会失效（界面另行提示）。

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::naming::sanitize_file_name;
use crate::store;

/// 开始菜单下的快捷方式子目录名。
const SHORTCUT_DIR_NAME: &str = "Claude Switcher";
const SHORTCUT_EXT: &str = "lnk";

/// 开始菜单快捷方式目录：
/// `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Claude Switcher`。
pub fn shortcut_dir() -> Result<PathBuf, String> {
    let appdata = std::env::var("APPDATA").map_err(|_| "无法读取 APPDATA 环境变量".to_string())?;
    Ok(PathBuf::from(appdata)
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join(SHORTCUT_DIR_NAME))
}

/// K-5：快捷方式目标固定指向主 GUI 程序。
///
/// 当前进程已是主程序时直接用；若从 cs.exe 触发，则在同目录找主程序
/// （安装版 `ClaudeSwitcher.exe`，开发版 `claude-switcher.exe`），找不到报错，
/// 绝不让快捷方式指向控制台程序。
fn target_exe() -> Result<PathBuf, String> {
    let current = std::env::current_exe().map_err(|e| format!("无法定位当前程序: {e}"))?;
    let stem = current
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    if stem != "cs" {
        return Ok(current);
    }
    let dir = current
        .parent()
        .ok_or_else(|| "无法定位程序目录".to_string())?;
    for candidate in ["ClaudeSwitcher.exe", "claude-switcher.exe"] {
        let path = dir.join(candidate);
        if path.is_file() {
            return Ok(path);
        }
    }
    Err("未找到主程序 ClaudeSwitcher.exe，无法创建快捷方式".to_string())
}

/// K-5：计算不冲突的 lnk 文件名（NTFS 大小写不敏感）。
///
/// 首次出现的基名直接使用；与已用名冲突（含仅大小写不同）时附加账号 id 前 8 位。
/// 纯函数 + 显式 `used` 集合，便于测试。
fn unique_lnk_name(base: &str, id: &str, used: &mut HashSet<String>) -> String {
    if used.insert(base.to_ascii_lowercase()) {
        return format!("{base}.{SHORTCUT_EXT}");
    }
    let short = if id.len() >= 8 { &id[..8] } else { id };
    let suffixed = format!("{base} ({short})");
    used.insert(suffixed.to_ascii_lowercase());
    format!("{suffixed}.{SHORTCUT_EXT}")
}

/// 在 `dir` 下为单个账号写一个快捷方式。
fn write_one(dir: &Path, id: &str, name: &str, used: &mut HashSet<String>) -> Result<(), String> {
    let target = target_exe()?;
    let mut link =
        mslnk::ShellLink::new(&target).map_err(|e| format!("创建快捷方式对象失败: {e}"))?;
    // K-5：参数用账号 id，无空格引号，改名后依然有效。
    link.set_arguments(Some(format!("--switch-id {id}")));
    link.set_name(Some(name.to_string()));
    let base = sanitize_file_name(name);
    let lnk_path = dir.join(unique_lnk_name(&base, id, used));
    link.create_lnk(&lnk_path)
        .map_err(|e| format!("写入快捷方式失败: {e}"))
}

/// 整体重建全部账号快捷方式：先清空目录（顺带清掉改名/删除残留），再逐个写。
/// 返回写出的快捷方式数量。
pub fn sync_all_shortcuts() -> Result<usize, String> {
    let dir = shortcut_dir()?;
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(|e| format!("清理旧快捷方式目录失败: {e}"))?;
    }
    fs::create_dir_all(&dir).map_err(|e| format!("创建快捷方式目录失败: {e}"))?;

    let profiles = store::read_lightweight()?.0;
    let mut used = HashSet::new();
    let mut count = 0usize;
    for profile in &profiles {
        write_one(&dir, &profile.id, &profile.name, &mut used)?;
        count += 1;
    }
    Ok(count)
}

/// 删除全部快捷方式（卸载/全部清理）。目录不存在视为成功。
pub fn remove_all_shortcuts() -> Result<(), String> {
    let dir = shortcut_dir()?;
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(|e| format!("删除快捷方式目录失败: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortcut_dir_lives_under_start_menu_programs() {
        let dir = shortcut_dir();
        if std::env::var("APPDATA").is_err() {
            return;
        }
        let dir = dir.expect("shortcut dir");
        let text = dir.to_string_lossy().replace('\\', "/");
        assert!(
            text.contains("Start Menu/Programs/Claude Switcher"),
            "got {text}"
        );
    }

    #[test]
    fn target_exe_is_resolvable() {
        assert!(target_exe().is_ok());
    }

    #[test]
    fn unique_name_appends_short_id_on_case_insensitive_collision() {
        let mut used = HashSet::new();
        // 首次出现直接用基名。
        assert_eq!(
            unique_lnk_name("acct", "1234567890abcdef", &mut used),
            "acct.lnk"
        );
        // 仅大小写不同 → 冲突，附加 id 前 8 位。
        assert_eq!(
            unique_lnk_name("ACCT", "abcdefgh12345678", &mut used),
            "ACCT (abcdefgh).lnk"
        );
    }

    #[test]
    fn unique_name_appends_short_id_when_sanitized_names_equal() {
        let mut used = HashSet::new();
        // a/b 与 a_b 经 naming 清洗后可能同名：这里直接以相同基名模拟冲突。
        assert_eq!(
            unique_lnk_name("a_b", "ididididXXXXXXXX", &mut used),
            "a_b.lnk"
        );
        // 第二个 id 前 8 位为 "abcdefgh"。
        let second = unique_lnk_name("a_b", "abcdefghZZZZZZZZ", &mut used);
        assert_eq!(second, "a_b (abcdefgh).lnk");
    }

    #[test]
    fn unique_name_handles_id_shorter_than_eight_chars() {
        let mut used = HashSet::new();
        assert_eq!(unique_lnk_name("x", "12345", &mut used), "x.lnk");
        assert_eq!(unique_lnk_name("x", "12345", &mut used), "x (12345).lnk");
    }
}
