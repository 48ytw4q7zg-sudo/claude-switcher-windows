//! 开始菜单快捷方式（F-2）：每个账号一个 `.lnk`，启动参数 `--switch "<名称>"`。
//!
//! 目录固定在当前用户的开始菜单：
//! `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Claude Switcher\`。
//! 快捷方式文件名用 [`crate::naming::sanitize_file_name`] 合法化，账号重命名 /
//! 删除后通过整体重建保持一致；另提供全部清理（卸载撤销用）。

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

/// 快捷方式目标：当前程序（GUI 触发时即主 exe，必然存在、可 canonicalize）。
fn target_exe() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("无法定位当前程序: {e}"))
}

/// 在 `dir` 下为单个账号写一个快捷方式。
fn write_one(dir: &Path, account_name: &str) -> Result<(), String> {
    let target = target_exe()?;
    let mut link =
        mslnk::ShellLink::new(&target).map_err(|e| format!("创建快捷方式对象失败: {e}"))?;
    // 名称里可能含空格，用引号包住；--switch 按 trim 后精确匹配。
    link.set_arguments(Some(format!("--switch \"{account_name}\"")));
    link.set_name(Some(account_name.to_string()));
    let lnk_path = dir.join(format!(
        "{}.{SHORTCUT_EXT}",
        sanitize_file_name(account_name)
    ));
    link.create_lnk(&lnk_path)
        .map_err(|e| format!("写入快捷方式失败: {e}"))
}

/// 整体重建全部账号快捷方式：先清空目录（顺带清掉改名 / 删除残留），再逐个写。
/// 返回写出的快捷方式数量。
pub fn sync_all_shortcuts() -> Result<usize, String> {
    let dir = shortcut_dir()?;
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(|e| format!("清理旧快捷方式目录失败: {e}"))?;
    }
    fs::create_dir_all(&dir).map_err(|e| format!("创建快捷方式目录失败: {e}"))?;

    let profiles = store::read_lightweight()?.0;
    let mut count = 0usize;
    for profile in &profiles {
        write_one(&dir, &profile.name)?;
        count += 1;
    }
    Ok(count)
}

/// 删除全部快捷方式（卸载 / 全部清理）。目录不存在视为成功。
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
}
