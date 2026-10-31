//! 目录绑定 + `cs run`（F-1）。
//!
//! 在项目目录放置标记文件 `.claude-switcher-account`（内容为账号名），从当前目录
//! 逐级向上查找即可确定该目录绑定的账号。`cs run` 复用并行账号目录
//! （[`crate::parallel::ensure_parallel_account_dir`]），设置 `CLAUDE_CONFIG_DIR`
//! 后在**同一控制台**启动 claude 并透传其退出码。K-2 起按 PATH/PATHEXT 解析
//! claude 真实路径直接启动（不再 `cmd /c`），并吞掉本进程的 Ctrl+C/Break。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli;
use crate::store;

/// 目录绑定标记文件名。
pub const MARKER_FILE_NAME: &str = ".claude-switcher-account";

/// 从 `start` 起逐级向上查找标记文件，返回第一个命中的完整路径；全部上级都没有 → None。
pub fn find_account_marker(start: &Path) -> Result<Option<PathBuf>, String> {
    let mut current: Option<&Path> = Some(start);
    while let Some(dir) = current {
        let candidate = dir.join(MARKER_FILE_NAME);
        if candidate.is_file() {
            return Ok(Some(candidate));
        }
        current = dir.parent();
    }
    Ok(None)
}

/// 读取标记文件里的账号名（trim 后），空内容报错。
pub fn read_marker_account_name(marker: &Path) -> Result<String, String> {
    let raw = std::fs::read_to_string(marker).map_err(|e| format!("读取账号标记文件失败: {e}"))?;
    let name = raw.trim();
    if name.is_empty() {
        return Err(format!(
            "账号标记文件 {MARKER_FILE_NAME} 内容为空，请写入要绑定的账号名"
        ));
    }
    Ok(name.to_string())
}

/// 写一个目录绑定标记（供界面/命令创建绑定用）：原子写入账号名。
pub fn write_account_marker(dir: &Path, account_name: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("创建绑定目录失败: {e}"))?;
    let marker = dir.join(MARKER_FILE_NAME);
    crate::fsx::write_atomically(&marker, account_name.trim())
        .map_err(|e| format!("写入账号标记文件失败: {e}"))?;
    Ok(marker)
}

/// 删除目录绑定标记（不存在视为成功）。
pub fn remove_account_marker(dir: &Path) -> Result<(), String> {
    let marker = dir.join(MARKER_FILE_NAME);
    if marker.exists() {
        std::fs::remove_file(&marker).map_err(|e| format!("删除账号标记文件失败: {e}"))?;
    }
    Ok(())
}

/// `cs run`：在当前目录绑定的账号下启动 claude，返回 claude 的真实退出码。
///
/// `extra_args` 是 `cs run` 之后透传给 claude 的命令行参数。
pub fn run_bound_account(start_dir: &Path, extra_args: &[String]) -> Result<i32, String> {
    let marker = find_account_marker(start_dir)?.ok_or_else(|| {
        format!(
            "当前目录及其上级目录都没有 {MARKER_FILE_NAME} 标记文件，无法确定要使用的账号；\
             可在界面为该目录绑定账号，或手动创建该文件并写入账号名"
        )
    })?;
    let account_name = read_marker_account_name(&marker)?;
    let profile_id = cli::resolve_profile_id(&account_name)?;

    let store_data = store::load_store()?;
    let profile = store_data
        .profiles
        .iter()
        .find(|p| p.id == profile_id)
        .ok_or_else(|| format!("账号库中找不到标记所指的账号「{account_name}」"))?;

    // 复用并行账号目录保障（凭据/settings 缺失才播种，已存在不覆盖）。
    let config_dir = crate::parallel::ensure_parallel_account_dir(profile)?;

    // K-2：启动时打印使用的账号与标记文件，避免克隆仓库自带标记时悄悄选中账号。
    println!("使用账号 {}（标记文件 {}）", account_name, marker.display());
    let _ = std::io::stdout().flush();

    // 先装处理器再 spawn，确保 cs 不会先于 claude 被 Ctrl+C/Break 终止。
    if !crate::platform::imp::install_console_ctrl_swallow() {
        eprintln!("警告：无法安装控制台 Ctrl 处理器，Ctrl+C 可能先终止本程序");
    }

    // K-2：不再 cmd /c，直接按 PATH/PATHEXT 解析 claude 真实路径后启动，
    // 避免参数里的 & | ^ % 经 cmd 二次解析被截断/展开（Rust 1.88 对 .cmd/.bat
    // 目标会做安全转义）。
    let claude = crate::mcp::resolve_executable_on_path("claude")
        .ok_or_else(|| "未找到 claude 命令，请先安装 Claude Code 并确认其在 PATH 上".to_string())?;
    let mut command = Command::new(&claude);
    command.args(extra_args);
    command.env("CLAUDE_CONFIG_DIR", &config_dir);
    let status = command
        .status()
        .map_err(|e| format!("启动 claude 失败: {e}"))?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_marker_walks_up_and_returns_nearest() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let nested = root.join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        // 上级放标记。
        write_account_marker(&root.join("a"), "work").unwrap();
        let found = find_account_marker(&nested).unwrap().expect("marker found");
        assert_eq!(found, root.join("a").join(MARKER_FILE_NAME));
    }

    #[test]
    fn find_marker_returns_none_when_absent_everywhere() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(find_account_marker(tmp.path()).unwrap().is_none());
    }

    #[test]
    fn read_marker_trims_name_and_rejects_blank() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_account_marker(tmp.path(), "  美国号  ").unwrap();
        assert_eq!(read_marker_account_name(&path).unwrap(), "美国号");

        let blank = tmp.path().join("blank");
        std::fs::create_dir_all(&blank).unwrap();
        let blank_marker = blank.join(MARKER_FILE_NAME);
        crate::fsx::write_atomically(&blank_marker, "   ").unwrap();
        assert!(read_marker_account_name(&blank_marker).is_err());
    }

    #[test]
    fn remove_marker_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        write_account_marker(tmp.path(), "x").unwrap();
        assert!(remove_account_marker(tmp.path()).is_ok());
        assert!(remove_account_marker(tmp.path()).is_ok());
    }
}
