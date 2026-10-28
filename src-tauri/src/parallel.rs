//! 按终端并行多账号（P1-3）。
//!
//! 与「全局切换」（接管唯一的 `~/.claude`）不同：并行模式为每个账号开一个独立
//! 终端，终端里把 `CLAUDE_CONFIG_DIR` 指向 `~/.claude-switcher/accounts/<id>/`，
//! 该目录持有该账号的凭据与 settings，于是多个终端可同时登录不同账号。
//! 终端启动用 `wt.exe powershell -EncodedCommand`（UTF-16LE base64），
//! 未装 Windows Terminal 时退回 `cmd start powershell`（显示窗口）。

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::Serialize;

use crate::fsx;
use crate::store::{self, StoredProfile};

/// 并行账号配置根目录：`~/.claude-switcher/accounts/<id>`。
pub fn parallel_account_dir(id: &str) -> Result<PathBuf, String> {
    Ok(crate::paths::app_data_dir()?.join("accounts").join(id))
}

/// 把账号材料写进并行配置目录：凭据 + settings（账号专属），共享 skills 走复制。
fn ensure_parallel_account_dir(profile: &StoredProfile) -> Result<PathBuf, String> {
    let dir = parallel_account_dir(&profile.id)?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建并行配置目录失败: {e}"))?;

    // 凭据：该账号的 OAuth token（claude 认证主存储）。
    if let Some(cred) = profile.keychain_password.as_deref() {
        fsx::write_atomically(&dir.join(".credentials.json"), cred)
            .map_err(|e| format!("写入并行凭据失败: {e}"))?;
    }
    // settings：账号自己的 settings（含 env）。
    if let Some(settings) = profile.settings_json.as_ref() {
        fsx::write_atomically(&dir.join("settings.json"), &settings.to_string())
            .map_err(|e| format!("写入并行 settings 失败: {e}"))?;
    }

    // 共享 skills：全局配置目录的 skills 若账号目录还没有，则复制（best-effort）。
    copy_shared_skills(&dir);

    Ok(dir)
}

/// 从全局 `~/.claude/skills` 复制共享 skills 到账号目录（best-effort，不阻断）。
fn copy_shared_skills(account_dir: &Path) {
    let Ok(global_dir) = crate::credentials::claude_dir() else {
        return;
    };
    let global_skills = global_dir.join("skills");
    let target_skills = account_dir.join("skills");
    if global_skills.is_dir() && !target_skills.exists() {
        let _ = crate::desktop::copy_dir_recursive(&global_skills, &target_skills);
    }
}

/// PowerShell 单引号字符串转义（单引号翻倍）。
fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// 生成并行终端的 PowerShell 脚本：设置窗口标题 + CLAUDE_CONFIG_DIR，再启动 claude。
fn build_parallel_ps_script(config_dir: &str, title: &str) -> String {
    let dir = ps_single_quote(config_dir);
    let title = ps_single_quote(title);
    format!("$Host.UI.RawUI.WindowTitle = {title}\n$env:CLAUDE_CONFIG_DIR = {dir}\nclaude")
}

/// 编码为 PowerShell `-EncodedCommand` 接受的 UTF-16LE base64。
fn encode_utf16le_base64(script: &str) -> String {
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    BASE64.encode(&utf16)
}

/// 尝试用 Windows Terminal 启动（新窗口）。
fn launch_wt(encoded: &str) -> Result<(), String> {
    // wt -w new powershell -NoExit -EncodedCommand <b64>
    let output = Command::new("wt.exe")
        .args([
            "-w",
            "new",
            "powershell",
            "-NoExit",
            "-EncodedCommand",
            encoded,
        ])
        .output()
        .map_err(|e| format!("wt.exe 启动失败: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("wt.exe 退出码 {:?}", output.status.code()))
    }
}

/// 退回方案：cmd /c start 开一个可见的 PowerShell 窗口（勿用 silent_command）。
fn launch_via_cmd_start(encoded: &str) -> Result<(), String> {
    let output = Command::new("cmd")
        .args([
            "/C",
            "start",
            "Claude",
            "powershell",
            "-NoExit",
            "-EncodedCommand",
            encoded,
        ])
        .output()
        .map_err(|e| format!("cmd start 启动失败: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("cmd start 退出码 {:?}", output.status.code()))
    }
}

/// 一次并行终端启动的结果。
#[derive(Debug, Serialize)]
pub struct ParallelTerminalResult {
    pub profile_id: String,
    pub config_dir: String,
    /// 实际使用的启动器：`wt` 或 `cmd-start`。
    pub launcher: String,
}

/// 为指定账号开一个并行终端（阻塞，调用方须走 blocking）。
pub fn open_parallel_terminal_for_profile(id: &str) -> Result<ParallelTerminalResult, String> {
    let store_data = store::load_store()?;
    let profile = store_data
        .profiles
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| format!("账号 {id} 不存在"))?;

    let dir = ensure_parallel_account_dir(profile)?;
    let script = build_parallel_ps_script(&dir.to_string_lossy(), &profile.name);
    let encoded = encode_utf16le_base64(&script);

    let launcher = if launch_wt(&encoded).is_ok() {
        "wt"
    } else {
        launch_via_cmd_start(&encoded)?;
        "cmd-start"
    };

    Ok(ParallelTerminalResult {
        profile_id: id.to_string(),
        config_dir: dir.to_string_lossy().to_string(),
        launcher: launcher.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_quote_escapes_apostrophes() {
        assert_eq!(ps_single_quote("abc"), "'abc'");
        assert_eq!(ps_single_quote("a'b"), "'a''b'");
        assert_eq!(ps_single_quote("C:\\path"), "'C:\\path'");
    }

    #[test]
    fn script_sets_config_dir_and_runs_claude() {
        let script = build_parallel_ps_script("C:\\accounts\\id1", "美国号");
        assert!(script.contains("$env:CLAUDE_CONFIG_DIR = 'C:\\accounts\\id1'"));
        assert!(script.contains("WindowTitle = '美国号'"));
        assert!(script.trim_end().ends_with("claude"));
    }

    #[test]
    fn encoded_command_is_utf16le_base64_and_roundtrips() {
        let script = "$env:CLAUDE_CONFIG_DIR = 'x'\nclaude";
        let encoded = encode_utf16le_base64(script);
        let bytes = BASE64.decode(&encoded).expect("valid base64");
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let decoded = String::from_utf16_lossy(&units);
        assert_eq!(decoded, script);
    }

    #[test]
    fn account_dir_under_app_data() {
        let dir = parallel_account_dir("abc").expect("dir");
        assert!(dir
            .to_string_lossy()
            .replace('\\', "/")
            .ends_with(".claude-switcher/accounts/abc"));
    }
}
