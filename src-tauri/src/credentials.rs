//! 凭据存取（平台差异收拢层）。
//!
//! - macOS：`security` 命令操作 Keychain（service=`Claude Code-credentials`）。
//! - Windows：官方凭据文件 `<claude_dir>\.credentials.json`，内容与 Keychain blob 相同。
//!   `claude_dir` = `CLAUDE_CONFIG_DIR`（若设置）否则 `%USERPROFILE%\.claude`；
//!   注意 `CLAUDE_CONFIG_DIR` 已经指向配置目录本身，凭据就在它下面，不再多一层 `.claude`。
//!
//! 统一暴露 read / write / clear / remove_legacy 四个动作，上层逻辑不写 cfg。
//! 文案统一用 [`CREDENTIAL_STORE_LABEL`]，不再让 Windows 用户看到 Keychain 字样。

use std::fs;
use std::path::PathBuf;

use crate::platform::imp;

/// 凭据存储的显示名称（用户可见文案、报错信息用）。
#[cfg(windows)]
pub const CREDENTIAL_STORE_LABEL: &str = "凭据文件";
#[cfg(not(windows))]
pub const CREDENTIAL_STORE_LABEL: &str = "Keychain";

/// Keychain service 名（仅 macOS 使用）。
#[cfg(not(windows))]
pub const KEYCHAIN_SERVICE: &str = "Claude Code-credentials";
/// store 加密主密钥的存储项名。
pub const STORE_KEY_KEYCHAIN_SERVICE: &str = "claude-switcher-store-key";
/// 早期 claude-switcher 误把 account 写成了 "Claude Code"（仅 macOS 有此残留）。
#[cfg(not(windows))]
pub const LEGACY_KEYCHAIN_ACCOUNT: &str = "Claude Code";

pub fn current_username() -> Result<String, String> {
    imp::current_username()
}

/// 读取当前 OAuth 凭据（明文 JSON blob）。不存在返回 Ok(None)。
pub fn read_password() -> Result<Option<String>, String> {
    #[cfg(windows)]
    {
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
    #[cfg(not(windows))]
    {
        read_keychain_password_macos()
    }
}

/// 写入 OAuth 凭据。Windows 上原子写入凭据文件；macOS 写 Keychain。
///
/// 配置目录被用户改到用户 profile 之外（例如 `D:\claude-alt`）时，凭据文件继承的
/// 是盘符根 ACL（同机其他本地账户可能读到）。此时额外收敛为「当前用户 + SYSTEM」。
/// 默认位置在 profile 内、本来就私有，不做多余 icacls。
pub fn write_password(password: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
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
    #[cfg(not(windows))]
    {
        write_keychain_password_macos(password)
    }
}

/// 清空凭据（best-effort；不存在也成功）。
pub fn clear_password() -> Result<(), String> {
    #[cfg(windows)]
    {
        let path = credentials_path()?;
        if crate::links::path_exists_or_link(&path) {
            let _ = crate::fsx::remove_file_with_retry(&path);
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        clear_keychain_password_macos()
    }
}

/// 清理早期版本的遗留凭据条目。Windows 上 `.credentials.json` 是主存储，
/// 「清理遗留」是空操作，绝不能删。
pub fn clear_legacy_password() -> Result<(), String> {
    #[cfg(windows)]
    {
        Ok(())
    }
    #[cfg(not(windows))]
    {
        clear_legacy_keychain_password_macos()
    }
}

/// macOS：删除遗留的 ~/.claude/.credentials.json（macOS 凭据应在 Keychain）。
/// Windows 上它是主存储，空操作（见 [`clear_legacy_password`]）。
pub fn remove_legacy_credentials_file() -> Result<(), String> {
    #[cfg(windows)]
    {
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let path = legacy_credentials_path()?;
        if path.exists() {
            fs::remove_file(&path)
                .map_err(|e| format!("删除 ~/.claude/.credentials.json 失败: {e}"))?;
        }
        Ok(())
    }
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
#[cfg(windows)]
pub fn credentials_path() -> Result<PathBuf, String> {
    Ok(claude_dir()?.join(".credentials.json"))
}

/// 遗留凭据文件路径（macOS 清理用）。
#[cfg(not(windows))]
pub fn legacy_credentials_path() -> Result<PathBuf, String> {
    Ok(claude_dir()?.join(".credentials.json"))
}
// ───────────────────────── macOS Keychain 实现 ─────────────────────────

#[cfg(not(windows))]
fn read_keychain_password_macos() -> Result<Option<String>, String> {
    use std::process::Command;

    let username = current_username()?;
    let output = Command::new("security")
        .arg("find-generic-password")
        .arg("-a")
        .arg(&username)
        .arg("-s")
        .arg(KEYCHAIN_SERVICE)
        .arg("-w")
        .output()
        .map_err(|e| format!("读取 Keychain 失败: {e}"))?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout)
            .trim_end()
            .to_string();
        return Ok(Some(text));
    }

    // 早期 claude-switcher 写条目时没带 account 属性，兜底按 service 再找一次。
    let fallback = Command::new("security")
        .args(["find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"])
        .output()
        .map_err(|e| format!("读取 Keychain 失败: {e}"))?;
    if fallback.status.success() {
        let text = String::from_utf8_lossy(&fallback.stdout)
            .trim_end()
            .to_string();
        return Ok(Some(text));
    }
    Ok(None)
}

#[cfg(not(windows))]
fn write_keychain_password_macos(password: &str) -> Result<(), String> {
    keychain_write(&current_username()?, KEYCHAIN_SERVICE, password)
}

#[cfg(not(windows))]
fn clear_keychain_password_macos() -> Result<(), String> {
    use std::process::Command;

    let username = current_username()?;
    loop {
        let output = Command::new("security")
            .args(["delete-generic-password", "-a"])
            .arg(&username)
            .args(["-s", KEYCHAIN_SERVICE])
            .output()
            .map_err(|e| format!("清理 Keychain 失败: {e}"))?;
        if !output.status.success() {
            break;
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn clear_legacy_keychain_password_macos() -> Result<(), String> {
    use std::process::Command;

    loop {
        let output = Command::new("security")
            .args(["delete-generic-password", "-a", LEGACY_KEYCHAIN_ACCOUNT])
            .args(["-s", KEYCHAIN_SERVICE])
            .output()
            .map_err(|e| format!("清理旧 Keychain 失败: {e}"))?;
        if !output.status.success() {
            break;
        }
    }
    Ok(())
}

/// 把 value（UTF-8 文本）写入 keychain 项（account/service）。
/// payload 走 `security -i` 的 stdin，不出现在 argv（ps 可见）；
/// 超过 fgets 行缓冲（~4096B）时回退 argv，避免静默截断。
#[cfg(not(windows))]
fn keychain_write(account: &str, service: &str, value: &str) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let hex: String = value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let command = format!("add-generic-password -U -a \"{account}\" -s \"{service}\" -X {hex}\n");
    const STDIN_LINE_LIMIT: usize = 4096 - 64;

    if command.len() <= STDIN_LINE_LIMIT {
        let mut child = Command::new("security")
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("写入 Keychain 失败: {e}"))?;
        child
            .stdin
            .take()
            .ok_or_else(|| "写入 Keychain 失败：无法获取 security stdin".to_string())?
            .write_all(command.as_bytes())
            .map_err(|e| format!("写入 Keychain 失败: {e}"))?;
        let out = child
            .wait_with_output()
            .map_err(|e| format!("写入 Keychain 失败: {e}"))?;
        if out.status.success() {
            return Ok(());
        }
        return Err(format!(
            "写入 Keychain 失败: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let out = Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-a",
            account,
            "-s",
            service,
            "-X",
            &hex,
        ])
        .output()
        .map_err(|e| format!("写入 Keychain 失败: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "写入 Keychain 失败: {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}
