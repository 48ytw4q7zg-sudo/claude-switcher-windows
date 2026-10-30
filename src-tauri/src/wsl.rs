//! F-6：WSL 集成（**实验功能，默认关闭**）。
//!
//! 仅在用户于界面显式开启 [crate::appconfig::AppConfig::wsl_integration_enabled]
//! 并选择一个具体发行版后，才把当前账号凭据写入该发行版的 `~/.claude/`。
//! 不开启、不选择发行版则不做任何 WSL 操作。
//!
//! 两个本机事实：
//! - `wsl -l -q` 输出为 **UTF-16LE**（带 BOM），需按 UTF-16 解码。
//! - 凭据经 stdin 管道写入（不进 argv，避免出现在进程命令行），并尝试 `chmod 600`。
//!   原生 ext4 家目录下 600 可生效；若目标在 DrvFs（`/mnt/c` 等）则权限位不可靠，
//!   界面须如实说明「0600 权限无法保证」。

use std::path::PathBuf;
use std::process::{Command, Stdio};

/// WSL 内凭据相对家目录的路径。
const WSL_CREDENTIALS_REL: &str = ".claude/.credentials.json";

/// 定位 wsl.exe（System32）。不依赖 PATH——新工具会话 PATH 可能不含 System32。
fn wsl_exe_path() -> Result<PathBuf, String> {
    let system_root =
        std::env::var("SystemRoot").map_err(|e| format!("读取 SystemRoot 失败: {e}"))?;
    Ok(PathBuf::from(system_root).join("System32").join("wsl.exe"))
}

/// 校验发行版名：非空、不含控制字符（distro 作为独立参数传入，不会被 shell 解释，
/// 这里仍做保守校验）。
fn validate_distro(distro: &str) -> Result<(), String> {
    let name = distro.trim();
    if name.is_empty() {
        return Err("未选择 WSL 发行版".to_string());
    }
    if name.chars().any(|c| c.is_control()) {
        return Err("WSL 发行版名含非法控制字符".to_string());
    }
    Ok(())
}

/// 解析 `wsl -l -q` 的 UTF-16LE 输出为发行版名列表（纯函数，便于测试）。
pub fn parse_wsl_distros(bytes: &[u8]) -> Vec<String> {
    let payload = if bytes.starts_with(&[0xFF, 0xFE]) {
        &bytes[2..]
    } else {
        bytes
    };
    let mut words: Vec<u16> = Vec::with_capacity(payload.len() / 2);
    let mut index = 0usize;
    while index + 1 < payload.len() {
        words.push(u16::from_le_bytes([payload[index], payload[index + 1]]));
        index += 2;
    }
    let text = String::from_utf16_lossy(&words);
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// 列出本机 WSL 发行版（调 `wsl -l -q`，UTF-16LE 解码）。
pub fn list_wsl_distros_blocking() -> Result<Vec<String>, String> {
    let output = Command::new(wsl_exe_path()?)
        .args(["-l", "-q"])
        .output()
        .map_err(|e| format!("执行 wsl -l -q 失败: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "wsl -l -q 失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(parse_wsl_distros(&output.stdout))
}

/// 把凭据 blob 写入指定发行版的 `~/.claude/.credentials.json`。
///
/// 前置：实验开关已开启（由调用方/下方 blocking 函数校验）、distro 非空。
/// 内容经 stdin 传入，`umask 077` + `chmod 600` 收敛权限。
pub fn write_credentials_to_wsl(distro: &str, blob: &str) -> Result<(), String> {
    validate_distro(distro)?;
    if blob.trim().is_empty() {
        return Err("凭据内容为空，未写入 WSL".to_string());
    }
    let script = format!(
        "mkdir -p ~/.claude && umask 077 && cat > {WSL_CREDENTIALS_REL} && chmod 600 {WSL_CREDENTIALS_REL}"
    );
    let mut child = Command::new(wsl_exe_path()?)
        .args(["-d", distro.trim(), "--", "bash", "-c", &script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("启动 wsl 写入进程失败: {e}"))?;
    {
        let Some(mut stdin) = child.stdin.take() else {
            return Err("无法取得 wsl 写入进程的 stdin".to_string());
        };
        use std::io::Write;
        stdin
            .write_all(blob.as_bytes())
            .map_err(|e| format!("写入凭据到 wsl stdin 失败: {e}"))?;
    } // stdin 关闭 → 远端 cat 收到 EOF。
    let output = child
        .wait_with_output()
        .map_err(|e| format!("等待 wsl 写入进程失败: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "写入 WSL 失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// 删除指定发行版里的凭据文件。
pub fn clear_wsl_credentials(distro: &str) -> Result<(), String> {
    validate_distro(distro)?;
    let script = format!("rm -f {WSL_CREDENTIALS_REL}");
    let output = Command::new(wsl_exe_path()?)
        .args(["-d", distro.trim(), "--", "bash", "-c", &script])
        .output()
        .map_err(|e| format!("启动 wsl 清理进程失败: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "清理 WSL 凭据失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// 带开关门禁的写入：实验开关未开启直接拒绝。
pub fn write_wsl_credentials_blocking(distro: String, blob: String) -> Result<(), String> {
    let config = crate::appconfig::load();
    if !config.wsl_integration_enabled {
        return Err("WSL 集成实验开关未开启，已拒绝写入".to_string());
    }
    write_credentials_to_wsl(&distro, &blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_utf16le_with_bom() {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in "Ubuntu".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0x0D, 0x00, 0x0A, 0x00]);
        for unit in "docker-desktop".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let distros = parse_wsl_distros(&bytes);
        assert_eq!(distros, vec!["Ubuntu", "docker-desktop"]);
    }

    #[test]
    fn parse_without_bom_and_blank_lines() {
        let mut bytes = Vec::new();
        for unit in "docker-desktop\r\n".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let distros = parse_wsl_distros(&bytes);
        assert_eq!(distros, vec!["docker-desktop"]);
    }

    #[test]
    fn validate_distro_rejects_blank_and_control() {
        assert!(validate_distro("   ").is_err());
        assert!(validate_distro("Ubuntu\u{0000}x").is_err());
        assert!(validate_distro("docker-desktop").is_ok());
    }
}
