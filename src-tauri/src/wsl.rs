//! F-6：WSL 集成（**实验功能，默认关闭**）。
//!
//! 仅在用户于界面显式开启 [crate::appconfig::AppConfig::wsl_integration_enabled]
//! 并选择一个具体发行版后，才把当前账号凭据写入该发行版的 `~/.claude/`。
//! 不开启、不选择发行版则不做任何 WSL 操作。
//!
//! 本机事实与 K-4 加固：
//! - `wsl -l -q` 输出为 **UTF-16LE**（带 BOM），需按 UTF-16 解码；
//! - 所有 wsl 进程都经 [crate::platform::silent_command] 加 `CREATE_NO_WINDOW`，
//!   发布版 GUI 不闪控制台；
//! - 每个命令带 [`WSL_TIMEOUT_SECS`] 超时，超时即 kill，WSL 服务卡住也不会无限等待；
//! - 内部发行版（docker-desktop / rancher-desktop 等）从选择列表过滤；
//! - 写入前先回读 WSL 凭据，按过期时间比较，更新的副本回写账号库；
//! - 先 `echo $HOME` / `whoami` 探测写入用户与家目录（防落到 root 的 /root）；
//! - 同步 `~/.claude.json`（登录身份/引导标记）；
//! - 凭据经 stdin 管道写入（不进 argv），`umask 077` + `chmod 600`。DrvFs
//!   （`/mnt/c`）权限位不可靠，界面如实说明「0600 无法保证」。

use std::fs;
use std::path::PathBuf;
use std::process::{Child, Output, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;

/// WSL 内凭据相对家目录的路径。
const WSL_CREDENTIALS_REL: &str = ".claude/.credentials.json";
/// WSL 内全局配置（家目录相对）。
const WSL_CLAUDE_JSON: &str = ".claude.json";
/// K-4：单个 WSL 命令的超时（秒），超时即终止。
const WSL_TIMEOUT_SECS: u64 = 15;
/// K-4：不是可用 Linux 环境的内部发行版（不区分大小写匹配）。
const INTERNAL_DISTROS: &[&str] = &[
    "docker-desktop",
    "docker-desktop-data",
    "rancher-desktop",
    "rancher-desktop-data",
];

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

/// K-4：等待子进程，超过 `timeout` 即 kill，返回其输出。
///
/// 用 `try_wait` 轮询而不是阻塞 `wait`，保证 WSL 服务卡住时也能在超时后终止。
fn wait_with_timeout(mut child: Child, timeout: Duration) -> Result<Output, String> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|e| format!("收集进程输出失败: {e}"));
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "WSL 命令超过 {} 秒未完成，已终止",
                        timeout.as_secs()
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("等待 WSL 进程失败: {e}")),
        }
    }
}

/// K-4：统一执行 `wsl -d <distro> -- bash -c <script>`，可选经 stdin 传数据。
///
/// 走 silent_command（不闪窗）+ 超时。`stdin_data` 为 Some 时管道写入并在写完后
/// 关闭（远端 cat 收到 EOF）；为 None 时 stdin 置 null。
fn run_wsl_bash(distro: &str, script: &str, stdin_data: Option<&str>) -> Result<Output, String> {
    let wsl = wsl_exe_path()?;
    let mut cmd = crate::platform::imp::silent_command(&wsl.to_string_lossy());
    cmd.args(["-d", distro, "--", "bash", "-c", script]);
    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("启动 wsl 进程失败: {e}"))?;
    if let Some(data) = stdin_data {
        let Some(mut stdin) = child.stdin.take() else {
            return Err("无法取得 wsl 进程的 stdin".to_string());
        };
        use std::io::Write;
        stdin
            .write_all(data.as_bytes())
            .map_err(|e| format!("写入 wsl stdin 失败: {e}"))?;
        // stdin 在此 drop → 关闭管道，远端收到 EOF。
    }
    wait_with_timeout(child, Duration::from_secs(WSL_TIMEOUT_SECS))
}

/// K-4：列出本机可用 WSL 发行版（过滤内部发行版，不闪窗、带超时）。
pub fn list_wsl_distros_blocking() -> Result<Vec<String>, String> {
    let wsl = wsl_exe_path()?;
    let mut cmd = crate::platform::imp::silent_command(&wsl.to_string_lossy());
    cmd.args(["-l", "-q"]);
    let child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("执行 wsl -l -q 失败: {e}"))?;
    let output = wait_with_timeout(child, Duration::from_secs(WSL_TIMEOUT_SECS))?;
    if !output.status.success() {
        return Err(format!(
            "wsl -l -q 失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut distros = parse_wsl_distros(&output.stdout);
    distros.retain(|d| !INTERNAL_DISTROS.contains(&d.to_ascii_lowercase().as_str()));
    Ok(distros)
}

/// K-4：写入目标的用户与家目录（防默认 root 落到 /root）。
#[derive(Debug, Clone)]
struct WslHome {
    user: String,
    home: String,
}

/// K-4：探测发行版的家目录与登录用户。
fn probe_wsl_home(distro: &str) -> Result<WslHome, String> {
    let script = "printf '%s\\n' \"$HOME\"; whoami";
    let output = run_wsl_bash(distro, script, None)?;
    if !output.status.success() {
        return Err(format!(
            "探测 WSL 家目录失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let lossy = String::from_utf8_lossy(&output.stdout);
    let mut lines = lossy.lines().map(str::trim).filter(|line| !line.is_empty());
    let home = lines
        .next()
        .ok_or_else(|| "无法解析 WSL 家目录".to_string())?
        .to_string();
    let user = lines.next().unwrap_or("").to_string();
    Ok(WslHome { user, home })
}

/// K-4：回读发行版里已有的凭据（文件缺失返回 None）。
fn read_wsl_credentials(distro: &str) -> Result<Option<String>, String> {
    let script = format!("if [ -f {WSL_CREDENTIALS_REL} ]; then cat {WSL_CREDENTIALS_REL}; fi");
    let output = run_wsl_bash(distro, &script, None)?;
    if !output.status.success() {
        return Err(format!(
            "回读 WSL 凭据失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        Ok(None)
    } else {
        Ok(Some(text))
    }
}

/// 取 blob 的访问令牌过期时间（毫秒），解析不到为 None。
fn blob_expiry_ms(blob: &str) -> Option<u64> {
    crate::token_status::evaluate_token_status(blob, 0).expires_at_ms
}

/// K-4：比较两份凭据，WSL 副本过期时间更晚（或本机无法解析而 WSL 可解析）时返回 true。
fn remote_blob_is_newer(local: &str, remote: &str) -> bool {
    match (blob_expiry_ms(local), blob_expiry_ms(remote)) {
        (Some(local_exp), Some(remote_exp)) => remote_exp > local_exp,
        (None, Some(_)) => true,
        _ => false,
    }
}

/// 把凭据 blob 写入指定发行版（stdin + umask + chmod，不闪窗、带超时）。
pub fn write_credentials_to_wsl(distro: &str, blob: &str) -> Result<(), String> {
    validate_distro(distro)?;
    if blob.trim().is_empty() {
        return Err("凭据内容为空，未写入 WSL".to_string());
    }
    let script = format!(
        "mkdir -p ~/.claude && umask 077 && cat > {WSL_CREDENTIALS_REL} && chmod 600 {WSL_CREDENTIALS_REL}"
    );
    let output = run_wsl_bash(distro.trim(), &script, Some(blob))?;
    if !output.status.success() {
        return Err(format!(
            "写入 WSL 失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// K-4：把本机 `~/.claude.json` 同步到发行版（stdin 写入，收敛权限）。
fn sync_claude_json_to_wsl(distro: &str) -> Result<(), String> {
    let local = crate::paths::claude_json_path()?;
    let content =
        fs::read_to_string(&local).map_err(|e| format!("读取本机 .claude.json 失败: {e}"))?;
    let script = format!("umask 077 && cat > {WSL_CLAUDE_JSON} && chmod 600 {WSL_CLAUDE_JSON}");
    let output = run_wsl_bash(distro, &script, Some(&content))?;
    if !output.status.success() {
        return Err(format!(
            "同步 .claude.json 失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// K-4：WSL 同步结果报告（回传给前端展示）。
#[derive(Debug, Clone, Serialize)]
pub struct WslSyncReport {
    pub distro: String,
    /// 写入目标登录用户。
    pub user: String,
    /// 写入目标家目录。
    pub home: String,
    /// WSL 内是否已有凭据。
    pub had_existing: bool,
    /// WSL 副本更新时的原 blob（供 lib 层回写账号库），否则 None。
    pub remote_newer_blob: Option<String>,
    /// 需向用户展示的提示（两处各一份、0600 限制等）。
    pub warnings: Vec<String>,
}

/// K-4：带开关门禁的完整同步流程。
///
/// 顺序：探测家目录 → 回读现有凭据并按过期时间对账 → 写入本机凭据 →
/// 同步 ~/.claude.json → 返回报告。实验开关未开启直接拒绝。
pub fn sync_to_wsl_blocking(distro: String, local_blob: String) -> Result<WslSyncReport, String> {
    let config = crate::appconfig::load();
    if !config.wsl_integration_enabled {
        return Err("WSL 集成实验开关未开启，已拒绝写入".to_string());
    }
    validate_distro(&distro)?;
    let name = distro.trim().to_string();
    if local_blob.trim().is_empty() {
        return Err("凭据内容为空，未写入 WSL".to_string());
    }

    // 1. 探测写入用户/家目录。
    let wsl_home = probe_wsl_home(&name)?;
    let mut warnings = Vec::new();

    // 2. 回读并对账。
    let existing = read_wsl_credentials(&name)?;
    let mut remote_newer_blob = None;
    if let Some(remote) = &existing {
        warnings.push(format!(
            "该账号在 WSL（{}）与本机各有一份凭据，两边各自刷新可能互相失效",
            wsl_home.home
        ));
        if remote_blob_is_newer(&local_blob, remote) {
            remote_newer_blob = Some(remote.clone());
            warnings.push("WSL 内凭据过期时间更晚，已将其回写账号库".to_string());
        }
    }

    // 3. 写入本机凭据。
    write_credentials_to_wsl(&name, &local_blob)?;

    // 4. 同步 ~/.claude.json（失败只告警，不阻断凭据写入）。
    if let Err(e) = sync_claude_json_to_wsl(&name) {
        warnings.push(format!("同步 ~/.claude.json 失败（不影响凭据）: {e}"));
    }

    Ok(WslSyncReport {
        distro: name,
        user: wsl_home.user,
        home: wsl_home.home,
        had_existing: existing.is_some(),
        remote_newer_blob,
        warnings,
    })
}

/// 删除指定发行版里的凭据与 .claude.json（不闪窗、带超时）。
pub fn clear_wsl_credentials(distro: &str) -> Result<(), String> {
    validate_distro(distro)?;
    let script = format!("rm -f {WSL_CREDENTIALS_REL} {WSL_CLAUDE_JSON}");
    let output = run_wsl_bash(distro.trim(), &script, None)?;
    if !output.status.success() {
        return Err(format!(
            "清理 WSL 凭据失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
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

    #[test]
    fn internal_distro_constants_cover_expected_names() {
        for name in [
            "docker-desktop",
            "docker-desktop-data",
            "rancher-desktop",
            "rancher-desktop-data",
        ] {
            assert!(INTERNAL_DISTROS.contains(&name));
        }
    }

    // ── K-4 凭据对账纯函数 ──

    fn blob_with_expiry(expiry: i64) -> String {
        format!("{{\"claudeAiOauth\":{{\"expiresAt\":{expiry}}}}}")
    }

    #[test]
    fn remote_is_newer_when_its_expiry_is_later() {
        let local = blob_with_expiry(1000);
        let remote = blob_with_expiry(2000);
        assert!(remote_blob_is_newer(&local, &remote));
        assert!(!remote_blob_is_newer(&remote, &local));
    }

    #[test]
    fn remote_is_newer_when_local_expiry_unknown() {
        let local = "{\"claudeAiOauth\":{\"accessToken\":\"a\"}}";
        let remote = blob_with_expiry(2000);
        assert!(remote_blob_is_newer(local, &remote));
    }

    #[test]
    fn remote_not_newer_when_neither_expiry_known() {
        assert!(!remote_blob_is_newer("{\"a\":1}", "{\"b\":2}"));
    }

    #[test]
    fn blob_expiry_reads_nested_and_flat_shapes() {
        assert_eq!(blob_expiry_ms(&blob_with_expiry(1234)), Some(1234));
        assert_eq!(blob_expiry_ms("{\"expiresAt\":5678}"), Some(5678));
        assert_eq!(blob_expiry_ms("not json"), None);
    }
}
