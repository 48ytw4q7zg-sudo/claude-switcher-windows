//! 进程检测与结束：Claude Code CLI（npm / 原生安装）+ 通用辅助。
//!
//! 用 sysinfo 在两个平台统一实现，替代原 Windows 版 PowerShell Get-CimInstance
//! （慢：数百 ms 到数秒；OEM 代码页乱码）与 macOS 版 pgrep。
//!
//! 匹配规则（对齐上游 Unix 版「basename 精确等于 claude」的精确度）：
//! 1. exe 文件名等于 `claude.exe` / `claude`（不区分大小写）——覆盖原生安装与
//!    npm 包自带的 bin/claude.exe。
//! 2. 或宿主是 `node`/`bun` 且命令行含 `@anthropic-ai\claude-code`
//!    / `@anthropic-ai/claude-code`（老 npm 安装走 cli.js）。
//! 3. 排除自身（claude-switcher）与 Claude Desktop（安装目录名含 AnthropicClaude）。
//!
//! 误杀防护：不做「命令行任意位置含 claude-code」的宽松匹配——
//! `code.exe C:\work\claude-code-notes` 这类进程绝不命中。

use std::thread;
use std::time::Duration as StdDuration;

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::platform::imp;

/// 是否为 Claude Code CLI 进程（按上文规则精确匹配）。
fn is_claude_code_process(exe: Option<&str>, cmd: Option<&[String]>) -> bool {
    let Some(exe_path) = exe else {
        return false;
    };
    let exe_lower = exe_path.to_lowercase();

    // Claude Desktop 的安装路径通常含 AnthropicClaude（AppData\Local\AnthropicClaude）。
    if exe_lower.contains("anthropicclaude") {
        return false;
    }
    // 本工具自身。
    if exe_lower.contains("claude-switcher") || exe_lower.contains("claude_switcher") {
        return false;
    }

    let exe_name = exe_lower
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&exe_lower)
        .to_string();

    if exe_name == "claude.exe" || exe_name == "claude" {
        return true;
    }

    if matches!(exe_name.as_str(), "node.exe" | "node" | "bun.exe" | "bun") {
        if let Some(args) = cmd {
            return args.iter().any(|arg| {
                let lower = arg.to_lowercase();
                lower.contains("@anthropic-ai\\claude-code")
                    || lower.contains("@anthropic-ai/claude-code")
            });
        }
    }
    false
}

/// 枚举当前运行的 Claude Code CLI 进程 (pid, 描述)。
/// 描述取 exe 路径（无则退命令行首段），仅用于展示与排错。
pub fn claude_code_processes() -> Vec<(u32, String)> {
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_exe(UpdateKind::Always)
            .with_cmd(UpdateKind::Always),
    );
    let self_pid = imp::current_pid();
    let mut result = Vec::new();
    for (pid, process) in system.processes() {
        let pid_u32 = pid.as_u32();
        if pid_u32 == self_pid {
            continue;
        }
        let exe = process.exe().and_then(|path| path.to_str());
        let cmd: Vec<String> = process
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        if !is_claude_code_process(exe, Some(&cmd)) {
            continue;
        }
        let description = exe
            .map(ToOwned::to_owned)
            .or_else(|| cmd.first().cloned())
            .unwrap_or_else(|| format!("pid {pid_u32}"));
        result.push((pid_u32, description));
    }
    result.sort();
    result
}

pub fn claude_code_running() -> bool {
    !claude_code_processes().is_empty()
}

/// 结束 Claude Code 进程：先温和（Windows: taskkill /T；Unix: kill），
/// 等待后对仍存活的强制（taskkill /T /F；kill -9），最后复查。
pub fn kill_claude_code_processes() -> Result<Vec<String>, String> {
    let processes = claude_code_processes();
    if processes.is_empty() {
        return Ok(Vec::new());
    }

    let pids = processes
        .iter()
        .map(|(pid, _)| pid.to_string())
        .collect::<Vec<_>>();
    for pid in &pids {
        let _ = terminate_pid(pid, false);
    }
    thread::sleep(StdDuration::from_millis(800));

    let remaining = claude_code_processes();
    if !remaining.is_empty() {
        for (pid, _) in &remaining {
            terminate_pid(&pid.to_string(), true)?;
        }
        thread::sleep(StdDuration::from_millis(400));
    }

    let still_running = claude_code_processes();
    if !still_running.is_empty() {
        return Err(format!(
            "仍有 Claude Code 进程未退出: {}",
            still_running
                .iter()
                .map(|(pid, command)| format!("{pid} {command}"))
                .collect::<Vec<_>>()
                .join("；")
        ));
    }

    Ok(vec![format!(
        "已结束 {} 个 Claude Code 进程：{}",
        processes.len(),
        pids.join(", ")
    )])
}

/// 单个 PID 终止。force=false 温和终止（进程树），force=true 强制。
#[cfg(windows)]
fn terminate_pid(pid: &str, force: bool) -> Result<(), String> {
    let mut command = imp::silent_command("taskkill");
    command.args(["/PID", pid, "/T"]);
    if force {
        command.arg("/F");
    }
    let output = command
        .output()
        .map_err(|e| format!("结束 Claude Code 进程失败: {e}"))?;
    if force && !output.status.success() {
        // 强杀阶段进程可能恰好已退出（taskkill 128），不算失败。
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("not found") && !stderr.contains("找不到") {
            return Err(format!("强制结束 Claude Code 进程失败: {}", stderr.trim()));
        }
    }
    Ok(())
}

/// 单个 PID 终止（Unix）。
#[cfg(unix)]
fn terminate_pid(pid: &str, force: bool) -> Result<(), String> {
    let mut command = imp::silent_command("kill");
    if force {
        command.arg("-9");
    }
    let output = command
        .arg(pid)
        .output()
        .map_err(|e| format!("结束 Claude Code 进程失败: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("No such process") {
            return Err(format!("结束 Claude Code 进程失败: {}", stderr.trim()));
        }
    }
    Ok(())
}
