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

/// 是否为 Claude Code CLI 进程（精确匹配，宁漏勿误杀）。
///
/// **黑名单（优先级最高）**——命中任意一条直接排除：
/// - Claude Desktop：路径含 `anthropicclaude`；或 MSIX 安装（`WindowsApps` 目录）；
///   或 Electron 子进程（命令行带 `--type=`，如 `--type=renderer`）。
///   Desktop 是 Electron 应用，主程序与子进程都可能叫 `claude.exe`，
///   误杀会连带干掉用户的桌面客户端。
/// - 本工具自身（`claude-switcher` / `claude_switcher`）。
/// - VS Code 等编辑器打开 `claude-code-notes` 目录、终端里敲 `claude-code` 字样：
///   这些都不是「exe 名等于 claude」，本来就不会命中白名单。
///
/// **白名单**——满足其一才算 Claude Code CLI：
/// 1. exe 文件名等于 `claude.exe` / `claude`（原生安装，以及 npm 包的 `bin/claude.exe`）；
/// 2. 宿主是 `node` / `bun` 且命令行含 `@anthropic-ai/claude-code`（老版 npm 安装走 cli.js）。
fn is_claude_code_process(exe: Option<&str>, cmd: Option<&[String]>) -> bool {
    let Some(exe_path) = exe else {
        return false;
    };
    let exe_lower = exe_path.to_lowercase();

    // ── 黑名单 ──
    // Claude Desktop：标准安装目录。
    if exe_lower.contains("anthropicclaude") {
        return false;
    }
    // （MSIX/WindowsApps 的排除移到 claude.exe 分支内：Store 版 Node 也在该目录，
    // 全局排除会漏检用它跑的 npm 版 Claude Code。）
    // 本工具自身。
    if exe_lower.contains("claude-switcher") || exe_lower.contains("claude_switcher") {
        return false;
    }
    // Electron 子进程：Desktop 的 renderer/gpu/utility 进程都带 `--type=`。
    if let Some(args) = cmd {
        if args.iter().any(|arg| arg.starts_with("--type=")) {
            return false;
        }
    }

    // ── 白名单 ──
    let exe_name = exe_lower
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&exe_lower)
        .to_string();

    if exe_name == "claude.exe" || exe_name == "claude" {
        // MSIX 排除**仅对 claude.exe 生效**：Microsoft Store 版 Node 也装在
        // WindowsApps 下，用它跑 npm 版 Claude Code（node.exe + cli.js）必须
        // 仍能命中——否则切号前的「结束 Claude Code」对这些用户静默失效。
        // 而 Desktop 的可执行文件就叫 claude.exe 且在 MSIX 安装目录里，
        // 用路径+文件名双重特征才能既排除 Desktop 又不伤 Store 版 Node。
        let in_windowsapps = exe_lower.contains("\\windowsapps\\");
        if in_windowsapps {
            // WindowsApps 下的 claude.exe：Store 版 Claude Code CLI 并不存在
            // （官方 CLI 不上架 Store），这里只会是 Desktop（Anthropic.Claude 包）。
            return false;
        }
        return true;
    }

    // node / bun 宿主：不受 WindowsApps 排除影响（见上）。
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
        // **用退出码判断，不要匹配 stderr 文案**：taskkill 在中文系统上输出的是
        // GBK 编码的「没有找到进程」，`from_utf8_lossy` 会乱码，字符串匹配基本失效。
        // 约定：128 = ERROR_WAIT_NO_CHILDREN / 进程不存在，属幂等成功。
        //      其它非零 = 真的失败（权限不足等）。
        const TASKKILL_PROCESS_NOT_FOUND: i32 = 128;
        let code = output.status.code().unwrap_or(-1);
        if code != TASKKILL_PROCESS_NOT_FOUND {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "强制结束 Claude Code 进程失败（退出码 {code}）: {}",
                stderr.trim()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 进程匹配表格测试：覆盖 npm / 原生安装、Claude Desktop（标准安装 / MSIX /
    /// Electron 子进程）、以及「编辑器打开 claude-code 目录」这类误杀场景。
    #[test]
    fn claude_code_process_matching_table() {
        // (exe 路径, 命令行, 是否应判定为 Claude Code, 场景说明)
        let cases: Vec<(&str, Option<Vec<String>>, bool, &str)> = vec![
            // ── 应命中（Claude Code CLI）──
            (
                r"C:\Users\A\AppData\Local\claude\claude.exe",
                None,
                true,
                "原生安装 claude.exe",
            ),
            (
                r"C:\Users\A\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe",
                None,
                true,
                "npm 包的 bin/claude.exe",
            ),
            (
                "node.exe",
                Some(vec![
                    r"C:\npm\node_modules\@anthropic-ai\claude-code\cli.js".into(),
                ]),
                true,
                "node 跑 cli.js（老 npm 安装）",
            ),
            (
                "node.exe",
                Some(vec!["@anthropic-ai/claude-code/dist/cli.js".into()]),
                true,
                "node + 正斜杠路径",
            ),
            (
                "bun.exe",
                Some(vec![r"@anthropic-ai\claude-code\bin\cli.js".into()]),
                true,
                "bun 跑 cli.js",
            ),
            // ── 必须排除（Claude Desktop；误杀会干掉用户的桌面客户端）──
            (
                r"C:\Users\A\AppData\Local\AnthropicClaude\app.exe",
                None,
                false,
                "Desktop 标准安装（目录名含 AnthropicClaude）",
            ),
            (
                r"C:\Users\A\AppData\Local\AnthropicClaude\claude.exe",
                None,
                false,
                "Desktop 主程序也叫 claude.exe",
            ),
            (
                r"C:\Program Files\WindowsApps\Anthropic.Claude_1.2.3\claude.exe",
                None,
                false,
                "Desktop MSIX 安装（WindowsApps + claude.exe 双特征）",
            ),
            (
                r"C:\Program Files\WindowsApps\Node.JS.20.11\java.exe",
                Some(vec![r"C:\WindowsApps\Node.JS.20.11\node.exe".into()]),
                false,
                "无关 Store 程序",
            ),
            // **Store 版 Node 跑 npm 版 Claude Code 必须命中**：
            // WindowsApps 排除只针对 claude.exe，不能漏检 node + cli.js。
            (
                r"C:\Program Files\WindowsApps\Node.JS.20.11\node.exe",
                Some(vec![
                    r"C:\Users\A\node_modules\@anthropic-ai\claude-code\cli.js".into(),
                ]),
                true,
                "Store 版 Node 跑 npm 版 Claude Code（WindowsApps 不排除 node）",
            ),
            (
                r"C:\Program Files\WindowsApps\Anthropic.Claude_1.2.3\claude.exe",
                Some(vec!["--type=renderer".into()]),
                false,
                "Electron 渲染子进程（--type=renderer）",
            ),
            (
                r"C:\somewhere\claude.exe",
                Some(vec!["--type=gpu-process".into()]),
                false,
                "Electron GPU 子进程",
            ),
            // ── 必须排除（本工具自身与无关进程）──
            (
                r"C:\Users\A\AppData\Local\Programs\Claude-Switcher.exe",
                None,
                false,
                "本工具自身",
            ),
            (
                r"C:\Users\A\AppData\Roaming\Code\Code.exe",
                Some(vec![r"code.exe C:\work\claude-code-notes".into()]),
                false,
                "VS Code 打开 claude-code 目录",
            ),
            (
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                Some(vec!["claude-code".into()]),
                false,
                "PowerShell 命令行含关键词",
            ),
            (r"C:\Windows\explorer.exe", None, false, "完全无关进程"),
            (
                "node.exe",
                Some(vec![r"C:\app\server.js".into()]),
                false,
                "node 跑别的脚本（不含 @anthropic-ai/claude-code）",
            ),
        ];

        let mut failures = Vec::new();
        for (exe, cmd, expect, desc) in cases {
            let got = is_claude_code_process(Some(exe), cmd.as_deref());
            if got != expect {
                failures.push(format!("  FAIL: {desc} (expect={expect}, got={got})"));
            }
        }
        assert!(
            failures.is_empty(),
            "进程匹配表格测试失败 {} 例:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
