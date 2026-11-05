//! 出口门禁的启动门禁（融合 ClaudeGuard `monitor.rs::launch`）。
//!
//! 语义：**出口未通过就不让应用启动**。这与「启动后再杀」有本质区别——后者
//! 允许应用在检查间隙里用真实 IP 连上一次。因此启动路径必须同步检查、当场决定。
//!
//! 与 [`crate::egate_monitor`] 的关系：常驻循环负责「运行中持续看守」，本模块
//! 负责「启动这一刻的一次性判定」。两者共用同一套判定与阈值语义，但启动检查
//! **不看防抖**——用户点「启动」时如果出口不对，应当立刻拒绝而不是等两轮。

use serde::Serialize;

use crate::egate::Verdict;

/// 启动决定的输入。
#[derive(Debug, Clone)]
pub struct LaunchGate {
    /// 本轮判定是否全部通过（所有启用目标 Pass）。
    pub all_pass: bool,
    /// 未通过的目标名（用于阻止理由）。
    pub failing: Vec<String>,
    /// 是否处于熔断态。
    pub tripped: bool,
    /// **低成本项 4**：熔断状态无法确认（防火墙查询失败）。
    ///
    /// 与 `tripped` 分开：`tripped=false + unknown=true` 不等于「确认未隔离」。
    /// 启动门禁遇到 unknown 必须阻止并说明「无法确认」，不能放行。
    pub trip_state_unknown: bool,
    /// 是否暂停守护。
    ///
    /// **P0-10**：暂停只停止自动副作用，**不参与**「是否允许启动」的判定；
    /// 保留该字段供界面展示当前处于暂停状态。
    pub paused: bool,
    /// 门禁总开关。
    pub enabled: bool,
}

/// 启动决定。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LaunchDecision {
    /// 是否允许启动。
    pub allowed: bool,
    /// 阻止理由（允许时为 None）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl LaunchDecision {
    fn allow() -> Self {
        Self {
            allowed: true,
            reason: None,
        }
    }

    fn block(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: Some(reason.into()),
        }
    }
}

/// 决定是否允许启动（纯函数）。
///
/// 优先级：未启用 → 允许；暂停 → 允许（用户显式让路）；已熔断 → 拒绝；
/// 未全通过 → 拒绝并列出失败目标；全通过 → 允许。
pub fn decide(gate: &LaunchGate) -> LaunchDecision {
    if !gate.enabled {
        return LaunchDecision::allow();
    }
    // **P0-10**：暂停只停止「新的自动副作用」（自动隔离/查杀），
    // **不等于安全检查通过**。已熔断/未通过仍必须阻止启动。
    if gate.tripped {
        return LaunchDecision::block("当前处于熔断状态，请先解除隔离并确认出口正常");
    }
    // **低成本项 4**：无法确认隔离状态时不能放行。这不是「已熔断」，
    // 而是「不知道有没有熔断」——两者都必须阻止，理由要能区分。
    if gate.trip_state_unknown {
        return LaunchDecision::block(
            "无法确认当前是否处于隔离状态（防火墙查询失败），请打开保护面板核对后再启动",
        );
    }
    if !gate.all_pass {
        let names = if gate.failing.is_empty() {
            "有目标未通过".to_string()
        } else {
            gate.failing.join("、")
        };
        let suffix = if gate.paused {
            "（守护已暂停，但启动仍需出口通过）"
        } else {
            ""
        };
        return LaunchDecision::block(format!("出口校验未通过：{names}{suffix}"));
    }
    LaunchDecision::allow()
}

/// 从一轮检查结果构造门控输入。
pub fn gate_from_round(
    report: &crate::egate_check::EgateReport,
    enabled: bool,
    paused: bool,
    tripped: bool,
) -> LaunchGate {
    let failing: Vec<String> = report
        .targets
        .iter()
        .filter(|target| target.verdict == Verdict::Fail)
        .map(|target| target.name.clone())
        .collect();
    LaunchGate {
        all_pass: report.overall.verdict == Verdict::Pass,
        failing,
        tripped,
        // 从全局状态读取：调用方传入的 `tripped` 只反映「是否已熔断」，
        // 而「能否确认」是另一个维度。
        trip_state_unknown: crate::egate_monitor::is_trip_state_unknown(),
        paused,
        enabled,
    }
}

/// 解析 Claude 的 AUMID（`shell:AppsFolder\<PackageFamilyName>!<AppId>`）。
///
/// 返回 `None` 表示不是 MSIX 安装或查询失败；调用方应回退到按 exe 启动。
pub fn claude_aumid() -> Option<String> {
    let script = "\
$ErrorActionPreference='SilentlyContinue'\n\
$pkg = Get-AppxPackage | Where-Object { $_.Name -like '*Claude*' -or $_.PackageFamilyName -like '*Claude*' } | Select-Object -First 1\n\
if (-not $pkg) { return }\n\
$manifest = Get-AppxPackageManifest -Package $pkg.PackageFullName\n\
$appId = [string](@($manifest.Package.Applications.Application)[0].Id)\n\
if ($appId) { \"$($pkg.PackageFamilyName)!$appId\" }";
    let text = crate::platform::imp::run_powershell(script).ok()?;
    let aumid = text.trim();
    if aumid.is_empty() {
        None
    } else {
        Some(aumid.to_string())
    }
}

/// 启动 Claude：优先 MSIX AUMID（经 explorer），否则按 exe 名启动。
pub fn launch_claude() -> Result<String, String> {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let explorer = std::path::PathBuf::from(&system_root).join("explorer.exe");
    if let Some(aumid) = claude_aumid() {
        let target = format!("shell:AppsFolder\\{aumid}");
        let status = crate::platform::imp::silent_command(&explorer.to_string_lossy())
            .arg(&target)
            .status()
            .map_err(|e| format!("无法向 Windows 发送 Claude 启动请求：{e}"))?;
        if !status.success() {
            return Err("Windows 拒绝了 Claude 启动请求".to_string());
        }
        return Ok(format!("已通过 MSIX 身份请求启动 Claude（{aumid}）"));
    }
    // L-11 (v0.7.2): pick ONLY a confirmed desktop GUI executable.
    //
    // The old code took the first process named Claude/claude, which can be a
    // Claude Code CLI running from an npm/node directory - launching that
    // would start the wrong product.
    //
    // The marker lists mirror `platform::windows::is_managed_gui_path` exactly;
    // a drift between the two makes "which process may be killed" and
    // "which process may be launched" disagree about what the desktop app is.
    //
    // Note: this is a RAW Rust string, so backslashes are literal. Writing
    // '\\node_modules\\' here would compare against double backslashes and
    // never match - PowerShell single-quoted strings have no escape sequences.
    //
    // P0-NEW-01: no statement-level `exit` in the script; it would bypass the
    // sentinel run_ps() uses to decide success.
    let script = r#"$ErrorActionPreference = 'Stop'
function Is-ManagedGui([string]$path) {
  if (-not $path) { return $false }
  $p = $path.ToLowerInvariant()
  foreach ($m in @(
      '\node_modules\',
      '\npm\',
      '\nvm\',
      '\fnm\',
      '\volta\',
      '\.bun\',
      '\.deno\'
  )) {
    if ($p.Contains($m)) { return $false }
  }
  foreach ($m in @(
      '\anthropicclaude',
      '\programs\claude',
      '\program files\claude',
      '\windowsapps',
      '\programs\chatgpt',
      '\program files\chatgpt',
      '\antigravity'
  )) {
    if ($p.Contains($m)) { return $true }
  }
  return $false
}
$launched = $null
foreach ($proc in @(Get-Process -Name Claude,claude -ErrorAction SilentlyContinue)) {
  if ($proc.Path -and (Is-ManagedGui $proc.Path)) {
    Start-Process $proc.Path
    $launched = $proc.Path
    break
  }
}
if (-not $launched) {
  $candidates = @(
    (Join-Path $env:LOCALAPPDATA 'AnthropicClaude\claude.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\Claude\Claude.exe'),
    (Join-Path $env:ProgramFiles 'Claude\Claude.exe')
  )
  foreach ($c in $candidates) {
    if ((Test-Path $c) -and (Is-ManagedGui $c)) {
      Start-Process $c
      $launched = $c
      break
    }
  }
}
if ($launched) { "launched=$launched" } else { "launched=" }"#;
    match crate::platform::imp::run_powershell(script) {
        Ok(out) if out.trim() != "launched=" => Ok(format!(
            "已按程序路径启动 Claude（{}）",
            out.trim().trim_start_matches("launched=")
        )),
        Ok(_) => Err(
            "找不到已确认的 Claude Desktop 图形界面程序。为避免误启动 Claude Code CLI，             本次未执行启动；请手动打开 Claude Desktop 后重试"
                .to_string(),
        ),
        Err(e) => Err(format!("启动 Claude 失败：{e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate() -> LaunchGate {
        LaunchGate {
            all_pass: true,
            failing: Vec::new(),
            tripped: false,
            trip_state_unknown: false,
            paused: false,
            enabled: true,
        }
    }

    #[test]
    fn disabled_gate_allows_launch() {
        let mut g = gate();
        g.enabled = false;
        g.all_pass = false;
        assert!(decide(&g).allowed, "门禁关闭时不阻止启动");
    }

    #[test]
    fn paused_still_blocks_unsafe_launch() {
        // P0-10：暂停 ≠ 安全检查通过。
        let mut g = gate();
        g.paused = true;
        g.all_pass = false;
        g.failing = vec!["Claude 出口".to_string()];
        assert!(!decide(&g).allowed, "暂停期间出口未通过仍必须阻止启动");

        // 暂停 + 已熔断：同样阻止。
        let mut tripped = gate();
        tripped.paused = true;
        tripped.tripped = true;
        assert!(!decide(&tripped).allowed, "暂停不能解除已熔断状态");

        // 暂停 + 全部通过：允许（安全检查确实通过）。
        let mut ok = gate();
        ok.paused = true;
        assert!(decide(&ok).allowed, "暂停但出口全通过时应允许");
    }

    #[test]
    fn tripped_blocks_launch() {
        let mut g = gate();
        g.tripped = true;
        let decision = decide(&g);
        assert!(!decision.allowed);
        assert!(decision.reason.unwrap().contains("熔断"));
    }

    /// **低成本项 4**：熔断状态无法确认时必须阻止启动，且理由要与
    /// 「已熔断」区分开——用户需要知道该去核对什么。
    #[test]
    fn unknown_trip_state_blocks_launch() {
        let mut g = gate();
        g.trip_state_unknown = true;
        let decision = decide(&g);
        assert!(!decision.allowed, "无法确认隔离状态时不得放行");
        let reason = decision.reason.unwrap();
        assert!(reason.contains("无法确认"), "{reason}");
        assert!(
            !reason.contains("处于熔断状态"),
            "理由应区分「未知」与「已熔断」：{reason}"
        );
    }

    #[test]
    fn failing_targets_block_with_names() {
        let mut g = gate();
        g.all_pass = false;
        g.failing = vec!["Claude 出口".to_string(), "Codex 出口".to_string()];
        let decision = decide(&g);
        assert!(!decision.allowed);
        let reason = decision.reason.unwrap();
        assert!(reason.contains("Claude 出口"), "{reason}");
        assert!(reason.contains("Codex 出口"), "{reason}");
    }

    #[test]
    fn all_pass_allows() {
        let decision = decide(&gate());
        assert!(decision.allowed);
        assert!(decision.reason.is_none());
    }

    #[test]
    fn unverified_does_not_count_as_pass() {
        // Unverified（拿不到出口信息）不是 Pass：启动门禁要求「全部通过」。
        let mut g = gate();
        g.all_pass = false;
        g.failing = Vec::new();
        let decision = decide(&g);
        assert!(!decision.allowed);
        assert!(decision.reason.unwrap().contains("未通过"));
    }
}
