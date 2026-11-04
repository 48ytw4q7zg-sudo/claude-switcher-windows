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
    /// 是否暂停守护（暂停期间不阻止启动：用户显式要求「现在别管我」）。
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
    if gate.paused {
        return LaunchDecision::allow();
    }
    if gate.tripped {
        return LaunchDecision::block("当前处于熔断状态，请先解除隔离并确认出口正常");
    }
    if !gate.all_pass {
        let names = if gate.failing.is_empty() {
            "有目标未通过".to_string()
        } else {
            gate.failing.join("、")
        };
        return LaunchDecision::block(format!("出口校验未通过：{names}"));
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
    // 回退：按 exe 名尝试启动（传统安装）。
    let script = "\
$ErrorActionPreference='Stop'\n\
$p = Get-Process -Name Claude,claude -ErrorAction SilentlyContinue | Where-Object { $_.Path } | Select-Object -First 1\n\
if ($p) { Start-Process $p.Path; exit 0 }\n\
$candidates = @(\"$env:LOCALAPPDATA\\AnthropicClaude\\claude.exe\", \"$env:LOCALAPPDATA\\Programs\\Claude\\Claude.exe\")\n\
foreach ($c in $candidates) { if (Test-Path $c) { Start-Process $c; exit 0 } }\n\
exit 1";
    match crate::platform::imp::run_powershell(script) {
        Ok(_) => Ok("已按程序路径启动 Claude".to_string()),
        Err(_) => Err("找不到 Claude 的启动入口（既非 MSIX 也未在常见安装路径中找到）".to_string()),
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
    fn paused_gate_allows_launch() {
        let mut g = gate();
        g.paused = true;
        g.all_pass = false;
        assert!(decide(&g).allowed, "暂停期间用户显式要求别管，应放行");
    }

    #[test]
    fn tripped_blocks_launch() {
        let mut g = gate();
        g.tripped = true;
        let decision = decide(&g);
        assert!(!decision.allowed);
        assert!(decision.reason.unwrap().contains("熔断"));
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
