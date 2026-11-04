//! 出口门禁的熔断执行（融合 ClaudeGuard `guard.rs` 的隔离语义）。
//!
//! 行为基准：ClaudeGuard `src/guard.rs`（固定 commit `1967377`）。要点：
//! - **按 exe 加防火墙阻断规则**：Windows 防火墙没有域名维度，只能按程序隔离；
//!   回环流量不受防火墙过滤，所以「系统代理仍可用、直连出不去」正好成立；
//! - **补完必须回查**：`netsh` 返回成功不等于规则真的生效（防火墙服务关闭、
//!   组策略覆盖）；不回查就宣称「已隔离」是本模块明确要避免的错误；
//! - **CLI 只提醒不杀**：Claude Code 跑在 node/终端宿主里，按 exe 查杀会误伤
//!   整个终端，防火墙也无粒度可拦；
//! - **解除隔离**按规则名整体删除，不依赖记录的状态（崩溃后也能清干净）。
//!
//! 本文件只做「执行 + 核验」；判定与阈值在 [`crate::egate`] / [`crate::egate_check`]。

use serde::Serialize;

/// 隔离规则的名称前缀（本产品独占，便于整体清理）。
const RULE_PREFIX: &str = "ClaudeSwitcher AppIsolation";

/// 单个被守护应用的隔离结果。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct QuarantineReport {
    pub agent: String,
    /// 实际写入的规则数。
    pub rules_added: u32,
    /// 回查确认生效的规则数。
    pub rules_verified: u32,
    /// **期望覆盖的规则总数**（exe × 出入站方向）。
    /// 必须以此为核验对象，不能用「本次添加了几条」作为成功标准。
    pub rules_expected: u32,
    /// 规则查询是否成功（失败时不得宣称成功）。
    pub query_ok: bool,
    /// **覆盖是否完整**（期望集合全部满足）。
    pub coverage_complete: bool,
    /// 失败的规则描述。
    pub failed_rules: Vec<String>,
    /// 命中并结束的进程描述。
    pub killed: Vec<String>,
    /// 回查是否成功；`false` 时不得宣称隔离已生效。
    pub verified: bool,
    /// 给人看的说明（含失败原因）。
    pub note: String,
}

/// 一次熔断的完整结果。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TripReport {
    pub agents: Vec<QuarantineReport>,
    /// 是否有任何应用被真正隔离（回查通过）。
    pub any_isolated: bool,
    /// **是否全部应用都已完整隔离**（每个应用 coverage_complete）。
    pub all_isolated: bool,
    /// 所有失败的说明（空表示全部成功）。
    pub failures: Vec<String>,
    pub note: String,
}

/// 内置守护应用与其进程特征。
///
/// `exe_names` 用于按进程名结束；CLI 宿主（node/bun）不在此列——按 exe 杀会
/// 误伤终端，与上游「CLI 只提醒」一致。
fn agent_spec(id: &str) -> Option<(&'static str, &'static [&'static str])> {
    match id {
        // Claude Desktop：安装版 exe 名既有 Claude 也有 claude。
        "claude" => Some(("Claude", &["Claude", "claude"])),
        "chatgpt" => Some(("ChatGPT", &["ChatGPT", "chatgpt"])),
        "antigravity" => Some(("Antigravity", &["Antigravity", "antigravity"])),
        _ => None,
    }
}

/// 解析应用 id 是否可被本模块守护（未知 id 忽略，不报错）。
pub fn is_guarded_agent(id: &str) -> bool {
    agent_spec(id).is_some()
}

/// 规则名：`ClaudeSwitcher Egate <agent> <Out|In>`。
pub fn rule_name(agent: &str, direction: &str) -> String {
    format!("{RULE_PREFIX} {agent} {direction}")
}

/// 结束一个应用的全部进程（按进程名）。返回被结束的进程描述。
pub fn kill_agent_processes(agent: &str) -> Result<Vec<String>, String> {
    let Some((_, exe_names)) = agent_spec(agent) else {
        return Ok(Vec::new());
    };
    crate::platform::imp::kill_processes_by_names(exe_names)
}

/// 枚举当前运行的被守护应用进程（pid → 应用 id）。
///
/// 供直连泄露观察使用：只有 GUI 应用本体参与，CLI 宿主（node/bun）不在此列。
pub fn agent_pids(agents: &[String]) -> std::collections::BTreeMap<u32, String> {
    let mut out = std::collections::BTreeMap::new();
    for agent in agents {
        let Some((_, exe_names)) = agent_spec(agent) else {
            continue;
        };
        let names = exe_names
            .iter()
            .map(|n| ps_quote(n))
            .collect::<Vec<_>>()
            .join(",");
        let script = format!(
            "$ErrorActionPreference='SilentlyContinue'\n\
             @(Get-Process -Name {names} | Select-Object -ExpandProperty Id) | ConvertTo-Json -Compress"
        );
        let Ok(json) = crate::platform::imp::run_powershell(&script) else {
            continue;
        };
        let value: serde_json::Value = match serde_json::from_str(json.trim()) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let pids: Vec<u32> = match value {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|v| v.as_u64().map(|n| n as u32))
                .collect(),
            serde_json::Value::Number(n) => n.as_u64().map(|n| vec![n as u32]).unwrap_or_default(),
            _ => Vec::new(),
        };
        for pid in pids {
            out.insert(pid, agent.clone());
        }
    }
    out
}

/// 查询某个 exe 路径对应的防火墙规则是否已存在且生效。
///
/// 返回 `(查询成功, 生效规则数)`。查询失败时调用方**不得**宣称隔离成功。
/// 防火墙规则核验结果。
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleVerification {
    query_ok: bool,
    expected: u32,
    verified: u32,
    failed: Vec<String>,
}

/// 查询某个 exe 路径对应的防火墙规则是否已存在且生效。
///
/// 核验语义：期望集合是「该 exe × 出站/入站」，每条规则都必须满足：
/// 存在、启用、动作=Block、方向正确、程序路径匹配。只有全部期望满足才算完整。
fn count_rules_for(agent: &str, exe: &str) -> RuleVerification {
    let out_name = rule_name(agent, "Out");
    let in_name = rule_name(agent, "In");
    let script = format!(
        "$ErrorActionPreference='Stop'
         $outName = {}
         $inName = {}
         $exe = {}
         $outOk = $false; $inOk = $false
         try {{
           $r = Get-NetFirewallRule -DisplayName $outName -ErrorAction Stop
           $f = $r | Get-NetFirewallApplicationFilter
           if ($r.Enabled -eq 'True' -and $r.Action -eq 'Block' -and $r.Direction -eq 'Outbound' -and $f.Program -and $f.Program -ieq $exe) {{ $outOk = $true }}
         }} catch {{}}
         try {{
           $r = Get-NetFirewallRule -DisplayName $inName -ErrorAction Stop
           $f = $r | Get-NetFirewallApplicationFilter
           if ($r.Enabled -eq 'True' -and $r.Action -eq 'Block' -and $r.Direction -eq 'Inbound' -and $f.Program -and $f.Program -ieq $exe) {{ $inOk = $true }}
         }} catch {{}}
         ConvertTo-Json @{{ out = $outOk; in = $inOk }} -Compress",
        ps_quote(&out_name),
        ps_quote(&in_name),
        ps_quote(exe)
    );
    match crate::platform::imp::run_powershell(&script) {
        Ok(json) => {
            let value: serde_json::Value = match serde_json::from_str(json.trim()) {
                Ok(value) => value,
                Err(_) => {
                    return RuleVerification {
                        query_ok: false,
                        expected: 2,
                        verified: 0,
                        failed: vec!["规则查询结果无法解析".to_string()],
                    }
                }
            };
            let out_ok = value.get("out").and_then(|v| v.as_bool()).unwrap_or(false);
            let in_ok = value.get("in").and_then(|v| v.as_bool()).unwrap_or(false);
            let mut failed = Vec::new();
            if !out_ok {
                failed.push("出站规则未生效".to_string());
            }
            if !in_ok {
                failed.push("入站规则未生效".to_string());
            }
            RuleVerification {
                query_ok: true,
                expected: 2,
                verified: out_ok as u32 + in_ok as u32,
                failed,
            }
        }
        Err(_) => RuleVerification {
            query_ok: false,
            expected: 2,
            verified: 0,
            failed: vec!["规则查询失败".to_string()],
        },
    }
}

/// PowerShell 单引号转义（把 `'` 写成 `''`）。
fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// 查询一个应用的实际可执行路径（用于按 exe 建规则）。
fn resolve_agent_exe(agent: &str) -> Option<String> {
    let (_, exe_names) = agent_spec(agent)?;
    let names = exe_names
        .iter()
        .map(|n| ps_quote(n))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'\n\
         $p = Get-Process -Name {names} | Where-Object {{ $_.Path }} | Select-Object -First 1\n\
         if ($p) {{ $p.Path }}"
    );
    let path = crate::platform::imp::run_powershell(&script).ok()?;
    let path = path.trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

/// 为单个应用加隔离：结束进程 → 按 exe 加出/入站阻断 → 回查核验。
///
/// `exe_path` 为 `None` 时尝试从运行中的进程解析；解析不到则只结束进程并如实
/// 说明「未加防火墙规则」，不谎称已隔离。
pub fn quarantine_agent(agent: &str, exe_path: Option<&str>) -> QuarantineReport {
    let mut report = QuarantineReport {
        agent: agent.to_string(),
        rules_added: 0,
        rules_verified: 0,
        rules_expected: 0,
        query_ok: false,
        coverage_complete: false,
        failed_rules: Vec::new(),
        killed: Vec::new(),
        verified: false,
        note: String::new(),
    };
    if !is_guarded_agent(agent) {
        report.note = format!("未知守护对象「{agent}」，已跳过");
        return report;
    }

    // 1. **先查 exe**：在进程还活着时获取安装路径（进程结束后无法从 Get-Process 取）。
    let exe = exe_path
        .map(str::to_string)
        .or_else(|| resolve_agent_exe(agent));
    let Some(exe) = exe else {
        report
            .note
            .push_str("未找到可执行文件，无法添加防火墙规则（应用可能未安装或已退出）");
        return report;
    };

    // 2. 再结束进程（失败不阻断后续隔离：进程可能已退出）。
    match kill_agent_processes(agent) {
        Ok(killed) => report.killed = killed,
        Err(error) => report.note.push_str(&format!("结束进程失败（{error}）；")),
    }

    // 3. 加出/入站阻断规则（已存在则不重复加）。
    for (direction, label) in [("out", "Out"), ("in", "In")] {
        let name = rule_name(agent, label);
        let script = format!(
            "$ErrorActionPreference='Stop'\n\
             $existing = Get-NetFirewallRule -DisplayName {} -ErrorAction SilentlyContinue\n\
             if (-not $existing) {{\n\
               New-NetFirewallRule -DisplayName {} -Direction {} -Action Block -Program {} -Enabled True | Out-Null\n\
             }}",
            ps_quote(&name),
            ps_quote(&name),
            if direction == "out" { "Outbound" } else { "Inbound" },
            ps_quote(&exe)
        );
        match crate::platform::imp::run_powershell(&script) {
            Ok(_) => report.rules_added += 1,
            Err(error) => report
                .note
                .push_str(&format!("添加{label}站规则失败（{error}）；")),
        }
    }

    // 4. 回查：netsh/New-NetFirewallRule 返回成功不等于规则生效。
    let verification = count_rules_for(agent, &exe);
    report.query_ok = verification.query_ok;
    report.rules_expected = verification.expected;
    report.rules_verified = verification.verified;
    report.coverage_complete =
        verification.query_ok && verification.verified >= verification.expected;
    report.verified = report.coverage_complete;
    report.failed_rules = verification.failed;

    if !verification.query_ok {
        report.note.push_str("规则回查失败，无法确认隔离是否生效；");
    } else if !report.coverage_complete {
        report.note.push_str(&format!(
            "规则覆盖不完整（{}条生效，期望{}条）；",
            verification.verified, verification.expected
        ));
        for fail in &report.failed_rules {
            report.note.push_str(&format!("{fail}；"));
        }
    }
    if report.coverage_complete {
        report
            .note
            .push_str(&format!("已隔离 {exe}（出/入站阻断规则完整生效）"));
    }
    report
}
/// 执行一次熔断：对配置里所有守护对象结束进程并隔离。
///
/// 与上游一致：**只处理 GUI 应用**；CLI 宿主不在守护列表里，避免误伤终端。
pub fn trip(guarded_agents: &[String]) -> TripReport {
    let mut agents = Vec::new();
    let mut failures = Vec::new();
    for id in guarded_agents {
        let report = quarantine_agent(id, None);
        if !report.verified {
            failures.push(format!("{}：{}", report.agent, report.note.trim()));
        }
        agents.push(report);
    }
    let any_isolated = agents.iter().any(|agent| agent.verified);
    let all_isolated = agents.iter().all(|agent| agent.coverage_complete);
    TripReport {
        note: if failures.is_empty() && all_isolated {
            "全部守护对象已结束进程并施加防火墙隔离".to_string()
        } else if any_isolated {
            "部分守护对象已隔离，其余见失败说明".to_string()
        } else {
            "未能确认任何隔离生效".to_string()
        },
        agents,
        any_isolated,
        all_isolated,
        failures,
    }
}

/// 解除应用隔离规则（只删除本应用的隔离规则，不影响全局断网）。
///
/// 使用 `AppIsolation` 前缀，与 `Cut All` 断网规则严格区分。
/// 按名字删而不是按记录的状态删：崩溃后重启也能清干净。
pub fn release_all() -> Result<u32, String> {
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'\n\
         $rules = @(Get-NetFirewallRule -DisplayName {}* )\n\
         $n = $rules.Count\n\
         $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue\n\
         ConvertTo-Json @{{ removed = $n }} -Compress",
        ps_quote(RULE_PREFIX)
    );
    let json = crate::platform::imp::run_powershell(&script)?;
    let value: serde_json::Value =
        serde_json::from_str(json.trim()).map_err(|e| format!("清理结果解析失败：{e}"))?;
    Ok(value.get("removed").and_then(|v| v.as_u64()).unwrap_or(0) as u32)
}

/// 当前存在的本产品隔离规则数（恢复后核验用）。
pub fn rule_count() -> Option<u32> {
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'\n\
         @(Get-NetFirewallRule -DisplayName {}*).Count | ConvertTo-Json -Compress",
        ps_quote(RULE_PREFIX)
    );
    let json = crate::platform::imp::run_powershell(&script).ok()?;
    json.trim().parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_names_are_scoped_per_agent_and_direction() {
        assert_eq!(
            rule_name("claude", "Out"),
            "ClaudeSwitcher AppIsolation claude Out"
        );
        assert_ne!(rule_name("claude", "Out"), rule_name("chatgpt", "Out"));
        assert_ne!(rule_name("claude", "Out"), rule_name("claude", "In"));
    }

    #[test]
    fn only_known_gui_agents_are_guarded() {
        for id in ["claude", "chatgpt", "antigravity"] {
            assert!(is_guarded_agent(id), "{id} 应可守护");
        }
        // CLI 宿主与未知 id 都不进入隔离队列（误伤终端 / 无对象）。
        for id in ["claude-code", "codex", "gemini", "node", "unknown", ""] {
            assert!(!is_guarded_agent(id), "{id} 不应被按 exe 隔离");
        }
    }

    #[test]
    fn ps_quote_escapes_single_quotes() {
        // 单引号必须双写，否则 PowerShell 会把路径截断成注入点。
        assert_eq!(ps_quote(r"C:\a'b\c.exe"), r"'C:\a''b\c.exe'");
    }

    #[test]
    fn unknown_agent_quarantine_is_a_noop_with_explanation() {
        let report = quarantine_agent("unknown-agent", None);
        assert!(report.killed.is_empty());
        assert_eq!(report.rules_added, 0);
        assert!(!report.verified);
        assert!(report.note.contains("未知守护对象"), "{report:?}");
    }

    #[test]
    fn trip_with_no_agents_reports_not_isolated() {
        let report = trip(&[]);
        assert!(!report.any_isolated);
        assert!(report.agents.is_empty());
        assert_eq!(report.failures.len(), 0, "没有守护对象不算失败");
    }
}
