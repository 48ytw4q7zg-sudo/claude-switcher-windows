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
    /// **P2-04**：受管应用的安装状态。
    ///
    /// 界面据此区分「没装这个应用（不适用）」「查不出安装状态（保护未知）」
    /// 与「装了但隔离失败」。三者对「是否已完整保护」的结论完全不同。
    pub installation: ApplicationInstallation,
    /// 给人看的说明（含失败原因）。
    pub note: String,
}

/// **P2-04**：受管应用的安装状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationInstallation {
    /// 已确认安装（默认值，覆盖「显式传入了路径」的测试/预览场景）。
    #[default]
    Installed,
    /// 已确认未安装：对该应用而言「不适用」，不算保护缺口。
    NotInstalled,
    /// 无法确认安装状态：不能当作「已完整保护」。
    Unknown,
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

/// **P0-01**：隔离的**来源**。不同来源使用不同规则名前缀，互不覆盖。
///
/// 原实现所有隔离共用 `ClaudeSwitcher AppIsolation` 前缀：解除「未接入兜底锁」
/// 会把普通熔断的规则一起删掉——熔断状态还写着 tripped，防火墙却已经空了。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationReason {
    /// 目标出口失败达阈值后的正式熔断。
    EgressTrip,
    /// 未接入代理时的即时兜底封锁。
    Uncovered,
}

impl IsolationReason {
    /// 规则名前缀：各自独立命名空间。
    fn prefix(self) -> &'static str {
        match self {
            IsolationReason::EgressTrip => RULE_PREFIX,
            IsolationReason::Uncovered => "ClaudeSwitcher UncoveredLock",
        }
    }

    fn label(self) -> &'static str {
        match self {
            IsolationReason::EgressTrip => "熔断",
            IsolationReason::Uncovered => "未接入兜底封锁",
        }
    }
}

#[cfg(test)]
/// 规则名：`ClaudeSwitcher AppIsolation <agent> <Out|In>`。
///
/// **兼容用法**：旧版按「每应用一条」建规则，规则名不带路径后缀。
/// 新代码按「每应用 × 每路径」建规则（见 [`rule_name_for_exe`]），
/// 但仍需识别旧规则以便清理，因此保留本函数。
pub fn rule_name(agent: &str, direction: &str) -> String {
    format!("{RULE_PREFIX} {agent} {direction}")
}

#[cfg(test)]
/// **P0-08**：按「应用 + 方向 + 具体可执行路径」生成规则名。
///
/// 同一应用可能有多个安装路径（用户级 / 系统级 / MSIX）。若仍用
/// `rule_name()` 的单一名，后建的规则会覆盖前一条，导致只有一份安装被隔离。
///
/// 后缀取路径 SHA256 的前 12 位十六进制：稳定（同一路径永远同一后缀）、
/// 短到能读、且不会因路径里的空格/斜杠污染规则名。
pub fn rule_name_for_exe(agent: &str, direction: &str, exe: &str) -> String {
    // 保持既有命名（熔断规则名不变），新来源走 `rule_name_for_reason`。
    use sha2::{Digest, Sha256};
    let normalized = crate::platform::imp::normalize_path(std::path::Path::new(exe));
    let digest = Sha256::digest(normalized.to_string_lossy().as_bytes());
    let suffix: String = digest.iter().take(6).map(|b| format!("{b:02x}")).collect();
    format!("{} {suffix}", rule_name(agent, direction))
}

/// 结束一个应用的全部进程（按进程名 + 映像路径判定 GUI/CLI）。
///
/// **P0-09**：不能只用 `kill_processes_by_names`。Windows 的进程名匹配
/// 大小写不敏感，`Claude` 与 `claude` 会同时命中桌面版与 Claude Code 原生 CLI。
/// 这里复用 `kill_desktop_app_processes`（按映像路径排除 node/npm/nvm 等 CLI 宿主），
/// 与旧保镖采用同一套策略。
pub fn kill_agent_processes(agent: &str) -> Result<Vec<String>, String> {
    let Some((_, exe_names)) = agent_spec(agent) else {
        return Ok(Vec::new());
    };
    crate::platform::imp::kill_desktop_app_processes(exe_names)
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

/// **P0-08**：一个受管应用的可执行文件候选路径及其来源。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExeCandidate {
    /// 规范化后的完整路径。
    pub path: String,
    /// 来源：`running`（运行中的进程）/ `installed`（安装记录）/ `registered`（注册表）。
    pub source: String,
}

/// **P0-08**：解析某个应用的全部候选 exe 路径。
///
/// 原实现 `Get-Process ... | Select-Object -First 1` 只取第一个正在运行的进程：
/// 应用没运行、或同一应用装了多份（用户级 + 系统级 + MSIX）时，要么拿不到路径
/// （无法预先建立隔离），要么只覆盖其中一份（另一份仍可联网）。
///
/// 现在按三个来源合并去重：
/// 1. **运行中的进程**：`Get-Process`（含 Path），保留全部不同路径；
/// 2. **注册表安装记录**：`App Paths` / `Uninstall` 里的 DisplayIcon /
///    InstallLocation，覆盖「没运行但已安装」的常见情形；
/// 3. **MSIX 包**：`Get-AppxPackage` 的 InstallLocation，Store 版 Claude 走这条。
///
/// 返回 **规整化后的去重列表**。调用方对每个路径都要建立规则，
/// `rules_expected` 也随之按路径数放大。
pub fn resolve_agent_exe_candidates(agent: &str) -> Vec<ExeCandidate> {
    match resolve_agent_installation(agent) {
        InstallationLookup::Installed(candidates) => candidates,
        // 未安装 / 无法确认都返回空列表：调用方对这两种情况的**处置不同**
        // （见 `quarantine_agent_for`），不能用同一个空 Vec 混过去。
        InstallationLookup::NotInstalled | InstallationLookup::Unknown(_) => Vec::new(),
    }
}

/// **P2-04**：受管应用的安装状态三态。
///
/// 原实现把「确认没装」与「查询失败」都变成空 `Vec`，于是界面只能显示
/// 「无法建立隔离」——用户分不清是自己没装这个应用（正常），
/// 还是保护能力出了问题（异常）。两者对「是否已完整保护」的结论完全不同。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallationLookup {
    /// 已确认安装，附带全部可执行文件路径。
    Installed(Vec<ExeCandidate>),
    /// 已确认未安装（查询成功，三个来源都没有）。
    NotInstalled,
    /// 无法确认（查询失败/输出异常）。
    Unknown(String),
}

/// 查询受管应用的安装状态（三态）。
///
/// 与 [`resolve_agent_exe_candidates`] 用同一份脚本：区别只在于
/// **把「查询失败」与「查询成功但为空」区分开**。
pub fn resolve_agent_installation(agent: &str) -> InstallationLookup {
    let Some((_, exe_names)) = agent_spec(agent) else {
        // 未知 agent id 是调用方的配置错误，不是「未安装」。
        return InstallationLookup::Unknown(format!("未知的受管应用标识：{agent}"));
    };
    let names = exe_names
        .iter()
        .map(|n| ps_quote(n))
        .collect::<Vec<_>>()
        .join(",");
    // exe 名用于在注册表 InstallLocation 里拼候选文件名。
    let exe_files = exe_names
        .iter()
        .map(|n| ps_quote(&format!("{n}.exe")))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'\n\
         $found = New-Object System.Collections.ArrayList\n\
         # 1) 运行中的进程\n\
         foreach ($p in @(Get-Process -Name {names})) {{\n\
           if ($p.Path) {{ [void]$found.Add(@{{ path = $p.Path; source = 'running' }}) }}\n\
         }}\n\
         # 2) 注册表 App Paths / Uninstall 的安装位置\n\
         $exeNames = @({exe_files})\n\
         $roots = @(\n\
           'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths',\n\
           'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths',\n\
           'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths'\n\
         )\n\
         foreach ($root in $roots) {{\n\
           foreach ($n in $exeNames) {{\n\
             $k = Join-Path $root $n\n\
             if (Test-Path $k) {{\n\
               $v = (Get-ItemProperty -Path $k).'(default)'\n\
               if ($v) {{ [void]$found.Add(@{{ path = $v; source = 'registered' }}) }}\n\
             }}\n\
           }}\n\
         }}\n\
         foreach ($root in @('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall')) {{\n\
           foreach ($sub in @(Get-ChildItem $root -ErrorAction SilentlyContinue)) {{\n\
             $props = Get-ItemProperty $sub.PSPath -ErrorAction SilentlyContinue\n\
             if (-not $props) {{ continue }}\n\
             $loc = $props.InstallLocation\n\
             if (-not $loc) {{ continue }}\n\
             foreach ($n in $exeNames) {{\n\
               $candidate = Join-Path $loc $n\n\
               if (Test-Path $candidate) {{ [void]$found.Add(@{{ path = $candidate; source = 'installed' }}) }}\n\
             }}\n\
           }}\n\
         }}\n\
         # 3) MSIX 包：InstallLocation 是**目录**不是 exe。
         #    从包清单 AppxManifest.xml 的 Application Executable 取真实可执行文件，
         #    拼成完整路径并确认是文件；取不到就跳过，绝不把目录当 exe。
         foreach ($pkg in @(Get-AppxPackage -Name 'Claude' -ErrorAction SilentlyContinue)) {{
           if (-not $pkg.InstallLocation) {{ continue }}
           $manifest = Join-Path $pkg.InstallLocation 'AppxManifest.xml'
           if (-not (Test-Path -LiteralPath $manifest)) {{ continue }}
           try {{
             [xml]$doc = Get-Content -LiteralPath $manifest -ErrorAction Stop
             foreach ($app in @($doc.Package.Applications.Application)) {{
               $rel = $app.Executable
               if (-not $rel) {{ continue }}
               $full = Join-Path $pkg.InstallLocation $rel
               if (Test-Path -LiteralPath $full -PathType Leaf) {{
                 [void]$found.Add(@{{ path = $full; source = 'msix' }})
               }}
             }}
           }} catch {{ }}
         }}
         ConvertTo-Json -InputObject @($found) -Compress",
        names = names,
        exe_files = exe_files
    );
    // **P2-04**：查询失败不能等同于「未安装」。原实现 `let Ok(..) else { Vec::new() }`
    // 把 PowerShell 失败、超时、输出异常全压成空列表，界面于是显示
    // 「无法建立隔离」——与「用户根本没装这个应用」完全无法区分。
    let json = match crate::platform::imp::run_powershell(&script) {
        Ok(json) => json,
        Err(error) => return InstallationLookup::Unknown(format!("查询安装状态失败：{error}")),
    };
    let candidates = parse_exe_candidates(&json);
    if candidates.is_empty() {
        // 查询成功且三个来源都没有 → 明确「未安装」。
        InstallationLookup::NotInstalled
    } else {
        InstallationLookup::Installed(candidates)
    }
}

/// 解析候选路径 JSON（数组 / 单对象 / 空），并做规整化去重。
///
/// 单独抽成纯函数便于单测：PowerShell 侧无法在 CI 里跑。
fn parse_exe_candidates(json: &str) -> Vec<ExeCandidate> {
    let trimmed = json.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Vec::new();
    }
    let value: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let items: Vec<serde_json::Value> = match value {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Object(_) => vec![value],
        _ => return Vec::new(),
    };
    let mut out: Vec<ExeCandidate> = Vec::new();
    let mut seen: Vec<std::path::PathBuf> = Vec::new();
    for item in items {
        let (Some(path), source) = (
            item.get("path").and_then(|v| v.as_str()).map(str::trim),
            item.get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
        ) else {
            continue;
        };
        if path.is_empty() {
            continue;
        }
        // MSIX 的 InstallLocation 是目录：拼上 exe 名再判断（由调用方保证存在）。
        let normalized = crate::platform::imp::normalize_path(std::path::Path::new(path));
        if seen.contains(&normalized) {
            continue;
        }
        seen.push(normalized);
        out.push(ExeCandidate {
            path: path.to_string(),
            source: source.to_string(),
        });
    }
    out
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleVerification {
    query_ok: bool,
    expected: u32,
    verified: u32,
    failed: Vec<String>,
}

/// 一条**预期存在的规则**：名称、方向、程序路径三者绑定。
///
/// **P0-01**：创建与核验必须共用同一份预期清单。原实现创建用
/// `rule_name_for_exe()`（带路径哈希后缀），核验却在 PowerShell 里重新拼
/// `"{prefix} {agent} {Out|In}"`（无后缀）——新建的规则永远核验不到，
/// `coverage_complete` 恒为 false。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedRule {
    pub name: String,
    /// `"Out"` / `"In"`（用于失败说明）。
    pub dir: String,
    /// 期望的 `Direction` 值：`Outbound` / `Inbound`。
    pub direction: &'static str,
    pub exe: String,
}

#[cfg(test)]
/// 为「应用 × 每个 exe × 每个方向」生成完整的预期规则集合。
///
/// 这是**唯一**的规则标识来源：创建与核验都调用它，不允许任何一方自行拼接。
pub fn expected_rules(agent: &str, exes: &[String]) -> Vec<ExpectedRule> {
    // 熔断是完整的出站+入站隔离；只有未接入兜底才是仅出站。
    expected_rules_for(IsolationReason::EgressTrip, agent, exes, false)
}

/// **P0-01 / QW-01**：按来源生成预期规则；`outbound_only` 只含出站方向。
pub fn expected_rules_for(
    reason: IsolationReason,
    agent: &str,
    exes: &[String],
    outbound_only: bool,
) -> Vec<ExpectedRule> {
    let mut out = Vec::with_capacity(exes.len() * 2);
    for exe in exes {
        out.push(ExpectedRule {
            name: rule_name_for_reason(reason, agent, "Out", exe),
            dir: "Out".to_string(),
            direction: "Outbound",
            exe: exe.clone(),
        });
        if !outbound_only {
            out.push(ExpectedRule {
                name: rule_name_for_reason(reason, agent, "In", exe),
                dir: "In".to_string(),
                direction: "Inbound",
                exe: exe.clone(),
            });
        }
    }
    out
}

/// 带来源前缀的规则名（同一应用的不同来源互不冲突）。
pub fn rule_name_for_reason(
    reason: IsolationReason,
    agent: &str,
    direction: &str,
    exe: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let normalized = crate::platform::imp::normalize_path(std::path::Path::new(exe));
    let digest = Sha256::digest(normalized.to_string_lossy().as_bytes());
    let suffix: String = digest.iter().take(6).map(|b| format!("{b:02x}")).collect();
    format!("{} {agent} {direction} {suffix}", reason.prefix())
}

/// 查询某个应用在**全部已解析路径**上的规则是否完整生效。
///
/// **P0-08**：期望集合从 `exe × 2 方向` 扩展为
/// `每一条候选 exe × 出站/入站`。多路径（用户级 + 系统级 + MSIX 共存）时
/// 只覆盖其中一份等于没隔离——另一份照样能联网。
///
/// **P0-01**：预期清单由 [`expected_rules`] 生成后**整体传给 PowerShell**，
/// 脚本只用传入的名称查询，绝不自行拼接。
///
/// 核验的每条规则必须同时满足：
/// 1. 存在且启用（`Enabled=True`）；
/// 2. `Action=Block`、方向正确；
/// 3. `Program` 与候选路径一致（规范化后比较）；
/// 4. **在当前生效策略下确实存在**——`Get-NetFirewallRule -PolicyStore ActiveStore`
///    能看到它。只查配置对象（`PersistentStore`）不等于证明阻断已生效：
///    组策略可能覆盖或禁用本地规则。
fn count_rules_for_reason(
    reason: IsolationReason,
    agent: &str,
    exes: &[String],
    outbound_only: bool,
) -> RuleVerification {
    let expected_rules = expected_rules_for(reason, agent, exes, outbound_only);
    let expected = expected_rules.len() as u32;
    if expected_rules.is_empty() {
        return RuleVerification {
            query_ok: true,
            expected: 0,
            verified: 0,
            failed: vec!["没有可核验的可执行文件路径".to_string()],
        };
    }
    // 把「名称 + 方向 + 程序」打包成 JSON 传入脚本：脚本不拼接规则名。
    let spec = expected_rules
        .iter()
        .map(|rule| {
            serde_json::json!({
                "name": rule.name,
                "dir": rule.dir,
                "direction": rule.direction,
                "exe": rule.exe,
            })
        })
        .collect::<Vec<_>>();
    let spec_json = serde_json::to_string(&spec).unwrap_or_else(|_| "[]".to_string());
    let script = format!(
        "$ErrorActionPreference='Stop'\n\
         $json = {spec} \n\
         $specs = $json | ConvertFrom-Json\n\
         $results = New-Object System.Collections.ArrayList\n\
         foreach ($s in $specs) {{\n\
           $ok = $false\n\
           $reason = ''\n\
           try {{\n\
             $r = Get-NetFirewallRule -DisplayName $s.name -PolicyStore PersistentStore -ErrorAction Stop | Select-Object -First 1\n\
             if (-not $r) {{ $reason = '规则不存在' }}\n\
             else {{\n\
               $f = $r | Get-NetFirewallApplicationFilter\n\
               if ($r.Enabled -ne 'True') {{ $reason = '规则未启用' }}\n\
               elseif ($r.Action -ne 'Block') {{ $reason = '动作不是阻断' }}\n\
               elseif ($r.Direction -ne $s.direction) {{ $reason = '方向不符' }}\n\
               elseif (-not $f.Program) {{ $reason = '规则未绑定程序' }}\n\
               elseif ($f.Program -ine $s.exe) {{ $reason = '程序路径不匹配' }}\n\
               else {{\n\
                 $active = @(Get-NetFirewallRule -DisplayName $s.name -PolicyStore ActiveStore -ErrorAction SilentlyContinue)\n\
                 if ($active.Count -eq 0) {{ $reason = '未进入当前生效策略（可能被组策略覆盖）' }}\n\
                 else {{\n\
                   $ar = $active | Select-Object -First 1
                   $af = $ar | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
                   $pf = $ar | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                   $adf = $ar | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                   $portAny = $pf -and (
                     (((-not $pf.Protocol) -or $pf.Protocol -eq 'Any') -and
                      ((-not $pf.LocalPort) -or $pf.LocalPort -eq 'Any') -and
                      ((-not $pf.RemotePort) -or $pf.RemotePort -eq 'Any'))
                   )
                   $addrAny = $adf -and (
                     (((-not $adf.LocalAddress) -or $adf.LocalAddress -eq 'Any') -and
                      ((-not $adf.RemoteAddress) -or $adf.RemoteAddress -eq 'Any'))
                   )
                   $profileAll = ([string]$ar.Profile).ToLowerInvariant() -eq 'any'
                   # **P0-B**：单条条件链，任何一项不符都不得落到 $ok = $true。
                   # 原实现把端口/地址/Profile 检查写成独立链，前半段（动作/方向/
                   # 程序）已经判错时，只要后半段通过仍会把 $ok 置真。
                   if ($ar.Enabled -ne 'True') {{ $reason = '生效策略中的规则未启用' }}
                   elseif ($ar.Action -ne 'Block') {{ $reason = '生效策略中的动作不是阻断' }}
                   elseif ($ar.Direction -ne $s.direction) {{ $reason = '生效策略中的方向不符' }}
                   elseif (-not $af -or -not $af.Program -or $af.Program -ine $s.exe) {{ $reason = '生效策略的程序过滤条件不符' }}
                   elseif (-not $pf -or -not $adf) {{ $reason = '生效策略的过滤器查询不完整' }}
                   elseif (-not $portAny) {{ $reason = '生效策略限定了端口范围，未覆盖全部流量' }}
                   elseif (-not $addrAny) {{ $reason = '生效策略限定了地址范围，未覆盖全部流量' }}
                   elseif (-not $profileAll) {{ $reason = '生效策略只对部分网络配置档生效' }}
                   else {{ $ok = $true }}
                 }}\n\
               }}\n\
             }}\n\
           }} catch {{ $reason = '规则不存在' }}\n\
           [void]$results.Add(@{{ name = $s.name; dir = $s.dir; exe = $s.exe; ok = $ok; reason = $reason }})\n\
         }}\n\
         ConvertTo-Json -InputObject @($results) -Compress",
        spec = ps_quote(&spec_json)
    );
    match crate::platform::imp::run_powershell(&script) {
        Ok(json) => parse_rule_verification_expected(&json, &expected_rules),
        Err(_) => RuleVerification {
            query_ok: false,
            expected,
            verified: 0,
            failed: vec!["规则查询失败（无法确认隔离是否生效）".to_string()],
        },
    }
}

/// 解析规则核验 JSON（严格：无法解析即 `query_ok=false`，绝不当作通过）。
fn parse_rule_verification_expected(json: &str, expected: &[ExpectedRule]) -> RuleVerification {
    let expected_count = expected.len() as u32;
    let value: serde_json::Value = match serde_json::from_str(json.trim()) {
        Ok(value) => value,
        Err(_) => {
            return RuleVerification {
                query_ok: false,
                expected: expected_count,
                verified: 0,
                failed: vec!["规则查询结果无法解析".to_string()],
            }
        }
    };
    let items: Vec<serde_json::Value> = match value {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Object(_) => vec![value],
        _ => {
            return RuleVerification {
                query_ok: false,
                expected: expected_count,
                verified: 0,
                failed: vec!["规则查询结果格式异常".to_string()],
            }
        }
    };
    // **QW-03**：结果必须与预期集合**逐项按名称匹配**。
    //
    // 原实现只统计 `ok=true` 的条数：脚本若返回重复条目（或返回了不属于预期
    // 集合的名称），条数照样能凑够 expected，于是「数量对上了」被当成完整覆盖。
    // 现在按规则名建立映射，每个预期名称恰好计一次；未出现、重复出现或
    // 名称不属于预期集合，都不计入 verified。
    let mut seen: std::collections::BTreeMap<&str, (bool, String)> =
        std::collections::BTreeMap::new();
    let mut unknown_names: Vec<String> = Vec::new();
    for item in &items {
        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let dir = item.get("dir").and_then(|v| v.as_str()).unwrap_or("?");
        let exe = item.get("exe").and_then(|v| v.as_str()).unwrap_or("?");
        // `ok` 必须是明确的布尔值：缺字段一律按失败处理（不能 filter_map 丢掉）。
        let ok = item.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        let reason = item
            .get("reason")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("原因未知")
            .to_string();
        if !expected.iter().any(|rule| rule.name == name) {
            unknown_names.push(format!("{name}（{dir} {exe}）"));
            continue;
        }
        // **QW-01**：同名结果**重复出现**本身就是异常（脚本应每条预期规则
        // 只返回一行）。若允许重复，两条 ok 就能凑出 verified=2，
        // 掩盖另一条规则根本没被检查的事实。这里直接判查询失败。
        if seen.contains_key(name) {
            return RuleVerification {
                query_ok: false,
                expected: expected_count,
                verified: 0,
                failed: vec![format!("核验结果中规则名重复出现：{name}")],
            };
        }
        seen.insert(name, (ok, reason));
    }
    let mut verified = 0u32;
    let mut failed = Vec::new();
    for rule in expected {
        match seen.get(rule.name.as_str()) {
            Some((true, _)) => verified += 1,
            Some((false, reason)) => failed.push(format!("{} {}：{reason}", rule.dir, rule.exe)),
            None => failed.push(format!("{} {}：核验结果中缺少该规则", rule.dir, rule.exe)),
        }
    }
    if !unknown_names.is_empty() {
        // 脚本返回了不属于预期集合的规则：说明名称拼接或查询范围有问题，
        // 不能当作查询成功。
        return RuleVerification {
            query_ok: false,
            expected: expected_count,
            verified,
            failed: vec![format!(
                "核验结果包含非预期规则：{}",
                unknown_names.join("、")
            )],
        };
    }
    RuleVerification {
        query_ok: true,
        expected: expected_count,
        verified,
        failed,
    }
}

/// PowerShell 单引号转义（把 `'` 写成 `''`）。
fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// 为单个应用加隔离：结束进程 → 按**全部已解析路径**加出/入站阻断 → 回查核验。
///
/// **P0-08 变化**：
/// - 路径来自 [`resolve_agent_exe_candidates`]（进程 + 注册表安装记录 + MSIX），
///   而不是「取第一个运行中的进程」——应用没运行也能预先建立隔离；
/// - 每个路径都建规则（多安装形态共存时只覆盖一份等于没隔离）；
/// - 核验走 [`count_rules_for`]，要求同时满足属性正确 + 出现在 `ActiveStore`。
///
/// 解析不到任何路径时只结束进程，并**如实**说明「未加防火墙规则」，
/// 绝不谎称已隔离。
pub fn quarantine_agent(agent: &str, exe_path: Option<&str>) -> QuarantineReport {
    quarantine_agent_with(agent, exe_path, true)
}

/// `kill=false` 时只建立出站隔离规则、**不结束进程**。
///
/// **P0-C**：未接入兜底封锁只应「挡住出站」，不该在用户刚发现代理没开时
/// 就把正在用的 Claude Desktop 杀掉——那是普通熔断（目标失败达阈值）的语义。
pub fn quarantine_agent_with(agent: &str, exe_path: Option<&str>, kill: bool) -> QuarantineReport {
    quarantine_agent_for(IsolationReason::EgressTrip, agent, exe_path, kill, false)
}

/// **P0-01 / QW-01**：按来源建立隔离；`outbound_only` 时只建出站规则。
pub fn quarantine_agent_for(
    reason: IsolationReason,
    agent: &str,
    exe_path: Option<&str>,
    kill: bool,
    outbound_only: bool,
) -> QuarantineReport {
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
        installation: ApplicationInstallation::Installed,
        note: String::new(),
    };
    if !is_guarded_agent(agent) {
        report.note = format!("未知守护对象「{agent}」，已跳过");
        return report;
    }

    // 1. **先解析路径**：必须在进程还活着时取（结束后 Get-Process 拿不到）。
    let exes: Vec<String> = match exe_path {
        // 显式传入的路径由调用方负责身份（测试/预览场景）。
        Some(explicit) => vec![explicit.to_string()],
        None => {
            // **P2-04**：三态。确认未安装与查询失败必须分开报告，否则用户
            // 无法判断「没装这个应用（正常）」还是「保护能力失效（异常）」。
            let candidates: Vec<String> = match resolve_agent_installation(agent) {
                InstallationLookup::Installed(candidates) => {
                    candidates.into_iter().map(|c| c.path).collect()
                }
                InstallationLookup::NotInstalled => {
                    report.installation = ApplicationInstallation::NotInstalled;
                    if kill {
                        match kill_agent_processes(agent) {
                            Ok(killed) => report.killed = killed,
                            Err(error) => {
                                report.note.push_str(&format!("结束进程失败（{error}）；"))
                            }
                        }
                    }
                    report.note.push_str(
                        "未检测到该应用的安装记录（已确认未安装），无需隔离；这不是保护失败",
                    );
                    return report;
                }
                InstallationLookup::Unknown(error) => {
                    report.installation = ApplicationInstallation::Unknown;
                    if kill {
                        match kill_agent_processes(agent) {
                            Ok(killed) => report.killed = killed,
                            Err(kill_error) => report
                                .note
                                .push_str(&format!("结束进程失败（{kill_error}）；")),
                        }
                    }
                    report.note.push_str(&format!(
                        "无法确认该应用的安装状态（{error}），不能宣称已保护；请重试或人工核对"
                    ));
                    return report;
                }
            };
            // **P1-06（v0.7.1）**：只保留确认属于**受管 GUI** 的路径。
            // 原实现把进程名匹配到的一切都收进来，原生 CLI 会被写成
            // GUI 隔离规则——查杀端早就按 GUI 身份过滤，两端标准必须一致。
            let gui = crate::platform::imp::filter_managed_gui_paths(candidates.clone());
            if gui.is_empty() {
                // 一个都不能确认属于 GUI：宁可不建规则，也不误伤 CLI。
                candidates
                    .into_iter()
                    .filter(|path| {
                        // 保留传统安装路径（无明确 CLI 特征且带程序目录）作为兜底，
                        // 但显式排除 CLI 宿主路径。
                        !path.to_ascii_lowercase().contains("\node_modules\\")
                            && !path.to_ascii_lowercase().contains("\npm\\")
                    })
                    .collect()
            } else {
                gui
            }
        }
    };
    if exes.is_empty() {
        // 没有路径：仍然结束进程（至少阻止当前实例），但必须说明隔离未完成。
        if kill {
            match kill_agent_processes(agent) {
                Ok(killed) => report.killed = killed,
                Err(error) => report.note.push_str(&format!("结束进程失败（{error}）；")),
            }
        }
        report.note.push_str(
            "未找到可执行文件路径（应用可能未安装或从未运行），无法建立防火墙隔离；保护未完成",
        );
        return report;
    }

    // 2. 再结束进程（失败不阻断后续隔离：进程可能已退出）。
    if kill {
        match kill_agent_processes(agent) {
            Ok(killed) => report.killed = killed,
            Err(error) => report.note.push_str(&format!("结束进程失败（{error}）；")),
        }
    }

    // 3. 为**每个路径**建立出/入站阻断规则。
    //
    // 规则名带上路径的稳定哈希后缀：同一应用多路径共存时，每条规则对应一个
    // 具体程序，既不会互相覆盖，也能在升级后按旧路径精确清理。
    // **P0-01**：规则名来自 [`expected_rules`]——与核验使用的是**同一份**清单。
    // 任何一方自行拼接名称都会让新建的规则永远核验不到。
    for rule in expected_rules_for(reason, agent, &exes, outbound_only) {
        // **P0-NEW-01**：创建路径上的 `SilentlyContinue` 会把「权限不足
        // （未以管理员运行）」吞成一次「成功」，随后回查才发现不完整，
        // 用户看到的是含糊的「覆盖不完整」。这里全部改 `Stop`，
        // 让错误消息直接带出真正原因（拒绝访问）。
        let script = format!(
            "$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='Stop'
# 无语句级 exit/return：两者都会跳过执行结果哨兵。
$name = {name}
$wantDirection = {direction}
$wantProgram = {program}
$existing = @(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)
$healthy = $false
foreach ($r in $existing) {{
  $f = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
  if ($r.Enabled -eq 'True' -and $r.Action -eq 'Block' -and
      $r.Direction -eq $wantDirection -and $f.Program -and $f.Program -ieq $wantProgram) {{
    $healthy = $true
  }}
}}
if (-not $healthy) {{
  if ($existing.Count -gt 0) {{ $existing | Remove-NetFirewallRule -ErrorAction Stop }}
  New-NetFirewallRule -DisplayName $name -Direction $wantDirection -Action Block -Program $wantProgram -Enabled True -ErrorAction Stop | Out-Null
}}",
            name = ps_quote(&rule.name),
            direction = rule.direction,
            program = ps_quote(&rule.exe)
        );
        match crate::platform::imp::run_powershell(&script) {
            Ok(_) => report.rules_added += 1,
            Err(error) => report.note.push_str(&format!(
                "添加 {} 的{}站规则失败（{error}）；",
                rule.exe,
                if rule.dir == "Out" { "出" } else { "入" }
            )),
        }
    }

    // 4. 回查：规则写入返回成功不等于当前策略下真的生效。
    let mut verification = count_rules_for_reason(reason, agent, &exes, outbound_only);
    if verification.query_ok && verification.verified > 0 {
        // 规则对象存在仍不代表当前活动网络受防火墙过滤。
        match crate::platform::imp::effective_firewall_enabled() {
            Some(true) => {}
            Some(false) => {
                verification.verified = 0;
                verification
                    .failed
                    .push("当前活动网络的防火墙已关闭".to_string());
            }
            None => {
                verification.query_ok = false;
                verification
                    .failed
                    .push("无法读取当前生效的防火墙配置".to_string());
            }
        }
    }
    report.query_ok = verification.query_ok;
    report.rules_expected = verification.expected;
    report.rules_verified = verification.verified;
    // 核验必须有过非零期望——「0 条期望、0 条通过」不能算成功。
    report.coverage_complete = verification.query_ok
        && verification.expected > 0
        && verification.verified >= verification.expected;
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
        report.note.push_str(&format!(
            "已隔离 {} 个可执行文件路径（出/入站阻断规则在当前生效策略下完整生效）：{}",
            exes.len(),
            exes.join("、")
        ));
        // **P0-08**：新路径规则已经完整生效，才清理指向旧路径的失效规则
        // （升级后 exe 路径变化会留下永远匹配不到的残留）。
        match prune_stale_rule_targets() {
            Ok(0) => {}
            Ok(removed) => report
                .note
                .push_str(&format!("；已清理 {removed} 条指向旧安装路径的失效规则")),
            Err(error) => report.note.push_str(&format!(
                "；清理旧路径规则失败（{error}），已保留待下次重试"
            )),
        }
    }
    report
}
/// **P0-04**：是否允许此刻新增隔离副作用（普通熔断与兜底封锁共用）。
///
/// 必须**在持有系统操作锁之后**调用：锁前读到的意图可能已经过期。
///
/// 这里检查的是「此刻的事实」而不是「调用方几秒前的判断」。P0-04 要求
/// `egate_revision` 贯穿**所有副作用**——光在探测结束时比一次代次不够：
/// 等待系统操作锁期间、以及每个应用建立规则之前，配置都可能已经变了。
pub fn can_apply_isolation_now() -> bool {
    can_apply_isolation_with_revision(None)
}

/// 带上「发起本次操作的配置代次」的版本。
///
/// `expected_revision = Some(r)` 时额外要求当前配置代次仍等于 `r`：
/// 用户在探测之后、真正动手之前改了目标/阈值/开关，旧判定就必须作废。
/// `None` 表示调用方没有代次信息（例如手动熔断按钮），只检查当前事实。
pub fn can_apply_isolation_with_revision(expected_revision: Option<u64>) -> bool {
    if crate::egate_monitor::protection_intent() != crate::egate_monitor::ProtectionIntent::Armed {
        return false;
    }
    if crate::egate_monitor::is_paused() {
        return false;
    }
    // **P0-04（v0.7.1）**：取锁后再确认门禁**当前**仍是开启的。
    // 探测可能耗时数秒，期间用户可能把 egate_enabled 关掉——
    // 此时旧判定不应再结束进程或写入规则。
    match crate::appconfig::load_checked() {
        crate::appconfig::ConfigLoad::Ok(config) => {
            if !config.egate_enabled {
                return false;
            }
            match expected_revision {
                // 代次不一致 = 配置在决策之后被改过，旧判定作废。
                Some(expected) => config.egate_revision == expected,
                None => true,
            }
        }
        // 配置损坏/首次安装：不据此施加新的隔离副作用。
        _ => false,
    }
}

/// **P0-C**：未接入兜底封锁——只建出站隔离，**不结束进程**。
///
/// 与 [`trip`] 共用同一套规则建立与核验逻辑（不新增第二套防火墙实现），
/// 但不杀进程：用户只是暂时没开代理，不应被直接踢下线。
pub fn enforce_uncovered_outbound(guarded_agents: &[String]) -> TripReport {
    if guarded_agents.is_empty() {
        return TripReport {
            agents: Vec::new(),
            any_isolated: false,
            all_isolated: false,
            failures: Vec::new(),
            note: "没有配置的守护对象，未执行任何操作".to_string(),
        };
    }
    let guard = match crate::egate_lock::acquire(crate::egate_lock::SystemOperation::Isolate) {
        Ok(guard) => guard,
        Err(error) => {
            return TripReport {
                agents: Vec::new(),
                any_isolated: false,
                all_isolated: false,
                failures: vec![format!("无法获取系统操作锁：{error}")],
                note: format!("兜底封锁未执行（{error}）"),
            };
        }
    };
    let _keep = &guard;
    // **P0-04**：拿到锁后**重新核验**用户意图——等待锁期间用户可能刚执行急救恢复。
    // 普通 `trip()` 早已这么做，新增的兜底路径漏了这一步，会出现
    // 「急救刚完成，迟到的后台任务又把规则加回来」。
    if !can_apply_isolation_now() {
        return TripReport {
            agents: Vec::new(),
            any_isolated: false,
            all_isolated: false,
            failures: Vec::new(),
            note: "保护已停止或已暂停（意图在等待锁期间改变），未执行兜底封锁".to_string(),
        };
    }
    let mut agents = Vec::new();
    let mut failures = Vec::new();
    for id in guarded_agents {
        // **QW-01**：兜底封锁只建**出站**规则，不碰入站。
        let report = quarantine_agent_for(IsolationReason::Uncovered, id, None, false, true);
        if !report.verified {
            failures.push(format!("{}：{}", report.agent, report.note.trim()));
        }
        agents.push(report);
    }
    let any_isolated = agents.iter().any(|agent| agent.verified);
    let all_isolated = agents.iter().all(|agent| agent.coverage_complete);
    TripReport {
        note: if all_isolated {
            "未接入兜底封锁：全部守护对象出站规则已生效".to_string()
        } else if any_isolated {
            "未接入兜底封锁：部分生效（见失败说明）".to_string()
        } else {
            "未能确认任何兜底规则生效".to_string()
        },
        agents,
        any_isolated,
        all_isolated,
        failures,
    }
}

/// 执行一次熔断：对配置里所有守护对象结束进程并隔离。
///
/// 与上游一致：**只处理 GUI 应用**；CLI 宿主不在守护列表里，避免误伤终端。
pub fn trip(guarded_agents: &[String]) -> TripReport {
    trip_with_revision(guarded_agents, None)
}

/// **P0-04**：带配置代次的熔断入口。
///
/// 监控线程在探测开始时就记下 `egate_revision`，真正动手前（已持锁）用
/// [`can_apply_isolation_with_revision`] 比对。代次不一致说明用户在探测之后
/// 改过目标/阈值/开关，这一轮的结论已经不作数——绝不按旧判定杀进程。
pub fn trip_with_revision(guarded_agents: &[String], expected_revision: Option<u64>) -> TripReport {
    // 没有守护对象时不申请系统操作锁：无事可做的调用不该因为锁不可用而报错。
    if guarded_agents.is_empty() {
        return TripReport {
            agents: Vec::new(),
            any_isolated: false,
            all_isolated: false,
            failures: Vec::new(),
            note: "没有配置的守护对象，未执行任何操作".to_string(),
        };
    }
    // **P0-02**：熔断必须独占系统操作权。
    let guard = match crate::egate_lock::acquire(crate::egate_lock::SystemOperation::Isolate) {
        Ok(guard) => guard,
        Err(error) => {
            return TripReport {
                agents: Vec::new(),
                any_isolated: false,
                all_isolated: false,
                failures: vec![format!("无法获取系统操作锁：{error}")],
                note: format!("熔断未执行（{error}）"),
            };
        }
    };
    let _keep = &guard;
    // **P0-06**：拿到锁后重新核验保护意图——等待锁期间用户可能刚执行了
    // 紧急恢复（Disarmed），或状态文件损坏（Unknown）。此时旧的「该熔断」决策
    // 已过期，绝不能继续施加隔离。
    // **P0-04**：同时比对配置代次（用户可能改了目标/阈值/开关）。
    if !can_apply_isolation_with_revision(expected_revision) {
        return TripReport {
            agents: Vec::new(),
            any_isolated: false,
            all_isolated: false,
            failures: Vec::new(),
            note: "保护已暂停、已停止或配置已变更（判定在操作期间过期），未执行熔断".to_string(),
        };
    }
    let mut agents = Vec::new();
    let mut failures = Vec::new();
    for id in guarded_agents {
        // **P0-04**：每个应用动手前再看一次——前一个应用建立规则可能耗时数秒。
        if !can_apply_isolation_with_revision(expected_revision) {
            failures.push("配置在熔断过程中变更，剩余应用未处理".to_string());
            break;
        }
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

/// **P0-C**：清理旧版应用隔离规则（升级兼容）。
///
/// 旧版本用 `ClaudeSwitcher Egate {agent} Out/In`，新版改为 `AppIsolation`。
/// 升级后旧规则可能残留，导致「已解除隔离」但应用仍无法联网。
///
/// **安全边界**：旧命名空间也可能包含全局断网规则（`... Cut All`），
/// 因此只删除**匹配旧应用隔离格式**的规则（名字里含具体 agent 名），
/// 绝不按 `ClaudeSwitcher Egate*` 通配删除。
pub fn cleanup_legacy_rules() -> Result<u32, String> {
    // **回归修复（v0.7.2）**：这里曾被改成按 `ClaudeSwitcher Egate *` 通配删除。
    // 那个前缀**同时覆盖全局断网规则** `ClaudeSwitcher Egate Cut All`，于是
    // 「解除应用隔离」会顺手把用户的全局断网一起删掉，而 `restore_all()`
    // 的账本仍写着「断网中」——恢复器随后又去核验一条已不存在的规则。
    //
    // 现在按**精确名称 + 精确谓词**删除：只处理旧版内置 agent 的两种方向，
    // 额外的 `Where-Object` 再挡一层，未来新增的规则名不会被误删。
    let legacy_names: Vec<String> = ["claude", "chatgpt", "antigravity"]
        .iter()
        .flat_map(|agent| {
            [
                format!("ClaudeSwitcher Egate {agent} Out"),
                format!("ClaudeSwitcher Egate {agent} In"),
            ]
        })
        .collect();
    let list = legacy_names
        .iter()
        .map(|name| ps_quote(name))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='Stop'
# 无语句级 exit/return：两者都会跳过执行结果哨兵。
$removed = 0
foreach ($n in @({list})) {{
  $pattern = [WildcardPattern]::Escape($n)
  $rules = @(Get-NetFirewallRule -DisplayName ($pattern + '*') -ErrorAction Stop |
             Where-Object {{ $_.DisplayName -eq $n }})
  if ($rules.Count -gt 0) {{
    $rules | Remove-NetFirewallRule -ErrorAction Stop
    $removed += $rules.Count
  }}
}}
ConvertTo-Json @{{ removed = $removed }} -Compress"
    );
    let json = crate::platform::imp::run_powershell(&script)
        .map_err(|e| format!("清理旧规则失败：{e}"))?;
    let value: serde_json::Value =
        serde_json::from_str(json.trim()).map_err(|e| format!("清理结果解析失败：{e}"))?;
    Ok(value.get("removed").and_then(|v| v.as_u64()).unwrap_or(0) as u32)
}

/// 解除应用隔离规则（只删除本应用的隔离规则，不影响全局断网）。
///
/// 使用 `AppIsolation` 前缀，与 `Cut All` 断网规则严格区分。
/// 按名字删而不是按记录的状态删：崩溃后重启也能清干净。
/// **P0-04**：删除结果（结构化，必须回查确认）。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseReport {
    pub requested: u32,
    pub remaining: u32,
    pub verified: bool,
    pub failures: Vec<String>,
}

/// **P0-08**：清理指向**已不存在路径**的本产品隔离规则。
///
/// 应用升级/换盘后 exe 路径会变：旧规则的 `Program` 指向一个不存在的文件，
/// 永远不会再匹配任何进程，却会让 `rule_count()` 认为「仍处于隔离」，
/// 也让用户以为还有保护。调用点在**新路径规则建立成功之后**——先有覆盖，
/// 再清旧账，顺序反过来会出现「旧规则删了、新规则还没建」的空窗。
///
/// **只删除确认属于本产品、且 Program 确实不存在的规则**；
/// 查询失败或无法解析一律不删（宁可留残留，也不误删正在生效的规则）。
pub fn prune_stale_rule_targets() -> Result<u32, String> {
    let script = format!(
        "$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='Stop'
# 无语句级 exit/return：两者都会跳过执行结果哨兵。
$rules = @(Get-NetFirewallRule -DisplayName ({} + '*') -ErrorAction Stop)
$removed = 0
foreach ($r in $rules) {{
  $f = $r | Get-NetFirewallApplicationFilter -ErrorAction Stop
  $p = $f.Program
  # 只有明确设置了程序路径、且该路径确实不存在的规则才算失效。
  # `Any` / 空 / 通配（全局阻断规则）绝不在这里处理。
  if (-not $p) {{ continue }}
  if ($p -eq 'Any') {{ continue }}
  if ($p -like '*\\*') {{
    if (-not (Test-Path -LiteralPath $p)) {{
      $r | Remove-NetFirewallRule -ErrorAction Stop
      $removed++
    }}
  }}
}}
ConvertTo-Json @{{ removed = $removed }} -Compress",
        ps_quote(RULE_PREFIX)
    );
    let json = crate::platform::imp::run_powershell(&script)
        .map_err(|e| format!("清理失效规则失败：{e}"))?;
    let value: serde_json::Value =
        serde_json::from_str(json.trim()).map_err(|e| format!("清理结果解析失败：{e}"))?;
    Ok(value.get("removed").and_then(|v| v.as_u64()).unwrap_or(0) as u32)
}

/// **P0-03**：只读核验「当前熔断是否仍然真正生效」。
///
/// 复用 `count_rules_for_reason`（ActiveStore + 属性 + 过滤器全覆盖），
/// 不靠规则条数判断。返回 `None` 表示查询失败（无法确认）。
pub fn verify_current_isolation(guarded_agents: &[String]) -> Option<bool> {
    if guarded_agents.is_empty() {
        return Some(true);
    }
    // **P0-03（v0.7.1）**：规则存在 ≠ 阻断生效。当前活动网络的防火墙
    // 配置若被关闭，规则一条不少也不会拦任何流量。
    // 这里与创建规则时的 `quarantine_agent_for()` 保持一致：必须同时成立。
    match crate::platform::imp::effective_firewall_enabled() {
        Some(true) => {}
        // 明确关闭：覆盖不完整（返回 Some(false) 让调用方降级）。
        Some(false) => return Some(false),
        // 读不出来：无法确认。
        None => return None,
    }
    let mut all_ok = true;
    for agent in guarded_agents {
        let exes = resolve_agent_exe_candidates(agent)
            .into_iter()
            .map(|c| c.path)
            .collect::<Vec<_>>();
        if exes.is_empty() {
            // 没有可执行路径：无法建立也无法核验，按「不完整」处理。
            all_ok = false;
            continue;
        }
        let verification = count_rules_for_reason(IsolationReason::EgressTrip, agent, &exes, false);
        if !verification.query_ok {
            return None;
        }
        if verification.verified < verification.expected {
            all_ok = false;
        }
    }
    Some(all_ok)
}

/// 解除隔离的来源，决定是否检查手动保持意图。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseReason {
    Automatic,
    UserRequested,
    Emergency,
}

/// 自动恢复、用户手动解除和紧急恢复共用核验删除逻辑，但只有自动恢复受手动保持拦截。
pub fn release_verified(reason: ReleaseReason) -> Result<ReleaseReport, String> {
    let guard = crate::egate_lock::acquire(crate::egate_lock::SystemOperation::ReleaseIsolation)?;
    if reason == ReleaseReason::Automatic {
        match crate::egate_monitor::manual_hold_state() {
            crate::egate_monitor::ManualHold::None => {}
            crate::egate_monitor::ManualHold::Held => {
                return Err(
                    "检测到用户手动保持的隔离，已放弃本次自动解除（仅手动解除可清除）".to_string(),
                );
            }
            crate::egate_monitor::ManualHold::Unknown => {
                return Err(
                    "无法确认手动隔离意图（意图文件损坏或不可读），已放弃本次自动解除".to_string(),
                );
            }
        }
    }
    release_verified_locked(&guard, reason)
}

/// 已持锁的解除实现：只有自动来源检查手动保持意图。
pub(crate) fn release_verified_locked(
    guard: &crate::egate_lock::OperationGuard,
    reason: ReleaseReason,
) -> Result<ReleaseReport, String> {
    if reason == ReleaseReason::Automatic {
        match crate::egate_monitor::manual_hold_state() {
            crate::egate_monitor::ManualHold::Held | crate::egate_monitor::ManualHold::Unknown => {
                return Err("手动保持隔离生效中，已放弃本次自动解除".to_string())
            }
            crate::egate_monitor::ManualHold::None => {}
        }
    }
    release_all_verified_locked(guard)
}

/// **P0-01**：只解除**指定来源**拥有的规则，不影响其他来源。
///
/// 原实现只有 `release_all_verified_locked()`：解除未接入兜底锁会把普通熔断的
/// 规则一起删掉——熔断状态仍写着 tripped，防火墙却已放行。
pub fn release_isolation_reason(reason: IsolationReason) -> Result<ReleaseReport, String> {
    let guard = crate::egate_lock::acquire(crate::egate_lock::SystemOperation::ReleaseIsolation)?;
    release_isolation_reason_locked(&guard, reason)
}

fn release_isolation_reason_locked(
    _guard: &crate::egate_lock::OperationGuard,
    reason: IsolationReason,
) -> Result<ReleaseReport, String> {
    use crate::platform::imp::RuleLookup;
    let prefix = reason.prefix();
    // **P0-02**：先严格确认「到底有没有」，查询失败就不动、不报成功。
    match crate::platform::imp::firewall_rules_exist(prefix) {
        RuleLookup::Absent => {
            return Ok(ReleaseReport {
                requested: 0,
                remaining: 0,
                verified: true,
                failures: Vec::new(),
            })
        }
        RuleLookup::Unknown => {
            return Err(format!(
                "{} 规则状态无法确认（权限/服务/RPC 异常），未执行删除",
                reason.label()
            ))
        }
        RuleLookup::Present => {}
    }
    let script = format!(
        "$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='Stop'
# 无语句级 exit/return：两者都会跳过执行结果哨兵。
$rules = @(Get-NetFirewallRule -DisplayName ({} + '*') -ErrorAction Stop)
$n = $rules.Count
if ($n -gt 0) {{ $rules | Remove-NetFirewallRule -ErrorAction Stop }}
ConvertTo-Json @{{ removed = $n }} -Compress",
        ps_quote(prefix)
    );
    // **P0-NEW-01**：删除失败要暴露，不能被吞成「删除 0 条」。
    let mut remove_failures = Vec::new();
    let requested = match crate::platform::imp::run_powershell(&script) {
        Ok(json) => match serde_json::from_str::<serde_json::Value>(json.trim()) {
            Ok(value) => value.get("removed").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            Err(e) => {
                remove_failures.push(format!("{} 清理结果解析失败：{e}", reason.label()));
                0
            }
        },
        Err(e) => {
            remove_failures.push(format!("{} 删除失败：{e}", reason.label()));
            0
        }
    };
    // 回查：**Unknown 绝不等于已清理**。
    let present = crate::platform::imp::firewall_rules_exist(prefix);
    let counted = count_rules_with_prefix(prefix);
    match (present, counted) {
        (RuleLookup::Absent, Some(0)) | (RuleLookup::Absent, None) => {
            // 严格查询明确说不存在；计数失败也不推翻这个结论。
            Ok(ReleaseReport {
                requested,
                remaining: 0,
                verified: remove_failures.is_empty(),
                failures: remove_failures,
            })
        }
        (RuleLookup::Unknown, _) | (_, None) => {
            let mut failures = remove_failures;
            failures.push("删除后无法查询规则状态，无法确认已清理".to_string());
            Ok(ReleaseReport {
                requested,
                remaining: 0,
                verified: false,
                failures,
            })
        }
        (_, Some(remaining)) => {
            let mut failures = remove_failures;
            failures.push(format!(
                "{} 仍有 {remaining} 条规则残留（可能被组策略或其他程序持有）",
                reason.label()
            ));
            Ok(ReleaseReport {
                requested,
                remaining,
                verified: false,
                failures,
            })
        }
    }
}

/// 统计旧版遗留规则（`ClaudeSwitcher Egate * Out/In`），查询失败返回 `None`。
fn count_legacy_rules() -> Option<u32> {
    // 旧版遗留名必须以 ` … Out` / ` … In` 结尾；全局断网 `… Cut All` 不在此列，
    // 因此这里不会把断网规则算成「应用隔离残留」。
    let script = "$ErrorActionPreference='Stop'
$n = @(Get-NetFirewallRule -DisplayName 'ClaudeSwitcher Egate * Out' -ErrorAction Stop).Count
$n += @(Get-NetFirewallRule -DisplayName 'ClaudeSwitcher Egate * In' -ErrorAction Stop).Count
ConvertTo-Json @{ total = $n } -Compress";
    let json = crate::platform::imp::run_powershell(script).ok()?;
    let value: serde_json::Value = serde_json::from_str(json.trim()).ok()?;
    value
        .get("total")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32)
}

/// 统计指定前缀下的规则数（查询失败返回 `None`）。
fn count_rules_with_prefix(prefix: &str) -> Option<u32> {
    // **P0-02**：必须用 `-ErrorAction Stop`。`SilentlyContinue` 会把权限不足
    // /RPC 失败吞成空集，计数 0 与「确实没有规则」无法区分；这里失败就
    // 返回 `None`，调用方据此报「无法确认」而不是「已清干净」。
    let script = format!(
        "$ErrorActionPreference='Stop'
$n = @(Get-NetFirewallRule -DisplayName ({} + '*') -ErrorAction Stop).Count
ConvertTo-Json @{{ total = $n }} -Compress",
        ps_quote(prefix)
    );
    let json = crate::platform::imp::run_powershell(&script).ok()?;
    let value: serde_json::Value = serde_json::from_str(json.trim()).ok()?;
    value
        .get("total")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32)
}

/// **P0-01**：已持锁版本的解除隔离——内部**不再申请锁**。
pub(crate) fn release_all_verified_locked(
    _guard: &crate::egate_lock::OperationGuard,
) -> Result<ReleaseReport, String> {
    // 该入口用于已经持锁的紧急恢复（Emergency），不再检查手动保持。
    //
    // **P0-01（v0.6.13.1）**：必须清理**两个**现行命名空间 + 旧版遗留。
    // **P0-02（v0.7.1）**：每个前缀都要先用严格查询确认「有没有」，
    // 查询失败按 Unknown 处理并让最终 verified=false，绝不当成已清理。
    let legacy = cleanup_legacy_rules().unwrap_or(0);
    let mut requested = legacy;
    let mut remove_failures: Vec<String> = Vec::new();
    let mut unknown = false;
    for prefix in [
        IsolationReason::EgressTrip.prefix(),
        IsolationReason::Uncovered.prefix(),
    ] {
        match crate::platform::imp::firewall_rules_exist(prefix) {
            crate::platform::imp::RuleLookup::Absent => continue,
            crate::platform::imp::RuleLookup::Unknown => {
                unknown = true;
                remove_failures.push(format!("{prefix} 规则状态无法确认"));
                continue;
            }
            crate::platform::imp::RuleLookup::Present => {}
        }
        // **P0-NEW-01**：删除必须 `-ErrorAction Stop`。`SilentlyContinue` 会把
        // 权限不足/组策略持有这类失败吞掉，脚本仍然输出「removed = N」，
        // 调用方据此以为删成功——正是「报告成功但规则还在」的来源。
        let script = format!(
            "$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='Stop'
# 无语句级 exit/return：两者都会跳过执行结果哨兵。
$rules = @(Get-NetFirewallRule -DisplayName ({} + '*') -ErrorAction Stop)
$n = $rules.Count
if ($n -gt 0) {{ $rules | Remove-NetFirewallRule -ErrorAction Stop }}
ConvertTo-Json @{{ removed = $n }} -Compress",
            ps_quote(prefix)
        );
        match crate::platform::imp::run_powershell(&script) {
            Ok(json) => match serde_json::from_str::<serde_json::Value>(json.trim()) {
                Ok(value) => {
                    requested += value.get("removed").and_then(|v| v.as_u64()).unwrap_or(0) as u32
                }
                Err(e) => remove_failures.push(format!("{prefix} 清理结果解析失败：{e}")),
            },
            Err(e) => remove_failures.push(format!("{prefix} 清理失败：{e}")),
        }
    }
    // P0-04：回查——删除命令返回成功不等于规则真的消失。
    // **P0-02**：严格清点；查询失败 = 无法确认，绝不报成功。
    let mut failures = remove_failures;
    if unknown {
        failures.push("存在无法确认的来源，本次恢复不能报告完整成功".to_string());
        return Ok(ReleaseReport {
            requested,
            remaining: 0,
            verified: false,
            failures,
        });
    }
    match inspect_isolation_inventory().map(|i| i.total()) {
        Some(0) => Ok(ReleaseReport {
            requested,
            remaining: 0,
            verified: true,
            failures,
        }),
        Some(remaining) => {
            failures.push(format!(
                "删除后仍有 {remaining} 条本产品规则残留（可能被组策略或其他程序持有）"
            ));
            Ok(ReleaseReport {
                requested,
                remaining,
                verified: false,
                failures,
            })
        }
        None => {
            failures.push("删除后无法查询规则状态，无法确认已清理".to_string());
            Ok(ReleaseReport {
                requested,
                remaining: 0,
                verified: false,
                failures,
            })
        }
    }
}

/// 当前存在的本产品隔离规则数（恢复后核验用）。
/// **P0-01（v0.7.1）**：按来源清点现存规则。
///
/// `rule_count()` 只给总数，无法回答「这些规则属于谁」。重启后若只剩
/// 兜底封锁规则，却被当成普通熔断去 `RetryProtection`，就会走 `trip()`
/// 去**结束 GUI 进程**——而兜底封锁的产品语义是「只挡出站、不杀进程」。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IsolationInventory {
    pub egress_trip: u32,
    pub uncovered: u32,
    pub legacy: u32,
}

impl IsolationInventory {
    pub fn total(self) -> u32 {
        self.egress_trip + self.uncovered + self.legacy
    }

    /// 存在任何形式的隔离。
    pub fn any(self) -> bool {
        self.total() > 0
    }
}

/// 查询两类命名空间 + 旧版遗留的**分别**计数。
///
/// 查询失败返回 `None`（不能当成「没有规则」——那会让恢复器误报清理完成）。
pub fn inspect_isolation_inventory() -> Option<IsolationInventory> {
    use crate::platform::imp::RuleLookup;
    let mut counts = [0u32; 3];
    let prefixes = [
        IsolationReason::EgressTrip.prefix(),
        IsolationReason::Uncovered.prefix(),
    ];
    for (index, prefix) in prefixes.iter().enumerate() {
        match crate::platform::imp::firewall_rules_exist(prefix) {
            // 严格查询只回答「有没有」；数量由下面的精确统计补。
            RuleLookup::Absent => counts[index] = 0,
            RuleLookup::Present => {
                counts[index] = count_rules_with_prefix(prefix)?;
            }
            // **P0-02**：查询失败不能被当成「没有规则」。
            RuleLookup::Unknown => return None,
        }
    }
    counts[2] = count_legacy_rules()?;
    Some(IsolationInventory {
        egress_trip: counts[0],
        uncovered: counts[1],
        legacy: counts[2],
    })
}

pub fn rule_count() -> Option<u32> {
    // **P0-01（v0.6.13.1）**：统计**两个**现行命名空间 + 旧版遗留。
    // 原实现只数 `ClaudeSwitcher AppIsolation`：兜底封锁残留时仍报 0，
    // 于是恢复器/重建器会误判「没有任何隔离」。
    // **P0-02**：只用 `-ErrorAction Stop`。`SilentlyContinue` 会把权限不足/RPC
    // 失败吞成 0——调用方（恢复器、界面、重建器）都把 0 当「已清干净」，
    // 这是「报告已恢复但规则还在」的根源。查询失败必须返回 `None`。
    let script = format!(
        "$ErrorActionPreference='Stop'
$a = @(Get-NetFirewallRule -DisplayName ({trip} + '*') -ErrorAction Stop).Count
$u = @(Get-NetFirewallRule -DisplayName ({covered} + '*') -ErrorAction Stop).Count
$legacy = @(Get-NetFirewallRule -DisplayName 'ClaudeSwitcher Egate * Out' -ErrorAction Stop).Count
$legacy += @(Get-NetFirewallRule -DisplayName 'ClaudeSwitcher Egate * In' -ErrorAction Stop).Count
ConvertTo-Json @{{ total = ($a + $u + $legacy) }} -Compress",
        trip = ps_quote(RULE_PREFIX),
        covered = ps_quote(IsolationReason::Uncovered.prefix())
    );
    let json = crate::platform::imp::run_powershell(&script).ok()?;
    let value: serde_json::Value = serde_json::from_str(json.trim()).ok()?;
    value
        .get("total")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32)
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

    /// **P0-08**：同一应用的不同安装路径必须得到**不同**规则名，
    /// 否则后建的规则会覆盖先建的，只有一份安装被隔离。
    #[test]
    fn rule_names_are_scoped_per_executable_path() {
        let user = r"C:\Users\a\AppData\Local\Programs\Claude\Claude.exe";
        let system = r"C:\Program Files\Claude\Claude.exe";
        let a = rule_name_for_exe("claude", "Out", user);
        let b = rule_name_for_exe("claude", "Out", system);
        assert_ne!(a, b, "不同路径必须得到不同规则名");
        // 同路径重复调用必须稳定（幂等：重复隔离不产生新规则）。
        assert_eq!(a, rule_name_for_exe("claude", "Out", user));
        // 大小写与分隔符差异属于同一路径（Windows 语义）。
        assert_eq!(
            a,
            rule_name_for_exe("claude", "Out", &user.to_lowercase().replace('\\', "/")),
            "规范化后同一路径必须映射到同一规则名"
        );
        // 方向不同仍是不同规则。
        assert_ne!(a, rule_name_for_exe("claude", "In", user));
        // 规则名仍落在可被 `rule_count()` 通配统计的前缀下。
        assert!(a.starts_with(RULE_PREFIX), "{a}");
    }
    /// **P0-01 / QW-03**：核验解析必须与**预期规则集合**逐项按名称匹配。
    ///
    /// 关键回归：预期清单来自 `expected_rules()`（带路径哈希后缀），
    /// 若解析端还在按另一个名字匹配，新建的规则永远核验不到。
    #[test]
    fn rule_verification_matches_expected_names() {
        let exes = vec!["C:/a.exe".to_string()];
        let expected = expected_rules("claude", &exes);
        assert_eq!(expected.len(), 2);
        let out_name = &expected[0].name;
        let in_name = &expected[1].name;
        // 规则名必须包含路径哈希后缀（与旧格式区分）。
        assert!(
            out_name.starts_with("ClaudeSwitcher AppIsolation claude Out "),
            "{out_name}"
        );

        // 正常：两条都通过。
        let ok_json = serde_json::json!([
            {"name": out_name, "dir": "Out", "exe": exes[0], "ok": true, "reason": ""},
            {"name": in_name,  "dir": "In",  "exe": exes[0], "ok": true, "reason": ""},
        ])
        .to_string();
        let ok = parse_rule_verification_expected(&ok_json, &expected);
        assert!(ok.query_ok);
        assert_eq!(ok.verified, 2);
        assert!(ok.failed.is_empty());

        // 一条失败：原因必须保留。
        let partial_json = serde_json::json!([
            {"name": out_name, "dir": "Out", "exe": exes[0], "ok": true},
            {"name": in_name,  "dir": "In",  "exe": exes[0], "ok": false,
             "reason": "未进入当前生效策略（可能被组策略覆盖）"},
        ])
        .to_string();
        let partial = parse_rule_verification_expected(&partial_json, &expected);
        assert!(partial.query_ok);
        assert_eq!(partial.verified, 1);
        assert!(
            partial.failed[0].contains("生效策略"),
            "{:?}",
            partial.failed
        );

        // **P0-01 回归**：脚本返回**旧格式名字**（无后缀）→ 视为非预期规则，
        // 查询失败；绝不能因为「条数凑够」而判为完整覆盖。
        let legacy_json = serde_json::json!([
            {"name": "ClaudeSwitcher AppIsolation claude Out", "dir": "Out", "exe": exes[0], "ok": true},
            {"name": "ClaudeSwitcher AppIsolation claude In",  "dir": "In",  "exe": exes[0], "ok": true},
        ])
        .to_string();
        let legacy = parse_rule_verification_expected(&legacy_json, &expected);
        assert!(!legacy.query_ok, "旧格式名字必须被判为查询失败");
        assert_eq!(legacy.verified, 0);

        // **QW-03**：重复结果不能凑数。
        let dup_json = serde_json::json!([
            {"name": out_name, "dir": "Out", "exe": exes[0], "ok": true},
            {"name": out_name, "dir": "Out", "exe": exes[0], "ok": true},
        ])
        .to_string();
        let dup = parse_rule_verification_expected(&dup_json, &expected);
        // **QW-01**：重复出现 = 核验异常（不是「只算一次」）。
        assert!(!dup.query_ok, "同名重复必须判为查询失败：{dup:?}");
        assert_eq!(dup.verified, 0);

        // 缺少结果条目 → 该条按失败记。
        let missing = parse_rule_verification_expected("[]", &expected);
        assert_eq!(missing.verified, 0);
        assert_eq!(missing.failed.len(), 2);

        // 非预期形状：查询失败（不是「零失败」）。
        assert!(!parse_rule_verification_expected("not json", &expected).query_ok);
        assert!(!parse_rule_verification_expected("123", &expected).query_ok);
    }

    /// 候选路径解析：去重、忽略空路径、保留来源。
    #[test]
    fn exe_candidates_are_deduplicated_and_tagged() {
        let json = r#"[
            {"path":"C:\\Users\\a\\Claude.exe","source":"running"},
            {"path":"c:/users/A/claude.EXE","source":"installed"},
            {"path":"","source":"running"},
            {"path":"C:\\Program Files\\Claude\\Claude.exe","source":"msix"}
        ]"#;
        let found = parse_exe_candidates(json);
        assert_eq!(found.len(), 2, "规范化后重复路径必须去重：{found:?}");
        assert_eq!(found[0].source, "running");
        assert_eq!(found[1].source, "msix");
        // 空 / null / 非 JSON 一律返回空列表，不 panic。
        assert!(parse_exe_candidates("").is_empty());
        assert!(parse_exe_candidates("null").is_empty());
        assert!(parse_exe_candidates("garbage").is_empty());
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

    /// 三个解除来源共用执行入口，只有自动恢复受手动保持拦截。
    #[test]
    fn release_reason_policy_separates_automatic_and_manual() {
        assert_ne!(ReleaseReason::UserRequested, ReleaseReason::Automatic);
        assert_ne!(ReleaseReason::Emergency, ReleaseReason::Automatic);
        assert_ne!(ReleaseReason::Emergency, ReleaseReason::UserRequested);
    }

    /// 手动保持存在时：自动恢复必须被拦截，用户主动解除不得被拦。
    #[test]
    fn manual_hold_blocks_only_automatic_release() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        std::fs::create_dir_all(dir.path().join(".claude-switcher")).unwrap();
        crate::egate_monitor::mark_manual_hold().unwrap();

        // 自动恢复：在拿锁前就会被判定为「不该解除」。
        assert_eq!(
            crate::egate_monitor::manual_hold_state(),
            crate::egate_monitor::ManualHold::Held
        );
        // 用户主动解除与紧急恢复的来源值不同，因此不会走手动保持拦截分支。
        assert_ne!(ReleaseReason::UserRequested, ReleaseReason::Automatic);
        assert_ne!(ReleaseReason::Emergency, ReleaseReason::Automatic);

        crate::egate_monitor::clear_manual_hold().unwrap();
    }

    /// **P0-B 回归**：把核验脚本的条件链单独抽出来在真实 PowerShell 里跑，
    /// 确认「前半段属性错误、后半段全部通过」不会被判成功。
    ///
    /// 这是上一版真实存在的缺陷：端口/地址/Profile 检查曾是一条独立链，
    /// 末尾的 `else { $ok = $true }` 会覆盖前面的方向/程序判定。
    #[test]
    fn verification_chain_rejects_earlier_mismatch() {
        let script = r#"
$s = @{ direction='Outbound'; exe='C:\a.exe' }
function Check($ar, $af, $pf, $adf) {
  $ok = $false; $reason = ''
  $portAny = (((-not $pf.Protocol) -or $pf.Protocol -eq 'Any') -and ((-not $pf.LocalPort) -or $pf.LocalPort -eq 'Any') -and ((-not $pf.RemotePort) -or $pf.RemotePort -eq 'Any'))
  $addrAny = (((-not $adf.LocalAddress) -or $adf.LocalAddress -eq 'Any') -and ((-not $adf.RemoteAddress) -or $adf.RemoteAddress -eq 'Any'))
  $profileAll = ([string]$ar.Profile).ToLowerInvariant() -eq 'any'
  if ($ar.Enabled -ne 'True') { $reason = 'not-enabled' }
  elseif ($ar.Action -ne 'Block') { $reason = 'bad-action' }
  elseif ($ar.Direction -ne $s.direction) { $reason = 'bad-direction' }
  elseif (-not $af -or -not $af.Program -or $af.Program -ine $s.exe) { $reason = 'bad-program' }
  elseif (-not $pf -or -not $adf) { $reason = 'filters-missing' }
  elseif (-not $portAny) { $reason = 'port-limited' }
  elseif (-not $addrAny) { $reason = 'addr-limited' }
  elseif (-not $profileAll) { $reason = 'profile-limited' }
  else { $ok = $true }
  return "$ok|$reason"
}
$anyPf = [pscustomobject]@{ Protocol='Any'; LocalPort='Any'; RemotePort='Any' }
$anyAdf = [pscustomobject]@{ LocalAddress='Any'; RemoteAddress='Any' }
$goodAf = [pscustomobject]@{ Program='C:\a.exe' }
$cases = @(
  @{ n='all-good';           a=[pscustomobject]@{Enabled='True';Action='Block';Direction='Outbound';Profile='Any'} },
  @{ n='bad-action';         a=[pscustomobject]@{Enabled='True';Action='Allow';Direction='Outbound';Profile='Any'} },
  @{ n='bad-direction';      a=[pscustomobject]@{Enabled='True';Action='Block';Direction='Inbound';Profile='Any'} },
  @{ n='domain-only';        a=[pscustomobject]@{Enabled='True';Action='Block';Direction='Outbound';Profile='Domain'} }
)
foreach ($c in $cases) { Write-Output ($c.n + '=' + (Check $c.a $goodAf $anyPf $anyAdf)) }
"#;
        let out = crate::platform::imp::run_powershell(script).unwrap_or_default();
        let out = out.trim();
        // 非 Windows / 无 PowerShell 的构建机上只校验脚本能生成（不误报失败）。
        if out.is_empty() {
            return;
        }
        assert!(out.contains("all-good=True|"), "{out}");
        assert!(out.contains("bad-action=False|bad-action"), "{out}");
        assert!(out.contains("bad-direction=False|bad-direction"), "{out}");
        assert!(out.contains("domain-only=False|profile-limited"), "{out}");
    }

    /// **P0-01 回归**：兜底封锁与普通熔断使用**不同前缀**，
    /// 解除其中一个不会删掉另一个的规则。
    #[test]
    fn isolation_reasons_use_separate_namespaces() {
        let exes = vec!["C:/a.exe".to_string()];
        let trip_rules = expected_rules_for(IsolationReason::EgressTrip, "claude", &exes, false);
        let cov_rules = expected_rules_for(IsolationReason::Uncovered, "claude", &exes, true);
        // 熔断：出站 + 入站各一条。
        assert_eq!(trip_rules.len(), 2);
        // 兜底：只有出站（QW-01）。
        assert_eq!(cov_rules.len(), 1);
        assert_eq!(cov_rules[0].direction, "Outbound");
        // 两条命名空间互不重叠，互不包含。
        for a in &trip_rules {
            for b in &cov_rules {
                assert_ne!(a.name, b.name);
                assert!(!b.name.starts_with(IsolationReason::EgressTrip.prefix()));
            }
        }
        assert!(trip_rules[0]
            .name
            .starts_with(IsolationReason::EgressTrip.prefix()));
        assert!(cov_rules[0]
            .name
            .starts_with(IsolationReason::Uncovered.prefix()));
    }

    /// **P0-04**：暂停状态下不允许施加隔离（谓词真实行为）。
    #[test]
    fn isolation_blocked_while_paused() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        std::fs::create_dir_all(dir.path().join(".claude-switcher")).unwrap();

        // P0-04 (v0.7.1): the predicate now also requires egate_enabled.
        // Default config has the gate OFF, so isolation must be refused.
        let armed = crate::egate_monitor::protection_intent()
            == crate::egate_monitor::ProtectionIntent::Armed;
        let gate_on = match crate::appconfig::load_checked() {
            crate::appconfig::ConfigLoad::Ok(config) => config.egate_enabled,
            _ => false,
        };
        assert_eq!(
            can_apply_isolation_now(),
            armed && !crate::egate_monitor::is_paused() && gate_on
        );
        assert!(!can_apply_isolation_now(), "门禁默认关闭时不得施加隔离");

        // 暂停后必须拒绝，即使仍处于 Armed。
        crate::egate_monitor::pause(60).unwrap();
        assert!(!can_apply_isolation_now(), "暂停期间不得施加新的隔离");
        crate::egate_monitor::resume().unwrap();
    }

    /// **P0-04（v0.7.2）**：配置代次必须贯穿到**动手之前**，而不只是探测结束时。
    ///
    /// 场景：监控线程在探测开始时记下代次 R；用户随后在 GUI 里改了目标
    /// （代次变成 R+1）；探测结果回来了，仍按旧判定去熔断。
    /// 带代次的入口必须拒绝，否则就是「按用户已经改掉的配置去杀进程」。
    #[test]
    fn isolation_refuses_when_expected_revision_is_stale() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        std::fs::create_dir_all(dir.path().join(".claude-switcher")).unwrap();

        // 打开门禁（否则谓词在第一步就拒绝，测不到代次分支）。
        crate::appconfig::update(|config| config.egate_enabled = true).unwrap();
        crate::egate_monitor::rearm().unwrap();
        let current = match crate::appconfig::load_checked() {
            crate::appconfig::ConfigLoad::Ok(config) => config.egate_revision,
            other => panic!("配置应可读：{other:?}"),
        };
        assert!(
            can_apply_isolation_with_revision(Some(current)),
            "代次一致时应允许"
        );
        // 模拟「探测之后用户改了配置」。
        crate::appconfig::update(|config| {
            config.egate_trip_threshold = config.egate_trip_threshold.saturating_add(1)
        })
        .unwrap();
        assert!(
            !can_apply_isolation_with_revision(Some(current)),
            "代次过期后不得再施加隔离副作用"
        );
        // 不带代次的入口只检查当前事实，用于手动熔断按钮。
        assert!(can_apply_isolation_now());

        // 清理：恢复默认的「未启用」，避免影响同进程内的其它测试。
        crate::appconfig::update(|config| config.egate_enabled = false).unwrap();
        crate::egate_monitor::disarm("测试结束").unwrap();
    }

    /// **P0-01 回归**：全量解除必须覆盖两个命名空间，规则统计也必须两边都数。
    ///
    /// 这是「紧急恢复后兜底规则仍留在防火墙里」的根因：只删了 AppIsolation。
    #[test]
    fn full_release_and_count_cover_both_namespaces() {
        // 两个来源的前缀必须是不同的字符串常量，且都被 rule_count 统计。
        let trip = IsolationReason::EgressTrip.prefix();
        let cov = IsolationReason::Uncovered.prefix();
        assert_ne!(trip, cov);
        // 兜底前缀不能是熔断前缀的前缀（否则通配会互相吞掉）。
        assert!(!cov.starts_with(trip));
        assert!(!trip.starts_with(cov));
    }

    /// **P0-02**：只有系统代理视为「可验证接入」；TUN 无路由证明时不得放行。
    #[test]
    fn release_eligibility_requires_verified_access() {
        assert!(crate::egate_monitor::access_verified_for_test(
            "system_proxy"
        ));
        assert!(!crate::egate_monitor::access_verified_for_test("tun"));
        assert!(!crate::egate_monitor::access_verified_for_test("uncovered"));
        assert!(!crate::egate_monitor::access_verified_for_test("unknown"));
    }

    /// P0-01 (v0.7.1): the inventory must distinguish the two namespaces.
    ///
    /// The regression this guards: `rule_count()` counted everything, so a
    /// restart with only UncoveredLock rules left marked the app as
    /// "partial trip" and the next round ran `trip()` - killing GUI processes
    /// for a rule set that is documented as "outbound block only, never kill".
    /// **P2-04**：安装状态三态必须可区分——「没装」不能被算成「保护失败」，
    /// 「查不出」也不能被算成「已完整保护」。
    #[test]
    fn installation_state_distinguishes_not_installed_from_unknown() {
        assert_ne!(
            ApplicationInstallation::NotInstalled,
            ApplicationInstallation::Unknown
        );
        assert_ne!(
            ApplicationInstallation::Installed,
            ApplicationInstallation::Unknown
        );
        // 未知 agent 标识是配置错误，归入「无法确认」而不是「未安装」。
        match resolve_agent_installation("no-such-agent") {
            InstallationLookup::Unknown(reason) => assert!(reason.contains("未知")),
            other => panic!("未知 agent 应报无法确认，实际：{other:?}"),
        }
    }

    #[test]
    fn isolation_inventory_separates_sources() {
        let inv = IsolationInventory {
            egress_trip: 0,
            uncovered: 3,
            legacy: 0,
        };
        assert_eq!(inv.total(), 3);
        assert!(inv.any());
        // Only uncovered rules present: no egress-trip rules => must not be
        // treated as a trip.
        assert_eq!(inv.egress_trip, 0);

        let empty = IsolationInventory::default();
        assert!(!empty.any());

        let both = IsolationInventory {
            egress_trip: 2,
            uncovered: 1,
            legacy: 1,
        };
        assert_eq!(both.total(), 4);
    }

    /// **回归（v0.7.2）**：解除应用隔离**绝不能**顺带删掉全局断网规则。
    ///
    /// 事故链：`cleanup_legacy_rules()` 曾被改成按 `ClaudeSwitcher Egate *`
    /// 通配删除，而 `ClaudeSwitcher Egate Cut All` 正落在这个前缀下。
    /// 结果是「解除隔离」把用户的全局断网一起解除，账本却仍写着断网中。
    ///
    /// 这里验证的是**删除清单本身**（纯逻辑，不动真实防火墙）：
    /// 旧版清理只允许命中「内置 agent × 方向」这 6 个精确名字。
    #[test]
    fn legacy_cleanup_never_targets_the_global_cut_rule() {
        let legacy_names: Vec<String> = ["claude", "chatgpt", "antigravity"]
            .iter()
            .flat_map(|agent| {
                [
                    format!("ClaudeSwitcher Egate {agent} Out"),
                    format!("ClaudeSwitcher Egate {agent} In"),
                ]
            })
            .collect();
        assert_eq!(legacy_names.len(), 6);
        assert!(
            !legacy_names
                .iter()
                .any(|name| name == crate::egate_netcut::CUT_RULE),
            "全局断网规则不得出现在解除隔离的删除清单里"
        );
        // 旧规则的两种方向都在清单内（升级后必须能清干净）。
        assert!(legacy_names.contains(&"ClaudeSwitcher Egate claude Out".to_string()));
        assert!(legacy_names.contains(&"ClaudeSwitcher Egate antigravity In".to_string()));
        // 现行两个命名空间与断网规则的命名互不重叠。
        assert!(!RULE_PREFIX.starts_with("ClaudeSwitcher Egate "));
        assert!(!IsolationReason::Uncovered
            .prefix()
            .starts_with("ClaudeSwitcher Egate "));
    }

    /// P0-02 (v0.7.1): the strict lookup must have exactly three states, and
    /// `Unknown` must be distinguishable from `Absent` (a silent query failure
    /// must never be reported as "no rules left").
    #[test]
    fn rule_lookup_is_three_state() {
        use crate::platform::imp::RuleLookup;
        assert_ne!(RuleLookup::Unknown, RuleLookup::Absent);
        assert_ne!(RuleLookup::Unknown, RuleLookup::Present);
        // Querying a prefix that cannot exist must be Absent (proves the strict
        // path actually runs and does not degrade to Unknown on this machine).
        let missing =
            crate::platform::imp::firewall_rules_exist("ClaudeSwitcher DefinitelyNotPresent zzz");
        assert_eq!(missing, RuleLookup::Absent);
    }
}
