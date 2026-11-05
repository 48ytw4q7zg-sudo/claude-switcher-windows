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

/// 规则名：`ClaudeSwitcher AppIsolation <agent> <Out|In>`。
///
/// **兼容用法**：旧版按「每应用一条」建规则，规则名不带路径后缀。
/// 新代码按「每应用 × 每路径」建规则（见 [`rule_name_for_exe`]），
/// 但仍需识别旧规则以便清理，因此保留本函数。
pub fn rule_name(agent: &str, direction: &str) -> String {
    format!("{RULE_PREFIX} {agent} {direction}")
}

/// **P0-08**：按「应用 + 方向 + 具体可执行路径」生成规则名。
///
/// 同一应用可能有多个安装路径（用户级 / 系统级 / MSIX）。若仍用
/// `rule_name()` 的单一名，后建的规则会覆盖前一条，导致只有一份安装被隔离。
///
/// 后缀取路径 SHA256 的前 12 位十六进制：稳定（同一路径永远同一后缀）、
/// 短到能读、且不会因路径里的空格/斜杠污染规则名。
pub fn rule_name_for_exe(agent: &str, direction: &str, exe: &str) -> String {
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
    let Some((_, exe_names)) = agent_spec(agent) else {
        return Vec::new();
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
    let Ok(json) = crate::platform::imp::run_powershell(&script) else {
        return Vec::new();
    };
    parse_exe_candidates(&json)
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

/// 为「应用 × 每个 exe × 每个方向」生成完整的预期规则集合。
///
/// 这是**唯一**的规则标识来源：创建与核验都调用它，不允许任何一方自行拼接。
pub fn expected_rules(agent: &str, exes: &[String]) -> Vec<ExpectedRule> {
    let mut out = Vec::with_capacity(exes.len() * 2);
    for exe in exes {
        out.push(ExpectedRule {
            name: rule_name_for_exe(agent, "Out", exe),
            dir: "Out".to_string(),
            direction: "Outbound",
            exe: exe.clone(),
        });
        out.push(ExpectedRule {
            name: rule_name_for_exe(agent, "In", exe),
            dir: "In".to_string(),
            direction: "Inbound",
            exe: exe.clone(),
        });
    }
    out
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
fn count_rules_for(agent: &str, exes: &[String]) -> RuleVerification {
    let expected_rules = expected_rules(agent, exes);
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
                   $ar = $active | Select-Object -First 1\n\
                   $af = $ar | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
                   if ($ar.Enabled -ne 'True' -or $ar.Action -ne 'Block') {{ $reason = '生效策略中的规则属性不符' }}
                   elseif ($ar.Direction -ne $s.direction -or -not $af.Program -or $af.Program -ine $s.exe) {{ $reason = '生效策略的方向或程序过滤条件不符' }}
                   # **P0-05**：端口/地址过滤器若被限定，就不再覆盖该程序的全部出站流量。
                   $pf = $ar | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                   $adf = $ar | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                   $portAny = (-not $pf) -or (
                     (((-not $pf.Protocol) -or $pf.Protocol -eq 'Any') -and
                      ((-not $pf.LocalPort) -or $pf.LocalPort -eq 'Any') -and
                      ((-not $pf.RemotePort) -or $pf.RemotePort -eq 'Any'))
                   )
                   $addrAny = (-not $adf) -or (
                     (((-not $adf.LocalAddress) -or $adf.LocalAddress -eq 'Any') -and
                      ((-not $adf.RemoteAddress) -or $adf.RemoteAddress -eq 'Any'))
                   )
                   $profileAll = ([string]$ar.Profile).ToLowerInvariant() -eq 'any'
                   if (-not $portAny) {{ $reason = '生效策略限定了端口范围，未覆盖全部流量' }}
                   elseif (-not $addrAny) {{ $reason = '生效策略限定了地址范围，未覆盖全部流量' }}
                   elseif (-not $profileAll) {{ $reason = '生效策略只对部分网络配置档生效' }}
                   else {{ $ok = $true }}\n\
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

    // 1. **先解析路径**：必须在进程还活着时取（结束后 Get-Process 拿不到）。
    let exes: Vec<String> = match exe_path {
        Some(explicit) => vec![explicit.to_string()],
        None => resolve_agent_exe_candidates(agent)
            .into_iter()
            .map(|candidate| candidate.path)
            .collect(),
    };
    if exes.is_empty() {
        // 没有路径：仍然结束进程（至少阻止当前实例），但必须说明隔离未完成。
        match kill_agent_processes(agent) {
            Ok(killed) => report.killed = killed,
            Err(error) => report.note.push_str(&format!("结束进程失败（{error}）；")),
        }
        report.note.push_str(
            "未找到可执行文件路径（应用可能未安装或从未运行），无法建立防火墙隔离；保护未完成",
        );
        return report;
    }

    // 2. 再结束进程（失败不阻断后续隔离：进程可能已退出）。
    match kill_agent_processes(agent) {
        Ok(killed) => report.killed = killed,
        Err(error) => report.note.push_str(&format!("结束进程失败（{error}）；")),
    }

    // 3. 为**每个路径**建立出/入站阻断规则。
    //
    // 规则名带上路径的稳定哈希后缀：同一应用多路径共存时，每条规则对应一个
    // 具体程序，既不会互相覆盖，也能在升级后按旧路径精确清理。
    // **P0-01**：规则名来自 [`expected_rules`]——与核验使用的是**同一份**清单。
    // 任何一方自行拼接名称都会让新建的规则永远核验不到。
    for rule in expected_rules(agent, &exes) {
        let script = format!(
            "$ErrorActionPreference='Stop'\n\
             $existing = Get-NetFirewallRule -DisplayName {} -ErrorAction SilentlyContinue\n\
             if (-not $existing) {{\n\
               New-NetFirewallRule -DisplayName {} -Direction {} -Action Block -Program {} -Enabled True | Out-Null\n\
             }}",
            ps_quote(&rule.name),
            ps_quote(&rule.name),
            rule.direction,
            ps_quote(&rule.exe)
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
    let mut verification = count_rules_for(agent, &exes);
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
/// 执行一次熔断：对配置里所有守护对象结束进程并隔离。
///
/// 与上游一致：**只处理 GUI 应用**；CLI 宿主不在守护列表里，避免误伤终端。
pub fn trip(guarded_agents: &[String]) -> TripReport {
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
    if crate::egate_monitor::protection_intent() != crate::egate_monitor::ProtectionIntent::Armed
        || crate::egate_monitor::is_paused()
    {
        return TripReport {
            agents: Vec::new(),
            any_isolated: false,
            all_isolated: false,
            failures: Vec::new(),
            note: "保护已暂停或已停止（用户意图在操作期间改变），未执行熔断".to_string(),
        };
    }
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

/// **P0-C**：清理旧版应用隔离规则（升级兼容）。
///
/// 旧版本用 `ClaudeSwitcher Egate {agent} Out/In`，新版改为 `AppIsolation`。
/// 升级后旧规则可能残留，导致「已解除隔离」但应用仍无法联网。
///
/// **安全边界**：旧命名空间也可能包含全局断网规则（`... Cut All`），
/// 因此只删除**匹配旧应用隔离格式**的规则（名字里含具体 agent 名），
/// 绝不按 `ClaudeSwitcher Egate*` 通配删除。
pub fn cleanup_legacy_rules() -> Result<u32, String> {
    // 明确列出旧版应用隔离的规则名（只含内置 agent），不碰 Cut All。
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
        "$ErrorActionPreference='SilentlyContinue'
         $removed = 0
         foreach ($n in @({list})) {{
           $r = Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue
           if ($r) {{ $r | Remove-NetFirewallRule -ErrorAction SilentlyContinue; $removed++ }}
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
        "$ErrorActionPreference='SilentlyContinue'
         $rules = @(Get-NetFirewallRule -DisplayName {}* )
         $removed = 0
         foreach ($r in $rules) {{
           $f = $r | Get-NetFirewallApplicationFilter
           $p = $f.Program
           # 只有明确设置了程序路径、且该路径确实不存在的规则才算失效。
           # `Any` / 空 / 通配（全局阻断规则）绝不在这里处理。
           if (-not $p) {{ continue }}
           if ($p -eq 'Any') {{ continue }}
           if ($p -like '*\\*') {{
             if (-not (Test-Path -LiteralPath $p)) {{
               $r | Remove-NetFirewallRule -ErrorAction SilentlyContinue
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

/// **P0-01**：已持锁版本的解除隔离——内部**不再申请锁**。
pub(crate) fn release_all_verified_locked(
    _guard: &crate::egate_lock::OperationGuard,
) -> Result<ReleaseReport, String> {
    // 该入口用于已经持锁的紧急恢复（Emergency），不再检查手动保持。
    // P0-C：先尝试清理旧版残留（升级兼容），失败不阻断主流程。
    let legacy = cleanup_legacy_rules().unwrap_or(0);
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
    let requested = value.get("removed").and_then(|v| v.as_u64()).unwrap_or(0) as u32 + legacy;

    // P0-04：回查——删除命令返回成功不等于规则真的消失。
    let mut failures = Vec::new();
    match rule_count() {
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
pub fn rule_count() -> Option<u32> {
    // 同时统计新版前缀与旧版应用隔离（不含 Cut All，避免把断网规则算进来）。
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'
         $new = @(Get-NetFirewallRule -DisplayName {}* -ErrorAction SilentlyContinue).Count
         $legacy = @(Get-NetFirewallRule -DisplayName 'ClaudeSwitcher Egate * Out' -ErrorAction SilentlyContinue).Count
         $legacy += @(Get-NetFirewallRule -DisplayName 'ClaudeSwitcher Egate * In' -ErrorAction SilentlyContinue).Count
         ConvertTo-Json @{{ total = ($new + $legacy) }} -Compress",
        ps_quote(RULE_PREFIX)
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
        let exes = vec![r"C:.exe".to_string()];
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
}
