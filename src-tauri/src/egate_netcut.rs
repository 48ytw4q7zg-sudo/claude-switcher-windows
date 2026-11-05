//! 断网执行与自愈账本（融合 ClaudeGuard `src/netcut.rs`）。
//!
//! 两档：
//! - `firewall`：加一条全局出站阻断规则（`ClaudeSwitcher Egate Cut All`）；
//! - `nics`：先加同一条规则，再禁用物理网卡——**规则是最后一道闸**，恢复网卡
//!   的过程中网络仍被挡着，避免出现「断网真空」。
//!
//! 现场落盘（`appconfig` 同目录的 `netcut.json`），进程崩溃/被杀后下次启动
//! 由 [`heal`] 恢复。这是 fail-closed 设计：宁可多恢复一次，也不能让用户
//! 在以为「已断网」的状态下留着一个没人接管的断网现场。
//!
//! 安全边界：断网是**最高强度的熔断动作**，默认关闭；只有用户显式选择档位
//! 且确认后才会执行。恢复不依赖内存状态，只依赖账本与规则名。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::fsx;

/// 断网防火墙规则名（自愈与恢复都按它找规则）。
pub const CUT_RULE: &str = "ClaudeSwitcher Egate Cut All";

/// 断网档位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CutMode {
    /// 不断网（默认；只做应用级隔离）。
    #[default]
    Off,
    /// 防火墙全局出站阻断。
    Firewall,
    /// 防火墙全局阻断 + 禁用物理网卡。
    Nics,
}

impl CutMode {
    /// 界面用的中文名。
    pub fn label(self) -> &'static str {
        match self {
            CutMode::Off => "不断网",
            CutMode::Firewall => "防火墙全局阻断",
            CutMode::Nics => "禁用物理网卡",
        }
    }

    /// 配置字符串 → 档位（未知值按 Off 处理，不误断网）。
    pub fn parse(raw: &str) -> CutMode {
        match raw.trim().to_ascii_lowercase().as_str() {
            "firewall" => CutMode::Firewall,
            "nics" => CutMode::Nics,
            _ => CutMode::Off,
        }
    }
}

/// 断网事务阶段。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CutPhase {
    /// 已记录意图，尚未执行任何系统修改。
    #[default]
    Prepared,
    /// 防火墙规则已添加。
    FirewallApplied,
    /// 网卡已禁用（仅 Nics 档）。
    NicsApplied,
    /// 全部完成并核验通过。
    Applied,
}

/// **P0-04**：网卡快照（保存稳定身份与原始管理状态）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterSnapshot {
    /// 显示名称（仅展示/旧账本兼容）。
    pub name: String,
    /// 稳定接口标识（InterfaceGuid；旧账本为空）。
    #[serde(default)]
    pub guid: String,
    /// 事务开始时的管理启用状态（AdminStatus）。
    #[serde(default)]
    pub admin_up: bool,
}

/// 断网现场（落盘，供崩溃后自愈）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutState {
    /// "firewall" | "nics"
    pub mode: String,
    /// 防火墙全局阻断规则是否已加上。
    pub firewall: bool,
    /// **P0-03**：计划禁用的**全部**网卡（写入后永不缩减）。
    /// 恢复器必须以此为准——「执行成功但进度没写」时它仍知道要恢复什么。
    #[serde(default)]
    pub planned_adapters: Vec<String>,
    /// 已确认禁用的网卡（进度记录，仅用于诊断与增量核验）。
    #[serde(default)]
    pub completed_adapters: Vec<String>,
    /// **P0-04**：网卡原始快照（含稳定身份与原始管理状态）。
    #[serde(default)]
    pub adapter_snapshots: Vec<AdapterSnapshot>,
    /// 旧版兼容字段（= planned_adapters 的别名，读取时回退）。
    #[serde(default)]
    pub nics: Vec<String>,
    /// 断网开始时间（unix 秒）。
    pub since: u64,
    /// 事务阶段（用于崩溃恢复时判断做到哪一步）。
    #[serde(default)]
    pub phase: CutPhase,
}

impl CutState {
    /// 需要恢复的全部网卡（优先新字段，回退旧字段）。
    pub fn adapters_to_restore(&self) -> &[String] {
        if !self.planned_adapters.is_empty() {
            &self.planned_adapters
        } else {
            &self.nics
        }
    }
}

fn state_path() -> Result<PathBuf, String> {
    Ok(crate::paths::app_data_dir()?.join("netcut.json"))
}

/// 读账本；不存在返回 None。
pub fn load_state() -> Result<Option<CutState>, String> {
    let path = state_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("读取断网现场失败：{e}"))?;
    let text = crate::jsonio::decode_text(text.as_bytes());
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| format!("断网现场格式无效：{e}"))
}

fn save_state(state: &CutState) -> Result<(), String> {
    let path = state_path()?;
    let text =
        serde_json::to_string_pretty(state).map_err(|e| format!("序列化断网现场失败：{e}"))?;
    fsx::write_atomically(&path, &text).map_err(|e| format!("写入断网现场失败：{e}"))
}

fn clear_state() -> Result<(), String> {
    let path = state_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("删除断网现场失败：{error}")),
    }
}

/// 当前时间（unix 秒）。
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 执行断网。返回 `(是否成功, 说明)`；Off 档是 no-op。
pub fn cut(mode: CutMode) -> (bool, String) {
    if mode == CutMode::Off {
        return (true, "档位为「不断网」，未执行断网".to_string());
    }
    // **P0-I**：能力门控必须在**修改任何系统状态之前**。
    // 注意：这里只拦「新增断网事务」，不影响对已有 netcut.json 的恢复——
    // 恢复路径不经过本函数的这个分支。
    if let CutCapability::Unavailable(reason) = global_cut_capability(mode) {
        return (false, format!("该断网档位当前不可用：{reason}"));
    }
    // **P0-02**：断网必须独占系统操作权。
    let guard = match crate::egate_lock::acquire(crate::egate_lock::SystemOperation::NetworkCut) {
        Ok(guard) => guard,
        Err(error) => return (false, format!("无法获取系统操作锁：{error}")),
    };
    // 已有现场：先严格检查账本状态。
    match load_state() {
        Ok(Some(_)) => {
            // 有效的未完成事务：先恢复（已持锁，走无锁版本）。
            let (ok, note) = restore_locked(&guard);
            if !ok {
                return (
                    false,
                    format!("上次断网现场恢复失败（{note}），已拒绝再次断网"),
                );
            }
        }
        Ok(None) => {}
        Err(error) => {
            // 账本损坏或无法读取：拒绝操作，避免叠加现场。
            return (
                false,
                format!("断网账本损坏或无法读取（{error}），已拒绝操作；请先手动清理 netcut.json"),
            );
        }
    }

    // **P0-04：先写 Prepared 账本，再执行系统修改。**
    let prepared = CutState {
        mode: if mode == CutMode::Nics {
            "nics"
        } else {
            "firewall"
        }
        .to_string(),
        firewall: false,
        planned_adapters: Vec::new(),
        completed_adapters: Vec::new(),
        adapter_snapshots: Vec::new(),
        nics: Vec::new(),
        since: now_secs(),
        phase: CutPhase::Prepared,
    };
    if let Err(error) = save_state(&prepared) {
        return (false, format!("写入断网意图失败，未做任何修改：{error}"));
    }

    // 步骤 2：添加防火墙规则。
    if let Err(error) = ensure_firewall_cut_rule() {
        // 规则添加失败：账本保留 Prepared 状态，restore 时不会破坏任何东西。
        return (false, format!("加全局阻断规则失败：{error}"));
    }
    let after_firewall = CutState {
        firewall: true,
        planned_adapters: Vec::new(),
        completed_adapters: Vec::new(),
        adapter_snapshots: Vec::new(),
        nics: Vec::new(),
        phase: CutPhase::FirewallApplied,
        ..prepared
    };
    if let Err(error) = save_state(&after_firewall) {
        // 账本更新失败：规则已加上但账本显示 Prepared。恢复时会尝试删规则（无害）。
        return (false, format!("防火墙已加但账本更新失败：{error}"));
    }

    // 步骤 3：禁用网卡（仅 Nics 档）。
    //
    // P0-A：**先枚举目标并写账本，再逐块禁用**。每禁一块都更新账本，
    // 这样中途崩溃时，恢复器知道哪些网卡已经被本事务禁用。
    let final_state = if mode == CutMode::Nics {
        // **P0-02**：保留完整快照（guid + 原始管理状态），不要只留名字。
        let snapshots = match list_up_physical_nics() {
            Ok(snapshots) => snapshots,
            Err(error) => {
                let _ = save_state(&after_firewall);
                return (
                    false,
                    format!("枚举网卡失败（已降级为防火墙阻断）：{error}"),
                );
            }
        };
        let targets: Vec<String> = snapshots.iter().map(|s| s.name.clone()).collect();
        // 先把「计划禁用的全部网卡」连同完整快照写入账本。
        let planned = CutState {
            mode: "nics".to_string(),
            planned_adapters: targets.clone(),
            completed_adapters: Vec::new(),
            adapter_snapshots: snapshots.clone(),
            phase: CutPhase::FirewallApplied,
            ..after_firewall.clone()
        };
        if let Err(error) = save_state(&planned) {
            return (
                false,
                format!("写入网卡计划失败，已停止（未禁用任何网卡）：{error}"),
            );
        }

        // 逐块禁用，每块后更新账本。
        let mut disabled: Vec<String> = Vec::new();
        for name in &targets {
            match disable_one_nic(name) {
                Ok(()) => {
                    disabled.push(name.clone());
                    let progress = CutState {
                        mode: "nics".to_string(),
                        planned_adapters: targets.clone(),
                        completed_adapters: disabled.clone(),
                        adapter_snapshots: snapshots.clone(),
                        phase: CutPhase::NicsApplied,
                        ..after_firewall.clone()
                    };
                    if let Err(error) = save_state(&progress) {
                        // 账本更新失败：停止继续禁用，保留已写内容。
                        return (
                            false,
                            format!(
                                "已禁用 {} 块网卡但账本更新失败，已停止：{error}",
                                disabled.len()
                            ),
                        );
                    }
                }
                Err(error) => {
                    // 单块失败：停止继续，如实报告已禁用范围。
                    let partial = CutState {
                        mode: "nics".to_string(),
                        planned_adapters: targets.clone(),
                        completed_adapters: disabled.clone(),
                        adapter_snapshots: snapshots.clone(),
                        phase: CutPhase::NicsApplied,
                        ..after_firewall.clone()
                    };
                    let _ = save_state(&partial);
                    return (
                        false,
                        format!(
                            "网卡「{name}」禁用失败（已禁用 {} 块，账本已记录，可恢复）：{error}",
                            disabled.len()
                        ),
                    );
                }
            }
        }
        CutState {
            mode: "nics".to_string(),
            planned_adapters: targets.clone(),
            completed_adapters: disabled,
            adapter_snapshots: snapshots.clone(),
            phase: CutPhase::Applied,
            ..after_firewall.clone()
        }
    } else {
        CutState {
            phase: CutPhase::Applied,
            ..after_firewall.clone()
        }
    };

    // 步骤 4：标记 Applied。
    if let Err(error) = save_state(&final_state) {
        return (
            false,
            format!("断网已执行但账本更新失败（重启后可能无法自愈）：{error}"),
        );
    }
    (true, format!("已断网（{}）", mode.label()))
}

/// 恢复网络：删规则 + 重新启用记录在案的网卡 + 删现场。
/// 恢复网络：删规则 + 重新启用记录在案的网卡 + 删现场。
///
/// **逐项核验**：每一步执行后都查询实际状态，只有确认恢复完成才清理账本。
/// 任何一项失败都保留账本，允许重复恢复。
pub fn restore() -> (bool, String) {
    // 公开入口：自己持锁一次。
    let guard = match crate::egate_lock::acquire(crate::egate_lock::SystemOperation::RestoreNetwork)
    {
        Ok(guard) => guard,
        Err(error) => return (false, format!("无法获取系统操作锁：{error}")),
    };
    restore_locked(&guard)
}

/// **P0-01**：已持锁版本的网络恢复——内部**不再申请锁**，避免自我死锁。
pub(crate) fn restore_locked(_guard: &crate::egate_lock::OperationGuard) -> (bool, String) {
    let state = match load_state() {
        Ok(state) => state,
        Err(error) => return (false, format!("读取断网现场失败，未做任何恢复：{error}")),
    };
    let mut failures = Vec::new();
    // **L-13 / P1-11（v0.7.5）**：用结构化状态做安全决策，不靠文本匹配。
    //
    // 原来写的是 `failures.iter().any(|f| f.contains("网卡"))`——凡是措辞改一个字，
    // 或将来新增别的错误分支，行为就悄悄变了。文本只用来给人看。
    let mut nic_restore_ok = true;

    // 顺序：先恢复网卡、最后删规则——恢复过程中网络始终被规则挡着。
    if let Some(state) = &state {
        // **P0-06**：优先按 `adapter_snapshots` 里的 **GUID** 恢复。
        //
        // - 只恢复「本次事务确实禁用过」且「原始管理状态为 Up」的设备；
        // - GUID 找不到时保留账本并报出具体设备，不拿同名设备顶替；
        // - 只有**旧账本**（没有 GUID）才回退到名称路径。
        let snapshots: Vec<AdapterSnapshot> = state
            .adapter_snapshots
            .iter()
            .filter(|snap| !snap.guid.trim().is_empty() && snap.admin_up)
            .cloned()
            .collect();
        let (restored_guids, guid_failures) = enable_nics_by_guid(&snapshots);
        if !guid_failures.is_empty() {
            nic_restore_ok = false;
        }
        failures.extend(guid_failures);
        let _ = restored_guids;

        // 兼容路径：旧账本只有名称，或计划里有快照没覆盖到的名称。
        let legacy_names: Vec<String> = state
            .adapters_to_restore()
            .iter()
            .filter(|name| {
                !state
                    .adapter_snapshots
                    .iter()
                    .any(|snap| &snap.name == *name && !snap.guid.trim().is_empty())
            })
            .cloned()
            .collect();
        if !legacy_names.is_empty() {
            if let Err(error) = enable_nics(&legacy_names) {
                nic_restore_ok = false;
                failures.push(format!("按名称启用网卡失败（旧账本兼容路径）：{error}"));
            } else {
                match verify_nics_up(&legacy_names) {
                    Ok(gone) if !gone.is_empty() => {
                        nic_restore_ok = false;
                        failures.push(format!("网卡未能恢复（可能驱动延迟）：{}", gone.join("、")));
                    }
                    Ok(_) => {}
                    Err(error) => {
                        nic_restore_ok = false;
                        failures.push(format!("网卡状态核验失败：{error}"));
                    }
                }
            }
        }
    }

    // **P0-05**：网卡恢复失败时**不解除全局阻断**——保留规则作为最后一道
    // 保护，进入待恢复状态；下次恢复会重试。
    //
    // **L-13 / P1-11**：判据是结构化标志 `nic_restore_ok`，
    // 不再用「错误文本里有没有「网卡」两个字」来决定要不要保留阻断规则。
    if !nic_restore_ok {
        // 保留账本与阻断规则，明确报告未完成。
        return (
            false,
            format!(
                "网卡恢复未完成，已保留全局阻断规则（防止断网真空）；{}",
                failures.join("；")
            ),
        );
    }

    // 删除阻断规则并核验。
    if let Err(error) = remove_cut_rule() {
        failures.push(format!("删除阻断规则失败：{error}"));
    } else {
        // 回查：确认规则确实已删除。
        match rule_exists(CUT_RULE) {
            Ok(true) => failures.push("阻断规则仍然存在（删除未生效）".to_string()),
            Ok(false) => {}
            Err(error) => failures.push(format!("规则删除核验失败：{error}")),
        }
    }

    if failures.is_empty() {
        if let Err(error) = clear_state() {
            return (false, format!("网络已恢复但清理现场失败：{error}"));
        }
        return (true, "已恢复网络（网卡与规则均已核验）".to_string());
    }
    // 保留账本，允许重复恢复。
    (false, failures.join("；"))
}

/// 查询指定网卡是否处于 Up 状态；返回仍处于 Down 的网卡名。
fn verify_nics_up(nics: &[String]) -> Result<Vec<String>, String> {
    // **P0-04**：按**原始管理启用状态**核验，不再要求 Status=Up——
    // 未插网线的正常网卡会显示 Disconnected，不应被误判为恢复失败。
    let list = nics
        .iter()
        .map(|n| ps_quote(n))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'
         $down = @()
         foreach ($n in @({list})) {{
           $a = Get-NetAdapter -Name $n -ErrorAction SilentlyContinue
           if (-not $a) {{ $down += $n; continue }}
           if ($a.AdminStatus -ne 'Up') {{ $down += $n }}
         }}
         ConvertTo-Json @($down) -Compress"
    );
    let json = crate::platform::imp::run_powershell(&script)
        .map_err(|e| format!("查询网卡状态失败：{e}"))?;
    let value: serde_json::Value =
        serde_json::from_str(json.trim()).map_err(|e| format!("网卡状态解析失败：{e}"))?;
    // **P0-04**：无法识别的输出类型必须报错，不能当成「没有失败项」。
    match value {
        serde_json::Value::Array(items) => Ok(items
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()),
        serde_json::Value::String(one) if !one.is_empty() => Ok(vec![one]),
        serde_json::Value::Null => Ok(Vec::new()),
        other => Err(format!("网卡状态输出格式异常：{other}")),
    }
}

/// 查询某条防火墙规则是否存在（**P0-02**：三态，不用 `SilentlyContinue`）。
///
/// 精确 `-DisplayName` 查询在「没有匹配」时会抛异常，而且异常消息随系统
/// 语言本地化——用字符串匹配区分「不存在」与「查询失败」不可靠。
/// 因此这里用「转义后的前缀通配 + 精确名过滤」：通配查询无匹配不抛错，
/// 那么**任何异常都只能是真的查询失败**。
fn rule_lookup(name: &str) -> crate::platform::imp::RuleLookup {
    use crate::platform::imp::RuleLookup;
    let script = format!(
        "$ErrorActionPreference='Stop'
$name = {name}
$pattern = [WildcardPattern]::Escape($name)
$rules = @(Get-NetFirewallRule -DisplayName ($pattern + '*') -ErrorAction Stop |
           Where-Object {{ $_.DisplayName -eq $name }})
if ($rules.Count -gt 0) {{ 'present' }} else {{ 'absent' }}",
        name = ps_quote(name)
    );
    match crate::platform::imp::run_powershell(&script) {
        Ok(out) => match out.trim().to_ascii_lowercase().as_str() {
            "present" => RuleLookup::Present,
            "absent" => RuleLookup::Absent,
            _ => RuleLookup::Unknown,
        },
        Err(_) => RuleLookup::Unknown,
    }
}

/// 旧签名（`Result<bool, String>`）的薄包装：查询未知按错误处理。
///
/// 调用点必须想清楚「未知」怎么处理；新代码直接用 [`rule_lookup`]。
fn rule_exists(name: &str) -> Result<bool, String> {
    match rule_lookup(name) {
        crate::platform::imp::RuleLookup::Present => Ok(true),
        crate::platform::imp::RuleLookup::Absent => Ok(false),
        crate::platform::imp::RuleLookup::Unknown => {
            Err("规则状态无法确认（权限/服务/RPC 异常）".to_string())
        }
    }
}

/// **P0-I**：全局断网能力门控。
///
/// ClaudeGuard v3.10 契约要求：没有独立于主程序的恢复执行器并自检通过之前，
/// 不应新增高风险的全局断网动作。`nics` 档位会**禁用物理网卡**，一旦主程序
/// 无法启动或崩溃，用户会失去网络且没有可靠的自助恢复手段。
///
/// 当前实现只有「启动自愈」与 `--egate-restore`（都需要主程序跑起来），
/// 因此按契约把 `nics` 标为不可用；`firewall` 档位不受影响。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CutCapability {
    /// 可用。
    Ready,
    /// 暂不可用（附原因）。
    Unavailable(String),
}

/// 查询某个断网档位当前是否允许执行。
pub fn global_cut_capability(mode: CutMode) -> CutCapability {
    match mode {
        CutMode::Nics => CutCapability::Unavailable(
            "禁用物理网卡后无法由本工具自身恢复网络，当前缺少独立于主程序的恢复执行器。             请改用「防火墙全局阻断」档位；已存在的断网账本仍可正常恢复"
                .to_string(),
        ),
        _ => CutCapability::Ready,
    }
}

/// 启动自愈：若存在断网现场就恢复（进程崩溃/被杀后由下次启动调用）。
pub fn heal() -> Vec<String> {
    match load_state() {
        Ok(None) => Vec::new(),
        Ok(Some(state)) => {
            let (ok, note) = restore();
            let when = state.since;
            if ok {
                vec![format!(
                    "检测到上次熔断残留的断网现场（始于 {when}），已恢复网络"
                )]
            } else {
                vec![format!("断网现场自愈失败：{note}")]
            }
        }
        Err(error) => vec![format!("断网现场无法解析，未自动恢复：{error}")],
    }
}

/// 加全局出站阻断规则（**属性核验 + 回查**）。
///
/// 只按名字查「存在」是不够的：同名规则可能被禁用、方向或动作不符。
/// 发现错误属性时删除重建，创建后回读确认。
fn ensure_firewall_cut_rule() -> Result<(), String> {
    match query_cut_rule()? {
        RuleState::Present => return Ok(()),
        RuleState::WrongAttributes => {
            // 同名但属性错误：只处理本产品规则名，删除后重建。
            remove_cut_rule()?;
        }
        RuleState::Absent => {}
        // **P0-07**：无法确认时**不重建也不宣称成功**。
        // 盲目重建可能在组策略覆盖下反复失败，甚至与用户安全策略冲突。
        RuleState::Unknown => {
            return Err(
                "阻断规则状态无法确认（不在当前生效策略内、防火墙配置关闭或查询失败）；\
                 为避免误报「已断网」，本次断网视为未完成"
                    .to_string(),
            )
        }
    }
    let script = format!(
        "$ErrorActionPreference='Stop'\n\
         New-NetFirewallRule -DisplayName {} -Direction Outbound -Action Block -Enabled True | Out-Null",
        ps_quote(CUT_RULE)
    );
    crate::platform::imp::run_powershell(&script).map(|_| ())?;
    match query_cut_rule()? {
        RuleState::Present => Ok(()),
        other => Err(format!("阻断规则创建后核验失败：{other:?}")),
    }
}

/// 规则核验三态：存在且正确 / 不存在 / 存在但属性不符。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleState {
    /// 规则存在、属性正确，且在当前生效策略下确实阻断。
    Present,
    /// 明确不存在。
    Absent,
    /// 存在但属性不符（可安全删除重建）。
    WrongAttributes,
    /// **P0-07**：无法确认（不在 ActiveStore / 防火墙配置关闭 / 查询失败）。
    /// 这种情况**不得**报告成功，也**不得**盲目删除规则。
    Unknown,
}

/// 查询规则并**核验属性**（严格解析，任何非预期输出都报错）。
fn query_cut_rule() -> Result<RuleState, String> {
    // **P0-07 / P0-C / P0-D**：三件事必须同时成立才算「规则真的在阻断」。
    //
    // P0-C（实测确认）：`Get-NetFirewallRule -ErrorAction Stop` 在**没有匹配对象**
    // 时不会返回空数组，而是**抛异常**（「找不到任何 DisplayName 属性等于 … 的
    // MSFT_NetFirewallRule 对象」）。原实现把异常一律吞成 `unknown`，导致
    // **首次断网**被误判为「状态未知」而拒绝创建规则。必须先用
    // `-ErrorAction SilentlyContinue` 枚举来区分「真的没有」与「查询失败」。
    //
    // P0-D：`$anyOn` 只要有一档配置文件开启就算通过，而当前活动的网络连接
    // 可能属于**关闭的那一档**。改为按当前活动连接的网络类别逐项核对。
    // **P0-NEW-01**：外层 `$ErrorActionPreference='Stop'` 只约束**终止错误**的
    // 呈现；`-ErrorAction SilentlyContinue` 会把它逐条压回去，于是
    // 「权限被拒 / RPC 失败 / 服务停止」全都表现为「0 条规则」= absent。
    // 这里改成「前缀通配 + 精确过滤」：通配查询无匹配不抛错，任何异常都只
    // 可能是真的查询失败，落到 catch 分支的 `unknown`。
    let script = format!(
        r#"$ErrorActionPreference='Stop'
$name = {name}
$pattern = [WildcardPattern]::Escape($name)
$result = 'unknown'
try {{
  $rules = @(Get-NetFirewallRule -DisplayName ($pattern + '*') -PolicyStore PersistentStore -ErrorAction Stop |
             Where-Object {{ $_.DisplayName -eq $name }})
  if ($rules.Count -eq 0) {{
    $result = 'absent'
  }} else {{
    $attrsOk = $true
    foreach ($r in $rules) {{
      if ($r.Enabled -ne 'True' -or $r.Direction -ne 'Outbound' -or $r.Action -ne 'Block') {{ $attrsOk = $false }}
    }}
    if (-not $attrsOk) {{
      $result = 'wrong'
    }} else {{
      # 生效策略查询本身失败 = 无法确认，不能让下面的 foreach 静默跳过。
      $active = @(Get-NetFirewallRule -DisplayName ($pattern + '*') -PolicyStore ActiveStore -ErrorAction Stop |
                  Where-Object {{ $_.DisplayName -eq $name }})
      $activeOk = $false
      foreach ($a in $active) {{
        if ($a.Enabled -ne 'True' -or $a.Action -ne 'Block' -or $a.Direction -ne 'Outbound') {{ continue }}
        $af = $a | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
        $pf = $a | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        $adf = $a | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
        if (-not $af -or -not $pf -or -not $adf) {{ continue }}
        $progAny = (-not $af.Program) -or $af.Program -eq 'Any'
        $portAny = (((-not $pf.Protocol) -or $pf.Protocol -eq 'Any') -and
                    ((-not $pf.LocalPort) -or $pf.LocalPort -eq 'Any') -and
                    ((-not $pf.RemotePort) -or $pf.RemotePort -eq 'Any'))
        $addrAny = (((-not $adf.LocalAddress) -or $adf.LocalAddress -eq 'Any') -and
                    ((-not $adf.RemoteAddress) -or $adf.RemoteAddress -eq 'Any'))
        $profileAll = ([string]$a.Profile).ToLowerInvariant() -eq 'any'
        if ($progAny -and $portAny -and $addrAny -and $profileAll) {{ $activeOk = $true }}
      }}
      if (-not $activeOk) {{
        $result = 'unknown'
      }} else {{
        # 防火墙配置/活动连接读取失败必须变成 unknown，而不是靠空集合推断。
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        if ($profiles.Count -eq 0) {{
          $result = 'unknown'
        }} else {{
          $statusMap = @{{}}
          foreach ($p in $profiles) {{ $statusMap[[string]$p.Name] = ($p.Enabled -eq 'True') }}
          $connections = @(Get-NetConnectionProfile -ErrorAction Stop)
          if ($connections.Count -eq 0) {{
            $anyOn = $false
            foreach ($v in $statusMap.Values) {{ if ($v) {{ $anyOn = $true }} }}
            if ($anyOn) {{ $result = 'present' }} else {{ $result = 'unknown' }}
          }} else {{
            $result = 'present'
            foreach ($c in $connections) {{
              $cat = [string]$c.NetworkCategory
              $key = switch ($cat) {{
                'DomainAuthenticated' {{ 'Domain' }}
                'Private' {{ 'Private' }}
                'Public' {{ 'Public' }}
                default {{ '' }}
              }}
              if ($key -eq '' -or -not $statusMap.ContainsKey($key) -or -not $statusMap[$key]) {{
                $result = 'unknown'
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}} catch {{ $result = 'unknown' }}
$result"#,
        name = ps_quote(CUT_RULE)
    );
    let out = crate::platform::imp::run_powershell(&script)
        .map_err(|e| format!("查询阻断规则失败：{e}"))?;
    match out.trim().to_ascii_lowercase().as_str() {
        "present" => {
            // 统一核验当前生效策略的活动网络 Profile，不能只信持久配置。
            match crate::platform::imp::effective_firewall_enabled() {
                Some(true) => Ok(RuleState::Present),
                Some(false) | None => Ok(RuleState::Unknown),
            }
        }
        "absent" => Ok(RuleState::Absent),
        "wrong" => Ok(RuleState::WrongAttributes),
        "unknown" => Ok(RuleState::Unknown),
        other => Err(format!("阻断规则查询输出无法解析：{other:?}")),
    }
}

/// 删除全局出站阻断规则。
///
/// **P0-NEW-01**：删除「不存在的东西」和「删除失败」必须分开。
/// 之前用 `SilentlyContinue`：未以管理员运行时删除会被静默拒绝，脚本仍以
/// 成功结束，恢复流程于是报告「已恢复网络」，而规则还在阻断全部流量。
///
/// 现在的语义：
/// - 规则本来就不存在 → `Ok`（幂等，重复恢复不报错）；
/// - 规则存在但删不掉 → `Err`（带出系统给的拒绝原因）。
fn remove_cut_rule() -> Result<(), String> {
    let script = format!(
        "$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='Stop'
# 无语句级 exit/return：两者都会跳过执行结果哨兵。
$name = {name}
$pattern = [WildcardPattern]::Escape($name)
$rules = @(Get-NetFirewallRule -DisplayName ($pattern + '*') -ErrorAction Stop |
           Where-Object {{ $_.DisplayName -eq $name }})
if ($rules.Count -gt 0) {{
  $rules | Remove-NetFirewallRule -ErrorAction Stop
  'removed'
}} else {{
  'absent'
}}",
        name = ps_quote(CUT_RULE)
    );
    let out = crate::platform::imp::run_powershell(&script)
        .map_err(|e| format!("删除全局阻断规则失败：{e}"))?;
    match out.trim() {
        "removed" | "absent" => Ok(()),
        other => Err(format!("删除全局阻断规则输出无法解析：{other:?}")),
    }
}

/// 枚举启用中的物理网卡并禁用它们；返回实际禁用的网卡名。
/// **P0-A**：只枚举将被禁用的物理网卡（只读，不改系统）。
///
/// 必须在执行任何禁用之前调用，并把结果连同原始状态一起写入账本——
/// 否则中途崩溃时账本里没有「哪些网卡已被禁用」的信息。
pub fn list_up_physical_nics() -> Result<Vec<AdapterSnapshot>, String> {
    // **P0-04**：同时取 InterfaceGuid 与 AdminStatus（原始管理状态）。
    let script = "$ErrorActionPreference='Stop'
$items = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
  [PSCustomObject]@{ name = $_.Name; guid = [string]$_.InterfaceGuid; admin_up = ($_.AdminStatus -eq 'Up') }
})
ConvertTo-Json @($items) -Compress";
    let json = crate::platform::imp::run_powershell(script)?;
    let value: serde_json::Value =
        serde_json::from_str(json.trim()).map_err(|e| format!("网卡列表解析失败：{e}"))?;
    let items = match value {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Object(_) => vec![value],
        serde_json::Value::Null => Vec::new(),
        other => return Err(format!("网卡列表格式异常：{other}")),
    };
    let mut out = Vec::new();
    for item in items {
        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        out.push(AdapterSnapshot {
            name,
            guid: item
                .get("guid")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            admin_up: item
                .get("admin_up")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
        });
    }
    Ok(out)
}

/// 禁用**一块**网卡（供逐块处理，每块之间更新账本）。
pub fn disable_one_nic(name: &str) -> Result<(), String> {
    let script = format!(
        "$ErrorActionPreference='Stop'
         Disable-NetAdapter -Name {} -Confirm:$false -ErrorAction Stop | Out-Null",
        ps_quote(name)
    );
    crate::platform::imp::run_powershell(&script).map(|_| ())
}

/// 重新启用记录在案的网卡。
///
/// **P0-NEW-01**：不能 `SilentlyContinue`。未以管理员运行时 `Enable-NetAdapter`
/// 会被拒绝，静默后恢复流程以为网卡已启用、继续删阻断规则——用户的网卡
/// 仍处于禁用状态却没有任何错误可看。这里逐块启用并收集失败，
/// 由调用方决定是否保留阻断规则。
fn enable_nics(nics: &[String]) -> Result<(), String> {
    let list = nics
        .iter()
        .map(|name| ps_quote(name))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='Stop'
# 无语句级 exit/return：两者都会跳过执行结果哨兵。
$failed = @()
foreach ($n in @({list})) {{
  try {{
    Enable-NetAdapter -Name $n -Confirm:$false -ErrorAction Stop | Out-Null
  }} catch {{
    $failed += ($n + '：' + $_.Exception.Message)
  }}
}}
ConvertTo-Json @($failed) -Compress"
    );
    let json = crate::platform::imp::run_powershell(&script)?;
    let failed: Vec<String> = serde_json::from_str(json.trim())
        .map_err(|e| format!("启用网卡结果解析失败：{e}; 原文：{}", json.trim()))?;
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("；"))
    }
}

/// **P0-06**：按**稳定身份**（InterfaceGuid）恢复网卡，找不到就明确报错。
///
/// 原实现只按显示名称 Enable：网卡在断网后改名（驱动更新、用户重命名、
/// 多语言系统切换）就找不到设备，而恢复流程会静默跳过那一块。
///
/// 返回 `(已恢复的 GUID, 失败说明)`。**绝不**用同名设备替代——名称可能已被
/// 另一块网卡占用，误启用会改变用户的网络拓扑。
fn enable_nics_by_guid(snapshots: &[AdapterSnapshot]) -> (Vec<String>, Vec<String>) {
    let mut restored = Vec::new();
    let mut failures = Vec::new();
    for snap in snapshots {
        if snap.guid.trim().is_empty() {
            continue;
        }
        // **P0-J**：`Get-NetAdapter` / `Enable-NetAdapter` **没有** `-InterfaceGuid`
        // 参数（实测报「找不到与参数名称匹配的参数」）。`InterfaceGuid` 只是
        // 网卡对象的属性，必须枚举后按属性精确匹配，再用 `-InputObject` 启用。
        //
        // 这条路径曾在 v0.6.8 因参数不存在而必然失败——断网后网卡无法恢复，
        // 是系统可用性级别的缺陷。下面的脚本已在本机 PowerShell 上验证语法。
        let script = format!(
            "$ErrorActionPreference='Stop'
             $guid = {guid}
             try {{
               $matches = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {{ [string]$_.InterfaceGuid -eq $guid }})
               if ($matches.Count -eq 0) {{ 'missing' }}
               elseif ($matches.Count -gt 1) {{ 'ambiguous' }}
               else {{
                 $adapter = $matches[0]
                 if ($adapter.AdminStatus -ne 'Up') {{
                   Enable-NetAdapter -InputObject $adapter -Confirm:$false -ErrorAction Stop
                 }}
                 $after = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object {{ [string]$_.InterfaceGuid -eq $guid }})
                 if ($after.Count -eq 1 -and $after[0].AdminStatus -eq 'Up') {{ 'ok' }} else {{ 'failed' }}
               }}
             }} catch {{ 'error: ' + $_.Exception.Message }}",
            guid = ps_quote(&snap.guid)
        );
        match crate::platform::imp::run_powershell(&script) {
            Ok(out) => {
                let out = out.trim();
                let lower = out.to_ascii_lowercase();
                if lower == "ok" {
                    restored.push(snap.guid.clone());
                } else if lower == "missing" {
                    failures.push(format!(
                        "网卡 {}（GUID {}）已不存在，无法恢复；账本保留待人工处理",
                        snap.name, snap.guid
                    ));
                } else if lower == "ambiguous" {
                    failures.push(format!(
                        "网卡 {}（GUID {}）匹配到多块设备，拒绝猜测启用",
                        snap.name, snap.guid
                    ));
                } else if let Some(detail) = out.strip_prefix("error: ") {
                    failures.push(format!(
                        "网卡 {}（GUID {}）恢复失败：{detail}",
                        snap.name, snap.guid
                    ));
                } else {
                    failures.push(format!(
                        "网卡 {}（GUID {}）启用后状态仍非 Up（{out}）",
                        snap.name, snap.guid
                    ));
                }
            }
            Err(error) => failures.push(format!(
                "网卡 {}（GUID {}）恢复失败：{error}",
                snap.name, snap.guid
            )),
        }
    }
    (restored, failures)
}

/// PowerShell 单引号转义。
fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cut_mode_parses_and_unknown_is_off() {
        assert_eq!(CutMode::parse("firewall"), CutMode::Firewall);
        assert_eq!(CutMode::parse(" NICS "), CutMode::Nics);
        assert_eq!(CutMode::parse("off"), CutMode::Off);
        // 未知值绝不能误断网。
        assert_eq!(CutMode::parse("something-else"), CutMode::Off);
        assert_eq!(CutMode::parse(""), CutMode::Off);
        assert_eq!(CutMode::default(), CutMode::Off);
    }

    #[test]
    fn cut_mode_labels_are_chinese() {
        assert_eq!(CutMode::Off.label(), "不断网");
        assert_eq!(CutMode::Firewall.label(), "防火墙全局阻断");
        assert_eq!(CutMode::Nics.label(), "禁用物理网卡");
    }

    #[test]
    fn off_mode_is_a_noop() {
        let (ok, note) = cut(CutMode::Off);
        assert!(ok);
        assert!(note.contains("未执行断网"), "{note}");
    }

    #[test]
    fn cut_state_round_trips() {
        let state = CutState {
            mode: "nics".to_string(),
            firewall: true,
            planned_adapters: vec!["以太网".to_string(), "WLAN".to_string()],
            completed_adapters: vec!["以太网".to_string()],
            adapter_snapshots: Vec::new(),
            nics: Vec::new(),
            since: 1_760_000_000,
            phase: CutPhase::Applied,
        };
        let text = serde_json::to_string(&state).unwrap();
        let back: CutState = serde_json::from_str(&text).unwrap();
        assert_eq!(state, back);
        // 旧账本缺 nics 字段时按空恢复（不 panic、不乱启用网卡）。
        let legacy: CutState =
            serde_json::from_str(r#"{"mode":"firewall","firewall":true,"since":1}"#).unwrap();
        assert!(legacy.nics.is_empty());
        assert!(legacy.adapters_to_restore().is_empty());
    }

    #[test]
    fn ps_quote_escapes_single_quotes() {
        assert_eq!(ps_quote("以太网"), "'以太网'");
        assert_eq!(ps_quote("it's"), "'it''s'");
    }

    #[test]
    fn cut_rule_name_is_product_scoped() {
        // 恢复与自愈都按这个名字找规则，改名会留下删不掉的残留。
        assert_eq!(CUT_RULE, "ClaudeSwitcher Egate Cut All");
    }

    /// **P0-I**：`nics` 档位必须被能力门控拦下（没有独立恢复执行器），
    /// 而 `firewall` 档位不受影响。
    #[test]
    fn nics_mode_is_gated_but_firewall_is_not() {
        assert!(matches!(
            global_cut_capability(CutMode::Nics),
            CutCapability::Unavailable(_)
        ));
        assert_eq!(
            global_cut_capability(CutMode::Firewall),
            CutCapability::Ready
        );
        assert_eq!(global_cut_capability(CutMode::Off), CutCapability::Ready);
    }
}

/// **P0-15**：统一恢复报告。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryReport {
    /// **P0-02**：停止保护意图是否成功提交（后台不会重新施加）。
    pub intent_ok: bool,
    /// 网络是否已恢复并核验。
    pub network_ok: bool,
    /// 应用隔离是否已解除并核验。
    pub isolation_ok: bool,
    /// 环境账本是否已还原。
    pub env_ok: bool,
    /// **P0-02**：是否全部必要项完成（只有此时才清除熔断状态）。
    pub complete: bool,
    /// 尚未恢复的资源。
    pub pending_resources: Vec<String>,
    /// 所有失败的说明。
    pub failures: Vec<String>,
    /// 最终结论。
    pub note: String,
}

/// **P0-15**：统一恢复入口——网络 + 应用隔离 + 环境账本。
///
/// CLI 急救、托盘退出、卸载前恢复都调用这一份实现，确保三者行为一致。
/// 只有全部必要项核验通过才返回 `network_ok && isolation_ok`。
pub fn restore_all() -> RecoveryReport {
    // **P0-02**：完整恢复必须独占系统操作权，避免与监控/保镖并发。
    let guard = match crate::egate_lock::acquire(crate::egate_lock::SystemOperation::FullRestore) {
        Ok(guard) => guard,
        Err(error) => {
            return RecoveryReport {
                intent_ok: false,
                network_ok: false,
                isolation_ok: false,
                env_ok: false,
                complete: false,
                pending_resources: vec!["系统操作锁".to_string()],
                failures: vec![format!("无法获取系统操作锁：{error}")],
                note: format!("恢复未执行（{error}）"),
            };
        }
    };

    let mut failures = Vec::new();
    let mut pending = Vec::new();

    // 1. **P0-02**：停止保护意图必须先成功提交——否则后台会在下一轮重新施加。
    // **P0-04（v0.6.13.1）**：停止保护意图是**强制前置门禁**。
    //
    // 原实现即使写盘失败也继续恢复网络与防火墙，最后才报「未完整」。
    // 但后台此时仍是 Armed——下一轮会立刻把刚解除的隔离重新加上，
    // 用户看到的是「恢复了，然后又断了」的不可预测竞态。
    // 现在：意图写不进去就**立即返回**，不做任何破坏性恢复。
    if let Err(error) = crate::egate_monitor::disarm("用户执行紧急恢复") {
        return RecoveryReport {
            intent_ok: false,
            network_ok: false,
            isolation_ok: false,
            env_ok: false,
            complete: false,
            pending_resources: vec!["停止保护意图".to_string()],
            failures: vec![format!(
                "停止保护意图写入失败（{error}）：为避免恢复后被后台立即重新封锁，                 本次**未执行任何**网络/隔离恢复"
            )],
            note: format!("恢复未执行：无法持久化「停止保护」意图（{error}）"),
        };
    }
    let intent_ok = true;

    // 2. 恢复网络（已持锁，走无锁版本）。
    let (network_ok, network_note) = restore_locked(&guard);
    if !network_ok {
        failures.push(format!("网络：{network_note}"));
        pending.push("网络（网卡/阻断规则）".to_string());
    }

    // 3. 解除应用隔离并回查（已持锁）。
    // **P0-04**：紧急恢复不受「手动保持」拦截——用户执行急救时明确要求恢复，
    // 与自动恢复不是一回事。此处已持锁，走无锁版本。
    let isolation_ok = match crate::egate_trip::release_verified_locked(
        &guard,
        crate::egate_trip::ReleaseReason::Emergency,
    ) {
        Ok(report) if report.verified => true,
        Ok(report) => {
            failures.push(format!("应用隔离：{}", report.failures.join("；")));
            pending.push(format!("应用隔离（剩余 {} 条规则）", report.remaining));
            false
        }
        Err(error) => {
            failures.push(format!("应用隔离：{error}"));
            pending.push("应用隔离".to_string());
            false
        }
    };

    // **P1-07（v0.7.1）**：隔离确认清理干净后，收敛持久化保护意图。
    // 否则重启后界面仍显示「兜底封锁中」，而规则已经不存在。
    if isolation_ok {
        if let Err(error) = crate::egate_monitor::clear_uncovered_lock() {
            failures.push(format!("兜底封锁意图清理失败（{error}）"));
            pending.push("兜底封锁意图".to_string());
        }
    }

    // 4. 还原环境账本。
    // **P1-07**： 已持 FullRestore 锁，环境还原走无锁版本，
    // 否则会与自己争同一把锁（自我死锁）。
    let env_ok = match crate::egate_env::restore_locked(&guard) {
        Ok(_) => true,
        Err(error) => {
            failures.push(format!("环境账本：{error}"));
            pending.push("环境设置（时区）".to_string());
            false
        }
    };

    // 5. **P0-02**：只有全部必要项完成才清除熔断状态。
    // **P1-07**：意图收敛失败同样不算完整恢复（pending 已记录）。
    let intent_converged = !pending.iter().any(|p| p.contains("兜底封锁意图"));
    let complete = intent_ok && network_ok && isolation_ok && env_ok && intent_converged;
    if complete {
        crate::egate_monitor::clear_tripped();
    } else {
        // 保留熔断状态与账本，允许重试。
        crate::egate_monitor::mark_tripped_state(false);
    }

    RecoveryReport {
        intent_ok,
        network_ok,
        isolation_ok,
        env_ok,
        complete,
        note: if complete {
            "已完整恢复：意图、网络、隔离与环境设置均已核验".to_string()
        } else {
            format!(
                "恢复未完成（待处理：{}）：{}",
                if pending.is_empty() {
                    "无".to_string()
                } else {
                    pending.join("、")
                },
                failures.join("；")
            )
        },
        failures,
        pending_resources: pending,
    }
}
