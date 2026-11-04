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

/// 断网现场（落盘，供崩溃后自愈）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutState {
    /// "firewall" | "nics"
    pub mode: String,
    /// 防火墙全局阻断规则是否已加上。
    pub firewall: bool,
    /// 断网前处于启用状态的物理网卡名（恢复时逐个启用）。
    #[serde(default)]
    pub nics: Vec<String>,
    /// 断网开始时间（unix 秒）。
    pub since: u64,
    /// 事务阶段（用于崩溃恢复时判断做到哪一步）。
    #[serde(default)]
    pub phase: CutPhase,
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
    // 已有现场：先严格检查账本状态。
    match load_state() {
        Ok(Some(_)) => {
            // 有效的未完成事务：先恢复。
            let (ok, note) = restore();
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
        phase: CutPhase::FirewallApplied,
        ..prepared
    };
    if let Err(error) = save_state(&after_firewall) {
        // 账本更新失败：规则已加上但账本显示 Prepared。恢复时会尝试删规则（无害）。
        return (false, format!("防火墙已加但账本更新失败：{error}"));
    }

    // 步骤 3：禁用网卡（仅 Nics 档）。
    let final_state = if mode == CutMode::Nics {
        match disable_up_nics() {
            Ok((disabled, errors)) => {
                if !errors.is_empty() {
                    let partial = CutState {
                        mode: "nics".to_string(),
                        nics: disabled,
                        phase: CutPhase::FirewallApplied,
                        ..after_firewall
                    };
                    let _ = save_state(&partial);
                    return (false, format!("部分网卡禁用失败：{}", errors.join("；")));
                }
                CutState {
                    mode: "nics".to_string(),
                    nics: disabled,
                    phase: CutPhase::Applied,
                    ..after_firewall
                }
            }
            Err(error) => {
                // 网卡禁用失败：降级为防火墙阻断，账本保留 FirewallApplied。
                let _ = save_state(&after_firewall);
                return (
                    false,
                    format!("禁用网卡失败（已降级为防火墙阻断）：{error}"),
                );
            }
        }
    } else {
        CutState {
            phase: CutPhase::Applied,
            ..after_firewall
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
    let state = match load_state() {
        Ok(state) => state,
        Err(error) => return (false, format!("读取断网现场失败，未做任何恢复：{error}")),
    };
    let mut failures = Vec::new();

    // 顺序：先恢复网卡、最后删规则——恢复过程中网络始终被规则挡着。
    if let Some(state) = &state {
        if !state.nics.is_empty() {
            // 启用网卡并核验。
            if let Err(error) = enable_nics(&state.nics) {
                failures.push(format!("启用网卡失败：{error}"));
            } else {
                // 回查：确认网卡确实已 Up（驱动加载可能延迟）。
                match verify_nics_up(&state.nics) {
                    Ok(gone) if !gone.is_empty() => {
                        failures.push(format!("网卡未能恢复（可能驱动延迟）：{}", gone.join("、")));
                    }
                    Ok(_) => {}
                    Err(error) => {
                        failures.push(format!("网卡状态核验失败：{error}"));
                    }
                }
            }
        }
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
           if (-not $a -or $a.Status -ne 'Up') {{ $down += $n }}
         }}
         ConvertTo-Json @($down) -Compress"
    );
    let json = crate::platform::imp::run_powershell(&script)
        .map_err(|e| format!("查询网卡状态失败：{e}"))?;
    let value: serde_json::Value =
        serde_json::from_str(json.trim()).map_err(|e| format!("网卡状态解析失败：{e}"))?;
    Ok(match value {
        serde_json::Value::Array(items) => items
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        serde_json::Value::String(one) if !one.is_empty() => vec![one],
        _ => Vec::new(),
    })
}

/// 查询某条防火墙规则是否存在。
fn rule_exists(name: &str) -> Result<bool, String> {
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'
         $r = Get-NetFirewallRule -DisplayName {} -ErrorAction SilentlyContinue
         if ($r) {{ 'true' }} else {{ 'false' }}",
        ps_quote(name)
    );
    let out =
        crate::platform::imp::run_powershell(&script).map_err(|e| format!("查询规则失败：{e}"))?;
    Ok(out.trim().eq_ignore_ascii_case("true"))
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

/// 加全局出站阻断规则（幂等）。
fn ensure_firewall_cut_rule() -> Result<(), String> {
    let script = format!(
        "$ErrorActionPreference='Stop'\n\
         $existing = Get-NetFirewallRule -DisplayName {} -ErrorAction SilentlyContinue\n\
         if (-not $existing) {{\n\
           New-NetFirewallRule -DisplayName {} -Direction Outbound -Action Block -Enabled True | Out-Null\n\
         }}",
        ps_quote(CUT_RULE),
        ps_quote(CUT_RULE)
    );
    crate::platform::imp::run_powershell(&script).map(|_| ())
}

/// 删除全局出站阻断规则。
fn remove_cut_rule() -> Result<(), String> {
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'\n\
         Remove-NetFirewallRule -DisplayName {} -ErrorAction SilentlyContinue",
        ps_quote(CUT_RULE)
    );
    crate::platform::imp::run_powershell(&script).map(|_| ())
}

/// 枚举启用中的物理网卡并禁用它们；返回实际禁用的网卡名。
fn disable_up_nics() -> Result<(Vec<String>, Vec<String>), String> {
    let script = "\
$ErrorActionPreference='Stop'\n\
$names = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name)\n\
$done = @(); $failed = @()\n\
foreach ($n in $names) {\n\
  try { Disable-NetAdapter -Name $n -Confirm:$false -ErrorAction Stop; $done += $n }\n\
  catch { $failed += \"$n($($_.Exception.Message))\" }\n\
}\n\
ConvertTo-Json @{ done = @($done); failed = @($failed) } -Compress";
    let json = crate::platform::imp::run_powershell(script)?;
    let value: serde_json::Value =
        serde_json::from_str(json.trim()).map_err(|e| format!("网卡列表解析失败：{e}"))?;
    let list = |key: &str| -> Vec<String> {
        value
            .get(key)
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok((list("done"), list("failed")))
}

/// 重新启用记录在案的网卡。
fn enable_nics(nics: &[String]) -> Result<(), String> {
    let list = nics
        .iter()
        .map(|name| ps_quote(name))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'\n\
         foreach ($n in @({list})) {{\n\
           Enable-NetAdapter -Name $n -Confirm:$false -ErrorAction SilentlyContinue\n\
         }}"
    );
    crate::platform::imp::run_powershell(&script).map(|_| ())
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
            nics: vec!["以太网".to_string(), "WLAN".to_string()],
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
}
