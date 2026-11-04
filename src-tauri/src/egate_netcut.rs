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
    // 已有现场：先按账本恢复，避免把「已断网」当成「未断网」再动一次网卡。
    if let Ok(Some(_)) = load_state() {
        let (ok, note) = restore();
        if !ok {
            return (
                false,
                format!("上次断网现场恢复失败（{note}），已拒绝再次断网"),
            );
        }
    }

    if let Err(error) = ensure_firewall_cut_rule() {
        return (false, format!("加全局阻断规则失败：{error}"));
    }

    let mut nics = Vec::new();
    if mode == CutMode::Nics {
        match disable_up_nics() {
            Ok((disabled, errors)) => {
                nics = disabled;
                if !errors.is_empty() {
                    // 网卡禁用部分失败：规则仍挡着出站，但如实报告。
                    let _ = save_state(&CutState {
                        mode: "nics".to_string(),
                        firewall: true,
                        nics: nics.clone(),
                        since: now_secs(),
                    });
                    return (false, format!("部分网卡禁用失败：{}", errors.join("；")));
                }
            }
            Err(error) => {
                // 规则已加上（出站仍被挡），但不能谎称「已断网」。
                let _ = save_state(&CutState {
                    mode: "firewall".to_string(),
                    firewall: true,
                    nics: Vec::new(),
                    since: now_secs(),
                });
                return (
                    false,
                    format!("禁用网卡失败（已降级为防火墙阻断）：{error}"),
                );
            }
        }
    }

    let state = CutState {
        mode: if mode == CutMode::Nics {
            "nics"
        } else {
            "firewall"
        }
        .to_string(),
        firewall: true,
        nics,
        since: now_secs(),
    };
    if let Err(error) = save_state(&state) {
        return (
            false,
            format!("断网已执行但写现场失败（重启后无法自愈）：{error}"),
        );
    }
    (true, format!("已断网（{}）", mode.label()))
}

/// 恢复网络：删规则 + 重新启用记录在案的网卡 + 删现场。
pub fn restore() -> (bool, String) {
    let state = match load_state() {
        Ok(state) => state,
        Err(error) => return (false, format!("读取断网现场失败，未做任何恢复：{error}")),
    };
    let mut failures = Vec::new();

    // 顺序：先恢复网卡、最后删规则——恢复过程中网络始终被规则挡着。
    if let Some(state) = &state {
        if !state.nics.is_empty() {
            if let Err(error) = enable_nics(&state.nics) {
                failures.push(format!("启用网卡失败：{error}"));
            }
        }
    }
    if let Err(error) = remove_cut_rule() {
        failures.push(format!("删除阻断规则失败：{error}"));
    }
    if failures.is_empty() {
        if let Err(error) = clear_state() {
            return (false, format!("网络已恢复但清理现场失败：{error}"));
        }
        return (true, "已恢复网络".to_string());
    }
    (false, failures.join("；"))
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
