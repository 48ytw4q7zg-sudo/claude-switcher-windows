//! 额度阈值通知（P1-4）。
//!
//! 80% / 95% 两档系统通知；每个重置周期（以官方 usage 的 `resets_at` 为 key）
//! 每档只通知一次，状态落 `notify-state.json`（原子写）。
//!
//! Windows Toast 需 AppUserModelID：打包后的应用以其 bundle id 作为 AUMID 正常显示；
//! 开发模式下 Toast 可能显示为宿主（PowerShell / 终端）身份，属正常现象，不影响逻辑。

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::fsx;
use crate::store;
use crate::usage;

/// 额度通知档位（百分比，升序）。
const QUOTA_THRESHOLDS: [u8; 2] = [80, 95];

/// 通知状态（落盘）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotifyState {
    /// 按账号（account_uuid）记录已通知档位。
    #[serde(default)]
    quota: BTreeMap<String, QuotaNotifyRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QuotaNotifyRecord {
    /// 该记录所属的重置周期（resets_at RFC3339）；周期变化则档位清零。
    reset_key: String,
    /// 本周期已通知过的档位。
    notified_levels: Vec<u8>,
}

fn notify_state_path() -> Result<PathBuf, String> {
    Ok(crate::paths::app_data_dir()?.join("notify-state.json"))
}

fn load_notify_state() -> NotifyState {
    let Ok(path) = notify_state_path() else {
        return NotifyState::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => NotifyState::default(),
    }
}

fn save_notify_state(state: &NotifyState) -> Result<(), String> {
    let path = notify_state_path()?;
    let raw = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    fsx::write_atomically(&path, &raw).map_err(|e| format!("写入 notify-state 失败: {e}"))
}

/// 纯函数：给定当前百分比、既有记录、当前重置周期 key，返回本次需要通知的档位。
/// 记录属于别的周期（或不存在）时视为本周期尚未通知任何档位。
fn thresholds_to_notify(
    percent: f64,
    record: Option<&QuotaNotifyRecord>,
    reset_key: &str,
) -> Vec<u8> {
    let already: Vec<u8> = match record {
        Some(r) if r.reset_key == reset_key => r.notified_levels.clone(),
        _ => Vec::new(),
    };
    QUOTA_THRESHOLDS
        .iter()
        .copied()
        .filter(|level| percent >= f64::from(*level) && !already.contains(level))
        .collect()
}

/// 一次评估的结果。
#[derive(Debug, Serialize)]
pub struct QuotaNotifyResult {
    pub percent: Option<f64>,
    pub notified_levels: Vec<u8>,
}

/// 评估当前账号的 5 小时用量，达阈值则发系统通知（每周期每档一次）。
/// 阻塞（读 usage 可能走网络），调用方须在后台线程 / blocking 中调用。
pub fn evaluate_quota_notification(app: &tauri::AppHandle) -> Result<QuotaNotifyResult, String> {
    let snapshot = usage::claude_usage_snapshot()?;
    let Some(percent) = snapshot.session.used_percent else {
        return Ok(QuotaNotifyResult {
            percent: None,
            notified_levels: Vec::new(),
        });
    };
    let reset_key = snapshot
        .session
        .reset_at
        .map(|r| r.to_rfc3339())
        .unwrap_or_else(|| "unknown-reset".to_string());

    // 当前账号 uuid（跨周期/跨账号隔离通知记录）。
    let store_data = store::load_store().unwrap_or_default();
    let account_key = store_data
        .current_profile_id
        .as_deref()
        .and_then(|id| store_data.profiles.iter().find(|p| p.id == id))
        .and_then(|p| p.meta.account_uuid.clone())
        .unwrap_or_else(|| "current".to_string());

    let mut state = load_notify_state();
    let to_notify = thresholds_to_notify(percent, state.quota.get(&account_key), &reset_key);

    if to_notify.is_empty() {
        return Ok(QuotaNotifyResult {
            percent: Some(percent),
            notified_levels: Vec::new(),
        });
    }

    // 更新记录（新周期则先清空已通知档位）。
    let record = state.quota.entry(account_key).or_insert(QuotaNotifyRecord {
        reset_key: reset_key.clone(),
        notified_levels: Vec::new(),
    });
    if record.reset_key != reset_key {
        record.reset_key = reset_key.clone();
        record.notified_levels.clear();
    }
    record.notified_levels.extend(to_notify.iter().copied());
    save_notify_state(&state)?;

    for level in &to_notify {
        send_quota_notification(app, *level, percent);
    }

    Ok(QuotaNotifyResult {
        percent: Some(percent),
        notified_levels: to_notify,
    })
}

fn send_quota_notification(app: &tauri::AppHandle, level: u8, percent: f64) {
    use tauri_plugin_notification::NotificationExt;
    let title = format!("额度已用 {level}%");
    let body = format!("当前账号 5 小时额度已用 {percent:.0}%，注意安排用量或切换账号。");
    if let Err(e) = app.notification().builder().title(title).body(body).show() {
        crate::log_error(&format!("发送额度通知失败: {e}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(reset_key: &str, levels: &[u8]) -> QuotaNotifyRecord {
        QuotaNotifyRecord {
            reset_key: reset_key.to_string(),
            notified_levels: levels.to_vec(),
        }
    }

    #[test]
    fn notifies_both_levels_when_crossing_95_first_time() {
        assert_eq!(thresholds_to_notify(96.0, None, "r1"), vec![80, 95]);
    }

    #[test]
    fn notifies_only_80_when_between_levels() {
        assert_eq!(thresholds_to_notify(81.0, None, "r1"), vec![80]);
        assert_eq!(thresholds_to_notify(79.0, None, "r1"), Vec::<u8>::new());
    }

    #[test]
    fn does_not_renotify_already_notified_levels() {
        let r = record("r1", &[80]);
        assert_eq!(thresholds_to_notify(85.0, Some(&r), "r1"), Vec::<u8>::new());
        let r = record("r1", &[80]);
        assert_eq!(thresholds_to_notify(96.0, Some(&r), "r1"), vec![95]);
    }

    #[test]
    fn new_reset_period_clears_notified_levels() {
        let r = record("r0", &[80, 95]);
        // 新周期 r1：80% 重新通知。
        assert_eq!(thresholds_to_notify(82.0, Some(&r), "r1"), vec![80]);
    }
}
