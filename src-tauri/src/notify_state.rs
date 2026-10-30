//! 额度阈值通知（P1-4）。
//!
//! 80% / 95% 两档系统通知；每个重置周期（以官方 usage 的 `resets_at` 为 key）
//! 每档只通知一次，状态落 `notify-state.json`（原子写）。
//!
//! H-8：5 小时与 7 天两个窗口各自独立去重；reset key 向下取整到 5 分钟
//! （秒级抖动收敛到同一周期）；当前账号 uuid 缺失时直接跳过，不再使用
//! 固定键 `"current"`。
//!
//! Windows Toast 需 AppUserModelID：打包后的应用以其 bundle id 作为 AUMID 正常显示；
//! 开发模式下 Toast 可能显示为宿主（PowerShell / 终端）身份，属正常现象，不影响逻辑。

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct QuotaNotifyRecord {
    /// 5 小时窗口所属的重置周期（reset_at 取整后 RFC3339）；周期变化则档位清零。
    reset_key: String,
    /// 5 小时窗口本周期已通知过的档位。
    #[serde(default)]
    notified_levels: Vec<u8>,
    /// 7 天窗口所属的重置周期。
    #[serde(default)]
    weekly_reset_key: String,
    /// 7 天窗口本周期已通知过的档位。
    #[serde(default)]
    weekly_notified_levels: Vec<u8>,
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

/// 同一重置周期判定的容差（秒）：两次报告的重置时间相差不超过 10 分钟即视为同一周期。
const RESET_PERIOD_TOLERANCE_SECS: i64 = 10 * 60;

/// 重置周期 key：Some→原始 RFC3339；None→固定占位串。
///
/// J-6：不再向下取整。去重判定改用 [`same_reset_period`] 的容差比较，
/// 避免「取整后 key 因 5 分钟边界翻转而误判为新周期」。
fn reset_key_of(reset: Option<DateTime<Utc>>) -> String {
    match reset {
        Some(reset) => reset.to_rfc3339(),
        None => "unknown-reset".to_string(),
    }
}

/// 两个周期 key 是否属于同一重置周期（J-6）。
///
/// 两者都能解析为时间时，绝对时间差 ≤ 10 分钟即同一周期（覆盖服务器秒级~分钟级
/// 抖动、取整边界等）；任一无法解析（如占位串 `unknown-reset`）则回退到字符串相等，
/// 保留对无法解析时间的字符串回退。
fn same_reset_period(record_key: &str, current_key: &str) -> bool {
    let parse = |s: &str| DateTime::parse_from_rfc3339(s).ok();
    match (parse(record_key), parse(current_key)) {
        (Some(a), Some(b)) => (a - b).num_seconds().abs() <= RESET_PERIOD_TOLERANCE_SECS,
        _ => record_key == current_key,
    }
}

/// 纯函数：从轻量账号列表取「当前账号」的 account_uuid。
///
/// uuid 缺失（或 current 缺失/匹配不到）一律返回 None——调用方必须跳过，
/// **绝不回退到固定键**。
fn uuid_of_current(profiles: &[store::LightProfile], current_id: Option<&str>) -> Option<String> {
    current_id
        .and_then(|id| profiles.iter().find(|p| p.id == id))
        .and_then(|p| p.account_uuid.clone())
}

/// 纯函数：给定当前百分比、本周期已通知档位、记录所属周期，返回本次还需通知的档位。
/// `record_reset_key` 与当前周期不同（或没有记录）时视为本周期尚未通知任何档位。
fn levels_to_notify(
    percent: f64,
    already: &[u8],
    record_reset_key: Option<&str>,
    current_reset_key: &str,
) -> Vec<u8> {
    let seen = match record_reset_key {
        Some(key) if same_reset_period(key, current_reset_key) => already,
        _ => &[][..],
    };
    QUOTA_THRESHOLDS
        .iter()
        .copied()
        .filter(|level| percent >= f64::from(*level) && !seen.contains(level))
        .collect()
}

/// 纯函数：5 小时窗口的去重入口（保留旧签名，等价于只看记录的 5h 字段）。
fn thresholds_to_notify(
    percent: f64,
    record: Option<&QuotaNotifyRecord>,
    reset_key: &str,
) -> Vec<u8> {
    match record {
        Some(r) => levels_to_notify(percent, &r.notified_levels, Some(&r.reset_key), reset_key),
        None => levels_to_notify(percent, &[], None, reset_key),
    }
}

/// 一次评估的结果。
#[derive(Debug, Serialize)]
pub struct QuotaNotifyResult {
    /// 5 小时窗口用量百分比。
    pub percent: Option<f64>,
    /// 5 小时窗口本次通知档位。
    pub notified_levels: Vec<u8>,
    /// 7 天窗口用量百分比。
    #[serde(default)]
    pub weekly_percent: Option<f64>,
    /// 7 天窗口本次通知档位。
    #[serde(default)]
    pub weekly_notified_levels: Vec<u8>,
}

/// 评估当前账号的 5 小时与 7 天用量，达阈值则发系统通知（每窗口每周期每档一次）。
/// 阻塞（读 usage 可能走网络），调用方须在后台线程 / blocking 中调用。
pub fn evaluate_quota_notification(app: &tauri::AppHandle) -> Result<QuotaNotifyResult, String> {
    let snapshot = usage::claude_usage_snapshot()?;
    let session_percent = snapshot.session.used_percent;
    let weekly_percent = snapshot.weekly.used_percent;
    let session_reset_key = reset_key_of(snapshot.session.reset_at);
    let weekly_reset_key = reset_key_of(snapshot.weekly.reset_at);

    // 当前账号 uuid（跨周期/跨账号隔离通知记录）。读不到 / uuid 缺失 → 直接跳过，
    // 不写任何状态，也绝不回退到固定键 "current"。
    let account_uuid = match store::read_lightweight() {
        Ok((profiles, current_id)) => uuid_of_current(&profiles, current_id.as_deref()),
        Err(e) => {
            crate::log_error(&format!("读取账号轻量元数据失败，跳过额度通知评估: {e}"));
            None
        }
    };
    let Some(account_uuid) = account_uuid else {
        return Ok(QuotaNotifyResult {
            percent: session_percent,
            notified_levels: Vec::new(),
            weekly_percent,
            weekly_notified_levels: Vec::new(),
        });
    };

    let mut state = load_notify_state();
    let existing = state.quota.get(&account_uuid);

    let session_to_notify = match session_percent {
        Some(p) => thresholds_to_notify(p, existing, &session_reset_key),
        None => Vec::new(),
    };
    let weekly_to_notify = match (weekly_percent, existing) {
        (Some(p), Some(r)) => levels_to_notify(
            p,
            &r.weekly_notified_levels,
            Some(&r.weekly_reset_key),
            &weekly_reset_key,
        ),
        (Some(p), None) => levels_to_notify(p, &[], None, &weekly_reset_key),
        _ => Vec::new(),
    };

    if session_to_notify.is_empty() && weekly_to_notify.is_empty() {
        return Ok(QuotaNotifyResult {
            percent: session_percent,
            notified_levels: Vec::new(),
            weekly_percent,
            weekly_notified_levels: Vec::new(),
        });
    }

    // 更新记录（任一窗口周期变化则先清该窗口已通知档位）。
    let record = state.quota.entry(account_uuid).or_default();
    if !same_reset_period(&record.reset_key, &session_reset_key) {
        record.reset_key = session_reset_key;
        record.notified_levels.clear();
    }
    record
        .notified_levels
        .extend(session_to_notify.iter().copied());
    if !same_reset_period(&record.weekly_reset_key, &weekly_reset_key) {
        record.weekly_reset_key = weekly_reset_key;
        record.weekly_notified_levels.clear();
    }
    record
        .weekly_notified_levels
        .extend(weekly_to_notify.iter().copied());
    save_notify_state(&state)?;

    for level in &session_to_notify {
        send_quota_notification(app, *level, session_percent.unwrap_or(0.0), "5 小时额度");
    }
    for level in &weekly_to_notify {
        send_quota_notification(app, *level, weekly_percent.unwrap_or(0.0), "7 天额度");
    }

    Ok(QuotaNotifyResult {
        percent: session_percent,
        notified_levels: session_to_notify,
        weekly_percent,
        weekly_notified_levels: weekly_to_notify,
    })
}

fn send_quota_notification(app: &tauri::AppHandle, level: u8, percent: f64, window: &str) {
    use tauri_plugin_notification::NotificationExt;
    let title = format!("{window}已用 {level}%");
    let body = format!("当前账号{window}已用 {percent:.0}%，注意安排用量或切换账号。");
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
            weekly_reset_key: String::new(),
            weekly_notified_levels: Vec::new(),
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

    #[test]
    fn same_period_within_tolerance_despite_jitter() {
        let base = "2026-10-30T12:07:42Z";
        // 相差 2 分 17 秒（旧取整逻辑会分到不同 5 分钟桶）→ 容差内仍同一周期。
        let nearby = "2026-10-30T12:09:59Z";
        assert!(same_reset_period(base, nearby));
        // 恰好 10 分钟 → 同一周期（含边界）。
        let at_limit = "2026-10-30T12:17:42Z";
        assert!(same_reset_period(base, at_limit));
        // 超过 10 分钟 → 不同周期。
        let beyond = "2026-10-30T12:17:43Z";
        assert!(!same_reset_period(base, beyond));
        // 数小时后的下一次重置 → 明确不同周期。
        let next_reset = "2026-10-30T17:07:42Z";
        assert!(!same_reset_period(base, next_reset));
    }

    #[test]
    fn same_period_falls_back_to_string_equality_when_unparseable() {
        // 占位串无法解析 → 回退字符串相等。
        assert!(same_reset_period("unknown-reset", "unknown-reset"));
        assert!(!same_reset_period("unknown-reset", "2026-10-30T12:07:42Z"));
        assert!(!same_reset_period("2026-10-30T12:07:42Z", "unknown-reset"));
    }

    #[test]
    fn reset_key_of_none_is_unknown() {
        assert_eq!(reset_key_of(None), "unknown-reset");
    }

    #[test]
    fn uuid_missing_never_falls_back_to_fixed_key() {
        let with_uuid = vec![store::LightProfile {
            id: "a".into(),
            name: "A".into(),
            account_uuid: Some("real-uuid".into()),
            email: None,
        }];
        assert_eq!(
            uuid_of_current(&with_uuid, Some("a")).as_deref(),
            Some("real-uuid")
        );

        // uuid 缺失 / current 缺失 / current 匹配不到 → None，绝不产生 "current"。
        let no_uuid = vec![store::LightProfile {
            id: "a".into(),
            name: "A".into(),
            account_uuid: None,
            email: None,
        }];
        assert_eq!(uuid_of_current(&no_uuid, Some("a")), None);
        assert_eq!(uuid_of_current(&no_uuid, None), None);
        assert_eq!(uuid_of_current(&no_uuid, Some("ghost")), None);
    }

    #[test]
    fn weekly_window_dedupes_independently_from_session() {
        let mut r = QuotaNotifyRecord {
            reset_key: "r5".into(),
            notified_levels: vec![80, 95],
            weekly_reset_key: "rw".into(),
            weekly_notified_levels: Vec::new(),
        };
        // 5h 同周期已通知满档 → 99% 也不再通知。
        assert!(levels_to_notify(99.0, &r.notified_levels, Some(&r.reset_key), "r5").is_empty());
        // 7d 同周期首次到 85% → 只通知 80。
        assert_eq!(
            levels_to_notify(
                85.0,
                &r.weekly_notified_levels,
                Some(&r.weekly_reset_key),
                "rw"
            ),
            vec![80]
        );
        // 7d 新周期 rw2 → 重新通知 80。
        assert_eq!(
            levels_to_notify(
                90.0,
                &r.weekly_notified_levels,
                Some(&r.weekly_reset_key),
                "rw2"
            ),
            vec![80]
        );
        // 模拟 evaluate 里的更新路径：7d 同周期再到 96% → 补 95。
        r.weekly_notified_levels.push(80);
        assert_eq!(
            levels_to_notify(
                96.0,
                &r.weekly_notified_levels,
                Some(&r.weekly_reset_key),
                "rw"
            ),
            vec![95]
        );
    }
}
