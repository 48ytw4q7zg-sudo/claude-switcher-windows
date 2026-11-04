//! 出口 IP 变化历史（48 小时窗口，融合 YOURSJEYO `Add-IpHistory`）。
//!
//! 只保存「最后一次 IP」时，连续多次漂移后再回到同一 IP 会让警告消失——历史
//! 丢失。本模块在 48 小时窗口内累计变化次数，超过阈值时给出更明确的提示。
//!
//! 存储为独立小文件（`ip-history.json`），与 appconfig 分离：它每轮安检都可能
//! 写入，放一起会让 appconfig 频繁整份重写。裁剪发生在读取时（无需定时任务）。

use serde::{Deserialize, Serialize};

/// 历史窗口（小时）。
pub const WINDOW_HOURS: i64 = 48;
/// 变化次数达到该值以上时给出「频繁漂移」提示。
pub const DRIFT_WARN_THRESHOLD: usize = 3;
/// 历史文件保留的最大条目数（防止长期运行无限增长）。
const MAX_ENTRIES: usize = 256;

/// 一条出口 IP 记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpRecord {
    /// 出口 IP。
    pub ip: String,
    /// 记录时间（unix 秒）。
    pub at: i64,
}

fn history_path() -> Result<std::path::PathBuf, String> {
    Ok(crate::paths::app_data_dir()?.join("ip-history.json"))
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 判断两个时间是否在同一窗口内（纯函数）。
pub fn within_window(at: i64, now: i64) -> bool {
    now.saturating_sub(at) <= WINDOW_HOURS * 3600
}

/// 统计窗口内的「变化」次数（纯函数）。
///
/// 变化 = 相邻两条记录的 IP 不同。窗口外的记录先被丢弃。
pub fn count_changes(records: &[IpRecord], now: i64) -> usize {
    let mut previous: Option<&str> = None;
    let mut changes = 0;
    for record in records {
        if !within_window(record.at, now) {
            continue;
        }
        if let Some(prev) = previous {
            if prev != record.ip {
                changes += 1;
            }
        }
        previous = Some(&record.ip);
    }
    changes
}

/// 窗口内的变化判定结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DriftReport {
    /// 窗口内变化次数。
    pub changes: usize,
    /// 窗口内出现过的不同 IP 数。
    pub distinct_ips: usize,
    /// 是否达到「频繁漂移」阈值。
    pub drifting: bool,
    /// 说明。
    pub note: String,
}

/// 评估窗口内的漂移情况（纯函数）。
pub fn evaluate_drift(records: &[IpRecord], now: i64) -> DriftReport {
    let in_window: Vec<&IpRecord> = records
        .iter()
        .filter(|record| within_window(record.at, now))
        .collect();
    let changes = count_changes(records, now);
    let mut ips: Vec<&str> = in_window.iter().map(|r| r.ip.as_str()).collect();
    ips.sort_unstable();
    ips.dedup();
    let drifting = changes >= DRIFT_WARN_THRESHOLD;
    let distinct_ips = ips.len();
    DriftReport {
        changes,
        distinct_ips,
        drifting,
        note: if in_window.is_empty() {
            format!("最近 {WINDOW_HOURS} 小时没有出口记录")
        } else if drifting {
            format!(
                "最近 {WINDOW_HOURS} 小时出口变化 {changes} 次（{distinct_ips} 个不同 IP），出口不稳定"
            )
        } else {
            format!("最近 {WINDOW_HOURS} 小时出口变化 {changes} 次")
        },
    }
}

/// 记录一次出口 IP（相同 IP 不重复追加，避免刷屏）。
pub fn record(ip: &str) -> Result<DriftReport, String> {
    let ip = ip.trim();
    if ip.is_empty() {
        return Err("出口 IP 为空，未记录".to_string());
    }
    let now = now_secs();
    let mut records = load_raw()?;
    // 只在与最后一条不同时追加（同一 IP 连续出现不构成「变化」）。
    if records.last().map(|r| r.ip.as_str()) != Some(ip) {
        records.push(IpRecord {
            ip: ip.to_string(),
            at: now,
        });
    }
    // 读取时就地裁剪：窗口外的老记录丢弃，再限制总条数。
    records.retain(|record| within_window(record.at, now));
    if records.len() > MAX_ENTRIES {
        let skip = records.len() - MAX_ENTRIES;
        records.drain(..skip);
    }
    save_raw(&records)?;
    Ok(evaluate_drift(&records, now))
}

/// 只读当前漂移情况。
pub fn current_drift() -> Result<DriftReport, String> {
    let records = load_raw()?;
    Ok(evaluate_drift(&records, now_secs()))
}

fn load_raw() -> Result<Vec<IpRecord>, String> {
    let path = history_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("读取出口历史失败：{e}"))?;
    let text = crate::jsonio::decode_text(&bytes);
    // 历史文件损坏不应阻断安检：按空历史继续（下一次记录会重建）。
    Ok(serde_json::from_str(&text).unwrap_or_default())
}

fn save_raw(records: &[IpRecord]) -> Result<(), String> {
    let path = history_path()?;
    let text =
        serde_json::to_string_pretty(records).map_err(|e| format!("序列化出口历史失败：{e}"))?;
    crate::fsx::write_atomically(&path, &text).map_err(|e| format!("写入出口历史失败：{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(ip: &str, at: i64) -> IpRecord {
        IpRecord {
            ip: ip.to_string(),
            at,
        }
    }

    #[test]
    fn window_is_48_hours_and_inclusive_at_boundary() {
        let now = 1_000_000i64;
        assert!(within_window(now, now));
        assert!(
            within_window(now - WINDOW_HOURS * 3600, now),
            "边界应算在窗口内"
        );
        assert!(!within_window(now - WINDOW_HOURS * 3600 - 1, now));
    }

    #[test]
    fn changes_count_only_when_ip_differs() {
        let now = 1_000_000;
        // 同一 IP 重复出现不算变化。
        assert_eq!(count_changes(&[rec("1.1.1.1", now - 10)], now), 0);
        assert_eq!(
            count_changes(&[rec("1.1.1.1", now - 30), rec("1.1.1.1", now - 20)], now),
            0
        );
        // 两次切换 = 2 次变化。
        assert_eq!(
            count_changes(
                &[
                    rec("1.1.1.1", now - 30),
                    rec("2.2.2.2", now - 20),
                    rec("3.3.3.3", now - 10),
                ],
                now
            ),
            2
        );
    }

    #[test]
    fn records_outside_window_are_ignored() {
        let now = 1_000_000;
        let old = now - WINDOW_HOURS * 3600 - 100;
        // 窗口外的记录不参与「变化」统计。
        assert_eq!(
            count_changes(&[rec("1.1.1.1", old), rec("2.2.2.2", now - 10)], now),
            0
        );
    }

    #[test]
    fn drift_is_reported_at_threshold() {
        let now = 1_000_000;
        let records = vec![
            rec("1.1.1.1", now - 40),
            rec("2.2.2.2", now - 30),
            rec("3.3.3.3", now - 20),
            rec("4.4.4.4", now - 10),
        ];
        let report = evaluate_drift(&records, now);
        assert_eq!(report.changes, 3);
        assert_eq!(report.distinct_ips, 4);
        assert!(report.drifting, "3 次变化应判为漂移");
        assert!(report.note.contains("不稳定"), "{}", report.note);
        // 少量变化不算漂移。
        let calm = evaluate_drift(&records[..2], now);
        assert!(!calm.drifting);
    }

    #[test]
    fn empty_history_is_reported_plainly() {
        let report = evaluate_drift(&[], 1_000_000);
        assert_eq!(report.changes, 0);
        assert!(!report.drifting);
        assert!(report.note.contains("没有出口记录"));
    }

    #[test]
    fn same_ip_returning_does_not_hide_earlier_changes() {
        // 这正是只看「最后一次 IP」的缺陷：切走又切回同一 IP 后，
        // 单值比较会显示「与上次一致」，但历史里其实已经漂移过。
        let now = 1_000_000;
        let records = vec![
            rec("1.1.1.1", now - 40),
            rec("2.2.2.2", now - 30),
            rec("3.3.3.3", now - 20),
            rec("1.1.1.1", now - 10),
        ];
        assert_eq!(
            records.last().map(|r| r.ip.as_str()),
            Some("1.1.1.1"),
            "最后一次与最初相同"
        );
        assert_eq!(count_changes(&records, now), 3, "历史仍要记到 3 次变化");
        assert!(evaluate_drift(&records, now).drifting);
    }
}
