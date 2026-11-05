//! 环境一致性检查与账本式对齐（融合 ClaudeGuard `envcheck.rs` / `envfix.rs`）。
//!
//! 动机：出口 IP 换了国家，系统时区/区域却还是原样——这种自相矛盾本身就是
//! 可识别的信号。检查**只提示不熔断**（用户可能就是想保持中文系统）。
//!
//! 对齐（会真正改系统设置）走**账本**：记下改前的值，随时可以一键还原。
//! 这与本项目 [`crate::region`] 的「锁定」不同——锁定是目标态驱动，账本是
//! 「改了什么就记什么」，还原不依赖用户还记得原值。

use serde::{Deserialize, Serialize};

/// 账本文件名（与本项目其它数据同目录）。
pub const LEDGER_FILE: &str = "env-align.json";

/// 已经做过的改动。字段全部可空，兼容旧账本。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppliedEnv {
    /// 改动时间（unix 秒）。
    pub at: u64,
    /// 目标城市（仅展示）。
    pub city: String,
    /// 改前的时区键（空 = 没改过时区）。
    pub tz_from: String,
    /// 改成什么时区（空 = 没改过时区）。
    pub tz_to: String,
}

impl AppliedEnv {
    /// 是否动过时区。
    pub fn touched_tz(&self) -> bool {
        !self.tz_to.is_empty()
    }

    /// 一句话摘要。
    pub fn summary(&self) -> String {
        if self.touched_tz() {
            format!(
                "已把时区从 {} 改为 {}（{}）",
                if self.tz_from.is_empty() {
                    "未知"
                } else {
                    &self.tz_from
                },
                self.tz_to,
                self.city
            )
        } else {
            "未做任何环境改动".to_string()
        }
    }
}

/// 一致性检查结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvCheck {
    /// 系统时区键。
    pub tz_key: String,
    /// 出口国家码（alpha-2）。
    pub egress_country: String,
    /// 出口对应的期望时区键。
    pub expected_tz: String,
    /// 时区是否与出口一致。
    pub tz_match: bool,
    /// 是否不一致（需要提示）。
    pub mismatched: bool,
    /// 说明。
    pub note: String,
}

/// 判定时区是否与出口国家一致（纯函数）。
///
/// 只比时区：区域格式（locale）是否要与出口一致属于用户偏好，本工具不擅自判定
/// ——保持中文系统是完全正当的选择，把它算作「不一致」会造成噪音。
pub fn evaluate(tz_key: &str, egress_country: &str) -> EnvCheck {
    let tz_key = tz_key.trim().to_string();
    // 两路判定，缺一不可：
    // 1. 单时区国家 → 直接比「应有时区」；
    // 2. 多时区国家 → 反过来查「当前时区是否属于该国」。
    // 只有两路都得不出结论时才说「无法判定」——绝不能因为查不到就默认一致
    // （那会让「出口美国、系统时区中国」被判为正常）。
    let expected_tz = crate::region::country_default_windows_tz(egress_country).to_string();
    let belongs = crate::region::timezone_belongs_to_country(&tz_key, egress_country);
    let (tz_match, note) = match (expected_tz.is_empty(), belongs) {
        (false, _) => {
            let matched = tz_key.eq_ignore_ascii_case(&expected_tz);
            let note = if matched {
                format!("系统时区与出口（{egress_country}）一致")
            } else {
                format!("系统时区 {tz_key} 与出口（{egress_country}，应为 {expected_tz}）不一致")
            };
            (matched, note)
        }
        (true, Some(belongs)) => {
            if belongs {
                (
                    true,
                    format!("系统时区 {tz_key} 属于出口国家 {egress_country}"),
                )
            } else if crate::region::is_known_country(egress_country) {
                // 国家已知但不匹配：这才是真正的不一致（例如出口美国、时区中国）。
                (
                    false,
                    format!("系统时区 {tz_key} 不属于出口国家 {egress_country}"),
                )
            } else {
                // 国家码本身无法识别：时区当然「不属于」它，但这不能当成
                // 「环境不一致」去打扰用户——结论应是「无法确认」。
                (
                    true,
                    format!("出口国家码 {egress_country} 无法识别，未做一致性判定"),
                )
            }
        }
        (true, None) => (
            true,
            format!("无法确认系统时区 {tz_key} 是否属于出口国家 {egress_country}，未做一致性判定"),
        ),
    };
    let mismatched = !tz_match;
    EnvCheck {
        note,
        tz_key,
        egress_country: egress_country.to_string(),
        expected_tz,
        tz_match,
        mismatched,
    }
}

fn ledger_path() -> Result<std::path::PathBuf, String> {
    Ok(crate::paths::app_data_dir()?.join(LEDGER_FILE))
}

/// **P0-11**：读账本，严格区分「不存在」「损坏」「正常」。
///
/// - 文件不存在 → `Ok(None)`（确实没有改动）
/// - 文件存在且可解析 → `Ok(Some(...))`
/// - 文件存在但损坏/不可读 → `Err(...)`（**不能**当成「没有改动」）
pub fn load() -> Result<Option<AppliedEnv>, String> {
    let path = ledger_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("读取环境账本失败：{e}"))?;
    let text = crate::jsonio::decode_text(&bytes);
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| format!("环境账本损坏（未清理，可手动修复）：{e}"))
}

fn save(record: &AppliedEnv) -> Result<(), String> {
    let path = ledger_path()?;
    let text =
        serde_json::to_string_pretty(record).map_err(|e| format!("序列化环境账本失败：{e}"))?;
    crate::fsx::write_atomically(&path, &text).map_err(|e| format!("写入环境账本失败：{e}"))
}

fn clear() -> Result<(), String> {
    let path = ledger_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("删除环境账本失败：{error}")),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 把系统时区对齐到出口国家。
///
/// 返回账本记录；无法确定目标时区时返回 `Err`（不给模糊建议）。
pub fn align_timezone(egress_country: &str, city: &str) -> Result<AppliedEnv, String> {
    // **P1-07**：改时区必须与看门狗/急救恢复共用同一把锁。
    let _guard = crate::egate_lock::acquire(crate::egate_lock::SystemOperation::TimezoneWrite)?;
    align_timezone_locked(egress_country, city)
}

/// **P1-07**：已持锁版本。
pub(crate) fn align_timezone_locked(
    egress_country: &str,
    city: &str,
) -> Result<AppliedEnv, String> {
    align_timezone_inner(egress_country, city)
}

fn align_timezone_inner(egress_country: &str, city: &str) -> Result<AppliedEnv, String> {
    let target = crate::region::country_default_windows_tz(egress_country);
    if target.is_empty() {
        return Err(format!(
            "出口国家 {egress_country} 没有可靠的默认时区，未做对齐"
        ));
    }
    let current = crate::platform::imp::current_timezone_id()?;
    if current.eq_ignore_ascii_case(target) {
        return Err("当前时区已与出口一致，无需改动".to_string());
    }
    // 已有账本时先还原，避免把「上次改后的值」当成原值记下来。
    match load() {
        Ok(Some(_)) => {
            restore()?;
        }
        Ok(None) => {}
        Err(error) => {
            // 账本损坏：拒绝覆盖，避免丢失原值。
            return Err(format!("{error}；请先修复或删除环境账本再对齐"));
        }
    }
    let current = crate::platform::imp::current_timezone_id()?;

    // **P1-05：先写账本（记录原时区与计划目标），再改系统。**
    // 如果先改后写，改成功但账本写失败时就无法按原值恢复了。
    let record = AppliedEnv {
        at: now_secs(),
        city: city.to_string(),
        tz_from: current.clone(),
        tz_to: target.to_string(),
    };
    // 先落盘（Prepared 状态即最终记录），写入成功才允许改系统。
    save(&record)?;

    crate::platform::imp::set_timezone_id(target)?;
    // 回读核验：设置接口返回成功不等于真的生效。
    let after = crate::platform::imp::current_timezone_id().unwrap_or_default();
    if !after.eq_ignore_ascii_case(target) {
        // 核验失败：账本已记录原值，restore() 可以还原。
        return Err(format!(
            "时区设置后回读为 {after}，与目标 {target} 不符（原时区已记录，可还原）"
        ));
    }
    Ok(record)
}

/// 按账本还原到改动前的状态（幂等：没有账本时返回 Ok）。
pub fn restore() -> Result<String, String> {
    // **P1-07（v0.7.6）**：所有改系统环境的入口统一走系统操作锁。
    //
    // 原来只有时区看门狗用 `SystemOperation::TimezoneWrite`，而手动地区锁定、
    // 环境对齐/还原都没取锁——三者同时执行会互相覆盖，最后结果取决于
    // 谁后写，而不是「最后一次合法事务」。
    //
    // 已持锁的调用方（`restore_all`）请用 `restore_locked`，否则会自我死锁。
    let guard = crate::egate_lock::acquire(crate::egate_lock::SystemOperation::TimezoneWrite)?;
    restore_locked(&guard)
}

/// **P1-07**：已持锁版本（内部**不再**申请锁，避免自我死锁）。
pub(crate) fn restore_locked(_guard: &crate::egate_lock::OperationGuard) -> Result<String, String> {
    restore_inner()
}

fn restore_inner() -> Result<String, String> {
    // **P0-11**：账本损坏必须报错，不能假装「没有改动」。
    let record = match load()? {
        Some(record) => record,
        None => return Ok("没有需要还原的环境改动".to_string()),
    };
    if record.touched_tz() && !record.tz_from.is_empty() {
        crate::platform::imp::set_timezone_id(&record.tz_from)
            .map_err(|e| format!("还原时区失败：{e}"))?;
        let after = crate::platform::imp::current_timezone_id().unwrap_or_default();
        if !after.eq_ignore_ascii_case(&record.tz_from) {
            return Err(format!(
                "还原后回读时区为 {after}，与账本记录的 {} 不符",
                record.tz_from
            ));
        }
    }
    clear()?;
    Ok(format!("已还原环境（{}）", record.summary()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applying_summary_reports_what_changed() {
        let record = AppliedEnv {
            at: 1,
            city: "洛杉矶".to_string(),
            tz_from: "China Standard Time".to_string(),
            tz_to: "Pacific Standard Time".to_string(),
        };
        assert!(record.touched_tz());
        let summary = record.summary();
        assert!(summary.contains("China Standard Time"));
        assert!(summary.contains("Pacific Standard Time"));
        assert!(summary.contains("洛杉矶"));
        // 空账本不能声称改过任何东西。
        assert!(!AppliedEnv::default().touched_tz());
        assert!(AppliedEnv::default().summary().contains("未做任何"));
    }

    #[test]
    fn matching_timezone_is_not_flagged() {
        let check = evaluate("Pacific Standard Time", "US");
        assert!(check.tz_match);
        assert!(!check.mismatched);
        // 多时区国家走「属于该国家」路径，文案是「属于」，不必强求「一致」二字。
        let note = &check.note;
        assert!(note.contains("属于") || note.contains("一致"), "{note}");
    }

    #[test]
    fn mismatched_timezone_is_flagged_with_both_sides() {
        let check = evaluate("China Standard Time", "US");
        assert!(!check.tz_match);
        assert!(check.mismatched);
        // 提示必须给出实际值，且说明与出口国家不符，用户才知道该怎么改。
        assert!(check.note.contains("China Standard Time"), "{check:?}");
        assert!(check.note.contains("US"), "{check:?}");
    }

    #[test]
    fn unknown_country_is_not_judged() {
        // 没有可靠默认时区的国家：不能硬套一个值去提示用户。
        let check = evaluate("China Standard Time", "ZZ");
        assert!(check.note.contains("未做一致性判定"), "{check:?}");
        assert!(!check.mismatched, "无法判定时不应报不一致");
    }

    #[test]
    fn comparison_is_case_insensitive() {
        let check = evaluate("pacific standard time", "US");
        assert!(check.tz_match, "Windows 时区键比较必须忽略大小写");
    }

    #[test]
    fn ledger_file_name_is_stable() {
        // 还原逻辑依赖这个文件名，改名会让用户改过的设置永远回不去。
        assert_eq!(LEDGER_FILE, "env-align.json");
    }
}
