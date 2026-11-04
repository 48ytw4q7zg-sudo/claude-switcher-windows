//! 出口门禁的桌面通知（融合 ClaudeGuard `src/notify.rs` 的六类语义）。
//!
//! 六类：熔断 / 恢复 / 阻止启动 / 预警 / 客户端更新 / 自身更新。
//! 统一走 `tauri-plugin-notification`（打包后以 bundle id 作 AUMID 正常显示；
//! 开发模式可能显示为宿主身份，属正常现象）。
//!
//! 设计约束：
//! - **发送失败只记日志，绝不让调用方失败**——通知是附加信息，不该影响熔断/启动；
//! - 文案固定简体中文；
//! - 同一类事件短时间内重复触发时由调用方去重（本模块只负责「说什么」）。

use serde::{Deserialize, Serialize};

use crate::egate::Verdict;

/// 通知类别（与上游一一对应）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotifyKind {
    /// 已熔断（结束进程 + 隔离）。
    Trip,
    /// 已恢复（出口正常，隔离解除）。
    Recover,
    /// 出口未通过，启动被阻止。
    LaunchBlocked,
    /// 连续失败预警（再失败一次就熔断）。
    Warning,
    /// 客户端有新版本。
    ClientUpdate,
    /// 本工具自身有新版本。
    SelfUpdate,
}

impl NotifyKind {
    /// 中文标题。
    pub fn title(self) -> &'static str {
        match self {
            NotifyKind::Trip => "出口门禁已熔断",
            NotifyKind::Recover => "出口门禁已恢复",
            NotifyKind::LaunchBlocked => "已阻止启动",
            NotifyKind::Warning => "出口校验未通过",
            NotifyKind::ClientUpdate => "客户端有新版本",
            NotifyKind::SelfUpdate => "账号切换器有新版本",
        }
    }

    /// 从字符串解析（`--notify-test` 用）；未知返回 None。
    pub fn parse(raw: &str) -> Option<NotifyKind> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "trip" => Some(NotifyKind::Trip),
            "recover" => Some(NotifyKind::Recover),
            "launch_blocked" | "launch-blocked" => Some(NotifyKind::LaunchBlocked),
            "warning" => Some(NotifyKind::Warning),
            "client_update" | "client-update" => Some(NotifyKind::ClientUpdate),
            "self_update" | "self-update" => Some(NotifyKind::SelfUpdate),
            _ => None,
        }
    }
}

/// 组装通知正文（纯函数，便于断言文案）。
pub fn body(kind: NotifyKind, detail: &str) -> String {
    let detail = detail.trim();
    match kind {
        NotifyKind::Trip => {
            if detail.is_empty() {
                "出口不符合白名单，已结束相关应用并施加隔离。确认出口正常后可恢复。".to_string()
            } else {
                format!("{detail}；已结束相关应用并施加隔离。确认出口正常后可恢复。")
            }
        }
        NotifyKind::Recover => "出口检查通过，已解除隔离并恢复网络。".to_string(),
        NotifyKind::LaunchBlocked => {
            if detail.is_empty() {
                "出口校验未通过，已阻止启动。".to_string()
            } else {
                format!("{detail}。已阻止启动。")
            }
        }
        NotifyKind::Warning => {
            if detail.is_empty() {
                "再次失败将触发熔断。".to_string()
            } else {
                format!("{detail}；再次失败将触发熔断。")
            }
        }
        NotifyKind::ClientUpdate => {
            if detail.is_empty() {
                "客户端有新版本可用。".to_string()
            } else {
                format!("{detail}。")
            }
        }
        NotifyKind::SelfUpdate => {
            if detail.is_empty() {
                "有新版本可用，可在设置中检查更新。".to_string()
            } else {
                format!("{detail}。")
            }
        }
    }
}

/// 发送一条通知；失败只记日志。
pub fn notify(app: &tauri::AppHandle, kind: NotifyKind, detail: &str) {
    use tauri_plugin_notification::NotificationExt;
    let result = app
        .notification()
        .builder()
        .title(kind.title())
        .body(body(kind, detail))
        .show();
    if let Err(error) = result {
        crate::log_error(&format!("发送出口门禁通知失败（{kind:?}）: {error}"));
    }
}

/// 从一轮检查结果生成预警文案（列出到预警点的目标）。
pub fn warning_detail(report: &crate::egate_check::EgateReport) -> String {
    let names: Vec<&str> = report
        .targets
        .iter()
        .filter(|target| target.fail_streak + 1 == report.trip_threshold)
        .map(|target| target.name.as_str())
        .collect();
    if names.is_empty() {
        String::new()
    } else {
        format!("{} 再次失败将触发熔断", names.join("、"))
    }
}

/// 从一轮检查结果生成熔断文案（列出失败目标）。
pub fn trip_detail(report: &crate::egate_check::EgateReport) -> String {
    let names: Vec<&str> = report
        .targets
        .iter()
        .filter(|target| target.verdict == Verdict::Fail)
        .map(|target| target.name.as_str())
        .collect();
    if names.is_empty() {
        "出口不符合白名单".to_string()
    } else {
        format!("{} 出口不符合白名单", names.join("、"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egate::Overall;
    use crate::egate_check::{EgateReport, TargetReport};

    #[test]
    fn titles_are_chinese_and_distinct() {
        let kinds = [
            NotifyKind::Trip,
            NotifyKind::Recover,
            NotifyKind::LaunchBlocked,
            NotifyKind::Warning,
            NotifyKind::ClientUpdate,
            NotifyKind::SelfUpdate,
        ];
        let mut titles = Vec::new();
        for kind in kinds {
            let title = kind.title();
            assert!(
                title
                    .chars()
                    .any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
                "标题应为中文：{title}"
            );
            assert!(!titles.contains(&title), "标题不能重复：{title}");
            titles.push(title);
        }
    }

    #[test]
    fn kind_parsing_accepts_aliases_and_rejects_unknown() {
        assert_eq!(NotifyKind::parse("trip"), Some(NotifyKind::Trip));
        assert_eq!(
            NotifyKind::parse("launch-blocked"),
            Some(NotifyKind::LaunchBlocked)
        );
        assert_eq!(
            NotifyKind::parse("SELF_UPDATE"),
            Some(NotifyKind::SelfUpdate)
        );
        assert_eq!(NotifyKind::parse("nonsense"), None);
        assert_eq!(NotifyKind::parse(""), None);
    }

    #[test]
    fn bodies_carry_detail_and_stay_chinese() {
        let trip = body(NotifyKind::Trip, "Claude 出口 出口不符合白名单");
        assert!(trip.contains("隔离"));
        assert!(trip.contains("Claude 出口"));
        let blocked = body(NotifyKind::LaunchBlocked, "出口校验未通过：Claude 出口");
        assert!(blocked.contains("已阻止启动"));
        // 空 detail 也要给出完整句子，不能只剩标点。
        for kind in [
            NotifyKind::Trip,
            NotifyKind::LaunchBlocked,
            NotifyKind::Warning,
        ] {
            let text = body(kind, "");
            assert!(text.len() > 6, "{kind:?} 的空详情文案太短：{text}");
            assert!(!text.starts_with('；'), "不能以标点开头：{text}");
        }
    }

    #[test]
    fn details_list_failing_and_warning_targets() {
        let report = EgateReport {
            access: crate::egate_access::AccessInfo::from(
                &crate::egate_access::AccessPath::Uncovered,
            ),
            overall: Overall {
                verdict: Verdict::Fail,
                note: String::new(),
            },
            targets: vec![
                TargetReport {
                    id: "a".to_string(),
                    name: "Claude 出口".to_string(),
                    verdict: Verdict::Fail,
                    reason: String::new(),
                    fail_streak: 1,
                    ip: None,
                    country: None,
                    latency_ms: 0,
                },
                TargetReport {
                    id: "b".to_string(),
                    name: "Codex 出口".to_string(),
                    verdict: Verdict::Pass,
                    reason: String::new(),
                    fail_streak: 0,
                    ip: None,
                    country: None,
                    latency_ms: 0,
                },
            ],
            probed: true,
            skipped_reason: None,
            should_trip: false,
            should_warn: true,
            trip_threshold: 2,
            access_trip: false,
            access_streak: 0,
        };
        assert!(trip_detail(&report).contains("Claude 出口"));
        assert!(
            !trip_detail(&report).contains("Codex"),
            "通过的不能列进失败"
        );
        assert!(warning_detail(&report).contains("Claude 出口"));
    }
}
