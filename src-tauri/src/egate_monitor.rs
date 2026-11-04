//! 出口门禁的常驻监控循环与暂停守护（融合 ClaudeGuard `src/monitor.rs`）。
//!
//! 手动「立即检查一轮」只解决「我想看一眼」；真正起保护作用的是**定时自动巡检**：
//! 出口漂移往往发生在用户没看界面的时刻。本模块提供：
//! - 按配置间隔（默认 15 秒，5–3600 可调）自动跑一轮；
//! - 暂停守护：暂停期间**照常检测**（状态仍然更新），但绝不执行熔断；
//! - 熔断门控：只有「未暂停 + 已达阈值 + 尚未熔断」才动手。
//!
//! 关键设计：**决策与副作用分离**。`decide()` 是纯函数，调度线程只负责按它的
//! 结论调用 [`crate::egate_trip`]。这样「暂停期间绝不熔断」这条最要紧的语义
//! 可以被单测锁死，而不需要真的去断网。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// 监控间隔下限（秒）——低于它会让探测频率高到没有意义。
pub const MIN_INTERVAL_SECS: u64 = 5;
/// 监控间隔上限（秒）。
pub const MAX_INTERVAL_SECS: u64 = 3600;
/// 调度线程的心跳粒度（毫秒）。
const TICK_MS: u64 = 500;

/// 收敛监控间隔到合法范围。
pub fn clamp_interval(secs: u64) -> u64 {
    secs.clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS)
}

/// 一轮巡检后的动作决定（纯函数输出）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundAction {
    /// 什么都不做（通过 / 无法确认 / 未达阈值 / 已暂停）。
    Idle,
    /// 已达到阈值，应执行熔断。
    Trip,
    /// 只发预警（再失败一次就会熔断）。
    Warn,
}

/// 决定输入。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    /// 本轮是否有目标达到熔断阈值。
    pub threshold_reached: bool,
    /// 是否处于预警点（阈值 - 1 次连续失败）。
    pub at_warning_point: bool,
    /// 是否已暂停守护。
    pub paused: bool,
    /// 是否已经处于熔断状态（避免重复执行）。
    pub already_tripped: bool,
    /// 门禁总开关是否开启。
    pub enabled: bool,
}

/// 决定一轮该做什么。
///
/// 优先级（从高到低）：未启用 > 已暂停 > 已熔断 > 达阈值 > 预警点。
/// 「已暂停」压过一切熔断动作——暂停期间照常检测但不熔断，这是用户显式表达
/// 的意图，任何阈值都不该覆盖它。
pub fn decide(gate: Gate) -> RoundAction {
    if !gate.enabled {
        return RoundAction::Idle;
    }
    if gate.paused {
        return RoundAction::Idle;
    }
    if gate.already_tripped {
        return RoundAction::Idle;
    }
    if gate.threshold_reached {
        return RoundAction::Trip;
    }
    if gate.at_warning_point {
        return RoundAction::Warn;
    }
    RoundAction::Idle
}

/// 暂停截止时间（unix 秒；0 表示未暂停）。
static PAUSED_UNTIL: AtomicU64 = AtomicU64::new(0);
/// 是否已熔断（避免重复执行熔断动作）。
static TRIPPED: AtomicBool = AtomicBool::new(false);
/// 监控线程是否已启动（单例）。
static MONITOR_STARTED: OnceLock<()> = OnceLock::new();

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 暂停守护 `minutes` 分钟（0 或负数按 0 处理，等于立即恢复）。
pub fn pause(minutes: u64) {
    let until = now_secs().saturating_add(minutes.saturating_mul(60));
    PAUSED_UNTIL.store(until, Ordering::SeqCst);
}

/// 立即恢复守护。
pub fn resume() {
    PAUSED_UNTIL.store(0, Ordering::SeqCst);
}

/// 是否处于暂停中（到达截止时间自动视为已恢复）。
pub fn is_paused() -> bool {
    let until = PAUSED_UNTIL.load(Ordering::SeqCst);
    until != 0 && now_secs() < until
}

/// 暂停剩余秒数（未暂停为 0）。
pub fn paused_remaining_secs() -> u64 {
    let until = PAUSED_UNTIL.load(Ordering::SeqCst);
    if until == 0 {
        return 0;
    }
    until.saturating_sub(now_secs())
}

/// 标记已熔断。
pub fn mark_tripped() {
    TRIPPED.store(true, Ordering::SeqCst);
}

/// 清除熔断标记（解除隔离后调用）。
pub fn clear_tripped() {
    TRIPPED.store(false, Ordering::SeqCst);
}

/// 是否已熔断。
pub fn is_tripped() -> bool {
    TRIPPED.load(Ordering::SeqCst)
}

/// 用当前全局状态组装门控输入。
pub fn current_gate(enabled: bool, threshold_reached: bool, at_warning_point: bool) -> Gate {
    Gate {
        threshold_reached,
        at_warning_point,
        paused: is_paused(),
        already_tripped: is_tripped(),
        enabled,
    }
}

/// 启动常驻监控线程（幂等：重复调用不会起第二个）。
///
/// 线程每 [`TICK_MS`] 醒一次，按配置间隔跑一轮；出错只记日志，不退出循环
/// （网络抖动不应该让守护进程自己死掉）。
pub fn start_monitor() {
    if MONITOR_STARTED.set(()).is_err() {
        return;
    }
    std::thread::spawn(|| {
        let mut last_run = 0u64;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(TICK_MS));
            let config = crate::appconfig::load();
            if !config.egate_enabled {
                continue;
            }
            let interval = clamp_interval(config.egate_interval_secs);
            let now = now_secs();
            if now.saturating_sub(last_run) < interval {
                continue;
            }
            last_run = now;
            run_monitor_round(&config);
        }
    });
}

/// 跑一轮监控（含熔断执行）。
fn run_monitor_round(config: &crate::appconfig::AppConfig) {
    let targets = if config.egate_targets.is_empty() {
        crate::egate_defaults::builtin_targets()
    } else {
        config.egate_targets.clone()
    };
    let mut streaks = crate::egate_streaks()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let report = crate::egate_check::run_round(
        &targets,
        &mut streaks,
        config.egate_enforce_access,
        config.egate_trip_threshold,
    );
    drop(streaks);

    let gate = current_gate(config.egate_enabled, report.should_trip, report.should_warn);
    match decide(gate) {
        RoundAction::Trip => {
            let agents = if config.egate_guarded_agents.is_empty() {
                crate::egate_defaults::DEFAULT_GUARDED_AGENTS
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
            } else {
                config.egate_guarded_agents.clone()
            };
            let trip = crate::egate_trip::trip(&agents);
            mark_tripped();
            crate::log_error(&format!(
                "出口门禁已熔断：{}；失败项：{}",
                trip.note,
                report
                    .targets
                    .iter()
                    .filter(|t| t.verdict == crate::egate::Verdict::Fail)
                    .map(|t| t.name.as_str())
                    .collect::<Vec<_>>()
                    .join("、")
            ));
        }
        RoundAction::Warn => {
            crate::log_error(&format!(
                "出口门禁预警：{} 再失败一次将熔断",
                report
                    .targets
                    .iter()
                    .find(|t| t.fail_streak + 1 == report.trip_threshold)
                    .map(|t| t.name.as_str())
                    .unwrap_or("有目标")
            ));
        }
        RoundAction::Idle => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate() -> Gate {
        Gate {
            threshold_reached: false,
            at_warning_point: false,
            paused: false,
            already_tripped: false,
            enabled: true,
        }
    }

    #[test]
    fn disabled_gate_never_acts() {
        let mut g = gate();
        g.enabled = false;
        g.threshold_reached = true;
        assert_eq!(decide(g), RoundAction::Idle, "门禁关闭时绝不能熔断");
    }

    #[test]
    fn paused_overrides_everything() {
        // 暂停期间照常检测但不熔断：即使已达阈值也只 Idle。
        let mut g = gate();
        g.paused = true;
        g.threshold_reached = true;
        assert_eq!(decide(g), RoundAction::Idle, "暂停期间绝不熔断");
        g.at_warning_point = true;
        assert_eq!(decide(g), RoundAction::Idle, "暂停期间也不预警");
    }

    #[test]
    fn already_tripped_does_not_repeat_actions() {
        let mut g = gate();
        g.already_tripped = true;
        g.threshold_reached = true;
        assert_eq!(decide(g), RoundAction::Idle, "已熔断不重复执行");
    }

    #[test]
    fn trip_needs_threshold() {
        let mut g = gate();
        g.at_warning_point = true;
        assert_eq!(decide(g), RoundAction::Warn);
        g.at_warning_point = false;
        g.threshold_reached = true;
        assert_eq!(decide(g), RoundAction::Trip);
    }

    #[test]
    fn healthy_round_is_idle() {
        assert_eq!(decide(gate()), RoundAction::Idle);
    }

    #[test]
    fn interval_is_clamped() {
        assert_eq!(clamp_interval(0), MIN_INTERVAL_SECS, "0 秒会打爆探测");
        assert_eq!(clamp_interval(99_999), MAX_INTERVAL_SECS);
        assert_eq!(clamp_interval(15), 15);
    }

    #[test]
    fn pause_and_resume_round_trip() {
        // 用全局状态做的测试：串行执行，避免与其他用例互相影响。
        resume();
        assert!(!is_paused());
        assert_eq!(paused_remaining_secs(), 0);
        pause(30);
        assert!(is_paused(), "暂停 30 分钟后应在暂停中");
        assert!(paused_remaining_secs() > 29 * 60);
        assert!(paused_remaining_secs() <= 30 * 60);
        resume();
        assert!(!is_paused(), "恢复后立即解除暂停");
        // 0 分钟等价于立即恢复，而不是「暂停到当前时刻」。
        pause(0);
        assert!(!is_paused());
        resume();
    }

    #[test]
    fn tripped_flag_round_trips() {
        clear_tripped();
        assert!(!is_tripped());
        mark_tripped();
        assert!(is_tripped());
        clear_tripped();
        assert!(!is_tripped());
    }

    #[test]
    fn current_gate_reflects_global_state() {
        resume();
        clear_tripped();
        let g = current_gate(true, true, false);
        assert!(!g.paused && !g.already_tripped && g.threshold_reached);
        pause(5);
        mark_tripped();
        let g = current_gate(true, true, false);
        assert!(g.paused && g.already_tripped);
        resume();
        clear_tripped();
    }
}
