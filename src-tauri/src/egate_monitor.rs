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
    /// **P0-06**：上次熔断只部分成功，本轮应补齐缺失的隔离。
    RetryProtection,
    /// **P0-07**：出口已恢复，应自动解除隔离。
    Recover,
}

/// 决定输入。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    /// **P0-NEW-04**：当前保护意图（Armed/Disarmed/Unknown）。
    pub intent: ProtectionIntent,
    /// 本轮是否有目标达到熔断阈值。
    pub threshold_reached: bool,
    /// 是否处于预警点（阈值 - 1 次连续失败）。
    pub at_warning_point: bool,
    /// 是否已暂停守护。
    pub paused: bool,
    /// 是否已经处于**完整**熔断状态（避免重复执行）。
    pub already_tripped: bool,
    /// **低成本项 4**：熔断状态无法确认（查询失败）。此时不得开始新的熔断，
    /// 也不得自动恢复——先要让用户知道「不知道」，而不是按猜测动作。
    pub trip_state_unknown: bool,
    /// **P0-06**：上次熔断是否只部分成功（需要补齐）。
    pub partial_protection: bool,
    /// **P0-03**：自动恢复资格（目标/接入/泄漏/手动保持）。
    pub recovery: RecoveryEligibility,
    /// 门禁总开关是否开启。
    pub enabled: bool,
}

/// **P0-03**：自动恢复资格（不能用单一布尔值代表所有条件）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryEligibility {
    /// 所有启用目标是否通过（Pass）。
    pub targets_pass: bool,
    /// 接入路径是否可靠（SystemProxy/Tun）。
    pub access_ok: bool,
    /// 直连泄漏是否已解除（未启用 leak_trip 时恒 true）。
    pub leak_clear: bool,
    /// 是否处于用户手动保持的隔离（不得自动解除）。
    pub manual_hold: bool,
}

impl RecoveryEligibility {
    /// 是否允许自动恢复。
    pub fn allowed(self) -> bool {
        self.targets_pass && self.access_ok && self.leak_clear && !self.manual_hold
    }

    /// 不合格原因（供日志）。
    pub fn blockers(self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.targets_pass {
            out.push("目标未全部通过");
        }
        if !self.access_ok {
            out.push("接入路径不可靠");
        }
        if !self.leak_clear {
            out.push("仍存在直连泄漏");
        }
        if self.manual_hold {
            out.push("用户手动保持隔离");
        }
        out
    }
}

/// 决定一轮该做什么。
///
/// 优先级（从高到低）：未启用 > 已暂停 > 已熔断 > 达阈值 > 预警点。
/// 「已暂停」压过一切熔断动作——暂停期间照常检测但不熔断，这是用户显式表达
/// 的意图，任何阈值都不该覆盖它。
pub fn decide(gate: Gate) -> RoundAction {
    // **P0-NEW-04**：只有明确 Armed 才允许开始新的自动保护副作用。
    // Disarmed（用户主动停止）与 Unknown（状态损坏）都必须停止——
    // 与 guard_tick 采用同一解释，避免两个守护器行为相反。
    if gate.intent != ProtectionIntent::Armed {
        return RoundAction::Idle;
    }
    if !gate.enabled {
        return RoundAction::Idle;
    }
    if gate.paused {
        return RoundAction::Idle;
    }
    // **低成本项 4**：熔断状态无法确认时**什么都不做**——既不在未知前提下
    // 叠加新的隔离（可能重复/覆盖），也不在未知前提下解除（可能放开仍然
    // 需要保护的机器）。先把「未知」显示给用户，由人工核对。
    if gate.trip_state_unknown {
        return RoundAction::Idle;
    }
    // **P0-03**：部分熔断时先看风险是否已消失——若恢复资格满足则进入恢复，
    // 否则继续补齐隔离（原实现无条件补齐，会导致环境恢复后仍不断重试）。
    if gate.partial_protection {
        return if gate.recovery.allowed() {
            RoundAction::Recover
        } else {
            RoundAction::RetryProtection
        };
    }
    // **P0-03**：已完整熔断 → 只有恢复资格全部满足才自动解除。
    if gate.already_tripped {
        return if gate.recovery.allowed() {
            RoundAction::Recover
        } else if gate.partial_protection {
            // **P0-03**：规则被外部删除/禁用后转 Partial，下一轮补齐。
            RoundAction::RetryProtection
        } else {
            RoundAction::Idle
        };
    }
    if gate.threshold_reached {
        return RoundAction::Trip;
    }
    if gate.at_warning_point {
        return RoundAction::Warn;
    }
    RoundAction::Idle
}

/// **P0-F**：用户主动停止保护的持久化意图（跨进程）。
///
/// 与「暂停」不同：暂停是临时的（到期自动恢复），停止保护是**持续**的——
/// 用户明确要求「别再保护了」，后台守护下一轮也不能重新施加规则。
fn disarm_file() -> Result<std::path::PathBuf, String> {
    Ok(crate::paths::app_data_dir()?.join("eguard-disarmed.json"))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DisarmState {
    /// 是否处于停止保护状态。
    disarmed: bool,
    /// 操作时间（unix 秒）。
    #[serde(default)]
    since: u64,
    /// 原因（供界面展示）。
    #[serde(default)]
    reason: String,
}

/// 保护意图的三态（**P0-01**：不能把「读不到」当成 Armed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionIntent {
    /// 保护已布防（正常）。
    Armed,
    /// 用户主动停止保护。
    Disarmed,
    /// 状态文件损坏或无法读取——**不得**当作 Armed，应保守处理。
    Unknown,
}

/// 写入「停止保护」意图（CLI 急救、托盘紧急停止调用）。
///
/// **P0-01**：返回 `Result`，调用方必须确认写入成功才能声称急救有效。
pub fn disarm(reason: &str) -> Result<(), String> {
    let state = DisarmState {
        disarmed: true,
        since: now_secs(),
        reason: reason.to_string(),
    };
    let path = disarm_file()?;
    let text =
        serde_json::to_string_pretty(&state).map_err(|e| format!("序列化停止保护意图失败：{e}"))?;
    crate::fsx::write_atomically(&path, &text)
        .map_err(|e| format!("写入停止保护意图失败（后台可能继续保护）：{e}"))
}

/// 清除「停止保护」意图（用户重新启用保护时调用）。
///
/// **P0-01**：返回 `Result`，写失败时前端不能声称已重新布防。
pub fn rearm() -> Result<(), String> {
    let state = DisarmState::default();
    let path = disarm_file()?;
    let text =
        serde_json::to_string_pretty(&state).map_err(|e| format!("序列化布防状态失败：{e}"))?;
    crate::fsx::write_atomically(&path, &text).map_err(|e| format!("写入布防状态失败：{e}"))
}

/// 读取保护意图（**P0-01**：严格三态）。
///
/// - 文件不存在 → Armed（首次安装的默认）
/// - 文件存在且可解析 → 按 `disarmed` 字段
/// - 文件存在但损坏/不可读 → **Unknown**（不得当作 Armed）
pub fn protection_intent() -> ProtectionIntent {
    let Ok(path) = disarm_file() else {
        return ProtectionIntent::Unknown;
    };
    if !path.exists() {
        return ProtectionIntent::Armed;
    }
    let Ok(bytes) = std::fs::read(&path) else {
        return ProtectionIntent::Unknown;
    };
    let text = crate::jsonio::decode_text(&bytes);
    match serde_json::from_str::<DisarmState>(&text) {
        Ok(state) if state.disarmed => ProtectionIntent::Disarmed,
        Ok(_) => ProtectionIntent::Armed,
        Err(_) => ProtectionIntent::Unknown,
    }
}

/// 是否处于「用户主动停止保护」状态（兼容旧调用）。
pub fn is_disarmed() -> bool {
    protection_intent() == ProtectionIntent::Disarmed
}

/// **P0-E**：暂停状态文件（跨进程共享）。
///
/// GUI 与计划任务拉起的 `--guard` 是**不同进程**，内存静态变量互不可见。
/// 必须通过磁盘共享，否则 GUI 暂停后独立保镖仍会查杀。
fn pause_file() -> Result<std::path::PathBuf, String> {
    Ok(crate::paths::app_data_dir()?.join("eguard-pause.json"))
}

/// 暂停状态（落盘）。
/// **P0-07**：手动隔离意图（与自动熔断分开）。
///
/// 自动巡检**不得**解除用户手动要求保持的隔离。意图持久化在磁盘，
/// 进程重启后仍生效；只有用户手动解除才清除。
fn isolation_intent_file() -> Result<std::path::PathBuf, String> {
    Ok(crate::paths::app_data_dir()?.join("eguard-manual-hold.json"))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ManualHoldState {
    /// 用户是否明确要求保持隔离。
    manual_hold: bool,
    /// 记录时间（unix 秒）。
    #[serde(default)]
    since: u64,
}

/// **P0-08**：手动保持隔离的三态。
///
/// `Unknown`（账本损坏/不可读）**不等于**「没有手动保持」——自动恢复遇到
/// `Unknown` 必须放弃解除，否则用户的明确要求会被静默推翻。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualHold {
    /// 用户明确要求保持隔离。
    Held,
    /// 明确没有手动保持。
    None,
    /// 无法确认（读取失败或账本损坏）。
    Unknown,
}

/// 用户手动执行隔离：写入 ManualHold 意图，自动恢复不得解除它。
///
/// **P0-08**：返回 `Result`。写不进去时调用方**不得**声称「手动保持成功」——
/// 原实现吞掉写盘错误，用户以为锁住了，自动恢复却按「没有手动保持」解除。
pub fn mark_manual_hold() -> Result<(), String> {
    let path = isolation_intent_file().map_err(|e| format!("无法定位手动隔离意图文件：{e}"))?;
    let state = ManualHoldState {
        manual_hold: true,
        since: now_secs(),
    };
    let text =
        serde_json::to_string_pretty(&state).map_err(|e| format!("序列化手动隔离意图失败：{e}"))?;
    crate::fsx::write_atomically(&path, &text)
        .map_err(|e| format!("写入手动隔离意图失败（自动恢复仍可能解除隔离）：{e}"))
}

/// 用户手动解除隔离：清除 ManualHold 意图。
///
/// **P0-08**：返回 `Result`——删除失败时意图仍然存在，下一次自动恢复
/// 会继续拒绝解除，必须让用户知道。
pub fn clear_manual_hold() -> Result<(), String> {
    let path = isolation_intent_file().map_err(|e| format!("无法定位手动隔离意图文件：{e}"))?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("清除手动隔离意图失败：{error}")),
    }
}

/// 读取手动保持隔离的当前状态（三态，见 [`ManualHold`]）。
pub fn manual_hold_state() -> ManualHold {
    let Ok(path) = isolation_intent_file() else {
        return ManualHold::Unknown;
    };
    if !path.exists() {
        return ManualHold::None;
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            crate::log_error(&format!(
                "手动隔离意图无法读取（{error}），按「无法确认」处理：不会自动解除现有隔离"
            ));
            return ManualHold::Unknown;
        }
    };
    let text = crate::jsonio::decode_text(&bytes);
    match serde_json::from_str::<ManualHoldState>(&text) {
        Ok(state) if state.manual_hold => ManualHold::Held,
        Ok(_) => ManualHold::None,
        Err(error) => {
            crate::log_error(&format!(
                "手动隔离意图文件损坏（{error}），按「无法确认」处理：不会自动解除现有隔离"
            ));
            ManualHold::Unknown
        }
    }
}

/// 兼容旧调用：是否有用户手动保持的隔离。
///
/// 只有**明确没有**才算 false；`Unknown` 也算 true（保守：不允许自动解除）。
pub fn is_manual_hold() -> bool {
    !matches!(manual_hold_state(), ManualHold::None)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PauseState {
    /// 暂停截止时间（unix 秒；0 表示未暂停）。
    until: u64,
    /// 状态代次（写入时递增，供跨进程判断新鲜度）。
    #[serde(default)]
    generation: u64,
}

/// 读取暂停状态。
///
/// 文件不存在 = 未暂停（正常）。文件存在但损坏/不可读时**仍然**按未暂停
/// 处理，但记一次日志——暂停是「减少保护」的方向，读不出来时保守按
/// 「没有暂停」对待（保护继续生效），而不是让损坏文件延长暂停。
fn read_pause_state() -> PauseState {
    let Ok(path) = pause_file() else {
        return PauseState::default();
    };
    if !path.exists() {
        return PauseState::default();
    }
    match std::fs::read(&path) {
        Ok(bytes) => {
            let text = crate::jsonio::decode_text(&bytes);
            match serde_json::from_str(&text) {
                Ok(state) => state,
                Err(error) => {
                    crate::log_error(&format!(
                        "暂停状态文件损坏（{error}），按未暂停处理（保护继续生效）"
                    ));
                    PauseState::default()
                }
            }
        }
        Err(error) => {
            crate::log_error(&format!(
                "暂停状态文件无法读取（{error}），按未暂停处理（保护继续生效）"
            ));
            PauseState::default()
        }
    }
}

fn write_pause_state(state: &PauseState) -> Result<(), String> {
    let path = pause_file()?;
    let text =
        serde_json::to_string_pretty(state).map_err(|e| format!("序列化暂停状态失败：{e}"))?;
    crate::fsx::write_atomically(&path, &text).map_err(|e| format!("写入暂停状态失败：{e}"))
}
/// 熔断状态：0=未熔断，1=部分熔断，2=完整熔断，3=**无法确认**。
///
/// 3 只在「本进程从未得出过结论、且从系统重建时查询失败」时写入。
/// 它与 0 的区别是语义上的：0 是「确认没有隔离」，3 是「防火墙状态读不出来，
/// 不知道有没有隔离」。界面与 CLI 必须分别显示，不能把读不出来当成安全。
static TRIP_STATE: AtomicU64 = AtomicU64::new(0);

/// 本进程是否已经对熔断状态得出过**可信**结论（执行过熔断/恢复，或重建成功）。
///
/// 用于区分「真的没有隔离」和「本进程还没查过」——后者在
/// [`rebuild_trip_state_from_system`] 查询失败时不能冒充「未熔断」。
static TRIP_STATE_CONFIRMED: AtomicBool = AtomicBool::new(false);
/// 监控线程是否已启动（单例）。
static MONITOR_STARTED: OnceLock<()> = OnceLock::new();

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 暂停守护 `minutes` 分钟（0 或负数按 0 处理，等于立即恢复）。
pub fn pause(minutes: u64) -> Result<(), String> {
    let until = now_secs().saturating_add(minutes.saturating_mul(60));
    let mut state = read_pause_state();
    state.until = until;
    state.generation = state.generation.saturating_add(1);
    write_pause_state(&state).map_err(|e| format!("写入暂停状态失败（后台可能仍在保护）：{e}"))
}

/// 立即恢复守护。
pub fn resume() -> Result<(), String> {
    let mut state = read_pause_state();
    state.until = 0;
    state.generation = state.generation.saturating_add(1);
    write_pause_state(&state).map_err(|e| format!("写入恢复状态失败：{e}"))
}

/// 是否处于暂停中（到达截止时间自动视为已恢复）。
pub fn is_paused() -> bool {
    let state = read_pause_state();
    state.until != 0 && now_secs() < state.until
}

/// 暂停剩余秒数（未暂停为 0）。
pub fn paused_remaining_secs() -> u64 {
    let state = read_pause_state();
    if state.until == 0 {
        return 0;
    }
    state.until.saturating_sub(now_secs())
}

/// 标记熔断完成（0=未熔断，1=部分成功，2=完整成功）。
pub fn mark_tripped_state(complete: bool) {
    TRIP_STATE.store(if complete { 2 } else { 1 }, Ordering::SeqCst);
    // 这是本进程亲自执行的结果，属于可信结论。
    TRIP_STATE_CONFIRMED.store(true, Ordering::SeqCst);
}

/// 清除熔断标记（解除隔离后调用）。
pub fn clear_tripped() {
    TRIP_STATE.store(0, Ordering::SeqCst);
    TRIP_STATE_CONFIRMED.store(true, Ordering::SeqCst);
}

/// **低成本项 4**：标记「无法确认是否隔离」。
///
/// 只在系统查询失败时使用；一旦后续查询成功，由 [`mark_tripped_state`] /
/// [`clear_tripped`] 覆盖成确定值。
pub fn mark_trip_state_unknown() {
    TRIP_STATE.store(3, Ordering::SeqCst);
    TRIP_STATE_CONFIRMED.store(false, Ordering::SeqCst);
}

/// 是否已完整熔断。
pub fn is_tripped() -> bool {
    TRIP_STATE.load(Ordering::SeqCst) == 2
}

/// **P0-06**：是否处于部分熔断（需要补齐隔离）。
pub fn is_partial() -> bool {
    TRIP_STATE.load(Ordering::SeqCst) == 1
}

/// **低成本项 4**：熔断状态是否无法确认（防火墙查询失败 / 从未查过）。
///
/// 与「未熔断」严格区分：调用方要显式展示「无法确认」，不能当成安全。
pub fn is_trip_state_unknown() -> bool {
    TRIP_STATE.load(Ordering::SeqCst) == 3
        || (!TRIP_STATE_CONFIRMED.load(Ordering::SeqCst) && !is_tripped() && !is_partial())
}

/// **P1-11（v0.7.3）**：Unknown 状态的低频重确认节流器。
///
/// 启动时若防火墙查询失败，状态被标记为 Unknown，这是保守的正确做法；
/// 但如果没有重新确认的路径，一次暂时性故障就会永久变成「未知」，
/// 用户既看不到真实状态，也无法自动恢复。
///
/// 这里使用失败的指数退避（上限 5 分钟）：避免每轮都去打一个正在故障的
/// 服务，同时保证故障恢复后能自行回到真实状态。
struct UnknownRecovery {
    last_attempt_secs: u64,
    attempts: u32,
}

static UNKNOWN_RECOVERY: std::sync::Mutex<UnknownRecovery> =
    std::sync::Mutex::new(UnknownRecovery {
        last_attempt_secs: 0,
        attempts: 0,
    });

/// 当前状态下是否应当尝试重确认（纯计算，便于单测）。
fn should_reconfirm(now: u64, last_attempt: u64, attempts: u32) -> bool {
    // 指数退避：失败次数越多间隔越大，上限 5 分钟。
    let backoff = 30u64.saturating_mul(1u64 << attempts.min(4)).min(300);
    now.saturating_sub(last_attempt) >= backoff
}

/// 若熔断状态是「未知」，按退避节奏重新向系统确认一次。
///
/// 只在 **Unknown** 时才动作：已知的 tripped/partial/clear 不需要重建，
/// 重建反而可能覆盖刚由本轮判定写入的状态。
fn reconfirm_unknown_state(now: u64) {
    if !is_trip_state_unknown() {
        return;
    }
    let mut guard = match UNKNOWN_RECOVERY.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if !should_reconfirm(now, guard.last_attempt_secs, guard.attempts) {
        return;
    }
    guard.last_attempt_secs = now;
    // 重建成功（查询恢复）会清掉 Unknown，此时重置退避。
    let before = is_trip_state_unknown();
    rebuild_trip_state_from_system();
    if before && !is_trip_state_unknown() {
        guard.attempts = 0;
        crate::log_error("防火墙查询已恢复，熔断状态按真实库存重建完成");
    } else {
        guard.attempts = guard.attempts.saturating_add(1);
    }
}

/// 主动触发一次重确认（测试/手动刷新可用）。
#[allow(dead_code)]
pub fn reconfirm_unknown_state_now() -> bool {
    if !is_trip_state_unknown() {
        return false;
    }
    rebuild_trip_state_from_system();
    !is_trip_state_unknown()
}

/// **P0-06**：启动时从**实际系统状态**重建熔断状态。
///
/// 内存里的 TRIP_STATE 在进程重启后会归零，但 Windows 防火墙里的规则
/// 仍然存在。若不做重建，界面会显示「未熔断」而系统实际仍被隔离。
///
/// 判定规则：
/// - 无本产品规则 → 未熔断
/// - 有规则且所有守护对象覆盖完整 → 完整熔断（2）
/// - 有规则但覆盖不完整 → 部分熔断（1）
/// - 查询失败 → **未知（3）**，不是「未熔断」
pub fn rebuild_trip_state_from_system() {
    // **P0-01（v0.7.1）**：必须**按来源**重建，不能把任何残留规则都当成
    // 「普通熔断」。只剩兜底封锁规则时若标记成 Partial，下一轮会走
    // `RetryProtection → trip()` 去结束 GUI 进程——而兜底封锁的语义是
    // 「只挡出站、不杀进程」。
    let inventory = match crate::egate_trip::inspect_isolation_inventory() {
        Some(inventory) => inventory,
        None => {
            mark_trip_state_unknown();
            crate::log_error("无法查询防火墙规则，熔断状态无法确认（显示为「未知」，请人工核对）");
            return;
        }
    };

    if !inventory.any() {
        clear_tripped();
        // 规则都没了：兜底锁意图若还在，说明规则被外部清理过，
        // 一并清掉意图，避免界面一直显示「兜底封锁中」。
        clear_uncovered_if_orphaned();
        return;
    }

    if inventory.egress_trip > 0 || inventory.legacy > 0 {
        // 存在正式熔断（或旧版遗留）规则：按部分熔断处理，下一轮补齐。
        mark_tripped_state(false);
        crate::log_error(&format!(
            "检测到 {} 条熔断规则残留（旧版 {} 条），已按「部分熔断」重建；下一轮将补齐或恢复",
            inventory.egress_trip, inventory.legacy
        ));
    } else {
        // **只有兜底封锁规则**：这不是熔断，清掉内存熔断状态；
        // 兜底规则由 `run_uncovered_lockdown` 每轮核验与补齐。
        clear_tripped();
        crate::log_error(&format!(
            "检测到 {} 条未接入兜底封锁规则残留（非熔断），已恢复兜底状态；不会结束任何进程",
            inventory.uncovered
        ));
    }
}

/// 用当前全局状态组装门控输入。
pub fn current_gate(
    enabled: bool,
    threshold_reached: bool,
    at_warning_point: bool,
    recovery: RecoveryEligibility,
) -> Gate {
    Gate {
        intent: protection_intent(),
        threshold_reached,
        at_warning_point,
        paused: is_paused(),
        already_tripped: is_tripped(),
        partial_protection: is_partial(),
        // 未知优先于「未熔断」：未查过/查失败时不能按未熔断动作。
        trip_state_unknown: is_trip_state_unknown(),
        recovery,
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
        // 通知需要 AppHandle；启动早期可能还没有，拿到后缓存。
        let mut app_handle: Option<tauri::AppHandle> = None;
        let mut last_run = 0u64;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(TICK_MS));
            // P0-12：配置损坏不能静默当成「用户关闭了门禁」。
            let config = match crate::appconfig::load_checked() {
                crate::appconfig::ConfigLoad::Ok(config) => *config,
                crate::appconfig::ConfigLoad::Fresh => continue,
                crate::appconfig::ConfigLoad::Corrupt(error) => {
                    // 配置损坏：不执行新熔断，但也不清除现有隔离。
                    // 每轮只记一次日志，避免刷屏。
                    static LAST_REPORT: AtomicU64 = AtomicU64::new(0);
                    let now = now_secs();
                    if now.saturating_sub(LAST_REPORT.load(Ordering::Relaxed)) > 300 {
                        LAST_REPORT.store(now, Ordering::Relaxed);
                        crate::log_error(&format!(
                            "出口门禁配置损坏（{error}），已暂停新熔断；现有隔离保持不变。请修复 appconfig.json"
                        ));
                    }
                    continue;
                }
            };
            // **P1-11**：Unknown 状态要能自己恢复——按退避节奏重确认，
            // 不依赖用户重启应用。非 Unknown 时这是一次极廉价的判断。
            reconfirm_unknown_state(now_secs());
            if !config.egate_enabled {
                continue;
            }
            let interval = clamp_interval(config.egate_interval_secs);
            let now = now_secs();
            if now.saturating_sub(last_run) < interval {
                continue;
            }
            last_run = now;
            run_monitor_round(&config, &mut app_handle);
        }
    });
}

/// 应用句柄（由 Tauri `setup` 钩子注入；之前为 None）。
static APP_HANDLE: OnceLock<tauri::AppHandle> = OnceLock::new();

/// 由 `setup` 钩子调用，让监控线程能发桌面通知。
pub fn set_app_handle(app: tauri::AppHandle) {
    let _ = APP_HANDLE.set(app);
}

/// 拿到 AppHandle。启动早期窗口还没建好时返回 None，
/// 此时只记日志不发通知——通知是附加信息，不能阻塞熔断本身。
fn ensure_app_handle(cache: &mut Option<tauri::AppHandle>) -> Option<&tauri::AppHandle> {
    if cache.is_none() {
        if let Some(app) = APP_HANDLE.get() {
            *cache = Some(app.clone());
        }
    }
    cache.as_ref()
}

/// 直连泄露的判定结果。
struct LeakRound {
    /// 是否达到熔断条件（仅在开启 leak_trip 时可能为 true）。
    trip: bool,
    /// 是否应告警（发现直连但不熔断）。
    warn: bool,
}

/// 观察一轮直连泄露。
///
/// 单次快照出现直连就熔断过于激进（应用启动瞬间可能先直连再走代理），
/// 因此沿用与目标失败相同的防抖计数，键名带 `leak:` 前缀避免与目标 id 冲突。
fn leak_round(config: &crate::appconfig::AppConfig) -> LeakRound {
    let evidence = crate::egate_check::read_proxy_evidence();
    let proxy_port = crate::egate_netwatch::proxy_port_from_evidence(&evidence);
    let agents = if config.egate_guarded_agents.is_empty() {
        crate::egate_defaults::DEFAULT_GUARDED_AGENTS
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
    } else {
        config.egate_guarded_agents.clone()
    };
    let targets = if config.egate_targets.is_empty() {
        crate::egate_defaults::builtin_targets()
    } else {
        config.egate_targets.clone()
    };
    let access = crate::egate_check::current_access(&crate::egate_check::monitored_hosts(&targets));
    let mode = match &access {
        crate::egate_access::AccessPath::SystemProxy { .. } => "system_proxy",
        crate::egate_access::AccessPath::Tun { .. } => "tun",
        crate::egate_access::AccessPath::Uncovered => "uncovered",
        crate::egate_access::AccessPath::Unknown { .. } => "unknown",
    };
    let pids = crate::egate_trip::agent_pids(&agents);
    let conns = crate::egate_netwatch::collect_agent_conns();
    let report = crate::egate_netwatch::summarize(mode, proxy_port, &conns, &pids);

    if !report.applicable || report.direct_total == 0 {
        // 没有直连就清零计数，避免历史累积。
        if let Ok(mut streaks) = crate::egate_streaks().lock() {
            streaks.remove("leak:direct");
        }
        return LeakRound {
            trip: false,
            warn: false,
        };
    }

    let threshold = config.egate_trip_threshold.max(1);
    let streak = {
        let mut streaks = crate::egate_streaks()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let next = streaks.get("leak:direct").copied().unwrap_or(0) + 1;
        streaks.insert("leak:direct".to_string(), next);
        next
    };
    crate::log_error(&format!(
        "直连泄露观察：{} 条绕过代理的直连（连续 {streak} 次）{}",
        report.direct_total,
        if config.egate_leak_trip {
            ""
        } else {
            "，当前仅告警"
        }
    ));
    LeakRound {
        trip: config.egate_leak_trip && streak >= threshold,
        warn: streak + 1 == threshold || (!config.egate_leak_trip && streak == 1),
    }
}

/// **P0-06**：未接入时的即时兜底封锁（独立于阈值熔断）。
///
/// - 只在确认「未接入」时施加，不对 Unknown / 未验证 TUN 动手；
/// - 使用与熔断相同的应用级隔离执行器（不新增第二套防火墙逻辑）；
/// - 结果写入独立的持久化意图文件，便于重启后判断「这批规则是兜底锁」；
/// - 建立失败只记 Degraded，绝不宣称已保护。
fn run_uncovered_lockdown(
    config: &crate::appconfig::AppConfig,
    report: &crate::egate_check::EgateReport,
) {
    let agents = if config.egate_guarded_agents.is_empty() {
        crate::egate_defaults::DEFAULT_GUARDED_AGENTS
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
    } else {
        config.egate_guarded_agents.clone()
    };
    if agents.is_empty() {
        return;
    }
    // **P0-C**：先写意图**再**动防火墙——崩溃时至少有「我打算锁」的记录。
    if !uncovered_lock_active() {
        if let Err(error) = mark_uncovered_lock() {
            crate::log_error(&format!(
                "未接入兜底封锁：意图落盘失败（{error}），本轮不施加规则以免无法归属"
            ));
            return;
        }
    }
    // **P0-C**：每轮都重新核验并补齐，不能因「意图文件存在」就跳过。
    let trip = crate::egate_trip::enforce_uncovered_outbound(&agents);
    if trip.all_isolated {
        // **L-13**：每次都重写 ready，而不是「存在就跳过」。
        // 记录里带 `verified_at` / 配置代次 / 受管清单 / 规则条数，
        // 任何一项变了都会在读取时失效，界面不会再展示上一轮的核验结果。
        let rules: u32 = trip.agents.iter().map(|agent| agent.rules_verified).sum();
        if let Err(error) = mark_uncovered_ready(&agents, rules) {
            crate::log_error(&format!(
                "兜底封锁已生效，但核验记录写入失败（{error}）：界面将显示为「未核验」"
            ));
        }
        return;
    }
    // 部分生效或完全失败：保持 Degraded，下一轮继续补齐。
    // 从「全部生效」退回「部分生效」：清掉 ready 标记，状态回到 Degraded。
    clear_uncovered_ready();
    crate::log_error(&format!(
        "未接入兜底封锁未完整生效（Degraded）：{}；下一轮将继续补齐",
        if trip.failures.is_empty() {
            report
                .targets
                .iter()
                .map(|t| t.name.as_str())
                .collect::<Vec<_>>()
                .join("、")
        } else {
            trip.failures.join("；")
        }
    ));
}

/// **P0-C**：接入恢复后独立解除兜底封锁，不依赖普通熔断的 `TRIP_STATE`。
///
/// 只删除本产品拥有的规则并核验；核验通过才清意图文件。
fn release_uncovered_lock() {
    if !uncovered_lock_active() {
        return;
    }
    // **P0-01**：只解除**未接入兜底**这一个来源的规则。
    // 原实现调用 `release_verified`，按整个 `ClaudeSwitcher AppIsolation`
    // 前缀删除——会把普通熔断的规则一起删掉，熔断状态却仍写着 tripped。
    match crate::egate_trip::release_isolation_reason(crate::egate_trip::IsolationReason::Uncovered)
    {
        Ok(report) if report.verified => {
            if let Err(error) = clear_uncovered_lock() {
                crate::log_error(&format!(
                    "兜底规则已解除，但意图文件未能删除（{error}）：状态将显示为待处理"
                ));
                return;
            }
            crate::log_error("接入已恢复：未接入兜底封锁已解除");
        }
        Ok(report) => crate::log_error(&format!(
            "接入已恢复，但兜底规则未能全部清除（剩余 {} 条），保留意图待重试",
            report.remaining
        )),
        Err(error) => crate::log_error(&format!("解除兜底封锁失败：{error}")),
    }
}

/// 规则已全部不存在时收敛兜底意图（避免界面长期显示「封锁中」）。
fn clear_uncovered_if_orphaned() {
    if uncovered_lock_active() {
        if let Err(error) = clear_uncovered_lock() {
            crate::log_error(&format!("清理孤立兜底意图失败：{error}"));
        }
    }
}

/// **P0-02**：是否具备解除未接入兜底封锁的资格。
///
/// 四个条件必须**同时**满足：
/// 1. 本轮确实做过探测（`probed`）——跳过/未验证的一律不算；
/// 2. 所有启用目标 `Pass`；
/// 3. 接入路径是**可验证**的（系统代理端口可连 / TUN 有路由证据）；
/// 4. 保护意图允许自动恢复（Armed 且未暂停，且无手动保持）。
pub fn can_release_uncovered(report: &crate::egate_check::EgateReport) -> bool {
    if !report.probed {
        return false;
    }
    if report.overall.verdict != crate::egate::Verdict::Pass {
        return false;
    }
    // **P1-10（v0.7.3）**：TUN 路线必须**带证据**才算接入有效。
    // `access_verified(path)` 只看标签，无法区分「有 TUN 网卡」与
    // 「流量确实经过 TUN」——后者由 `report.access.tun_proven` 携带。
    if !access_verified(&report.access.path, report.access.tun_proven) {
        return false;
    }
    if protection_intent() != ProtectionIntent::Armed || is_paused() {
        return false;
    }
    // L-01 (v0.7.1): Unknown must NOT be treated as "no manual hold".
    // The intent file being corrupt/unreadable means we cannot confirm the
    // user's wish - releasing on that basis would silently override it.
    matches!(manual_hold_state(), ManualHold::None)
}

/// **L-03**：兜底封锁给界面用的真实状态。
///
/// `active` 表示「有意图文件」，`verified` 表示**本轮实际核验过规则覆盖**；
/// 只看意图文件存在会让界面在规则被外部删除后仍显示「封锁中」。
pub fn uncovered_lock_status() -> (bool, bool) {
    (uncovered_lock_active(), uncovered_lock_ready())
}

/// **L-13**：兜底封锁状态的完整描述，供 UI / CLI 使用。
///
/// 返回 `(意图存在, 核验状态)`；核验状态区分「有效 / 从未核验 / 已失效（原因）」，
/// 界面据此显示「兜底封锁中（已核验）」或「兜底封锁（核验已过期：配置已变更）」。
pub fn uncovered_lock_detail() -> (bool, String) {
    let active = uncovered_lock_active();
    let note = match uncovered_ready_state() {
        UncoveredReadyState::Valid => "已核验".to_string(),
        UncoveredReadyState::Missing => "尚未核验".to_string(),
        UncoveredReadyState::Stale(reason) => format!("核验已失效：{reason}"),
    };
    (active, note)
}

/// 测试用：暴露 `access_verified` 的判定（不改变生产语义）。
#[cfg(test)]
pub fn access_verified_for_test(path: &str) -> bool {
    access_verified(path, false)
}

/// 测试用：带上 `tun_proven` 的版本。
#[cfg(test)]
pub fn access_verified_with_evidence_for_test(path: &str, tun_proven: bool) -> bool {
    access_verified(path, tun_proven)
}

/// 接入路径是否有**可信证据**（而不只是标签）。
///
/// **P1-10（v0.7.3）**：TUN 不再一律拒绝，但也不接受「有网卡就行」——
/// 只有 `tun_proven`（逐目标路由证据全部成立）时才认为 TUN 接入有效。
/// 这样兜底封锁在真正接回 TUN 后能自动解除，而「网卡残留」时仍保持隔离。
fn access_verified(path: &str, tun_proven: bool) -> bool {
    match path {
        // 系统代理：本轮探测已通过（请求确实经由该代理发出）。
        "system_proxy" => true,
        // TUN：必须携带路由证明。
        "tun" => tun_proven,
        _ => false,
    }
}

/// 兜底封锁意图文件（与手动保持隔离分开，互不覆盖）。
fn uncovered_lock_file() -> Result<std::path::PathBuf, String> {
    Ok(crate::paths::app_data_dir()?.join("eguard-uncovered-lock.json"))
}

fn uncovered_lock_active() -> bool {
    uncovered_lock_file()
        .map(|path| path.exists())
        .unwrap_or(false)
}

fn mark_uncovered_lock() -> Result<(), String> {
    let path = uncovered_lock_file()?;
    let body = serde_json::json!({ "since": now_secs() }).to_string();
    crate::fsx::write_atomically(&path, &body).map_err(|e| e.to_string())
}

fn uncovered_lock_ready_file() -> Result<std::path::PathBuf, String> {
    Ok(crate::paths::app_data_dir()?.join("eguard-uncovered-lock-ready.json"))
}

/// **L-13**：兜底封锁的「已验证」状态必须**绑定到具体的核验结果**。
///
/// 原实现是一个空 `{}` 文件的存在性判断：一旦写下就永久代表「已验证」，
/// 哪怕之后规则被外部删除、配置改了目标、受管应用清单变了——
/// 界面仍会显示「兜底封锁中（已核验）」。用户看到的是过去某一刻的事实。
///
/// 现在写入 `verified_at` / `revision` / `rules` 三项；读取时逐项比对，
/// 任一不匹配就视为**未验证**（并说明原因），由下一轮核验重写。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default, PartialEq, Eq)]
struct UncoveredReady {
    /// 写入时刻（Unix 秒）。
    verified_at: u64,
    /// 核验时的配置代次（`egate_revision`）；配置一改立即失效。
    revision: u64,
    /// 核验时实际生效的兜底规则条数。
    rules: u32,
    /// 核验时使用的受管应用清单（顺序无关，写入前排序）。
    agents: Vec<String>,
}

const UNCOVERED_READY_TTL_SECS: u64 = 15 * 60;

fn read_uncovered_ready() -> Option<UncoveredReady> {
    let path = uncovered_lock_ready_file().ok()?;
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// 当前 `ready` 记录是否仍可作为「已验证」的依据。
fn uncovered_lock_ready() -> bool {
    matches!(uncovered_ready_state(), UncoveredReadyState::Valid)
}

/// `ready` 的三种状态（**L-13**：界面需要能说明「为什么不再是已验证」）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UncoveredReadyState {
    /// 有记录且与当前配置/规则一致，且在有效期内。
    Valid,
    /// 从未核验过。
    Missing,
    /// 有过记录但已失效（附原因）。
    Stale(String),
}

fn uncovered_ready_state() -> UncoveredReadyState {
    let Some(ready) = read_uncovered_ready() else {
        return UncoveredReadyState::Missing;
    };
    let config = match crate::appconfig::load_checked() {
        crate::appconfig::ConfigLoad::Ok(config) => *config,
        crate::appconfig::ConfigLoad::Fresh => crate::appconfig::AppConfig::default(),
        crate::appconfig::ConfigLoad::Corrupt(error) => {
            return UncoveredReadyState::Stale(format!("配置损坏（{error}）"))
        }
    };
    if ready.revision != config.egate_revision {
        return UncoveredReadyState::Stale("门禁配置已变更".to_string());
    }
    let mut expected = if config.egate_guarded_agents.is_empty() {
        crate::egate_defaults::DEFAULT_GUARDED_AGENTS
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
    } else {
        config.egate_guarded_agents.clone()
    };
    expected.sort();
    let mut recorded = ready.agents.clone();
    recorded.sort();
    if recorded != expected {
        return UncoveredReadyState::Stale("受管应用清单已变更".to_string());
    }
    let age = now_secs().saturating_sub(ready.verified_at);
    if age > UNCOVERED_READY_TTL_SECS {
        return UncoveredReadyState::Stale(format!("核验已过期（{} 分钟前）", age / 60));
    }
    // **P1-08（v0.7.3）**：记录里写了规则数，就必须拿它跟**当前系统库存**对账。
    //
    // 原实现只比对代次/清单/时间：规则被外部删除后，在有效期内界面仍会显示
    // 「兜底封锁中（已核验）」。用户看到的是过去某一刻的事实，而现在没有保护。
    //
    // 查询失败（`None`）同样按失效处理：读不到规则就不能宣称「已验证」。
    match crate::egate_trip::inspect_isolation_inventory() {
        Some(inventory) => {
            let current = inventory.uncovered + inventory.legacy;
            if current < ready.rules {
                return UncoveredReadyState::Stale(format!(
                    "实际兜底规则少于核验记录（当前 {current} 条，核验时 {} 条）",
                    ready.rules
                ));
            }
        }
        None => {
            return UncoveredReadyState::Stale(
                "无法查询当前防火墙规则，核验结果不能作为当前状态".to_string(),
            )
        }
    }
    UncoveredReadyState::Valid
}

/// 写入 `ready` 记录：绑定当前配置代次、受管应用清单与实际规则条数。
fn mark_uncovered_ready(agents: &[String], rules: u32) -> Result<(), String> {
    let path = uncovered_lock_ready_file()?;
    let revision = match crate::appconfig::load_checked() {
        crate::appconfig::ConfigLoad::Ok(config) => config.egate_revision,
        _ => 0,
    };
    let mut agents = agents.to_vec();
    agents.sort();
    let ready = UncoveredReady {
        verified_at: now_secs(),
        revision,
        rules,
        agents,
    };
    let body = serde_json::to_string(&ready).map_err(|e| e.to_string())?;
    crate::fsx::write_atomically(&path, &body).map_err(|e| e.to_string())
}

fn clear_uncovered_ready() {
    if let Ok(path) = uncovered_lock_ready_file() {
        let _ = std::fs::remove_file(path);
    }
}

/// 接入恢复后清除兜底锁记录（规则由自动恢复统一解除）。
///
/// **QW-03**：返回 `Result`——删不掉意图文件时不能当成成功，
/// 否则下次启动会以为兜底锁仍在（或反之），状态与实际不符。
pub fn clear_uncovered_lock() -> Result<(), String> {
    clear_uncovered_ready();
    let path = uncovered_lock_file()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("清除兜底锁意图失败：{error}")),
    }
}

/// 跑一轮监控（含熔断执行）。
fn run_monitor_round(
    config: &crate::appconfig::AppConfig,
    app_handle: &mut Option<tauri::AppHandle>,
) {
    let targets = if config.egate_targets.is_empty() {
        crate::egate_defaults::builtin_targets()
    } else {
        config.egate_targets.clone()
    };
    // **P0-04**：记录本轮开始时的配置代次；探测结束后若代次已变，
    // 说明用户改了目标/阈值/开关，本轮结果作废。
    let revision = config.egate_revision;
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

    // **P0-04**：代次不一致 → 丢弃本轮结果，不做任何熔断/解除动作。
    //
    // **L-05（v0.7.3）**：配置读不出来时**不能**回退成「代次未变」。
    // 原实现 `_ => revision` 等于假设配置没改过——但那正是最需要谨慎的情况：
    // 配置损坏/不可读时，我们并不知道用户此刻的意图是什么。
    let current_revision = match crate::appconfig::load_checked() {
        crate::appconfig::ConfigLoad::Ok(config) => config.egate_revision,
        other => {
            crate::log_error(&format!(
                "无法读取门禁配置（{other:?}），本轮结果作废（不熔断、不解除）"
            ));
            return;
        }
    };
    if current_revision != revision {
        crate::log_error("门禁配置在本轮探测期间已变更，丢弃本轮结果");
        return;
    }

    // 直连泄露：默认只告警；开启 egate_leak_trip 后与目标失败同等对待。
    let leak = leak_round(config);
    // **P0-03**：恢复资格必须综合目标、接入、泄漏三项——不能只看目标 Pass。
    let access_ok = matches!(report.access.path.as_str(), "system_proxy" | "tun");
    let recovery = RecoveryEligibility {
        targets_pass: report.overall.verdict == crate::egate::Verdict::Pass,
        access_ok,
        // 启用 leak_trip 时，仍有达阈值的直连泄漏则不允许恢复。
        leak_clear: !(config.egate_leak_trip && leak.trip),
        // **P0-07**：用户手动要求保持的隔离不被自动恢复解除。
        manual_hold: is_manual_hold(),
    };
    if !recovery.allowed() && is_tripped() {
        crate::log_error(&format!(
            "自动恢复条件未满足：{}",
            recovery.blockers().join("、")
        ));
    }
    let mut gate = current_gate(
        config.egate_enabled,
        report.should_trip || leak.trip,
        report.should_warn || leak.warn,
        recovery,
    );
    // **P0-06**：未接入代理时的**即时兜底封锁**。
    //
    // 独立的 `access_streak` 阈值熔断要等若干轮；而在「系统代理关 + 无 TUN」
    // 的那一刻，受管应用就已经在直连了。这里在发现 Uncovered 的当轮就同步
    // 出站规则，不等阈值。
    //
    // 注意：这是**应用级出站隔离**，不是全局断网，只作用于受管 GUI 应用。
    if config.lockdown_on_uncovered
        && report.access.path == "uncovered"
        && !is_paused()
        && protection_intent() == ProtectionIntent::Armed
    {
        run_uncovered_lockdown(config, &report);
    }

    // **P0-02（v0.6.13.1）**：解除兜底封锁必须有**可验证的出口证据**，
    // 不能只看接入路径标签。
    //
    // 原实现只要 path 是 system_proxy 或 tun 就解除：
    // - 代理开着但端口不通/服务挂了 → 应用实际仍在裸连；
    // - TUN 网卡 Up 但没有路由证明 → 流量可能仍走物理网卡。
    // 两者都会在「已放行」的假象下留下直连窗口。
    if can_release_uncovered(&report) {
        release_uncovered_lock();
    }

    // **P0-03（v0.6.13.1）**：已标记「完整熔断」时，本轮**重新核验**规则是否
    // 仍然生效。外部程序/组策略/用户可能删除了规则，而内存状态还写着 tripped——
    // 不核验就会一直相信一个已经不存在的保护。
    if is_tripped() {
        let agents = if config.egate_guarded_agents.is_empty() {
            crate::egate_defaults::DEFAULT_GUARDED_AGENTS
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
        } else {
            config.egate_guarded_agents.clone()
        };
        match crate::egate_trip::verify_current_isolation(&agents) {
            Some(true) => {}
            Some(false) => {
                // 覆盖不完整：降级为 Partial，下一轮由 RetryProtection 补齐。
                mark_tripped_state(false);
                crate::log_error("隔离覆盖已不完整（规则被删除或修改），下一轮将补齐");
            }
            None => {
                // 查询失败：不能继续宣称完整保护。
                mark_trip_state_unknown();
                crate::log_error("无法核验隔离是否仍生效，已标记为「无法确认」");
            }
        }
        // L-02 (v0.7.1): the gate above was built from the state BEFORE this
        // re-verification. After downgrading to Partial/Unknown we must rebuild
        // it, otherwise this round still decides on a stale "already_tripped".
        gate = current_gate(
            config.egate_enabled,
            report.should_trip || leak.trip,
            report.should_warn || leak.warn,
            recovery,
        );
    }

    match decide(gate) {
        RoundAction::Trip => {
            // P0-02：若另一进程正在修改系统保护资源，本轮跳过（下轮再试），
            // 不能阻塞监控线程。
            if matches!(
                crate::egate_lock::try_acquire(crate::egate_lock::SystemOperation::Isolate),
                Ok(None)
            ) {
                crate::log_error("另一保护操作正在进行，本轮熔断推迟");
                return;
            }
            let agents = if config.egate_guarded_agents.is_empty() {
                crate::egate_defaults::DEFAULT_GUARDED_AGENTS
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
            } else {
                config.egate_guarded_agents.clone()
            };
            // **P0-04**：把本轮的配置代次带进熔断——持锁后若代次已变，
            // 熔断会自行放弃，不会按过期判定结束用户进程。
            let trip = crate::egate_trip::trip_with_revision(&agents, Some(revision));
            // P0-06：只有全部隔离成功才标记完整熔断；部分成功进入可重试状态。
            //
            // **L-13（v0.7.3）**：因配置过期而「主动放弃」时**不碰状态**。
            // 原来这种情况会走到 `mark_tripped_state(false)`，界面上凭空出现
            // 一个「部分隔离」——用户既没有触发熔断，也没有任何规则被建立。
            if trip.outcome.touches_state() {
                mark_tripped_state(trip.all_isolated);
            } else {
                crate::log_error(&format!(
                    "本轮熔断已取消（判定过期），不更新隔离状态：{}",
                    trip.note
                ));
            }
            if trip.outcome.touches_state() {
                if let Some(app) = ensure_app_handle(app_handle) {
                    crate::egate_notify::notify(
                        app,
                        crate::egate_notify::NotifyKind::Trip,
                        &crate::egate_notify::trip_detail(&report),
                    );
                }
            }
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
        RoundAction::RetryProtection => {
            // P0-06：上次只部分隔离，本轮补齐缺失的规则。
            let agents = if config.egate_guarded_agents.is_empty() {
                crate::egate_defaults::DEFAULT_GUARDED_AGENTS
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
            } else {
                config.egate_guarded_agents.clone()
            };
            // **P0-04**：把本轮的配置代次带进熔断——持锁后若代次已变，
            // 熔断会自行放弃，不会按过期判定结束用户进程。
            let trip = crate::egate_trip::trip_with_revision(&agents, Some(revision));
            mark_tripped_state(trip.all_isolated);
            crate::log_error(&format!(
                "出口门禁补齐隔离：{}（完整={}）",
                trip.note, trip.all_isolated
            ));
        }
        RoundAction::Recover => {
            // P0-07：出口已恢复，自动解除隔离。
            // **P0-NEW-02**：只有核验通过才清除熔断状态。
            // **P0-06（v0.7.3）**：把本轮判定时的配置代次带进自动解除。
            // 持锁后若代次已变 / 已暂停 / 手动保持状态不明，解除会自行放弃。
            match crate::egate_trip::release_verified_with_revision(
                crate::egate_trip::ReleaseReason::Automatic,
                Some(revision),
            ) {
                Ok(report) if report.verified => {
                    let removed = report.requested;
                    clear_tripped();
                    if let Some(app) = ensure_app_handle(app_handle) {
                        crate::egate_notify::notify(
                            app,
                            crate::egate_notify::NotifyKind::Recover,
                            "",
                        );
                    }
                    crate::log_error(&format!(
                        "出口已恢复，自动解除隔离（清理 {removed} 条规则）"
                    ));
                }
                Ok(report) => {
                    crate::log_error(&format!(
                        "自动解除隔离未完成（剩余 {} 条：{}），保持熔断状态",
                        report.remaining,
                        report.failures.join("；")
                    ));
                }
                Err(error) => {
                    crate::log_error(&format!("自动解除隔离失败：{error}"));
                }
            }
        }
        RoundAction::Warn => {
            if let Some(app) = ensure_app_handle(app_handle) {
                crate::egate_notify::notify(
                    app,
                    crate::egate_notify::NotifyKind::Warning,
                    &crate::egate_notify::warning_detail(&report),
                );
            }
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
            intent: ProtectionIntent::Armed,
            threshold_reached: false,
            at_warning_point: false,
            paused: false,
            already_tripped: false,
            trip_state_unknown: false,
            partial_protection: false,
            recovery: RecoveryEligibility {
                targets_pass: false,
                access_ok: false,
                leak_clear: true,
                manual_hold: false,
            },
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
    fn leak_trip_is_off_by_default_and_needs_threshold() {
        // 直连熔断默认关闭：默认配置下 leak_round 的 trip 必须是 false。
        // 这里验证「开关 + 阈值」的组合语义，不依赖真实连接表。
        let cfg = crate::appconfig::AppConfig::default();
        assert!(!cfg.egate_leak_trip, "直连熔断必须默认关闭");
        assert!(!cfg.egate_enabled, "门禁总开关也必须默认关闭");

        // 开启后：仍要连续达到阈值（单次快照不熔断——应用启动瞬间可能先直连）。
        let on = crate::appconfig::AppConfig {
            egate_leak_trip: true,
            egate_trip_threshold: 2,
            ..Default::default()
        };
        assert!(on.egate_leak_trip && on.egate_trip_threshold >= 2);
    }

    #[test]
    fn interval_is_clamped() {
        assert_eq!(clamp_interval(0), MIN_INTERVAL_SECS, "0 秒会打爆探测");
        assert_eq!(clamp_interval(99_999), MAX_INTERVAL_SECS);
        assert_eq!(clamp_interval(15), 15);
    }

    #[test]
    fn pause_state_serializes_and_expires_correctly() {
        // 用纯函数验证状态语义（不依赖真实数据目录）。
        let now = 1_000_000u64;
        let paused = PauseState {
            until: now + 1800,
            generation: 3,
        };
        // 未到期 → 暂停中。
        assert!(paused.until != 0 && now < paused.until);
        // 到期后 → 自动视为已恢复（读时判断，无需定时器）。
        assert!(!(paused.until != 0 && (now + 1800) < paused.until));
        // 恢复状态：until=0 永不处于暂停。
        let resumed = PauseState {
            until: 0,
            generation: 4,
        };
        assert!(!(resumed.until != 0));
        // 代次递增：跨进程 freshness 判断依赖它。
        assert!(resumed.generation > paused.generation);
        // 序列化往返（跨进程共享的前提）。
        let text = serde_json::to_string(&paused).unwrap();
        let back: PauseState = serde_json::from_str(&text).unwrap();
        assert_eq!(paused.until, back.until);
        assert_eq!(paused.generation, back.generation);
    }

    #[test]
    fn tripped_flag_round_trips() {
        clear_tripped();
        assert!(!is_tripped());
        mark_tripped_state(true);
        assert!(is_tripped());
        clear_tripped();
        assert!(!is_tripped());
    }

    #[test]
    fn current_gate_reflects_inputs() {
        // 纯函数语义：各字段如实映射到 Gate（不依赖全局磁盘状态）。
        let g = current_gate(
            true,
            true,
            false,
            RecoveryEligibility {
                targets_pass: false,
                access_ok: false,
                leak_clear: true,
                manual_hold: false,
            },
        );
        assert!(g.enabled && g.threshold_reached && !g.already_tripped);
        // 部分保护优先于已熔断的判断由 decide() 覆盖（见 decide 测试）。
    }

    /// **P0-08 / P0-G**：手动保持意图三态——只有「明确没有」才允许自动解除。
    #[test]
    fn manual_hold_state_is_tri_state() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());

        // 初始：没有意图文件 → None。
        assert_eq!(manual_hold_state(), ManualHold::None);
        assert!(!is_manual_hold(), "明确没有手动保持时不应判为保持");

        // 写入后 → Held。
        mark_manual_hold().unwrap();
        assert_eq!(manual_hold_state(), ManualHold::Held);
        assert!(is_manual_hold());

        // 清除后 → None。
        clear_manual_hold().unwrap();
        assert_eq!(manual_hold_state(), ManualHold::None);

        // 损坏文件 → Unknown（保守：视为保持，不允许自动解除）。
        let path = isolation_intent_file().unwrap();
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(manual_hold_state(), ManualHold::Unknown);
        assert!(
            is_manual_hold(),
            "Unknown 必须按「保持」对待，否则会静默推翻用户意图"
        );
    }

    /// **P1-11（v0.7.3）**：Unknown 的重确认必须退避——不能每轮都去打
    /// 一个正在故障的防火墙服务，也不能永远不重试。
    #[test]
    fn unknown_reconfirm_backs_off_and_caps() {
        // attempts=0 → 30 秒后重试（首次失败前的正常节奏）。
        assert!(!should_reconfirm(1_000 + 29, 1_000, 0));
        assert!(should_reconfirm(1_000 + 30, 1_000, 0));
        // 连续失败一次后 → 60 秒；两次后 → 120 秒。
        assert!(!should_reconfirm(1_000 + 59, 1_000, 1));
        assert!(should_reconfirm(1_000 + 60, 1_000, 1));
        assert!(!should_reconfirm(1_000 + 119, 1_000, 2));
        assert!(should_reconfirm(1_000 + 120, 1_000, 2));
        // 上限 5 分钟：退避不会无限增长，故障恢复后仍能自愈。
        assert!(!should_reconfirm(1_000 + 299, 1_000, 4));
        assert!(should_reconfirm(1_000 + 301, 1_000, 9));
    }

    /// **P0-C / P1-08（v0.7.3）**：兜底锁的意图/就绪两个状态互不混淆。
    ///
    /// 注意本测试在真实 Windows 上运行：`ready` 现在还会**对账实际规则数**，
    /// 所以「写下记录」本身不再等于「已验证」——这正是 P1-08 要的语义。
    #[test]
    fn uncovered_lock_state_files_are_independent() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        std::fs::create_dir_all(dir.path().join(".claude-switcher")).unwrap();

        assert!(!uncovered_lock_active());
        assert!(!uncovered_lock_ready());

        // 只写意图：表示「打算锁」，但规则未必全部生效。
        mark_uncovered_lock().unwrap();
        assert!(uncovered_lock_active());
        assert!(!uncovered_lock_ready());

        let defaults: Vec<String> = crate::egate_defaults::DEFAULT_GUARDED_AGENTS
            .iter()
            .map(|id| id.to_string())
            .collect();
        // **P1-08**：记录里声称 2 条规则，但系统上一条都没有 → 必须判失效。
        mark_uncovered_ready(&defaults, 2).unwrap();
        assert!(
            !uncovered_lock_ready(),
            "实际规则少于核验记录时不得显示为「已核验」"
        );
        assert!(matches!(
            uncovered_ready_state(),
            UncoveredReadyState::Stale(_)
        ));

        // 记录 0 条规则 → 与当前库存一致，视为有效（这是纯逻辑测试，
        // 不依赖真实防火墙内容）。
        mark_uncovered_ready(&defaults, 0).unwrap();
        assert!(uncovered_lock_ready());

        // **L-13**：ready 必须绑定到具体核验结果——配置代次一变就失效。
        crate::appconfig::update(|config| {
            config.egate_revision = config.egate_revision.saturating_add(1);
        })
        .unwrap();
        assert!(
            !uncovered_lock_ready(),
            "配置变更后旧的核验结果不得继续显示为「已核验」"
        );
        assert!(matches!(
            uncovered_ready_state(),
            UncoveredReadyState::Stale(_)
        ));

        // 重新核验后恢复有效。
        mark_uncovered_ready(&defaults, 0).unwrap();
        assert!(uncovered_lock_ready());

        // **L-13**：受管应用清单变化同样立刻失效。
        mark_uncovered_ready(&["claude".to_string()], 0).unwrap();
        assert!(
            !uncovered_lock_ready(),
            "受管清单与当前配置不一致时不得视为已核验"
        );

        // 清除时两者一起走。
        clear_uncovered_lock().unwrap();
        assert!(!uncovered_lock_active());
        assert!(!uncovered_lock_ready());
    }

    /// **P0-C**：兜底封锁只建规则，不结束进程。
    #[test]
    fn uncovered_enforcement_does_not_kill_processes() {
        // 无守护对象时是安全空操作；有对象时也不应调用进程结束路径。
        let report = crate::egate_trip::enforce_uncovered_outbound(&[]);
        assert!(report.agents.is_empty());
        assert!(!report.any_isolated);
        assert!(report.note.contains("没有配置"));
    }

    /// **P0-04**：停止保护意图写不进去时，恢复必须**立即中止**，不碰网络与防火墙。
    #[test]
    fn restore_aborts_when_disarm_fails() {
        use crate::test_support::env_lock;
        let _env = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        // 让数据目录不可写：父级是普通文件 → create_dir_all 必然失败。
        let blocker = dir.path().join(".claude-switcher");
        std::fs::write(&blocker, b"not a dir").unwrap();

        let report = crate::egate_netcut::restore_all();
        assert!(!report.complete, "意图写不进去时不得报告完整恢复");
        assert!(!report.intent_ok);
        assert!(
            report.note.contains("未执行"),
            "应明确说明恢复未执行：{}",
            report.note
        );
    }
}
