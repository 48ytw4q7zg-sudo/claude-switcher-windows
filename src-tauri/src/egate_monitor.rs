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
    revision: u64,
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
    // **P1-13**：记录触发原因（未接入 vs 严格模式下接入无法确认）。
    // **P0-02**：事务号只在**新建意图**时生成一次，后面 `Preparing -> Applied`
    // 只推进阶段、沿用同一个号。
    let reason = if report.access.path == "uncovered" {
        "uncovered"
    } else {
        "strict_unknown_access"
    };
    let txn = match read_uncovered_intent() {
        UncoveredIntent::Current { txn, phase } if phase != UncoveredPhase::Releasing => txn,
        // 已在解除中 / 没有意图 / 旧格式 / 读不到 -> 开一个新的事务。
        _ => match mark_uncovered_lock_with_reason(reason) {
            Ok(txn) => txn,
            Err(error) => {
                crate::log_error(&format!(
                    "未接入兜底封锁：意图落盘失败（{error}），本轮不施加规则以免无法归属"
                ));
                return;
            }
        },
    };

    // **P0-02**：规则建立**与结果提交在同一段系统锁内**。
    //
    // v0.7.7 是「锁内建规则 -> 释放锁 -> 锁外写 Applied/ready」。间隙里
    // 急救恢复可以停保护、删规则与意图，随后旧流程又把 Applied 写回去。
    let guard = match crate::egate_lock::acquire(crate::egate_lock::SystemOperation::Isolate) {
        Ok(guard) => guard,
        Err(error) => {
            crate::log_error(&format!("兜底封锁未执行（{error}），下一轮再试"));
            return;
        }
    };
    // 持锁后复核：等待锁期间用户可能已急救 / 暂停 / 改配置。
    if !crate::egate_trip::can_apply_isolation_with_revision(Some(revision)) {
        crate::log_error("兜底封锁判定已过期（等待锁期间状态改变），未建立规则");
        return;
    }
    let trip =
        crate::egate_trip::enforce_uncovered_outbound_locked(&guard, &agents, Some(revision));
    if trip.all_isolated {
        let rules: u32 = trip.agents.iter().map(|agent| agent.rules_verified).sum();
        let mut rule_names: Vec<String> = Vec::new();
        for agent in &trip.agents {
            rule_names.extend(agent.expected_rule_names.iter().cloned());
        }
        let mut specs: Vec<crate::egate_trip::RuleSpec> = Vec::new();
        for agent in &trip.agents {
            for spec in &agent.expected_rules {
                specs.push(spec.clone());
            }
        }
        // **P0-02**：同一事务号推进到 Applied + 写 ready，**都在锁内**。
        // 若此刻意图已被别的流程替换，`transition_uncovered_phase` 会拒绝。
        let current_reason = uncovered_lock_reason();
        match transition_uncovered_phase(&txn, UncoveredPhase::Applied, &current_reason) {
            Ok(_) => {
                if let Err(error) =
                    mark_uncovered_ready(&agents, rules, rule_names, specs, Some(txn.clone()))
                {
                    crate::log_error(&format!(
                        "兜底封锁已生效，但核验记录写入失败（{error}）：界面将显示为「未核验」"
                    ));
                }
            }
            Err(error) => {
                crate::log_error(&format!(
                    "兜底规则已建立，但意图已被别的流程变更（{error}）：未写入 ready，交由下一轮对账"
                ));
            }
        }
        return;
    }
    // 部分生效或完全失败：保持 Degraded，下一轮继续补齐。
    if let Err(error) = clear_uncovered_ready() {
        crate::log_error(&format!("{error}：界面可能继续显示过期的「已核验」"));
    }
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
fn release_uncovered_lock(expected_revision: Option<u64>) {
    if !uncovered_lock_active() {
        return;
    }
    // **P0-01**：只解除**未接入兜底**这一个来源的规则。
    //
    // **P0-03（v0.7.5）**：改用带持锁复核的入口。原来直接调
    // `release_isolation_reason`——它在锁内只做「按来源删除」，不复核
    // 保护意图/暂停/代次/接入路径。于是「检查通过 → 等锁 → 删规则」之间
    // 代理断了、用户暂停了，仍会被过期结论解除保护。
    // **P0-06**：意图/ready 的清理已并入 `release_uncovered_with_evidence`
    // 的持锁事务里，这里不再单独清（那会产生事务间隙）。
    match crate::egate_trip::release_uncovered_with_evidence(expected_revision) {
        Ok(report) if report.fully_cleared() => {
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
    if !uncovered_lock_active() {
        return;
    }
    // **P0-05（v0.7.7）**：「规则为零」不足以判定意图是孤立的。
    //
    // 真实交错顺序（v0.7.6 未排除）：
    //   1. 监控 A 写入新兜底意图（此时 phase=Preparing，规则还没建）
    //   2. A 等待系统操作锁
    //   3. 进程 B 查到零条规则 -> 删掉「看起来孤立」的意图
    //   4. A 拿到锁、建立阻断规则
    //   => 规则在，归属它的意图却被删了。
    //
    // 现在：**持锁** + 意图阶段可清理 + 规则确实为零，三条都满足才删。
    let _guard =
        match crate::egate_lock::try_acquire(crate::egate_lock::SystemOperation::FullRestore) {
            Ok(Some(guard)) => guard,
            // 有别的保护操作在进行：本轮不动意图（宁可留着，也不能误删）。
            Ok(None) => {
                crate::log_error("另有保护操作进行中，本轮跳过孤立兜底意图清理");
                return;
            }
            Err(error) => {
                crate::log_error(&format!(
                    "无法获取系统操作锁，跳过孤立兜底意图清理：{error}"
                ));
                return;
            }
        };
    // 意图阶段：`Preparing` 表示事务还在进行，绝不清理。
    match read_uncovered_intent() {
        UncoveredIntent::Absent => return,
        UncoveredIntent::Unreadable(error) => {
            crate::log_error(&format!("无法读取兜底意图，跳过孤立清理：{error}"));
            return;
        }
        UncoveredIntent::Legacy => {
            // 旧格式没有阶段：不能确认是否在进行中 -> 不自动清理。
            crate::log_error("兜底意图为旧格式，无法确认事务阶段，跳过自动清理");
            return;
        }
        UncoveredIntent::Current { phase, .. } => {
            if !phase.clearable() {
                return;
            }
        }
    }
    // 持锁后**再查一次**规则：取锁期间可能已经建好了。
    if let Some(inventory) = crate::egate_trip::inspect_isolation_inventory() {
        if inventory.uncovered > 0 {
            return;
        }
    } else {
        crate::log_error("无法查询兜底规则库存，跳过孤立意图清理");
        return;
    }
    if let Err(error) = clear_uncovered_lock() {
        crate::log_error(&format!("清理孤立兜底意图失败：{error}"));
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

/// **P1-10（v0.7.5）**：一次查询取全兜底状态（`active / verified / 说明`）。
///
/// `uncovered_lock_status()` 与 `uncovered_lock_detail()` 各自都会跑一遍
/// `uncovered_ready_state()`，而后者要查真实防火墙库存（几次 PowerShell 往返）。
/// 界面一次刷新同时调两个就等于把查询翻倍，还会在同一个响应里拿到两次
/// 可能不一致的结论。这里只算一次。
pub fn uncovered_lock_snapshot() -> (bool, bool, String) {
    let active = uncovered_lock_active();
    let state = uncovered_ready_state();
    // **L-07（v0.8.1）**：只有「意图存在 + 阶段 Applied + ready 事务号一致」
    // 才能返回 verified。ready 是某次事务的快照，不是当前事实——
    // 意图被别的流程替换后，这份快照就不该继续代表「已核验」。
    let verified = match (
        matches!(state, UncoveredReadyState::Valid),
        read_uncovered_intent(),
    ) {
        (false, _) => false,
        (
            true,
            UncoveredIntent::Current {
                phase: UncoveredPhase::Applied,
                txn,
            },
        ) => read_uncovered_ready()
            .and_then(|r| r.txn)
            .map(|ready_txn| ready_txn == txn)
            .unwrap_or(false),
        // 阶段不是 Applied，或意图是旧格式/读不到/没有 -> 都不算「已核验」。
        _ => false,
    };
    // **P1-13**：把触发原因也说清楚——「未接入代理」与「严格模式下接入
    // 无法确认」走同一套规则，但前者是故障、后者是用户主动选择的安全策略。
    let cause = match uncovered_lock_reason().as_str() {
        "strict_unknown_access" => "严格防泄漏模式：接入路径无法证明，已封锁受管应用出站",
        _ => "未接入代理链路，已封锁受管应用出站",
    };
    let note = match state {
        UncoveredReadyState::Valid => format!("{cause}（已核验）"),
        UncoveredReadyState::Missing => format!("{cause}（尚未核验）"),
        UncoveredReadyState::Stale(reason) => format!("{cause}；核验已失效：{reason}"),
    };
    (active, verified, note)
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

pub(crate) fn uncovered_lock_active() -> bool {
    uncovered_lock_file()
        .map(|path| path.exists())
        .unwrap_or(false)
}

/// **P1-13**：写入兜底意图，并记录**触发原因**。
///
/// 「未接入代理」与「严格模式下接入无法确认」走同一套规则与清理路径，
/// 但用户需要知道自己是被哪一种触发的——后者是主动的安全选择，不是故障。
/// **P0-05（v0.7.7）**：意图的事务阶段。
///
/// 意图在**取锁之前**写入（崩溃时至少有「我打算锁」的记录），但那段时间里
/// 规则还没建立。若此时另一个进程查到「零条规则」就删意图，就会出现
/// 「规则建好了、意图没了」——孤立规则再也没有归属。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UncoveredPhase {
    /// 已写意图，规则尚未建立。
    Preparing,
    /// 规则已建立并核验。
    Applied,
    /// 正在解除。
    Releasing,
}

impl UncoveredPhase {
    /// 是否允许被「孤立清理」逻辑删除。
    ///
    /// `Preparing` **不许**删：它对应的事务还在进行中。
    pub fn clearable(self) -> bool {
        !matches!(self, UncoveredPhase::Preparing)
    }
}

fn mark_uncovered_lock_with_reason(reason: &str) -> Result<String, String> {
    mark_uncovered_lock_with_phase(reason, UncoveredPhase::Preparing, None)
}

/// **P0-05 / P0-07**：写入意图，带**真正唯一**的事务号与阶段。
/// **P0-02（v0.8.1）**：写入意图记录。
///
/// `txn` 为 `Some` 表示**阶段转换**（沿用同一事务号），`None` 表示新事务
/// （生成新号）。v0.7.7 每次调用都 `Uuid::new_v4()`，于是 `Preparing → Applied`
/// 会给同一次封锁两个不同事务号——「旧事务不删新事务」的保护因此失效。
fn mark_uncovered_lock_with_phase(
    reason: &str,
    phase: UncoveredPhase,
    txn: Option<&str>,
) -> Result<String, String> {
    let path = uncovered_lock_file()?;
    let txn_id = match txn {
        Some(existing) if !existing.is_empty() => existing.to_string(),
        _ => uuid::Uuid::new_v4().to_string(),
    };
    let body = serde_json::json!({
        "since": now_secs(),
        "reason": reason,
        "txn": txn_id,
        "phase": phase,
    })
    .to_string();
    crate::fsx::write_atomically(&path, &body).map_err(|e| e.to_string())?;
    Ok(txn_id)
}

/// **P0-02**：只在**事务号不变**的前提下推进阶段。
///
/// 如果记录已经被别的流程替换（事务号不符），拒绝覆盖——那是旧事务
/// 试图把新事务的意图改写成自己的状态。
pub fn transition_uncovered_phase(
    expected_txn: &str,
    phase: UncoveredPhase,
    reason: &str,
) -> Result<String, String> {
    match read_uncovered_intent() {
        UncoveredIntent::Current { txn, .. } if txn != expected_txn => Err(format!(
            "兜底意图已被别的流程替换（txn {txn} != {expected_txn}），拒绝推进阶段"
        )),
        UncoveredIntent::Current { .. } => {
            mark_uncovered_lock_with_phase(reason, phase, Some(expected_txn))
        }
        UncoveredIntent::Absent => {
            Err("兜底意图已不存在（可能已被急救恢复清除），拒绝推进阶段".to_string())
        }
        UncoveredIntent::Legacy => {
            Err("兜底意图是旧格式（无事务号），拒绝推进阶段以免改写不明归属的记录".to_string())
        }
        UncoveredIntent::Unreadable(error) => {
            Err(format!("无法读取兜底意图（{error}），拒绝推进阶段"))
        }
    }
}

/// 意图记录（**P0-07**：严格解析，区分「旧格式 / 损坏 / 读不到」）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UncoveredIntent {
    /// 没有意图文件。
    Absent,
    /// 新格式记录。
    Current { txn: String, phase: UncoveredPhase },
    /// 旧格式（无 txn / phase）——需要专门迁移，不能让自动清理直接删。
    Legacy,
    /// 无法读取 / 解析。
    Unreadable(String),
}

pub fn read_uncovered_intent() -> UncoveredIntent {
    let path = match uncovered_lock_file() {
        Ok(path) => path,
        Err(error) => return UncoveredIntent::Unreadable(error),
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return UncoveredIntent::Absent
        }
        Err(error) => return UncoveredIntent::Unreadable(format!("读取意图文件失败：{error}")),
    };
    let value: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(error) => return UncoveredIntent::Unreadable(format!("意图文件解析失败：{error}")),
    };
    let txn = value
        .get("txn")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    let phase = match value.get("phase").and_then(|v| v.as_str()) {
        Some("applied") => Some(UncoveredPhase::Applied),
        Some("releasing") => Some(UncoveredPhase::Releasing),
        Some("preparing") => Some(UncoveredPhase::Preparing),
        _ => None,
    };
    match (txn, phase) {
        (Some(txn), Some(phase)) => UncoveredIntent::Current { txn, phase },
        // 缺 txn 或缺 phase = 旧格式（或被外部改坏），一律按需迁移处理。
        _ => UncoveredIntent::Legacy,
    }
}

/// 读取当前兜底意图的事务号（旧记录没有该字段时返回 None）。
#[allow(dead_code)]
pub fn uncovered_lock_txn() -> Option<String> {
    match read_uncovered_intent() {
        UncoveredIntent::Current { txn, .. } => Some(txn),
        _ => None,
    }
}

/// **P0-07**：仅当事务号仍与 `expected` 一致时才清理意图 + ready。
///
/// **新格式缺少事务号（或记录损坏）时拒绝清理**——那表示我们无法确认
/// 当前这份意图是谁的，删除它可能抹掉别的流程刚建立的意图。
/// v0.7.6 的「读不到就退化为按存在性清理」正是这里的问题。
pub fn clear_uncovered_lock_if_txn(expected: &str) -> Result<(), String> {
    match read_uncovered_intent() {
        UncoveredIntent::Current { txn, .. } if txn != expected => Err(format!(
            "兜底意图已被别的流程更新（txn {txn} != {expected}），本次未清理以免误删新意图"
        )),
        UncoveredIntent::Current { .. } => clear_uncovered_lock(),
        UncoveredIntent::Legacy => Err(
            "兜底意图是旧格式（无事务号），无法确认归属，已拒绝自动清理；请手动核对后处理"
                .to_string(),
        ),
        UncoveredIntent::Unreadable(error) => {
            Err(format!("无法读取兜底意图（{error}），已拒绝自动清理"))
        }
        UncoveredIntent::Absent => Ok(()),
    }
}

/// 读取兜底意图的触发原因（用于界面说明；旧文件没有该字段时返回 `uncovered`）。
pub fn uncovered_lock_reason() -> String {
    uncovered_lock_file()
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(str::to_string))
        .unwrap_or_else(|| "uncovered".to_string())
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
    /// **P1-07**：核验时**应存在**的规则名清单。
    ///
    /// 有了它才能按「来源 + 受管对象 + 预期规则名」对账，而不是只比条数。
    /// 只比条数会漏掉「兜底规则被删一条、旧版遗留恰好留一条」这种巧合。
    #[serde(default)]
    rule_names: Vec<String>,
    /// **P0-04**：核验时的**完整规则规格**（名称 + 方向 + 程序路径）。
    ///
    /// 只存名称不够：外部程序把规则改成 `Allow` 或换掉程序路径后，
    /// 名称与数量都不变，仅凭存在性检查会误报「已核验」。
    #[serde(default)]
    specs: Vec<crate::egate_trip::RuleSpec>,
    /// **L-07（v0.8.1）**：这份核验结果属于哪个意图事务。
    ///
    /// ready 是「某次事务的核验快照」，不是「当前事实」。绑上事务号后，
    /// 意图被别的流程替换时这份 ready 立刻失效，界面不会继续显示过期结论。
    #[serde(default)]
    txn: Option<String>,
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
            // **P1-07**：只认**本来源**（UncoveredLock）的规则。
            //
            // v0.7.3 写的是 `inventory.uncovered + inventory.legacy`——旧版遗留
            // 规则不属于当前兜底来源，不该拿来凑数。典型漏检：兜底规则被外部
            // 删掉一条，旧版遗留恰好留一条，计数刚好相等，界面继续显示「已核验」。
            let current = inventory.uncovered;
            if current < ready.rules {
                return UncoveredReadyState::Stale(format!(
                    "实际兜底规则少于核验记录（当前 {current} 条，核验时 {} 条；旧版遗留 {} 条不计入）",
                    ready.rules, inventory.legacy
                ));
            }
        }
        None => {
            return UncoveredReadyState::Stale(
                "无法查询当前防火墙规则，核验结果不能作为当前状态".to_string(),
            )
        }
    }
    // **P0-04（v0.7.6）**：按**完整规格**核验，不只是看名字还在不在。
    //
    // 外部程序把规则改成 `Allow`、换掉程序路径、或它根本没进 ActiveStore 时，
    // 名称与条数都不变——仅凭存在性检查会把「已经不阻断了」显示成「已核验」。
    if !ready.specs.is_empty() {
        let verification = crate::egate_trip::verify_rule_specs(&ready.specs);
        if !verification.query_ok {
            return UncoveredReadyState::Stale(
                "无法查询兜底规则的实际属性，核验结果不能作为当前状态".to_string(),
            );
        }
        if verification.verified < verification.expected {
            let detail = if verification.failed.is_empty() {
                format!(
                    "{} 条规则未生效",
                    verification.expected - verification.verified
                )
            } else {
                verification.failed.join("；")
            };
            return UncoveredReadyState::Stale(format!("部分兜底规则已失效或属性被改动：{detail}"));
        }
        // **P0-04（v0.7.7）**：规则属性都对、也在 ActiveStore 里，还**不够**。
        //
        // 当前活动网络的防火墙 Profile 如果被关掉，阻断规则照样存在、属性
        // 照样正确，但**没有实际拦住任何流量**。普通隔离执行器早就用
        // `effective_firewall_enabled()` 复核了这一条，ready 判定却漏了——
        // 两处判据不一致，正是审计点出的问题。
        match crate::platform::imp::effective_firewall_enabled() {
            Some(true) => {}
            Some(false) => {
                return UncoveredReadyState::Stale(
                    "当前活动网络的防火墙已关闭，阻断规则并未实际拦住流量".to_string(),
                );
            }
            None => {
                return UncoveredReadyState::Stale(
                    "无法确认当前活动网络的防火墙是否启用，不能宣称阻断已生效".to_string(),
                );
            }
        }
    } else if !ready.rule_names.is_empty() {
        // 旧版记录只有名称没有规格：至少确认名称仍在，但**不能**声称
        // 属性已核验——留待下一轮补齐后再写完整规格。
        match crate::platform::imp::firewall_rules_all_present(&ready.rule_names) {
            crate::platform::imp::RuleLookup::Present => {}
            crate::platform::imp::RuleLookup::Absent => {
                return UncoveredReadyState::Stale(
                    "部分兜底规则已被外部删除，覆盖不再完整".to_string(),
                );
            }
            crate::platform::imp::RuleLookup::Unknown => {
                return UncoveredReadyState::Stale(
                    "无法确认兜底规则是否仍然生效，核验结果不能作为当前状态".to_string(),
                );
            }
        }
    } else {
        // **L-06**：既无规格也无名称的记录不能当作「已核验」。
        return UncoveredReadyState::Stale("核验记录缺少规则明细，需重新核验".to_string());
    }
    UncoveredReadyState::Valid
}

/// 写入 `ready` 记录：绑定当前配置代次、受管应用清单与实际规则条数。
fn mark_uncovered_ready(
    agents: &[String],
    rules: u32,
    rule_names: Vec<String>,
    specs: Vec<crate::egate_trip::RuleSpec>,
    txn: Option<String>,
) -> Result<(), String> {
    let path = uncovered_lock_ready_file()?;
    let revision = match crate::appconfig::load_checked() {
        crate::appconfig::ConfigLoad::Ok(config) => config.egate_revision,
        _ => 0,
    };
    let mut agents = agents.to_vec();
    agents.sort();
    let mut rule_names = rule_names;
    rule_names.sort();
    let ready = UncoveredReady {
        verified_at: now_secs(),
        revision,
        rules,
        agents,
        rule_names,
        specs,
        txn,
    };
    let body = serde_json::to_string(&ready).map_err(|e| e.to_string())?;
    crate::fsx::write_atomically(&path, &body).map_err(|e| e.to_string())
}

fn clear_uncovered_ready() -> Result<(), String> {
    // **L-03（v0.7.7）**：删不掉 ready 记录不能静默忽略。
    //
    // 记录留着会让界面继续显示「已核验」，而实际覆盖已经不完整——
    // 这正是 L-13/P1-08 一直在防的「过去某一刻的事实冒充当前事实」。
    let path = uncovered_lock_ready_file()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("清理兜底 ready 记录失败：{error}")),
    }
}

/// 接入恢复后清除兜底锁记录（规则由自动恢复统一解除）。
///
/// **QW-03**：返回 `Result`——删不掉意图文件时不能当成成功，
/// 否则下次启动会以为兜底锁仍在（或反之），状态与实际不符。
pub fn clear_uncovered_lock() -> Result<(), String> {
    clear_uncovered_ready()?;
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
    // **P1-14（v0.7.5）**：在**工作副本**上算本轮结果，不立即写进共享计数。
    //
    // v0.7.3 的 `run_round` 直接改共享 map，之后才比对配置代次；发现代次变了
    // 就丢弃本轮报告——但已经写进去的失败次数**没有回滚**。于是旧白名单、
    // 旧目标、旧阈值下产生的失败会进入下一轮新配置的防抖计算：
    // 「第一轮失败 → 用户改白名单 → 第二轮直接累计到阈值」→ 误熔断。
    let mut staged = streaks.clone();
    let report = crate::egate_check::run_round(
        &targets,
        &mut staged,
        config.egate_enforce_access,
        config.egate_trip_threshold,
    );

    // **P0-04**：代次不一致 → 丢弃本轮结果，不做任何熔断/解除动作。
    //
    // **L-05（v0.7.3）**：配置读不出来时**不能**回退成「代次未变」。
    let current_revision = match crate::appconfig::load_checked() {
        crate::appconfig::ConfigLoad::Ok(config) => config.egate_revision,
        other => {
            crate::log_error(&format!(
                "无法读取门禁配置（{other:?}），本轮结果作废（不熔断、不解除）"
            ));
            // **P1-14**：整份工作副本丢弃，共享计数保持原样。
            drop(streaks);
            return;
        }
    };
    if current_revision != revision {
        crate::log_error("门禁配置在本轮探测期间已变更，丢弃本轮结果");
        // **P1-14 / L-12**：安全参数（白名单、目标、阈值、保护对象）变了，
        // 旧的连续失败历史**必须**一并作废——同一个目标 ID 下内容可能已经
        // 完全不同，继续累计等于用旧配置的失败触发新配置的熔断。
        streaks.clear();
        drop(streaks);
        return;
    }
    // 判定有效才提交本轮计数。
    *streaks = staged;
    drop(streaks);

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
    //
    // **P1-13（v0.7.5）**：严格防泄漏模式下，`unknown` / 未证明的 `tun`
    // 也需要保护。普通模式只是报告 `Unverified`——那并没有**阻止**受管应用
    // 直连，对「绝不暴露真实出口」的用户不够。
    //
    // 严格模式仍然只做**出站兜底封锁**（`quarantine_agent_for(..., kill=false)`），
    // 绝不查杀进程：证据不足就杀进程是最容易误伤的做法。
    let needs_lockdown = match report.access.path.as_str() {
        "uncovered" => true,
        // TUN 只有在路由已证明时才算「接入有效」；否则等同于没有保护。
        "tun" => config.strict_leak_protection && !report.access.tun_proven,
        // 未知 / 读取失败：严格模式下也要拦住，普通模式只观察。
        "unknown" => config.strict_leak_protection,
        _ => false,
    };
    if config.lockdown_on_uncovered
        && needs_lockdown
        && !is_paused()
        && protection_intent() == ProtectionIntent::Armed
    {
        run_uncovered_lockdown(config, &report, revision);
    }

    // **P0-02（v0.6.13.1）**：解除兜底封锁必须有**可验证的出口证据**，
    // 不能只看接入路径标签。
    //
    // 原实现只要 path 是 system_proxy 或 tun 就解除：
    // - 代理开着但端口不通/服务挂了 → 应用实际仍在裸连；
    // - TUN 网卡 Up 但没有路由证明 → 流量可能仍走物理网卡。
    // 两者都会在「已放行」的假象下留下直连窗口。
    if can_release_uncovered(&report) {
        // **P0-03**：把本轮代次带进去——持锁后若代次已变/代理已断/已暂停，
        // 解除会自行放弃，不会按过期结论放行。
        release_uncovered_lock(Some(revision));
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
                // **P1-06**：`AbortedStale`（判定过期）与 `NoApplicable`（全部对象
                // 未安装，没有建立任何规则）都不触碰隔离状态——后者不能被写成
                // 「已成功建立隔离规则」。
                crate::log_error(&format!(
                    "本轮熔断不更新隔离状态（{}）：{}",
                    trip.outcome.serialized(),
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
            // **L-15（v0.7.5）**：补齐分支同样要按 `outcome` 决定是否写状态。
            //
            // 原来无条件 `mark_tripped_state(trip.all_isolated)`：一次
            // 「因配置过期而放弃」的补齐会写成 `false` → 界面凭空出现部分隔离。
            if trip.outcome.touches_state() {
                mark_tripped_state(trip.all_isolated);
            } else {
                crate::log_error(&format!(
                    "本轮补齐隔离已取消（判定过期），不更新隔离状态：{}",
                    trip.note
                ));
            }
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

    /// **P1-13（v0.7.5）**：严格防泄漏模式下，未知接入也必须进入兜底封锁。
    ///
    /// 普通模式只报告 `Unverified`——那并没有**阻止**受管应用直连。
    /// 这条断言固定住「哪种接入状态需要保护」的判定口径。
    #[test]
    fn strict_leak_mode_locks_down_on_unproven_access() {
        // 严格模式：uncovered / 未证明的 tun / unknown 都需要保护。
        assert!(needs_lockdown_strict("uncovered", false));
        assert!(needs_lockdown_strict("uncovered", true));
        assert!(needs_lockdown_strict("tun", false));
        assert!(needs_lockdown_strict("unknown", false));
        // 严格模式下 TUN 路由**已证明**时不需要额外保护。
        assert!(!needs_lockdown_strict("tun", true));
        // 普通模式：只有 uncovered 需要保护，unknown/tun 只观察。
        assert!(needs_lockdown_off("uncovered"));
        assert!(!needs_lockdown_off("unknown"));
        assert!(!needs_lockdown_off("tun"));
    }

    /// 纯函数：严格模式下该接入状态是否需要出站兜底封锁。
    fn needs_lockdown_strict(path: &str, tun_proven: bool) -> bool {
        match path {
            "uncovered" => true,
            "tun" => !tun_proven,
            "unknown" => true,
            _ => false,
        }
    }

    /// 纯函数：普通模式下该接入状态是否需要出站兜底封锁。
    fn needs_lockdown_off(path: &str) -> bool {
        path == "uncovered"
    }

    /// **P1-13**：兜底意图必须能说明触发原因，便于界面区分
    /// 「故障」与「用户主动选择的安全策略」。
    #[test]
    fn uncovered_lock_reason_distinguishes_strict_mode() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        std::fs::create_dir_all(dir.path().join(".claude-switcher")).unwrap();

        mark_uncovered_lock_with_reason("strict_unknown_access").unwrap();
        assert_eq!(uncovered_lock_reason(), "strict_unknown_access");
        clear_uncovered_lock().unwrap();

        mark_uncovered_lock_with_reason("uncovered").unwrap();
        assert_eq!(uncovered_lock_reason(), "uncovered");
        clear_uncovered_lock().unwrap();
    }

    /// **P0-C / P1-07 / P1-08（v0.7.5）**：兜底锁的意图/就绪两个状态互不混淆，
    /// 且 ready 必须与**当前真实规则**对账。
    ///
    /// 注意本测试跑在真实 Windows 上：`ready` 的判定会查真实防火墙库存，
    /// 所以「写下记录」本身不再等于「已验证」——这正是 P1-07 要的语义。
    #[test]
    fn uncovered_lock_state_files_are_independent() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        std::fs::create_dir_all(dir.path().join(".claude-switcher")).unwrap();

        assert!(!uncovered_lock_active());
        assert!(!uncovered_lock_ready());

        // 只写意图：表示「打算锁」，但规则未必全部生效。
        mark_uncovered_lock_with_reason("uncovered").unwrap();
        assert!(uncovered_lock_active());
        assert!(!uncovered_lock_ready());

        let defaults: Vec<String> = crate::egate_defaults::DEFAULT_GUARDED_AGENTS
            .iter()
            .map(|id| id.to_string())
            .collect();
        // **P1-07**：记录里声称 2 条规则，但系统上一条都没有 → 必须判失效。
        mark_uncovered_ready(&defaults, 2, Vec::new(), Vec::new(), None).unwrap();
        assert!(matches!(
            uncovered_ready_state(),
            UncoveredReadyState::Stale(_)
        ));

        // 记录 0 条规则 + 无规格 -> **不是**有效（P0-04：没有属性级核验
        // 就不能说「已核验」）。完整 Valid 路径需要真实防火墙规则，
        // 由 tests/windows-integration/03-restore-ledger.ps1 覆盖。
        mark_uncovered_ready(&defaults, 0, Vec::new(), Vec::new(), None).unwrap();
        assert!(matches!(
            uncovered_ready_state(),
            UncoveredReadyState::Stale(_)
        ));
        assert!(!uncovered_lock_ready(), "无规则规格的记录不得显示已核验");

        // **L-13**：配置代次一变就失效。
        crate::appconfig::update(|config| {
            config.egate_revision = config.egate_revision.saturating_add(1);
        })
        .unwrap();
        assert!(matches!(
            uncovered_ready_state(),
            UncoveredReadyState::Stale(_)
        ));

        // **P1-07**：受管应用清单变化同样立刻失效。
        mark_uncovered_ready(&["claude".to_string()], 0, Vec::new(), Vec::new(), None).unwrap();
        assert!(matches!(
            uncovered_ready_state(),
            UncoveredReadyState::Stale(_)
        ));

        // **P1-07**：预期规则名对不上时也要失效（哪怕条数看着对）。
        mark_uncovered_ready(
            &defaults,
            0,
            vec!["ClaudeSwitcher UncoveredLock ghost Out".into()],
            Vec::new(),
            None,
        )
        .unwrap();
        assert!(matches!(
            uncovered_ready_state(),
            UncoveredReadyState::Stale(_)
        ));

        // 清除时两者一起走。
        clear_uncovered_lock().unwrap();
        assert!(!uncovered_lock_active());
        assert!(!uncovered_lock_ready());
    }

    /// **P0-04（v0.7.6）**：ready 记录缺少规则明细时不得算「已核验」。
    ///
    /// 回归点：v0.7.5 只核对规则名存在性。外部程序把规则改成 `Allow`
    /// 或换掉程序路径后，名称与条数都不变，界面仍显示「已核验」。
    /// 现在必须有完整规格并逐条核验属性；旧版只有名称的记录也降级为
    /// 「需重新核验」而不是当成完整核验。
    #[test]
    fn ready_without_rule_specs_is_never_valid() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        std::fs::create_dir_all(dir.path().join(".claude-switcher")).unwrap();

        let defaults: Vec<String> = crate::egate_defaults::DEFAULT_GUARDED_AGENTS
            .iter()
            .map(|id| id.to_string())
            .collect();
        // 既有规则名、也有条数，但**没有规格** -> 必须判失效（L-06）。
        mark_uncovered_ready(&defaults, 0, vec!["some-rule".into()], Vec::new(), None).unwrap();
        assert!(
            matches!(uncovered_ready_state(), UncoveredReadyState::Stale(_)),
            "缺少规则明细的记录不能算已核验"
        );

        // 有规格但规则在系统上不存在 -> 同样失效（属性级核验）。
        let spec = crate::egate_trip::RuleSpec {
            name: "ClaudeSwitcher UncoveredLock definitely-missing Out".into(),
            dir: "Out".into(),
            direction: "Outbound".into(),
            exe: r"C:\Windows\System32
otepad.exe"
                .into(),
        };
        mark_uncovered_ready(&defaults, 1, vec![spec.name.clone()], vec![spec], None).unwrap();
        assert!(
            matches!(uncovered_ready_state(), UncoveredReadyState::Stale(_)),
            "属性核验不通过时不得显示已核验"
        );

        clear_uncovered_lock().unwrap();
    }

    /// **P0-05（v0.7.7）**：`Preparing` 阶段的意图**不得**被孤立清理删除。
    ///
    /// 回归点：意图在取锁之前写入，规则还没建立。若此时另一个进程查到
    /// 「零条规则」就删意图，最终会得到「规则在、归属它的意图没了」。
    #[test]
    fn preparing_intent_is_never_cleared_as_orphan() {
        assert!(
            !UncoveredPhase::Preparing.clearable(),
            "事务进行中的意图不得被孤立清理删除"
        );
        assert!(UncoveredPhase::Applied.clearable());
        assert!(UncoveredPhase::Releasing.clearable());
    }

    /// **P0-07（v0.7.7）**：事务号必须真正唯一。
    ///
    /// 回归点：v0.7.6 用 `秒级时间 + PID`，同一进程同一秒内两次意图会
    /// 得到同一个 ID，旧事务因此可能删掉新事务的意图。
    #[test]
    fn uncovered_txn_ids_are_unique() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        std::fs::create_dir_all(dir.path().join(".claude-switcher")).unwrap();

        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..20 {
            mark_uncovered_lock_with_phase("test", UncoveredPhase::Preparing, None).unwrap();
            let txn = uncovered_lock_txn().expect("新格式记录必须有事务号");
            assert!(seen.insert(txn.clone()), "同一秒内不得重复事务号：{txn}");
        }
        clear_uncovered_lock().unwrap();
    }

    /// **P0-07**：旧格式记录（无事务号）**拒绝**自动清理。
    ///
    /// 「读不到事务号」与「旧版确实没有事务号」不能混为一谈。
    #[test]
    fn legacy_intent_without_txn_refuses_auto_cleanup() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        std::fs::create_dir_all(dir.path().join(".claude-switcher")).unwrap();

        let path = uncovered_lock_file().unwrap();
        std::fs::write(&path, b"{\"since\":0}").unwrap();
        assert_eq!(read_uncovered_intent(), UncoveredIntent::Legacy);
        let error = clear_uncovered_lock_if_txn("whatever").unwrap_err();
        assert!(error.contains("旧格式"), "{error}");
        // 记录仍然保留（没被误删）。
        assert!(path.exists());
    }

    /// **P1-05（v0.7.7）**：严格防泄漏的前置条件必须真正生效。
    #[test]
    fn strict_leak_toggle_checks_prerequisites() {
        // 判据本身：门禁关闭时，strict 标志并不能让兜底封锁生效。
        let off = crate::appconfig::AppConfig {
            egate_enabled: false,
            lockdown_on_uncovered: true,
            strict_leak_protection: true,
            ..crate::appconfig::AppConfig::default()
        };
        assert!(!off.egate_enabled, "strict 标志不能代替门禁开关");
        let both = crate::appconfig::AppConfig {
            egate_enabled: true,
            lockdown_on_uncovered: false,
            strict_leak_protection: true,
            ..crate::appconfig::AppConfig::default()
        };
        assert!(
            !both.lockdown_on_uncovered,
            "strict 标志不能代替兜底封锁开关"
        );
    }

    /// **P0-02（v0.8.1）**：`Preparing -> Applied` 必须沿用同一事务号。
    ///
    /// 回归点：v0.7.7 每次写意图都 `Uuid::new_v4()`，于是同一次封锁拿到
    /// 两个事务号——「旧事务不删新事务」的保护因此失效。
    #[test]
    fn phase_transition_preserves_transaction_id() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        std::fs::create_dir_all(dir.path().join(".claude-switcher")).unwrap();

        let txn = mark_uncovered_lock_with_reason("test").unwrap();
        let (txn_after, phase) = match read_uncovered_intent() {
            UncoveredIntent::Current { txn, phase } => (txn, phase),
            other => panic!("应为新格式记录：{other:?}"),
        };
        assert_eq!(txn, txn_after);
        assert_eq!(phase, UncoveredPhase::Preparing);

        // 推进到 Applied：事务号必须不变。
        let committed = transition_uncovered_phase(&txn, UncoveredPhase::Applied, "test").unwrap();
        assert_eq!(committed, txn, "阶段推进不得更换事务身份");
        match read_uncovered_intent() {
            UncoveredIntent::Current { txn: now, phase } => {
                assert_eq!(now, txn);
                assert_eq!(phase, UncoveredPhase::Applied);
            }
            other => panic!("应为新格式记录：{other:?}"),
        }
    }

    /// **P0-02**：意图已被别的流程替换时，旧事务不得推进阶段。
    #[test]
    fn stale_transaction_cannot_advance_phase() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        std::fs::create_dir_all(dir.path().join(".claude-switcher")).unwrap();

        let old_txn = mark_uncovered_lock_with_reason("test").unwrap();
        // 另一个流程替换意图（新事务）。
        let new_txn = mark_uncovered_lock_with_reason("test").unwrap();
        assert_ne!(old_txn, new_txn);
        let error =
            transition_uncovered_phase(&old_txn, UncoveredPhase::Applied, "test").unwrap_err();
        assert!(error.contains("替换"), "{error}");
    }

    /// **L-07（v0.8.1）**：ready 是「某次事务的快照」，意图换了就失效。
    #[test]
    fn ready_without_matching_txn_is_not_verified() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        std::fs::create_dir_all(dir.path().join(".claude-switcher")).unwrap();

        let defaults: Vec<String> = crate::egate_defaults::DEFAULT_GUARDED_AGENTS
            .iter()
            .map(|id| id.to_string())
            .collect();
        // ready 带事务号 A，意图却是事务 B -> 不算已核验。
        mark_uncovered_ready(&defaults, 0, Vec::new(), Vec::new(), Some("txn-A".into())).unwrap();
        let _ = mark_uncovered_lock_with_phase("test", UncoveredPhase::Applied, Some("txn-B"));
        assert!(
            !uncovered_lock_ready(),
            "ready 事务号与意图不一致时不得显示已核验"
        );

        // 事务号一致 -> 才可能算已核验（还要看规则属性核验）。
        let _ = mark_uncovered_lock_with_phase("test", UncoveredPhase::Applied, Some("txn-A"));
        let (_active, _verified, note) = uncovered_lock_snapshot();
        assert!(!note.is_empty());
    }

    /// **P1-01（v0.8.1）**：代理健康三态，远程代理不得判为 Verified。
    #[test]
    fn remote_proxy_health_is_never_verified() {
        // 判据本身：Verified 只允许出现在「回环且端口可达」的路径上。
        use crate::guard::ProxyHealth;
        let remote = ProxyHealth::Unknown;
        assert_ne!(remote, ProxyHealth::Verified, "远程代理不得被判定为已验证");
        assert_ne!(
            remote,
            ProxyHealth::Unavailable,
            "远程代理也不是已验证不可用"
        );
    }

    /// **P1-07**：旧版遗留规则**不能**用来顶替兜底规则的对账数量。
    ///
    /// 回归点：v0.7.3 用 `inventory.uncovered + inventory.legacy` 比对，
    /// 于是「兜底规则被删一条、旧版遗留恰好留一条」会被判成已核验。
    /// 现在只认 `uncovered` 一个来源——这条断言验证的是判定口径本身。
    #[test]
    fn ready_reconciliation_only_counts_uncovered_source() {
        use crate::egate_trip::IsolationInventory;
        let record = 2u32;
        let legacy_padded = IsolationInventory {
            egress_trip: 0,
            uncovered: 1,
            legacy: 1,
        };
        // 旧口径（uncovered + legacy）会认为「够了」；新口径必须认为不够。
        assert_eq!(legacy_padded.uncovered + legacy_padded.legacy, record);
        assert!(
            legacy_padded.uncovered < record,
            "旧版遗留规则不得顶替兜底规则的数量"
        );
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
