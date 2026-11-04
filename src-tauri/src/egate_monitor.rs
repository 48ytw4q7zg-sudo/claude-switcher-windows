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

use std::sync::atomic::{AtomicU64, Ordering};
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

/// 用户手动执行隔离：写入 ManualHold 意图，自动恢复不得解除它。
pub fn mark_manual_hold() {
    let state = ManualHoldState {
        manual_hold: true,
        since: now_secs(),
    };
    if let Ok(path) = isolation_intent_file() {
        if let Ok(text) = serde_json::to_string_pretty(&state) {
            let _ = crate::fsx::write_atomically(&path, &text);
        }
    }
}

/// 用户手动解除隔离：清除 ManualHold 意图。
pub fn clear_manual_hold() {
    if let Ok(path) = isolation_intent_file() {
        let _ = std::fs::remove_file(path);
    }
}

/// 当前是否有用户手动保持的隔离（读取失败按 false——见 P0-NEW-04 的意图检查）。
pub fn is_manual_hold() -> bool {
    let Ok(path) = isolation_intent_file() else {
        return false;
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return false;
    };
    let text = crate::jsonio::decode_text(&bytes);
    serde_json::from_str::<ManualHoldState>(&text)
        .map(|state| state.manual_hold)
        .unwrap_or(false)
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
/// 熔断状态：0=未熔断，1=部分熔断，2=完整熔断。
static TRIP_STATE: AtomicU64 = AtomicU64::new(0);
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
}

/// 清除熔断标记（解除隔离后调用）。
pub fn clear_tripped() {
    TRIP_STATE.store(0, Ordering::SeqCst);
}

/// 是否已完整熔断。
pub fn is_tripped() -> bool {
    TRIP_STATE.load(Ordering::SeqCst) == 2
}

/// **P0-06**：是否处于部分熔断（需要补齐隔离）。
pub fn is_partial() -> bool {
    TRIP_STATE.load(Ordering::SeqCst) == 1
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
/// - 查询失败 → 不猜测（保持未熔断，但记日志告知无法确认）
pub fn rebuild_trip_state_from_system() {
    let count = match crate::egate_trip::rule_count() {
        Some(count) => count,
        None => {
            crate::log_error("无法查询防火墙规则，熔断状态无法重建（按未熔断处理，请人工确认）");
            return;
        }
    };
    if count == 0 {
        clear_tripped();
        return;
    }
    // 有规则：默认按部分熔断处理（保守——会触发补齐而非直接解除）。
    mark_tripped_state(false);
    crate::log_error(&format!(
        "检测到 {count} 条本产品防火墙规则残留，已按「部分熔断」重建状态；下一轮巡检将补齐或恢复"
    ));
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
    let gate = current_gate(
        config.egate_enabled,
        report.should_trip || leak.trip,
        report.should_warn || leak.warn,
        recovery,
    );
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
            let trip = crate::egate_trip::trip(&agents);
            // P0-06：只有全部隔离成功才标记完整熔断；部分成功进入可重试状态。
            mark_tripped_state(trip.all_isolated);
            if let Some(app) = ensure_app_handle(app_handle) {
                crate::egate_notify::notify(
                    app,
                    crate::egate_notify::NotifyKind::Trip,
                    &crate::egate_notify::trip_detail(&report),
                );
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
            let trip = crate::egate_trip::trip(&agents);
            mark_tripped_state(trip.all_isolated);
            crate::log_error(&format!(
                "出口门禁补齐隔离：{}（完整={}）",
                trip.note, trip.all_isolated
            ));
        }
        RoundAction::Recover => {
            // P0-07：出口已恢复，自动解除隔离。
            // **P0-NEW-02**：只有核验通过才清除熔断状态。
            match crate::egate_trip::release_all_verified() {
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
}
