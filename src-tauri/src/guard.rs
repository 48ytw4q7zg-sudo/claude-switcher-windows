//! 保镖 kill-switch 与时区看门狗（计划任务 + 常驻巡检）。
//!
//! 迁移自上游 `windows/claude-bodyguard.ps1` 与 `daemons/tz-watchdog.sh`：
//!
//! - **kill-switch**：每 10s 巡检「代理内核进程」与「TUN 网卡」。两者任一
//!   丢失即 **fail-closed** 强制结束 Claude（桌面版进程 `Claude` + CLI `claude`），
//!   防止账号在裸连下暴露真实 IP。掉线状态只在「刚掉线」那一轮记一条日志，
//!   之后每轮仍尝试杀（防止用户在代理挂掉期间重新打开 Claude）。
//! - **时区看门狗**：系统时区偏离 `appconfig.tz_target` 时自动改回并记日志。
//!
//! 安装形态：本 exe 以 `--guard` 参数被「ClaudeBodyguard」计划任务在登录时
//! 拉起（highest 权限，以便 Set-TimeZone / 杀进程），进入 [`run_guard_loop`]
//! 常驻。所有平台差异走 [`crate::platform::imp`]，本文件不写 `#[cfg]`。
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sysinfo::{ProcessesToUpdate, System};

use crate::appconfig;
use crate::paths;
use crate::platform::imp;
use crate::platform::imp::AdapterInfo;

/// 计划任务名（与上游 install.ps1 `Register-ScheduledTask -TaskName 'ClaudeBodyguard'` 一致）。
pub const GUARD_TASK_NAME: &str = "ClaudeBodyguard";
/// 巡检周期（秒），对齐上游 `Start-Sleep -Seconds 10`。
const TICK_INTERVAL_SECS: u64 = 10;

/// 单次巡检结果（供前端安检面板 / 日志消费）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct GuardTick {
    pub tun_up: bool,
    pub tun_detail: String,
    pub client_up: bool,
    /// `tun_up && client_up`。
    pub alive: bool,
    /// 本轮实际被结束的进程描述（kill_processes_by_names 返回值）。
    pub killed: Vec<String>,
}

// ────────────────────────── TUN 在线判定 ──────────────────────────

/// TUN 在线判定（纯函数，对齐 PS `Get-TunStatus`）。
///
/// 1. 优先：存在 **Up** 且任一 IPv4 落在 `198.18.` 假IP段的网卡 → `"198.18 假IP段"`。
/// 2. 回退：存在 **Up** 且驱动描述命中 TAP/TUN/WireGuard/Wintun/VPN/Tailscale
///    的虚拟网卡 → `"通用虚拟网卡"`（兼容 Astrill/OpenVPN 等）。
/// 3. 都没有 → `(false, "不在线")`。
///
/// 必须 `status=="Up"`：Disabled/Disconnected 的网卡即使残留旧 IP 也不算在线
/// （避免拔掉 TUN 后旧 198.18 地址残留导致误判存活）。
pub fn tun_status_from_adapters(adapters: &[AdapterInfo]) -> (bool, &'static str) {
    // 198.18 假IP段优先（与 PS 一致：先查 IP 再回退网卡描述）。
    if adapters.iter().any(|a| {
        a.status.eq_ignore_ascii_case("Up") && a.ipv4.iter().any(|ip| ip.starts_with("198.18."))
    }) {
        return (true, "198.18 假IP段");
    }
    // 回退到任意 Up 的虚拟网卡。
    if adapters
        .iter()
        .any(|a| a.status.eq_ignore_ascii_case("Up") && is_vpn_adapter_description(&a.description))
    {
        return (true, "通用虚拟网卡");
    }
    (false, "不在线")
}

/// 驱动描述是否像虚拟网卡（大小写不敏感子串匹配，等价 PS `-match 'TAP|TUN|...'`）。
fn is_vpn_adapter_description(desc: &str) -> bool {
    let d = desc.to_lowercase();
    d.contains("tap")
        || d.contains("tun")
        || d.contains("wireguard")
        || d.contains("wintun")
        || d.contains("vpn")
        || d.contains("tailscale")
}

// ────────────────────────── 客户端进程存活 ──────────────────────────

/// 各代理模式需要存活的内核进程名（小写、去 `.exe` 后缀）。
///
/// `auto`/`other` 不要求特定进程（只依赖 TUN），返回 `None`——避免误杀。
fn required_process(mode: &str) -> Option<&'static str> {
    match mode {
        "clash-verge" => Some("verge-mihomo"),
        "sing-box" => Some("sing-box"),
        "clashx" => Some("clashx"),
        "surge" => Some("surge"),
        // wireguard 不按进程判定：GUI（wireguard.exe）开着≠隧道在线，真实判定走
        // `WireGuardTunnel$*` 服务查询（见 client_up_for），与上游 PS 一致。
        "wireguard" | "auto" | "other" => None,
        // 未知模式按上游旧版 Clash Verge 行为回退到 verge-mihomo。
        _ => Some("verge-mihomo"),
    }
}

/// 纯逻辑：给定「正在运行的进程名集合」判断客户端是否在线。
/// 便于在单测里注入假进程列表，不依赖 sysinfo。
fn client_alive_in(mode: &str, running: &HashSet<String>) -> bool {
    match required_process(mode) {
        None => true,
        Some(needle) => running.contains(needle),
    }
}

/// 客户端在线判定（含 wireguard 特例）：wireguard 查 `WireGuardTunnel$*` 服务是否
/// Running，其余模式查进程名。服务查询失败按离线处理（fail-closed，与 TUN 探测
/// 失败同语义）。
fn client_up_for(mode: &str, running: &HashSet<String>) -> bool {
    if mode == "wireguard" {
        return imp::wireguard_tunnel_running().unwrap_or(false);
    }
    client_alive_in(mode, running)
}

/// 枚举当前运行的进程名集合（小写、去 `.exe` 后缀）。
fn running_process_names() -> HashSet<String> {
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::All, true);
    system
        .processes()
        .values()
        .map(|p| {
            let name = p.name().to_string_lossy().to_string().to_lowercase();
            // sysinfo 在 Windows 上可能带 ".exe"，统一去掉便于与 required_process 匹配。
            name.strip_suffix(".exe").unwrap_or(&name).to_string()
        })
        .collect()
}

/// 客户端进程/服务是否在线（auto/other 恒 true，只依赖 TUN）。
pub fn client_alive(mode: &str) -> bool {
    let running = running_process_names();
    client_up_for(mode, &running)
}

// ────────────────────────── 巡检纯决策 ──────────────────────────

/// 单次 tick 的纯决策（不含任何 IO）：返回 `(alive, should_log_offline_edge, should_kill)`。
///
/// - `alive`：TUN 与客户端都在线。
/// - `should_log_offline_edge`：仅在「刚从在线掉到离线」那一轮为 true（记一条掉线日志）。
/// - `should_kill`：只要离线就 true——fail-closed，每轮都尝试杀（防用户重开 Claude）。
fn tick_decision(tun_up: bool, client_up: bool, prev_offline: bool) -> (bool, bool, bool) {
    let alive = tun_up && client_up;
    let log_offline = !alive && !prev_offline;
    let kill = !alive;
    (alive, log_offline, kill)
}

// ────────────────────────── 日志 ──────────────────────────

fn now_timestamp() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// 追加一行日志到 `app_data_dir/<filename>`。日志文件天然追加、崩溃安全，
/// 不要求原子写（原子写约束针对 store/凭据这类截断会丢数据的文件）。
fn append_log(filename: &str, line: &str) {
    if let Ok(dir) = paths::app_data_dir() {
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(filename);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            use std::io::Write;
            let _ = writeln!(f, "{line}");
        }
    }
}

// ────────────────────────── 单次巡检 ──────────────────────────

/// 跨 tick 持久化的「上一轮是否离线」状态（对齐 PS 脚本级 `$offline` 变量）。
static OFFLINE: AtomicBool = AtomicBool::new(false);

/// 单次巡检：判定 TUN/客户端 → 离线则 fail-closed 杀 Claude 并记日志。
pub fn guard_tick() -> GuardTick {
    let cfg = appconfig::load();
    let mode = cfg
        .proxy_mode
        .clone()
        .unwrap_or_else(|| "clash-verge".to_string());

    // list_adapters 失败时按空网卡处理 → 判离线 → fail-closed 杀（与 PS
    // SilentlyContinue 返回空一致）。
    let adapters = imp::list_adapters().unwrap_or_default();
    let running = running_process_names();
    let (tun_up, tun_detail) = tun_status_from_adapters(&adapters);
    let client_up = client_up_for(&mode, &running);

    let prev_offline = OFFLINE.swap(!(tun_up && client_up), Ordering::SeqCst);
    let (alive, log_offline, should_kill) = tick_decision(tun_up, client_up, prev_offline);

    if log_offline {
        let client_state = if mode == "auto" || mode == "other" {
            "跳过(仅TUN)"
        } else if client_up {
            "在线"
        } else {
            "离线"
        };
        append_log(
            "bodyguard.log",
            &format!(
                "{} 代理离线(模式={mode}, TUN={tun_detail}, 客户端={client_state})",
                now_timestamp()
            ),
        );
    }

    let mut killed = Vec::new();
    if should_kill {
        // 同时杀桌面版（进程名 Claude）与 CLI（claude）；Get-Process -Name 本就
        // 大小写不敏感，两个名都传是显式对齐任务约定。
        match imp::kill_processes_by_names(&["Claude", "claude"]) {
            Ok(list) if !list.is_empty() => {
                append_log(
                    "bodyguard.log",
                    &format!(
                        "{} 代理离线(内核或TUN丢失),已自动关闭 Claude",
                        now_timestamp()
                    ),
                );
                killed = list;
            }
            Ok(_) => {}
            Err(e) => append_log(
                "bodyguard.log",
                &format!("{} 结束 Claude 失败: {e}", now_timestamp()),
            ),
        }
    }

    GuardTick {
        tun_up,
        tun_detail: tun_detail.to_string(),
        client_up,
        alive,
        killed,
    }
}

/// 时区看门狗：当前时区与 `appconfig.tz_target` 不一致则回滚并记日志。
fn tz_watchdog_tick() {
    let cfg = appconfig::load();
    let Some(target) = cfg.tz_target.clone() else {
        return; // 未锁定目标时区，无可守护
    };
    let current = match imp::current_timezone_id() {
        Ok(c) => c,
        Err(e) => {
            append_log(
                "tz-watchdog.log",
                &format!("{} 读取当前时区失败: {e}", now_timestamp()),
            );
            return;
        }
    };
    if current.eq_ignore_ascii_case(&target) {
        return;
    }
    match imp::set_timezone_id(&target) {
        Ok(()) => append_log(
            "tz-watchdog.log",
            &format!(
                "{} 时区异常: [{current}] 已自动恢复为 {target}",
                now_timestamp()
            ),
        ),
        Err(e) => append_log(
            "tz-watchdog.log",
            &format!(
                "{} 时区恢复失败: 当前[{current}] 目标[{target}] 错误: {e}",
                now_timestamp()
            ),
        ),
    }
}

// ────────────────────────── 常驻循环与安装 ──────────────────────────

/// 常驻巡检循环：每 10s 一次 kill-switch tick + 时区看门狗，永不退出。
/// 由计划任务以 `--guard` 拉起后调用。
pub fn run_guard_loop() -> ! {
    loop {
        let _ = guard_tick();
        tz_watchdog_tick();
        std::thread::sleep(Duration::from_secs(TICK_INTERVAL_SECS));
    }
}

fn current_exe_path() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("定位当前可执行文件失败: {e}"))?;
    exe.into_os_string()
        .into_string()
        .map_err(|_| "可执行路径不是合法 UTF-8".to_string())
}

/// 注册「登录时运行保镖」计划任务（highest=true，便于 Set-TimeZone / 杀进程）。
///
/// 以最高权限注册需要管理员；非管理员调用会从平台层返回明确错误，
/// 前端应据此弹 UAC 让用户重试。
pub fn install_guard() -> Result<(), String> {
    let exe = current_exe_path()?;
    imp::register_logon_task(GUARD_TASK_NAME, &exe, "--guard", true)?;
    // 对齐上游 install.ps1：Register 之后立即 Start-ScheduledTask——
    // 保镖当场生效开始巡检，而不是等下一次登录才上线。
    imp::start_task(GUARD_TASK_NAME)
}

/// 保镖兜底（一键修复步骤 E 用）：未注册则注册；已注册也补一次启动（幂等），
/// 覆盖「任务在但进程没跑」的中间态——上游 install.ps1 同样是注册后立即启动。
pub fn ensure_guard_running() -> Result<(), String> {
    if guard_installed() {
        imp::start_task(GUARD_TASK_NAME)
    } else {
        install_guard()
    }
}

/// 删除保镖计划任务（不存在视为成功）。
pub fn uninstall_guard() -> Result<(), String> {
    imp::delete_task(GUARD_TASK_NAME)
}

/// 保镖计划任务是否已注册。
pub fn guard_installed() -> bool {
    imp::task_exists(GUARD_TASK_NAME).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(name: &str, desc: &str, status: &str, ipv4: &[&str]) -> AdapterInfo {
        AdapterInfo {
            name: name.to_string(),
            description: desc.to_string(),
            status: status.to_string(),
            if_index: 0,
            ipv4: ipv4.iter().map(|s| s.to_string()).collect(),
            ipv6: vec![],
        }
    }

    #[test]
    fn tun_detection_table() {
        // (场景, 网卡列表, 期望结果)
        let cases: Vec<(&str, Vec<AdapterInfo>, (bool, &str))> = vec![
            (
                "198.18 假IP段",
                vec![adapter("Mihomo", "Wintun", "Up", &["198.18.0.2"])],
                (true, "198.18 假IP段"),
            ),
            (
                "通用虚拟网卡 Wintun",
                vec![adapter(
                    "Wintun",
                    "Wintun Userspace Tunnel",
                    "Up",
                    &["10.0.0.2"],
                )],
                (true, "通用虚拟网卡"),
            ),
            (
                "无 TUN（仅物理网卡）",
                vec![adapter(
                    "以太网",
                    "Realtek PCIe GbE",
                    "Up",
                    &["192.168.1.5"],
                )],
                (false, "不在线"),
            ),
            (
                "Disabled 虚拟网卡不算",
                vec![adapter(
                    "Wintun",
                    "Wintun Userspace Tunnel",
                    "Disabled",
                    &["10.0.0.2"],
                )],
                (false, "不在线"),
            ),
            (
                "大小写不敏感 WIREGUARD",
                vec![adapter("wg", "WIREGUARD Tunnel", "Up", &["10.0.0.1"])],
                (true, "通用虚拟网卡"),
            ),
            (
                "198.18 优先于通用虚拟网卡",
                vec![
                    adapter("以太网", "Realtek", "Up", &["192.168.1.5"]),
                    adapter("Mihomo", "Wintun", "Up", &["198.18.0.1"]),
                ],
                (true, "198.18 假IP段"),
            ),
            (
                "Disabled 网卡残留 198.18 不算在线",
                vec![adapter("old", "Wintun", "Disabled", &["198.18.0.9"])],
                (false, "不在线"),
            ),
            (
                "Disconnected 虚拟网卡不算",
                vec![adapter(
                    "tun",
                    "Tailscale Tunnel",
                    "Disconnected",
                    &["100.64.0.1"],
                )],
                (false, "不在线"),
            ),
        ];
        for (desc, adapters, expect) in cases {
            let got = tun_status_from_adapters(&adapters);
            assert_eq!(got, expect, "场景: {desc}");
        }
    }

    #[test]
    fn client_alive_logic_table() {
        let mut running = HashSet::new();
        running.insert("verge-mihomo".to_string());
        running.insert("sing-box".to_string());
        let empty: HashSet<String> = HashSet::new();

        // clash-verge / sing-box 进程在 → 在线
        assert!(client_alive_in("clash-verge", &running));
        assert!(client_alive_in("sing-box", &running));
        // auto/other 不查进程，恒在线
        assert!(client_alive_in("auto", &empty));
        assert!(client_alive_in("other", &empty));
        // 进程不在 → 离线
        assert!(!client_alive_in("clash-verge", &empty));
        assert!(!client_alive_in("surge", &running)); // 无 surge 进程
                                                      // wireguard 不按进程判定（真实判定走 WireGuardTunnel$* 服务，见 client_up_for），
                                                      // 进程表恒放行。
        assert!(client_alive_in("wireguard", &empty));
        // 未知模式回退到 verge-mihomo
        assert!(client_alive_in("some-unknown", &running));
        assert!(!client_alive_in("some-unknown", &empty));
    }

    #[test]
    fn tick_decision_kills_when_offline_and_edges_logged_once() {
        // 在线：不杀、不记日志
        let (alive, log, kill) = tick_decision(true, true, false);
        assert!(alive && !log && !kill);

        // 首次离线（prev=false）：记一次日志 + 杀
        let (alive, log, kill) = tick_decision(false, true, false);
        assert!(!alive && log && kill);

        // 持续离线（prev=true）：仍杀但不重复记日志
        let (alive, log, kill) = tick_decision(false, true, true);
        assert!(!alive && !log && kill);

        // TUN 在但客户端丢：也算离线要杀
        let (alive, _log, kill) = tick_decision(true, false, false);
        assert!(!alive && kill);

        // 恢复在线：不杀
        let (alive, log, kill) = tick_decision(true, true, true);
        assert!(alive && !log && !kill);
    }

    #[test]
    fn task_name_is_stable() {
        assert_eq!(GUARD_TASK_NAME, "ClaudeBodyguard");
    }
}
