//! Claude Desktop 桌面版（`%APPDATA%\Claude`）账号快照与切换。
//!
//! 与 [`crate::isolation`] 管理的 Claude Code CLI（`~/.claude`）并列：Desktop 是
//! Electron 应用，其登录态与本地状态整体落在 `%APPDATA%\Claude`。上游 PowerShell
//! 用 `robocopy /MIR` 整目录镜像实现存档/载入，本模块用 Rust 递归拷贝对齐该行为，
//! 并在切换前把当前活目录先备份到 staging（崩溃可回滚）。
//!
//! 行为基准（上游 windows/claude-switch.ps1）：
//! - `Stop-ClaudeApp`：按进程名 `Claude` 强制结束，再轮询等待最多 15 秒退出；
//! - `Save-Account`：robocopy 活目录 -> 账号槽位（镜像）；
//! - `Invoke-Switch`：结束 Claude -> 存档当前 -> 删除活目录 -> robocopy 目标槽位
//!   -> 启动 Claude。
//!
//! 设计约束（沿用 AGENTS.md）：
//! - 递归复制、进程检测全部走本模块的可注入边界（`running`/`kill`/`copy` 闭包），
//!   纯文件系统逻辑拿临时目录即可表驱动单测，不依赖真实网络 / 真实 Claude；
//! - 被占用文件一律 [`fsx::retry_io`] 短退避重试，绝不裸 unwrap；
//! - 符号链接 / junction（含悬空 junction）一律跳过，不跟随、不炸目录；
//! - 切换失败自动用 staging 备份回滚，活目录绝不留拷了一半的状态。
use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use uuid::Uuid;

use crate::fsx;
use crate::links;
use crate::paths;
use crate::platform::imp;
use crate::store::{self, DesktopProfile, Store};

/// Claude Desktop 活数据目录名（拼在 `config_dir()` 下，即 `%APPDATA%\Claude`）。
const DESKTOP_DIR_NAME: &str = "Claude";
/// 快照根目录（相对 `app_data_dir()`）。
const DESKTOP_ACCOUNTS_SUBDIR: &str = "desktop-accounts";
/// 切换前活目录的备份暂存（相对 `app_data_dir()`，带下划线前缀不参与账号枚举）。
const LIVE_BACKUP_SUBDIR: &str = "desktop-accounts/.live-backup";
/// 结束进程后轮询其退出的轮次与间隔（对齐上游 Stop-ClaudeApp 的 15 秒等待）。
const QUIT_WAIT_ROUNDS: u32 = 15;
const QUIT_WAIT_INTERVAL_MS: u64 = 1000;
/// 温和关闭的等待：10 轮 × 500ms = 5 秒（Electron flush + 自行退出通常 <2 秒）。
const GRACEFUL_WAIT_ROUNDS: u32 = 10;
const GRACEFUL_WAIT_INTERVAL_MS: u64 = 500;

// ───────────────────────── 路径 ─────────────────────────

/// MSIX 版 Claude 的数据根目录名（拼在 `%LOCALAPPDATA%` 下）。
const MSIX_DATA_DIR_NAME: &str = "Claude-Data";
/// MSIX 数据目录下包族子目录的前缀（`claude_<hash>`）。
const MSIX_DIR_PREFIX: &str = "claude_";

/// 纯函数：按上游 `Find-ClaudeDataPath` 的优先级解析 Claude Desktop 活数据目录。
///
/// 1. `%APPDATA%\Claude` 存在（传统 EXE 安装）→ 用它；
/// 2. 否则按 AppX 包族名找 `%LOCALAPPDATA%\Claude-Data\<PackageFamilyName>`；
/// 3. 再退到 `Claude-Data\` 下**唯一**的 `claude_*` 子目录；
/// 4. 都没有 → 回落到 `%APPDATA%\Claude`（让调用方给出明确的「未安装」错误）。
///
/// 三个输入全部可注入，测试不必依赖真实环境或 MSIX 安装。
fn resolve_desktop_live_dir(
    appdata_claude: &Path,
    msix_root: &Path,
    appx_families: &[String],
) -> PathBuf {
    // 1. 传统安装优先：MSIX 与 EXE 并存时以真实在用的目录为准。
    if appdata_claude.is_dir() {
        return appdata_claude.to_path_buf();
    }
    resolve_msix_data_dir(msix_root, appx_families).unwrap_or_else(|| appdata_claude.to_path_buf())
}

fn resolve_msix_data_dir(msix_root: &Path, appx_families: &[String]) -> Option<PathBuf> {
    // 2. AppX 包族名精确命中。
    for family in appx_families {
        let candidate = msix_root.join(family);
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    // 3. 只有一个 claude_* 子目录时也能唯一定位。
    if let Ok(entries) = fs::read_dir(msix_root) {
        let mut matches: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.is_dir()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.to_ascii_lowercase().starts_with(MSIX_DIR_PREFIX))
            })
            .collect();
        if matches.len() == 1 {
            return Some(matches.remove(0));
        }
    }
    None
}

/// Claude Desktop 活数据目录：MSIX 感知。
///
/// 上游 `Find-ClaudeDataPath` 的行为基准：先 `%APPDATA%\Claude`，再按
/// `Get-AppxPackage` 的 PackageFamilyName 找 `%LOCALAPPDATA%\Claude-Data\*`。
pub fn desktop_live_dir() -> Result<PathBuf, String> {
    let config = dirs::config_dir()
        .ok_or_else(|| "无法定位应用配置目录（%APPDATA% / config_dir）".to_string())?;
    let legacy = config.join(DESKTOP_DIR_NAME);
    if legacy.is_dir() {
        return Ok(legacy);
    }
    // 传统目录不存在时才查 MSIX（多一次 PowerShell 调用，只在首次用到）。
    let local = dirs::data_local_dir()
        .ok_or_else(|| "无法定位本地数据目录（%LOCALAPPDATA%）".to_string())?;
    let msix_root = local.join(MSIX_DATA_DIR_NAME);
    let families = imp::claude_appx_families();
    Ok(resolve_desktop_live_dir(&legacy, &msix_root, &families))
}

fn client_locale_from_dirs(
    legacy: &Path,
    msix_root: &Path,
    families: &[String],
) -> Result<String, String> {
    let legacy_config = legacy.join("config.json");
    let config_path = if legacy_config.try_exists().map_err(|e| e.to_string())? {
        legacy_config
    } else {
        let mut registered = families
            .iter()
            .map(|family| msix_root.join(family))
            .filter(|candidate| candidate.is_dir());
        if let Some(first) = registered.next() {
            let first = imp::normalize_path(&first);
            if registered.any(|candidate| imp::normalize_path(&candidate) != first) {
                return Err("发现多个 Claude 安装版本，无法确定语言配置".to_string());
            }
        }
        // MSIX 迁移后旧目录可能仅保留 MCP 配置；不能用旧目录存在代替语言配置存在。
        resolve_msix_data_dir(msix_root, families)
            .ok_or_else(|| "未能定位 Claude 的语言配置".to_string())?
            .join("config.json")
    };
    read_client_locale_config(&config_path)
}

fn read_client_locale_config(path: &Path) -> Result<String, String> {
    let config = crate::jsonio::read_json_optional(path.to_path_buf())?;
    config
        .and_then(|value| {
            value
                .get("locale")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .filter(|locale| valid_client_locale(locale))
        .ok_or_else(|| "未能读取 Claude 的语言设置".to_string())
}

fn valid_client_locale(locale: &str) -> bool {
    let mut parts = locale.split('-');
    let language = parts.next().unwrap_or_default();
    (2..=3).contains(&language.len())
        && language.bytes().all(|c| c.is_ascii_alphabetic())
        && parts.all(|part| {
            (2..=8).contains(&part.len()) && part.bytes().all(|c| c.is_ascii_alphanumeric())
        })
}

/// 读取 Claude 的语言配置；不等同于验证运行中的 navigator.language。
pub fn client_locale() -> Result<String, String> {
    let legacy = dirs::config_dir()
        .ok_or_else(|| "无法定位应用配置目录（%APPDATA%）".to_string())?
        .join(DESKTOP_DIR_NAME);
    let config = legacy.join("config.json");
    if config.try_exists().map_err(|e| e.to_string())? {
        return read_client_locale_config(&config);
    }
    // 仅在传统配置缺失时查询 AppX 包族，避免给普通安装额外增加 PowerShell 调用。
    let msix_root = dirs::data_local_dir()
        .ok_or_else(|| "无法定位本地数据目录（%LOCALAPPDATA%）".to_string())?
        .join(MSIX_DATA_DIR_NAME);
    client_locale_from_dirs(&legacy, &msix_root, &imp::claude_appx_families())
}

/// 快照根目录 `~/.claude-switcher/desktop-accounts`。
pub fn desktop_accounts_dir() -> Result<PathBuf, String> {
    Ok(paths::app_data_dir()?.join(DESKTOP_ACCOUNTS_SUBDIR))
}

/// 指定账号的快照目录。
pub fn desktop_snapshot_dir(id: &str) -> Result<PathBuf, String> {
    Ok(desktop_accounts_dir()?.join(id))
}

fn live_backup_root() -> Result<PathBuf, String> {
    Ok(paths::app_data_dir()?.join(LIVE_BACKUP_SUBDIR))
}

// ───────────────────────── 递归复制（独立可测） ─────────────────────────

/// 一次目录复制的统计结果。
#[derive(Debug, Clone, Copy, Default)]
pub struct CopyOutcome {
    /// 实际拷贝的文件字节总数。
    pub bytes: u64,
    /// 被跳过的符号链接 / junction（含悬空 junction）数量。
    pub skipped_links: usize,
}

/// 可注入的「按名杀进程」闭包签名（测试可替换）。
type KillFn = dyn Fn(&[&str]) -> Result<Vec<String>, String>;
/// 可注入的「Claude Desktop 是否在运行」判定闭包签名。
type RunningFn = dyn Fn() -> Result<bool, String>;
/// 可注入的「递归复制」闭包签名（失败路径单测可模拟）。
type CopyFn = dyn Fn(&Path, &Path) -> Result<CopyOutcome, String>;

/// 递归复制目录树 `src` -> `dst`（`dst` 不存在则创建，存在则合并覆盖同名文件）。
///
/// - 不跟随符号链接 / junction：`symlink_metadata` 判定，悬空 junction 也能识别；
///   快照把链接指向的数据整包拷进来既不安全（可能是无关大目录）也不可移植。
/// - 被占用文件走 [`fsx::retry_io`] 短退避重试（Windows 错误 5/32/33）。
/// - fifo/socket 等非常规条目跳过，不报错。
pub fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<CopyOutcome, String> {
    if !src.is_dir() {
        return Err(format!("源目录不存在或不是目录: {}", src.display()));
    }
    fs::create_dir_all(dst).map_err(|e| format!("创建目标目录失败 {}: {e}", dst.display()))?;
    let mut outcome = CopyOutcome::default();
    copy_dir_recursive_inner(src, dst, &mut outcome)?;
    Ok(outcome)
}

fn copy_dir_recursive_inner(
    src: &Path,
    dst: &Path,
    outcome: &mut CopyOutcome,
) -> Result<(), String> {
    let entries = fs::read_dir(src).map_err(|e| {
        format!(
            "读取目录失败 {}: {}",
            src.display(),
            fsx::humanize_io_error(&e)
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("读取目录项失败 {}: {e}", src.display()))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        // 先看链接（不跟随）：symlink_metadata 对悬空 junction 依然有效，
        // 否则 entry.metadata() 打开悬空点会直接报错中断整个复制。
        if imp::is_link(&src_path) {
            outcome.skipped_links += 1;
            continue;
        }
        let meta = entry
            .metadata()
            .map_err(|e| format!("读取文件属性失败 {}: {}", src_path.display(), e))?;
        if meta.is_dir() {
            fs::create_dir_all(&dst_path)
                .map_err(|e| format!("创建目录失败 {}: {}", dst_path.display(), e))?;
            copy_dir_recursive_inner(&src_path, &dst_path, outcome)?;
        } else if meta.is_file() {
            let copied = fsx::retry_io(|| fs::copy(&src_path, &dst_path)).map_err(|e| {
                format!(
                    "复制文件失败 {} -> {}: {}",
                    src_path.display(),
                    dst_path.display(),
                    fsx::humanize_io_error(&e)
                )
            })?;
            outcome.bytes += copied;
        }
        // 其它类型（fifo/socket 等）跳过。
    }
    Ok(())
}

/// 递归统计目录体积（字节），符号链接不跟随。
pub fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    dir_size_inner(path, &mut total);
    total
}

fn dir_size_inner(path: &Path, total: &mut u64) {
    if imp::is_link(path) {
        return;
    }
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            dir_size_inner(&entry.path(), total);
        }
    } else if meta.is_file() {
        *total += meta.len();
    }
}

// ───────────────────────── 进程检测 ─────────────────────────

/// 判定 exe 路径是否指向 Claude Desktop（而非 Claude Code CLI / 本工具自身）。
///
/// 表格对齐 [`crate::processes`] 的黑名单特征：
/// - 标准安装：路径含 `anthropicclaude`（`%LOCALAPPDATA%\AnthropicClaude`）；
/// - MSIX/Store 安装：`WindowsApps` 下可执行名为 `claude(.exe)` 的即 Desktop
///   （官方 CLI 不上架 Store）。
fn is_claude_desktop_exe(exe: Option<&str>) -> bool {
    let Some(exe_path) = exe else {
        return false;
    };
    let lower = exe_path.to_lowercase();
    if lower.contains("anthropicclaude") {
        return true;
    }
    let name = lower.rsplit(['\\', '/']).next().unwrap_or("");
    if lower.contains("\\windowsapps\\") && (name == "claude.exe" || name == "claude") {
        return true;
    }
    false
}

/// Claude Desktop 主进程与全部子进程的 PID 列表（含 renderer/gpu/utility，
/// 它们的 exe 路径同样落在 AnthropicClaude 目录下）。
fn claude_desktop_processes() -> Vec<u32> {
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    let self_pid = imp::current_pid();
    system
        .processes()
        .iter()
        .filter(|(pid, _)| pid.as_u32() != self_pid)
        .filter(|(_, process)| is_claude_desktop_exe(process.exe().and_then(|p| p.to_str())))
        .map(|(pid, _)| pid.as_u32())
        .collect()
}

/// Claude Desktop 是否正在运行。
pub fn claude_desktop_running() -> Result<bool, String> {
    Ok(!claude_desktop_processes().is_empty())
}

/// 按 PID 结束 Desktop 进程树（不按 exe 名）。
///
/// **不能只按进程名杀**：`is_claude_desktop_exe` 按 exe 路径判定，接受的形态
/// 包括 `AnthropicClaude\app.exe`（主程序镜像名不是 `Claude`）。早期只
/// `kill(&["Claude"])`，那种安装下杀不到任何进程，`wait_until_quite` 15 秒后
/// 必然超时——Desktop 切换功能整体不可用。这里按判定同源的 PID 列表终止。
fn kill_desktop_processes() -> Result<Vec<String>, String> {
    let pids = claude_desktop_processes();
    if pids.is_empty() {
        return Ok(Vec::new());
    }
    let mut killed = Vec::new();
    // 两段式结束：先温和关闭，再强杀。
    //
    // Claude Desktop 是 Electron 应用，`%APPDATA%\Claude` 里有 LevelDB 与
    // SQLite（带 WAL）。直接 `taskkill /F` 会在任意两点之间撕掉进程，WAL 可能
    // 没来得及 checkpoint，拷出来的快照处于不一致状态——下次载入时登录态或
    // 会话异常，而这种损坏是延迟暴露的，很难查。
    // 温和关闭（不带 /F，对 GUI 窗口发 WM_CLOSE）让应用自己 flush 后退出；
    // 等待数秒仍未退出才强杀。托盘常驻的辅助进程也要覆盖。
    for pid in &pids {
        let _ = crate::platform::imp::silent_command("taskkill")
            .args(["/PID", &pid.to_string()])
            .output();
    }
    // 给应用留出 flush + 自行退出的时间（含子进程逐个退出）。
    let mut still_running = Vec::new();
    for _ in 0..GRACEFUL_WAIT_ROUNDS {
        std::thread::sleep(std::time::Duration::from_millis(GRACEFUL_WAIT_INTERVAL_MS));
        still_running = claude_desktop_processes();
        if still_running.is_empty() {
            return Ok(killed);
        }
    }

    // 超时：对仍存活的进程强杀。
    for pid in &still_running {
        let _ = crate::platform::imp::silent_command("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .output();
        killed.push(format!("Claude Desktop (PID {pid}, 强制)"));
    }
    // 等一小会儿让句柄释放，再让调用方轮询判定。
    std::thread::sleep(std::time::Duration::from_millis(500));
    Ok(killed)
}

fn wait_until_quite(running: &dyn Fn() -> Result<bool, String>) -> Result<(), String> {
    for _ in 0..QUIT_WAIT_ROUNDS {
        if !running()? {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(QUIT_WAIT_INTERVAL_MS));
    }
    Err("Claude Desktop 未能完全退出（托盘图标也需退出），请手动退出后重试".to_string())
}

// ───────────────────────── 快照列表 ─────────────────────────

/// 列出全部 Desktop 账号快照（读 store；store 损坏时记录错误并返回空列表，
/// 避免前端列表整页崩）。
pub fn list_desktop_profiles() -> Vec<DesktopProfile> {
    match store::load_store() {
        Ok(store) => store.desktop_profiles,
        Err(e) => {
            crate::log_error(&format!("读取桌面账号列表失败: {e}"));
            Vec::new()
        }
    }
}

// ───────────────────────── 捕获快照 ─────────────────────────

/// 捕获当前 `%APPDATA%\Claude` 为一个新的 Desktop 账号快照。
///
/// 前置：Claude Desktop 必须已完全退出（含托盘），否则缓存/锁文件会让拷贝
/// 不完整。
pub fn capture_desktop_profile(
    name: &str,
    notes: Option<String>,
) -> Result<DesktopProfile, String> {
    let live = desktop_live_dir()?;
    paths::ensure_app_dirs()?;
    let id = Uuid::new_v4().simple().to_string();
    let snapshot = desktop_snapshot_dir(&id)?;
    // H-2：账号库读—改—写走 with_store（外部 copy/running 检查在闭包内，随事务一起）。
    store::with_store(|store| {
        capture_desktop_profile_into(name, notes, &live, &snapshot, store, &|| {
            claude_desktop_running()
        })
    })
}

/// [`capture_desktop_profile`] 的可注入版本：活目录、快照目录、store 与
/// 「是否在运行」判定全部由参数传入，测试用临时目录 + 假判定即可覆盖。
#[allow(clippy::too_many_arguments)]
fn capture_desktop_profile_into(
    name: &str,
    notes: Option<String>,
    live_dir: &Path,
    snapshot_dir: &Path,
    store: &mut Store,
    running: &RunningFn,
) -> Result<DesktopProfile, String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("账号名称不能为空".to_string());
    }
    if !live_dir.is_dir() {
        return Err(format!(
            "未找到 Claude Desktop 数据目录（{}）：请先安装并至少登录一次 Claude Desktop",
            live_dir.display()
        ));
    }
    if running()? {
        return Err(
            "Claude Desktop 仍在运行。请先通过托盘图标完全退出 Claude Desktop 后再捕获快照"
                .to_string(),
        );
    }
    if snapshot_dir.exists() {
        return Err(format!(
            "快照目录已存在（{}），请重试",
            snapshot_dir.display()
        ));
    }

    let outcome = copy_dir_recursive(live_dir, snapshot_dir)?;
    let id = snapshot_dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .ok_or_else(|| "快照目录命名异常".to_string())?;
    let now = Utc::now();
    let profile = DesktopProfile {
        id: id.clone(),
        name,
        notes,
        created_at: now,
        updated_at: now,
        last_switched_at: None,
        snapshot_rel: format!("{DESKTOP_ACCOUNTS_SUBDIR}/{id}"),
        size_bytes: outcome.bytes,
        meta: None,
    };
    store.desktop_profiles.push(profile.clone());
    // capture 到的就是此刻的活目录，因此它立即成为「当前桌面账号」：
    // 之后第一次切换才会把此后的使用变更回存给它。
    store.current_desktop_profile_id = Some(profile.id.clone());
    Ok(profile)
}

// ───────────────────────── 切换账号 ─────────────────────────

/// 切换到指定 Desktop 账号：完全退出 Claude -> 备份当前活目录 -> 清空活目录
/// -> 目标快照覆盖回活目录。失败自动用备份回滚。
pub fn switch_desktop_profile(id: &str) -> Result<Vec<String>, String> {
    let live = desktop_live_dir()?;
    let accounts = desktop_accounts_dir()?;
    let backup_root = live_backup_root()?;

    // **P0-07**：文件切换与账号库提交必须形成事务。
    //
    // with_store 是「先执行闭包、再 save_store」。如果闭包里的文件切换成功
    // 但 save_store 失败，就会出现「活目录是 B、账号库记录是 A」。
    //
    // 做法：闭包内记录本次切换前的活目录备份路径；若 save_store 失败
    // （with_store 返回 Err 且错误来自保存），用该备份把活目录回滚。
    // **P0-NEW-03**：由 switch_desktop_profile_in 通过 out-param 回传**本次**精确备份路径。
    // 绝不用 «扫描备份目录取最新» 猜测——那可能选中其他账号的历史备份。
    let transaction = DesktopTransaction {
        target_id: id.to_string(),
        backup_path: std::cell::RefCell::new(None),
        original_existed: std::cell::Cell::new(false),
        phase: std::cell::Cell::new(DesktopSwitchPhase::Prepared),
    };
    // **P0-08 / P0-F**：账本必须**在取得账号库执行权之后**才写。
    //
    // 原实现先写账本、再进 `with_store`：两个并发的 Desktop 切换会在等锁期间
    // 互相覆盖对方的账本（后写的赢），导致先执行的那次切换丢失恢复依据。
    // 现在把建账本 + 检查未完成事务都放进闭包内（已持 STORE_LOCK）。
    let tx_id = Uuid::new_v4().simple().to_string();
    let mut ledger_slot: Option<DesktopSwitchLedger> = None;

    let mut switched = false;
    let result = store::with_store(|store| {
        // **P0-F**：已有未完成**迁移**事务时同样拒绝——迁移会整体替换
        // `desktop-accounts`，此时切换 Desktop 会拿到即将被替换的目录。
        if crate::export::has_pending_migration() {
            return Err(
                "检测到未完成的完整迁移事务，请先重启应用让恢复器处理后再切换 Desktop".to_string(),
            );
        }
        // **P0-F**：已有未完成事务时拒绝新的破坏性操作，避免覆盖现场。
        if let Some(existing) = read_pending_switch_ledger()? {
            return Err(format!(
                "检测到未完成的 Desktop 切换（事务 {}，目标 {}）。                 请先重启应用让恢复器处理，或人工核对后再操作",
                existing.transaction_id, existing.to_id
            ));
        }
        let ledger = DesktopSwitchLedger {
            transaction_id: tx_id.clone(),
            from_id: store.current_desktop_profile_id.clone(),
            to_id: id.to_string(),
            backup_path: None,
            original_existed: live.is_dir(),
            live_dir: live.to_string_lossy().to_string(),
            store_commit: None,
            snapshot_swap: None,
            phase: DesktopSwitchPhase::Prepared,
            started_at: chrono::Utc::now().timestamp(),
        };
        write_switch_ledger(&ledger)
            .map_err(|e| format!("写入 Desktop 切换账本失败，已放弃切换：{e}"))?;
        ledger_slot = Some(ledger);

        let outcome = switch_desktop_profile_in(
            id,
            &live,
            &accounts,
            store,
            &|_names| kill_desktop_processes(),
            &|| claude_desktop_running(),
            &backup_root,
            &copy_dir_recursive,
            &transaction,
        );
        if outcome.is_ok() {
            // 事务 ID 与当前 Desktop 账号在同一次账号库保存中原子落盘。
            store.last_desktop_transaction_id = Some(tx_id.clone());
            switched = true;
        }
        outcome
    });

    // 更新账本：记录精确备份路径与阶段。
    //
    // 闭包可能在建账本之前就失败（例如「已有未完成事务」），此时
    // `ledger_slot` 为空——直接用临时账本占位，后续分支不会再写盘。
    let Some(base_ledger) = ledger_slot.clone() else {
        return Err(match result {
            Ok(_) => "Desktop 切换未建立事务账本".to_string(),
            Err(error) => error,
        });
    };
    let mut final_ledger = base_ledger.clone();
    final_ledger.backup_path = transaction
        .backup_path
        .borrow()
        .as_ref()
        .map(|p| p.to_string_lossy().to_string());
    // **P0-03**：**绝不在失败路径上把账本推进到比实际更靠后的阶段。**
    //
    // 原实现在这里无条件写 `FilesSwitched`：一次「目标快照不存在」的前置
    // 检查失败，就会留下 `original_existed=true + backup_path=None` 的账本，
    // 恢复器无法判断如何恢复只能保留，之后每次切换都被
    // `read_pending_switch_ledger()` 拒绝——一次普通失败永久卡死切换功能。
    //
    // 现在只在**确实完成了文件切换**时推进；否则保持在已落盘的真实阶段。
    if switched {
        final_ledger.phase = DesktopSwitchPhase::FilesSwitched;
    }

    match result {
        Ok(mut warnings) => {
            // `with_store` 已成功返回 → 账号库确实落盘，此时才是 StoreCommitted。
            // **P0-A**：先把「提交标记」写进账本，再改阶段——标记里带事务 ID 与
            // 目标账号，恢复器据此判断账号库到底提交了哪一次切换。
            final_ledger.store_commit = Some(StoreCommitMarker {
                transaction_id: base_ledger.transaction_id.clone(),
                to_id: base_ledger.to_id.clone(),
                committed_at: chrono::Utc::now().timestamp(),
            });
            final_ledger.phase = DesktopSwitchPhase::StoreCommitted;
            if let Err(error) = write_switch_ledger(&final_ledger) {
                // 账本写不进去不影响本次切换的正确性（数据已一致），
                // 但下次启动会看到 FilesSwitched 并尝试回滚——必须让用户知道。
                let _ = clear_switch_ledger();
                warnings.push(format!(
                    "切换已完成，但完成标记写入失败（{error}）；已清理账本避免下次启动误回滚"
                ));
            } else if let Err(error) = clear_switch_ledger() {
                warnings.push(error);
            }
            Ok(warnings)
        }
        Err(error) => {
            // 若是保存账号库失败且文件已切换 → 回滚活目录，恢复一致状态。
            if switched {
                let backup = transaction.backup_path.borrow().clone();
                if let Some(backup) = &backup {
                    let rollback = (|| -> Result<(), String> {
                        if live.exists() || links::path_is_link(&live) {
                            fsx::retry_io(|| fs::remove_dir_all(&live))
                                .map_err(|e| format!("清理目标目录失败：{e}"))?;
                        }
                        copy_dir_recursive(backup, &live)
                            .map(|_| ())
                            .map_err(|e| format!("还原活目录失败：{e}"))
                    })();
                    return Err(match rollback {
                        Ok(()) => format!(
                            "{error}；账号库保存失败，已将 Desktop 活目录回滚到切换前状态"
                        ),
                        Err(rollback_error) => format!(
                            "{error}；账号库保存失败且活目录回滚失败（{rollback_error}），                             请用备份手动恢复：{}",
                            backup.display()
                        ),
                    });
                } else if !transaction.original_existed.get() {
                    // **P0-NEW-03**：原本没有活目录 → 回滚应恢复「不存在」，
                    // 不能错误复制任何历史备份。
                    let cleared = fsx::retry_io(|| fs::remove_dir_all(&live)).is_ok();
                    return Err(if cleared {
                        format!("{error}；账号库保存失败，已清理本次载入内容（原本无活目录）")
                    } else {
                        format!(
                            "{error}；账号库保存失败且清理失败，请手动删除 {}",
                            live.display()
                        )
                    });
                }
            }
            // **P0-02**：错误路径不删除账本。
            //
            // - 回滚成功：账本写回 `FilesSwitched` 会误导下次启动去"回滚"一个
            //   已经一致的状态；因此这里**清掉**账本，但清失败要如实报告。
            // - 回滚失败：账本必须留下（下次启动重试恢复），且阶段保持
            //   `FilesSwitched`（可回滚态）。
            // **P0-A**：判定依据是**事务实际推进到的阶段**（`transaction.phase`）
            // 与**磁盘账本**，而不是外层最初创建的 `Prepared`。
            //
            // 原实现用 `base_ledger.phase` 判断：内层已经推进到 FilesSwitching、
            // 甚至清空了一半活目录后才失败，外层仍认为「没动过文件」而清掉账本，
            // 结果需要恢复的现场失去了恢复依据。
            let disk_phase = read_pending_switch_ledger()
                .ok()
                .flatten()
                .map(|l| l.phase)
                .unwrap_or(DesktopSwitchPhase::Unknown);
            let effective_phase = match (transaction.phase.get(), disk_phase) {
                // 两者取「更靠后」的那个：任何一方显示动过文件，就必须保留账本。
                (a, DesktopSwitchPhase::Unknown) => a,
                (a, b) => {
                    if phase_rank(b) > phase_rank(a) {
                        b
                    } else {
                        a
                    }
                }
            };
            let touched_files = matches!(
                effective_phase,
                DesktopSwitchPhase::BackupVerified
                    | DesktopSwitchPhase::FilesSwitching
                    | DesktopSwitchPhase::FilesSwitched
            );
            if !touched_files {
                if let Err(clear_error) = clear_switch_ledger() {
                    return Err(format!(
                        "{error}；且清理未开始的切换账本失败（{clear_error}）"
                    ));
                }
                return Err(error);
            }
            // 动过文件：账本必须留下，且写明**实际阶段**（便于恢复器判断）。
            final_ledger.phase = effective_phase;
            if let Err(write_error) = write_switch_ledger(&final_ledger) {
                return Err(format!(
                    "{error}；且切换账本写入失败（{write_error}），下次启动可能需要人工核对 {}",
                    live.display()
                ));
            }
            Err(error)
        }
    }
}

/// **P0-NEW-03**：Desktop 切换事务上下文（记录本次切换的精确备份）。
///
/// **P0-08**：同时写入持久化账本，供程序崩溃后恢复。
struct DesktopTransaction {
    target_id: String,
    /// 本次切换创建的原活目录备份（精确路径，不靠扫描猜测）。
    backup_path: std::cell::RefCell<Option<std::path::PathBuf>>,
    /// 切换前活目录是否存在。
    original_existed: std::cell::Cell<bool>,
    /// **P0-A**：本次事务**实际推进到**的阶段（由 `advance_ledger_phase` 回写）。
    ///
    /// 外层错误处理不能再用最初创建的 `Prepared` 判断「有没有动过文件」：
    /// 内层可能已经把账本推进到 `FilesSwitching`、清空了活目录后才失败。
    phase: std::cell::Cell<DesktopSwitchPhase>,
}

impl Default for DesktopTransaction {
    fn default() -> Self {
        Self {
            target_id: String::new(),
            backup_path: std::cell::RefCell::new(None),
            original_existed: std::cell::Cell::new(false),
            phase: std::cell::Cell::new(DesktopSwitchPhase::Prepared),
        }
    }
}

/// **P0-A**：账号库提交标记（写入账本，用于崩溃后判定提交归属）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoreCommitMarker {
    /// 本次事务 ID（与账本一致，防止把别的切换当成自己）。
    transaction_id: String,
    /// 提交后账号库记录的当前 Desktop 账号。
    to_id: String,
    /// 提交时间（unix 秒）。
    committed_at: i64,
}

/// 回存当前账号快照的两段式替换状态。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotSwapState {
    snapshot_id: String,
    snapshot: String,
    staging: String,
    retired: String,
    /// 原快照已改名为 retired；此时若正式目录缺失，启动恢复必须把它请回来。
    retired_original: bool,
}

/// **P0-08**：Desktop 切换事务账本（落盘，崩溃后恢复用）。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DesktopSwitchLedger {
    /// 事务 ID。
    transaction_id: String,
    /// 原始账号 ID（切换前）。
    from_id: Option<String>,
    /// 目标账号 ID。
    to_id: String,
    /// 本次备份路径（精确）。
    backup_path: Option<String>,
    /// 切换前活目录是否存在。
    original_existed: bool,
    /// 活目录路径。
    live_dir: String,
    /// **P0-A**：账号库提交标记。
    ///
    /// 只有 `with_store()` **真正返回 Ok** 之后才写入，并在同一次账本更新里
    /// 带上 `to_id`。恢复器据此判断「账号库是否已经提交了这次切换」——
    /// 阶段枚举本身不足以证明：崩溃可能恰好发生在保存成功与阶段更新之间。
    #[serde(default)]
    store_commit: Option<StoreCommitMarker>,
    /// 当前账号快照回存子事务。
    #[serde(default)]
    snapshot_swap: Option<SnapshotSwapState>,
    /// 事务阶段。
    ///
    /// **P0-02**：从任意字符串改为枚举。原实现用 `"prepared"` / `"backup_verified"`
    /// 等字面量，而 `heal_desktop_switch()` 的 `match` 只列了其中几个，
    /// 新增的 `backup_verified` 直接落到「未知阶段」——关键崩溃窗口无人处理。
    /// 枚举 + `#[serde(other)]` 兜底让「新增阶段忘记加分支」变成编译期可见的
    /// 未覆盖分支，而不是运行时的静默忽略。
    #[serde(default = "DesktopSwitchPhase::default_missing")]
    phase: DesktopSwitchPhase,
    /// 开始时间（unix 秒）。
    started_at: i64,
}

/// Desktop 切换事务阶段。
///
/// 每个阶段都必须有确定的恢复决策（见 `heal_desktop_switch` 的穷尽 `match`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopSwitchPhase {
    /// 已写账本，尚未备份。
    Prepared,
    /// 备份已完成并登记——**此时崩溃可以确定回滚**。
    BackupVerified,
    /// 活目录正在被替换（不可逆修改已开始）。
    FilesSwitching,
    /// 文件已替换，账号库尚未提交。
    FilesSwitched,
    /// 账号库已提交（切换实际生效）。
    StoreCommitted,
    /// 全部完成，仅剩清理账本。
    Completed,
    /// 不认识的阶段（旧版本或损坏）：保守处理，绝不自动删除。
    #[serde(other)]
    Unknown,
}

/// 阶段先后顺序（数值越大越「靠后」）。用于在「内存记录」与「磁盘账本」
/// 不一致时取更保守（更靠后）的那个。
fn phase_rank(phase: DesktopSwitchPhase) -> u8 {
    match phase {
        DesktopSwitchPhase::Prepared => 0,
        DesktopSwitchPhase::BackupVerified => 1,
        DesktopSwitchPhase::FilesSwitching => 2,
        DesktopSwitchPhase::FilesSwitched => 3,
        DesktopSwitchPhase::StoreCommitted => 4,
        DesktopSwitchPhase::Completed => 5,
        DesktopSwitchPhase::Unknown => 0,
    }
}

impl DesktopSwitchPhase {
    /// 反序列化缺省值：旧账本没有枚举化时按「未知」处理（保守）。
    fn default_missing() -> Self {
        DesktopSwitchPhase::Unknown
    }
}

fn desktop_switch_ledger_path() -> Result<std::path::PathBuf, String> {
    Ok(crate::paths::app_data_dir()?.join("desktop-switch.json"))
}

fn write_switch_ledger(ledger: &DesktopSwitchLedger) -> Result<(), String> {
    let path = desktop_switch_ledger_path()?;
    let text =
        serde_json::to_string_pretty(ledger).map_err(|e| format!("序列化切换账本失败：{e}"))?;
    fsx::write_atomically(&path, &text).map_err(|e| format!("写入切换账本失败：{e}"))
}

/// **P0-01**：备份一落地就更新持久化账本，再允许删除活目录。
///
/// 原实现在 `with_store()` 返回后才把备份路径写入账本：在备份与记账之间崩溃，
/// 磁盘账本仍是 `backup_path=None`，恢复器会误当作「原本没有活目录」而删掉
/// 唯一可用副本。改为备份成功即记账，写失败则中止切换（原账号尚未被动）。
///
/// **P0-02**：账本读不到/读坏时**必须返回 Err**，不能在「没有有效账本」的
/// 情况下继续做破坏性修改——那会让崩溃恢复完全失去依据。
fn persist_backup_path(backup: &Path, live_dir: &Path) -> Result<(), String> {
    let path = desktop_switch_ledger_path()?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // 非生产入口（单元测试直接调内部函数）：没有账本就不登记。
            // 生产入口 `switch_desktop_profile` 一定先写 `Prepared` 账本，
            // 真到这一步读不到账本属于异常，由下面的 Err 分支兜住。
            crate::log_info("Desktop 切换备份完成，但未找到账本（非生产入口），跳过登记");
            return Ok(());
        }
        Err(error) => {
            return Err(format!(
                "切换账本缺失或不可读（{error}），已中止切换以避免无依据的破坏性修改"
            ))
        }
    };
    let text = crate::jsonio::decode_text(&bytes);
    let mut ledger: DesktopSwitchLedger =
        serde_json::from_str(&text).map_err(|e| format!("已有切换账本损坏，拒绝覆盖：{e}"))?;
    if !crate::platform::imp::paths_equivalent(Path::new(&ledger.live_dir), live_dir) {
        return Err("已有切换账本的活目录与当前操作不一致，已拒绝覆盖".to_string());
    }
    ledger.backup_path = Some(backup.to_string_lossy().to_string());
    ledger.phase = DesktopSwitchPhase::BackupVerified;
    write_switch_ledger(&ledger).map_err(|e| format!("备份已创建但账本更新失败，已中止切换：{e}"))
}

/// 把账本推进到指定阶段（读-改-写，保留其余字段）。
///
/// **P0-02**：每次进入不可逆的文件修改前，先用它把「能支持恢复的状态」落盘。
fn advance_ledger_phase(phase: DesktopSwitchPhase, live_dir: &Path) -> Result<(), String> {
    let path = desktop_switch_ledger_path()?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        // 账本不存在：说明调用方不是从 `switch_desktop_profile` 进来的
        // （单元测试直接调内部函数，或旧版本遗留路径）。生产入口一定会
        // 先写 `Prepared` 账本，因此这里只记日志、不阻断。
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::log_info(&format!(
                "Desktop 切换阶段推进到 {phase:?} 时未找到账本（非生产入口），跳过落盘"
            ));
            return Ok(());
        }
        Err(error) => {
            return Err(format!(
                "切换账本不可读（{error}），拒绝在无账本的情况下修改文件"
            ))
        }
    };
    let text = crate::jsonio::decode_text(&bytes);
    let mut ledger: DesktopSwitchLedger =
        serde_json::from_str(&text).map_err(|e| format!("切换账本损坏，拒绝继续：{e}"))?;
    if !crate::platform::imp::paths_equivalent(Path::new(&ledger.live_dir), live_dir) {
        return Err("账本中的活目录与本次操作不一致，已拒绝继续".to_string());
    }
    ledger.phase = phase;
    write_switch_ledger(&ledger).map_err(|e| format!("写入切换阶段失败：{e}"))
}

/// 读取未完成的切换账本（不存在返回 `None`）。
///
/// **P0-F**：用于在取得执行权后拒绝「已有未完成事务时再开新事务」。
/// 账本损坏时返回 Err——不能当成「没有未完成事务」而放行。
fn read_pending_switch_ledger() -> Result<Option<DesktopSwitchLedger>, String> {
    let path = desktop_switch_ledger_path()?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("读取切换账本失败：{error}")),
    };
    let text = crate::jsonio::decode_text(&bytes);
    let ledger: DesktopSwitchLedger = serde_json::from_str(&text)
        .map_err(|e| format!("切换账本损坏，请先人工核对后再操作：{e}"))?;
    Ok(Some(ledger))
}

/// 推进/清除当前切换里的快照替换子事务。
fn advance_snapshot_swap(swap: SnapshotSwapState, live_dir: &Path) -> Result<(), String> {
    let path = desktop_switch_ledger_path()?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    let mut ledger: DesktopSwitchLedger = serde_json::from_str(&crate::jsonio::decode_text(&bytes))
        .map_err(|e| format!("切换账本损坏：{e}"))?;
    if !crate::platform::imp::paths_equivalent(Path::new(&ledger.live_dir), live_dir) {
        return Err("快照替换账本与本次切换的活目录不一致".to_string());
    }
    ledger.snapshot_swap = Some(swap);
    write_switch_ledger(&ledger)
}

fn clear_snapshot_swap(live_dir: &Path) -> Result<(), String> {
    let path = desktop_switch_ledger_path()?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    let mut ledger: DesktopSwitchLedger = serde_json::from_str(&crate::jsonio::decode_text(&bytes))
        .map_err(|e| format!("切换账本损坏：{e}"))?;
    if !crate::platform::imp::paths_equivalent(Path::new(&ledger.live_dir), live_dir) {
        return Err("快照替换账本与本次切换的活目录不一致".to_string());
    }
    ledger.snapshot_swap = None;
    write_switch_ledger(&ledger)
}

/// 删除事务账本。
///
/// **P0-02**：改为返回 `Result`。原实现吞掉删除失败，调用方以为「已清理」，
/// 实际下次启动仍会读到旧账本并再执行一次恢复动作。
fn clear_switch_ledger() -> Result<(), String> {
    let path = desktop_switch_ledger_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "删除切换账本失败（{}）：{error}；下次启动会再次尝试恢复",
            path.display()
        )),
    }
}

/// **P0-08**：启动时检查未完成的 Desktop 切换并恢复一致状态。
///
/// 返回需要展示给用户的说明（无残留时为空）。
pub fn heal_desktop_switch() -> Vec<String> {
    let Ok(path) = desktop_switch_ledger_path() else {
        return Vec::new();
    };
    // **P0-02**：只有「文件不存在」才等于「没有待恢复事务」。
    // 权限错误、磁盘读取错误都必须报出来——把它们当成「无事发生」
    // 会让一次真实中断被静默忽略。
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            return vec![format!(
                "Desktop 切换账本无法读取（{error}），已保留现场请人工核对"
            )];
        }
    };
    let text = crate::jsonio::decode_text(&bytes);
    let ledger: DesktopSwitchLedger = match serde_json::from_str(&text) {
        Ok(ledger) => ledger,
        Err(error) => {
            return vec![format!(
                "Desktop 切换账本损坏（{error}），已保留原文件请人工检查"
            )];
        }
    };

    let mut messages = Vec::new();
    let live = std::path::PathBuf::from(&ledger.live_dir);
    if let Some(swap) = &ledger.snapshot_swap {
        let snapshot = std::path::PathBuf::from(&swap.snapshot);
        let retired = std::path::PathBuf::from(&swap.retired);
        let staging = std::path::PathBuf::from(&swap.staging);
        if !snapshot.exists() && swap.retired_original && retired.is_dir() {
            match fsx::rename_with_retry(&retired, &snapshot) {
                Ok(()) => messages.push(format!(
                    "Desktop 回存在替换时中断，已将账号 {} 的原快照恢复到正式目录",
                    swap.snapshot_id
                )),
                Err(error) => {
                    messages.push(format!(
                        "Desktop 原快照仍在 {}，恢复正式目录失败：{error}；账本已保留",
                        retired.display()
                    ));
                    return messages;
                }
            }
        }
        if let Err(error) = fsx::retry_io(|| fs::remove_dir_all(&staging)) {
            messages.push(format!("Desktop 回存半成品清理失败：{error}；账本已保留"));
            return messages;
        }
    }

    // **P0-A**：阶段不足以判定「账号库是否已提交」。
    //
    // 崩溃可能正好落在 `with_store()` 保存成功之后、账本阶段更新为
    // `StoreCommitted` 之前——此时账本还写着 `FilesSwitching`，但账号库
    // 已经是 B。若只看阶段就回滚，会造成「活目录 A + 账号库 B」的不一致。
    //
    // 判定顺序：
    // 1. 先看账号库里的 `current_desktop_profile_id` 是否等于本次目标；
    // 2. 若是 → 视为已提交，保持活目录并清账本；
    // 3. 若账号库**读不出来** → 不猜，保留现场与账本；
    // 4. 只有确认「账号库不是本次目标」时，才按阶段回滚。
    let store_state = store::load_store();
    let committed_target: Option<bool> = match &store_state {
        Ok(data) => Some(
            data.last_desktop_transaction_id.as_deref() == Some(ledger.transaction_id.as_str())
                && data.current_desktop_profile_id.as_deref() == Some(ledger.to_id.as_str()),
        ),
        Err(_) => None,
    };
    if committed_target == Some(true) {
        messages.push(format!(
            "检测到 Desktop 切换已完成（→ {}），账号库已提交；活目录保持现状，仅清理账本",
            ledger.to_id
        ));
        if let Err(error) = clear_switch_ledger() {
            messages.push(error);
        }
        return messages;
    }
    if committed_target.is_none() && !matches!(ledger.phase, DesktopSwitchPhase::Prepared) {
        // 账号库读不出来：不能判断该回滚还是该保留。
        messages.push(format!(
            "检测到未完成的 Desktop 切换（→ {}），但账号库无法读取，             无法判断是否已提交。已保留活目录 {} 与账本，请人工核对",
            ledger.to_id, ledger.live_dir
        ));
        return messages;
    }

    // **P0-02**：穷尽匹配所有阶段。新增阶段若忘记处理，这里会编译失败
    // （而不是像原实现那样静默落到「未知阶段」分支）。
    match ledger.phase {
        // 已完成、或根本没动过文件：只需清理账本。
        DesktopSwitchPhase::Completed => {
            if let Err(error) = clear_switch_ledger() {
                messages.push(error);
            }
        }
        DesktopSwitchPhase::Prepared => {
            // 尚未备份、更未动活目录：原状态完好，清账本即可。
            if let Err(error) = clear_switch_ledger() {
                messages.push(error);
            }
        }
        // **关键修复**：备份已登记，文件替换可能已经开始。
        // 这是原实现漏掉的窗口——必须按回滚处理。
        DesktopSwitchPhase::BackupVerified
        | DesktopSwitchPhase::FilesSwitching
        | DesktopSwitchPhase::FilesSwitched => {
            messages.extend(rollback_desktop_switch(&ledger, &live));
        }
        // 账号库已提交：切换实际生效，**不能**回滚（那会让账号库与文件再度不一致）。
        DesktopSwitchPhase::StoreCommitted => {
            messages.push(format!(
                "检测到已生效但未清理的 Desktop 切换（→ {}），活目录保持现状，仅清理账本",
                ledger.to_id
            ));
            if let Err(error) = clear_switch_ledger() {
                messages.push(error);
            }
        }
        // 不认识的阶段（旧版本账本或损坏）：**绝不自动删除**活目录。
        DesktopSwitchPhase::Unknown => messages.push(format!(
            "检测到阶段不明的 Desktop 切换账本（目标 {}，活目录 {}）。             为避免误删唯一可用副本，已保留全部现场，请人工核对后再恢复",
            ledger.to_id, ledger.live_dir
        )),
    }
    messages
}

/// 按账本备份**回滚**活目录（`BackupVerified` / `FilesSwitching` / `FilesSwitched` 共用）。
///
/// 三条硬规则：
/// 1. 没有备份路径且原本存在活目录 → **绝不清理**，只报告（唯一副本可能在活目录里）；
/// 2. 备份存在但不可用 → 保留现场并报告具体路径；
/// 3. 只有回滚成功才删除账本；失败时账本必须留下，供下次启动重试。
fn rollback_desktop_switch(ledger: &DesktopSwitchLedger, live: &Path) -> Vec<String> {
    let mut messages = Vec::new();
    match &ledger.backup_path {
        Some(backup) => {
            let backup = std::path::PathBuf::from(backup);
            if !backup.is_dir() {
                messages.push(format!(
                    "Desktop 切换中断，备份缺失（{}），已保留活目录 {} 供人工核对",
                    backup.display(),
                    live.display()
                ));
                return messages;
            }
            let rollback = (|| -> Result<(), String> {
                if live.exists() || links::path_is_link(live) {
                    fsx::retry_io(|| fs::remove_dir_all(live))
                        .map_err(|e| format!("清理活目录失败：{e}"))?;
                }
                copy_dir_recursive(&backup, live)
                    .map(|_| ())
                    .map_err(|e| format!("还原活目录失败：{e}"))
            })();
            match rollback {
                Ok(()) => {
                    messages.push(format!(
                        "检测到中断的 Desktop 切换（→ {}），已回滚到切换前状态",
                        ledger.to_id
                    ));
                    if let Err(error) = clear_switch_ledger() {
                        messages.push(error);
                    }
                }
                Err(error) => messages.push(format!(
                    "Desktop 切换中断且回滚失败（{error}），备份保留在 {}",
                    backup.display()
                )),
            }
        }
        None if ledger.original_existed => {
            // **P0-01**：原本有数据但缺备份路径——绝不按「无活目录」清理。
            messages.push(format!(
                "检测到中断的 Desktop 切换（→ {}），但账本没有备份路径（原本存在活目录）。                 已保留全部现场，请人工核对 {} 的账号归属后再恢复",
                ledger.to_id, ledger.live_dir
            ));
        }
        None => {
            // 原本无活目录：目标内容都是本次新建的半成品，可以清理。
            if live.exists() {
                match fsx::retry_io(|| fs::remove_dir_all(live)) {
                    Ok(()) => {
                        messages.push(format!(
                            "检测到中断的 Desktop 切换（→ {}，原本无活目录），已清理",
                            ledger.to_id
                        ));
                        if let Err(error) = clear_switch_ledger() {
                            messages.push(error);
                        }
                    }
                    Err(error) => messages.push(format!(
                        "检测到中断的 Desktop 切换，但清理失败（{error}），账本已保留待重试"
                    )),
                }
            } else if let Err(error) = clear_switch_ledger() {
                messages.push(error);
            }
        }
    }
    messages
}

/// [`switch_desktop_profile`] 的可注入版本：`kill`/`running`/`copy` 均可替换，
/// 测试能在临时目录里完整走「备份 -> 清空 -> 载入 -> 回滚」全流程。
#[allow(clippy::too_many_arguments)]
fn switch_desktop_profile_in(
    id: &str,
    live_dir: &Path,
    accounts_dir: &Path,
    store: &mut Store,
    kill: &KillFn,
    running: &RunningFn,
    backup_root: &Path,
    copy: &CopyFn,
    transaction: &DesktopTransaction,
) -> Result<Vec<String>, String> {
    if id.trim().is_empty() {
        return Err("缺少目标账号 id".to_string());
    }
    let profile = store
        .desktop_profiles
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .ok_or_else(|| format!("未找到桌面账号快照: {id}"))?;
    // 同账号重选必须保留 capture 后产生的实时会话，不能再用旧快照覆盖。
    // 活目录缺失时仍走下方恢复流程；已有活目录时也不要求快照仍然存在。
    if store.current_desktop_profile_id.as_deref() == Some(id) && live_dir.is_dir() {
        return Ok(vec![format!(
            "当前已是桌面账号「{}」，已保留正在使用的数据",
            profile.name
        )]);
    }
    let snapshot = accounts_dir.join(&profile.id);
    if !snapshot.is_dir() {
        return Err(format!(
            "账号「{}」的快照目录缺失（{}），可能已被手动删除",
            profile.name,
            snapshot.display()
        ));
    }

    let mut warnings = Vec::new();

    // 1. 完全退出 Claude Desktop（含托盘），对齐上游 Stop-ClaudeApp。
    let killed = kill(&["Claude"])?;
    for desc in killed {
        warnings.push(format!("已结束进程：{desc}"));
    }
    wait_until_quite(running)?;

    // 跨身份保留：退出后、备份前，把 keep 列表里的相对路径收进暂存（默认关闭）。
    // 暂存失败（含上次还原残留）直接中止，不覆盖唯一副本。
    let keep_report = crate::keep::stage_keep(live_dir)?;
    if keep_report.count > 0 {
        warnings.push(format!("跨身份保留：已暂存 {} 项", keep_report.count));
    }
    warnings.extend(
        keep_report
            .warnings
            .into_iter()
            .map(|w| format!("跨身份保留：{w}")),
    );

    // 2. 把当前活目录回存到「当前账号」的快照（上游 Save-Account $cur 语义）。
    //
    // 没有这一步，切换即静默回退：A 账号在 capture 之后产生的登录态/会话变更
    // 只进一次性 staging 备份，从不写回 A 的快照；再切回 A 时活目录被清空并
    // 载入的是 capture 那一刻的旧快照。CLI 侧对应 refresh_current_profile_snapshot。
    //
    // 只回存与当前账号 id 匹配的快照；id 为 None（从未切换过）或快照目录缺失时
    // 跳过——首次切换前没有"当前账号"，此时活目录内容由 staging 备份兜底。
    if let Some(current_id) = store.current_desktop_profile_id.clone() {
        if current_id != profile.id {
            if let Some(current) = store
                .desktop_profiles
                .iter()
                .find(|p| p.id == current_id)
                .cloned()
            {
                let current_snapshot = accounts_dir.join(&current.id);
                if current_snapshot.is_dir() {
                    // 安全替换：先拷到 `.new`，成功后再让旧目录让位。
                    //
                    // 早期实现是「先 remove_dir_all 旧快照，再 copy」——拷贝中途
                    // 失败（文件被占用、磁盘满）时旧快照已没了、新快照只是半成品，
                    // 快照得重新捕获。改成两段式替换后，任何一步失败旧快照都完好，
                    // 最坏情况只是残留一个 `.new` 半成品（下次会被覆盖）。
                    let staging = accounts_dir.join(format!("{}.new", current.id));
                    let retired = accounts_dir.join(format!("{}.old", current.id));
                    let _ = fsx::retry_io(|| fs::remove_dir_all(&staging));
                    let _ = fsx::retry_io(|| fs::remove_dir_all(&retired));
                    copy(live_dir, &staging)?;
                    if let Err(error) = advance_snapshot_swap(
                        SnapshotSwapState {
                            snapshot_id: current.id.clone(),
                            snapshot: current_snapshot.to_string_lossy().to_string(),
                            staging: staging.to_string_lossy().to_string(),
                            retired: retired.to_string_lossy().to_string(),
                            retired_original: true,
                        },
                        live_dir,
                    ) {
                        return Err(format!("回存快照前无法登记恢复依据：{error}"));
                    }
                    fsx::retry_io(|| fs::rename(&current_snapshot, &retired)).map_err(|e| {
                        format!(
                            "回存账号「{}」时替换旧快照失败（{}）：{}",
                            current.name,
                            current_snapshot.display(),
                            fsx::humanize_io_error(&e)
                        )
                    })?;
                    if let Err(e) = fsx::retry_io(|| fs::rename(&staging, &current_snapshot)) {
                        // 正式名没换上：把旧快照请回来，现场回到替换前。
                        // 恢复也可能失败（.old 被占用等）——此时必须如实告知旧快照
                        // 现在落在 `.old` 目录，不能让用户以为已经恢复好了。
                        match fsx::retry_io(|| fs::rename(&retired, &current_snapshot)) {
                            Ok(()) => {
                                return Err(format!(
                                    "回存账号「{}」快照失败（{}）：{}（已恢复原快照）",
                                    current.name,
                                    current_snapshot.display(),
                                    fsx::humanize_io_error(&e)
                                ));
                            }
                            Err(restore_err) => {
                                return Err(format!(
                                    "回存账号「{}」快照失败（{}）：{}；且恢复原快照也失败：{}。\
                                     原快照目前仍在 {}，请手动处理（不要直接删除）。",
                                    current.name,
                                    current_snapshot.display(),
                                    fsx::humanize_io_error(&e),
                                    fsx::humanize_io_error(&restore_err),
                                    retired.display()
                                ));
                            }
                        }
                    }
                    if let Err(error) = clear_snapshot_swap(live_dir) {
                        return Err(format!(
                            "回存已完成但清除替换账本失败（保留旧快照供恢复）：{error}"
                        ));
                    }
                    fsx::retry_io(|| fs::remove_dir_all(&retired))
                        .map_err(|e| format!("回存已完成，但删除旧快照失败（保留现场）：{e}"))?;
                    // size_bytes 只算一次：快照有几个 GB 时，重复走完整目录遍历
                    // 会让每次切换都白等一遍。
                    let saved_size = dir_size(&current_snapshot);
                    if let Some(p) = store
                        .desktop_profiles
                        .iter_mut()
                        .find(|p| p.id == current.id)
                    {
                        p.updated_at = Utc::now();
                        p.size_bytes = saved_size;
                    }
                    warnings.push(format!(
                        "已回存当前账号「{}」的使用变更（{} 字节）",
                        current.name, saved_size
                    ));
                } else {
                    warnings.push(format!(
                        "账号「{}」的快照目录缺失，跳过回存（活目录变更仍在下方备份中）",
                        current.name
                    ));
                }
            }
        }
    }

    // 3. 备份当前活目录到 staging（随后清空/回滚都靠它兜底）。
    transaction.original_existed.set(live_dir.is_dir());
    // target_id 用于诊断日志（事务归属）。
    let _ = &transaction.target_id;
    let backup_path = if live_dir.is_dir() {
        fs::create_dir_all(backup_root)
            .map_err(|e| format!("创建备份目录失败 {}: {e}", backup_root.display()))?;
        let path = backup_root.join(format!(
            "{}-{}",
            Utc::now().format("%Y%m%d%H%M%S"),
            Uuid::new_v4().simple()
        ));
        let outcome = copy(live_dir, &path)?;
        // **P0-NEW-03**：把本次备份的精确路径交给事务上下文。
        *transaction.backup_path.borrow_mut() = Some(path.clone());
        // **P0-01**：备份一落地就写入账本——删除活目录之前，账本里必须已经
        // 存在精确的备份路径，否则崩溃时恢复器不知道去哪里恢复。
        // 写失败则中止（活目录尚未改动，原账号仍完整）。
        persist_backup_path(&path, live_dir)?;
        // **P0-A**：备份已登记，账本此刻已是 BackupVerified。
        transaction.phase.set(DesktopSwitchPhase::BackupVerified);
        warnings.push(format!(
            "切换前已备份当前 Claude Desktop 数据到 {}（{} 字节，跳过链接 {} 个）",
            path.display(),
            outcome.bytes,
            outcome.skipped_links
        ));
        Some(path)
    } else {
        None
    };

    // 3. 清空活目录（普通目录或悬空链接都要清掉）。
    //    **P0-02**：进入不可逆修改前，账本必须已经推进到 `FilesSwitching`。
    if let Err(error) = advance_ledger_phase(DesktopSwitchPhase::FilesSwitching, live_dir) {
        return Err(format!(
            "无法把切换账本推进到「文件替换中」（{error}），已中止切换：活目录未被修改"
        ));
    }
    // **P0-A**：记录真实推进到的阶段，供外层失败判定使用。
    transaction.phase.set(DesktopSwitchPhase::FilesSwitching);
    if live_dir.exists() || links::path_is_link(live_dir) {
        fsx::retry_io(|| fs::remove_dir_all(live_dir)).map_err(|e| {
            format!(
                "清空当前 Claude Desktop 数据目录失败（{}）：{}。旧数据已备份至 {}，可手动恢复",
                live_dir.display(),
                fsx::humanize_io_error(&e),
                backup_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            )
        })?;
    }
    if let Some(parent) = live_dir.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建配置父目录失败: {e}"))?;
    }

    // 4. 快照覆盖回活目录；失败则用 staging 备份回滚，不留半截状态。
    match copy(&snapshot, live_dir) {
        Ok(outcome) => {
            warnings.push(format!(
                "已载入账号「{}」快照（{} 字节，跳过链接 {} 个）",
                profile.name, outcome.bytes, outcome.skipped_links
            ));
        }
        Err(e) => {
            let mut message = e;
            if let Some(backup) = &backup_path {
                let _ = fsx::retry_io(|| fs::remove_dir_all(live_dir));
                match copy(backup, live_dir) {
                    Ok(..) => message.push_str("；已自动回滚到切换前状态"),
                    Err(..) => {
                        message.push_str("；自动回滚失败，请用备份手动恢复");
                    }
                }
            }
            return Err(message);
        }
    }

    // 跨身份保留：把暂存文件合并回载入后的活目录。
    //
    // P0-14：合并失败是**必要步骤失败**，必须中止切换——否则活目录内容与
    // 账号库记录（current_desktop_profile_id）会不一致，下次切换会把错误
    // 数据进一步写回。此时活目录已替换为目标账号，但账号 ID 尚未更新，
    // 保持「文件已换、记录仍是旧账号」比「记录谎称已换」更可诊断。
    match crate::keep::merge_keep(live_dir) {
        Ok(report) => {
            if report.count > 0 {
                warnings.push(format!("跨身份保留：已合并 {} 项到新账号", report.count));
            }
            warnings.extend(
                report
                    .warnings
                    .into_iter()
                    .map(|w| format!("跨身份保留：{w}")),
            );
        }
        Err(e) => {
            // P0-L：合并失败必须**真正回滚活目录**，不能留下「活目录是 B、
            // 账号记录是 A」的不一致状态——下次切换会把 B 的内容归档进 A。
            let mut message = format!("跨身份保留合并失败，正在回滚：{e}");
            match &backup_path {
                Some(backup) => {
                    // 先删掉已载入的目标账号内容，再还原切换前的备份。
                    let cleaned = fsx::retry_io(|| fs::remove_dir_all(live_dir)).is_ok();
                    if !cleaned {
                        message.push_str("；清理目标账号内容失败");
                    }
                    match copy(backup, live_dir) {
                        Ok(..) => {
                            message.push_str("；已回滚到切换前状态（账号记录未改动）");
                        }
                        Err(rollback_error) => {
                            message.push_str(&format!(
                                "；自动回滚失败（{rollback_error}），请用备份手动恢复：{}",
                                backup.display()
                            ));
                        }
                    }
                }
                None => {
                    // 首次切换（原本没有活目录）：清空载入内容即可，
                    // 账号记录同样保持未改动。
                    let _ = fsx::retry_io(|| fs::remove_dir_all(live_dir));
                    message.push_str("；首次切换无原数据，已清理目标账号内容（账号记录未改动）");
                }
            }
            return Err(message);
        }
    }

    // 5. 更新切换时间戳，并按载入后的实际内容刷新体积缓存。
    if let Some(p) = store.desktop_profiles.iter_mut().find(|p| p.id == id) {
        p.last_switched_at = Some(Utc::now());
        p.updated_at = Utc::now();
        p.size_bytes = dir_size(live_dir);
    }
    // 记录「现在活目录里装的是谁」：下次切换时才知道该把活目录回存给谁。
    store.current_desktop_profile_id = Some(profile.id.clone());
    Ok(warnings)
}

// ───────────────────────── 删除 / 重命名 ─────────────────────────

/// 删除 Desktop 账号登记；`also_files` 为 true 时连快照目录一起删除。
/// 登记不存在视为幂等成功。
/// **P0-D**：Desktop 删除的持久化账本。
///
/// 原实现「改名 → 存库 → 删目录」没有账本：崩在「改名之后、存库之前」时，
/// 登记还在、正式目录却已不存在，数据只躺在待删目录里且无人知晓。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DesktopDeleteJournal {
    transaction_id: String,
    snapshot_id: String,
    original: String,
    pending: String,
    /// 正式目录已改名。
    files_moved: bool,
    /// 账号库已提交（登记已删除）。
    store_committed: bool,
    started_at: i64,
}

fn desktop_delete_journal_path() -> Result<std::path::PathBuf, String> {
    Ok(crate::paths::app_data_dir()?.join("desktop-delete.json"))
}

fn write_delete_journal(journal: &DesktopDeleteJournal) -> Result<(), String> {
    let path = desktop_delete_journal_path()?;
    crate::fsx::write_atomically(
        &path,
        &serde_json::to_string_pretty(journal).map_err(|e| format!("序列化删除账本失败：{e}"))?,
    )
    .map_err(|e| format!("写入删除账本失败：{e}"))
}

fn clear_delete_journal() -> Result<(), String> {
    let path = desktop_delete_journal_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("删除删除账本失败：{error}")),
    }
}

/// **P0-D**：启动时恢复中断的快照删除。
///
/// 判据是「账号库登记 + 文件实际状态」：
/// - 登记还在、正式目录不存在、待删目录存在 → 把目录改回正式名（恢复数据）；
/// - 登记已删 → 继续删除待删目录，完成后清账本；
/// - 情况不明 → 保留账本与所有文件，报告唯一副本位置。
pub fn heal_desktop_delete() -> Vec<String> {
    let path = match desktop_delete_journal_path() {
        Ok(path) => path,
        Err(_) => return Vec::new(),
    };
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            return vec![format!("Desktop 删除账本无法读取（{error}），已保留现场")];
        }
    };
    let journal: DesktopDeleteJournal =
        match serde_json::from_str(&crate::jsonio::decode_text(&bytes)) {
            Ok(journal) => journal,
            Err(error) => {
                return vec![format!(
                    "Desktop 删除账本损坏（{error}），已保留现场请人工核对"
                )];
            }
        };
    let original = std::path::PathBuf::from(&journal.original);
    let pending = std::path::PathBuf::from(&journal.pending);
    let registered = store::load_store()
        .map(|data| {
            data.desktop_profiles
                .iter()
                .any(|p| p.id == journal.snapshot_id)
        })
        .unwrap_or(true);
    let mut messages = Vec::new();

    if registered && !original.exists() && pending.is_dir() {
        match fsx::rename_with_retry(&pending, &original) {
            Ok(()) => {
                if let Err(error) = clear_delete_journal() {
                    messages.push(error);
                }
                messages.push(format!(
                    "检测到中断的快照删除（{}），已把待删目录恢复为正式快照",
                    journal.snapshot_id
                ));
            }
            Err(error) => messages.push(format!(
                "快照 {} 的目录仍保留在 {}，恢复正式名失败：{error}；账本已保留",
                journal.snapshot_id,
                pending.display()
            )),
        }
        return messages;
    }
    if !registered && pending.is_dir() {
        match fsx::retry_io(|| std::fs::remove_dir_all(&pending)) {
            Ok(()) => {
                if let Err(error) = clear_delete_journal() {
                    messages.push(error);
                }
                messages.push(format!(
                    "检测到中断的快照删除（{}），登记已删除，已清理待删目录",
                    journal.snapshot_id
                ));
            }
            Err(error) => messages.push(format!(
                "登记已删除，但待删目录 {} 清理失败：{error}",
                pending.display()
            )),
        }
        return messages;
    }
    // 其余情况：不清账本，报告现场。
    messages.push(format!(
        "Desktop 删除事务（{}）状态不明（files_moved={}，store_committed={}），         已保留账本与全部目录，请人工核对",
        journal.transaction_id, journal.files_moved, journal.store_committed
    ));
    messages
}

pub fn delete_desktop_profile(id: &str, also_files: bool) -> Result<(), String> {
    // **P0-04**：整个删除过程持有与导入/切换相同的执行权。
    //
    // 原实现「先在 with_store 里删登记 → 释放锁 → 再 remove_dir_all」：
    // 两步之间若另一个导入事务重建了同 ID 的快照，删除动作会把**新导入的
    // 数据**一起删掉。这个窗口不需要两个实例，同进程两个命令并发就够。
    store::with_store_transaction(|tx| {
        // 未收尾的迁移/切换事务存在时，不做删除（避免删掉正在被恢复的数据）。
        crate::export::ensure_no_pending_migration()?;
        if let Some(pending) = read_pending_switch_ledger()? {
            return Err(format!(
                "存在未完成的 Desktop 切换（{}），请先重启应用完成恢复再删除",
                pending.transaction_id
            ));
        }
        let mut data = tx.load()?;
        let Some(pos) = data.desktop_profiles.iter().position(|p| p.id == id) else {
            return Ok(()); // 幂等：登记不存在，直接成功
        };
        let profile = data.desktop_profiles.remove(pos);
        if data.current_desktop_profile_id.as_deref() == Some(id) {
            data.current_desktop_profile_id = None;
        }
        if !also_files {
            tx.save(&data)?;
            return Ok(());
        }
        // 先把物理目录改名成唯一的「待删除」名：改名是原子的，且此后即使
        // 有并发导入重建了同 ID 目录，也不会被本次删除波及。
        let snapshot = desktop_snapshot_dir(&profile.id)?;
        let pending = snapshot.with_file_name(format!(
            ".{}.delete-pending-{}",
            profile.id,
            uuid::Uuid::new_v4().simple()
        ));
        let mut journal = DesktopDeleteJournal {
            transaction_id: uuid::Uuid::new_v4().simple().to_string(),
            snapshot_id: profile.id.clone(),
            original: snapshot.to_string_lossy().to_string(),
            pending: pending.to_string_lossy().to_string(),
            files_moved: false,
            store_committed: false,
            started_at: chrono::Utc::now().timestamp(),
        };
        // **P0-D**：先落账本，再动文件。
        write_delete_journal(&journal)?;
        let renamed = if snapshot.exists() {
            fsx::rename_with_retry(&snapshot, &pending).map_err(|e| {
                let _ = clear_delete_journal();
                format!(
                    "移走快照目录失败 {}: {}（账号未删除）",
                    snapshot.display(),
                    fsx::humanize_io_error(&e)
                )
            })?;
            true
        } else {
            false
        };
        journal.files_moved = renamed;
        write_delete_journal(&journal)?;
        // 登记保存失败 → 把目录改回原名，保证「登记与文件」一致。
        if let Err(error) = tx.save(&data) {
            // **QW-03**：回滚改名失败时必须把**两个**错误都报出来，
            // 不能声称「已恢复快照目录」。
            if renamed {
                return Err(match fsx::rename_with_retry(&pending, &snapshot) {
                    Ok(()) => {
                        let _ = clear_delete_journal();
                        format!("保存账号库失败，已恢复快照目录：{error}")
                    }
                    Err(restore_error) => format!(
                        "保存账号库失败（{error}）；且恢复快照目录失败（{restore_error}）。                         该账号的唯一副本仍在 {}，请勿删除，账本已保留",
                        pending.display()
                    ),
                });
            }
            let _ = clear_delete_journal();
            return Err(format!("保存账号库失败：{error}"));
        }
        journal.store_committed = true;
        write_delete_journal(&journal)?;
        if renamed {
            if let Err(error) = fsx::retry_io(|| std::fs::remove_dir_all(&pending)) {
                // 登记已删、目录已移走：残留不影响正确性，但要如实说明位置。
                // 账本保留，下次启动会继续清理。
                return Err(format!(
                    "账号已删除，但清理快照目录失败（{error}）；残留目录：{}",
                    pending.display()
                ));
            }
        }
        clear_delete_journal()?;
        Ok(())
    })
}
/// 重命名 Desktop 账号（不动物理快照）。
pub fn rename_desktop_profile(id: &str, name: &str) -> Result<DesktopProfile, String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("账号名称不能为空".to_string());
    }
    // H-2：读—改—写走 with_store。
    store::with_store(|store| {
        let profile = store
            .desktop_profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| format!("未找到桌面账号快照: {id}"))?;
        profile.name = name;
        profile.updated_at = Utc::now();
        Ok(profile.clone())
    })
}

// ───────────────────────── 单测 ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn client_locale_falls_back_to_msix_when_legacy_only_has_mcp_config() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("Claude");
        fs::create_dir_all(&legacy).unwrap();
        fs::write(
            legacy.join("claude_desktop_config.json"),
            b"{\"mcpServers\":{}}",
        )
        .unwrap();
        let msix = dir.path().join("Claude-Data");
        let family = "Claude_family";
        fs::create_dir_all(msix.join(family)).unwrap();
        fs::write(
            msix.join(family).join("config.json"),
            b"{\"locale\":\"ja-JP\"}",
        )
        .unwrap();
        assert_eq!(
            client_locale_from_dirs(&legacy, &msix, &[family.into()]).unwrap(),
            "ja-JP"
        );
    }

    // ── MSIX 数据目录发现（上游 Find-ClaudeDataPath 行为基准）──

    fn locale_config(directory: &Path, bytes: &[u8]) -> PathBuf {
        fs::create_dir_all(directory).unwrap();
        let path = directory.join("config.json");
        fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn client_locale_prefers_existing_legacy_config_without_modifying_it() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("Claude");
        let msix = dir.path().join("Claude-Data");
        locale_config(&msix.join("claude_family"), br#"{"locale":"ja-JP"}"#);
        for locale in ["en", "EN-us", "eng-US", "es-419", "zh-Hant-TW"] {
            let original = format!(r#"{{"locale":"{locale}","other":"preserve"}}"#);
            let path = locale_config(&legacy, original.as_bytes());
            assert_eq!(
                client_locale_from_dirs(&legacy, &msix, &[]).unwrap(),
                locale
            );
            assert_eq!(fs::read(path).unwrap(), original.as_bytes());
        }
    }

    #[test]
    fn client_locale_uses_unique_msix_directory_without_package_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let msix = dir.path().join("Claude-Data");
        locale_config(&msix.join("claude_unique"), br#"{"locale":"de-DE"}"#);
        assert_eq!(
            client_locale_from_dirs(&dir.path().join("Claude"), &msix, &[]).unwrap(),
            "de-DE"
        );
    }

    #[test]
    fn client_locale_selects_registered_package_among_multiple_directories() {
        let dir = tempfile::tempdir().unwrap();
        let msix = dir.path().join("Claude-Data");
        locale_config(&msix.join("claude_old"), br#"{"locale":"en-US"}"#);
        locale_config(&msix.join("claude_current"), br#"{"locale":"fr-FR"}"#);
        assert_eq!(
            client_locale_from_dirs(
                &dir.path().join("Claude"),
                &msix,
                &["claude_current".into()]
            )
            .unwrap(),
            "fr-FR"
        );
    }

    #[test]
    fn client_locale_accepts_case_aliases_of_one_registered_package() {
        let dir = tempfile::tempdir().unwrap();
        let msix = dir.path().join("Claude-Data");
        locale_config(&msix.join("claude_current"), br#"{"locale":"fr-FR"}"#);
        assert_eq!(
            client_locale_from_dirs(
                &dir.path().join("Claude"),
                &msix,
                &["claude_current".into(), "CLAUDE_CURRENT".into()],
            )
            .unwrap(),
            "fr-FR"
        );
    }

    #[test]
    fn client_locale_rejects_multiple_registered_packages_in_either_order() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("Claude");
        let msix = dir.path().join("Claude-Data");
        locale_config(&msix.join("claude_a"), br#"{"locale":"en-US"}"#);
        locale_config(&msix.join("claude_b"), br#"{"locale":"ja-JP"}"#);
        for families in [["claude_a", "claude_b"], ["claude_b", "claude_a"]] {
            let families: Vec<String> = families.into_iter().map(str::to_string).collect();
            assert!(client_locale_from_dirs(&legacy, &msix, &families).is_err());
        }
    }

    #[test]
    fn client_locale_does_not_guess_when_configs_are_missing_or_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("Claude");
        let msix = dir.path().join("Claude-Data");
        assert!(client_locale_from_dirs(&legacy, &msix, &[]).is_err());
        fs::create_dir_all(msix.join("claude_a")).unwrap();
        assert!(client_locale_from_dirs(&legacy, &msix, &[]).is_err());
        locale_config(&msix.join("claude_a"), br#"{"locale":"en-US"}"#);
        locale_config(&msix.join("claude_b"), br#"{"locale":"fr-FR"}"#);
        assert!(client_locale_from_dirs(&legacy, &msix, &[]).is_err());
    }

    #[test]
    fn client_locale_does_not_mask_invalid_legacy_config_with_msix_settings() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("Claude");
        let msix = dir.path().join("Claude-Data");
        locale_config(&msix.join("claude_family"), br#"{"locale":"en-US"}"#);
        for raw in [
            "{truncated",
            "{}",
            r#"{"locale":null}"#,
            r#"{"locale":123}"#,
            r#"{"locale":""}"#,
            r#"{"locale":"en_US"}"#,
            r#"{"locale":" en-US"}"#,
            r#"{"locale":"en-US\n"}"#,
            r#"{"locale":"en-u"}"#,
            r#"{"locale":"en-123456789"}"#,
            r#"{"locale":"中文"}"#,
        ] {
            let path = locale_config(&legacy, raw.as_bytes());
            assert!(
                client_locale_from_dirs(&legacy, &msix, &[]).is_err(),
                "accepted {raw}"
            );
            assert_eq!(fs::read(path).unwrap(), raw.as_bytes());
        }
    }

    #[test]
    fn client_locale_reads_windows_bom_encodings() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("Claude");
        let msix = dir.path().join("Claude-Data");
        let raw = r#"{"locale":"zh-Hans-CN"}"#;
        let mut utf8 = vec![0xef, 0xbb, 0xbf];
        utf8.extend(raw.as_bytes());
        let mut utf16 = vec![0xff, 0xfe];
        utf16.extend(raw.encode_utf16().flat_map(u16::to_le_bytes));
        for bytes in [utf8, utf16] {
            let path = locale_config(&legacy, &bytes);
            assert_eq!(
                client_locale_from_dirs(&legacy, &msix, &[]).unwrap(),
                "zh-Hans-CN"
            );
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn live_dir_prefers_legacy_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("Claude");
        std::fs::create_dir_all(&legacy).unwrap();
        let msix_root = dir.path().join("Claude-Data");
        std::fs::create_dir_all(msix_root.join("Claude_family1")).unwrap();
        // 传统目录存在时优先，即使 MSIX 目录也在。
        assert_eq!(
            resolve_desktop_live_dir(&legacy, &msix_root, &["Claude_family1".to_string()]),
            legacy
        );
    }

    #[test]
    fn live_dir_uses_msix_package_family() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("Claude");
        let msix_root = dir.path().join("Claude-Data");
        let family = "Claude_1.2.3_x64__abc";
        std::fs::create_dir_all(msix_root.join(family)).unwrap();
        assert_eq!(
            resolve_desktop_live_dir(&legacy, &msix_root, &[family.to_string()]),
            msix_root.join(family)
        );
    }

    #[test]
    fn live_dir_falls_back_to_single_claude_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("Claude");
        let msix_root = dir.path().join("Claude-Data");
        let only = msix_root.join("claude_1.2.3_x64__zzz");
        std::fs::create_dir_all(&only).unwrap();
        // AppX 查询失败（空列表）但只有一个 claude_* 目录时也能定位。
        assert_eq!(resolve_desktop_live_dir(&legacy, &msix_root, &[]), only);
    }

    #[test]
    fn live_dir_ambiguous_msix_dirs_fall_back_to_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("Claude");
        let msix_root = dir.path().join("Claude-Data");
        std::fs::create_dir_all(msix_root.join("claude_a")).unwrap();
        std::fs::create_dir_all(msix_root.join("claude_b")).unwrap();
        // 多个候选且没有 AppX 命中：回落 legacy，让调用方报「未安装」。
        assert_eq!(resolve_desktop_live_dir(&legacy, &msix_root, &[]), legacy);
    }

    #[test]
    fn live_dir_nothing_found_falls_back_to_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("Claude");
        let msix_root = dir.path().join("Claude-Data");
        std::fs::create_dir_all(&msix_root).unwrap();
        assert_eq!(resolve_desktop_live_dir(&legacy, &msix_root, &[]), legacy);
    }

    /// 造一个带嵌套目录 / 空目录 / 文件的假活目录。
    fn sample_live(root: &Path) -> PathBuf {
        let live = root.join("Claude");
        fs::create_dir_all(live.join("nested/empty-dir")).unwrap();
        fs::write(live.join("config.json"), b"{\"hello\":\"world\"}").unwrap();
        fs::write(live.join("nested/a.txt"), b"aaaa").unwrap();
        fs::write(live.join("nested/b.bin"), vec![0u8; 1024]).unwrap();
        live
    }

    #[test]
    fn copy_dir_recursive_roundtrips_tree_and_size() {
        let dir = tempfile::tempdir().unwrap();
        let live = sample_live(dir.path());
        let snapshot = dir.path().join("snap");

        let outcome = copy_dir_recursive(&live, &snapshot).unwrap();

        // 文件内容逐字一致、空目录被重建、体积统计与拷贝字节吻合。
        assert_eq!(
            fs::read_to_string(snapshot.join("config.json")).unwrap(),
            "{\"hello\":\"world\"}"
        );
        assert_eq!(fs::read(snapshot.join("nested/a.txt")).unwrap(), b"aaaa");
        assert!(snapshot.join("nested/empty-dir").is_dir());
        assert_eq!(outcome.bytes, dir_size(&snapshot));
        assert_eq!(outcome.bytes, 17 + 4 + 1024);
        assert_eq!(outcome.skipped_links, 0);
    }

    #[test]
    fn dir_size_matches_actual_file_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let live = sample_live(dir.path());
        assert_eq!(dir_size(&live), 17 + 4 + 1024);
        // 不存在路径计 0，不 panic。
        assert_eq!(dir_size(&dir.path().join("nope")), 0);
    }

    /// 悬空 junction（目标已被删）必须被跳过而不是让整个复制失败。
    #[test]
    fn copy_dir_skips_dangling_junction() {
        let dir = tempfile::tempdir().unwrap();
        let live = sample_live(dir.path());

        let linked_target = dir.path().join("linked-target");
        fs::create_dir_all(&linked_target).unwrap();
        fs::write(linked_target.join("big.dat"), vec![0u8; 5000]).unwrap();
        imp::create_junction(&linked_target, &live.join("linked")).unwrap();
        // 目标消失 -> live 下的 junction 变悬空。
        fs::remove_dir_all(&linked_target).unwrap();

        let snapshot = dir.path().join("snap");
        let outcome = copy_dir_recursive(&live, &snapshot).unwrap();

        assert_eq!(outcome.skipped_links, 1, "悬空 junction 应被跳过且计数为 1");
        assert!(!snapshot.join("linked").exists());
        assert_eq!(outcome.bytes, 17 + 4 + 1024, "链接指向的数据绝不能被拷进来");
    }

    #[test]
    fn capture_into_pushes_profile_and_copies_files() {
        let dir = tempfile::tempdir().unwrap();
        let live = sample_live(dir.path());
        let snapshot = dir.path().join("desktop-accounts").join("abc123");
        let mut store = Store::default();

        let profile = capture_desktop_profile_into(
            "  测试账号  ",
            Some("备注".to_string()),
            &live,
            &snapshot,
            &mut store,
            &|| Ok(false),
        )
        .unwrap();

        assert_eq!(store.desktop_profiles.len(), 1);
        assert_eq!(profile.name, "测试账号", "名称应去空白");
        assert_eq!(profile.id, "abc123");
        assert_eq!(profile.snapshot_rel, "desktop-accounts/abc123");
        assert_eq!(profile.size_bytes, dir_size(&snapshot));
        assert!(profile.last_switched_at.is_none());
        assert!(snapshot.join("config.json").exists());
    }

    #[test]
    fn capture_into_rejects_running_empty_name_and_missing_live() {
        let dir = tempfile::tempdir().unwrap();
        let live = sample_live(dir.path());
        let snapshot = dir.path().join("snap");
        let mut store = Store::default();

        // 仍在运行 -> 拒绝。
        let err =
            capture_desktop_profile_into("号", None, &live, &snapshot, &mut store, &|| Ok(true))
                .unwrap_err();
        assert!(err.contains("完全退出"), "{err}");
        assert!(store.desktop_profiles.is_empty(), "拒绝时不得写入登记");

        // 空名 -> 拒绝。
        let err =
            capture_desktop_profile_into("   ", None, &live, &snapshot, &mut store, &|| Ok(false))
                .unwrap_err();
        assert!(err.contains("不能为空"), "{err}");

        // 活目录不存在 -> 拒绝。
        let err = capture_desktop_profile_into(
            "号",
            None,
            &dir.path().join("missing"),
            &snapshot,
            &mut store,
            &|| Ok(false),
        )
        .unwrap_err();
        assert!(err.contains("未找到"), "{err}");
    }

    #[test]
    fn switch_in_loads_snapshot_backup_old_live_and_updates_timestamp() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let accounts = dir.path().join("desktop-accounts");
        let snapshot = accounts.join("b-id");
        fs::create_dir_all(&snapshot).unwrap();
        fs::write(snapshot.join("who.txt"), b"B-account").unwrap();

        let mut store = Store::default();
        let now = Utc::now();
        store.desktop_profiles.push(DesktopProfile {
            id: "b-id".into(),
            name: "B".into(),
            notes: None,
            created_at: now,
            updated_at: now,
            last_switched_at: None,
            snapshot_rel: "desktop-accounts/b-id".into(),
            size_bytes: 0,
            meta: None,
        });

        // 当前活目录 = 账号 A 的数据。
        let live = dir.path().join("APPDATA").join("Claude");
        fs::create_dir_all(live.join("cache")).unwrap();
        fs::write(live.join("who.txt"), b"A-account").unwrap();
        fs::write(live.join("cache/old.tmp"), b"old").unwrap();

        let backup_root = dir.path().join("backups");
        let tx = DesktopTransaction::default();
        let warnings = switch_desktop_profile_in(
            "b-id",
            &live,
            &accounts,
            &mut store,
            &|_names| Ok(Vec::new()),
            &|| Ok(false),
            &backup_root,
            &copy_dir_recursive,
            &tx,
        )
        .unwrap();

        // 活目录被换成 B。
        assert_eq!(
            fs::read_to_string(live.join("who.txt")).unwrap(),
            "B-account"
        );
        assert!(!live.join("cache/old.tmp").exists(), "A 的缓存不应残留");
        // A 被完整备份到 staging。
        let backups: Vec<_> = fs::read_dir(&backup_root)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(
            fs::read_to_string(backups[0].path().join("who.txt")).unwrap(),
            "A-account"
        );
        assert_eq!(
            fs::read(backups[0].path().join("cache/old.tmp")).unwrap(),
            b"old"
        );
        // store 时间戳更新、警告文案到位。
        let p = &store.desktop_profiles[0];
        assert!(p.last_switched_at.is_some());
        assert!(warnings.iter().any(|w| w.contains("已载入")));
        assert!(warnings.iter().any(|w| w.contains("备份")));
    }

    #[test]
    fn switch_in_saves_current_live_changes_into_current_account_snapshot() {
        // 上游 Save-Account $cur 语义：切换前必须把活目录回存给「当前账号」，
        // 否则每次切换都把活账号静默回退到上次 capture 的状态。
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let accounts = dir.path().join("desktop-accounts");
        let snap_a = accounts.join("a-id");
        let snap_b = accounts.join("b-id");
        fs::create_dir_all(&snap_a).unwrap();
        fs::create_dir_all(&snap_b).unwrap();
        // A 的快照是 capture 那一刻的旧内容。
        fs::write(snap_a.join("who.txt"), b"A-at-capture").unwrap();
        fs::write(snap_b.join("who.txt"), b"B-account").unwrap();

        let mut store = Store::default();
        let now = Utc::now();
        for (id, name) in [("a-id", "A"), ("b-id", "B")] {
            store.desktop_profiles.push(DesktopProfile {
                id: id.into(),
                name: name.into(),
                notes: None,
                created_at: now,
                updated_at: now,
                last_switched_at: None,
                snapshot_rel: format!("desktop-accounts/{id}"),
                size_bytes: 0,
                meta: None,
            });
        }
        // 当前活目录装的是 A，且 A 在使用期间产生了新变更。
        store.current_desktop_profile_id = Some("a-id".into());
        let live = dir.path().join("APPDATA").join("Claude");
        fs::create_dir_all(live.join("cache")).unwrap();
        fs::write(live.join("who.txt"), b"A-after-use").unwrap();
        fs::write(live.join("cache/new.tmp"), b"new").unwrap();

        let tx = DesktopTransaction::default();
        switch_desktop_profile_in(
            "b-id",
            &live,
            &accounts,
            &mut store,
            &|_names| Ok(Vec::new()),
            &|| Ok(false),
            &dir.path().join("backups"),
            &copy_dir_recursive,
            &tx,
        )
        .unwrap();

        // A 的快照必须拿到使用后的内容，而不是停留在 capture 那一刻。
        assert_eq!(
            fs::read_to_string(snap_a.join("who.txt")).unwrap(),
            "A-after-use",
            "不回存活目录会静默丢失 A 的使用变更"
        );
        assert_eq!(
            fs::read(snap_a.join("cache/new.tmp")).unwrap(),
            b"new",
            "新增文件也要回存"
        );
        // 当前账号标记切到 B：下次切换才会把 B 的变更回存给 B。
        assert_eq!(store.current_desktop_profile_id.as_deref(), Some("b-id"));
    }

    #[test]
    fn switch_in_skips_save_back_when_no_current_desktop_account() {
        // 从未 capture/切换过（无当前标记）时不得报错，也不得凭空创建快照。
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let accounts = dir.path().join("desktop-accounts");
        let snapshot = accounts.join("b-id");
        fs::create_dir_all(&snapshot).unwrap();
        fs::write(snapshot.join("who.txt"), b"B-account").unwrap();

        let mut store = Store::default();
        store.desktop_profiles.push(DesktopProfile {
            id: "b-id".into(),
            name: "B".into(),
            notes: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_switched_at: None,
            snapshot_rel: "desktop-accounts/b-id".into(),
            size_bytes: 0,
            meta: None,
        });
        let live = dir.path().join("APPDATA").join("Claude");
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("who.txt"), b"unknown-account").unwrap();

        let tx = DesktopTransaction::default();
        switch_desktop_profile_in(
            "b-id",
            &live,
            &accounts,
            &mut store,
            &|_names| Ok(Vec::new()),
            &|| Ok(false),
            &dir.path().join("backups"),
            &copy_dir_recursive,
            &tx,
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(live.join("who.txt")).unwrap(),
            "B-account"
        );
        assert_eq!(store.current_desktop_profile_id.as_deref(), Some("b-id"));
    }

    #[test]
    fn switch_in_rolls_back_when_snapshot_copy_fails() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let accounts = dir.path().join("desktop-accounts");
        let snapshot = accounts.join("b-id");
        fs::create_dir_all(&snapshot).unwrap();
        fs::write(snapshot.join("who.txt"), b"B-account").unwrap();

        let mut store = Store::default();
        store.desktop_profiles.push(DesktopProfile {
            id: "b-id".into(),
            name: "B".into(),
            notes: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_switched_at: None,
            snapshot_rel: "desktop-accounts/b-id".into(),
            size_bytes: 0,
            meta: None,
        });

        let live = dir.path().join("APPDATA").join("Claude");
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("who.txt"), b"A-account").unwrap();
        let backup_root = dir.path().join("backups");
        let live_clone = live.clone();
        let snapshot_clone = snapshot.clone();

        // live->backup 放行；快照->live 模拟失败；回滚的 backup->live 再放行。
        let copy = move |src: &Path, dst: &Path| {
            if src == snapshot_clone && dst == live_clone {
                return Err("模拟快照覆盖失败".to_string());
            }
            copy_dir_recursive(src, dst)
        };

        let tx = DesktopTransaction::default();
        let err = switch_desktop_profile_in(
            "b-id",
            &live,
            &accounts,
            &mut store,
            &|_names| Ok(Vec::new()),
            &|| Ok(false),
            &backup_root,
            &copy,
            &tx,
        )
        .unwrap_err();

        assert!(err.contains("模拟快照覆盖失败"), "{err}");
        assert!(err.contains("已自动回滚"), "{err}");
        // 回滚后活目录仍是 A，而不是空的 / 半截 B。
        assert_eq!(
            fs::read_to_string(live.join("who.txt")).unwrap(),
            "A-account",
            "回滚失败会让用户失去整个登录态"
        );
        // 回滚成功后不应更新切换时间戳。
        assert!(store.desktop_profiles[0].last_switched_at.is_none());
    }

    #[test]
    fn switch_in_errors_for_unknown_missing_snapshot_and_still_running() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let accounts = dir.path().join("desktop-accounts");
        fs::create_dir_all(&accounts).unwrap();
        let live = dir.path().join("APPDATA").join("Claude");
        fs::create_dir_all(&live).unwrap();
        let mut store = Store::default();

        // 未知 id。
        let tx = DesktopTransaction::default();
        let err = switch_desktop_profile_in(
            "nobody",
            &live,
            &accounts,
            &mut store,
            &|_| Ok(Vec::new()),
            &|| Ok(false),
            &dir.path().join("backups"),
            &copy_dir_recursive,
            &tx,
        )
        .unwrap_err();
        assert!(err.contains("未找到"), "{err}");

        // id 存在但快照目录被删。
        store.desktop_profiles.push(DesktopProfile {
            id: "ghost".into(),
            name: "幽灵".into(),
            notes: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_switched_at: None,
            snapshot_rel: "desktop-accounts/ghost".into(),
            size_bytes: 0,
            meta: None,
        });
        let tx = DesktopTransaction::default();
        let err = switch_desktop_profile_in(
            "ghost",
            &live,
            &accounts,
            &mut store,
            &|_| Ok(Vec::new()),
            &|| Ok(false),
            &dir.path().join("backups"),
            &copy_dir_recursive,
            &tx,
        )
        .unwrap_err();
        assert!(err.contains("快照目录缺失"), "{err}");

        // kill 后仍在运行 -> 中止，不动物理目录。
        // 注意：快照目录检查在 kill 之前，这里要先把 ghost 快照补齐，
        // 才能走到 wait_until_quite 这一步。
        fs::create_dir_all(accounts.join("ghost")).unwrap();
        fs::write(live.join("who.txt"), b"A").unwrap();
        let tx = DesktopTransaction::default();
        let err = switch_desktop_profile_in(
            "ghost",
            &live,
            &accounts,
            &mut store,
            &|_| Ok(Vec::new()),
            &|| Ok(true),
            &dir.path().join("backups"),
            &copy_dir_recursive,
            &tx,
        )
        .unwrap_err();
        assert!(err.contains("未能完全退出"), "{err}");
        assert_eq!(fs::read_to_string(live.join("who.txt")).unwrap(), "A");
    }

    fn current_desktop_store() -> Store {
        let past = "2000-01-01T00:00:00Z"
            .parse::<chrono::DateTime<Utc>>()
            .unwrap();
        let mut store = Store {
            current_desktop_profile_id: Some("current".to_string()),
            ..Default::default()
        };
        store.desktop_profiles.push(DesktopProfile {
            id: "current".to_string(),
            name: "当前测试账号".to_string(),
            snapshot_rel: "desktop-accounts/current".to_string(),
            created_at: past,
            updated_at: past,
            last_switched_at: Some(past),
            size_bytes: 42,
            ..Default::default()
        });
        store
    }

    fn file_tree(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        fn collect(
            root: &Path,
            current: &Path,
            result: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>,
        ) {
            for entry in fs::read_dir(current).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    collect(root, &path, result);
                } else {
                    result.insert(
                        path.strip_prefix(root).unwrap().to_path_buf(),
                        fs::read(path).unwrap(),
                    );
                }
            }
        }
        let mut result = std::collections::BTreeMap::new();
        collect(root, root, &mut result);
        result
    }

    #[test]
    fn switch_in_current_account_preserves_newer_live_bytes_and_store() {
        use std::cell::Cell;
        use std::rc::Rc;
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let accounts = dir.path().join("desktop-accounts");
        let snapshot = accounts.join("current");
        fs::create_dir_all(&snapshot).unwrap();
        fs::write(snapshot.join("session.bin"), b"old-capture").unwrap();
        let live = dir.path().join("APPDATA/Claude");
        fs::create_dir_all(live.join("nested")).unwrap();
        fs::write(live.join("session.bin"), b"new-live-session\0\xff").unwrap();
        fs::write(live.join("nested/new-session.dat"), [0, 1, 2, 254, 255]).unwrap();
        let live_before = file_tree(&live);
        let snapshot_before = file_tree(&snapshot);
        let mut store = current_desktop_store();
        let store_before = serde_json::to_value(&store).unwrap();
        let calls = Rc::new(Cell::new(0));
        let kill_calls = Rc::clone(&calls);
        let running_calls = Rc::clone(&calls);
        let copy_calls = Rc::clone(&calls);
        let backup_root = dir.path().join("backups");
        let tx = DesktopTransaction::default();
        let warnings = switch_desktop_profile_in(
            "current",
            &live,
            &accounts,
            &mut store,
            &move |_| {
                kill_calls.set(kill_calls.get() + 1);
                Ok(Vec::new())
            },
            &move || {
                running_calls.set(running_calls.get() + 1);
                Ok(false)
            },
            &backup_root,
            &move |src, dst| {
                copy_calls.set(copy_calls.get() + 1);
                copy_dir_recursive(src, dst)
            },
            &tx,
        )
        .unwrap();
        assert_eq!(
            file_tree(&live),
            live_before,
            "同账号重选不得把当前会话换成旧快照"
        );
        assert_eq!(file_tree(&snapshot), snapshot_before);
        assert_eq!(
            serde_json::to_value(&store).unwrap(),
            store_before,
            "当前标记和所有时间戳应保持原值"
        );
        assert_eq!(calls.get(), 0, "幂等操作不得调用退出、进程检测或复制");
        assert!(!backup_root.exists());
        assert!(warnings.iter().any(|message| message.contains("当前已是")));
    }

    #[test]
    fn switch_in_current_account_with_live_needs_no_snapshot_or_keep_staging() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let accounts = dir.path().join("desktop-accounts");
        let live = dir.path().join("APPDATA/Claude");
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("session.bin"), b"live-only").unwrap();
        let keep = dir.path().join(".claude-switcher");
        fs::create_dir_all(keep.join("keep-stage")).unwrap();
        fs::write(keep.join("keep-in-workspace.txt"), "session.bin").unwrap();
        fs::write(keep.join("keep-stage/retained.bin"), b"only-retained-copy").unwrap();
        let keep_before = file_tree(&keep);
        let mut store = current_desktop_store();
        let store_before = serde_json::to_value(&store).unwrap();
        for snapshot_exists in [false, true] {
            if snapshot_exists {
                fs::create_dir_all(accounts.join("current")).unwrap();
            }
            let tx = DesktopTransaction::default();
            let result = switch_desktop_profile_in(
                "current",
                &live,
                &accounts,
                &mut store,
                &|_| panic!("同账号已有活目录时不得退出进程"),
                &|| panic!("同账号已有活目录时不得检测进程"),
                &dir.path().join("backups"),
                &|_, _| panic!("同账号已有活目录时不得复制文件"),
                &tx,
            )
            .unwrap();
            assert!(result.iter().any(|message| message.contains("当前已是")));
            assert_eq!(fs::read(live.join("session.bin")).unwrap(), b"live-only");
            assert_eq!(
                file_tree(&keep),
                keep_before,
                "不得暂存、合并或清理已有 keep 材料"
            );
            assert_eq!(serde_json::to_value(&store).unwrap(), store_before);
            assert!(!dir.path().join("backups").exists());
        }
    }

    #[test]
    fn switch_in_current_account_recovers_missing_live_from_snapshot() {
        use std::cell::Cell;
        use std::rc::Rc;
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let accounts = dir.path().join("desktop-accounts");
        let snapshot = accounts.join("current");
        fs::create_dir_all(&snapshot).unwrap();
        fs::write(snapshot.join("session.bin"), b"recoverable-session").unwrap();
        let snapshot_before = file_tree(&snapshot);
        let live = dir.path().join("APPDATA/Claude");
        let mut store = current_desktop_store();
        let old_updated_at = store.desktop_profiles[0].updated_at;
        let kill_calls = Rc::new(Cell::new(0));
        let copy_calls = Rc::new(Cell::new(0));
        let kill_count = Rc::clone(&kill_calls);
        let copy_count = Rc::clone(&copy_calls);
        let tx = DesktopTransaction::default();
        let warnings = switch_desktop_profile_in(
            "current",
            &live,
            &accounts,
            &mut store,
            &move |_| {
                kill_count.set(kill_count.get() + 1);
                Ok(Vec::new())
            },
            &|| Ok(false),
            &dir.path().join("backups"),
            &move |src, dst| {
                copy_count.set(copy_count.get() + 1);
                copy_dir_recursive(src, dst)
            },
            &tx,
        )
        .unwrap();
        assert_eq!(file_tree(&live), snapshot_before);
        assert_eq!(file_tree(&snapshot), snapshot_before);
        assert_eq!(kill_calls.get(), 1);
        assert_eq!(copy_calls.get(), 1);
        assert_eq!(store.current_desktop_profile_id.as_deref(), Some("current"));
        assert!(store.desktop_profiles[0].updated_at > old_updated_at);
        assert!(warnings.iter().any(|message| message.contains("已载入")));
        assert!(!dir.path().join("backups").exists());
    }

    #[test]
    fn switch_in_current_missing_both_and_unknown_id_fail_without_side_effects() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let accounts = dir.path().join("desktop-accounts");
        let live = dir.path().join("APPDATA/Claude");
        let mut store = current_desktop_store();
        let store_before = serde_json::to_value(&store).unwrap();
        for (target, expected) in [("current", "快照目录缺失"), ("unknown", "未找到")] {
            let tx = DesktopTransaction::default();
            let error = switch_desktop_profile_in(
                target,
                &live,
                &accounts,
                &mut store,
                &|_| panic!("材料缺失时不得退出进程"),
                &|| panic!("材料缺失时不得检测进程"),
                &dir.path().join("backups"),
                &|_, _| panic!("材料缺失时不得复制文件"),
                &tx,
            )
            .unwrap_err();
            assert!(error.contains(expected), "{error}");
            assert_eq!(serde_json::to_value(&store).unwrap(), store_before);
            assert!(!live.exists());
            assert!(!dir.path().join("backups").exists());
        }
    }

    #[test]
    fn desktop_exe_detection_table() {
        let cases: Vec<(Option<&str>, bool, &str)> = vec![
            (
                Some(r"C:\Users\A\AppData\Local\AnthropicClaude\Claude.exe"),
                true,
                "Desktop 标准安装",
            ),
            (
                Some(r"C:\Users\A\AppData\Local\AnthropicClaude\app.exe"),
                true,
                "Desktop 主进程可能叫 app.exe",
            ),
            (
                Some(r"C:\Program Files\WindowsApps\Anthropic.Claude_1.2.3\claude.exe"),
                true,
                "Desktop MSIX 安装",
            ),
            (
                Some(r"C:\Users\A\AppData\Local\claude\claude.exe"),
                false,
                "Claude Code CLI 原生安装",
            ),
            (Some("node.exe"), false, "CLI 的 node 宿主（无路径特征）"),
            (
                Some(r"C:\Users\A\AppData\Local\Programs\Claude-Switcher\Claude-Switcher.exe"),
                false,
                "本工具自身",
            ),
            (
                Some(r"C:\Program Files\WindowsApps\Node.JS.20.11\node.exe"),
                false,
                "无关 Store 程序",
            ),
            (None, false, "拿不到 exe 路径"),
        ];
        let mut failures = Vec::new();
        for (exe, expect, desc) in cases {
            let got = is_claude_desktop_exe(exe);
            if got != expect {
                failures.push(format!("FAIL: {desc} (expect={expect}, got={got})"));
            }
        }
        assert!(
            failures.is_empty(),
            "进程判定表格测试:\n{}",
            failures.join("\n")
        );
    }

    /// **P0-02**：对**每一个**可能落盘的阶段模拟崩溃，恢复器都必须有确定决策。
    ///
    /// 原实现的 `match ledger.phase.as_str()` 只列了 committed / files_switched /
    /// prepared，`backup_verified` 直接掉进「未知阶段」——备份已完成、文件可能
    /// 已替换的关键窗口无人回滚。这个测试把它变成不可回归的约束。
    #[test]
    fn heal_handles_every_phase() {
        let _env = crate::test_support::env_lock();

        // 期望行为：是否应该回滚到切换前内容。
        let cases = [
            (DesktopSwitchPhase::Prepared, false, "未动文件"),
            (DesktopSwitchPhase::BackupVerified, true, "备份已登记"),
            (DesktopSwitchPhase::FilesSwitching, true, "文件替换中"),
            (DesktopSwitchPhase::FilesSwitched, true, "文件已替换"),
            (DesktopSwitchPhase::StoreCommitted, false, "账号库已提交"),
            (DesktopSwitchPhase::Unknown, false, "未知阶段不自动删除"),
        ];

        for (phase, expect_rollback, desc) in cases {
            let dir = tempfile::tempdir().unwrap();
            let _home = crate::test_support::set_env("USERPROFILE", dir.path());
            let data = dir.path().join(".claude-switcher");
            fs::create_dir_all(&data).unwrap();

            // 备份目录 = 切换前内容（A），活目录 = 切换后内容（B）。
            let backup = data.join("backup-A");
            fs::create_dir_all(&backup).unwrap();
            fs::write(backup.join("who.txt"), b"A-account").unwrap();
            let live = dir.path().join("Claude");
            fs::create_dir_all(&live).unwrap();
            fs::write(live.join("who.txt"), b"B-account").unwrap();

            let ledger = DesktopSwitchLedger {
                transaction_id: "t".to_string(),
                from_id: Some("a".to_string()),
                to_id: "b".to_string(),
                backup_path: Some(backup.to_string_lossy().to_string()),
                original_existed: true,
                live_dir: live.to_string_lossy().to_string(),
                store_commit: None,
                snapshot_swap: None,
                phase,
                started_at: 0,
            };
            write_switch_ledger(&ledger).unwrap();

            let messages = heal_desktop_switch();
            let content = fs::read_to_string(live.join("who.txt")).unwrap_or_default();
            if expect_rollback {
                assert_eq!(
                    content, "A-account",
                    "{desc}：应回滚到切换前内容，实际 {content}；消息：{messages:?}"
                );
            } else {
                assert_eq!(
                    content, "B-account",
                    "{desc}：不应删除/覆盖活目录，实际 {content}；消息：{messages:?}"
                );
            }
            // 回滚成功或已提交/未动文件时应清账本；Unknown 必须保留。
            let ledger_exists = desktop_switch_ledger_path().unwrap().exists();
            if matches!(phase, DesktopSwitchPhase::Unknown) {
                assert!(ledger_exists, "{desc}：未知阶段必须保留账本");
            } else {
                assert!(!ledger_exists, "{desc}：账本应已清理；消息：{messages:?}");
            }
        }
    }

    /// **P0-02**：`BackupVerified` 但备份目录已丢失时，**绝不**删除活目录。
    #[test]
    fn heal_keeps_live_when_backup_missing() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let data = dir.path().join(".claude-switcher");
        fs::create_dir_all(&data).unwrap();
        let live = dir.path().join("Claude");
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("who.txt"), b"only-copy").unwrap();

        let ledger = DesktopSwitchLedger {
            transaction_id: "t".to_string(),
            from_id: None,
            to_id: "b".to_string(),
            backup_path: Some(data.join("gone-backup").to_string_lossy().to_string()),
            original_existed: true,
            live_dir: live.to_string_lossy().to_string(),
            store_commit: None,
            snapshot_swap: None,
            phase: DesktopSwitchPhase::BackupVerified,
            started_at: 0,
        };
        write_switch_ledger(&ledger).unwrap();

        let messages = heal_desktop_switch();
        assert_eq!(
            fs::read_to_string(live.join("who.txt")).unwrap(),
            "only-copy",
            "备份缺失时绝不能动活目录"
        );
        assert!(
            messages.iter().any(|m| m.contains("备份缺失")),
            "{messages:?}"
        );
        // 账本保留，等待人工核对后再清理。
        assert!(desktop_switch_ledger_path().unwrap().exists());
    }

    /// **P0-02**：旧账本用字符串阶段，反序列化必须落到 `Unknown`（不自动删除）。
    #[test]
    fn legacy_string_phase_deserializes_to_unknown() {
        // 用 serde 构造 JSON，避免手写转义出错。
        let legacy = serde_json::json!({
            "transaction_id": "t",
            "from_id": null,
            "to_id": "b",
            "backup_path": null,
            "original_existed": true,
            "live_dir": r"C:\x",
            "phase": "committed",
            "started_at": 0,
        });
        let json = legacy.to_string();
        let ledger: DesktopSwitchLedger = serde_json::from_str(&json).unwrap();
        // 旧版的 "committed" 不是枚举变体名 → Unknown（保守，不自动清理）。
        assert_eq!(ledger.phase, DesktopSwitchPhase::Unknown);
    }

    /// **P0-A**：崩溃恰好落在「账号库已保存成功、账本阶段还没改成
    /// StoreCommitted」这一窗口时，恢复器必须以**账号库实际状态**为准，
    /// 保持活目录而不是回滚——否则会产生「活目录 A + 账号库 B」的不一致。
    #[test]
    fn heal_prefers_store_state_over_stale_phase() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let data = dir.path().join(".claude-switcher");
        fs::create_dir_all(&data).unwrap();

        let backup = data.join("backup-A");
        fs::create_dir_all(&backup).unwrap();
        fs::write(backup.join("who.txt"), b"A-account").unwrap();
        let live = dir.path().join("Claude");
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("who.txt"), b"B-account").unwrap();

        // 账号库已经提交到 B（模拟 with_store 保存成功）。
        let store_data = Store {
            desktop_profiles: vec![DesktopProfile {
                id: "b".into(),
                name: "B".into(),
                notes: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_switched_at: None,
                snapshot_rel: "desktop-accounts/b".into(),
                size_bytes: 0,
                meta: None,
            }],
            current_desktop_profile_id: Some("b".into()),
            last_desktop_transaction_id: Some("t".into()),
            ..Default::default()
        };
        store::save_store(&store_data).unwrap();

        // 账本仍停在 FilesSwitching（阶段还没来得及推进）。
        let ledger = DesktopSwitchLedger {
            transaction_id: "t".to_string(),
            from_id: Some("a".to_string()),
            to_id: "b".to_string(),
            backup_path: Some(backup.to_string_lossy().to_string()),
            original_existed: true,
            live_dir: live.to_string_lossy().to_string(),
            store_commit: None,
            snapshot_swap: None,
            phase: DesktopSwitchPhase::FilesSwitching,
            started_at: 0,
        };
        write_switch_ledger(&ledger).unwrap();

        let messages = heal_desktop_switch();
        assert_eq!(
            fs::read_to_string(live.join("who.txt")).unwrap(),
            "B-account",
            "账号库已提交 B，绝不能把活目录回滚成 A；消息：{messages:?}"
        );
        assert!(
            !desktop_switch_ledger_path().unwrap().exists(),
            "应清理账本"
        );
    }

    /// 当前账号本来就是 B，但本次事务尚未提交，不能误认已成功。
    #[test]
    fn heal_requires_matching_transaction_id_not_just_target() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let data = dir.path().join(".claude-switcher");
        fs::create_dir_all(&data).unwrap();
        let backup = data.join("backup-B");
        fs::create_dir_all(&backup).unwrap();
        fs::write(backup.join("who.txt"), b"original-B").unwrap();
        let live = dir.path().join("Claude");
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("who.txt"), b"partial-B").unwrap();
        store::save_store(&Store {
            current_desktop_profile_id: Some("b".into()),
            ..Default::default()
        })
        .unwrap();
        write_switch_ledger(&DesktopSwitchLedger {
            transaction_id: "new-tx".into(),
            from_id: Some("b".into()),
            to_id: "b".into(),
            backup_path: Some(backup.to_string_lossy().to_string()),
            original_existed: true,
            live_dir: live.to_string_lossy().to_string(),
            store_commit: None,
            snapshot_swap: None,
            phase: DesktopSwitchPhase::FilesSwitching,
            started_at: 0,
        })
        .unwrap();
        heal_desktop_switch();
        assert_eq!(
            fs::read_to_string(live.join("who.txt")).unwrap(),
            "original-B"
        );
    }

    /// **P0-A**：账号库未提交本次目标时，仍按备份回滚。
    #[test]
    fn heal_rolls_back_when_store_did_not_commit() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let data = dir.path().join(".claude-switcher");
        fs::create_dir_all(&data).unwrap();

        let backup = data.join("backup-A");
        fs::create_dir_all(&backup).unwrap();
        fs::write(backup.join("who.txt"), b"A-account").unwrap();
        let live = dir.path().join("Claude");
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("who.txt"), b"B-account").unwrap();

        // 账号库仍是 A（保存失败/尚未保存）。
        let store_data = Store {
            current_desktop_profile_id: Some("a".into()),
            ..Default::default()
        };
        store::save_store(&store_data).unwrap();

        let ledger = DesktopSwitchLedger {
            transaction_id: "t".to_string(),
            from_id: Some("a".to_string()),
            to_id: "b".to_string(),
            backup_path: Some(backup.to_string_lossy().to_string()),
            original_existed: true,
            live_dir: live.to_string_lossy().to_string(),
            store_commit: None,
            snapshot_swap: None,
            phase: DesktopSwitchPhase::FilesSwitching,
            started_at: 0,
        };
        write_switch_ledger(&ledger).unwrap();

        let _ = heal_desktop_switch();
        assert_eq!(
            fs::read_to_string(live.join("who.txt")).unwrap(),
            "A-account",
            "账号库未提交，必须回滚到切换前内容"
        );
    }

    /// 回存中断在 `.old` 阶段时，必须把原快照请回正式目录。
    #[test]
    fn heal_restores_snapshot_from_retired() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let data = dir.path().join(".claude-switcher");
        let accounts = data.join("desktop-accounts");
        std::fs::create_dir_all(&accounts).unwrap();
        // 正式快照缺失，.old 里是原数据。
        let retired = accounts.join("a.old");
        std::fs::create_dir_all(&retired).unwrap();
        std::fs::write(retired.join("who.txt"), b"original-snapshot").unwrap();
        let staging = accounts.join("a.new");
        std::fs::create_dir_all(&staging).unwrap();

        let live = dir.path().join("Claude");
        std::fs::create_dir_all(&live).unwrap();
        let ledger = DesktopSwitchLedger {
            transaction_id: "t".into(),
            from_id: Some("a".into()),
            to_id: "b".into(),
            backup_path: None,
            original_existed: true,
            live_dir: live.to_string_lossy().to_string(),
            store_commit: None,
            snapshot_swap: Some(SnapshotSwapState {
                snapshot_id: "a".into(),
                snapshot: accounts.join("a").to_string_lossy().to_string(),
                staging: staging.to_string_lossy().to_string(),
                retired: retired.to_string_lossy().to_string(),
                retired_original: true,
            }),
            phase: DesktopSwitchPhase::FilesSwitching,
            started_at: 0,
        };
        write_switch_ledger(&ledger).unwrap();
        heal_desktop_switch();
        assert_eq!(
            std::fs::read(accounts.join("a").join("who.txt")).unwrap(),
            b"original-snapshot",
            "原快照必须回到正式目录"
        );
        assert!(!staging.exists(), "半成品 .new 必须清理");
    }

    /// **P0-03**：一次前置检查失败（目标快照不存在）不得留下永久待恢复事务。
    #[test]
    fn failed_switch_does_not_leave_permanent_ledger() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        std::fs::create_dir_all(dir.path().join(".claude-switcher")).unwrap();
        // 没有注册任何 Desktop 账号：切换必然在查找阶段失败。
        let err = switch_desktop_profile("nonexistent-id").unwrap_err();
        assert!(!err.is_empty());
        assert!(
            !desktop_switch_ledger_path().unwrap().exists(),
            "未动任何文件就失败时，账本必须清掉；实际残留：{err}"
        );
        // 之后仍能正常建立下一次事务（不会被上一次失败卡死）。
        assert!(read_pending_switch_ledger().unwrap().is_none());
    }

    /// **P0-04**：删除快照时，物理目录先被改名成唯一待删名；
    /// 即使此时另有导入重建了同 ID 目录，也不会被本次删除波及。
    #[test]
    fn delete_renames_snapshot_before_removal() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let data = dir.path().join(".claude-switcher");
        let snapshot = data.join("desktop-accounts").join("a-id");
        std::fs::create_dir_all(&snapshot).unwrap();
        std::fs::write(snapshot.join("who.txt"), b"A").unwrap();
        store::with_store(|store| {
            store.desktop_profiles.push(DesktopProfile {
                id: "a-id".into(),
                name: "A".into(),
                notes: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_switched_at: None,
                snapshot_rel: "desktop-accounts/a-id".into(),
                size_bytes: 0,
                meta: None,
            });
            store.current_desktop_profile_id = Some("a-id".into());
            Ok(())
        })
        .unwrap();

        delete_desktop_profile("a-id", true).unwrap();
        assert!(!snapshot.exists(), "快照目录应被删除");
        // 不应残留任何待删目录。
        let leftovers: Vec<String> = std::fs::read_dir(data.join("desktop-accounts"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(leftovers.is_empty(), "残留：{leftovers:?}");
        let after = store::load_store().unwrap();
        assert!(after.desktop_profiles.is_empty());
        assert!(after.current_desktop_profile_id.is_none());
    }

    /// **P0-A 回归**：内层已把账本推进到 FilesSwitching 后失败时，
    /// 外层**不能**因为自己手里还是 Prepared 就清掉账本。
    #[test]
    fn failed_after_files_switching_keeps_ledger() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let accounts = dir.path().join("desktop-accounts");
        let snapshot = accounts.join("b-id");
        fs::create_dir_all(&snapshot).unwrap();
        fs::write(snapshot.join("who.txt"), b"B").unwrap();

        let mut store_data = Store::default();
        store_data.desktop_profiles.push(DesktopProfile {
            id: "b-id".into(),
            name: "B".into(),
            notes: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_switched_at: None,
            snapshot_rel: "desktop-accounts/b-id".into(),
            size_bytes: 0,
            meta: None,
        });

        let live = dir.path().join("Claude");
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("who.txt"), b"A").unwrap();
        let backup_root = dir.path().join("backups");
        let snapshot_clone = snapshot.clone();
        let live_clone = live.clone();
        // 备份成功、活目录清空之后，快照→活目录复制失败。
        let copy = move |src: &Path, dst: &Path| {
            if src == snapshot_clone && dst == live_clone {
                return Err("模拟目标快照复制失败".to_string());
            }
            copy_dir_recursive(src, dst)
        };
        let tx = DesktopTransaction::default();
        let err = switch_desktop_profile_in(
            "b-id",
            &live,
            &accounts,
            &mut store_data,
            &|_n| Ok(Vec::new()),
            &|| Ok(false),
            &backup_root,
            &copy,
            &tx,
        )
        .unwrap_err();
        assert!(err.contains("复制失败"), "{err}");
        // 事务上下文必须反映出「已经动过文件」。
        assert!(
            matches!(
                tx.phase.get(),
                DesktopSwitchPhase::FilesSwitching | DesktopSwitchPhase::BackupVerified
            ),
            "内层推进阶段后应回写事务上下文，实际 {:?}",
            tx.phase.get()
        );
    }

    /// **P0-D**：删除在「改名后、存库前」崩溃时，启动恢复要把目录改回正式名。
    #[test]
    fn delete_journal_restores_directory_when_store_not_committed() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let accounts = dir.path().join(".claude-switcher").join("desktop-accounts");
        let original = accounts.join("a-id");
        let pending = accounts.join(".a-id.delete-pending-test");
        std::fs::create_dir_all(&pending).unwrap();
        std::fs::write(pending.join("who.txt"), b"only-copy").unwrap();

        // 账号库仍登记该快照（存库未完成）。
        store::with_store(|store| {
            store.desktop_profiles.push(DesktopProfile {
                id: "a-id".into(),
                name: "A".into(),
                notes: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_switched_at: None,
                snapshot_rel: "desktop-accounts/a-id".into(),
                size_bytes: 0,
                meta: None,
            });
            Ok(())
        })
        .unwrap();
        write_delete_journal(&DesktopDeleteJournal {
            transaction_id: "t".into(),
            snapshot_id: "a-id".into(),
            original: original.to_string_lossy().to_string(),
            pending: pending.to_string_lossy().to_string(),
            files_moved: true,
            store_committed: false,
            started_at: 0,
        })
        .unwrap();

        let messages = heal_desktop_delete();
        assert!(
            original.is_dir(),
            "登记仍在时必须把待删目录恢复为正式快照；消息：{messages:?}"
        );
        assert_eq!(fs::read(original.join("who.txt")).unwrap(), b"only-copy");
        assert!(!desktop_delete_journal_path().unwrap().exists());
    }

    /// **P0-D**：登记已删除时，恢复器继续清理待删目录。
    #[test]
    fn delete_journal_cleans_pending_when_store_committed() {
        let _env = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let accounts = dir.path().join(".claude-switcher").join("desktop-accounts");
        let pending = accounts.join(".a-id.delete-pending-test");
        std::fs::create_dir_all(&pending).unwrap();
        // 账号库里没有该登记（删除已提交）。
        store::with_store(|store| {
            store.desktop_profiles.clear();
            Ok(())
        })
        .unwrap();
        write_delete_journal(&DesktopDeleteJournal {
            transaction_id: "t".into(),
            snapshot_id: "a-id".into(),
            original: accounts.join("a-id").to_string_lossy().to_string(),
            pending: pending.to_string_lossy().to_string(),
            files_moved: true,
            store_committed: true,
            started_at: 0,
        })
        .unwrap();

        let _ = heal_desktop_delete();
        assert!(!pending.exists(), "登记已删除时应清理待删目录");
        assert!(!desktop_delete_journal_path().unwrap().exists());
    }
}
