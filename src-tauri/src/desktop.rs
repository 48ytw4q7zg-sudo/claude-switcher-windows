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

/// Claude Desktop 活数据目录：`%APPDATA%\Claude`（macOS 上为 `config_dir()/Claude`，
/// 即 `~/Library/Application Support/Claude`，行为对齐）。
pub fn desktop_live_dir() -> Result<PathBuf, String> {
    let config = dirs::config_dir()
        .ok_or_else(|| "无法定位应用配置目录（%APPDATA% / config_dir）".to_string())?;
    Ok(config.join(DESKTOP_DIR_NAME))
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
    let mut store = store::load_store()?;
    let profile = capture_desktop_profile_into(name, notes, &live, &snapshot, &mut store, &|| {
        claude_desktop_running()
    })?;
    store::save_store(&store)?;
    Ok(profile)
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
    let mut store = store::load_store()?;
    let warnings = switch_desktop_profile_in(
        id,
        &live,
        &accounts,
        &mut store,
        &|_names| kill_desktop_processes(),
        &|| claude_desktop_running(),
        &backup_root,
        &copy_dir_recursive,
    )?;
    store::save_store(&store)?;
    Ok(warnings)
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
                    let _ = fsx::retry_io(|| fs::remove_dir_all(&retired));
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
    let backup_path = if live_dir.is_dir() {
        fs::create_dir_all(backup_root)
            .map_err(|e| format!("创建备份目录失败 {}: {e}", backup_root.display()))?;
        let path = backup_root.join(format!(
            "{}-{}",
            Utc::now().format("%Y%m%d%H%M%S"),
            Uuid::new_v4().simple()
        ));
        let outcome = copy(live_dir, &path)?;
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

    // 跨身份保留：把暂存文件合并回载入后的活目录；失败保留暂存、提示手动恢复。
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
        Err(e) => warnings.push(format!("跨身份保留合并失败（暂存已保留，可手动恢复）：{e}")),
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
pub fn delete_desktop_profile(id: &str, also_files: bool) -> Result<(), String> {
    let mut store = store::load_store()?;
    let Some(pos) = store.desktop_profiles.iter().position(|p| p.id == id) else {
        return Ok(());
    };
    let profile = store.desktop_profiles.remove(pos);
    // 删的是当前账号：清掉当前标记，避免下次切换尝试回存到不存在的快照。
    if store.current_desktop_profile_id.as_deref() == Some(id) {
        store.current_desktop_profile_id = None;
    }
    store::save_store(&store)?;

    if also_files {
        let snapshot = desktop_snapshot_dir(&profile.id)?;
        if snapshot.exists() {
            fsx::retry_io(|| fs::remove_dir_all(&snapshot)).map_err(|e| {
                format!(
                    "删除快照目录失败 {}: {}",
                    snapshot.display(),
                    fsx::humanize_io_error(&e)
                )
            })?;
        }
    }
    Ok(())
}

/// 重命名 Desktop 账号（不动物理快照）。
pub fn rename_desktop_profile(id: &str, name: &str) -> Result<DesktopProfile, String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("账号名称不能为空".to_string());
    }
    let mut store = store::load_store()?;
    let profile = store
        .desktop_profiles
        .iter_mut()
        .find(|p| p.id == id)
        .ok_or_else(|| format!("未找到桌面账号快照: {id}"))?;
    profile.name = name;
    profile.updated_at = Utc::now();
    let cloned = profile.clone();
    store::save_store(&store)?;
    Ok(cloned)
}

// ───────────────────────── 单测 ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
        let dir = tempfile::tempdir().unwrap();
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
        let warnings = switch_desktop_profile_in(
            "b-id",
            &live,
            &accounts,
            &mut store,
            &|_names| Ok(Vec::new()),
            &|| Ok(false),
            &backup_root,
            &copy_dir_recursive,
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
        let dir = tempfile::tempdir().unwrap();
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

        switch_desktop_profile_in(
            "b-id",
            &live,
            &accounts,
            &mut store,
            &|_names| Ok(Vec::new()),
            &|| Ok(false),
            &dir.path().join("backups"),
            &copy_dir_recursive,
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
        let dir = tempfile::tempdir().unwrap();
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

        switch_desktop_profile_in(
            "b-id",
            &live,
            &accounts,
            &mut store,
            &|_names| Ok(Vec::new()),
            &|| Ok(false),
            &dir.path().join("backups"),
            &copy_dir_recursive,
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
        let dir = tempfile::tempdir().unwrap();
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

        let err = switch_desktop_profile_in(
            "b-id",
            &live,
            &accounts,
            &mut store,
            &|_names| Ok(Vec::new()),
            &|| Ok(false),
            &backup_root,
            &copy,
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
        let dir = tempfile::tempdir().unwrap();
        let accounts = dir.path().join("desktop-accounts");
        fs::create_dir_all(&accounts).unwrap();
        let live = dir.path().join("APPDATA").join("Claude");
        fs::create_dir_all(&live).unwrap();
        let mut store = Store::default();

        // 未知 id。
        let err = switch_desktop_profile_in(
            "nobody",
            &live,
            &accounts,
            &mut store,
            &|_| Ok(Vec::new()),
            &|| Ok(false),
            &dir.path().join("backups"),
            &copy_dir_recursive,
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
        let err = switch_desktop_profile_in(
            "ghost",
            &live,
            &accounts,
            &mut store,
            &|_| Ok(Vec::new()),
            &|| Ok(false),
            &dir.path().join("backups"),
            &copy_dir_recursive,
        )
        .unwrap_err();
        assert!(err.contains("快照目录缺失"), "{err}");

        // kill 后仍在运行 -> 中止，不动物理目录。
        // 注意：快照目录检查在 kill 之前，这里要先把 ghost 快照补齐，
        // 才能走到 wait_until_quite 这一步。
        fs::create_dir_all(accounts.join("ghost")).unwrap();
        fs::write(live.join("who.txt"), b"A").unwrap();
        let err = switch_desktop_profile_in(
            "ghost",
            &live,
            &accounts,
            &mut store,
            &|_| Ok(Vec::new()),
            &|| Ok(true),
            &dir.path().join("backups"),
            &copy_dir_recursive,
        )
        .unwrap_err();
        assert!(err.contains("未能完全退出"), "{err}");
        assert_eq!(fs::read_to_string(live.join("who.txt")).unwrap(), "A");
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
}
