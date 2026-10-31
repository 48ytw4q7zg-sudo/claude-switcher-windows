//! Claude Switcher（Windows 迁移版）。
//!
//! 模块划分（原 4229 行 lib.rs 拆分）：
//! - [`platform`]：cfg 收拢层（Windows/Unix 同名 API）。
//! - [`paths`]：路径解析（含 CLAUDE_CONFIG_DIR 跟随）与目录保障。
//! - [`credentials`]：凭据存取（Windows 凭据文件 / macOS Keychain）。
//! - [`fsx`]：原子写入与锁重试。
//! - [`jsonio`]：JSON/YAML 读写。
//! - [`links`]：隔离链接（symlink/junction/硬链接）。
//! - [`isolation`]：按 profile 接管/激活本地状态。
//! - [`store`]：账号快照库（C2 加密）。
//! - [`accounts`]：账号材料事务化写入与 settings env 注入。
//! - [`net`]：reqwest HTTP（Claude OAuth + Clash 控制器）。
//! - [`clash`]：Clash 状态与切换。
//! - [`processes`]：Claude Code CLI 进程检测/结束（sysinfo）。
//! - [`usage`]：用量统计（本地日志 + OAuth API 缓存）。
//! - [`tray`]：托盘、弹窗定位（防抖/多屏/工作区）。
//!
//! 迁移基线：上游 VallierDev/claude-switcher commit `6897984`。

mod accounts;
mod appconfig;
mod checks;
mod clash;
mod cli;
mod credentials;
mod desktop;
mod diagnostics;
mod dirbinding;
mod egress;
mod export;
mod fsx;
mod guard;
mod isolation;
mod jsonio;
mod keep;
mod links;
mod mcp;
mod naming;
mod net;
mod notify_state;
mod parallel;
mod paths;
mod permissions;
mod platform;
mod processes;
mod provider;
mod reconcile;
mod region;
mod rules;
mod sanitize;
mod shortcuts;
mod store;
mod stun;
// 测试共享基础设施（环境锁 / 环境还原器）。
#[cfg(test)]
mod test_support;
mod token_status;
mod tray;
mod update;
mod usage;
mod userpath;
mod workspace;
mod wsl;

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use tauri::Manager;

use accounts::BackupSnapshot;
use credentials::CREDENTIAL_STORE_LABEL;
use isolation::SessionIsolationStatus;
use jsonio::read_json_optional;
use paths as p;
use store::{
    PendingNewAccount, ProfileSummary, Store, StoredProfile, TelemetryMode, DEFAULT_CLASH_GROUP,
};

// ───────────────────────── 返回类型 ─────────────────────────

#[derive(Debug, Clone, Serialize)]
struct ClaudeStatus {
    claude_json_exists: bool,
    settings_json_exists: bool,
    credentials_json_exists: bool,
    keychain_exists: bool,
    keychain_parse_ok: bool,
    meta: store::ProfileMeta,
    claude_json_path: String,
    settings_json_path: String,
    data_dir: String,
    backup_dir: String,
    session_isolation: SessionIsolationStatus,
    profile_count: usize,
    current_profile_id: Option<String>,
    current_profile_name: Option<String>,
    pending_new_account: Option<PendingNewAccount>,
    telemetry_mode: TelemetryMode,
    /// 残留的切换事务日志（上次切换中断）；有值时前端提示用户按备份回滚。
    pending_switch: Option<SwitchJournal>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct BackupResult {
    id: String,
    path: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
struct BackupSummary {
    id: String,
    label: String,
    created_at: String,
}

#[derive(Debug, Clone, Serialize)]
struct SwitchResult {
    switched_to: String,
    backup: BackupResult,
    clash: Option<clash::ClashSwitchResult>,
    restart_hint: String,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PrepareNewAccountResult {
    pending: PendingNewAccount,
    backup: BackupResult,
    clash: clash::ClashSwitchResult,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RestoreResult {
    restored_from: String,
    backup: BackupResult,
    warnings: Vec<String>,
}

/// 切换事务日志：记录「正在切换到谁、做到哪步、备份在哪」。
/// 正常完成即删除；进程中途崩溃/被杀时残留，下次启动 `get_status` 会报出来，
/// 用户可按备份 id 回滚（restore_backup），而不是面对半切换状态猜。
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct SwitchJournal {
    target_id: String,
    step: String,
    backup_id: Option<String>,
    started_at: DateTime<Utc>,
}

fn write_switch_journal(journal: &SwitchJournal) {
    let Ok(path) = paths::switch_journal_path() else {
        return;
    };
    if let Ok(text) = serde_json::to_string_pretty(journal) {
        // 写日志失败不能阻断切换本身（记日志是旁路）。
        let _ = fsx::write_atomically(&path, &text);
    }
}

fn clear_switch_journal() {
    if let Ok(path) = paths::switch_journal_path() {
        let _ = fsx::remove_file_with_retry(&path);
    }
}

/// 启动/刷新时读取残留的切换事务日志（无残留返回 None）。
fn read_switch_journal() -> Option<SwitchJournal> {
    let path = paths::switch_journal_path().ok()?;
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// 切换前预检：目标快照可解密、凭据存储可写、磁盘可写。
/// 任一硬性项失败即中止（此时还没动任何数据，是最后的无损放弃点）。
fn preflight_switch(store_data: &Store, id: &str) -> Result<Vec<String>, String> {
    let mut notes = Vec::new();

    let profile = store_data
        .profiles
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| "找不到这个账号快照".to_string())?;

    // 1. 目标快照的加密凭据必须现在就能解开——切到一半才发现密钥丢失，
    //    会留下「JSON 已换、凭据没换」的错配态。
    if let Some(encrypted) = profile.keychain_password.as_deref() {
        if encrypted.starts_with(store::ENC_PREFIX) {
            store::decrypt_secret(encrypted).map_err(|e| {
                format!("预检失败：目标快照的凭据无法解密（{e}）。请先恢复 store 加密密钥再切换")
            })?;
        }
    }

    // 2. 凭据文件目录可写（实际写入在事务内，这里只探目录）。
    let claude_dir = credentials::claude_dir()?;
    if !claude_dir.exists() {
        fs::create_dir_all(&claude_dir).map_err(|e| format!("预检失败：无法创建配置目录: {e}"))?;
    }
    let probe = claude_dir.join(".claude-switcher-write-probe");
    fs::write(&probe, b"probe").map_err(|e| format!("预检失败：配置目录不可写: {e}"))?;
    let _ = fs::remove_file(&probe);

    // 3. Claude Code 在跑只是提示（切换仍允许，重启后生效），
    //    放在 warnings 而不是阻断——用户可能就是想切完再重启。
    if processes::claude_code_running() {
        notes.push(
            "检测到 Claude Code 仍在运行，切换不会作用于已运行的会话，请切换后重启 Claude Code"
                .to_string(),
        );
    }

    Ok(notes)
}

// ───────────────────────── 工具函数 ─────────────────────────

/// 把会阻塞的工作丢进 `spawn_blocking`，命令本体保持 `async`。
///
/// Tauri 2 中非 `async` 命令跑在主线程上：里面任何阻塞调用（网络请求、
/// 进程扫描、文件锁退避重试）都会让窗口卡成"未响应"。统一走这个包装，
/// 不再逐个命令手写 `.await.map_err(...)`。
///
/// **不要用 `#[tauri::command(async)]` 直接包同步函数**：那会跑在 tokio 工作线程里，
/// 其中调用 `reqwest::blocking` 有 panic 风险。
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("后台任务失败: {e}"))?
}

/// 当前平台（前端替代已弃用的 navigator.platform）。本产品只面向 Windows。
#[tauri::command]
fn get_platform() -> &'static str {
    "windows"
}

/// F-7：获取用户默认 UI 语言（多语言默认跟随系统）。
#[tauri::command]
fn get_system_language() -> String {
    platform::imp::user_default_ui_language()
}

/// 应用内版本检查（GitHub Releases latest）。网络请求，走 blocking 壳。
/// 失败静默返回说明文本，不弹错、不阻塞主线程。
#[tauri::command]
async fn check_for_update() -> Result<update::UpdateCheckResult, String> {
    blocking(|| Ok(update::check_for_update_blocking())).await
}

/// 快照加密导出（Argon2id + AES-GCM，单文件 CSBK1）。口令 ≥8 位。
#[tauri::command]
async fn export_store_encrypted(
    dest: String,
    password: String,
) -> Result<export::ExportResult, String> {
    blocking(move || {
        export::export_store_encrypted_blocking(PathBuf::from(dest).as_path(), &password)
    })
    .await
}

/// 快照加密导入：口令解密 + 校验 store 形状 + 原子替换（先备份现有 store）。
#[tauri::command]
async fn import_store_encrypted(
    src: String,
    password: String,
) -> Result<export::ImportResult, String> {
    blocking(move || {
        export::import_store_encrypted_blocking(PathBuf::from(src).as_path(), &password)
    })
    .await
}

// ───────────────────────── 状态 ─────────────────────────

/// Tauri 2 中非 async 命令跑在主线程上。`get_status` 里有 OAuth profile 请求
/// （最长数秒）、凭据存储读取和目录遍历，网络不好时会把窗口卡成"未响应"。
/// 因此对外暴露 async 壳，实际工作丢进 `spawn_blocking`。
///
/// 注意：不要用 `#[tauri::command(async)]` 直接包同步函数——那会跑在 tokio 工作线程里，
/// 其中调用 `reqwest::blocking` 有 panic 风险。
#[tauri::command]
async fn get_status() -> Result<ClaudeStatus, String> {
    blocking(|| get_status_blocking(false)).await
}

fn get_status_blocking(offline: bool) -> Result<ClaudeStatus, String> {
    p::ensure_app_dirs()?;
    let store_data = store::load_store()?;
    let claude_json = read_json_optional(p::claude_json_path()?)?;
    let settings_json = read_json_optional(p::claude_settings_path()?)?;
    let keychain = credentials::read_password()?;
    let keychain_parse_ok = keychain
        .as_ref()
        .map(|raw| serde_json::from_str::<Value>(raw).is_ok())
        .unwrap_or(false);
    let mut meta = usage::extract_meta(claude_json.as_ref(), keychain.as_deref());
    if store_data.pending_new_account.is_none() {
        fill_meta_from_saved_profile(&mut meta, &store_data);
    }
    let mut warnings = Vec::new();
    if !offline {
        let _ = usage::apply_oauth_profile(&mut meta, keychain.as_deref());
    }

    if claude_json.is_none() {
        warnings.push("没有发现 ~/.claude.json，可能尚未登录 Claude Code".to_string());
    }
    if keychain.is_none() {
        warnings.push(format!("没有发现{CREDENTIAL_STORE_LABEL}登录态"));
    }
    if keychain.is_some() && !keychain_parse_ok {
        warnings.push(format!("{CREDENTIAL_STORE_LABEL}内容存在但不是可解析 JSON"));
    }
    let auth_envs = store::AUTH_ENV_KEYS
        .iter()
        .filter(|key| std::env::var_os(key).is_some())
        .copied()
        .collect::<Vec<_>>();
    if !auth_envs.is_empty() {
        warnings.push(format!(
            "检测到认证环境变量 {}，Claude Code 可能会忽略已保存的 OAuth，切号可能对当前环境无效",
            auth_envs.join(", ")
        ));
    }
    if accounts::settings_has_api_key_helper() {
        warnings.push(
            "~/.claude/settings.json 含 apiKeyHelper 字段，会覆盖已保存的 OAuth，切号可能无效"
                .to_string(),
        );
    }
    // 提示 CLAUDE_CONFIG_DIR 已被跟随（避免「为什么路径不在 ~/.claude」的困惑）。
    if std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(|v| !v.to_string_lossy().trim().is_empty())
        .unwrap_or(false)
    {
        warnings.push(format!(
            "已跟随 CLAUDE_CONFIG_DIR（配置目录：{}）",
            credentials::claude_dir()?.to_string_lossy()
        ));
    }

    let current_profile_id_ref = store_data.current_profile_id.as_deref();
    let session_isolation = isolation::session_isolation_status(current_profile_id_ref)?;
    if store_data.current_profile_id.is_some()
        && store_data.pending_new_account.is_none()
        && !session_isolation.enabled
    {
        warnings.push(
            "Claude session 隔离未激活；切换一次当前账号或重新捕获账号后会自动接管 ~/.claude/projects"
                .to_string(),
        );
    }

    // 残留的切换事务日志 = 上次切换中断；提示用户用备份回滚。
    let pending_switch = read_switch_journal();
    if let Some(journal) = &pending_switch {
        warnings.push(format!(
            "检测到上次切换未完成（目标 {}，步骤 {}）——可用「备份与恢复」回滚到切换前备份",
            journal.target_id.chars().take(8).collect::<String>(),
            journal.step
        ));
    }

    Ok(ClaudeStatus {
        claude_json_exists: p::claude_json_path()?.exists(),
        settings_json_exists: settings_json.is_some(),
        credentials_json_exists: credentials_file_probe(),
        keychain_exists: keychain.is_some(),
        keychain_parse_ok,
        meta,
        claude_json_path: p::claude_json_path()?.to_string_lossy().to_string(),
        settings_json_path: p::claude_settings_path()?.to_string_lossy().to_string(),
        data_dir: p::app_data_dir()?.to_string_lossy().to_string(),
        backup_dir: p::backups_dir()?.to_string_lossy().to_string(),
        session_isolation,
        profile_count: store_data.profiles.len(),
        current_profile_name: store_data
            .current_profile_id
            .as_deref()
            .and_then(|id| store_data.profiles.iter().find(|profile| profile.id == id))
            .map(|profile| profile.name.clone()),
        pending_new_account: store_data.pending_new_account.clone(),
        current_profile_id: store_data.current_profile_id,
        telemetry_mode: store_data.telemetry_mode,
        pending_switch,
        warnings,
    })
}

/// 凭据文件存在性探测（Windows 主存储 `.credentials.json`）。
fn credentials_file_probe() -> bool {
    credentials::credentials_path()
        .map(|path| path.exists())
        .unwrap_or(false)
}

fn fill_meta_from_saved_profile(meta: &mut store::ProfileMeta, store_data: &Store) {
    let Some(current_id) = store_data.current_profile_id.as_deref() else {
        return;
    };
    let Some(profile) = store_data
        .profiles
        .iter()
        .find(|item| item.id == current_id)
    else {
        return;
    };
    if meta.email.is_none() {
        meta.email = profile.meta.email.clone();
    }
    if meta.account_uuid.is_none() {
        meta.account_uuid = profile.meta.account_uuid.clone();
    }
    if meta.organization_uuid.is_none() {
        meta.organization_uuid = profile.meta.organization_uuid.clone();
    }
    if meta.organization_name.is_none() {
        meta.organization_name = profile.meta.organization_name.clone();
    }
    if meta.subscription_type.is_none() {
        meta.subscription_type = profile.meta.subscription_type.clone();
    }
    if meta.rate_limit_tier.is_none() {
        meta.rate_limit_tier = profile.meta.rate_limit_tier.clone();
    }
}

// ───────────────────────── 遥测模式 ─────────────────────────

#[tauri::command]
fn set_telemetry_mode(mode: String) -> Result<(), String> {
    let parsed = match mode.trim() {
        "default" => TelemetryMode::Default,
        "disableTelemetry" => TelemetryMode::DisableTelemetry,
        "essentialOnly" => TelemetryMode::EssentialOnly,
        other => {
            return Err(format!(
                "非法的遥测模式「{other}」，只接受 default / disableTelemetry / essentialOnly"
            ))
        }
    };

    // H-2：账号库读—改—写走 with_store 互斥；外部 settings 写入在锁外执行。
    let runtime = store::with_store(|store_data| {
        store_data.telemetry_mode = parsed;
        Ok(store_data
            .pending_new_account
            .as_ref()
            .map(|pending| pending.runtime.clone())
            .or_else(|| {
                store_data.current_profile_id.as_deref().and_then(|id| {
                    store_data
                        .profiles
                        .iter()
                        .find(|profile| profile.id == id)
                        .and_then(|profile| profile.runtime.clone())
                })
            }))
    })?;
    accounts::apply_profile_env_to_settings(parsed, runtime.as_ref())
}

// ───────────────────────── 账号列表 / 捕获 ─────────────────────────

#[tauri::command]
fn list_profiles() -> Result<Vec<ProfileSummary>, String> {
    let store_data = store::load_store()?;
    Ok(store_data
        .profiles
        .iter()
        .map(|prof| profile_summary_of(prof, store_data.current_profile_id.as_deref()))
        .collect())
}

fn profile_summary_of(profile: &StoredProfile, current_id: Option<&str>) -> ProfileSummary {
    ProfileSummary {
        id: profile.id.clone(),
        name: profile.name.clone(),
        notes: profile.notes.clone(),
        created_at: profile.created_at,
        updated_at: profile.updated_at,
        last_switched_at: profile.last_switched_at,
        meta: profile.meta.clone(),
        clash: profile.clash.clone(),
        runtime: profile.runtime.clone(),
        token_status: profile
            .keychain_password
            .as_deref()
            .map(token_status::token_status_from_blob),
        is_current: current_id == Some(profile.id.as_str()),
    }
}

#[tauri::command]
async fn capture_current_profile(
    name: String,
    notes: Option<String>,
) -> Result<ProfileSummary, String> {
    blocking(move || capture_current_profile_blocking(name, notes)).await
}

fn capture_current_profile_blocking(
    name: String,
    notes: Option<String>,
) -> Result<ProfileSummary, String> {
    let clean_name = name.trim();
    if clean_name.is_empty() {
        return Err("账号名称不能为空".to_string());
    }
    let (claude_json, settings_json, keychain_password) = accounts::current_snapshot()?;
    let claude_json =
        claude_json.ok_or_else(|| "当前没有 ~/.claude.json，无法创建账号快照".to_string())?;
    if keychain_password.is_none() {
        return Err(format!(
            "当前没有{CREDENTIAL_STORE_LABEL}登录态，无法创建完整快照"
        ));
    }

    let now = Utc::now();
    let runtime = store::default_runtime_for_profile(clean_name, None);
    let profile = StoredProfile {
        id: uuid::Uuid::new_v4().to_string(),
        name: clean_name.to_string(),
        notes,
        created_at: now,
        updated_at: now,
        last_switched_at: None,
        meta: usage::extract_meta(Some(&claude_json), keychain_password.as_deref()),
        claude_json,
        settings_json,
        encrypted_auth_settings: None,
        keychain_password,
        last_used_percent: None,
        clash: None,
        runtime: Some(runtime),
    };
    let summary = profile_summary_of(&profile, Some(""));
    let profile_id = profile.id.clone();
    // H-2：账号库读—改—写走 with_store；隔离链接在锁外 best-effort。
    // 先把 profile 落进 store，再改 live 隔离链接：链接操作随时可能因
    // Windows 文件锁失败，但快照本身已完整保存——失败不再回滚 store
    // （回滚会让 live 链接指向 store 里已不存在的 profile，反而更乱），
    // 只记日志；UI 的 session_isolation 状态会提示"隔离未激活"，
    // 用户重新执行一次"切换"即可补上链接。
    store::with_store(|store_data| {
        store_data.current_profile_id = Some(profile_id.clone());
        // 捕获新账号后必须清缓存：OAuth/本地用量缓存里可能还留着上一个账号的数据
        // （token 指纹能防串号，但 projects 目录也换了，本地统计必须重算）。
        usage::clear_caches();
        store_data.profiles.push(profile);
        Ok(())
    })?;
    if let Err(e) = isolation::adopt_live_claude_local_state_for_profile(&profile_id)
        .and_then(|_| isolation::activate_profile_claude_local_state(&profile_id))
    {
        log_error(&format!("账号快照已保存，但本地状态接管失败: {e}"));
    }
    Ok(summary)
}

// ───────────────────────── 新号向导 ─────────────────────────

/// 新号向导里有阻塞操作（`kill_claude_code_processes` 含等待、Clash 切换与
/// 节点健康检查、链接重试），必须离开主线程。
#[tauri::command]
async fn prepare_new_account_login(
    name: String,
    notes: Option<String>,
    node: String,
    timezone: Option<String>,
    locale: Option<String>,
    chrome_profile: Option<String>,
) -> Result<PrepareNewAccountResult, String> {
    blocking(move || {
        prepare_new_account_login_blocking(name, notes, node, timezone, locale, chrome_profile)
    })
    .await
}

#[allow(clippy::too_many_arguments)]
fn prepare_new_account_login_blocking(
    name: String,
    notes: Option<String>,
    node: String,
    timezone: Option<String>,
    locale: Option<String>,
    chrome_profile: Option<String>,
) -> Result<PrepareNewAccountResult, String> {
    let clean_name = name.trim();
    if clean_name.is_empty() {
        return Err("新账号名称不能为空".to_string());
    }
    let clean_node = node.trim();
    if clean_node.is_empty() {
        return Err("必须选择新账号绑定的 Clash 节点".to_string());
    }

    // H-2：新号准备是一次账号库事务，读—改—写全程持 with_store 锁。
    store::with_store(|store_data| {
        let mut warnings = Vec::new();
        if store_data.pending_new_account.is_some() {
            return Err("已有待完成的新号登录流程，请先完成保存或切回旧账号重新开始".to_string());
        }
        warnings.extend(processes::kill_claude_code_processes()?);

        let backup = create_backup_with_label("before-new-account-login")?;
        // K-3：开新号向导前先清供应商 env，避免供应商的键被写进 OAuth 账号快照。
        provider::clear_active_provider_env(store_data)?;
        warnings.extend(refresh_current_profile_snapshot(
            store_data,
            "__new_account_login__",
        ));
        if let Some(current_id) = store_data.current_profile_id.as_deref() {
            warnings.extend(isolation::adopt_live_claude_local_state_for_profile(
                current_id,
            )?);
        }

        let (_, settings_json, _) = accounts::current_snapshot()?;
        let rollback_from = load_backup_snapshot(&backup.path)?;
        let clash_result = clash::switch_clash_node_internal(DEFAULT_CLASH_GROUP, clean_node)?;
        if !clash_result.verified {
            return Err(format!(
                "Auto-Claude 切换到「{clean_node}」未被 Clash 确认，已停止准备新号。"
            ));
        }
        clash::assert_clash_node_ready(DEFAULT_CLASH_GROUP, clean_node)?;
        let mut runtime = store::default_runtime_for_profile(clean_name, Some(clean_node));
        if timezone
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
        {
            runtime.timezone = timezone.map(|value| value.trim().to_string());
        }
        if locale
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
        {
            runtime.locale = locale.map(|value| value.trim().to_string());
        }
        if chrome_profile
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
        {
            runtime.chrome_profile = chrome_profile.map(|value| value.trim().to_string());
        }

        let pending = PendingNewAccount {
            id: format!("pending-{}", uuid::Uuid::new_v4()),
            name: clean_name.to_string(),
            notes,
            group: DEFAULT_CLASH_GROUP.to_string(),
            node: clean_node.to_string(),
            runtime,
            created_at: Utc::now(),
        };
        accounts::clean_live_account_for_new_login(settings_json, &rollback_from)?;
        // 顺序关键：先保存 pending，再激活隔离链接。
        // 旧顺序是「activate 失败就 Err、pending 尚未保存」——而此刻凭据已被清空、
        // Clash 已切换，一旦 activate 失败（Windows 文件锁很常见），用户既没有
        // pending 记录可取消切回，也无从重试，陷入"登录态已清空"的死局。
        // 先落 pending 保证「取消切回」始终可用；activate 失败降级为 warning。
        store_data.pending_new_account = Some(pending.clone());
        // with_store 在闭包返回 Ok 后统一 save，这里不再显式 save。
        match isolation::activate_profile_claude_local_state(&pending.id) {
            Ok(items) => warnings.extend(items),
            Err(e) => warnings.push(format!(
                "新号隔离目录激活失败（不影响登录，可重新执行一次切换恢复）：{e}"
            )),
        }
        if let Err(e) = accounts::apply_profile_env_to_settings(
            store_data.telemetry_mode,
            Some(&pending.runtime),
        ) {
            warnings.push(format!(
                "隐私 env 注入失败（可在设置里重选遥测模式重试）：{e}"
            ));
        }
        // 新号流程已清空当前账号并换到全新的日志目录，旧账号缓存不能继续显示。
        usage::clear_caches();
        Ok(PrepareNewAccountResult {
            pending,
            backup,
            clash: clash_result,
            warnings,
        })
    })
}

#[tauri::command]
async fn complete_new_account_login() -> Result<ProfileSummary, String> {
    blocking(complete_new_account_login_blocking).await
}

fn complete_new_account_login_blocking() -> Result<ProfileSummary, String> {
    // H-2：读—改—写走 with_store。
    let result = store::with_store(|store_data| {
        let pending = store_data
            .pending_new_account
            .clone()
            .ok_or_else(|| "没有待完成的新号登录流程".to_string())?;
        let (claude_json, settings_json, keychain_password) = accounts::current_snapshot()?;
        let claude_json = claude_json.ok_or_else(|| {
            "当前没有 ~/.claude.json，请先手动完成 Claude Code OAuth 登录".to_string()
        })?;
        let keychain_password = keychain_password.ok_or_else(|| {
            format!("当前没有{CREDENTIAL_STORE_LABEL}登录态，请先完成 Claude OAuth 登录")
        })?;

        if store_data
            .profiles
            .iter()
            .any(|profile| profile.id == pending.id)
        {
            return Err("这个待完成账号已经保存过".to_string());
        }
        let now = Utc::now();
        let profile = StoredProfile {
            id: pending.id.clone(),
            name: pending.name.clone(),
            notes: pending.notes.clone(),
            created_at: pending.created_at,
            updated_at: now,
            last_switched_at: Some(now),
            meta: usage::extract_meta(Some(&claude_json), Some(&keychain_password)),
            claude_json,
            settings_json,
            encrypted_auth_settings: None,
            keychain_password: Some(keychain_password),
            last_used_percent: None,
            clash: Some(store::ProfileClashBinding {
                enabled: true,
                group: pending.group.clone(),
                node: pending.node.clone(),
            }),
            runtime: Some(pending.runtime.clone()),
        };
        let summary = profile_summary_of(&profile, Some(""));
        // 链接激活失败不阻断保存：登录态已就绪是用户关心的结果，
        // 链接未激活会由 get_status 的 session_isolation 状态显示，重新切换一次即可补上。
        if let Err(e) = isolation::activate_profile_claude_local_state(&profile.id) {
            log_error(&format!("新号隔离链接激活失败（已保存登录态）: {e}"));
        }
        store_data.current_profile_id = Some(profile.id.clone());
        // 新号登录完成 = 账号已变，缓存全部作废（否则用量/套餐显示的还是旧账号）。
        usage::clear_caches();
        store_data.pending_new_account = None;
        store_data.profiles.push(profile);
        // with_store 在闭包返回 Ok 后统一 save。
        Ok(summary)
    });
    // F-2：新账号落库成功后重建开始菜单快捷方式（best-effort，不阻断主流程）。
    if result.is_ok() {
        if let Err(e) = shortcuts::sync_all_shortcuts() {
            log_error(&format!("同步开始菜单快捷方式失败: {e}"));
        }
    }
    result
}

/// 内部会触发一次完整切号（含进程结束等待、Clash 请求、链接重试），
/// 因此和 switch_profile 一样走 spawn_blocking。
#[tauri::command]
async fn cancel_pending_new_account_login() -> Result<Option<SwitchResult>, String> {
    blocking(cancel_pending_new_account_login_blocking).await
}

fn cancel_pending_new_account_login_blocking() -> Result<Option<SwitchResult>, String> {
    // 只读检查（不持锁）：确认有 pending、取当前账号 id。
    let store_data = store::load_store()?;
    if store_data.pending_new_account.is_none() {
        return Err("没有待取消的新号登录流程".to_string());
    }
    let current_id = store_data.current_profile_id.clone();

    // 先尝试切回旧账号；切换失败时保留 pending，让用户可以重试取消。
    if let Some(id) = current_id {
        // 切回旧账号：switch 内部自己获取/释放 with_store，这里不能预先持锁
        // （std Mutex 不可重入，会自死锁）。
        match switch_profile_blocking(id) {
            Ok(result) => {
                // 切换成功后，窄临界区清 pending。
                store::with_store(|after| {
                    after.pending_new_account = None;
                    Ok(())
                })?;
                return Ok(Some(result));
            }
            Err(e) => {
                return Err(format!(
                    "切回旧账号失败，新号流程仍保留（可修正后重试）：{e}"
                ))
            }
        }
    }

    // 没有旧账号可切：窄临界区清 pending（H-2 走 with_store）。
    store::with_store(|data| {
        data.pending_new_account = None;
        Ok(())
    })?;
    Ok(None)
}

// ───────────────────────── 切换 ─────────────────────────

/// 切换前 best-effort 回写「当前活账号」的 live 快照到它对应的 profile。
/// 快照不完整或身份不匹配时跳过并 warn，绝不阻断切号。
/// 切换 / 新号登录前：读取 live 快照并做身份对账（Current / Other / Unknown），
/// 把 live 状态回写到正确的账号，必要时自动收养。详见 [`reconcile`]。
fn refresh_current_profile_snapshot(store_data: &mut Store, _target_id: &str) -> Vec<String> {
    match accounts::current_snapshot() {
        Ok(snapshot) => reconcile::reconcile_live_into_store(
            store_data,
            &snapshot,
            crate::appconfig::load().auto_adopt_enabled,
            Utc::now(),
        ),
        Err(err) => vec![format!(
            "未能读取当前 live 快照，已跳过对账（不中断切换）：{err}"
        )],
    }
}

/// 切号流程里有阻塞操作（杀进程等待约 1.2s、Clash 切换 250ms sleep、
/// 链接操作最多 1.3s 退避重试、Clash 请求最长 8s），必须离开主线程，
/// 否则窗口会卡成"未响应"、托盘事件也会被拖住。
#[tauri::command]
async fn switch_profile(id: String) -> Result<SwitchResult, String> {
    blocking(move || switch_profile_blocking(id)).await
}

/// 并行模式：为指定账号开一个独立终端（CLAUDE_CONFIG_DIR 隔离），
/// 与「全局切换」互不影响。阻塞（写文件 + 拉起终端），走 blocking。
#[tauri::command]
async fn open_parallel_terminal(id: String) -> Result<parallel::ParallelTerminalResult, String> {
    blocking(move || parallel::open_parallel_terminal_for_profile(&id)).await
}

/// 列出 MCP 服务器（scope: "global" | "project"）。
#[tauri::command]
async fn list_mcp_servers(
    scope: String,
    project_dir: Option<String>,
) -> Result<serde_json::Value, String> {
    blocking(move || {
        let scope = parse_mcp_scope(&scope);
        mcp::list_mcp_servers(scope, project_dir.as_deref())
    })
    .await
}

/// 新增 / 更新 MCP 服务器。
#[tauri::command]
async fn upsert_mcp_server(
    scope: String,
    project_dir: Option<String>,
    name: String,
    server: serde_json::Value,
) -> Result<(), String> {
    blocking(move || {
        let scope = parse_mcp_scope(&scope);
        mcp::upsert_mcp_server(scope, project_dir.as_deref(), &name, server)
    })
    .await
}

/// 删除 MCP 服务器。
#[tauri::command]
async fn delete_mcp_server(
    scope: String,
    project_dir: Option<String>,
    name: String,
) -> Result<bool, String> {
    blocking(move || {
        let scope = parse_mcp_scope(&scope);
        mcp::delete_mcp_server(scope, project_dir.as_deref(), &name)
    })
    .await
}

fn parse_mcp_scope(scope: &str) -> mcp::McpScope {
    if scope.eq_ignore_ascii_case("project") {
        mcp::McpScope::Project
    } else {
        mcp::McpScope::Global
    }
}

/// P2-1：查询阈值提醒（当前用量 + 推荐切换账号）。
#[tauri::command]
async fn get_quota_reminder() -> Result<usage::QuotaReminder, String> {
    blocking(usage::quota_reminder_blocking).await
}

/// P2-1：设置阈值提醒开关与阈值（默认关闭）。
#[tauri::command]
async fn set_quota_reminder(enabled: bool, threshold: u8) -> Result<appconfig::AppConfig, String> {
    blocking(move || {
        appconfig::update(|cfg| {
            cfg.quota_reminder_enabled = enabled;
            if (1..=100).contains(&threshold) {
                cfg.quota_reminder_threshold = threshold;
            }
        })
    })
    .await
}

/// H-6：设置「检测到未登记账号时自动收养」开关（默认开启）。
#[tauri::command]
async fn set_auto_adopt(enabled: bool) -> Result<appconfig::AppConfig, String> {
    blocking(move || appconfig::update(|cfg| cfg.auto_adopt_enabled = enabled)).await
}

fn switch_profile_blocking(id: String) -> Result<SwitchResult, String> {
    // H-2：整个切换是一次账号库事务，读—改—写全程持 with_store 锁。
    // 内部调用（preflight/backup/reconcile/clash/accounts/isolation/keep）均不获取
    // STORE_LOCK，无重入死锁；只读路径（read_lightweight/load_store）不持锁。
    store::with_store(|store_data| {
        if !store_data.profiles.iter().any(|p| p.id == id) {
            return Err("找不到这个账号快照".to_string());
        }
        // F-5：切回 OAuth 账号前，先清掉当前供应商写入的受管 env（若有），避免供应商
        // 认证键与 OAuth 材料并存。清不掉不阻断（OAuth 材料仍会落盘），仅记录日志。
        if let Err(e) = provider::clear_active_provider_env(store_data) {
            log_error(&format!("清理供应商 env 失败（不阻断切换）: {e}"));
        }
        // 预检：目标快照可解密 / 配置目录可写 / Claude Code 在跑只提示。
        // 通过后才开始动数据（此后每步都有备份/日志可回滚）。
        let mut warnings = preflight_switch(store_data, &id)?;

        // J-3 同步点：全局切换到该账号之前，先扫描并行目录里已刷新的凭据并回写
        // （仅 mtime 晚于 updated_at，身份不一致拒绝回写）。复用已借用的 store，
        // 不嵌套取锁。
        warnings.extend(parallel::scan_parallel_credential_changes_into(store_data));

        let backup = create_backup_with_label(&format!("before-switch-to-{id}"))?;
        // 切换事务日志：从「备份已建」起记录——此刻备份是回滚点，
        // 之后任何中断都能按 backup_id 恢复。备份失败则什么都没改，不需要日志。
        write_switch_journal(&SwitchJournal {
            target_id: id.clone(),
            step: "backup-created".to_string(),
            backup_id: Some(backup.id.clone()),
            started_at: Utc::now(),
        });
        // 跨身份保留：切换前把 keep-in-workspace.txt 列出的相对路径收进暂存（默认关闭）。
        // 与上游一致：暂存失败（含上次还原残留的唯一副本）直接中止切换，不覆盖。
        let keep_base = credentials::claude_dir()?;
        let keep_report = keep::stage_keep(&keep_base)?;
        if keep_report.count > 0 {
            warnings.push(format!("跨身份保留：已暂存 {} 项", keep_report.count));
        }
        warnings.extend(
            keep_report
                .warnings
                .into_iter()
                .map(|w| format!("跨身份保留：{w}")),
        );

        warnings.extend(refresh_current_profile_snapshot(store_data, &id));
        if let Some(current_id) = store_data.current_profile_id.as_deref() {
            warnings.extend(isolation::adopt_live_claude_local_state_for_profile(
                current_id,
            )?);
        }
        let idx = store_data
            .profiles
            .iter()
            .position(|p| p.id == id)
            .ok_or_else(|| "找不到这个账号快照".to_string())?;
        let profile = store_data.profiles[idx].clone();

        let rollback_from = load_backup_snapshot(&backup.path)?;
        accounts::apply_account_material(
            accounts::WriteMode::Merge,
            Some(&profile.claude_json),
            profile.settings_json.as_ref(),
            profile.keychain_password.as_deref(),
            &rollback_from,
        )?;

        if let Err(e) = accounts::apply_profile_env_to_settings(
            store_data.telemetry_mode,
            profile.runtime.as_ref(),
        ) {
            warnings.push(format!(
                "隐私 env 注入失败（可在设置里重选遥测模式重试）：{e}"
            ));
        }
        // J-2：Clash 节点切换必须放在账号材料应用成功之后。旧代码在材料应用前就切节点，
        // 一旦材料应用失败，节点已被切走、账号却没切，留下错误的网络出口。
        // 此刻材料已落盘，若 Clash 切换失败按 warning 处理（不能返回 Err 让 UI 显示
        // 「切换失败」而磁盘其实已切，与 activate/keep 失败同一处理原则）。
        let clash_result = if let Some(binding) = &profile.clash {
            if binding.enabled {
                match clash::switch_clash_node_internal(&binding.group, &binding.node) {
                    Ok(result) => Some(result),
                    Err(e) => {
                        warnings.push(format!(
                            "Clash 节点切换失败（账号材料已切换成功，可在网络恢复后手动切换节点）：{e}"
                        ));
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };
        // 关键：activate 失败不能阻断切号——此刻账号材料（凭据/JSON）已成功切到新账号，
        // 若因 Windows 文件锁导致链接激活失败而返回 Err，前端会显示"切换失败"，
        // 但磁盘上其实已经切过去了（UI 与实际状态相反）。降级为 warning，
        // 用户按提示重新执行一次"切换"即可补上链接。
        let mut link_mode = String::new();
        match isolation::activate_profile_claude_local_state(&profile.id) {
            Ok(items) => {
                warnings.extend(items);
                link_mode = isolation::session_isolation_status(Some(&profile.id))
                    .map(|s| s.link_mode)
                    .unwrap_or_default();
            }
            Err(e) => warnings.push(format!(
                "session 隔离链接激活失败（账号材料已切换成功，重新执行一次切换可补上）：{e}"
            )),
        }
        // 跨身份保留：把暂存文件合并回新账号目录。此刻账号材料已切成功，合并失败不回滚
        // （否则 UI 显示失败、磁盘已切，状态相反），保留暂存并提示手动恢复。
        match keep::merge_keep(&keep_base) {
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
        // 记录切号结果与链接模式：排障时最需要的两条信息。
        // 账号名只记 id 前 8 位（隐私：日志可能被用户直接贴给别人排障）。
        // 用 chars().take() 而不是字节切片，id 含非 ASCII 时不会 panic。
        log_info(&format!(
            "切号成功 → {}（链接模式：{}，Clash：{}）",
            profile.id.chars().take(8).collect::<String>(),
            if link_mode.is_empty() {
                "未激活"
            } else {
                &link_mode
            },
            clash_result
                .as_ref()
                .map(|c| format!(
                    "{}（{}）",
                    c.node,
                    if c.verified { "已确认" } else { "未确认" }
                ))
                .unwrap_or_else(|| "未绑定".to_string())
        ));

        store_data.current_profile_id = Some(profile.id.clone());
        // 切号成功 = 账号已变，立即作废全部缓存。
        // token 指纹能防「拿新 token 查到旧账号」，但 projects 目录也换了，
        // 本地用量统计（45s 缓存）同样必须重算——不清就会显示旧账号的用量。
        usage::clear_caches();
        store_data.profiles[idx].last_switched_at = Some(Utc::now());
        store_data.profiles[idx].updated_at = Utc::now();
        // with_store 在闭包返回 Ok 后统一 save，这里不再显式 save。
        // 事务正常完成：清掉切换日志（残留日志 = 上次切换中断的信号）。
        clear_switch_journal();

        Ok(SwitchResult {
            switched_to: profile.name,
            backup,
            clash: clash_result,
            restart_hint: format!(
                "切换已写入磁盘和{CREDENTIAL_STORE_LABEL}；请重启正在运行的 Claude Code 会话。"
            ),
            warnings,
        })
    })
}

// ───────────────────────── Clash ─────────────────────────

/// 探测默认控制器（每端口最长 1 秒）+ 请求最长 8 秒，跑在主线程会卡 UI，
/// 故同样走 spawn_blocking。
#[tauri::command]
async fn get_clash_status() -> Result<clash::ClashStatus, String> {
    blocking(|| Ok(clash::clash_status_for_group(DEFAULT_CLASH_GROUP))).await
}

#[tauri::command]
async fn get_claude_usage() -> Result<usage::ClaudeUsageSnapshot, String> {
    blocking(usage::claude_usage_snapshot).await
}

/// 直接发 Clash 请求（最长 8 秒），走 blocking 避免卡主线程。
#[tauri::command]
async fn switch_clash_node(
    group: String,
    node: String,
) -> Result<clash::ClashSwitchResult, String> {
    blocking(move || clash::switch_clash_node_internal(group.trim(), node.trim())).await
}

/// 同上：内部是一次 Clash 请求。
#[tauri::command]
async fn switch_profile_clash_node(id: String) -> Result<clash::ClashSwitchResult, String> {
    blocking(move || switch_profile_clash_node_blocking(id)).await
}

fn switch_profile_clash_node_blocking(id: String) -> Result<clash::ClashSwitchResult, String> {
    let store_data = store::load_store()?;
    let profile = store_data
        .profiles
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| "找不到这个账号快照".to_string())?;
    let binding = profile
        .clash
        .as_ref()
        .ok_or_else(|| "这个账号还没有绑定 Clash 节点".to_string())?;
    if !binding.enabled {
        return Err("这个账号的 Clash 绑定未启用".to_string());
    }
    clash::switch_clash_node_internal(&binding.group, &binding.node)
}

#[tauri::command]
fn set_profile_clash_binding(
    id: String,
    enabled: bool,
    group: String,
    node: String,
) -> Result<(), String> {
    // H-2：读—改—写走 with_store；校验失败返回 Err 时不保存。
    store::with_store(|store_data| {
        let profile = store_data
            .profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| "找不到这个账号快照".to_string())?;
        let group = group.trim();
        let node = node.trim();
        if enabled {
            if group.is_empty() {
                return Err("Clash 组不能为空".to_string());
            }
            if node.is_empty() {
                return Err("Clash 节点不能为空".to_string());
            }
            profile.clash = Some(store::ProfileClashBinding {
                enabled,
                group: group.to_string(),
                node: node.to_string(),
            });
        } else {
            profile.clash = None;
        }
        profile.updated_at = Utc::now();
        Ok(())
    })
}

#[tauri::command]
fn set_profile_runtime_binding(
    id: String,
    timezone: Option<String>,
    locale: Option<String>,
    chrome_profile: Option<String>,
) -> Result<(), String> {
    let runtime = store::ProfileRuntimeBinding {
        timezone: timezone
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        locale: locale
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        chrome_profile: chrome_profile
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
    };
    // H-2：读—改—写走 with_store；外部 settings 写入在锁外执行。
    let (current, telemetry_mode) = store::with_store(|store_data| {
        let current = store_data.current_profile_id.as_deref() == Some(id.as_str());
        let telemetry_mode = store_data.telemetry_mode;
        let profile = store_data
            .profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| "找不到这个账号快照".to_string())?;
        profile.runtime = Some(runtime.clone());
        profile.updated_at = Utc::now();
        Ok((current, telemetry_mode))
    })?;
    if current {
        accounts::apply_profile_env_to_settings(telemetry_mode, Some(&runtime))?;
    }
    Ok(())
}

#[tauri::command]
async fn delete_profile(id: String, delete_sessions: Option<bool>) -> Result<(), String> {
    blocking(move || delete_profile_blocking(id, delete_sessions.unwrap_or(false))).await
}

fn delete_profile_blocking(id: String, delete_sessions: bool) -> Result<(), String> {
    // 只读预检（不持锁）：确认账号存在、是否当前。
    let (profiles_meta, current_id) = store::read_lightweight()?;
    if !profiles_meta.iter().any(|p| p.id == id) {
        return Err("找不到这个账号快照".to_string());
    }
    let was_current = current_id.as_deref() == Some(id.as_str());

    // ── 预检：删会话历史是有破坏性的多步操作，先确认前提再动任何东西 ──
    // 顺序：先预检 → 取消链接 → 删目录 → 删快照。
    // 反过来（先删快照）会出现「快照已删、会话没删成」的半完成状态。
    let sessions_dir = p::session_profiles_dir()?.join(&id);
    let has_sessions = delete_sessions && sessions_dir.exists();
    if has_sessions {
        if processes::claude_code_running() {
            return Err(
                "Claude Code 正在运行，无法安全删除会话历史（目录里的文件被占用，\
                 Windows 上会删一半失败并留下半截目录）。请先退出 Claude Code 再试。"
                    .to_string(),
            );
        }
        // 取消隔离链接。只删指向该账号的链接，且任一项失败即中止——
        // 失败后仍删目录会让链接悬空（原因从"误删"变成"锁文件"），不如保留现场。
        let removed = isolation::deactivate_profile(&id).map_err(|e| {
            format!("删除会话历史前取消隔离链接失败，已中止（未删除任何数据）：{e}")
        })?;
        if !removed.is_empty() {
            log_info(&format!(
                "已移除账号 {} 的隔离链接：{}",
                id.chars().take(8).collect::<String>(),
                removed.join(", ")
            ));
        }
    }

    // ── 正式删除（H-2：读—改—写走 with_store，外部链接/目录操作在锁外）──
    store::with_store(|store_data| {
        let before = store_data.profiles.len();
        store_data.profiles.retain(|p| p.id != id);
        if store_data.profiles.len() == before {
            return Err("找不到这个账号快照".to_string());
        }
        if was_current {
            store_data.current_profile_id = None;
        }
        Ok(())
    })
    // 注意：取消链接发生在此之前。若这里保存失败，live 链接已移除但
    // 快照还在——下次对该账号「切换」会重新激活链接，可接受；
    // 但错误信息要说明，否则用户会以为状态完好。
    .map_err(|e| format!("保存 store 失败（隔离链接已取消，下次切换该账号会重建）：{e}"))?;

    if has_sessions {
        fs::remove_dir_all(&sessions_dir).map_err(|e| {
            format!(
                "删除会话历史失败（快照已删除，可手动删除 {}）：{}",
                sessions_dir.to_string_lossy(),
                fsx::humanize_io_error(&e)
            )
        })?;
        log_info(&format!(
            "已删除账号 {} 的会话历史（{}）",
            id.chars().take(8).collect::<String>(),
            sessions_dir.to_string_lossy()
        ));
    }
    // F-2：删除成功后重建快捷方式（被删账号的 .lnk 随之消失）。
    if let Err(e) = shortcuts::sync_all_shortcuts() {
        log_error(&format!("同步开始菜单快捷方式失败: {e}"));
    }
    Ok(())
}

/// F-2：手动重建全部开始菜单快捷方式，返回写出数量。
#[tauri::command]
async fn rebuild_start_menu_shortcuts() -> Result<usize, String> {
    blocking(shortcuts::sync_all_shortcuts).await
}

/// K-5：是否运行于便携模式（exe 旁有 portable.flag）。便携版移动 exe 后，
/// 旧快捷方式指向的目标路径会失效，界面据此提示重新同步。
#[tauri::command]
async fn is_portable_mode() -> Result<bool, String> {
    blocking(|| Ok(paths::portable_root().is_some())).await
}

/// F-2：全部清理开始菜单快捷方式（卸载撤销）。
#[tauri::command]
async fn clear_start_menu_shortcuts() -> Result<(), String> {
    blocking(shortcuts::remove_all_shortcuts).await
}

/// F-1：把工具 bin 目录追加到用户 PATH（REG_EXPAND_SZ，幂等）。
#[tauri::command]
async fn add_to_user_path(bin_dir: String) -> Result<userpath::PathUpdateResult, String> {
    blocking(move || userpath::add_bin_to_user_path(&bin_dir)).await
}

/// F-1：从用户 PATH 移除工具 bin 目录（撤销）。
#[tauri::command]
async fn remove_from_user_path(bin_dir: String) -> Result<userpath::PathUpdateResult, String> {
    blocking(move || userpath::remove_bin_from_user_path(&bin_dir)).await
}

/// 列出工作区资产（技能/命令/子代理/CLAUDE.md）。
#[tauri::command]
async fn list_workspace_items() -> Result<Vec<workspace::WorkspaceItem>, String> {
    blocking(workspace::list_workspace_items).await
}

/// 启用/停用工作区资产（重命名实现，可逆）。
#[tauri::command]
async fn set_workspace_item_enabled(
    kind: workspace::WorkspaceKind,
    id: String,
    enabled: bool,
) -> Result<workspace::WorkspaceItem, String> {
    blocking(move || workspace::set_workspace_enabled(kind, &id, enabled)).await
}

/// 读取权限与钩子编辑器数据（含校验告警）。
#[tauri::command]
async fn read_permission_editor() -> Result<permissions::PermissionEditorData, String> {
    blocking(permissions::read_permission_editor).await
}

/// 保存权限与钩子编辑器数据（乐观并发写入）。
#[tauri::command]
async fn save_permission_editor(
    permissions: permissions::PermissionRules,
    hooks: Vec<permissions::HookEntry>,
) -> Result<(), String> {
    blocking(move || permissions::save_permission_editor(permissions, hooks)).await
}

/// F-1：为指定目录创建账号绑定标记。
#[tauri::command]
async fn bind_directory(dir: String, account_name: String) -> Result<String, String> {
    blocking(move || {
        dirbinding::write_account_marker(std::path::Path::new(&dir), &account_name)
            .map(|p| p.to_string_lossy().to_string())
    })
    .await
}

/// F-1：移除指定目录的账号绑定标记。
#[tauri::command]
async fn unbind_directory(dir: String) -> Result<(), String> {
    blocking(move || dirbinding::remove_account_marker(std::path::Path::new(&dir))).await
}

/// F-1：返回 cs.exe 所在目录（当前 exe 同目录），供 PATH 操作使用。
#[tauri::command]
fn get_tool_bin_dir() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("定位当前程序失败: {e}"))?;
    let parent = exe.parent().ok_or_else(|| "无法定位程序目录".to_string())?;
    Ok(parent.to_string_lossy().to_string())
}

/// F-5：新建第三方供应商账号（auth token 加密落盘）。
#[tauri::command]
async fn create_provider(
    name: String,
    base_url: String,
    auth_token: String,
    model_env: std::collections::BTreeMap<String, String>,
) -> Result<store::ProviderProfile, String> {
    blocking(move || provider::create_provider_blocking(name, base_url, auth_token, model_env))
        .await
}

/// F-5/K-3：列出全部供应商视图（不含加密令牌）。
#[tauri::command]
async fn list_providers() -> Result<Vec<provider::ProviderView>, String> {
    blocking(provider::list_providers_blocking).await
}

/// F-5：删除供应商（当前生效则先清受管 env）。
#[tauri::command]
async fn delete_provider(id: String) -> Result<(), String> {
    blocking(move || provider::delete_provider_blocking(id)).await
}

/// F-5：切换到供应商（先删旧键再写新键）。
#[tauri::command]
async fn switch_to_provider(id: String) -> Result<(), String> {
    blocking(move || provider::switch_to_provider_blocking(id)).await
}

/// F-5：连通性测试（5 秒超时，不回显令牌）。
#[tauri::command]
async fn test_provider_connection(base_url: String) -> Result<String, String> {
    blocking(move || provider::test_provider_connection(base_url)).await
}

/// F-5：当前生效供应商 id（无则 null）。
#[tauri::command]
async fn get_active_provider_id() -> Result<Option<String>, String> {
    blocking(|| Ok(store::load_store()?.current_provider_id)).await
}

/// F-6：开启/关闭 WSL 集成实验开关（默认关闭）。
#[tauri::command]
async fn set_wsl_integration_enabled(enabled: bool) -> Result<bool, String> {
    blocking(move || {
        appconfig::update(|cfg| cfg.wsl_integration_enabled = enabled)?;
        Ok(enabled)
    })
    .await
}

/// F-6：列出本机 WSL 发行版。
#[tauri::command]
async fn list_wsl_distros() -> Result<Vec<String>, String> {
    blocking(wsl::list_wsl_distros_blocking).await
}

/// F-6/K-4：把当前账号凭据同步到指定发行版，返回对账报告（实验开关未开则拒绝）。
///
/// 若 WSL 内副本更新，先把它回写当前账号库，再返回报告给前端展示。
#[tauri::command]
async fn write_wsl_credentials(distro: String) -> Result<wsl::WslSyncReport, String> {
    blocking(move || {
        let (current_id, blob) = {
            let store_data = store::load_store()?;
            let current_id = store_data
                .current_profile_id
                .clone()
                .ok_or_else(|| "当前没有可写入 WSL 的账号".to_string())?;
            let profile = store_data
                .profiles
                .iter()
                .find(|p| p.id == current_id)
                .ok_or_else(|| "找不到当前账号".to_string())?;
            let blob = profile
                .keychain_password
                .clone()
                .ok_or_else(|| "当前账号没有可写入 WSL 的凭据".to_string())?;
            (current_id, blob)
        };
        let report = wsl::sync_to_wsl_blocking(distro, blob)?;
        // WSL 副本更新：回写账号库。
        if let Some(remote_blob) = report.remote_newer_blob.clone() {
            store::with_store(|data| {
                if let Some(profile) = data.profiles.iter_mut().find(|p| p.id == current_id) {
                    profile.keychain_password = Some(remote_blob);
                    profile.updated_at = chrono::Utc::now();
                }
                Ok(())
            })?;
        }
        Ok(report)
    })
    .await
}

/// F-6：删除指定发行版里的凭据。
#[tauri::command]
async fn clear_wsl_credentials(distro: String) -> Result<(), String> {
    blocking(move || wsl::clear_wsl_credentials(&distro)).await
}

#[tauri::command]
fn rename_profile(id: String, name: String, notes: Option<String>) -> Result<(), String> {
    let clean_name = name.trim();
    if clean_name.is_empty() {
        return Err("账号名称不能为空".to_string());
    }
    // H-2：读—改—写走 with_store。
    let result = store::with_store(|store_data| {
        let profile = store_data
            .profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| "找不到这个账号快照".to_string())?;
        profile.name = clean_name.to_string();
        profile.notes = notes;
        profile.updated_at = Utc::now();
        Ok(())
    });
    // F-2：改名成功后重建快捷方式（旧名文件随目录清空被移除）。
    if result.is_ok() {
        if let Err(e) = shortcuts::sync_all_shortcuts() {
            log_error(&format!("同步开始菜单快捷方式失败: {e}"));
        }
    }
    result
}

// ───────────────────────── 备份 ─────────────────────────

fn create_backup_with_label(label: &str) -> Result<BackupResult, String> {
    p::ensure_app_dirs()?;
    let (claude_json, settings_json, keychain_password) = accounts::current_snapshot()?;
    let keychain_password = match keychain_password {
        Some(plain) => Some(store::encrypt_keychain_field(&plain)?),
        None => None,
    };
    // 备份同样不能留下明文 API key / apiKeyHelper；与 store 复用拆分加密，
    // 旧备份没有 encrypted_auth_settings 字段时仍能按原样恢复。
    let (plain_settings, secret_settings) = store::split_auth_settings(settings_json);
    let encrypted_auth_settings = secret_settings
        .map(|secret| store::encrypt_secret(&secret.to_string()))
        .transpose()?;
    let id = format!(
        "{}-{}",
        Utc::now().format("%Y%m%d%H%M%S"),
        uuid::Uuid::new_v4()
    );
    let path = p::backups_dir()?.join(format!("{id}.json"));
    let backup = json!({
        "id": id,
        "label": label,
        "created_at": Utc::now(),
        "claude_json": claude_json,
        "settings_json": plain_settings,
        "encrypted_auth_settings": encrypted_auth_settings,
        "keychain_password": keychain_password,
    });
    jsonio::write_json_pretty(path.clone(), &backup)?;
    prune_backups(30);
    Ok(BackupResult {
        id,
        path: path.to_string_lossy().to_string(),
        created_at: Utc::now(),
    })
}

fn load_backup_snapshot(path: &str) -> Result<BackupSnapshot, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("读取备份失败: {e}"))?;
    let backup: Value =
        serde_json::from_str(&raw).map_err(|e| format!("备份 JSON 解析失败: {e}"))?;
    BackupSnapshot::from_backup_value(&backup)
}

fn prune_backups(keep: usize) {
    let Ok(dir) = p::backups_dir() else {
        return;
    };
    let Ok(entries) = fs::read_dir(&dir) else {
        return;
    };

    let mut files: Vec<(String, std::time::SystemTime, std::path::PathBuf)> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json"))
        .map(|path| {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            let mtime = path
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            (name, mtime, path)
        })
        .collect();

    if files.len() <= keep {
        return;
    }
    files.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let remove_count = files.len() - keep;
    for (_, _, path) in files.into_iter().take(remove_count) {
        let _ = fsx::remove_file_with_retry(&path);
    }
}

#[tauri::command]
async fn create_backup() -> Result<BackupResult, String> {
    blocking(|| create_backup_with_label("manual")).await
}

/// 列出备份。串行读最多 30 个含完整 claude_json 的大 JSON，可能耗时数十毫秒到
/// 数秒，必须离开主线程。
#[tauri::command]
async fn list_backups() -> Result<Vec<BackupSummary>, String> {
    blocking(list_backups_blocking).await
}

fn list_backups_blocking() -> Result<Vec<BackupSummary>, String> {
    p::ensure_app_dirs()?;
    let dir = p::backups_dir()?;
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(_) => return Ok(Vec::new()),
    };

    let mut summaries: Vec<BackupSummary> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json"))
        .filter_map(|path| {
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<unknown>")
                .to_string();
            let raw = match fs::read_to_string(&path) {
                Ok(raw) => raw,
                Err(e) => {
                    log_error(&format!(
                        "list_backups: 跳过坏备份「{file_name}」(读取失败): {e}"
                    ));
                    return None;
                }
            };
            let value: Value = match serde_json::from_str(&raw) {
                Ok(value) => value,
                Err(e) => {
                    log_error(&format!(
                        "list_backups: 跳过坏备份「{file_name}」(JSON 解析失败): {e}"
                    ));
                    return None;
                }
            };
            let id = value
                .get("id")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
                .or_else(|| {
                    path.file_stem()
                        .and_then(|n| n.to_str())
                        .map(ToOwned::to_owned)
                })?;
            let label = value
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let created_at = value
                .get("created_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Some(BackupSummary {
                id,
                label,
                created_at,
            })
        })
        .collect();

    summaries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(summaries)
}

/// 恢复流程里有 `claude_code_running()`（全进程扫描）与账号材料写入，走 blocking。
#[tauri::command]
async fn restore_backup(id: String) -> Result<RestoreResult, String> {
    blocking(move || restore_backup_blocking(id)).await
}

fn restore_backup_blocking(id: String) -> Result<RestoreResult, String> {
    let clean_id = id.trim();
    if clean_id.is_empty() {
        return Err("备份 id 不能为空".to_string());
    }
    if clean_id.contains('/') || clean_id.contains('\\') || clean_id.contains("..") {
        return Err("非法的备份 id".to_string());
    }

    let path = p::backups_dir()?.join(format!("{clean_id}.json"));
    if !path.exists() {
        return Err(format!("找不到备份文件: {}", path.to_string_lossy()));
    }
    let raw = fs::read_to_string(&path).map_err(|e| format!("读取备份失败: {e}"))?;
    let backup: Value =
        serde_json::from_str(&raw).map_err(|e| format!("备份 JSON 解析失败: {e}"))?;

    let mut warnings = Vec::new();

    if processes::claude_code_running() {
        warnings.push(
            "检测到 Claude Code 仍在运行，恢复不会作用于已运行的会话，请恢复后重启 Claude Code"
                .to_string(),
        );
    }

    let backup_result = create_backup_with_label("before-restore")?;

    let restored = BackupSnapshot::from_backup_value(&backup)?;
    let claude_json = restored.claude_json.as_ref();
    let settings_json = restored.settings_json.as_ref();
    let keychain_password = restored.keychain;
    let has_auth_settings = backup
        .get("encrypted_auth_settings")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .is_some();

    if claude_json.is_none()
        && settings_json.is_none()
        && keychain_password.is_none()
        && !has_auth_settings
    {
        return Err("该备份不包含任何可恢复的内容".to_string());
    }

    if claude_json.is_none() {
        warnings.push(
            "备份缺少 claude_json，将删除当前 ~/.claude.json（完整还原到备份时刻）".to_string(),
        );
    }
    if settings_json.is_none() {
        warnings.push(
            "备份缺少 settings_json，将删除当前 ~/.claude/settings.json（完整还原到备份时刻）"
                .to_string(),
        );
    }
    if keychain_password.is_none() {
        warnings.push(format!(
            "备份缺少 keychain_password，将清空当前{CREDENTIAL_STORE_LABEL}（完整还原到备份时刻）"
        ));
    }

    let rollback_from = load_backup_snapshot(&backup_result.path)?;
    accounts::apply_account_material(
        accounts::WriteMode::FullReplace,
        claude_json,
        settings_json,
        keychain_password.as_deref(),
        &rollback_from,
    )?;

    let store_data = store::load_store()?;
    let runtime = store_data.current_profile_id.as_deref().and_then(|id| {
        store_data
            .profiles
            .iter()
            .find(|profile| profile.id == id)
            .and_then(|profile| profile.runtime.clone())
    });
    if let Err(e) =
        accounts::apply_profile_env_to_settings(store_data.telemetry_mode, runtime.as_ref())
    {
        warnings.push(format!(
            "隐私 env 注入失败（可在设置里重选遥测模式重试）：{e}"
        ));
    }
    // 恢复备份也会改变当前账号及本地日志来源，旧缓存必须立即失效。
    usage::clear_caches();

    Ok(RestoreResult {
        restored_from: clean_id.to_string(),
        backup: backup_result,
        warnings,
    })
}

// ───────────────────────── 其它命令 ─────────────────────────

/// Windows：explorer 即使成功也常返回非零退出码，用 spawn 忽略退出码。
#[tauri::command]
fn open_data_dir() -> Result<(), String> {
    let path = p::app_data_dir()?;
    platform::imp::silent_command("explorer")
        .arg(path)
        .spawn()
        .map_err(|e| format!("打开目录失败: {e}"))?;
    Ok(())
}

#[tauri::command]
fn inspect_local_files() -> Result<BTreeMap<String, bool>, String> {
    let mut map = BTreeMap::new();
    map.insert(
        "~/.claude.json".to_string(),
        p::claude_json_path()?.exists(),
    );
    map.insert(
        "~/.claude/settings.json".to_string(),
        p::claude_settings_path()?.exists(),
    );
    map.insert(credentials_file_key(), credentials_file_probe());
    map.insert(
        CREDENTIAL_STORE_LABEL.to_string(),
        credentials::read_password()?.is_some(),
    );
    map.insert(
        "~/.claude-switcher/store.private.json".to_string(),
        p::store_path()?.exists(),
    );
    Ok(map)
}

fn credentials_file_key() -> String {
    "~/.claude/.credentials.json".to_string()
}

#[tauri::command]
fn show_main_window_cmd(app: tauri::AppHandle) {
    tray::show_main_window(&app);
}

#[tauri::command]
fn quit_app_cmd(app: tauri::AppHandle) {
    tray::quit_app(&app);
}

/// 关闭主窗口 = 隐藏到托盘（真正的退出走托盘右键菜单）。
/// 习惯对齐 Windows 托盘应用；上游是关闭即退出，这里属于增强项。
#[tauri::command]
fn hide_main_window_cmd(app: tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
}

// ───────────────────────── 日志与诊断 ─────────────────────────

/// 发布版（`windows_subsystem = "windows"`）里 stderr 被丢弃，`eprintln!`
/// 无处可去。把关键错误同时落到 `~/.claude-switcher/logs/claude-switcher.log`
/// （追加写入，带时间戳），排障才有线索。写日志失败绝不影响主流程。
pub fn log_error(message: &str) {
    log_line("ERROR", message);
}

/// 信息级日志（切号成功、链接模式这类非错误事件）：与错误共用落盘实现，
/// 前缀区分级别，排障日志按 ERROR 优先阅读。
pub fn log_info(message: &str) {
    log_line("INFO", message);
}

fn log_line(level: &str, message: &str) {
    let message = format!("[{level}] {message}");
    let line = format!("[{}] {message}\n", Utc::now().format("%Y-%m-%d %H:%M:%S"));
    if let Ok(dir) = p::app_data_dir() {
        let logs = dir.join("logs");
        if fs::create_dir_all(&logs).is_ok() {
            use std::io::Write;
            // 进程内互斥：多线程（托盘刷新 + 命令）并发写同一文件，
            // 否则轮转的「读一半 → 截断 → 写」会互相踩。
            static LOG_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let _guard = LOG_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
            if let Ok(mut file) = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(logs.join("claude-switcher.log"))
            {
                let _ = file.write_all(line.as_bytes());
                // 简单滚动：超过 1MB 时截断保留后半，避免无限增长。
                if let Ok(meta) = file.metadata() {
                    if meta.len() > 1_048_576 {
                        let _ = rotate_log(&logs);
                    }
                }
            }
        }
    }
    eprintln!("[claude-switcher] {message}");
}

fn rotate_log(logs: &std::path::Path) -> io::Result<()> {
    use std::io::Write;
    let path = logs.join("claude-switcher.log");
    let content = fs::read(&path)?;
    // 保留后半（约 512KB），头部丢弃。
    let keep = &content[content.len() / 2..];
    let mut file = fs::File::create(&path)?;
    file.write_all(keep)
}

/// 日志目录路径（前端「打开日志」用）。
#[tauri::command]
fn get_logs_dir() -> Result<String, String> {
    Ok(p::app_data_dir()?
        .join("logs")
        .to_string_lossy()
        .to_string())
}

/// 诊断信息：默认仅本地检查，不访问网络；`include_network=true` 时才查询
/// Clash 控制器和 OAuth profile。这样断网时点诊断也不会卡住。
#[tauri::command]
async fn get_diagnostic_info(include_network: Option<bool>) -> Result<Value, String> {
    blocking(move || get_diagnostic_info_blocking(include_network.unwrap_or(false))).await
}

fn get_diagnostic_info_blocking(include_network: bool) -> Result<Value, String> {
    let status = get_status_blocking(!include_network)?;
    let processes = processes::claude_code_processes();
    let mut payload = json!({
        "platform": get_platform(),
        "claude_json_path": status.claude_json_path,
        "settings_json_path": status.settings_json_path,
        "data_dir": status.data_dir,
        "credentials_json_exists": status.credentials_json_exists,
        "profile_count": status.profile_count,
        "current_profile_id": status.current_profile_id,
        "session_isolation": status.session_isolation,
        "claude_code_processes": processes.iter()
            .map(|(pid, exe)| format!("{pid}: {exe}"))
            .collect::<Vec<_>>(),
        "warnings": status.warnings,
    });
    if include_network {
        let clash_status = clash::clash_status_for_group(DEFAULT_CLASH_GROUP);
        payload["clash"] = json!({
            "controller": clash_status.controller,
            "available": clash_status.available,
            "now": clash_status.now,
            "error": clash_status.error,
        });
    } else {
        payload["network"] = json!({ "included": false });
    }
    Ok(payload)
}

/// F-7：生成脱敏诊断包 zip（含诊断信息 + 日志，全部脱敏）。
/// 返回 zip 文件路径。默认不做网络检查，保证断网也能生成。
#[tauri::command]
async fn build_diagnostic_bundle(include_network: Option<bool>) -> Result<String, String> {
    blocking(move || build_diagnostic_bundle_blocking(include_network.unwrap_or(false))).await
}

/// K-7：导出前预览脱敏后的诊断内容（不写盘、不打包）。
#[derive(Debug, Clone, serde::Serialize)]
struct DiagnosticPreview {
    info_json: String,
    log_text: String,
}

/// K-7：返回脱敏后的诊断信息与日志，供用户先确认再打包。
#[tauri::command]
async fn preview_diagnostic_bundle(
    include_network: Option<bool>,
) -> Result<DiagnosticPreview, String> {
    blocking(move || {
        let (info_json, log_text) =
            collect_redacted_diagnostic_content(include_network.unwrap_or(false))?;
        Ok(DiagnosticPreview {
            info_json,
            log_text,
        })
    })
    .await
}

/// K-7：收集并脱敏诊断包内容（不写盘），返回 (诊断信息 JSON, 日志文本)。
/// 供预览与实际打包共用，保证用户看到的就是会被导出的内容。
fn collect_redacted_diagnostic_content(include_network: bool) -> Result<(String, String), String> {
    // 1) 收集诊断信息并脱敏。
    let mut info = get_diagnostic_info_blocking(include_network)?;
    sanitize::redact_json(&mut info);
    let info_text =
        serde_json::to_string_pretty(&info).map_err(|e| format!("序列化诊断信息失败: {e}"))?;

    // 2) 读取日志并脱敏（日志可能含邮箱/令牌）。
    let log_path = p::app_data_dir()?.join("logs").join("claude-switcher.log");
    let log_text = if log_path.exists() {
        let raw = fs::read_to_string(&log_path).unwrap_or_default();
        sanitize::redact_text(&raw, &sanitize_current_user())
    } else {
        "（无日志文件）".to_string()
    };
    Ok((info_text, log_text))
}

/// 当前用户名（供 redact_text 替换路径），取不到时返回空串。
fn sanitize_current_user() -> String {
    dirs::home_dir()
        .and_then(|home| {
            home.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .unwrap_or_default()
}

fn build_diagnostic_bundle_blocking(include_network: bool) -> Result<String, String> {
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    let (info_text, log_text) = collect_redacted_diagnostic_content(include_network)?;

    // 打包 zip 到 app_data_dir/diagnostic-bundle-<时间戳>.zip。
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let zip_path = p::app_data_dir()?.join(format!("diagnostic-bundle-{timestamp}.zip"));
    let file = fs::File::create(&zip_path).map_err(|e| format!("创建诊断包文件失败: {e}"))?;
    let mut writer = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    writer
        .start_file("diagnostic-info.json", options)
        .map_err(|e| format!("写入诊断信息条目失败: {e}"))?;
    writer
        .write_all(info_text.as_bytes())
        .map_err(|e| format!("写入诊断信息内容失败: {e}"))?;

    writer
        .start_file("claude-switcher.log", options)
        .map_err(|e| format!("写入日志条目失败: {e}"))?;
    writer
        .write_all(log_text.as_bytes())
        .map_err(|e| format!("写入日志内容失败: {e}"))?;

    writer
        .finish()
        .map_err(|e| format!("完成诊断包 zip 失败: {e}"))?;
    Ok(zip_path.to_string_lossy().to_string())
}

/// 一键打开 Windows「开发者设置」页（降级到 junction/硬链接时的引导）。
#[tauri::command]
fn open_developer_settings() -> Result<(), String> {
    platform::imp::silent_command("explorer")
        .arg("ms-settings:developers")
        .spawn()
        .map_err(|e| format!("打开开发者设置失败: {e}"))?;
    Ok(())
}

/// 打开日志目录（资源管理器）。
#[tauri::command]
fn open_logs_dir() -> Result<(), String> {
    let dir = p::app_data_dir()?.join("logs");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    platform::imp::silent_command("explorer")
        .arg(dir)
        .spawn()
        .map_err(|e| format!("打开日志目录失败: {e}"))?;
    Ok(())
}

// ───────────────────────── Claude 配置目录覆盖 ─────────────────────────

/// 当前生效的 Claude 配置目录（解析后的绝对路径）。
#[tauri::command]
fn get_claude_config_dir() -> Result<String, String> {
    Ok(credentials::claude_dir()?.to_string_lossy().to_string())
}

/// 用户显式设置的覆盖路径。与「当前生效目录」分开返回，避免界面把默认路径
/// 预填进输入框，用户一点保存就把默认行为永久固化。
#[tauri::command]
fn get_claude_config_dir_override() -> Result<Option<String>, String> {
    let path = p::app_data_dir()?.join("claude-config-dir.txt");
    Ok(fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty()))
}

/// 手动指定 Claude 配置目录（写入 `~/.claude-switcher/claude-config-dir.txt`）。
/// 传空字符串表示清除覆盖、回到默认解析。
///
/// 典型场景：用户在终端里 `$env:CLAUDE_CONFIG_DIR=D:\claude-alt`，但从开始菜单启动
/// 本工具时读不到该变量——在这里指定一次即可让 GUI 启动也生效。
#[tauri::command]
async fn set_claude_config_dir(path: String) -> Result<String, String> {
    blocking(move || set_claude_config_dir_blocking(path)).await
}

fn set_claude_config_dir_blocking(path: String) -> Result<String, String> {
    let override_file = p::app_data_dir()?.join("claude-config-dir.txt");
    let mut warnings: Vec<String> = Vec::new();
    let trimmed = path.trim();
    if trimmed.is_empty() {
        // 清除覆盖：文件不存在也算成功（幂等）。
        if override_file.exists() {
            fs::remove_file(&override_file).map_err(|e| format!("清除配置目录覆盖失败: {e}"))?;
        }
        usage::clear_caches();
        // 清回默认目录后同样要重建隔离链接，否则 projects 仍指向旧目录
        // 的隔离目录（内容还在，但路径是旧配置目录下的 live 链接）。
        rebuild_isolation_after_config_switch(&mut warnings);
        // 凭据不对称提示：默认目录里的登录态可能是旧的（甚至不存在），
        // 而当前选中账号的凭据还留在原目录。至少要让用户知道该看哪里。
        warnings.push(
            "已切回默认配置目录（~/.claude）。该目录下的登录态可能与此前不同；\
             若 Claude Code 显示未登录或账号不对，请在本工具里重新选择对应快照。"
                .to_string(),
        );
        return Ok(with_warnings(
            "已恢复默认配置目录（~/.claude）；隔离链接已按当前目录重建".to_string(),
            &warnings,
        ));
    }
    let dir = PathBuf::from(trimmed);
    if !dir.is_absolute() {
        return Err("请填写绝对路径（例如 D:\\claude-alt）".to_string());
    }
    // 盘符根（`D:\`）的 parent 是 None，要单独给出可读提示而不是「父目录不存在：」空串。
    match dir.parent() {
        Some(parent) if parent.exists() => {}
        Some(parent) => {
            return Err(format!(
                "父目录不存在：{}（请先确认路径拼写，本工具不会自动创建多级目录）",
                parent.to_string_lossy()
            ));
        }
        None => {
            // parent 为 None = 盘符根或路径前缀。盘符根不适合放配置。
            return Err(format!(
                "「{}」是盘符根目录，不能作为 Claude 配置目录；请填一个子目录（例如 D:\\claude-alt）",
                dir.to_string_lossy()
            ));
        }
    }
    // 先校验新目录可写，避免保存一个不可用路径让凭据写失败。
    fs::create_dir_all(&dir).map_err(|e| format!("配置目录不可写: {e}"))?;
    let probe = dir.join(".claude-switcher-write-test");
    fs::write(&probe, b"ok").map_err(|e| format!("配置目录不可写: {e}"))?;
    fs::remove_file(&probe).map_err(|e| format!("清理写入测试失败: {e}"))?;

    // 凭据迁移：新目录里没有 .credentials.json 时 Claude Code 会显示未登录。
    // 读取旧凭据（覆盖生效前的目录），写入新目录——不删旧文件（回退路径保留）。
    let old_credentials = credentials::read_password()?;
    let new_credentials = {
        let candidate = dir.join(".credentials.json");
        if candidate.exists() {
            Some(fs::read_to_string(&candidate).map_err(|e| e.to_string())?)
        } else {
            None
        }
    };
    // 新目录已有凭据：那里登录的可能是**另一个账号**，与当前选中的快照对不上。
    // 不做静默迁移（会覆盖别人的登录态），明确告知用户。
    if new_credentials.is_some() {
        warnings.push(format!(
            "该目录已存在登录态（{}），未迁移当前账号凭据；Claude Code 将以那个账号运行。如需切换，请在本工具里选择对应快照。",
            dir.join(".credentials.json").to_string_lossy()
        ));
    }
    // 数据盘/非 profile 路径的权限提示：凭据文件继承盘符根 ACL，需额外收敛。
    if !platform::imp::is_under_user_profile(&dir) {
        warnings.push(
            "该目录位于用户配置目录之外（数据盘/其他路径），凭据文件的访问权限依赖该目录的 ACL；\
             本工具会在写入时把它收敛为「仅当前用户 + SYSTEM」，但目录本身的 ACL 需要你自行确认。"
                .to_string(),
        );
    }
    if let (Some(plain), None) = (&old_credentials, &new_credentials) {
        // 先写覆盖文件：之后 credentials::claude_dir() 就解析到新目录，
        // 统一走 write_password 才能带上 secure_private_file 权限收敛
        // （直接用 write_atomically 会绕过，迁移完的凭据文件继承数据盘根 ACL）。
        fs::create_dir_all(p::app_data_dir()?).map_err(|e| e.to_string())?;
        crate::fsx::write_atomically(&override_file, trimmed).map_err(|e| {
            format!(
                "保存配置目录覆盖失败: {}",
                crate::fsx::humanize_io_error(&e)
            )
        })?;
        credentials::write_password(plain).map_err(|e| format!("迁移凭据到新目录失败: {e}"))?;
        // 隔离链接重建：新目录的 projects 等要重新指向当前账号的隔离目录，
        // 否则用户会以为切号生效了、实际 Claude Code 读的是空目录。
        rebuild_isolation_after_config_switch(&mut warnings);
        usage::clear_caches();
        return Ok(with_warnings(
            format!(
                "配置目录已设为：{}（当前登录态已迁移；旧目录数据保留）",
                dir.display()
            ),
            &warnings,
        ));
    }

    // 不自动删除旧目录或旧链接：它们可能仍包含用户会话历史。
    fs::create_dir_all(p::app_data_dir()?).map_err(|e| e.to_string())?;
    // 只写路径本身，不带换行（读取端会 trim）。
    crate::fsx::write_atomically(&override_file, trimmed).map_err(|e| {
        format!(
            "保存配置目录覆盖失败: {}",
            crate::fsx::humanize_io_error(&e)
        )
    })?;
    usage::clear_caches();
    rebuild_isolation_after_config_switch(&mut warnings);
    let base = if new_credentials.is_some() {
        format!("配置目录已设为：{}", dir.display())
    } else {
        format!(
            "配置目录已设为：{}（该目录没有登录态，Claude Code 将显示未登录；可重新登录或切回）",
            dir.display()
        )
    };
    Ok(with_warnings(base, &warnings))
}

/// 把非阻断 warning 拼到成功消息后面（隔离重建失败这类）。
fn with_warnings(base: String, warnings: &[String]) -> String {
    if warnings.is_empty() {
        base
    } else {
        format!("{base}\n注意：{}", warnings.join("；"))
    }
}

/// 切换配置目录后重建当前账号的隔离链接。
///
/// 旧目录里指向 `session-profiles/<id>` 的链接是**旧路径**上的，换目录后新目录里
/// 没有链接，Claude Code 会读到空 projects。这里对当前账号重新 activate 一次
/// （幂等：已正确链接就直接返回）。失败只作 warning，不阻断切换本身。
fn rebuild_isolation_after_config_switch(warnings: &mut Vec<String>) {
    let Ok(store_data) = store::load_store() else {
        return;
    };
    let Some(current_id) = store_data.current_profile_id else {
        return;
    };
    match isolation::activate_profile_claude_local_state(&current_id) {
        Ok(items) => warnings.extend(items),
        Err(e) => warnings.push(format!(
            "隔离链接重建失败（账号材料已切换，重新执行一次「切换」可补上）：{e}"
        )),
    }
}

/// Run 注册表项的值名（固定，便于 UI 显示与排查）。
const AUTOSTART_VALUE_NAME: &str = "ClaudeSwitcher";
/// HKCU 下开机自启的标准位置。
const AUTOSTART_RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

const AUTOSTART_APPROVED_KEY: &str =
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run";

/// 开机自启开关（Windows 写 HKCU Run 项；其它平台不支持）。
///
/// 用 `winreg` 直接操作注册表，替代早前的 `reg.exe` 子进程——后者的错误信息是
/// 本地化字符串（中文系统是「系统找不到指定的值」），靠字符串匹配判断
/// 「删除一个不存在的值」几乎必然失效。
///
/// 写入的值带 `--autostart` 参数，启动时据此判断是否静默运行（只留托盘、不弹主窗口）。
/// 说明：这是增强项，上游 macOS 版没有对应功能。
#[tauri::command]
fn set_autostart(enabled: bool) -> Result<(), String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    // **必须用 create_subkey**：`open_subkey` 内部是 `KEY_READ` 只读句柄
    // （winreg reg_key.rs:146），在它上面 set_value/delete_value 会返回
    // 拒绝访问 (os error 5)。Run 项在 Windows 上一定存在，用 open_subkey
    // 试探再 create 的写法永远走只读分支——自启开关会 100% 失败。
    // create_subkey 用 KEY_ALL_ACCESS，项已存在时也能正常打开（reg_key.rs:241）。
    let (run, _) = RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey(AUTOSTART_RUN_KEY)
        .map_err(|e| format!("打开 Run 注册表项失败: {e}"))?;

    if enabled {
        let exe = std::env::current_exe().map_err(|e| format!("定位当前可执行文件失败: {e}"))?;
        let value = format!("\"{}\" --autostart", exe.to_string_lossy());
        run.set_value(AUTOSTART_VALUE_NAME, &value)
            .map_err(|e| format!("写入开机自启失败: {e}"))?;
        // Run 项存在不代表 Windows 会启动：任务管理器的 StartupApproved
        // 禁用标记也必须清除，否则应用里反复点“开启”永远不会生效。
        let (approved, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(AUTOSTART_APPROVED_KEY)
            .map_err(|e| format!("打开 StartupApproved 注册表项失败: {e}"))?;
        approved
            .set_raw_value(
                AUTOSTART_VALUE_NAME,
                &winreg::RegValue {
                    // 与 Windows 启动项启用值保持一致：02 + 11 个 0。
                    bytes: vec![0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    vtype: winreg::enums::RegType::REG_BINARY,
                },
            )
            .map_err(|e| format!("恢复启动项启用状态失败: {e}"))?;
        Ok(())
    } else {
        // delete_value 对不存在的值返回 NotFound——这正是幂等成功。
        match run.delete_value(AUTOSTART_VALUE_NAME) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("删除开机自启失败: {e}")),
        }
    }
}

/// 开机自启当前状态（三态，供 UI 精确显示）。
#[derive(Debug, Clone, Serialize)]
struct AutostartState {
    /// Run 项是否存在（我们写没写过）。
    registered: bool,
    /// 是否在任务管理器「启动应用」里被用户禁用。
    /// Windows 会把禁用状态存在 StartupApproved\Run 的二进制值里：
    /// 首字节按奇偶判断（偶数启用，奇数禁用；02 启用、03 禁用，缺失按启用）。
    disabled_by_user: bool,
}

#[tauri::command]
fn get_autostart() -> AutostartState {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;

    let registered = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(AUTOSTART_RUN_KEY)
        .and_then(|key| key.get_value::<String, _>(AUTOSTART_VALUE_NAME))
        .is_ok();

    // StartupApproved\Run 里与本值名对应的二进制：首字节 02=启用、03=禁用。
    // 注意 winreg 0.52 的 FromRegValue 没为 Vec<u8> 实现（只支持 String/u32 等），
    // 二进制值必须走 get_raw_value 拿原始 bytes。
    let disabled_by_user = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
            KEY_READ,
        )
        .and_then(|key| key.get_raw_value(AUTOSTART_VALUE_NAME))
        .ok()
        .and_then(|raw| raw.bytes.first().copied())
        .map(|first| first % 2 == 1)
        .unwrap_or(false);

    AutostartState {
        registered,
        disabled_by_user,
    }
}

// ───── 环境安检 / 地区 / 保镖 / 规则 / 桌面版 / 诊断 ─────

/// 14 项安全检查（逐项 ok / warn / fail + 详情）。
#[tauri::command]
async fn run_security_checks() -> Result<Vec<checks::CheckItem>, String> {
    blocking(|| Ok(checks::run_checks_blocking())).await
}

/// 一键修复（拉起代理 / 锁时区 / 关 IPv6 / 写规则 / 注册保镖），并复测。
#[tauri::command]
async fn run_security_fix() -> Result<checks::FixReport, String> {
    blocking(|| Ok(checks::run_fix_blocking())).await
}

/// 探测当前出口（IP / 国家 / IANA 时区 / ASN org）。
#[tauri::command]
async fn detect_egress() -> Result<egress::EgressInfo, String> {
    blocking(egress::detect_egress_blocking).await
}

/// 地区锁定结果（set-region）。
#[derive(Debug, Clone, Serialize)]
pub struct RegionLockReport {
    pub plan: region::RegionPlan,
    pub applied: bool,
    /// 应用后回读的当前 Home Location GeoId（best-effort，仅在 apply 时读取）。
    pub current_geo: Option<u32>,
    pub message: String,
}

/// set-region：按当前出口重锁国家 / 时区 / 区域格式；`apply=true` 时立即改系统时区与区域。
#[tauri::command]
async fn lock_region(apply: bool) -> Result<RegionLockReport, String> {
    blocking(move || {
        let info = egress::detect_egress_blocking()?;
        let plan = region::plan_for_egress(&info.country, &info.iana_tz);
        appconfig::update(|c| {
            c.country_target = Some(plan.country.clone());
            c.tz_target = Some(plan.windows_tz.clone());
            c.locale_target = Some(plan.locale.clone());
            c.last_egress_ip = Some(info.ip.clone());
        })?;
        let mut current_geo = None;
        if apply {
            platform::imp::set_timezone_id(&plan.windows_tz)?;
            platform::imp::set_culture_and_location(&plan.locale, plan.geo_id)?;
            // 回读 Home Location 验证（best-effort，失败不阻断）。
            current_geo = platform::imp::current_home_location_geo().ok();
        }
        Ok(RegionLockReport {
            plan,
            applied: apply,
            current_geo,
            message: if apply {
                "已按出口锁定并应用时区/区域格式".to_string()
            } else {
                "已按出口锁定目标（未改动系统）".to_string()
            },
        })
    })
    .await
}

/// set-client：安装后更换代理客户端。
#[tauri::command]
fn set_client(mode: String) -> Result<(), String> {
    const ALLOWED: [&str; 8] = [
        "clash-verge",
        "sing-box",
        "clashx",
        "surge",
        "wireguard",
        "flclash",
        "other",
        "auto",
    ];
    let m = mode.trim().to_lowercase();
    if !ALLOWED.contains(&m.as_str()) {
        return Err(format!("未知客户端，可选：{}", ALLOWED.join("/")));
    }
    appconfig::update(|c| c.proxy_mode = Some(m.clone()))?;
    Ok(())
}

/// 保镖安装状态。
#[derive(Debug, Clone, Serialize)]
pub struct GuardStatusReport {
    pub installed: bool,
}

/// 查询计划任务要 spawn 隐藏 PowerShell（数百毫秒），必须离开主线程，
/// 否则点一次保镖面板就让窗口卡一下。
#[tauri::command]
async fn guard_status() -> Result<GuardStatusReport, String> {
    blocking(|| {
        Ok(GuardStatusReport {
            installed: guard::guard_installed(),
        })
    })
    .await
}

/// 手动执行一次保镖巡检（kill-switch），返回本轮判定（前端「立即检测」按钮）。
#[tauri::command]
async fn guard_run_tick() -> Result<guard::GuardTick, String> {
    blocking(|| Ok(guard::guard_tick())).await
}

#[tauri::command]
async fn install_guard_cmd() -> Result<(), String> {
    blocking(guard::install_guard).await
}

#[tauri::command]
async fn uninstall_guard_cmd() -> Result<(), String> {
    blocking(guard::uninstall_guard).await
}

/// Clash 当前模式（rule / global / direct）。
#[tauri::command]
async fn get_clash_mode() -> Result<String, String> {
    blocking(rules::clash_mode).await
}

/// 按当前模式写 / 清规则（Script.js 托管块），并验证、失败回滚。
#[tauri::command]
async fn ensure_clash_rules() -> Result<rules::RulesReport, String> {
    blocking(rules::ensure_rules).await
}

/// 设置 WebRTC 策略（proxy / reject）。
#[tauri::command]
fn set_webrtc_policy(policy: String) -> Result<(), String> {
    let p = policy.trim().to_lowercase();
    if p != "proxy" && p != "reject" {
        return Err("WebRTC 策略仅支持 proxy / reject".to_string());
    }
    appconfig::update(|c| c.webrtc_policy = Some(p.clone()))?;
    Ok(())
}

/// 读取当前全局环境/代理偏好（前端面板回显已保存值，避免重启后显示默认值、
/// 用户一点击就把旧选择覆盖掉）。
#[tauri::command]
fn get_appconfig() -> appconfig::AppConfig {
    appconfig::load()
}

/// 设置 Clash 代理组名（Script.js 置顶规则的目标）。空串清除，回落到默认组。
#[tauri::command]
fn set_proxy_group(group: String) -> Result<(), String> {
    let cleaned = group.trim().to_string();
    appconfig::update(|c| {
        c.proxy_group = if cleaned.is_empty() {
            None
        } else {
            Some(cleaned.clone())
        }
    })?;
    Ok(())
}

// ── Claude Desktop 桌面版 ──

#[tauri::command]
fn list_desktop_profiles_cmd() -> Vec<store::DesktopProfile> {
    desktop::list_desktop_profiles()
}

#[tauri::command]
async fn capture_desktop_profile_cmd(
    name: String,
    notes: Option<String>,
) -> Result<store::DesktopProfile, String> {
    blocking(move || desktop::capture_desktop_profile(&name, notes)).await
}

#[tauri::command]
async fn switch_desktop_profile_cmd(id: String) -> Result<Vec<String>, String> {
    blocking(move || desktop::switch_desktop_profile(&id)).await
}

#[tauri::command]
async fn delete_desktop_profile_cmd(id: String, also_files: bool) -> Result<(), String> {
    blocking(move || desktop::delete_desktop_profile(&id, also_files)).await
}

#[tauri::command]
async fn rename_desktop_profile_cmd(
    id: String,
    name: String,
) -> Result<store::DesktopProfile, String> {
    blocking(move || desktop::rename_desktop_profile(&id, &name)).await
}

// ── 隐私 / 诊断工具 ──

#[tauri::command]
async fn open_safe_cmd(url: String) -> Result<String, String> {
    blocking(move || diagnostics::open_safe(&url)).await
}

#[tauri::command]
async fn close_safe_cmd(id: String) -> Result<(), String> {
    blocking(move || diagnostics::close_safe(&id)).await
}

#[tauri::command]
async fn diagnose_proxy_cmd(proxy_url: String) -> Result<Value, String> {
    blocking(move || diagnostics::diagnose_proxy(&proxy_url)).await
}

#[tauri::command]
async fn system_fingerprint_cmd() -> Result<diagnostics::SystemFingerprint, String> {
    blocking(|| Ok(diagnostics::system_fingerprint())).await
}

#[tauri::command]
async fn cli_info_cmd() -> Result<diagnostics::CliInfo, String> {
    blocking(|| Ok(diagnostics::cli_info())).await
}

// ───────────────────────── 启动 ─────────────────────────

/// 安装 panic hook：把 panic 信息写进本机日志（发布版 stderr 被丢弃），
/// 否则崩溃后用户只看到程序消失、排查毫无线索。
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<非字符串 panic>".to_string());
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<未知位置>".to_string());
        log_error(&format!("PANIC at {location}: {payload}"));
    }));
}

/// 控制台子系统 `cs.exe` 的入口（J-1）：在已自带控制台的进程中同步执行
/// CLI 子命令，返回真实退出码（由 bin 用 `std::process::exit` 透传）。
pub fn cli_console(args: &[String]) -> i32 {
    cli::run_console(args)
}

pub fn run() {
    install_panic_hook();

    // 保镖/时区看门狗常驻模式：由计划任务（ClaudeBodyguard，AtLogOn）以 `--guard` 拉起，
    // 进入后不初始化 GUI，10 秒巡检循环（代理内核/TUN 丢失即杀 Claude，fail-closed）。
    if std::env::args().any(|a| a == "--guard") {
        guard::run_guard_loop();
    }

    let args: Vec<String> = std::env::args().collect();
    let cli_command = cli::parse(&args);

    // 只读 CLI 子命令：附加控制台执行后直接退出，不初始化 GUI、不写账号库。
    if let Some(cmd @ (cli::CliCommand::List | cli::CliCommand::Status)) = &cli_command {
        let code = cli::run_readonly(cmd);
        std::process::exit(code);
    }
    // 便携模式（H-1）：WebView2 用户数据目录必须在 WebView2 创建前设置，
    // 指向数据子目录（exe/ClaudeSwitcherData），而非 exe 目录本身，避免污染程序目录。
    if let Some(data_dir) = paths::portable_data_dir() {
        std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", &data_dir);
    }
    // F-7 完整便携版：若 exe 旁带固定 WebView2 运行时，在 WebView2 创建前指向它，
    // 使目标机器即使没装 WebView2 也能运行；无此目录则回退系统已安装的 WebView2。
    if let Some(runtime_dir) = paths::fixed_webview2_dir() {
        std::env::set_var("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", &runtime_dir);
    }

    // 启动早期探测数据目录可写（H-1）：解压到 Program Files 等只读位置时
    // 弹明确原生提示并退出，而不是静默失败。
    if let Err(error) = paths::probe_data_dir_writable() {
        platform::imp::show_startup_error("无法启动 Claude Switcher", &error);
        std::process::exit(1);
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        // 单实例：第二个进程的 argv 会回调到运行实例——--switch 转交执行，
        // 其余情况唤起主窗口；也避免两个进程并发写账号库。
        .plugin(tauri_plugin_single_instance::init(
            |app, argv, _cwd| match cli::parse(&argv) {
                Some(cli::CliCommand::Switch(name)) => cli::forward_switch(app, &name),
                Some(cli::CliCommand::SwitchId(id)) => cli::forward_switch_id(app, &id),
                _ => tray::show_main_window(app),
            },
        ))
        .on_window_event(|window, event| {
            // 主窗口点 X → 隐藏到托盘（退出走托盘菜单）。
            if window.label() == "main" {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .setup(move |app| {
            // CLI --switch 且未被单实例插件转交（说明本进程是唯一实例）：
            // 执行切换、打印结果后立即退出，不安装托盘、不显示主窗口。
            match &cli_command {
                Some(cli::CliCommand::Switch(name)) => {
                    let code = cli::run_switch_first_instance(name);
                    use std::io::Write;
                    let _ = std::io::stdout().flush();
                    std::process::exit(code);
                }
                Some(cli::CliCommand::SwitchId(id)) => {
                    let code = cli::run_switch_id_first_instance(id);
                    use std::io::Write;
                    let _ = std::io::stdout().flush();
                    std::process::exit(code);
                }
                _ => {}
            }

            if let Err(error) = tray::install_tray_handlers(app) {
                log_error(&format!("初始化托盘失败: {error}"));
            }
            // 开机自启时带 `--autostart` 参数：静默运行，只留托盘图标、不弹主窗口
            // （开机就弹窗口是很恼人的体验）。手动启动才显示主窗口。
            let is_autostart = std::env::args().any(|arg| arg == "--autostart");
            if is_autostart {
                let _ = app.get_webview_window("main").map(|w| w.hide());
            } else {
                // tauri.conf.json 里 visible:false + 这里 show，
                // 保证托盘已就绪再出现窗口。
                tray::show_main_window(app.handle());
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_platform,
            get_system_language,
            get_status,
            check_for_update,
            export_store_encrypted,
            import_store_encrypted,
            set_telemetry_mode,
            list_profiles,
            capture_current_profile,
            prepare_new_account_login,
            complete_new_account_login,
            cancel_pending_new_account_login,
            switch_profile,
            open_parallel_terminal,
            list_mcp_servers,
            upsert_mcp_server,
            delete_mcp_server,
            get_quota_reminder,
            set_quota_reminder,
            set_auto_adopt,
            get_clash_status,
            get_claude_usage,
            switch_clash_node,
            switch_profile_clash_node,
            set_profile_clash_binding,
            set_profile_runtime_binding,
            delete_profile,
            rename_profile,
            rebuild_start_menu_shortcuts,
            clear_start_menu_shortcuts,
            is_portable_mode,
            add_to_user_path,
            remove_from_user_path,
            list_workspace_items,
            set_workspace_item_enabled,
            read_permission_editor,
            save_permission_editor,
            get_tool_bin_dir,
            bind_directory,
            unbind_directory,
            create_provider,
            list_providers,
            delete_provider,
            switch_to_provider,
            test_provider_connection,
            get_active_provider_id,
            set_wsl_integration_enabled,
            list_wsl_distros,
            write_wsl_credentials,
            clear_wsl_credentials,
            create_backup,
            list_backups,
            restore_backup,
            open_data_dir,
            inspect_local_files,
            show_main_window_cmd,
            quit_app_cmd,
            hide_main_window_cmd,
            get_logs_dir,
            get_diagnostic_info,
            build_diagnostic_bundle,
            preview_diagnostic_bundle,
            open_developer_settings,
            open_logs_dir,
            get_claude_config_dir,
            get_claude_config_dir_override,
            set_claude_config_dir,
            set_autostart,
            get_autostart,
            // 环境安检 / 地区 / 保镖 / 规则
            run_security_checks,
            run_security_fix,
            detect_egress,
            lock_region,
            set_client,
            guard_status,
            guard_run_tick,
            install_guard_cmd,
            uninstall_guard_cmd,
            get_clash_mode,
            ensure_clash_rules,
            set_webrtc_policy,
            get_appconfig,
            set_proxy_group,
            // Claude Desktop 桌面版
            list_desktop_profiles_cmd,
            capture_desktop_profile_cmd,
            switch_desktop_profile_cmd,
            delete_desktop_profile_cmd,
            rename_desktop_profile_cmd,
            // 隐私 / 诊断
            open_safe_cmd,
            close_safe_cmd,
            diagnose_proxy_cmd,
            system_fingerprint_cmd,
            cli_info_cmd,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Claude Switcher");
}
