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
mod clash;
mod credentials;
mod fsx;
mod isolation;
mod jsonio;
mod links;
mod net;
mod paths;
mod platform;
mod processes;
mod store;
mod tray;
mod usage;

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

fn string_field<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = value;
    for key in path {
        cur = cur.get(*key)?;
    }
    cur.as_str()
}

/// 当前平台（前端替代已弃用的 navigator.platform）。
#[tauri::command]
fn get_platform() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
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
        warnings,
    })
}

/// 凭据文件存在性探测。
/// Windows 上是主存储（`.credentials.json`）；macOS 上它是旧版残留文件（凭据在 Keychain）。
/// Note: credentials::credentials_path() 在 Windows 上才有（macOS 版是 legacy_credentials_path）。
fn credentials_file_probe() -> bool {
    #[cfg(windows)]
    {
        credentials::credentials_path()
            .map(|path| path.exists())
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        credentials::legacy_credentials_path()
            .map(|path| path.exists())
            .unwrap_or(false)
    }
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

    let mut store_data = store::load_store()?;
    store_data.telemetry_mode = parsed;
    let runtime = store_data
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
        });
    store::save_store(&store_data)?;
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

    let mut store_data = store::load_store()?;
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
        clash: None,
        runtime: Some(runtime),
    };
    let summary = profile_summary_of(&profile, Some(""));
    let profile_id = profile.id.clone();
    // 先把 profile 落进 store，再改 live 隔离链接：链接操作随时可能因
    // Windows 文件锁失败，但快照本身已完整保存——失败不再回滚 store
    // （回滚会让 live 链接指向 store 里已不存在的 profile，反而更乱），
    // 只记日志；UI 的 session_isolation 状态会提示"隔离未激活"，
    // 用户重新执行一次"切换"即可补上链接。
    store_data.current_profile_id = Some(profile_id.clone());
    // 捕获新账号后必须清缓存：OAuth/本地用量缓存里可能还留着上一个账号的数据
    // （token 指纹能防串号，但 projects 目录也换了，本地统计必须重算）。
    usage::clear_caches();
    store_data.profiles.push(profile);
    store::save_store(&store_data)?;
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

    let mut store_data = store::load_store()?;
    let mut warnings = Vec::new();
    if store_data.pending_new_account.is_some() {
        return Err("已有待完成的新号登录流程，请先完成保存或切回旧账号重新开始".to_string());
    }
    warnings.extend(processes::kill_claude_code_processes()?);

    let backup = create_backup_with_label("before-new-account-login")?;
    warnings.extend(refresh_current_profile_snapshot(
        &mut store_data,
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
    store::save_store(&store_data)?;
    match isolation::activate_profile_claude_local_state(&pending.id) {
        Ok(items) => warnings.extend(items),
        Err(e) => warnings.push(format!(
            "新号隔离目录激活失败（不影响登录，可重新执行一次切换恢复）：{e}"
        )),
    }
    if let Err(e) =
        accounts::apply_profile_env_to_settings(store_data.telemetry_mode, Some(&pending.runtime))
    {
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
}

#[tauri::command]
async fn complete_new_account_login() -> Result<ProfileSummary, String> {
    blocking(complete_new_account_login_blocking).await
}

fn complete_new_account_login_blocking() -> Result<ProfileSummary, String> {
    let mut store_data = store::load_store()?;
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
    store::save_store(&store_data)?;
    Ok(summary)
}

/// 内部会触发一次完整切号（含进程结束等待、Clash 请求、链接重试），
/// 因此和 switch_profile 一样走 spawn_blocking。
#[tauri::command]
async fn cancel_pending_new_account_login() -> Result<Option<SwitchResult>, String> {
    blocking(cancel_pending_new_account_login_blocking).await
}

fn cancel_pending_new_account_login_blocking() -> Result<Option<SwitchResult>, String> {
    let mut store_data = store::load_store()?;
    if store_data.pending_new_account.is_none() {
        return Err("没有待取消的新号登录流程".to_string());
    }
    let current_id = store_data.current_profile_id.clone();

    // 先尝试切回旧账号；切换失败时保留 pending，让用户可以重试取消。
    // 原来的顺序是先清 pending 再切——一旦切号失败，pending 就永久丢了，
    // 用户既回不到旧账号也重启不了新号流程。
    if let Some(id) = current_id.clone() {
        // 走同步实现：本命令自身也是 spawn_blocking 里的同步逻辑（见下方）。
        match switch_profile_blocking(id) {
            Ok(result) => {
                let mut after = store::load_store()?;
                after.pending_new_account = None;
                store::save_store(&after)?;
                return Ok(Some(result));
            }
            Err(e) => {
                return Err(format!(
                    "切回旧账号失败，新号流程仍保留（可修正后重试）：{e}"
                ))
            }
        }
    }

    // 没有旧账号可切：直接清 pending。
    store_data.pending_new_account = None;
    store::save_store(&store_data)?;
    Ok(None)
}

// ───────────────────────── 切换 ─────────────────────────

/// 切换前 best-effort 回写「当前活账号」的 live 快照到它对应的 profile。
/// 快照不完整或身份不匹配时跳过并 warn，绝不阻断切号。
fn refresh_current_profile_snapshot(store_data: &mut Store, target_id: &str) -> Vec<String> {
    let mut warnings = Vec::new();

    let Some(current_id) = store_data.current_profile_id.clone() else {
        return warnings;
    };
    if current_id == target_id {
        return warnings;
    }
    let Some(profile) = store_data.profiles.iter_mut().find(|p| p.id == current_id) else {
        return warnings;
    };

    let (claude_json, settings_json, keychain_password) = match accounts::current_snapshot() {
        Ok(snapshot) => snapshot,
        Err(err) => {
            warnings.push(format!(
                "未能读取当前账号 live 快照，已跳过对「{}」的回写：{err}",
                profile.name
            ));
            return warnings;
        }
    };

    let Some(claude_json) = claude_json else {
        warnings.push(format!(
            "当前缺少 ~/.claude.json，已跳过对「{}」的快照回写",
            profile.name
        ));
        return warnings;
    };
    let Some(keychain_password) = keychain_password else {
        warnings.push(format!(
            "当前缺少{CREDENTIAL_STORE_LABEL}登录态，已跳过对「{}」的快照回写",
            profile.name
        ));
        return warnings;
    };

    let Some(live_uuid) = string_field(&claude_json, &["oauthAccount", "accountUuid"]) else {
        warnings.push(format!(
            "无法从 live ~/.claude.json 读取 accountUuid，无法确认身份，已跳过对「{}」的回写",
            profile.name
        ));
        return warnings;
    };
    match profile.meta.account_uuid.as_deref() {
        Some(profile_uuid) if profile_uuid == live_uuid => {
            profile.meta =
                usage::extract_meta(Some(&claude_json), Some(keychain_password.as_str()));
            profile.claude_json = claude_json;
            profile.settings_json = settings_json;
            profile.keychain_password = Some(keychain_password);
            profile.updated_at = Utc::now();
        }
        _ => {
            warnings.push(format!(
                "当前 live 身份（accountUuid={live_uuid}）与账号「{}」不一致，可能是手动登录了别的号，已跳过回写以免覆盖凭据",
                profile.name
            ));
        }
    }

    warnings
}

/// 切号流程里有阻塞操作（杀进程等待约 1.2s、Clash 切换 250ms sleep、
/// 链接操作最多 1.3s 退避重试、Clash 请求最长 8s），必须离开主线程，
/// 否则窗口会卡成"未响应"、托盘事件也会被拖住。
#[tauri::command]
async fn switch_profile(id: String) -> Result<SwitchResult, String> {
    blocking(move || switch_profile_blocking(id)).await
}

fn switch_profile_blocking(id: String) -> Result<SwitchResult, String> {
    let mut store_data = store::load_store()?;
    if !store_data.profiles.iter().any(|p| p.id == id) {
        return Err("找不到这个账号快照".to_string());
    }
    let mut warnings = Vec::new();

    if processes::claude_code_running() {
        warnings.push(
            "检测到 Claude Code 仍在运行，切换不会作用于已运行的会话，请切换后重启 Claude Code"
                .to_string(),
        );
    }

    let backup = create_backup_with_label(&format!("before-switch-to-{id}"))?;
    warnings.extend(refresh_current_profile_snapshot(&mut store_data, &id));
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

    let clash_result = if let Some(binding) = &profile.clash {
        if binding.enabled {
            Some(clash::switch_clash_node_internal(
                &binding.group,
                &binding.node,
            )?)
        } else {
            None
        }
    } else {
        None
    };

    let rollback_from = load_backup_snapshot(&backup.path)?;
    accounts::apply_account_material(
        accounts::WriteMode::Merge,
        Some(&profile.claude_json),
        profile.settings_json.as_ref(),
        profile.keychain_password.as_deref(),
        &rollback_from,
    )?;

    if let Err(e) =
        accounts::apply_profile_env_to_settings(store_data.telemetry_mode, profile.runtime.as_ref())
    {
        warnings.push(format!(
            "隐私 env 注入失败（可在设置里重选遥测模式重试）：{e}"
        ));
    }
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
    // 记录切号结果与链接模式：排障时最需要的两条信息。
    // 账号名只记 id 前 8 位（隐私：日志可能被用户直接贴给别人排障）。
    log_info(&format!(
        "切号成功 → {}（链接模式：{}，Clash：{}）",
        &profile.id[..profile.id.len().min(8)],
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
    store::save_store(&store_data)?;

    Ok(SwitchResult {
        switched_to: profile.name,
        backup,
        clash: clash_result,
        restart_hint: format!(
            "切换已写入磁盘和{CREDENTIAL_STORE_LABEL}；请重启正在运行的 Claude Code 会话。"
        ),
        warnings,
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
    let mut store_data = store::load_store()?;
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
    store::save_store(&store_data)
}

#[tauri::command]
fn set_profile_runtime_binding(
    id: String,
    timezone: Option<String>,
    locale: Option<String>,
    chrome_profile: Option<String>,
) -> Result<(), String> {
    let mut store_data = store::load_store()?;
    let current = store_data.current_profile_id.as_deref() == Some(id.as_str());
    let telemetry_mode = store_data.telemetry_mode;
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
    let profile = store_data
        .profiles
        .iter_mut()
        .find(|p| p.id == id)
        .ok_or_else(|| "找不到这个账号快照".to_string())?;
    profile.runtime = Some(runtime.clone());
    profile.updated_at = Utc::now();
    store::save_store(&store_data)?;
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
    let mut store_data = store::load_store()?;
    let before = store_data.profiles.len();
    store_data.profiles.retain(|p| p.id != id);
    if store_data.profiles.len() == before {
        return Err("找不到这个账号快照".to_string());
    }
    if store_data.current_profile_id.as_deref() == Some(&id) {
        store_data.current_profile_id = None;
    }
    store::save_store(&store_data)?;
    // 可选清理会话历史：目录可能很大（GB 级），只在用户显式勾选时删除。
    // 失败只记日志不报错——快照已删，目录残留是次要问题。
    if delete_sessions {
        let dir = p::session_profiles_dir()?.join(&id);
        if dir.exists() {
            match fs::remove_dir_all(&dir) {
                Ok(()) => log_info(&format!(
                    "已删除账号 {} 的会话历史（{}）",
                    &id[..id.len().min(8)],
                    dir.to_string_lossy()
                )),
                Err(e) => log_error(&format!("删除会话历史失败（可手动删除）: {e}")),
            }
        }
    }
    Ok(())
}

#[tauri::command]
fn rename_profile(id: String, name: String, notes: Option<String>) -> Result<(), String> {
    let mut store_data = store::load_store()?;
    let clean_name = name.trim();
    if clean_name.is_empty() {
        return Err("账号名称不能为空".to_string());
    }
    let profile = store_data
        .profiles
        .iter_mut()
        .find(|p| p.id == id)
        .ok_or_else(|| "找不到这个账号快照".to_string())?;
    profile.name = clean_name.to_string();
    profile.notes = notes;
    profile.updated_at = Utc::now();
    store::save_store(&store_data)
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

#[tauri::command]
fn list_backups() -> Result<Vec<BackupSummary>, String> {
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

#[cfg(unix)]
#[tauri::command]
fn open_data_dir() -> Result<(), String> {
    let path = p::app_data_dir()?;
    let program = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let output = platform::imp::silent_command(program)
        .arg(path)
        .output()
        .map_err(|e| format!("打开目录失败: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "打开目录失败: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Windows：explorer 即使成功也常返回非零退出码，用 spawn 忽略退出码。
#[cfg(windows)]
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

/// 一键打开 Windows「开发者设置」页（降级到 junction/硬链接时的引导）。
#[tauri::command]
fn open_developer_settings() -> Result<(), String> {
    #[cfg(windows)]
    {
        platform::imp::silent_command("explorer")
            .arg("ms-settings:developers")
            .spawn()
            .map_err(|e| format!("打开开发者设置失败: {e}"))?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err("仅 Windows 支持打开开发者设置".to_string())
    }
}

/// 打开日志目录（资源管理器）。
#[tauri::command]
fn open_logs_dir() -> Result<(), String> {
    #[cfg(windows)]
    {
        let dir = p::app_data_dir()?.join("logs");
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        platform::imp::silent_command("explorer")
            .arg(dir)
            .spawn()
            .map_err(|e| format!("打开日志目录失败: {e}"))?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err("仅 Windows 支持打开日志目录".to_string())
    }
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
        return Ok("已恢复默认配置目录".to_string());
    }
    let dir = PathBuf::from(trimmed);
    if !dir.is_absolute() {
        return Err("请填写绝对路径（例如 D:\\claude-alt）".to_string());
    }
    // **父目录必须已存在**：`create_dir_all` 会把拼错的路径（比如 `D:\claude-al`）
    // 直接建出来，用户还以为保存对了。只有父目录存在才允许创建最后一级。
    match dir.parent() {
        Some(parent) if parent.exists() => {}
        _ => {
            return Err(format!(
                "父目录不存在：{}（请先确认路径拼写，本工具不会自动创建多级目录）",
                dir.parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default()
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
    if let (Some(plain), None) = (&old_credentials, &new_credentials) {
        // 先写覆盖文件再写凭据：万一凭据写失败，用户只需再执行一次即可。
        fs::create_dir_all(p::app_data_dir()?).map_err(|e| e.to_string())?;
        crate::fsx::write_atomically(&override_file, trimmed).map_err(|e| {
            format!(
                "保存配置目录覆盖失败: {}",
                crate::fsx::humanize_io_error(&e)
            )
        })?;
        crate::fsx::write_atomically(&dir.join(".credentials.json"), plain).map_err(|e| {
            format!(
                "迁移凭据到新目录失败: {}",
                crate::fsx::humanize_io_error(&e)
            )
        })?;
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
#[cfg(windows)]
const AUTOSTART_VALUE_NAME: &str = "ClaudeSwitcher";
/// HKCU 下开机自启的标准位置。
#[cfg(windows)]
const AUTOSTART_RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

#[cfg(windows)]
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
    #[cfg(windows)]
    {
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
            let exe =
                std::env::current_exe().map_err(|e| format!("定位当前可执行文件失败: {e}"))?;
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
    #[cfg(not(windows))]
    {
        let _ = enabled;
        Err("开机自启仅支持 Windows".to_string())
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
    #[cfg(windows)]
    {
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
    #[cfg(not(windows))]
    {
        AutostartState {
            registered: false,
            disabled_by_user: false,
        }
    }
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

pub fn run() {
    install_panic_hook();
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        // 单实例：双击两次只留一个托盘图标，也避免并发写 store。
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            tray::show_main_window(app);
        }))
        .on_window_event(|window, event| {
            // 主窗口点 X → 隐藏到托盘（退出走托盘菜单）。
            if window.label() == "main" {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .setup(|app| {
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
            get_status,
            set_telemetry_mode,
            list_profiles,
            capture_current_profile,
            prepare_new_account_login,
            complete_new_account_login,
            cancel_pending_new_account_login,
            switch_profile,
            get_clash_status,
            get_claude_usage,
            switch_clash_node,
            switch_profile_clash_node,
            set_profile_clash_binding,
            set_profile_runtime_binding,
            delete_profile,
            rename_profile,
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
            open_developer_settings,
            open_logs_dir,
            get_claude_config_dir,
            get_claude_config_dir_override,
            set_claude_config_dir,
            set_autostart,
            get_autostart,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Claude Switcher");
}
