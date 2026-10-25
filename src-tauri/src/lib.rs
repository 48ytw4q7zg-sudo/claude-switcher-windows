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

#[tauri::command]
fn get_status() -> Result<ClaudeStatus, String> {
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
    let _ = usage::apply_oauth_profile(&mut meta, keychain.as_deref());

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
fn capture_current_profile(name: String, notes: Option<String>) -> Result<ProfileSummary, String> {
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
    store_data.profiles.push(profile);
    store::save_store(&store_data)?;
    if let Err(e) = isolation::adopt_live_claude_local_state_for_profile(&profile_id)
        .and_then(|_| isolation::activate_profile_claude_local_state(&profile_id))
    {
        eprintln!("[claude-switcher] 账号快照已保存，但本地状态接管失败: {e}");
    }
    Ok(summary)
}

// ───────────────────────── 新号向导 ─────────────────────────

#[tauri::command]
fn prepare_new_account_login(
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
    Ok(PrepareNewAccountResult {
        pending,
        backup,
        clash: clash_result,
        warnings,
    })
}

#[tauri::command]
fn complete_new_account_login() -> Result<ProfileSummary, String> {
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
        eprintln!("[claude-switcher] 新号隔离链接激活失败（已保存登录态）: {e}");
    }
    store_data.current_profile_id = Some(profile.id.clone());
    store_data.pending_new_account = None;
    store_data.profiles.push(profile);
    store::save_store(&store_data)?;
    Ok(summary)
}

#[tauri::command]
fn cancel_pending_new_account_login() -> Result<Option<SwitchResult>, String> {
    let mut store_data = store::load_store()?;
    if store_data.pending_new_account.is_none() {
        return Err("没有待取消的新号登录流程".to_string());
    }
    let current_id = store_data.current_profile_id.clone();

    // 先尝试切回旧账号；切换失败时保留 pending，让用户可以重试取消。
    // 原来的顺序是先清 pending 再切——一旦切号失败，pending 就永久丢了，
    // 用户既回不到旧账号也重启不了新号流程。
    if let Some(id) = current_id.clone() {
        // 临时保留 pending 供 switch 内部逻辑参考，切成功后再清。
        match switch_profile(id) {
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

#[tauri::command]
fn switch_profile(id: String) -> Result<SwitchResult, String> {
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
    match isolation::activate_profile_claude_local_state(&profile.id) {
        Ok(items) => warnings.extend(items),
        Err(e) => warnings.push(format!(
            "session 隔离链接激活失败（账号材料已切换成功，重新执行一次切换可补上）：{e}"
        )),
    }

    store_data.current_profile_id = Some(profile.id.clone());
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

#[tauri::command]
fn get_clash_status() -> Result<clash::ClashStatus, String> {
    Ok(clash::clash_status_for_group(DEFAULT_CLASH_GROUP))
}

#[tauri::command]
async fn get_claude_usage() -> Result<usage::ClaudeUsageSnapshot, String> {
    tauri::async_runtime::spawn_blocking(usage::claude_usage_snapshot)
        .await
        .map_err(|e| format!("Claude 用量后台任务失败: {e}"))?
}

#[tauri::command]
fn switch_clash_node(group: String, node: String) -> Result<clash::ClashSwitchResult, String> {
    clash::switch_clash_node_internal(group.trim(), node.trim())
}

#[tauri::command]
fn switch_profile_clash_node(id: String) -> Result<clash::ClashSwitchResult, String> {
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
fn delete_profile(id: String) -> Result<(), String> {
    let mut store_data = store::load_store()?;
    let before = store_data.profiles.len();
    store_data.profiles.retain(|p| p.id != id);
    if store_data.profiles.len() == before {
        return Err("找不到这个账号快照".to_string());
    }
    if store_data.current_profile_id.as_deref() == Some(&id) {
        store_data.current_profile_id = None;
    }
    store::save_store(&store_data)
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
        "settings_json": settings_json,
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
fn create_backup() -> Result<BackupResult, String> {
    create_backup_with_label("manual")
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
        .filter(|path| {
            path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json")
        })
        .filter_map(|path| {
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<unknown>")
                .to_string();
            let raw = match fs::read_to_string(&path) {
                Ok(raw) => raw,
                Err(e) => {
                    eprintln!("[claude-switcher] list_backups: 跳过坏备份「{file_name}」(读取失败): {e}");
                    return None;
                }
            };
            let value: Value = match serde_json::from_str(&raw) {
                Ok(value) => value,
                Err(e) => {
                    eprintln!("[claude-switcher] list_backups: 跳过坏备份「{file_name}」(JSON 解析失败): {e}");
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

#[tauri::command]
fn restore_backup(id: String) -> Result<RestoreResult, String> {
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

    let claude_json = backup.get("claude_json").filter(|v| !v.is_null());
    let settings_json = backup.get("settings_json").filter(|v| !v.is_null());
    let keychain_password = backup
        .get("keychain_password")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(store::decrypt_secret)
        .transpose()?;

    if claude_json.is_none() && settings_json.is_none() && keychain_password.is_none() {
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

/// 开机自启开关（Windows 写注册表 Run 项；其它平台 no-op）。
/// 说明：这是增强项，上游 macOS 版没有对应功能。
#[tauri::command]
fn set_autostart(enabled: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        // HKCU\Software\Microsoft\Windows\CurrentVersion\Run 值名固定，
        // 指向当前可执行文件（Tauri 打包后即安装目录里的 exe）。
        let exe = std::env::current_exe().map_err(|e| format!("定位当前可执行文件失败: {e}"))?;
        let value = format!("\"{}\"", exe.to_string_lossy());
        let (verb, args): (&str, Vec<String>) = if enabled {
            (
                "add",
                vec![
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                    "/v".into(),
                    "ClaudeSwitcher".into(),
                    "/t".into(),
                    "REG_SZ".into(),
                    "/d".into(),
                    value,
                    "/f".into(),
                ],
            )
        } else {
            (
                "delete",
                vec![
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                    "/v".into(),
                    "ClaudeSwitcher".into(),
                    "/f".into(),
                ],
            )
        };
        // 走统一的静默子进程封装（CREATE_NO_WINDOW），不闪黑窗。
        let output = platform::imp::silent_command("reg")
            .arg(verb)
            .args(&args)
            .output()
            .map_err(|e| format!("调用 reg 失败: {e}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // 删除一个不存在的值也返回非零，这属于幂等成功。
            if !enabled && (stderr.contains("unable to find") || stderr.is_empty()) {
                return Ok(());
            }
            return Err(format!("设置开机自启失败: {}", stderr.trim()));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = enabled;
        Err("开机自启仅支持 Windows".to_string())
    }
}

#[tauri::command]
fn get_autostart() -> bool {
    #[cfg(windows)]
    {
        platform::imp::silent_command("reg")
            .arg("query")
            .arg("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
            .arg("/v")
            .arg("ClaudeSwitcher")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

// ───────────────────────── 启动 ─────────────────────────

pub fn run() {
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
                eprintln!("[claude-switcher] 初始化托盘失败: {error}");
            }
            // 首次启动显示主窗口（tauri.conf.json 里 visible:false + 这里 show，
            // 保证托盘已就绪再出现窗口）。
            tray::show_main_window(app.handle());
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
            set_autostart,
            get_autostart,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Claude Switcher");
}
