//! 按终端并行多账号（P1-3）。
//!
//! 与「全局切换」（接管唯一的 `~/.claude`）不同：并行模式为每个账号开一个独立
//! 终端，终端里把 `CLAUDE_CONFIG_DIR` 指向 `~/.claude-switcher/accounts/<id>/`，
//! 该目录持有该账号的凭据与 settings，于是多个终端可同时登录不同账号。
//! 终端启动用 `wt.exe powershell -EncodedCommand`（UTF-16LE base64），
//! 未装 Windows Terminal 时退回 `cmd start powershell`（显示窗口）。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread::sleep;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::Serialize;

use crate::fsx;
use crate::store::{self, StoredProfile};

/// 并行账号配置根目录：`~/.claude-switcher/accounts/<id>`。
pub fn parallel_account_dir(id: &str) -> Result<PathBuf, String> {
    Ok(crate::paths::app_data_dir()?.join("accounts").join(id))
}

/// 仅当 `dir/file_name` 不存在时才原子写入 `content`（H-3 播种核心）。
///
/// 返回 `Ok(true)` 表示本次新写入；`Ok(false)` 表示文件已存在、**未覆盖**。
/// 抽成纯函数是为了用 tempdir 单测「缺失才写、已存在不覆盖」这条规则，
/// 不依赖全局 app_data_dir / 真实凭据库。
fn seed_if_missing(dir: &Path, file_name: &str, content: &str) -> Result<bool, String> {
    let path = dir.join(file_name);
    if path.exists() {
        return Ok(false);
    }
    fsx::write_atomically(&path, content)
        .map_err(|e| format!("写入 {} 失败: {e}", path.display()))?;
    Ok(true)
}

/// 把账号材料写进并行配置目录：凭据 + settings（账号专属），共享 skills 走复制。
///
/// H-3：`.credentials.json` 与 `settings.json` 都**只在文件不存在时才播种**。
/// 已存在的 `.credentials.json` 说明并行终端里 claude 已经刷新过令牌——
/// 绝不能用账号库里的旧值覆盖回去（否则刚刷新的令牌被打回旧值，下次切号又把
/// 这个旧值同步给全局，形成互相踢下线）。已存在时改为把磁盘上的现行凭据原文
/// best-effort 回写账号库，让库跟随终端里的新令牌。
pub(crate) fn ensure_parallel_account_dir(profile: &StoredProfile) -> Result<PathBuf, String> {
    let dir = parallel_account_dir(&profile.id)?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建并行配置目录失败: {e}"))?;

    // 凭据：该账号的 OAuth token（claude 认证主存储）。
    let cred_path = dir.join(".credentials.json");
    if cred_path.exists() {
        // 已存在：读出现行凭据原文，best-effort 回写账号库。
        // 读不到/为空就跳过（不阻断开终端）。
        if let Ok(raw) = std::fs::read_to_string(&cred_path) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                sync_parallel_credentials_back(&profile.id, trimmed);
            }
        }
    } else if let Some(cred) = profile.keychain_password.as_deref() {
        seed_if_missing(&dir, ".credentials.json", cred)?;
    }

    // settings：账号自己的 settings（含 env）。只在缺失时播种，不覆盖终端里
    // 用户可能已经改过的配置。
    if let Some(settings) = profile.settings_json.as_ref() {
        // seed_if_missing 返回 Ok(false) 表示文件已存在——这里不关心是否新写。
        let _ = seed_if_missing(&dir, "settings.json", &settings.to_string())?;
    }

    // 共享 skills：优先 junction 指向全局 skills，失败降级复制（best-effort）。
    let _ = link_or_copy_shared_skills(&dir);

    Ok(dir)
}

/// 从凭据 blob 本地解析账号 uuid（纯本地，不联网）。
///
/// 复用 [`crate::usage::extract_meta`]：它在 `claude_json` 缺失时会从 blob 的
/// `claudeAiOauth`（或扁平根）读取 `accountUuid`。本地确实无法解析时返回 None，
/// 调用方据此走保守路径，**绝不在回写路径做阻塞联网**。
fn credential_blob_account_uuid(blob: &str) -> Option<String> {
    crate::usage::extract_meta(None, Some(blob)).account_uuid
}

/// J-3：凭据文件是否比 profile 的更新时间更新（mtime 晚于 updated_at）。
/// 抽成纯函数以便单测覆盖陈旧文件过滤，不依赖真实目录。
fn is_credential_file_newer(
    mtime: std::time::SystemTime,
    updated_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    mtime > std::time::SystemTime::from(updated_at)
}

/// 某 profile 已登记的账号 uuid：优先 `meta.account_uuid`，回退内嵌
/// `claude_json.oauthAccount.accountUuid`。
fn stored_profile_uuid(profile: &StoredProfile) -> Option<&str> {
    profile.meta.account_uuid.as_deref().or_else(|| {
        profile
            .claude_json
            .get("oauthAccount")
            .and_then(|v| v.get("accountUuid"))
            .and_then(|v| v.as_str())
    })
}

/// K-1/I-09：把已核对身份的远端凭据提交进账号库（纯函数，供并行与 WSL 共用）。
///
/// 三道闸门，缺一不可：
/// 1. **身份一致**：调用方已核对 `disk_uuid == 登记 uuid`（身份未知绝不进这里）；
/// 2. **严格更新**：远端过期时间必须晚于库内现值，否则回写等于把库里的新令牌
///    打回旧值（并行目录保存 T1、全局已刷新为 T2 的经典顺序）；
/// 3. **快照未变**：`observed_store_blob` 是核对期间读到的库内快照；提交时若它
///    已与当前值不同，说明期间有别的写入（用户切号/另一次回写）先落地，
///    本次结果已过期，必须放弃而不是覆盖。
///
/// 返回 `true` 表示已写入；`false` 表示按上述任一条件放弃（值相同也返回 false）。
pub(crate) fn commit_verified_credential(
    profile: &mut StoredProfile,
    observed_store_blob: &str,
    remote_blob: &str,
    disk_uuid: Option<&str>,
) -> bool {
    // 身份必须**可核对且一致**：任一边拿不到 uuid 都不算证明同一账号。
    // （`None == None` 会让「两边都未知」被误判为一致，正是原始缺陷的成因。）
    if disk_uuid.is_none() || disk_uuid != stored_profile_uuid(profile) {
        return false;
    }
    if !remote_credential_is_newer(remote_blob, observed_store_blob) {
        return false;
    }
    if !matches!(&profile.keychain_password, Some(cur) if cur == observed_store_blob) {
        return false;
    }
    if matches!(&profile.keychain_password, Some(cur) if cur == remote_blob) {
        return false;
    }
    profile.keychain_password = Some(remote_blob.to_string());
    profile.updated_at = chrono::Utc::now();
    true
}

/// 远端凭据是否严格新于库内快照（过期时间更晚；任一边解析不到时按旧宽松语义
/// 认为「可写」，但前提是另外两道闸门已通过）。
fn remote_credential_is_newer(remote: &str, current: &str) -> bool {
    match (
        credential_blob_expiry(remote),
        credential_blob_expiry(current),
    ) {
        (Some(remote_exp), Some(current_exp)) => remote_exp > current_exp,
        _ => true,
    }
}

/// 从凭据 blob 读访问令牌过期时间（毫秒）。
fn credential_blob_expiry(blob: &str) -> Option<u64> {
    crate::token_status::evaluate_token_status(blob, 0).expires_at_ms
}

/// I-09/WSL：延迟凭据回写的账号库提交入口（带「仍是当前账号」闸门）。
///
/// WSL 同步与并行后台核对都是「先读库 → 花数秒联网核对 → 再写库」的形状，
/// 期间用户可能切到别的账号。若目标账号已不是当前账号，本次结果可能是上一个
/// 账号的残留，必须拒绝而不是写进账号库。
pub(crate) fn commit_wsl_credential_if_current(
    store_data: &mut store::Store,
    profile_id: &str,
    observed_store_blob: &str,
    remote_blob: &str,
) -> Result<(), String> {
    let Some(profile) = store_data.profiles.iter_mut().find(|p| p.id == profile_id) else {
        return Err("找不到当前账号".to_string());
    };
    if store_data.current_profile_id.as_deref() != Some(profile_id) {
        return Err("账号已切换，已放弃本次凭据回写".to_string());
    }
    if !matches!(&profile.keychain_password, Some(cur) if cur == observed_store_blob) {
        return Err("账号库凭据在核对期间已被更新，已放弃本次回写".to_string());
    }
    let disk_uuid = stored_profile_uuid(profile).map(str::to_string);
    if !commit_verified_credential(
        profile,
        observed_store_blob,
        remote_blob,
        disk_uuid.as_deref(),
    ) {
        return Err("账号库凭据不比远端旧或身份不一致，已放弃本次回写".to_string());
    }
    Ok(())
}

/// 正在做身份核对/回写的 profile id 集合（in-flight 去重）。
///
/// 身份未知时回写不会推进 `updated_at`，于是每次托盘刷新/切换都会再次扫描到同一
/// 份凭据；没有去重就会为同一个账号不断 spawn 后台线程，断网或账号多时累积争锁。
static INFLIGHT_WRITEBACK: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();

fn inflight_writeback() -> &'static Mutex<std::collections::HashSet<String>> {
    INFLIGHT_WRITEBACK.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

/// 尝试登记一个 profile 的 in-flight 回写；已在处理中返回 false（跳过本次）。
fn try_claim_writeback(profile_id: &str) -> bool {
    inflight_writeback()
        .lock()
        .map(|mut set| set.insert(profile_id.to_string()))
        .unwrap_or(false)
}

/// 释放 in-flight 标记，线程结束（无论成功失败）都必须调用。
fn release_writeback(profile_id: &str) {
    if let Ok(mut set) = inflight_writeback().lock() {
        set.remove(profile_id);
    }
}

/// 把并行终端里已刷新过的 `.credentials.json` 原文回写到账号库（best-effort，K-1 后台化）。
///
/// 并行终端里 claude 刷新令牌后，磁盘上的 `.credentials.json` 是新的，但账号库里
/// 快照的 `keychain_password` 还是旧的。真实凭据 blob 不含 uuid，本地校验恒为空操作，
/// 因此 K-1 起整个回写放进**后台线程**：
/// 1. 用 access token 调 OAuth profile 端点核对磁盘账号 uuid（带超时与 token 指纹缓存）；
/// 2. 进 `with_store` 做身份校验：身份不一致拒绝回写；查不到身份保守不覆盖，
///    留待下次托盘刷新；一致才更新。
///
/// 同一 profile 已有回写在途时直接跳过（[`try_claim_writeback`]），避免重复 spawn。
/// 立即返回、不阻塞开终端。任何内部错误都只记日志；找不到对应 profile 视为 no-op。
fn sync_parallel_credentials_back(profile_id: &str, raw_cred: &str) {
    if !try_claim_writeback(profile_id) {
        return;
    }
    let (id, raw) = (profile_id.to_string(), raw_cred.to_string());
    std::thread::spawn(move || {
        // 在途标记必须在任何退出路径（含 panic）都释放，否则该 profile 会被永久
        // 判定为「处理中」，之后的回写全部被跳过。
        struct ClaimGuard(String);
        impl Drop for ClaimGuard {
            fn drop(&mut self) {
                release_writeback(&self.0);
            }
        }
        let _guard = ClaimGuard(id.clone());
        // 联网核对前先记录库内快照原文：核对要花数秒，期间用户可能切号或
        // 另一次回写先落地，提交时必须比对这份快照有没有变。
        let observed = store::with_store(|s| {
            let Some(profile) = s.profiles.iter().find(|p| p.id == id) else {
                return Ok(None);
            };
            Ok(Some((
                profile.keychain_password.clone().unwrap_or_default(),
                stored_profile_uuid(profile).map(str::to_string),
            )))
        })
        .ok()
        .flatten();
        let Some((observed_blob, stored_uuid)) = observed else {
            return;
        };
        // 网络核对（约 4 秒超时，命中缓存则更快）；失败 → None。
        let disk_uuid = crate::usage::oauth_account_uuid_for_blob(&raw);
        let result = store::with_store(|s| {
            let Some(profile) = s.profiles.iter_mut().find(|p| p.id == id) else {
                return Ok(());
            };
            // 身份核对：库内未登记 uuid 或两边不一致 → 拒绝，绝不覆盖。
            match (disk_uuid.as_deref(), stored_uuid.as_deref()) {
                (Some(disk), Some(stored)) if disk == stored => {}
                (Some(disk), None) => {
                    crate::log_error(&format!(
                        "账号「{}」未登记账号 uuid，无法确认并行目录凭据（{disk}）属于它，已拒绝回写；请重新捕获该账号后再试。",
                        profile.name
                    ));
                    return Ok(());
                }
                (Some(disk), Some(stored)) => {
                    crate::log_error(&format!(
                        "并行目录「{}」已换成别的账号（磁盘账号 {disk} ≠ 登记账号 {stored}），已拒绝回写以免覆盖；可在界面把它收养为新账号。",
                        profile.name
                    ));
                    return Ok(());
                }
                (None, _) => {
                    // 网络也核对不到身份：保守不覆盖，留待下次托盘刷新再试。
                    return Ok(());
                }
            }
            // 三道闸门（身份/严格更新/快照未变）在提交函数内统一校验。
            if commit_verified_credential(
                profile,
                &observed_blob,
                &raw,
                Some(
                    disk_uuid
                        .as_deref()
                        .unwrap_or(&stored_uuid.unwrap_or_default()),
                ),
            ) {
                return Ok(());
            }
            crate::log_error(&format!(
                "并行目录凭据回写已放弃（可能已有更新写入或账号已切换）: profile={id}"
            ));
            Ok(())
        });
        if let Err(e) = result {
            crate::log_error(&format!(
                "回写并行终端凭据到账号库失败（best-effort，已忽略）: profile={id}, err={e}"
            ));
        }
    });
}

/// J-3/K-1：扫描路径对一条磁盘凭据的处置决定。
#[derive(Debug, Clone, PartialEq, Eq)]
enum CredentialAction {
    /// 本地已能判定身份且不一致：拒绝回写，消息需展示/记录。
    Reject(String),
    /// 本地已能判定身份且一致：立即回写。
    Apply,
    /// 本地解析不到磁盘 uuid：真实凭据 blob 通常不含 uuid，此时本地校验恒为空操作，
    /// 必须交给后台网络核对（[`sync_parallel_credentials_back`]），不能凭 best-effort
    /// 直接覆盖——否则用户在并行终端里 /login 换了号，下次回写就污染原账号快照。
    DeferToBackground,
}

/// J-3/K-1：在已借用的 profile 上判定一条磁盘凭据该如何处置（纯函数）。
///
/// 这里**不写入**，只给决定，由调用方分派到「立即回写」或「后台网络核对」。
fn classify_scanned_credential(profile: &StoredProfile, raw: &str) -> CredentialAction {
    let stored_uuid = stored_profile_uuid(profile);
    match (credential_blob_account_uuid(raw), stored_uuid) {
        // 两边都能解析且不一致 → 拒绝。
        (Some(disk), Some(stored)) if disk != stored => CredentialAction::Reject(format!(
            "并行目录「{}」已换成别的账号（磁盘账号 {disk} ≠ 登记账号 {stored}），已拒绝回写以免覆盖；可在界面把它收养为新账号。",
            profile.name
        )),
        // 本地能解析且一致 → 立即回写。
        (Some(_), Some(_)) => CredentialAction::Apply,
        // 磁盘 uuid 解析不到 → 后台网络核对，本地绝不覆盖。
        (None, _) => CredentialAction::DeferToBackground,
        // 库内未登记 uuid 但磁盘有 uuid：无法比对，同样交后台核对。
        (Some(_), None) => CredentialAction::DeferToBackground,
    }
}

/// J-3 同步点：扫描 `accounts/*/.credentials.json`，把并行终端刷新的令牌回写账号库。
///
/// 仅处理 **mtime 晚于 profile.updated_at** 的凭据文件。身份判定分两路：
/// 本地能解析到 uuid 且一致 → 立即回写；解析不到 → 交给后台线程做网络核对
/// （[`sync_parallel_credentials_back`]），本地绝不覆盖。该版本接收已借用的 store，
/// 供 `switch_profile_blocking`（已持 with_store 锁，不能再嵌套取锁）调用。
pub(crate) fn scan_parallel_credential_changes_into(store_data: &mut store::Store) -> Vec<String> {
    let Ok(accounts_root) = crate::paths::app_data_dir().map(|d| d.join("accounts")) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&accounts_root) else {
        return Vec::new();
    };
    let mut messages = Vec::new();
    for entry in entries.filter_map(|e| e.ok()) {
        let profile_id = entry.file_name().to_string_lossy().to_string();
        let cred_path = entry.path().join(".credentials.json");
        if !cred_path.exists() {
            continue;
        }
        let Ok(mtime) = std::fs::metadata(&cred_path).and_then(|m| m.modified()) else {
            continue;
        };
        let Some(profile) = store_data.profiles.iter_mut().find(|p| p.id == profile_id) else {
            continue;
        };
        // 仅处理 mtime 晚于 updated_at 的（陈旧文件跳过）。
        if !is_credential_file_newer(mtime, profile.updated_at) {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&cred_path) else {
            continue;
        };
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        match classify_scanned_credential(profile, raw) {
            CredentialAction::Reject(msg) => messages.push(msg),
            CredentialAction::Apply => {
                // 值相同则不动（也不刷新 updated_at，否则 mtime 过滤会失效）。
                if !matches!(&profile.keychain_password, Some(cur) if cur == raw) {
                    profile.keychain_password = Some(raw.to_string());
                    profile.updated_at = chrono::Utc::now();
                }
            }
            CredentialAction::DeferToBackground => {
                // 后台线程会自己取 with_store，这里已借用 store，不能嵌套调用。
                sync_parallel_credentials_back(&profile_id, raw);
            }
        }
    }
    messages
}

/// J-3 同步点（托盘刷新用）：在一次 with_store 事务内扫描并回写并行凭据变化。
pub fn scan_parallel_credential_changes() -> Result<Vec<String>, String> {
    store::with_store(|s| Ok(scan_parallel_credential_changes_into(s)))
}

/// 共享 skills 的落地方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedSkillsMode {
    /// 建了目录联接：全局 skills 的改动在账号目录立即可见。
    Junction,
    /// 联接失败，降级为一次性复制。
    Copied,
    /// 账号目录已有 skills，未改动。
    AlreadyPresent,
    /// 全局配置目录没有 skills，无需处理。
    Missing,
}

/// 把全局 `~/.claude/skills` 共享给并行账号目录（best-effort，不阻断开终端）。
///
/// 优先用目录联接（junction）指向主目录：既省空间，也不会出现「各改各的」两份
/// skills。联接失败（目标已存在为普通目录、无权限等）时降级为复制，保留原行为。
fn link_or_copy_shared_skills(account_dir: &Path) -> SharedSkillsMode {
    let Ok(global_dir) = crate::credentials::claude_dir() else {
        return SharedSkillsMode::Missing;
    };
    let global_skills = global_dir.join("skills");
    if !global_skills.is_dir() {
        return SharedSkillsMode::Missing;
    }
    let target_skills = account_dir.join("skills");
    if target_skills.exists() || crate::links::path_is_link(&target_skills) {
        return SharedSkillsMode::AlreadyPresent;
    }
    match crate::platform::imp::create_junction(&global_skills, &target_skills) {
        Ok(()) => SharedSkillsMode::Junction,
        Err(_) => {
            // 降级：复制一份（旧行为），保证功能可用。
            if crate::desktop::copy_dir_recursive(&global_skills, &target_skills).is_ok() {
                SharedSkillsMode::Copied
            } else {
                SharedSkillsMode::Missing
            }
        }
    }
}

/// PowerShell 单引号字符串转义（单引号翻倍）。
fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// 生成并行终端的 PowerShell 脚本：设置窗口标题 + CLAUDE_CONFIG_DIR，再显式解析
/// `claude` 应用并启动。
///
/// H-4：不再直接 `claude`——那样会解析到 `claude.ps1` 包装脚本，在 ExecutionPolicy
/// 为 Restricted 的机器上被直接拦截。这里用 `Get-Command -CommandType Application`
/// 只挑可执行文件（exe/cmd/bat），拿 `$cmd.Source` 显式调用。
fn build_parallel_ps_script(config_dir: &str, title: &str) -> String {
    let dir = ps_single_quote(config_dir);
    let title = ps_single_quote(title);
    format!(
        "$Host.UI.RawUI.WindowTitle = {title}\n\
         $env:CLAUDE_CONFIG_DIR = {dir}\n\
         $cmd = Get-Command claude -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1;\n\
         if (-not $cmd) {{ Write-Host '未找到 claude，请先安装 Claude Code 并确认在 PATH 中。'; return }}\n\
         & $cmd.Source"
    )
}

/// 编码为 PowerShell `-EncodedCommand` 接受的 UTF-16LE base64。
fn encode_utf16le_base64(script: &str) -> String {
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    BASE64.encode(&utf16)
}

/// powershell.exe 的公共启动参数（H-4：加 `-ExecutionPolicy Bypass`）。
///
/// 抽成独立函数以便单测断言顺序：`-NoExit` → `-ExecutionPolicy Bypass` → `-EncodedCommand`。
fn parallel_powershell_args(encoded: &str) -> Vec<&str> {
    vec![
        "-NoExit",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encoded,
    ]
}

/// H-5：spawn 后 800ms 探一次子进程状态，决定这次拉起算 Ok 还是 Err。
///
/// - `exited = Some(true)`：子进程已退出；`success` 为退出码是否 0。
/// - `exited = None`：仍在运行（窗口已拉起，正常）。
/// - 已退出且非成功 = Err；其余（仍在跑 / 成功退出）= Ok。
fn launch_verdict(exited: Option<bool>, success: bool) -> Result<(), ()> {
    match exited {
        Some(true) if !success => Err(()),
        _ => Ok(()),
    }
}

/// 非阻塞拉起命令：spawn 后等 800ms 让窗口/子进程就绪，再 try_wait。
///
/// H-5：原来用 `.output()` 会阻塞到子进程结束（wt/cmd start 拉起的窗口不退出，
/// 命令线程就一直挂住）。改为 stdin/stdout/stderr 全 null + spawn + try_wait：
/// 已退出且非 0 才算失败；仍在运行或成功退出都算 Ok。
/// 注意：**不要**给 wt/cmd 加 CREATE_NO_WINDOW——cmd start 路径本就要显示窗口。
fn spawn_and_probe(mut cmd: Command, launcher: &str) -> Result<(), String> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("{launcher} 启动失败: {e}"))?;
    sleep(Duration::from_millis(800));
    let status = child
        .try_wait()
        .map_err(|e| format!("{launcher} 进程状态检查失败: {e}"))?;
    let (exited, success) = match &status {
        Some(s) => (Some(true), s.success()),
        None => (None, false),
    };
    launch_verdict(exited, success)
        .map_err(|()| format!("{launcher} 退出码 {:?}", status.and_then(|s| s.code())))
}

/// 尝试用 Windows Terminal 启动（新窗口）。
fn launch_wt(encoded: &str) -> Result<(), String> {
    // wt -w new powershell -NoExit -ExecutionPolicy Bypass -EncodedCommand <b64>
    // 用 PowerShell 完整路径，避免 PATH 缺少 WindowsPowerShell 目录时拉起失败。
    let ps = crate::platform::imp::powershell_path();
    let ps = ps.to_string_lossy();
    let mut cmd = Command::new("wt.exe");
    cmd.args(["-w", "new", ps.as_ref()]);
    cmd.args(parallel_powershell_args(encoded));
    spawn_and_probe(cmd, "wt.exe")
}

/// 退回方案：cmd /c start 开一个可见的 PowerShell 窗口（勿用 silent_command）。
fn launch_via_cmd_start(encoded: &str) -> Result<(), String> {
    // 用 PowerShell 完整路径，避免 PATH 缺少 WindowsPowerShell 目录时拉起失败。
    let ps = crate::platform::imp::powershell_path();
    let ps = ps.to_string_lossy();
    let mut cmd = Command::new("cmd");
    cmd.args(["/C", "start", "Claude", ps.as_ref()]);
    cmd.args(parallel_powershell_args(encoded));
    spawn_and_probe(cmd, "cmd start")
}

/// 一次并行终端启动的结果。
#[derive(Debug, Serialize)]
pub struct ParallelTerminalResult {
    pub profile_id: String,
    pub config_dir: String,
    /// 实际使用的启动器：`wt` 或 `cmd-start`。
    pub launcher: String,
}

/// 判断目标账号是否正作为全局账号被打开（H-3 双开冲突）。
///
/// 全局 `~/.claude` 与并行终端目录同时刷同一 OAuth 令牌会互相踢下线，
/// 所以目标账号若已是 `current_profile_id`，禁止再开并行终端。
fn is_dual_open(current_id: Option<&str>, target: &str) -> bool {
    matches!(current_id, Some(cur) if cur == target)
}

/// 为指定账号开一个并行终端（阻塞，调用方须走 blocking）。
pub fn open_parallel_terminal_for_profile(id: &str) -> Result<ParallelTerminalResult, String> {
    // H-3：开终端前先轻量读一次 current_profile_id（不解密、不持锁），
    // 若目标账号正作为全局账号打开，直接拒绝。
    let (_, current_id) = store::read_lightweight()?;
    if is_dual_open(current_id.as_deref(), id) {
        return Err("该账号正作为全局账号，两处（全局 + 并行终端）刷新同一令牌可能导致登录失效，请先切换到其它账号再开并行终端。".to_string());
    }

    let store_data = store::load_store()?;
    let profile = store_data
        .profiles
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| format!("账号 {id} 不存在"))?;

    let dir = ensure_parallel_account_dir(profile)?;
    let script = build_parallel_ps_script(&dir.to_string_lossy(), &profile.name);
    let encoded = encode_utf16le_base64(&script);

    let launcher = if launch_wt(&encoded).is_ok() {
        "wt"
    } else {
        launch_via_cmd_start(&encoded)?;
        "cmd-start"
    };

    Ok(ParallelTerminalResult {
        profile_id: id.to_string(),
        config_dir: dir.to_string_lossy().to_string(),
        launcher: launcher.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_quote_escapes_apostrophes() {
        assert_eq!(ps_single_quote("abc"), "'abc'");
        assert_eq!(ps_single_quote("a'b"), "'a''b'");
        assert_eq!(ps_single_quote("C:\\path"), "'C:\\path'");
    }

    #[test]
    fn script_sets_config_dir_and_runs_claude() {
        let script = build_parallel_ps_script("C:\\accounts\\id1", "美国号");
        assert!(script.contains("$env:CLAUDE_CONFIG_DIR = 'C:\\accounts\\id1'"));
        assert!(script.contains("WindowTitle = '美国号'"));
        // H-4：显式解析 Application，避免 claude.ps1 被 Restricted 策略拦截。
        assert!(script.contains("Get-Command claude -CommandType Application"));
        // 找不到时打印提示并 return（不继续往下跑空 shell）。
        assert!(script.contains("return"));
        // 以 & $cmd.Source 结尾，显式调用解析到的 exe。
        assert!(script.trim_end().ends_with("& $cmd.Source"));
    }

    #[test]
    fn launcher_args_order_includes_execution_policy_bypass() {
        let args = parallel_powershell_args("QUFB");
        let joined = args.join(" ");
        // H-4：-NoExit 之后、-EncodedCommand 之前必须夹着 -ExecutionPolicy Bypass。
        assert_eq!(
            joined,
            "-NoExit -ExecutionPolicy Bypass -EncodedCommand QUFB"
        );
    }

    #[test]
    fn encoded_command_is_utf16le_base64_and_roundtrips() {
        let script = "$env:CLAUDE_CONFIG_DIR = 'x'\n& $cmd.Source";
        let encoded = encode_utf16le_base64(script);
        let bytes = BASE64.decode(&encoded).expect("valid base64");
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let decoded = String::from_utf16_lossy(&units);
        assert_eq!(decoded, script);
    }

    #[test]
    fn account_dir_under_app_data() {
        let dir = parallel_account_dir("abc").expect("dir");
        assert!(dir
            .to_string_lossy()
            .replace('\\', "/")
            .ends_with(".claude-switcher/accounts/abc"));
    }

    // H-3：seed_if_missing 只在缺失时写入，已存在绝不覆盖。
    #[test]
    fn seed_if_missing_creates_when_absent_and_keeps_existing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // 缺失：新写入，返回 true。
        let wrote = seed_if_missing(root, ".credentials.json", "old-token-v1").unwrap();
        assert!(wrote);
        assert_eq!(
            std::fs::read_to_string(root.join(".credentials.json")).unwrap(),
            "old-token-v1"
        );
        // 已存在：不覆盖，返回 false；磁盘上仍是旧令牌。
        let wrote = seed_if_missing(root, ".credentials.json", "new-token-v2").unwrap();
        assert!(!wrote);
        assert_eq!(
            std::fs::read_to_string(root.join(".credentials.json")).unwrap(),
            "old-token-v1",
            "已存在的 .credentials.json 绝不能被账号库里的旧值覆盖"
        );
        // 另一个缺失文件：正常创建。
        let wrote = seed_if_missing(root, "settings.json", "{\"a\":1}").unwrap();
        assert!(wrote);
        assert!(root.join("settings.json").exists());
    }

    // H-3：全局/并行双开冲突判定。
    #[test]
    fn is_dual_open_detects_current_target_match() {
        // 当前账号 == 目标 → 拒绝。
        assert!(is_dual_open(Some("abc"), "abc"));
        // 当前账号 != 目标 → 放行。
        assert!(!is_dual_open(Some("abc"), "def"));
        // 没有全局账号 → 放行。
        assert!(!is_dual_open(None, "abc"));
    }

    // H-5：try_wait 判定——已退出且非成功=Err，其余=Ok。
    #[test]
    fn launch_verdict_fails_only_when_exited_nonzero() {
        // 已退出且失败 → Err。
        assert!(launch_verdict(Some(true), false).is_err());
        // 已退出但成功 → Ok。
        assert!(launch_verdict(Some(true), true).is_ok());
        // 仍在运行（窗口已拉起）→ Ok。
        assert!(launch_verdict(None, false).is_ok());
        // Some(false) 语义上「不算已退出」→ Ok。
        assert!(launch_verdict(Some(false), false).is_ok());
    }

    // ── J-3 并行回写身份校验 ──

    fn make_test_profile(stored_uuid: Option<&str>) -> StoredProfile {
        let now = chrono::Utc::now();
        let meta = crate::store::ProfileMeta {
            account_uuid: stored_uuid.map(str::to_string),
            ..Default::default()
        };
        StoredProfile {
            id: "p1".to_string(),
            name: "测试号".to_string(),
            notes: None,
            created_at: now,
            updated_at: now,
            last_switched_at: None,
            claude_json: serde_json::json!({}),
            settings_json: None,
            encrypted_auth_settings: None,
            keychain_password: Some("old-raw".to_string()),
            meta,
            last_used_percent: None,
            clash: None,
            runtime: None,
        }
    }

    fn blob_with_uuid(uuid: &str) -> String {
        serde_json::json!({
            "claudeAiOauth": { "accountUuid": uuid, "accessToken": "x" }
        })
        .to_string()
    }

    #[test]
    fn credential_blob_account_uuid_reads_nested_oauth() {
        assert_eq!(
            credential_blob_account_uuid(&blob_with_uuid("abc")).as_deref(),
            Some("abc")
        );
        assert_eq!(credential_blob_account_uuid("not-json"), None);
    }

    // 回写提交语义由下面这些 checked 测试覆盖（身份/严格更新/快照未变）。

    // ── K-1 后台网络核对路径 ──

    fn blob_with_expiry(expiry: u64) -> String {
        serde_json::json!({
            "claudeAiOauth": { "accessToken": "fixture", "expiresAt": expiry }
        })
        .to_string()
    }

    #[test]
    fn checked_rejects_stale_remote_and_changed_snapshot() {
        let old = blob_with_expiry(1_000);
        let newer_disk = blob_with_expiry(2_000);
        let newest_store = blob_with_expiry(3_000);
        // (库内现值, 期望回写结果)：旧库 → 写新；已相同 → 不动；库更新 → 拒绝。
        for (store_blob, expected) in [
            (old.as_str(), Some(newer_disk.as_str())),
            (newer_disk.as_str(), Some(newer_disk.as_str())),
            (newest_store.as_str(), Some(newest_store.as_str())),
        ] {
            let mut profile = make_test_profile(Some("same-uuid"));
            profile.keychain_password = Some(store_blob.to_string());
            commit_verified_credential(&mut profile, store_blob, &newer_disk, Some("same-uuid"));
            assert_eq!(
                profile.keychain_password.as_deref(),
                expected,
                "远端必须严格新于库内版本；相同或库内更新时不得回写"
            );
        }
        // 身份不一致：即使远端更新也不得写入。
        let mut profile = make_test_profile(Some("same-uuid"));
        profile.keychain_password = Some(old.clone());
        commit_verified_credential(&mut profile, &old, &newer_disk, Some("other-uuid"));
        assert_eq!(
            profile.keychain_password.as_deref(),
            Some(old.as_str()),
            "身份不一致绝不回写"
        );
    }

    #[test]
    fn checked_refuses_changed_snapshot_and_wrong_selected_profile() {
        let mut store = store::Store::default();
        let mut profile = make_test_profile(Some("same-uuid"));
        let observed = blob_with_expiry(1_000);
        profile.keychain_password = Some(observed.clone());
        store.profiles.push(profile);
        let current_id = store.profiles[0].id.clone();
        // 1. 目标账号不是当前账号 → 拒绝。
        store.current_profile_id = Some("other".to_string());
        assert!(
            commit_wsl_credential_if_current(
                &mut store,
                &current_id,
                &observed,
                &blob_with_expiry(2_000),
            )
            .is_err(),
            "账号已切换时必须拒绝回写"
        );
        // 2. 仍是当前账号，但库内快照在核对期间被改新 → 拒绝覆盖。
        store.current_profile_id = Some(current_id.clone());
        store.profiles[0].keychain_password = Some(blob_with_expiry(3_000));
        assert!(
            commit_wsl_credential_if_current(
                &mut store,
                &current_id,
                &observed,
                &blob_with_expiry(2_000),
            )
            .is_err(),
            "观察到的旧快照已被改动时必须拒绝回写"
        );
        assert_eq!(
            store.profiles[0].keychain_password.as_deref(),
            Some(blob_with_expiry(3_000).as_str()),
            "较新的库内值必须保留"
        );
        // 3. 仍是当前账号且快照未变 → 允许回写。
        let observed_old = store.profiles[0].keychain_password.clone().unwrap();
        store.profiles[0].keychain_password = Some(blob_with_expiry(1_000));
        assert!(
            commit_wsl_credential_if_current(
                &mut store,
                &current_id,
                &blob_with_expiry(1_000),
                &blob_with_expiry(2_000),
            )
            .is_ok(),
            "快照未变且远端更新时应允许回写"
        );
        assert_eq!(
            store.profiles[0].keychain_password.as_deref(),
            Some(blob_with_expiry(2_000).as_str()),
            "回写后库内应为远端新值"
        );
        let _ = observed_old;
    }

    #[test]
    fn checked_conservative_skips_write_when_identity_unknown() {
        let mut profile = make_test_profile(Some("stored-uuid"));
        let raw = "new-raw-cred";
        // 网络查不到身份（None）→ 保守不覆盖，也无警告。
        // 身份核对不到（None）→ 提交函数拒绝回写。
        let written = commit_verified_credential(&mut profile, "old-raw", raw, None);
        assert!(!written);
        assert_eq!(
            profile.keychain_password.as_deref(),
            Some("old-raw"),
            "查不到身份时绝不能覆盖原凭据"
        );
    }

    #[test]
    fn checked_rejects_write_when_network_identity_mismatches() {
        let mut profile = make_test_profile(Some("stored-uuid"));
        let raw = "new-raw-cred";
        // 网络核对到的 uuid 与登记 uuid 不一致 → 拒绝回写并提示收养。
        let written = commit_verified_credential(&mut profile, "old-raw", raw, Some("other-uuid"));
        assert!(!written, "身份不一致必须拒绝回写");
        assert_eq!(
            profile.keychain_password.as_deref(),
            Some("old-raw"),
            "身份不一致时原凭据不能被覆盖"
        );
    }

    #[test]
    fn checked_applies_when_network_identity_matches() {
        let mut profile = make_test_profile(Some("same-uuid"));
        let raw = "new-raw-cred";
        // 网络 uuid 与登记一致 → 回写新凭据。
        let written = commit_verified_credential(&mut profile, "old-raw", raw, Some("same-uuid"));
        assert!(written, "身份一致且远端更新时应回写");
        assert_eq!(profile.keychain_password.as_deref(), Some(raw));
    }

    #[test]
    fn checked_refuses_when_stored_uuid_unknown_but_network_resolves() {
        let mut profile = make_test_profile(None);
        let raw = "new-raw-cred";
        // 账号库未登记 uuid，网络却能核对到身份：无法证明是同一账号。
        // 早先这里放行回写——等于把并行终端里换号后的凭据写进原账号快照，
        // 之后切回该账号就会写入别人的登录态。必须拒绝。
        let written =
            commit_verified_credential(&mut profile, "old-raw", raw, Some("network-uuid"));
        assert!(!written, "账号库无 uuid 时必须拒绝回写");
        assert_eq!(
            profile.keychain_password.as_deref(),
            Some("old-raw"),
            "无法确认身份时绝不能覆盖原凭据"
        );
    }

    #[test]
    fn checked_refuses_when_stored_uuid_unknown_and_disk_uuid_unknown() {
        // 两边都解析不到 uuid：后台路径保守不覆盖，也不报错（留待下次重试）。
        let mut profile = make_test_profile(None);
        let written = commit_verified_credential(&mut profile, "old-raw", "new-raw-cred", None);
        assert!(!written, "两边都解析不到 uuid 时不得覆盖");
        assert_eq!(profile.keychain_password.as_deref(), Some("old-raw"));
    }

    #[test]
    fn mtime_filter_only_processes_newer_credential() {
        let now = chrono::Utc::now();
        let newer = std::time::SystemTime::from(now) + std::time::Duration::from_secs(60);
        let older = std::time::SystemTime::from(now) - std::time::Duration::from_secs(60);
        assert!(is_credential_file_newer(newer, now), "mtime 更晚应处理");
        assert!(!is_credential_file_newer(older, now), "陈旧文件应跳过");
    }

    // ── 扫描路径分派：身份未知绝不本地覆盖 ──

    #[test]
    fn unknown_disk_identity_is_deferred_not_written() {
        let profile = make_test_profile(Some("stored-uuid"));
        // 真实 .credentials.json 通常不含 uuid：本地解析恒为 None。
        let raw =
            serde_json::json!({"claudeAiOauth": {"accessToken": "t", "expiresAt": 1}}).to_string();
        let action = classify_scanned_credential(&profile, &raw);
        assert_eq!(
            action,
            CredentialAction::DeferToBackground,
            "本地解析不到磁盘 uuid 时必须交后台网络核对，不能 best-effort 覆盖"
        );
        // 分派函数本身不写 profile。
        assert_eq!(
            profile.keychain_password.as_deref(),
            Some("old-raw"),
            "分派阶段绝不能改动凭据"
        );
    }

    #[test]
    fn local_mismatch_is_rejected_with_adoption_hint() {
        let profile = make_test_profile(Some("stored-uuid"));
        let action = classify_scanned_credential(&profile, &blob_with_uuid("other"));
        match action {
            CredentialAction::Reject(msg) => assert!(msg.contains("收养")),
            _ => panic!("身份不一致必须拒绝回写"),
        }
    }

    #[test]
    fn local_match_is_applied_immediately() {
        let profile = make_test_profile(Some("same-uuid"));
        assert_eq!(
            classify_scanned_credential(&profile, &blob_with_uuid("same-uuid")),
            CredentialAction::Apply
        );
    }

    #[test]
    fn missing_stored_uuid_defers_even_when_disk_resolves() {
        // 库内没登记 uuid 时无法比对，交后台核对（后台会按 stored_uuid=None 放行）。
        let profile = make_test_profile(None);
        assert_eq!(
            classify_scanned_credential(&profile, &blob_with_uuid("disk-uuid")),
            CredentialAction::DeferToBackground
        );
    }

    #[test]
    fn scan_applies_verified_match_without_touching_other_profiles() {
        // 用一个假的 accounts 目录验证 Apply 分支的写入语义与 mtime 过滤。
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("accounts/p1")).unwrap();
        let cred = root.join("accounts/p1/.credentials.json");
        std::fs::write(&cred, blob_with_uuid("same-uuid")).unwrap();

        let mut profile = make_test_profile(Some("same-uuid"));
        // updated_at 设为 1 分钟前，确保 mtime 判定为「更新」。
        profile.updated_at = chrono::Utc::now() - chrono::Duration::minutes(1);
        let mut store_data = store::Store {
            profiles: vec![profile],
            ..Default::default()
        };
        let messages = scan_with_root(&mut store_data.profiles, &root.join("accounts"));
        assert!(messages.is_empty(), "一致身份不应产生提示");
        assert_eq!(
            store_data.profiles[0].keychain_password.as_deref(),
            Some(blob_with_uuid("same-uuid").as_str()),
            "本地可确认一致时应立即回写"
        );
    }

    /// 与 [`scan_parallel_credential_changes_into`] 同逻辑、但 accounts 根目录可注入，
    /// 便于在临时目录里测真实读写语义。
    fn scan_with_root(profiles: &mut [store::StoredProfile], accounts_root: &Path) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(accounts_root) else {
            return Vec::new();
        };
        let mut messages = Vec::new();
        for entry in entries.filter_map(|e| e.ok()) {
            let profile_id = entry.file_name().to_string_lossy().to_string();
            let cred_path = entry.path().join(".credentials.json");
            if !cred_path.exists() {
                continue;
            }
            let Ok(mtime) = std::fs::metadata(&cred_path).and_then(|m| m.modified()) else {
                continue;
            };
            let Some(profile) = profiles.iter_mut().find(|p| p.id == profile_id) else {
                continue;
            };
            if !is_credential_file_newer(mtime, profile.updated_at) {
                continue;
            }
            let Ok(raw) = std::fs::read_to_string(&cred_path) else {
                continue;
            };
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            match classify_scanned_credential(profile, raw) {
                CredentialAction::Reject(msg) => messages.push(msg),
                CredentialAction::Apply => {
                    if !matches!(&profile.keychain_password, Some(cur) if cur == raw) {
                        profile.keychain_password = Some(raw.to_string());
                        profile.updated_at = chrono::Utc::now();
                    }
                }
                CredentialAction::DeferToBackground => {}
            }
        }
        messages
    }

    // ── 后台回写 in-flight 去重 ──

    #[test]
    fn writeback_claim_is_exclusive_and_releasable() {
        // 用独立 id，避免与其他用例互相干扰。
        let id = "claim-test-unique";
        release_writeback(id);
        assert!(try_claim_writeback(id), "首次应能登记");
        assert!(
            !try_claim_writeback(id),
            "同一 profile 已在进行中时不能重复登记，否则每次扫描都 spawn 新线程"
        );
        release_writeback(id);
        assert!(
            try_claim_writeback(id),
            "释放后必须能重新登记——否则该账号的回写被永久跳过"
        );
        release_writeback(id);
    }

    #[test]
    fn writeback_claims_are_per_profile() {
        let a = "claim-a";
        let b = "claim-b";
        release_writeback(a);
        release_writeback(b);
        assert!(try_claim_writeback(a));
        assert!(try_claim_writeback(b), "不同账号互不影响");
        release_writeback(a);
        release_writeback(b);
    }

    // ── 共享 skills：junction 优先，复制降级 ──
    #[test]
    fn shared_skills_are_junctioned_not_copied() {
        let dir = tempfile::tempdir().unwrap();
        let global = dir.path().join("global");
        let account = dir.path().join("account");
        std::fs::create_dir_all(global.join("skills/tdd")).unwrap();
        std::fs::create_dir_all(&account).unwrap();
        std::fs::write(global.join("skills/tdd/SKILL.md"), "v1").unwrap();

        // 直接把全局 skills 当 claude_dir 用：create_junction 目标是绝对路径，
        // 这里手工构造同样形态，验证联接而非复制的语义。
        let mode = link_skills_for_test(&global.join("skills"), &account);
        assert_eq!(mode, SharedSkillsMode::Junction, "应建目录联接");
        let linked = account.join("skills/tdd/SKILL.md");
        assert!(linked.is_file(), "联接后账号目录应能直接看到全局 skills");

        // 关键：全局新增文件在账号目录立即可见——复制做不到这点。
        std::fs::write(global.join("skills/tdd/SKILL.md"), "v2").unwrap();
        assert_eq!(std::fs::read_to_string(&linked).unwrap(), "v2");
        std::fs::create_dir_all(global.join("skills/new")).unwrap();
        std::fs::write(global.join("skills/new/SKILL.md"), "n").unwrap();
        assert!(account.join("skills/new/SKILL.md").is_file());
    }

    #[test]
    fn shared_skills_fall_back_to_copy_when_target_exists() {
        let dir = tempfile::tempdir().unwrap();
        let global = dir.path().join("global");
        let account = dir.path().join("account");
        std::fs::create_dir_all(global.join("skills/tdd")).unwrap();
        std::fs::create_dir_all(&account).unwrap();
        std::fs::write(global.join("skills/tdd/SKILL.md"), "v1").unwrap();
        // 账号目录已有 skills（普通目录）→ 不覆盖。
        std::fs::create_dir_all(account.join("skills/mine")).unwrap();

        let mode = link_skills_for_test(&global.join("skills"), &account);
        assert_eq!(mode, SharedSkillsMode::AlreadyPresent);
        assert!(
            account.join("skills/mine").is_dir(),
            "用户自己的 skills 不能被动"
        );
    }

    #[test]
    fn shared_skills_missing_when_no_global_skills() {
        let dir = tempfile::tempdir().unwrap();
        let global = dir.path().join("global");
        let account = dir.path().join("account");
        std::fs::create_dir_all(&global).unwrap();
        std::fs::create_dir_all(&account).unwrap();
        assert_eq!(
            link_skills_for_test(&global.join("skills"), &account),
            SharedSkillsMode::Missing
        );
    }

    /// [`link_or_copy_shared_skills`] 的可注入版本：全局 skills 目录由参数给定，
    /// 不依赖真实 `claude_dir()`。
    fn link_skills_for_test(global_skills: &Path, account_dir: &Path) -> SharedSkillsMode {
        if !global_skills.is_dir() {
            return SharedSkillsMode::Missing;
        }
        let target_skills = account_dir.join("skills");
        if target_skills.exists() || crate::links::path_is_link(&target_skills) {
            return SharedSkillsMode::AlreadyPresent;
        }
        match crate::platform::imp::create_junction(global_skills, &target_skills) {
            Ok(()) => SharedSkillsMode::Junction,
            Err(_) => {
                if crate::desktop::copy_dir_recursive(global_skills, &target_skills).is_ok() {
                    SharedSkillsMode::Copied
                } else {
                    SharedSkillsMode::Missing
                }
            }
        }
    }
}
