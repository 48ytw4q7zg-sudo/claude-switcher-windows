//! 按终端并行多账号（P1-3）。
//!
//! 与「全局切换」（接管唯一的 `~/.claude`）不同：并行模式为每个账号开一个独立
//! 终端，终端里把 `CLAUDE_CONFIG_DIR` 指向 `~/.claude-switcher/accounts/<id>/`，
//! 该目录持有该账号的凭据与 settings，于是多个终端可同时登录不同账号。
//! 终端启动用 `wt.exe powershell -EncodedCommand`（UTF-16LE base64），
//! 未装 Windows Terminal 时退回 `cmd start powershell`（显示窗口）。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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

    // 共享 skills：全局配置目录的 skills 若账号目录还没有，则复制（best-effort）。
    copy_shared_skills(&dir);

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

/// J-3/K-1 核心：在已借用的 profile 上做身份校验并按需回写凭据。
///
/// `disk_uuid` 为已解析到的磁盘账号 uuid（本地解析或网络 profile 核对），
/// `conservative_when_unknown` 决定磁盘 uuid 缺失时的策略：
/// - 两者都能解析且**不一致** → 拒绝回写，返回提示「该并行目录已换成别的账号，
///   可收养为新账号」，绝不覆盖；
/// - `disk_uuid=None` 且 `conservative_when_unknown=true`（后台网络路径）→
///   查不到身份，保守不覆盖，留待下次托盘刷新再试；
/// - 其余（一致，或本地路径 uuid 缺失）→ best-effort 回写，值不同才更新。
///
/// 返回 Some(提示) 时调用方负责展示/记录。
fn verify_and_apply_credential_inner(
    profile: &mut StoredProfile,
    raw: &str,
    disk_uuid: Option<&str>,
    conservative_when_unknown: bool,
) -> Option<String> {
    let stored_uuid = stored_profile_uuid(profile);
    if let (Some(disk), Some(stored)) = (disk_uuid, stored_uuid) {
        if disk != stored {
            return Some(format!(
                "并行目录「{}」已换成别的账号（磁盘账号 {disk} ≠ 登记账号 {stored}），已拒绝回写以免覆盖；可在界面把它收养为新账号。",
                profile.name
            ));
        }
    }
    if disk_uuid.is_none() && conservative_when_unknown {
        // 网络核对查不到身份：保守不覆盖，下次托盘刷新再试。
        return None;
    }
    let same = matches!(&profile.keychain_password, Some(cur) if cur == raw);
    if !same {
        profile.keychain_password = Some(raw.to_string());
        profile.updated_at = chrono::Utc::now();
    }
    None
}

/// J-3：本地解析磁盘 uuid 后做身份校验（纯本地、不联网）。
///
/// 本地无法解析 uuid 时沿用 best-effort 回写（`conservative=false`），
/// 供持锁的 in-store 扫描路径使用——那里不能做阻塞联网。
/// 返回 Some(提示) 时调用方负责展示/记录。
fn verify_and_apply_credential(profile: &mut StoredProfile, raw: &str) -> Option<String> {
    let disk_uuid = credential_blob_account_uuid(raw);
    verify_and_apply_credential_inner(profile, raw, disk_uuid.as_deref(), false)
}

/// K-1：用已核对好的磁盘 uuid（网络 profile）做身份校验，查不到身份时保守不覆盖。
fn verify_and_apply_credential_checked(
    profile: &mut StoredProfile,
    raw: &str,
    disk_uuid: Option<&str>,
) -> Option<String> {
    verify_and_apply_credential_inner(profile, raw, disk_uuid, true)
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
/// 立即返回、不阻塞开终端。任何内部错误都只记日志；找不到对应 profile 视为 no-op。
fn sync_parallel_credentials_back(profile_id: &str, raw_cred: &str) {
    let (id, raw) = (profile_id.to_string(), raw_cred.to_string());
    std::thread::spawn(move || {
        // 网络核对（约 4 秒超时，命中缓存则更快）；失败 → None。
        let disk_uuid = crate::usage::oauth_account_uuid_for_blob(&raw);
        let result = store::with_store(|s| {
            let Some(profile) = s.profiles.iter_mut().find(|p| p.id == id) else {
                return Ok(());
            };
            if let Some(warn) =
                verify_and_apply_credential_checked(profile, &raw, disk_uuid.as_deref())
            {
                crate::log_error(&warn);
            }
            Ok::<(), String>(())
        });
        if let Err(e) = result {
            crate::log_error(&format!(
                "回写并行终端凭据到账号库失败（best-effort，已忽略）: profile={id}, err={e}"
            ));
        }
    });
}

/// J-3 同步点：扫描 `accounts/*/.credentials.json`，把并行终端刷新的令牌回写账号库。
///
/// 仅处理 **mtime 晚于 profile.updated_at** 的凭据文件；身份校验（含「可收养为新账号」
/// 拒绝）复用 [`verify_and_apply_credential`]。该版本接收已借用的 store，供
/// `switch_profile_blocking`（已持 with_store 锁，不能再嵌套取锁）调用。
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
        if let Some(msg) = verify_and_apply_credential(profile, raw) {
            messages.push(msg);
        }
    }
    messages
}

/// J-3 同步点（托盘刷新用）：在一次 with_store 事务内扫描并回写并行凭据变化。
pub fn scan_parallel_credential_changes() -> Result<Vec<String>, String> {
    store::with_store(|s| Ok(scan_parallel_credential_changes_into(s)))
}

/// 从全局 `~/.claude/skills` 复制共享 skills 到账号目录（best-effort，不阻断）。
fn copy_shared_skills(account_dir: &Path) {
    let Ok(global_dir) = crate::credentials::claude_dir() else {
        return;
    };
    let global_skills = global_dir.join("skills");
    let target_skills = account_dir.join("skills");
    if global_skills.is_dir() && !target_skills.exists() {
        let _ = crate::desktop::copy_dir_recursive(&global_skills, &target_skills);
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

    #[test]
    fn rejects_write_when_identity_mismatch_and_keeps_old_credential() {
        let mut profile = make_test_profile(Some("stored-uuid"));
        let raw = blob_with_uuid("different-disk");
        let warn = verify_and_apply_credential(&mut profile, &raw);
        assert!(warn.is_some(), "身份不一致必须返回提示");
        assert!(warn.unwrap().contains("收养"));
        assert_eq!(
            profile.keychain_password.as_deref(),
            Some("old-raw"),
            "拒绝回写时原凭据绝不能被覆盖"
        );
    }

    #[test]
    fn applies_when_identity_matches() {
        let mut profile = make_test_profile(Some("same-uuid"));
        let raw = blob_with_uuid("same-uuid");
        assert!(verify_and_apply_credential(&mut profile, &raw).is_none());
        assert_eq!(profile.keychain_password.as_deref(), Some(raw.as_str()));
    }

    #[test]
    fn best_effort_apply_when_disk_uuid_unparseable() {
        let mut profile = make_test_profile(Some("stored-uuid"));
        let raw = serde_json::json!({ "no_uuid": true }).to_string();
        // 本地无法解析磁盘 uuid → 不阻断，best-effort 回写。
        assert!(verify_and_apply_credential(&mut profile, &raw).is_none());
        assert_eq!(profile.keychain_password.as_deref(), Some(raw.as_str()));
    }

    // ── K-1 后台网络核对路径 ──

    #[test]
    fn checked_conservative_skips_write_when_identity_unknown() {
        let mut profile = make_test_profile(Some("stored-uuid"));
        let raw = "new-raw-cred";
        // 网络查不到身份（None）→ 保守不覆盖，也无警告。
        let warn = verify_and_apply_credential_checked(&mut profile, raw, None);
        assert!(warn.is_none());
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
        let warn = verify_and_apply_credential_checked(&mut profile, raw, Some("other-uuid"));
        assert!(warn.is_some());
        assert!(warn.unwrap().contains("收养"));
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
        assert!(
            verify_and_apply_credential_checked(&mut profile, raw, Some("same-uuid")).is_none()
        );
        assert_eq!(profile.keychain_password.as_deref(), Some(raw));
    }

    #[test]
    fn checked_applies_when_stored_uuid_unknown_but_network_resolves() {
        let mut profile = make_test_profile(None);
        let raw = "new-raw-cred";
        // 库内未登记 uuid，但网络能核对到身份 → 无冲突，允许回写。
        assert!(
            verify_and_apply_credential_checked(&mut profile, raw, Some("network-uuid")).is_none()
        );
        assert_eq!(profile.keychain_password.as_deref(), Some(raw));
    }

    #[test]
    fn mtime_filter_only_processes_newer_credential() {
        let now = chrono::Utc::now();
        let newer = std::time::SystemTime::from(now) + std::time::Duration::from_secs(60);
        let older = std::time::SystemTime::from(now) - std::time::Duration::from_secs(60);
        assert!(is_credential_file_newer(newer, now), "mtime 更晚应处理");
        assert!(!is_credential_file_newer(older, now), "陈旧文件应跳过");
    }
}
