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
fn ensure_parallel_account_dir(profile: &StoredProfile) -> Result<PathBuf, String> {
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

/// 把并行终端里已刷新过的 `.credentials.json` 原文回写到账号库（best-effort）。
///
/// 并行终端里 claude 刷新令牌后，磁盘上的 `.credentials.json` 是新的，但账号库里
/// 快照的 `keychain_password` 还是旧的。下次切号/备份/导出时若拿旧快照覆盖，会把刚
/// 刷新的令牌废掉。这里在开并行终端时检测一次：文件已存在且与库中值不同，就把新值
/// 同步回去并刷新 `updated_at`。
///
/// 整个函数 best-effort：任何内部错误都只记日志、不向上抛——开终端不能因为同步失败
/// 而被阻断。找不到对应 profile 视为 no-op。
fn sync_parallel_credentials_back(profile_id: &str, raw_cred: &str) {
    let result = store::with_store(|s| {
        let Some(profile) = s.profiles.iter_mut().find(|p| p.id == profile_id) else {
            return Ok(());
        };
        let same = matches!(&profile.keychain_password, Some(cur) if cur == raw_cred);
        if !same {
            profile.keychain_password = Some(raw_cred.to_string());
            profile.updated_at = chrono::Utc::now();
        }
        Ok::<(), String>(())
    });
    if let Err(e) = result {
        crate::log_error(&format!(
            "回写并行终端凭据到账号库失败（best-effort，已忽略）: profile={profile_id}, err={e}"
        ));
    }
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
}
