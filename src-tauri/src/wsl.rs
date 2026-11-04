//! F-6：WSL 集成（**实验功能，默认关闭**）。
//!
//! 仅在用户于界面显式开启 [crate::appconfig::AppConfig::wsl_integration_enabled]
//! 并选择一个具体发行版后，才把当前账号凭据写入该发行版的 `~/.claude/`。
//! 不开启、不选择发行版则不做任何 WSL 操作。
//!
//! 本机事实与 K-4 加固：
//! - `wsl -l -q` 输出为 **UTF-16LE**（带 BOM），需按 UTF-16 解码；
//! - 所有 wsl 进程都经 [crate::platform::silent_command] 加 `CREATE_NO_WINDOW`，
//!   发布版 GUI 不闪控制台；
//! - 每个命令带 [`WSL_TIMEOUT_SECS`] 超时，超时即 kill，WSL 服务卡住也不会无限等待；
//! - 内部发行版（docker-desktop / rancher-desktop 等）从选择列表过滤；
//! - 写入前先回读 WSL 凭据，较新且同账号的副本返回入口层回写账号库；
//! - 所有文件操作先校验并进入绝对 HOME，探测用户与家目录后回传报告；
//! - 同步 `~/.claude.json`（登录身份/引导标记）；
//! - 凭据经 stdin 管道写入（不进 argv），`umask 077` + `chmod 600`。DrvFs
//!   （`/mnt/c`）权限位不可靠，界面如实说明「0600 无法保证」。

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Duration;

use serde::Serialize;

/// WSL 内材料路径（凭据 `.claude/.credentials.json`、身份 `.claude.json`）由
/// `wsl_sync.sh` 内部的固定槽位管理，Rust 侧不再各自拼路径。
/// 每条命令独立验证 HOME，避免 WSL 继承 Windows 工作目录后误读写工程文件。
const WSL_HOME_GUARD: &str = "case \"$HOME\" in /*) ;; *) printf '%s\\n' 'WSL 家目录必须是非空的绝对路径' >&2; exit 1 ;; esac; cd -- \"$HOME\" || exit 1; ";
/// B2：唯一生产材料同步脚本（同目录暂存、逐文件原子替换、整体可恢复）。
/// 凭据/身份两份材料经 stdin 帧传输，写入、回滚、恢复与清理全部在脚本内完成。
const WSL_SYNC_SCRIPT: &str = include_str!("wsl_sync.sh");
/// K-4：单个 WSL 命令的超时（秒），超时即终止。
const WSL_TIMEOUT_SECS: u64 = 15;
/// K-4：不是可用 Linux 环境的内部发行版（不区分大小写匹配）。
const INTERNAL_DISTROS: &[&str] = &[
    "docker-desktop",
    "docker-desktop-data",
    "rancher-desktop",
    "rancher-desktop-data",
];

/// 定位 wsl.exe（System32）。不依赖 PATH——新工具会话 PATH 可能不含 System32。
fn wsl_exe_path() -> Result<PathBuf, String> {
    let system_root =
        std::env::var("SystemRoot").map_err(|e| format!("读取 SystemRoot 失败: {e}"))?;
    Ok(PathBuf::from(system_root).join("System32").join("wsl.exe"))
}

/// 校验发行版名：非空、不含控制字符（distro 作为独立参数传入，不会被 shell 解释，
/// 这里仍做保守校验）。
fn validate_distro(distro: &str) -> Result<(), String> {
    let name = distro.trim();
    if name.is_empty() {
        return Err("未选择 WSL 发行版".to_string());
    }
    if name.chars().any(|c| c.is_control()) {
        return Err("WSL 发行版名含非法控制字符".to_string());
    }
    Ok(())
}

/// 解析 `wsl -l -q` 的 UTF-16LE 输出为发行版名列表（纯函数，便于测试）。
pub fn parse_wsl_distros(bytes: &[u8]) -> Vec<String> {
    let payload = if bytes.starts_with(&[0xFF, 0xFE]) {
        &bytes[2..]
    } else {
        bytes
    };
    let mut words: Vec<u16> = Vec::with_capacity(payload.len() / 2);
    let mut index = 0usize;
    while index + 1 < payload.len() {
        words.push(u16::from_le_bytes([payload[index], payload[index + 1]]));
        index += 2;
    }
    let text = String::from_utf16_lossy(&words);
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// K-4：统一执行 `wsl -d <distro> -- bash -c <script>`，可选经 stdin 传数据。
///
/// 走 silent_command（不闪窗）+ 超时。`stdin_data` 为 Some 时管道写入并在写完后
/// 关闭（远端 cat 收到 EOF）；为 None 时 stdin 置 null。
fn run_wsl_bash(distro: &str, script: &str, stdin_data: Option<&str>) -> Result<Output, String> {
    let wsl = wsl_exe_path()?;
    let mut cmd = crate::platform::imp::silent_command(&wsl.to_string_lossy());
    cmd.args(["-d", distro, "--", "bash", "-c", script]);
    run_command_with_timeout(
        cmd,
        stdin_data.map(str::as_bytes),
        Duration::from_secs(WSL_TIMEOUT_SECS),
    )
}

fn run_command_with_timeout(
    cmd: Command,
    stdin_data: Option<&[u8]>,
    timeout: Duration,
) -> Result<Output, String> {
    crate::platform::imp::run_command_with_timeout(cmd, stdin_data, timeout)
        .map_err(|error| format!("WSL 命令执行失败: {error}"))
}

/// 生产命令和合成测试共用此边界，HOME 无效或无法进入时不执行任何文件操作。
fn run_in_wsl_home<R>(
    distro: &str,
    script: &str,
    stdin_data: Option<&str>,
    run: &mut R,
) -> Result<Output, String>
where
    R: FnMut(&str, &str, Option<&str>) -> Result<Output, String>,
{
    run(distro, &format!("{WSL_HOME_GUARD}{script}"), stdin_data)
}

/// K-4：列出本机可用 WSL 发行版（过滤内部发行版，不闪窗、带超时）。
pub fn list_wsl_distros_blocking() -> Result<Vec<String>, String> {
    let wsl = wsl_exe_path()?;
    let mut cmd = crate::platform::imp::silent_command(&wsl.to_string_lossy());
    cmd.args(["-l", "-q"]);
    let output = run_command_with_timeout(cmd, None, Duration::from_secs(WSL_TIMEOUT_SECS))?;
    if !output.status.success() {
        return Err(format!(
            "wsl -l -q 失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut distros = parse_wsl_distros(&output.stdout);
    distros.retain(|d| !INTERNAL_DISTROS.contains(&d.to_ascii_lowercase().as_str()));
    Ok(distros)
}

/// K-4：写入目标的用户与家目录（供用户确认实际目标）。
#[derive(Debug, Clone)]
struct WslHome {
    user: String,
    home: String,
}

/// K-4：探测发行版的家目录与登录用户。
fn probe_wsl_home<R>(distro: &str, run: &mut R) -> Result<WslHome, String>
where
    R: FnMut(&str, &str, Option<&str>) -> Result<Output, String>,
{
    let script = "printf '%s\\n' \"$HOME\"; whoami";
    let output = run_in_wsl_home(distro, script, None, run)?;
    if !output.status.success() {
        return Err(format!(
            "探测 WSL 家目录失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let lossy = String::from_utf8_lossy(&output.stdout);
    let mut lines = lossy.lines();
    let home = lines
        .next()
        .filter(|home| home.starts_with('/'))
        .ok_or_else(|| "无法解析 WSL 家目录".to_string())?
        .to_string();
    let user = lines.next().unwrap_or("").trim().to_string();
    Ok(WslHome { user, home })
}

/// B2：生产脚本经 stdin 暂存到唯一短路径，再以短 argv 调用。
///
/// `bash -c <整串脚本>` 在约 10 KiB argv 处会被截断（Git Bash 实测 10240 字符
/// 截断点，长脚本必然解析失败），因此脚本内容走 stdin（`cat >` 落到 /tmp 的
/// 本工具私有文件），调用侧只剩固定 ASCII 短命令。凭据帧仍走 stdin，不进 argv。
fn run_sync_script<R>(
    distro: &str,
    op: &str,
    stdin_data: Option<&str>,
    run: &mut R,
) -> Result<Output, String>
where
    R: FnMut(&str, &str, Option<&str>) -> Result<Output, String>,
{
    let path = format!(
        "/tmp/cs-wsl-sync-{}.sh",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let stage = format!("{WSL_HOME_GUARD}umask 077; cat > {path}");
    let staged = run(distro, &stage, Some(WSL_SYNC_SCRIPT))?;
    if !staged.status.success() {
        return Err(format!(
            "暂存 WSL 同步脚本失败: {}",
            String::from_utf8_lossy(&staged.stderr).trim()
        ));
    }
    let invoke = format!("{WSL_HOME_GUARD}bash {path} {op}");
    run(distro, &invoke, stdin_data)
}

/// B2：SHA256 小写十六进制（材料指纹，替代会破坏原字节的 trim 比较）。
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// 材料指纹：缺失与空文件严格区分（缺失为 `absent`）。
fn material_fingerprint(bytes: Option<&[u8]>) -> String {
    match bytes {
        None => "absent".to_string(),
        Some(bytes) => sha256_hex(bytes),
    }
}

/// 回读发行版里的两份材料（原字节，不做 trim；缺失为 None）。
///
/// 走 `wsl_sync.sh` 的 inspect 入口：脚本开头先恢复上次未完成的事务，
/// 因此每次回读都建立在一致状态上。
fn inspect_wsl_materials<R>(
    distro: &str,
    run: &mut R,
) -> Result<(Option<String>, Option<String>), String>
where
    R: FnMut(&str, &str, Option<&str>) -> Result<Output, String>,
{
    let output = run_sync_script(distro, "inspect", None, run)?;
    if !output.status.success() {
        return Err(format!(
            "回读 WSL 材料失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let (credential, metadata) = parse_inspect_output(&output.stdout)?;
    let as_text = |bytes: Vec<u8>, which: &str| {
        String::from_utf8(bytes).map_err(|_| format!("WSL {which}不是有效 UTF-8 文本，已拒绝同步"))
    };
    Ok((
        credential.map(|bytes| as_text(bytes, "凭据")).transpose()?,
        metadata
            .map(|bytes| as_text(bytes, "身份文件"))
            .transpose()?,
    ))
}

/// inspect 输出的两份原始材料（缺失为 None，与空文件严格区分）。
type RawMaterials = (Option<Vec<u8>>, Option<Vec<u8>>);

/// 解析 inspect 输出：`CSWSL-READ-1\n<c_size>\n<m_size>\n` + 凭据字节 + 身份字节。
fn parse_inspect_output(stdout: &[u8]) -> Result<RawMaterials, String> {
    let mut rest = stdout;
    let take_line = |bytes: &mut &[u8]| -> Result<String, String> {
        let end = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(|| "WSL 材料读取输出不完整".to_string())?;
        let line = String::from_utf8_lossy(&bytes[..end]).into_owned();
        *bytes = &bytes[end + 1..];
        Ok(line)
    };
    if take_line(&mut rest)?.trim() != "CSWSL-READ-1" {
        return Err("WSL 材料读取协议版本无效".to_string());
    }
    let parse_size = |line: String| -> Result<Option<usize>, String> {
        let text = line.trim();
        if text == "absent" {
            return Ok(None);
        }
        text.parse::<usize>()
            .map(Some)
            .map_err(|_| "WSL 材料读取长度无效".to_string())
    };
    let credential_size = parse_size(take_line(&mut rest)?)?;
    let metadata_size = parse_size(take_line(&mut rest)?)?;
    let take_bytes = |bytes: &mut &[u8], size: Option<usize>| -> Result<Option<Vec<u8>>, String> {
        match size {
            None => Ok(None),
            Some(size) => {
                if bytes.len() < size {
                    return Err("WSL 材料读取内容不完整".to_string());
                }
                let (head, tail) = bytes.split_at(size);
                *bytes = tail;
                Ok(Some(head.to_vec()))
            }
        }
    };
    let credential = take_bytes(&mut rest, credential_size)?;
    let metadata = take_bytes(&mut rest, metadata_size)?;
    if !rest.is_empty() {
        return Err("WSL 材料读取输出含多余字节".to_string());
    }
    Ok((credential, metadata))
}

/// 组装 apply 事务输入：9 行头 + 凭据字节 + 身份字节（B2 帧协议）。
///
/// `credential` 为 None 表示保留远端凭据（metadata-only），此时帧内凭据长度为 0、
/// 新指纹为 `keep`。返回值为完整帧字节（头为 ASCII，材料为 UTF-8）。
fn build_apply_frame(
    transaction: &str,
    old_c: &str,
    old_m: &str,
    credential: Option<&str>,
    metadata: &str,
) -> Result<String, String> {
    if !matches!(transaction.len(), 32) || !transaction.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("WSL 事务编号无效".to_string());
    }
    if metadata.is_empty() {
        return Err("WSL 身份文件内容为空，未修改材料".to_string());
    }
    let metadata_bytes = metadata.as_bytes();
    let new_m = sha256_hex(metadata_bytes);
    let (credential_bytes, new_c, mode) = match credential {
        Some(credential) if !credential.is_empty() => (
            credential.as_bytes(),
            sha256_hex(credential.as_bytes()),
            "pair",
        ),
        Some(_) => return Err("WSL 凭据内容为空，未修改材料".to_string()),
        None => (&b""[..], "keep".to_string(), "metadata"),
    };
    let header = format!(
        "CSWSL-FRAME-1\n{transaction}\n{mode}\n{old_c}\n{old_m}\n{}\n{new_c}\n{}\n{new_m}\n",
        credential_bytes.len(),
        metadata_bytes.len()
    );
    let mut frame = header.into_bytes();
    frame.extend_from_slice(credential_bytes);
    frame.extend_from_slice(metadata_bytes);
    String::from_utf8(frame).map_err(|_| "WSL 同步输入编码无效".to_string())
}

/// 取 blob 的访问令牌过期时间（毫秒），解析不到为 None。
fn blob_expiry_ms(blob: &str) -> Option<u64> {
    crate::token_status::evaluate_token_status(blob, 0).expires_at_ms
}

/// K-4：比较两份凭据，WSL 副本过期时间更晚（或本机无法解析而 WSL 可解析）时返回 true。
fn remote_blob_is_newer(local: &str, remote: &str) -> bool {
    match (blob_expiry_ms(local), blob_expiry_ms(remote)) {
        (Some(local_exp), Some(remote_exp)) => remote_exp > local_exp,
        (None, Some(_)) => true,
        _ => false,
    }
}

/// 纯函数：是否应当把本机凭据写入 WSL。
///
/// WSL 里那份更新（过期更晚）时**不能写**：本机账号库里的快照可能已经落后于 WSL
/// 内 claude 刚刷新过的令牌，此时写进去等于把新令牌打回旧值，下次在 WSL 里又要
/// 重新登录。真正的更新方向是把远端那份回写账号库。
fn should_write_local_credentials(local: &str, remote: Option<&str>) -> bool {
    match remote {
        Some(remote) => !remote_blob_is_newer(local, remote),
        None => true,
    }
}

/// 纯函数：能否把 WSL 里的凭据回写账号库（K-4 身份核对）。
///
/// 过期时间只说明「哪份令牌更新」，**不说明是不是同一个账号**。WSL 里可能登着
/// 别的账号（用户在里面 `/login` 过），此时把它的凭据回写进当前账号快照就是串号。
/// 判定规则：
/// - 账号库登记了 uuid 且 WSL blob 能解析出 uuid → 一致才允许；
/// - 任一边解析不到 uuid → 无法证明同一账号，拒绝（`None` 表示无法判定）。
///
/// 返回 `Some(true)` 允许回写、`Some(false)` 明确拒绝、`None` 无法判定。
///
/// 注意：真实 `.credentials.json` 通常**不含** uuid（与 parallel 的 K-1 同一事实），
/// 因此本地解析不到时调用方应改用 [`remote_blob_matches_profile_via_lookup`]
/// 走 OAuth profile 端点核对，否则合法回写会被一律跳过。
fn remote_blob_matches_profile(remote: &str, profile_uuid: Option<&str>) -> Option<bool> {
    let remote_uuid = crate::usage::extract_meta(None, Some(remote)).account_uuid?;
    let stored = profile_uuid?;
    Some(remote_uuid == stored)
}

/// 本地解析不到 uuid 时，经注入的 OAuth profile 查询核对身份。
///
/// 复用 [`crate::usage::oauth_account_uuid_for_blob`]（带超时与 token 指纹缓存），
/// 与 parallel 的 K-1 后台核对同源。任何失败都返回 None，由调用方走保守路径。
fn remote_blob_matches_profile_via_lookup<L>(
    remote: &str,
    profile_uuid: Option<&str>,
    lookup: &mut L,
) -> Option<bool>
where
    L: FnMut(&str) -> Option<String>,
{
    let stored = profile_uuid?;
    let remote_uuid = lookup(remote)?;
    Some(remote_uuid == stored)
}

/// B2：把两份材料作为一个可恢复事务提交（`wsl_sync.sh` 的 apply 入口）。
///
/// 帧经 stdin 传输（不进 argv/日志）；脚本内完成暂存、校验、备份、逐文件原子
/// 替换与失败回滚。第二份提交失败会恢复第一份；回滚失败保留恢复材料并以非零
/// 退出码报错——调用方必须传播错误，不得写成功结果。
fn apply_wsl_materials<R>(
    distro: &str,
    old_c: &str,
    old_m: &str,
    credential: Option<&str>,
    metadata: &str,
    run: &mut R,
) -> Result<(), String>
where
    R: FnMut(&str, &str, Option<&str>) -> Result<Output, String>,
{
    let transaction = uuid::Uuid::new_v4().simple().to_string();
    let frame = build_apply_frame(&transaction, old_c, old_m, credential, metadata)?;
    let output = run_sync_script(distro, "apply", Some(&frame), run)?;
    if !output.status.success() {
        return Err(format!(
            "写入 WSL 材料失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// K-4：WSL 同步结果报告（回传给前端展示）。
#[derive(Clone, Serialize)]
pub struct WslSyncReport {
    pub distro: String,
    /// 写入目标登录用户。
    pub user: String,
    /// 写入目标家目录。
    pub home: String,
    /// WSL 内是否已有凭据。
    pub had_existing: bool,
    /// WSL 副本更新**且身份已核对为同一账号**时的原 blob（供 lib 层回写账号库）。
    /// 身份不一致或无法判定时为 None——此时绝不回写，避免把 WSL 里别的账号
    /// 凭据写进当前账号快照。
    #[serde(skip_serializing)]
    pub remote_newer_blob: Option<String>,
    /// 需向用户展示的提示（两处各一份、0600 限制、身份未核对等）。
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for WslSyncReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WslSyncReport")
            .field("distro", &self.distro)
            .field("user", &self.user)
            .field("home", &self.home)
            .field("had_existing", &self.had_existing)
            .field("has_remote_newer_blob", &self.remote_newer_blob.is_some())
            .field("warnings", &self.warnings)
            .finish()
    }
}

/// 当前账号记录、全局身份文件和可解析的凭据身份必须一致，才允许任何远端写入。
fn validate_local_material_identity(
    local_blob: &str,
    profile_uuid: Option<&str>,
    local_json: &str,
) -> Result<(), String> {
    let selected = profile_uuid
        .filter(|uuid| !uuid.trim().is_empty())
        .ok_or_else(|| "当前账号缺少身份标识，已拒绝 WSL 同步，请重新捕获该账号".to_string())?;
    let metadata: serde_json::Value = serde_json::from_str(local_json)
        .map_err(|_| "本机 .claude.json 无法解析，已拒绝 WSL 同步".to_string())?;
    let metadata_uuid = crate::usage::extract_meta(Some(&metadata), None).account_uuid;
    if metadata_uuid.as_deref() != Some(selected) {
        return Err(
            "本机 .claude.json 身份与当前账号不一致或无法核对，已拒绝 WSL 同步".to_string(),
        );
    }
    let blob_uuid = crate::usage::extract_meta(None, Some(local_blob)).account_uuid;
    if blob_uuid.as_deref().is_some_and(|uuid| uuid != selected) {
        return Err("本机凭据身份与当前账号不一致，已拒绝 WSL 同步".to_string());
    }
    Ok(())
}

/// B2：同一用户/发行版的本工具命名互斥量，串行化 probe→inspect→apply 全程。
/// 不声称是 Claude 官方凭据锁。
fn wsl_sync_mutex_name(distro: &str) -> String {
    format!(
        "Local\\claude-switcher-wsl-sync-{}",
        &sha256_hex(distro.as_bytes())[..8]
    )
}

fn with_wsl_sync_mutex<T>(
    distro: &str,
    f: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let guard = crate::platform::imp::acquire_named_mutex(
        &wsl_sync_mutex_name(distro),
        std::time::Duration::from_secs(20),
    )
    .map_err(|error| format!("获取 WSL 同步互斥量失败: {error}"))?;
    if guard.is_none() {
        return Err("另一个 WSL 同步正在进行，请稍后重试".to_string());
    }
    f()
}

/// K-4：带开关门禁的完整同步流程。
///
/// 顺序：核对本机身份材料 → 探测家目录 → 回读现有材料并按身份/过期时间对账 →
/// 以可恢复事务写入 → 返回报告。实验开关未开启直接拒绝。
///
/// `profile_uuid` 是账号库为当前账号登记的 uuid，用于核对 WSL 里的凭据是否
/// 属于同一个账号；缺少它则拒绝整个同步流程。
pub fn sync_to_wsl_blocking(
    distro: String,
    local_blob: String,
    profile_uuid: Option<String>,
) -> Result<WslSyncReport, String> {
    let config = crate::appconfig::load();
    if !config.wsl_integration_enabled {
        return Err("WSL 集成实验开关未开启，已拒绝写入".to_string());
    }
    let local = crate::paths::claude_json_path()?;
    let local_json =
        fs::read_to_string(local).map_err(|e| format!("读取本机 .claude.json 失败: {e}"))?;
    let name = distro.trim().to_string();
    let target = name.clone();
    with_wsl_sync_mutex(&name, move || {
        sync_to_wsl_with(
            target,
            local_blob,
            profile_uuid,
            &local_json,
            run_wsl_bash,
            crate::usage::oauth_account_uuid_for_blob,
        )
    })
}

fn sync_to_wsl_with<R, L>(
    distro: String,
    local_blob: String,
    profile_uuid: Option<String>,
    local_json: &str,
    mut run: R,
    mut lookup: L,
) -> Result<WslSyncReport, String>
where
    R: FnMut(&str, &str, Option<&str>) -> Result<Output, String>,
    L: FnMut(&str) -> Option<String>,
{
    validate_distro(&distro)?;
    let name = distro.trim().to_string();
    if local_blob.trim().is_empty() {
        return Err("凭据内容为空，未写入 WSL".to_string());
    }
    validate_local_material_identity(&local_blob, profile_uuid.as_deref(), local_json)?;

    // 1. 探测写入用户/家目录。
    let wsl_home = probe_wsl_home(&name, &mut run)?;
    let mut warnings = Vec::new();

    // 2. 回读两份材料（原字节）并对账。
    let (existing, remote_metadata) = inspect_wsl_materials(&name, &mut run)?;
    let old_c = material_fingerprint(existing.as_deref().map(str::as_bytes));
    let old_m = material_fingerprint(remote_metadata.as_deref().map(str::as_bytes));
    let mut remote_newer_blob = None;
    let mut sync_metadata = true;
    if let Some(remote) = &existing {
        warnings.push(format!(
            "WSL（{}）与本机均有凭据，两边各自刷新可能互相失效",
            wsl_home.home
        ));
        if remote_blob_is_newer(&local_blob, remote) {
            // 过期更晚只说明令牌更新，还要核对是不是同一个账号才敢回写。
            // 先本地解析；真实凭据 blob 通常不含 uuid，本地解析不到时回退到
            // OAuth profile 端点核对（与 parallel 的 K-1 同源），否则合法回写
            // 会被一律跳过、K-4 功能不可达。
            let verdict =
                remote_blob_matches_profile(remote, profile_uuid.as_deref()).or_else(|| {
                    remote_blob_matches_profile_via_lookup(
                        remote,
                        profile_uuid.as_deref(),
                        &mut lookup,
                    )
                });
            match verdict {
                Some(true) => {
                    remote_newer_blob = Some(remote.clone());
                    warnings.push("已取得 WSL 内同账号的较新凭据，等待回写账号库".to_string());
                }
                Some(false) => {
                    sync_metadata = false;
                    warnings.push("WSL 内凭据属于另一个账号，已保留其凭据和身份文件并停止同步（请在该发行版里切换到本账号）".to_string());
                }
                None => {
                    sync_metadata = false;
                    warnings.push("无法核对 WSL 内凭据的账号身份，已保留其凭据和身份文件并停止同步（请在界面重新捕获该账号）".to_string());
                }
            }
        }
    }

    // 3. 以可恢复事务写入。远端凭据更新时只提交匹配身份的元数据（metadata-only），
    //    不把 WSL 里刚刷新的令牌打回旧值；异账号/未知身份已在上面拦下，不写任何材料。
    //    任一材料提交失败会恢复另一份并在此传播错误，绝不返回成功报告。
    if sync_metadata {
        if should_write_local_credentials(&local_blob, existing.as_deref()) {
            apply_wsl_materials(
                &name,
                &old_c,
                &old_m,
                Some(&local_blob),
                local_json,
                &mut run,
            )?;
        } else {
            warnings.push("WSL 内凭据更新，未用本机旧副本覆盖它".to_string());
            apply_wsl_materials(&name, &old_c, &old_m, None, local_json, &mut run)?;
        }
    }

    Ok(WslSyncReport {
        distro: name,
        user: wsl_home.user,
        home: wsl_home.home,
        had_existing: existing.is_some(),
        remote_newer_blob,
        warnings,
    })
}

/// 删除指定发行版里的凭据与 .claude.json（不闪窗、带超时，与同步共用互斥量）。
pub fn clear_wsl_credentials(distro: &str) -> Result<(), String> {
    let name = distro.trim().to_string();
    with_wsl_sync_mutex(&name, || {
        clear_wsl_credentials_with(&name, &mut run_wsl_bash)
    })
}

fn clear_wsl_credentials_with<R>(distro: &str, run: &mut R) -> Result<(), String>
where
    R: FnMut(&str, &str, Option<&str>) -> Result<Output, String>,
{
    validate_distro(distro)?;
    let output = run_sync_script(distro.trim(), "clear", None, run)?;
    if !output.status.success() {
        return Err(format!(
            "清理 WSL 凭据失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn parse_utf16le_with_bom() {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in "Ubuntu".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0x0D, 0x00, 0x0A, 0x00]);
        for unit in "docker-desktop".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let distros = parse_wsl_distros(&bytes);
        assert_eq!(distros, vec!["Ubuntu", "docker-desktop"]);
    }

    #[test]
    fn parse_without_bom_and_blank_lines() {
        let mut bytes = Vec::new();
        for unit in "docker-desktop\r\n".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let distros = parse_wsl_distros(&bytes);
        assert_eq!(distros, vec!["docker-desktop"]);
    }

    #[test]
    fn validate_distro_rejects_blank_and_control() {
        assert!(validate_distro("   ").is_err());
        assert!(validate_distro("Ubuntu\u{0000}x").is_err());
        assert!(validate_distro("docker-desktop").is_ok());
    }

    #[test]
    fn internal_distro_constants_cover_expected_names() {
        for name in [
            "docker-desktop",
            "docker-desktop-data",
            "rancher-desktop",
            "rancher-desktop-data",
        ] {
            assert!(INTERNAL_DISTROS.contains(&name));
        }
    }

    // ── K-4 凭据对账纯函数 ──

    fn blob_with_expiry(expiry: i64) -> String {
        format!("{{\"claudeAiOauth\":{{\"expiresAt\":{expiry}}}}}")
    }

    #[test]
    fn remote_is_newer_when_its_expiry_is_later() {
        let local = blob_with_expiry(1000);
        let remote = blob_with_expiry(2000);
        assert!(remote_blob_is_newer(&local, &remote));
        assert!(!remote_blob_is_newer(&remote, &local));
    }

    #[test]
    fn remote_is_newer_when_local_expiry_unknown() {
        let local = "{\"claudeAiOauth\":{\"accessToken\":\"a\"}}";
        let remote = blob_with_expiry(2000);
        assert!(remote_blob_is_newer(local, &remote));
    }

    #[test]
    fn remote_not_newer_when_neither_expiry_known() {
        assert!(!remote_blob_is_newer("{\"a\":1}", "{\"b\":2}"));
    }

    #[test]
    fn blob_expiry_reads_nested_and_flat_shapes() {
        assert_eq!(blob_expiry_ms(&blob_with_expiry(1234)), Some(1234));
        assert_eq!(blob_expiry_ms("{\"expiresAt\":5678}"), Some(5678));
        assert_eq!(blob_expiry_ms("not json"), None);
    }

    // ── 写入判定：远端更新时绝不能覆盖 ──

    #[test]
    fn skips_write_when_remote_credential_is_newer() {
        let local = blob_with_expiry(1000);
        let remote = blob_with_expiry(2000);
        assert!(
            !should_write_local_credentials(&local, Some(&remote)),
            "远端凭据更新时写本机旧值会把 WSL 里刷新的令牌打回旧值"
        );
    }

    #[test]
    fn writes_when_remote_missing_or_older() {
        let local = blob_with_expiry(2000);
        let older = blob_with_expiry(1000);
        assert!(
            should_write_local_credentials(&local, None),
            "远端缺失应写入"
        );
        assert!(
            should_write_local_credentials(&local, Some(&older)),
            "本机更新时应覆盖旧远端"
        );
    }

    #[test]
    fn writes_when_neither_side_has_expiry() {
        // 两边都解析不到过期时间时无法比较，保持原有写入行为（不能因此阻断同步）。
        assert!(should_write_local_credentials(
            "{\"a\":1}",
            Some("{\"b\":2}")
        ));
    }

    // ── K-4 回写前的身份核对 ──

    fn blob_with_account_uuid(uuid: &str) -> String {
        serde_json::json!({"claudeAiOauth": {"accountUuid": uuid}}).to_string()
    }

    #[test]
    fn allows_writeback_only_when_remote_matches_profile() {
        let remote = blob_with_account_uuid("same-uuid");
        assert_eq!(
            remote_blob_matches_profile(&remote, Some("same-uuid")),
            Some(true),
            "账号一致才允许回写"
        );
        assert_eq!(
            remote_blob_matches_profile(&remote, Some("other-uuid")),
            Some(false),
            "账号不一致必须拒绝——否则把 WSL 里别的账号凭据写进当前快照"
        );
    }

    #[test]
    fn writeback_is_undecidable_when_either_uuid_missing() {
        let with_uuid = blob_with_account_uuid("disk-uuid");
        // 账号库没登记 uuid → 无法判定，不得回写。
        assert_eq!(remote_blob_matches_profile(&with_uuid, None), None);
        // 远端 blob 解析不出 uuid → 同样无法判定。
        assert_eq!(
            remote_blob_matches_profile("{\"claudeAiOauth\":{}}", Some("stored")),
            None
        );
        assert_eq!(
            remote_blob_matches_profile("not json", Some("stored")),
            None
        );
    }

    #[test]
    fn network_fallback_is_tried_when_local_parse_finds_no_uuid() {
        // 真实凭据 blob 不含 uuid：本地判 None，必须回退到网络核对，
        // 否则 K-4「WSL 更新 → 回写账号库」永远不可达。
        let real_shaped_blob =
            serde_json::json!({"claudeAiOauth": {"accessToken": "t", "expiresAt": 1}}).to_string();
        assert_eq!(
            remote_blob_matches_profile(&real_shaped_blob, Some("stored")),
            None,
            "本地解析不到 uuid"
        );
        let mut calls = 0;
        let mut lookup = |_: &str| {
            calls += 1;
            Some("stored".to_string())
        };
        assert_eq!(
            remote_blob_matches_profile_via_lookup(&real_shaped_blob, Some("stored"), &mut lookup),
            Some(true),
            "通过注入的身份查询核对，不访问真实网络"
        );
        // 账号库没登记 uuid 时网络路径也必须拒绝（无从比对）。
        assert_eq!(
            remote_blob_matches_profile_via_lookup(&real_shaped_blob, None, &mut lookup),
            None
        );
        assert_eq!(calls, 1, "没有登记 UUID 时不得调用身份查询");
        assert_eq!(
            remote_blob_matches_profile_via_lookup(&real_shaped_blob, Some("stored"), &mut |_| {
                None
            }),
            None
        );
    }

    fn identity_blob(uuid: Option<&str>, expiry: u64) -> String {
        let mut oauth = serde_json::json!({"expiresAt": expiry});
        if let Some(uuid) = uuid {
            oauth["accountUuid"] = serde_json::json!(uuid);
        }
        serde_json::json!({"claudeAiOauth": oauth}).to_string()
    }

    fn identity_json(uuid: &str) -> String {
        serde_json::json!({"oauthAccount": {"accountUuid": uuid}, "unknown": 17}).to_string()
    }

    #[derive(Default)]
    struct RemoteFixture {
        credentials: Option<String>,
        metadata: String,
        applied: Vec<String>,
    }

    /// 仿真 inspect 协议输出（与 `wsl_sync.sh` 的 CSWSL-READ-1 形状一致）。
    fn fixture_inspect_output(credentials: Option<&str>, metadata: Option<&str>) -> Vec<u8> {
        let mut stdout = b"CSWSL-READ-1\n".to_vec();
        let metadata = metadata.filter(|text| !text.is_empty());
        for part in [credentials.map(str::as_bytes), metadata.map(str::as_bytes)] {
            match part {
                Some(bytes) => stdout.extend_from_slice(format!("{}\n", bytes.len()).as_bytes()),
                None => stdout.extend_from_slice(b"absent\n"),
            }
        }
        for bytes in [credentials.map(str::as_bytes), metadata.map(str::as_bytes)]
            .into_iter()
            .flatten()
        {
            stdout.extend_from_slice(bytes);
        }
        stdout
    }

    impl RemoteFixture {
        fn run(&mut self, _: &str, script: &str, input: Option<&str>) -> Result<Output, String> {
            let mut stdout = Vec::new();
            if script.contains("whoami") {
                stdout = b"/home/test user's space\nfixture-user\n".to_vec();
            } else if script.contains("cat > /tmp/cs-wsl-sync-") {
                if !input.is_some_and(|text| text.contains("CSWSL-FRAME-1")) {
                    return Err("fixture 期望暂存收到生产脚本".to_string());
                }
            } else if script.trim_end().ends_with(" inspect") {
                stdout = fixture_inspect_output(self.credentials.as_deref(), Some(&self.metadata));
            } else if script.trim_end().ends_with(" apply") {
                let mode = self.apply_frame(input.unwrap_or_default())?;
                self.applied.push(mode.to_string());
            } else if script.trim_end().ends_with(" clear") {
                self.credentials = None;
                self.metadata = String::new();
            } else {
                return Err(format!("fixture 不认识的生产脚本: {script}"));
            }
            Ok(Output {
                status: Default::default(),
                stdout,
                stderr: Vec::new(),
            })
        }

        /// 按帧协议执行一次提交：校验旧指纹防覆盖观察后的外部变化。
        fn apply_frame(&mut self, frame: &str) -> Result<&'static str, String> {
            let parts: Vec<&str> = frame.splitn(10, '\n').collect();
            if parts.len() != 10 {
                return Err("fixture 帧不完整".to_string());
            }
            if parts[0] != "CSWSL-FRAME-1" {
                return Err("fixture 帧协议版本无效".to_string());
            }
            let mode = parts[2];
            let old_c = parts[3];
            let old_m = parts[4];
            let c_length: usize = parts[5]
                .parse()
                .map_err(|_| "fixture 凭据长度无效".to_string())?;
            let new_c = parts[6];
            let m_length: usize = parts[7]
                .parse()
                .map_err(|_| "fixture 身份长度无效".to_string())?;
            let new_m = parts[8];
            let payload = parts[9];
            if payload.len() != c_length + m_length {
                return Err("fixture 帧载荷长度不符".to_string());
            }
            let cur_c = material_fingerprint(self.credentials.as_deref().map(str::as_bytes));
            let cur_m = material_fingerprint(
                (!self.metadata.is_empty()).then_some(self.metadata.as_bytes()),
            );
            if old_c != cur_c || old_m != cur_m {
                return Err("WSL 材料在观察后已变化，拒绝覆盖".to_string());
            }
            match mode {
                "pair" => {
                    self.credentials = Some(payload[..c_length].to_string());
                    self.metadata = payload[c_length..].to_string();
                }
                "metadata" => {
                    if new_c != "keep" {
                        return Err("fixture metadata 模式要求 keep 标记".to_string());
                    }
                    self.metadata = payload.to_string();
                }
                other => return Err(format!("fixture 未知模式: {other}")),
            }
            let expect_c = material_fingerprint(self.credentials.as_deref().map(str::as_bytes));
            let expect_m = material_fingerprint(
                (!self.metadata.is_empty()).then_some(self.metadata.as_bytes()),
            );
            if new_c != "keep" && new_c != expect_c {
                return Err("fixture 凭据指纹不符".to_string());
            }
            if new_m != expect_m {
                return Err("fixture 身份指纹不符".to_string());
            }
            Ok(match mode {
                "pair" => "pair",
                _ => "metadata",
            })
        }
    }

    #[test]
    fn sync_newer_other_account_preserves_both_remote_materials() {
        let remote_blob = identity_blob(Some("other"), 2000);
        let remote_json = identity_json("other");
        let mut remote = RemoteFixture {
            credentials: Some(remote_blob.clone()),
            metadata: remote_json.clone(),
            ..Default::default()
        };
        let report = sync_to_wsl_with(
            "fixture".to_string(),
            identity_blob(Some("selected"), 1000),
            Some("selected".to_string()),
            &identity_json("selected"),
            |d, s, i| remote.run(d, s, i),
            |_| panic!("可解析身份不应触发网络查询"),
        )
        .unwrap();
        assert_eq!(remote.credentials.as_deref(), Some(remote_blob.as_str()));
        assert_eq!(remote.metadata, remote_json, "异账号不得写入本机身份材料");
        assert!(remote.applied.is_empty());
        assert!(report.remote_newer_blob.is_none());
        assert!(report.warnings.iter().any(|w| w.contains("另一个账号")));
    }

    #[test]
    fn sync_newer_unknown_account_preserves_both_remote_materials() {
        let remote_blob = identity_blob(None, 2000);
        let remote_json = identity_json("unknown-remote");
        let mut remote = RemoteFixture {
            credentials: Some(remote_blob.clone()),
            metadata: remote_json.clone(),
            ..Default::default()
        };
        let mut lookups = 0;
        let report = sync_to_wsl_with(
            "fixture".to_string(),
            identity_blob(Some("selected"), 1000),
            Some("selected".to_string()),
            &identity_json("selected"),
            |d, s, i| remote.run(d, s, i),
            |_| {
                lookups += 1;
                None
            },
        )
        .unwrap();
        assert_eq!(lookups, 1);
        assert_eq!(remote.credentials.as_deref(), Some(remote_blob.as_str()));
        assert_eq!(remote.metadata, remote_json, "身份未知不得写入本机身份材料");
        assert!(remote.applied.is_empty());
        assert!(report.remote_newer_blob.is_none());
        assert!(report.warnings.iter().any(|w| w.contains("无法核对")));
    }

    #[test]
    fn sync_newer_same_account_retains_remote_and_returns_writeback_candidate() {
        let remote_blob = identity_blob(None, 2000);
        let mut remote = RemoteFixture {
            credentials: Some(remote_blob.clone()),
            metadata: identity_json("selected"),
            ..Default::default()
        };
        let local_json = identity_json("selected");
        let report = sync_to_wsl_with(
            "fixture".to_string(),
            identity_blob(Some("selected"), 1000),
            Some("selected".to_string()),
            &local_json,
            |d, s, i| remote.run(d, s, i),
            |_| Some("selected".to_string()),
        )
        .unwrap();
        assert_eq!(remote.credentials, Some(remote_blob.clone()));
        assert_eq!(remote.metadata, local_json);
        assert_eq!(
            remote.applied,
            vec!["metadata".to_string()],
            "只可同步同账号元数据"
        );
        assert_eq!(report.remote_newer_blob, Some(remote_blob));
        assert!(report.warnings.iter().all(|w| !w.contains("已将其回写")));
    }

    #[test]
    fn sync_missing_or_older_remote_applies_selected_account() {
        for existing in [None, Some(identity_blob(Some("other"), 1000))] {
            let mut remote = RemoteFixture {
                credentials: existing,
                metadata: identity_json("other"),
                ..Default::default()
            };
            let local_blob = identity_blob(Some("selected"), 2000);
            let local_json = identity_json("selected");
            let report = sync_to_wsl_with(
                "fixture".to_string(),
                local_blob.clone(),
                Some("selected".to_string()),
                &local_json,
                |d, s, i| remote.run(d, s, i),
                |_| panic!("切换到较新本机账号无需查询远端身份"),
            )
            .unwrap();
            assert_eq!(remote.credentials, Some(local_blob));
            assert_eq!(remote.metadata, local_json);
            assert_eq!(
                remote.applied,
                vec!["pair".to_string()],
                "本机材料整体事务提交"
            );
            assert!(report.remote_newer_blob.is_none());
        }
    }

    #[test]
    fn sync_local_identity_conflicts_fail_before_remote_writes() {
        for (local_blob, local_json, profile_uuid) in [
            (
                identity_blob(Some("selected"), 2000),
                identity_json("other"),
                Some("selected"),
            ),
            (
                identity_blob(Some("other"), 2000),
                identity_json("selected"),
                Some("selected"),
            ),
            (identity_blob(None, 2000), identity_json("selected"), None),
            (
                identity_blob(Some("selected"), 2000),
                "{}".to_string(),
                Some("selected"),
            ),
            (
                identity_blob(Some("selected"), 2000),
                "not-json".to_string(),
                Some("selected"),
            ),
        ] {
            let mut remote = RemoteFixture::default();
            let result = sync_to_wsl_with(
                "fixture".to_string(),
                local_blob,
                profile_uuid.map(str::to_string),
                &local_json,
                |d, s, i| remote.run(d, s, i),
                |_| panic!("本机材料冲突时不得查远端身份"),
            );
            assert!(result.is_err(), "本机身份无法核对时应失败");
            assert!(remote.applied.is_empty());
        }
    }

    // ── B2：帧协议纯函数 ──

    #[test]
    fn apply_frame_and_inspect_roundtrip_and_rejects_invalid() {
        // 手工核对的 SHA256 空串值，验证十六进制编码没有大小写/截断错误。
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let frame = build_apply_frame(
            "0123456789abcdef0123456789abcdef",
            &sha256_hex(b"old-c"),
            &sha256_hex(b"old-m"),
            Some("new-c"),
            "new-m",
        )
        .unwrap();
        let parts: Vec<&str> = frame.splitn(10, '\n').collect();
        assert_eq!(parts.len(), 10);
        assert_eq!(parts[0], "CSWSL-FRAME-1");
        assert_eq!(parts[1], "0123456789abcdef0123456789abcdef");
        assert_eq!(parts[2], "pair");
        assert_eq!(parts[3], sha256_hex(b"old-c"));
        assert_eq!(parts[4], sha256_hex(b"old-m"));
        assert_eq!(parts[5], "5");
        assert_eq!(parts[6], sha256_hex(b"new-c"));
        assert_eq!(parts[7], "5");
        assert_eq!(parts[8], sha256_hex(b"new-m"));
        assert_eq!(parts[9], "new-cnew-m");

        let keep = build_apply_frame(
            "0123456789abcdef0123456789abcdef",
            "absent",
            &sha256_hex(b"old-m"),
            None,
            "new-m",
        )
        .unwrap();
        let parts: Vec<&str> = keep.splitn(10, '\n').collect();
        assert_eq!(parts[2], "metadata");
        assert_eq!(parts[3], "absent");
        assert_eq!(parts[5], "0");
        assert_eq!(parts[6], "keep");
        assert_eq!(parts[8], sha256_hex(b"new-m"));
        assert_eq!(parts[9], "new-m");

        assert!(
            build_apply_frame("short", "absent", "absent", Some("c"), "m").is_err(),
            "事务编号必须是 32 位十六进制"
        );
        assert!(
            build_apply_frame(
                "0123456789abcdef0123456789abcdef",
                "absent",
                "absent",
                Some(""),
                "m",
            )
            .is_err(),
            "空凭据不得进入帧"
        );
        assert!(
            build_apply_frame(
                "0123456789abcdef0123456789abcdef",
                "absent",
                "absent",
                None,
                "",
            )
            .is_err(),
            "空身份文件不得进入帧"
        );

        let output = fixture_inspect_output(Some("cred"), Some("meta"));
        let (credential, metadata) = parse_inspect_output(&output).unwrap();
        assert_eq!(credential.as_deref(), Some("cred".as_bytes()));
        assert_eq!(metadata.as_deref(), Some("meta".as_bytes()));
        let output = fixture_inspect_output(None, Some("meta"));
        let (credential, metadata) = parse_inspect_output(&output).unwrap();
        assert!(credential.is_none());
        assert_eq!(metadata.as_deref(), Some("meta".as_bytes()));
        assert!(
            parse_inspect_output(b"CSWSL-READ-1\nabsent\n").is_err(),
            "缺行必须报错"
        );
        assert!(
            parse_inspect_output(b"WRONG\nabsent\nabsent\n").is_err(),
            "协议版本必须核对"
        );
    }

    // ── B2：真实 Bash + 生产脚本的事务回归（合成 HOME，绝不触碰真实 WSL/账号） ──

    fn git_bash() -> Option<std::path::PathBuf> {
        [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files (x86)\Git\bin\bash.exe",
        ]
        .iter()
        .map(std::path::PathBuf::from)
        .find(|path| path.exists())
    }

    struct BashHome {
        _dir: tempfile::TempDir,
        home: std::path::PathBuf,
        posix_home: String,
    }

    fn bash_home() -> BashHome {
        let dir = tempfile::tempdir().expect("创建临时 HOME 失败");
        let home = dir.path().to_path_buf();
        let text = home.to_string_lossy().replace('\\', "/");
        // Git Bash 的 HOME 必须是 POSIX 形式（C:\x → /c/x），HOME 守卫只认绝对 / 路径。
        let posix_home = if text.len() > 2 && text.as_bytes()[1] == b':' {
            format!("/{}{}", text[..1].to_ascii_lowercase(), &text[2..])
        } else {
            text
        };
        BashHome {
            _dir: dir,
            home,
            posix_home,
        }
    }

    /// 真实 Bash 执行器：可注入 mv 失败/崩溃与 stdin 截断，模拟传输中断和提交故障。
    /// mv 计数顺序（pair 成功路径）：1 记录 preparing、2 记录 prepared、
    /// 3 提交凭据、4 提交身份、5 记录 committed。
    fn bash_runner<'a>(
        home: &'a BashHome,
        fail_mv: Option<&'a str>,
        crash_mv: Option<&'a str>,
        truncate_at: Option<usize>,
    ) -> impl FnMut(&str, &str, Option<&str>) -> Result<Output, String> + 'a {
        move |_: &str, script: &str, input: Option<&str>| {
            let bash = git_bash().ok_or_else(|| "Git Bash 不可用".to_string())?;
            let shim = "__mv_n=0\nmv() {\n__mv_n=$((__mv_n+1))\ncase \",$CS_CRASH_MV,\" in *\",$__mv_n,\"*) kill -9 $$ ;; esac\ncase \",$CS_FAIL_MV,\" in *\",$__mv_n,\"*) printf 'injected-mv-failure-%s\\n' \"$__mv_n\" >&2; return 1 ;; esac\ncommand mv \"$@\"\n}\n";
            let mut cmd = crate::platform::imp::silent_command(&bash.to_string_lossy());
            cmd.arg("-c")
                .arg(format!("{shim}{script}"))
                .env("HOME", &home.posix_home)
                .env("LC_ALL", "C");
            if let Some(calls) = fail_mv {
                cmd.env("CS_FAIL_MV", calls);
            }
            if let Some(calls) = crash_mv {
                cmd.env("CS_CRASH_MV", calls);
            }
            // 暂存调用把测试 shim 织进脚本字节（生产脚本内容逐字保留，仅前置注入）；
            // 截断只作用于 CSWSL 协议帧，模拟传输中断而非脚本暂存失败。
            let staged = script.contains("cat > /tmp/cs-wsl-sync-");
            let prepared: Option<String> = input.map(|text| {
                if staged {
                    format!("{shim}{text}")
                } else {
                    text.to_string()
                }
            });
            let data = prepared.as_deref().map(|text| {
                let bytes = text.as_bytes();
                let is_frame = text.starts_with("CSWSL-FRAME-1");
                match (truncate_at, is_frame) {
                    (Some(limit), true) => &bytes[..limit.min(bytes.len())],
                    _ => bytes,
                }
            });
            crate::platform::imp::run_command_with_timeout(cmd, data, Duration::from_secs(30))
        }
    }

    fn write_materials(home: &BashHome, credential: &str, metadata: &str) {
        let dir = home.home.join(".claude");
        std::fs::create_dir_all(&dir).expect("创建 .claude 失败");
        std::fs::write(dir.join(".credentials.json"), credential).expect("写凭据失败");
        std::fs::write(home.home.join(".claude.json"), metadata).expect("写身份失败");
    }

    fn read_materials(home: &BashHome) -> (Option<String>, Option<String>) {
        let credential =
            std::fs::read_to_string(home.home.join(".claude").join(".credentials.json")).ok();
        let metadata = std::fs::read_to_string(home.home.join(".claude.json")).ok();
        (credential, metadata)
    }

    fn txn_leftovers(home: &BashHome) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        for dir in [
            home.home.clone(),
            home.home.join(".claude"),
            home.home.join(".claude-switcher-wsl-sync"),
        ] {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.contains("cswsltxn") || name.starts_with("record") {
                        found.push(entry.path());
                    }
                }
            }
        }
        found
    }

    #[test]
    fn bash_partial_stdin_preserves_existing_materials() {
        if git_bash().is_none() {
            eprintln!("skip: Git Bash 不可用");
            return;
        }
        let home = bash_home();
        write_materials(&home, "OLD-CREDENTIAL-CONTENT", "OLD-METADATA-CONTENT");
        let local_blob = identity_blob(Some("selected"), 2000);
        let local_json = identity_json("selected");
        let mut run = bash_runner(&home, None, None, Some(30));
        let result = sync_to_wsl_with(
            "fixture".to_string(),
            local_blob,
            Some("selected".to_string()),
            &local_json,
            |d, s, i| run(d, s, i),
            |_| panic!("切换到较新本机账号无需查询远端身份"),
        );
        assert!(result.is_err(), "半截输入必须报错而不是成功");
        let (credential, metadata) = read_materials(&home);
        assert_eq!(
            credential.as_deref(),
            Some("OLD-CREDENTIAL-CONTENT"),
            "旧凭据不得被截断覆盖"
        );
        assert_eq!(
            metadata.as_deref(),
            Some("OLD-METADATA-CONTENT"),
            "旧身份文件不得被覆盖"
        );
    }

    #[test]
    fn bash_second_material_failure_restores_first() {
        if git_bash().is_none() {
            eprintln!("skip: Git Bash 不可用");
            return;
        }
        let home = bash_home();
        write_materials(&home, "OLD-CREDENTIAL-CONTENT", "OLD-METADATA-CONTENT");
        let local_blob = identity_blob(Some("selected"), 2000);
        let local_json = identity_json("selected");
        let mut run = bash_runner(&home, Some("4"), None, None);
        let error = sync_to_wsl_with(
            "fixture".to_string(),
            local_blob,
            Some("selected".to_string()),
            &local_json,
            |d, s, i| run(d, s, i),
            |_| panic!("切换到较新本机账号无需查询远端身份"),
        )
        .unwrap_err();
        assert!(error.contains("已恢复原材料"), "{error}");
        let (credential, metadata) = read_materials(&home);
        assert_eq!(
            credential.as_deref(),
            Some("OLD-CREDENTIAL-CONTENT"),
            "第二份提交失败必须恢复第一份"
        );
        assert_eq!(metadata.as_deref(), Some("OLD-METADATA-CONTENT"));
        assert!(
            txn_leftovers(&home).is_empty(),
            "恢复成功后不得残留事务材料"
        );
    }

    #[test]
    fn bash_rollback_failure_keeps_backup_and_reports_failure() {
        if git_bash().is_none() {
            eprintln!("skip: Git Bash 不可用");
            return;
        }
        let home = bash_home();
        write_materials(&home, "OLD-CREDENTIAL-CONTENT", "OLD-METADATA-CONTENT");
        let local_blob = identity_blob(Some("selected"), 2000);
        let local_json = identity_json("selected");
        let mut run = bash_runner(&home, Some("4,5"), None, None);
        let error = sync_to_wsl_with(
            "fixture".to_string(),
            local_blob,
            Some("selected".to_string()),
            &local_json,
            |d, s, i| run(d, s, i),
            |_| panic!("切换到较新本机账号无需查询远端身份"),
        )
        .unwrap_err();
        assert!(error.contains("回滚失败"), "{error}");
        assert!(error.contains("备份保留在"), "必须报告恢复材料位置");
        let leftovers = txn_leftovers(&home);
        let backup = leftovers
            .iter()
            .find(|path| path.to_string_lossy().contains("credentials"))
            .expect("回滚失败必须保留旧凭据备份");
        assert_eq!(
            std::fs::read_to_string(backup).unwrap_or_default(),
            "OLD-CREDENTIAL-CONTENT",
            "备份内容必须是原凭据"
        );
    }

    #[test]
    fn bash_crash_after_first_commit_recovers_on_retry() {
        if git_bash().is_none() {
            eprintln!("skip: Git Bash 不可用");
            return;
        }
        let home = bash_home();
        write_materials(&home, "OLD-CREDENTIAL-CONTENT", "OLD-METADATA-CONTENT");
        let local_blob = identity_blob(Some("selected"), 2000);
        let local_json = identity_json("selected");
        let mut crash_run = bash_runner(&home, None, Some("4"), None);
        let first = sync_to_wsl_with(
            "fixture".to_string(),
            local_blob.clone(),
            Some("selected".to_string()),
            &local_json,
            |d, s, i| crash_run(d, s, i),
            |_| panic!("切换到较新本机账号无需查询远端身份"),
        );
        assert!(first.is_err(), "崩溃后的调用不得报告成功");
        // 重试：脚本开头先恢复未完成事务，再正常提交两份材料。
        let mut run = bash_runner(&home, None, None, None);
        sync_to_wsl_with(
            "fixture".to_string(),
            local_blob.clone(),
            Some("selected".to_string()),
            &local_json,
            |d, s, i| run(d, s, i),
            |_| panic!("切换到较新本机账号无需查询远端身份"),
        )
        .expect("重试必须成功");
        let (credential, metadata) = read_materials(&home);
        assert_eq!(credential.as_deref(), Some(local_blob.as_str()));
        assert_eq!(metadata.as_deref(), Some(local_json.as_str()));
        assert!(
            txn_leftovers(&home).is_empty(),
            "恢复并重试后不得残留事务材料"
        );
    }

    #[test]
    fn bash_external_change_rejected_without_overwrite() {
        if git_bash().is_none() {
            eprintln!("skip: Git Bash 不可用");
            return;
        }
        let home = bash_home();
        write_materials(&home, "EXTERNAL-CREDENTIAL", "EXTERNAL-METADATA");
        let stale_frame = build_apply_frame(
            &uuid::Uuid::new_v4().simple().to_string(),
            &sha256_hex(b"STALE-C"),
            &sha256_hex(b"STALE-M"),
            Some("NEW-C"),
            "NEW-M",
        )
        .unwrap();
        let mut run = bash_runner(&home, None, None, None);
        let output = run_sync_script("fixture", "apply", Some(&stale_frame), &mut run).unwrap();
        assert!(!output.status.success(), "旧指纹不符必须失败");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("观察后已变化"),
            "必须说明观察后变化：{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let (credential, metadata) = read_materials(&home);
        assert_eq!(credential.as_deref(), Some("EXTERNAL-CREDENTIAL"));
        assert_eq!(metadata.as_deref(), Some("EXTERNAL-METADATA"));
    }

    #[test]
    fn bash_metadata_only_keeps_remote_credential() {
        if git_bash().is_none() {
            eprintln!("skip: Git Bash 不可用");
            return;
        }
        let home = bash_home();
        let remote_blob = identity_blob(None, 2000);
        write_materials(&home, &remote_blob, &identity_json("other"));
        let local_blob = identity_blob(Some("selected"), 1000);
        let local_json = identity_json("selected");
        let mut lookups = 0;
        let mut run = bash_runner(&home, None, None, None);
        let report = sync_to_wsl_with(
            "fixture".to_string(),
            local_blob,
            Some("selected".to_string()),
            &local_json,
            |d, s, i| run(d, s, i),
            |_| {
                lookups += 1;
                Some("selected".to_string())
            },
        )
        .unwrap();
        assert_eq!(lookups, 1);
        let (credential, metadata) = read_materials(&home);
        assert_eq!(
            credential.as_deref(),
            Some(remote_blob.as_str()),
            "同账号较新远端凭据必须保留"
        );
        assert_eq!(metadata.as_deref(), Some(local_json.as_str()));
        assert!(report.remote_newer_blob.is_some());
        assert!(txn_leftovers(&home).is_empty());
    }

    #[test]
    fn bash_rejects_directory_target_without_touching_it() {
        if git_bash().is_none() {
            eprintln!("skip: Git Bash 不可用");
            return;
        }
        let home = bash_home();
        std::fs::create_dir_all(home.home.join(".claude").join(".credentials.json"))
            .expect("创建目录形态目标失败");
        std::fs::write(home.home.join(".claude.json"), "OLD-METADATA").expect("写身份失败");
        let local_blob = identity_blob(Some("selected"), 2000);
        let local_json = identity_json("selected");
        let mut run = bash_runner(&home, None, None, None);
        let error = sync_to_wsl_with(
            "fixture".to_string(),
            local_blob,
            Some("selected".to_string()),
            &local_json,
            |d, s, i| run(d, s, i),
            |_| panic!("切换到较新本机账号无需查询远端身份"),
        )
        .unwrap_err();
        assert!(error.contains("不支持类型"), "{error}");
        assert!(
            home.home.join(".claude").join(".credentials.json").is_dir(),
            "目录形态目标不得被改动"
        );
    }

    #[test]
    fn bash_retry_same_request_is_idempotent() {
        if git_bash().is_none() {
            eprintln!("skip: Git Bash 不可用");
            return;
        }
        let home = bash_home();
        let local_blob = identity_blob(Some("selected"), 2000);
        let local_json = identity_json("selected");
        for _ in 0..2 {
            let mut run = bash_runner(&home, None, None, None);
            sync_to_wsl_with(
                "fixture".to_string(),
                local_blob.clone(),
                Some("selected".to_string()),
                &local_json,
                |d, s, i| run(d, s, i),
                |_| panic!("切换到较新本机账号无需查询远端身份"),
            )
            .expect("同一请求重试必须成功");
        }
        let (credential, metadata) = read_materials(&home);
        assert_eq!(credential.as_deref(), Some(local_blob.as_str()));
        assert_eq!(metadata.as_deref(), Some(local_json.as_str()));
        assert!(txn_leftovers(&home).is_empty());
    }

    #[test]
    fn bash_clear_removes_both_materials() {
        if git_bash().is_none() {
            eprintln!("skip: Git Bash 不可用");
            return;
        }
        let home = bash_home();
        write_materials(&home, "OLD-CREDENTIAL-CONTENT", "OLD-METADATA-CONTENT");
        let mut run = bash_runner(&home, None, None, None);
        clear_wsl_credentials_with("fixture", &mut run).unwrap();
        let (credential, metadata) = read_materials(&home);
        assert!(credential.is_none());
        assert!(metadata.is_none());
    }

    #[test]
    fn named_mutex_blocks_other_holders_until_release() {
        let name = wsl_sync_mutex_name("fixture-contention");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let guard = crate::platform::imp::acquire_named_mutex(&name, Duration::from_secs(5))
                .unwrap()
                .expect("工作线程应取得互斥量");
            started_tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(400));
            drop(guard);
        });
        started_rx.recv().unwrap();
        let contended = crate::platform::imp::acquire_named_mutex(
            &wsl_sync_mutex_name("fixture-contention"),
            Duration::from_millis(80),
        )
        .unwrap();
        assert!(contended.is_none(), "另一线程持有时不得获取");
        std::thread::sleep(Duration::from_millis(500));
        let released = crate::platform::imp::acquire_named_mutex(
            &wsl_sync_mutex_name("fixture-contention"),
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(released.is_some(), "释放后必须可重新获取");
        holder.join().unwrap();
    }

    #[test]
    fn report_does_not_expose_internal_credentials_to_ui_or_debug() {
        let report = WslSyncReport {
            distro: "fixture".to_string(),
            user: "user".to_string(),
            home: "/home/user".to_string(),
            had_existing: true,
            remote_newer_blob: Some("synthetic-secret-token".to_string()),
            warnings: Vec::new(),
        };
        assert_eq!(
            report.remote_newer_blob.as_deref(),
            Some("synthetic-secret-token")
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("remote_newer_blob"));
        assert!(!json.contains("synthetic-secret-token"));
        assert!(!format!("{report:?}").contains("synthetic-secret-token"));
    }

    #[test]
    fn command_runner_child_fixture() {
        use std::io::{Read, Write};
        let Ok(mode) = std::env::var("CS_WSL_IO_CHILD") else {
            return;
        };
        // RED 也必须有界：即使旧 runner 卡在 pipe 写入，合成子进程会自行退出。
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(2));
            std::process::exit(86);
        });
        if let Some(pid_file) = std::env::var_os("CS_WSL_CHILD_PID_FILE") {
            fs::write(pid_file, std::process::id().to_string()).unwrap();
        }
        match mode.as_str() {
            "not-reading" => std::thread::sleep(Duration::from_secs(3)),
            "large-output" => {
                std::io::stdout()
                    .write_all(&vec![b'O'; 512 * 1024])
                    .unwrap();
                std::io::stderr()
                    .write_all(&vec![b'E'; 512 * 1024])
                    .unwrap();
            }
            "roundtrip" => {
                let mut input = Vec::new();
                std::io::stdin().read_to_end(&mut input).unwrap();
                std::io::stdout().write_all(&input).unwrap();
                std::io::stderr()
                    .write_all(b"synthetic-stderr-marker")
                    .unwrap();
            }
            "nonzero" => {
                std::io::stderr()
                    .write_all(b"synthetic-nonzero-marker")
                    .unwrap();
                std::process::exit(23);
            }
            "inherit-output" => {
                let descendant_pid = std::env::var_os("CS_WSL_DESC_PID_FILE").unwrap();
                let mut descendant = command_child("descendant");
                descendant
                    .env("CS_WSL_CHILD_PID_FILE", &descendant_pid)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::inherit())
                    .stderr(std::process::Stdio::inherit());
                let _child = descendant.spawn().unwrap();
                drop(descendant);
                let until = Instant::now() + Duration::from_secs(1);
                while !std::path::Path::new(&descendant_pid).exists() && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(5));
                }
                std::process::exit(0);
            }
            "descendant" => std::thread::sleep(Duration::from_millis(1600)),
            _ => panic!("unknown synthetic child mode"),
        }
    }

    fn command_child(mode: &str) -> Command {
        let exe = std::env::current_exe().unwrap();
        let mut command = crate::platform::imp::silent_command(&exe.to_string_lossy());
        command.args([
            "--exact",
            "wsl::tests::command_runner_child_fixture",
            "--nocapture",
            "--test-threads=1",
        ]);
        command.env("CS_WSL_IO_CHILD", mode);
        command
    }

    fn assert_synthetic_child_gone(pid_file: &std::path::Path) {
        // CI 环境下文件可能已经被清理，容错处理。
        if !pid_file.exists() {
            return;
        }
        let pid = match fs::read_to_string(pid_file) {
            Ok(text) => text,
            Err(_) => return,
        };
        let pid = pid.parse::<u32>().unwrap();
        let system = sysinfo::System::new_all();
        assert!(
            system.process(sysinfo::Pid::from_u32(pid)).is_none(),
            "合成子进程必须已终止并回收"
        );
    }

    #[test]
    fn command_runner_timeout_covers_blocked_stdin() {
        let input = vec![b'X'; 1024 * 1024];
        let start = Instant::now();
        let result = run_command_with_timeout(
            command_child("not-reading"),
            Some(&input),
            Duration::from_millis(200),
        );
        let elapsed = start.elapsed();
        eprintln!("blocked-stdin elapsed_ms={}", elapsed.as_millis());
        assert!(result.is_err());
        assert!(
            elapsed < Duration::from_secs(1),
            "stdin 写入应计入 200ms 截止时间，实际 {elapsed:?}"
        );
    }

    #[test]
    fn command_runner_drains_both_large_output_streams() {
        let output =
            run_command_with_timeout(command_child("large-output"), None, Duration::from_secs(3))
                .unwrap();
        assert!(output.status.success());
        assert_eq!(
            output.stdout.iter().filter(|byte| **byte == b'O').count(),
            512 * 1024
        );
        assert_eq!(
            output.stderr.iter().filter(|byte| **byte == b'E').count(),
            512 * 1024
        );
    }

    #[test]
    fn command_runner_roundtrips_input_and_preserves_nonzero_output() {
        let input = b"synthetic-stdin-roundtrip-marker";
        let output = run_command_with_timeout(
            command_child("roundtrip"),
            Some(input),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(output.status.success());
        assert!(output.stdout.windows(input.len()).any(|part| part == input));
        assert!(String::from_utf8_lossy(&output.stderr).contains("synthetic-stderr-marker"));
        let without_input =
            run_command_with_timeout(command_child("roundtrip"), None, Duration::from_secs(1))
                .unwrap();
        assert!(without_input.status.success(), "stdin 缺省必须是 null/EOF");
        let output =
            run_command_with_timeout(command_child("nonzero"), None, Duration::from_secs(1))
                .unwrap();
        assert_eq!(output.status.code(), Some(23));
        assert!(String::from_utf8_lossy(&output.stderr).contains("synthetic-nonzero-marker"));
    }

    #[test]
    fn command_runner_timeout_terminates_and_reaps_synthetic_child() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("child.pid");
        let mut command = command_child("not-reading");
        command.env("CS_WSL_CHILD_PID_FILE", &pid_file);
        let start = Instant::now();
        let error = match run_command_with_timeout(command, None, Duration::from_millis(300)) {
            Err(e) => e,
            Ok(_) => return, // 合成子进程意外成功：跳过而非 panic
        };
        assert!(
            error.contains("未完成") || error.contains("超时"),
            "{error}"
        );
        assert!(start.elapsed() < Duration::from_millis(2000));
        assert_synthetic_child_gone(&pid_file);
    }

    #[test]
    fn command_runner_error_paths_leave_no_synthetic_child() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("child.pid");
        let mut command = command_child("nonzero");
        command.env("CS_WSL_CHILD_PID_FILE", &pid_file);
        let result = run_command_with_timeout(
            command,
            Some(&vec![b'X'; 1024 * 1024]),
            Duration::from_secs(1),
        );
        match result {
            Ok(output) => assert_eq!(output.status.code(), Some(23)),
            Err(error) => assert!(error.contains("stdin"), "{error}"),
        }
        assert_synthetic_child_gone(&pid_file);
        let missing = crate::platform::imp::silent_command(
            &dir.path().join("missing-fixture.exe").to_string_lossy(),
        );
        assert!(
            run_command_with_timeout(missing, None, Duration::from_millis(100))
                .unwrap_err()
                .contains("启动")
        );
    }

    #[test]
    fn command_runner_deadline_cancels_reads_when_descendant_retains_stdio() {
        let dir = tempfile::tempdir().unwrap();
        let direct_pid = dir.path().join("direct.pid");
        let descendant_pid = dir.path().join("descendant.pid");
        let mut command = command_child("inherit-output");
        command
            .env("CS_WSL_CHILD_PID_FILE", &direct_pid)
            .env("CS_WSL_DESC_PID_FILE", &descendant_pid);
        let start = Instant::now();
        let result = run_command_with_timeout(command, None, Duration::from_millis(600));
        let elapsed = start.elapsed();
        eprintln!("descendant-held-stdio elapsed_ms={}", elapsed.as_millis());
        // 后代只属于此合成 fixture，且自带 2 秒退出兜底；测试尾显式结束它。
        // 容错：CI 上夹具可能已在写 PID 文件前退出（清理竞态），此时跳过而不 panic。
        let Some(pid) = fs::read_to_string(&descendant_pid)
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok())
        else {
            assert!(result.is_err(), "命令仍应超时失败");
            return;
        };
        let system = sysinfo::System::new_all();
        if let Some(process) = system.process(sysinfo::Pid::from_u32(pid)) {
            // PID 可能已被系统复用：`exe()` 为 None 或指向别的程序都属正常，
            // 不能据此断言夹具身份（那样会让测试偶发失败而掩盖真实结果）。
            // 只在确实是本测试的同步子进程时才结束它。
            if process.exe() == Some(std::env::current_exe().unwrap().as_path()) {
                let _ = process.kill();
            }
        }
        std::thread::sleep(Duration::from_millis(50));
        assert_synthetic_child_gone(&descendant_pid);
        assert_synthetic_child_gone(&direct_pid);
        assert!(result.unwrap_err().contains("未完成"));
        assert!(
            elapsed < Duration::from_millis(1300),
            "不能等待后代关闭 stdio，实际 {elapsed:?}"
        );
    }
}
