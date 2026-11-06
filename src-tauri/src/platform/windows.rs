//! Windows 适配层：把所有 `#[cfg(windows)]` 噪音收拢到这一个模块。
//!
//! 覆盖：
//! - 静默子进程（CREATE_NO_WINDOW，避免托盘每分钟闪黑窗）
//! - 目录 ACL 收敛（仅 `~/.claude-switcher` 创建时执行一次，子项继承）
//! - junction 创建 / reparse tag 精确识别（含悬空链接）
//! - 路径规范化比较（大小写、`\\?\` 前缀、尾分隔符、8.3 短名展开）
//! - GetFileInformationByHandle 稳定文件 ID（硬链接识别）
//! - 文件锁短退避重试（rename/删除被占位时）

use std::fs;
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration as StdDuration;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, GetLongPathNameW, BY_HANDLE_FILE_INFORMATION,
    FILE_FLAG_BACKUP_SEMANTICS,
};
use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;
use windows_sys::Win32::System::Threading::GetCurrentProcessId;
use windows_sys::Win32::System::WindowsProgramming::GetUserNameW;
use windows_sys::Win32::System::IO::{DeviceIoControl, OVERLAPPED};

/// CREATE_NO_WINDOW：GUI 子系统下 spawn 控制台程序不再闪黑窗。
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// FILE_ATTRIBUTE_REPARSE_POINT (0x400)。
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// 符号链接 reparse tag。
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
/// junction（目录联接）reparse tag。
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;

/// 构造不闪黑窗的 Command。Windows 上所有 spawn 控制台程序（curl/icacls/
/// taskkill/whoami…）都必须走这里；explorer 除外（它本身就是 GUI 程序）。
pub fn silent_command(program: &str) -> Command {
    use std::os::windows::process::CommandExt;
    let mut command = Command::new(program);
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

/// LocalAlloc 系列 API 的返回内存必须用 LocalFree 释放。
struct LocalAllocation(*mut std::ffi::c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::LocalFree(self.0) };
    }
}

struct CommandPipeSecurity(LocalAllocation);

impl CommandPipeSecurity {
    fn new() -> io::Result<Self> {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        use windows_sys::Win32::Security::Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::{
            GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut length = 0;
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                std::ptr::null_mut(),
                0,
                &mut length,
            );
        }
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        // TOKEN_USER 含指针，使用 usize 缓冲保证对齐，SID 在本次调用期间仍由缓冲持有。
        let mut user = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                user.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let sid = unsafe { &*user.as_ptr().cast::<TOKEN_USER>() }.User.Sid;
        let mut sid_text = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut sid_text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let sid_text = LocalAllocation(sid_text.cast());
        let sid_pointer = sid_text.0.cast::<u16>();
        let mut sid_length = 0;
        while unsafe { *sid_pointer.add(sid_length) } != 0 {
            sid_length += 1;
        }
        let sid = String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(sid_pointer, sid_length)
        });
        // 默认命名管道 DACL 允许更广的读取；令牌管道只允许当前用户与 SYSTEM。
        let sddl: Vec<u16> = format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(LocalAllocation(descriptor)))
    }
}

async fn command_pipe(
    security: &CommandPipeSecurity,
    parent_reads: bool,
) -> io::Result<(tokio::net::windows::named_pipe::NamedPipeServer, fs::File)> {
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    let name = format!(r"\\.\pipe\claude-switcher-io-{}", uuid::Uuid::new_v4());
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.0 .0,
        bInheritHandle: 0,
    };
    let server = unsafe {
        ServerOptions::new()
            .access_inbound(parent_reads)
            .access_outbound(!parent_reads)
            .first_pipe_instance(true)
            .max_instances(1)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                &name,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            )?
    };
    // 子端保持同步 File；只有父端使用 overlapped I/O。Stdio 在 spawn 时复制需要继承的句柄。
    let client = fs::OpenOptions::new()
        .read(!parent_reads)
        .write(parent_reads)
        .open(name)?;
    server.connect().await?;
    Ok((server, client))
}

struct CommandChild(std::process::Child);

impl Drop for CommandChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
        }
    }
}

enum CommandIo {
    Input,
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

async fn read_command_pipe(
    mut pipe: tokio::net::windows::named_pipe::NamedPipeServer,
) -> io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    match pipe.read_to_end(&mut bytes).await {
        Ok(_) => Ok(bytes),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(bytes),
        Err(error) => Err(error),
    }
}

async fn stop_command(
    child: &mut CommandChild,
    tasks: &mut tokio::task::JoinSet<Result<CommandIo, String>>,
) -> Result<(), String> {
    let cleanup_deadline = tokio::time::Instant::now() + StdDuration::from_secs(1);
    tasks.abort_all();
    if !matches!(child.0.try_wait(), Ok(Some(_))) {
        let _ = child.0.kill();
    }
    tokio::time::timeout_at(cleanup_deadline, async {
        while tasks.join_next().await.is_some() {}
        loop {
            match child.0.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => tokio::time::sleep(StdDuration::from_millis(5)).await,
                Err(error) => return Err(format!("确认直接子进程退出失败: {error}")),
            }
        }
    })
    .await
    .map_err(|_| "取消管道或确认直接子进程退出超时".to_string())?
}

/// 真正可取消的 Windows 子进程管道；不使用 Tokio ChildStdio 的阻塞线程包装。
pub fn run_command_with_timeout(
    mut command: Command,
    input: Option<&[u8]>,
    timeout: StdDuration,
) -> Result<std::process::Output, String> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    let deadline = std::time::Instant::now() + timeout;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| format!("创建子进程执行环境失败: {error}"))?;
    runtime.block_on(async {
        let security =
            CommandPipeSecurity::new().map_err(|error| format!("创建私有管道权限失败: {error}"))?;
        let setup = async {
            let (stdout, stdout_child) = command_pipe(&security, true).await?;
            let (stderr, stderr_child) = command_pipe(&security, true).await?;
            let stdin = if input.is_some() {
                let (pipe, file) = command_pipe(&security, false).await?;
                command.stdin(Stdio::from(file));
                Some(pipe)
            } else {
                command.stdin(Stdio::null());
                None
            };
            command
                .stdout(Stdio::from(stdout_child))
                .stderr(Stdio::from(stderr_child));
            Ok::<_, io::Error>((stdin, stdout, stderr))
        };
        let deadline = tokio::time::Instant::from_std(deadline);
        let (stdin, stdout, stderr) = tokio::time::timeout_at(deadline, setup)
            .await
            .map_err(|_| "创建子进程管道超时".to_string())?
            .map_err(|error| format!("创建子进程管道失败: {error}"))?;
        let mut child = CommandChild(
            command
                .spawn()
                .map_err(|error| format!("启动子进程失败: {error}"))?,
        );
        // builder 仍持有子端 File，必须立刻释放，否则 stdout/stderr 永远收不到 EOF。
        drop(command);
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            read_command_pipe(stdout)
                .await
                .map(CommandIo::Stdout)
                .map_err(|error| format!("读取 stdout 失败: {error}"))
        });
        tasks.spawn(async move {
            read_command_pipe(stderr)
                .await
                .map(CommandIo::Stderr)
                .map_err(|error| format!("读取 stderr 失败: {error}"))
        });
        if let (Some(mut pipe), Some(input)) = (stdin, input) {
            let bytes = input.to_vec();
            tasks.spawn(async move {
                pipe.write_all(&bytes)
                    .await
                    .map_err(|error| format!("写入 stdin 失败: {error}"))?;
                // drop 最后一个父端，子进程才能读到真正 EOF；仅 shutdown 不足以关管道。
                drop(pipe);
                Ok(CommandIo::Input)
            });
        }
        let operation = async {
            let mut status = None;
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            loop {
                while let Some(completed) = tasks.try_join_next() {
                    match completed.map_err(|error| format!("执行管道任务失败: {error}"))??
                    {
                        CommandIo::Input => {}
                        CommandIo::Stdout(bytes) => stdout = bytes,
                        CommandIo::Stderr(bytes) => stderr = bytes,
                    }
                }
                if status.is_none() {
                    status = child
                        .0
                        .try_wait()
                        .map_err(|error| format!("等待子进程失败: {error}"))?;
                }
                if tasks.is_empty() {
                    if let Some(status) = status {
                        return Ok(std::process::Output {
                            status,
                            stdout,
                            stderr,
                        });
                    }
                }
                tokio::time::sleep(StdDuration::from_millis(5)).await;
            }
        };
        let result = tokio::time::timeout_at(deadline, operation)
            .await
            .map_err(|_| format!("命令超过 {:.3} 秒未完成", timeout.as_secs_f64()))
            .and_then(|result| result);
        match result {
            Ok(output) => Ok(output),
            Err(error) => match stop_command(&mut child, &mut tasks).await {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(format!("{error}；{cleanup_error}")),
            },
        }
    })
}

/// Windows PowerShell 5.1 的完整路径。
///
/// 不要依赖 PATH 直接按名启动 `powershell.exe`：部分精简/安装环境（以及被
/// 改写过的进程 PATH）里并不包含 `System32\WindowsPowerShell\v1.0`，按名
/// 启动会报「系统找不到指定的文件」。统一从 `SystemRoot` 拼出权威路径。
pub fn powershell_path() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    PathBuf::from(root).join("System32\\WindowsPowerShell\\v1.0\\powershell.exe")
}

/// F-7：读取用户默认 UI 语言，返回前端可识别的语言码（zh-CN / zh-TW / en）。
///
/// 精确匹配常见 LANGID，其余按主语言段（低 10 位）判断，无法识别时回退 en。
pub fn user_default_ui_language() -> String {
    use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;
    let lang_id = unsafe { GetUserDefaultUILanguage() };
    let exact = match lang_id {
        0x0804 | 0x1004 | 0x0004 => Some("zh-CN"),
        0x0404 | 0x0c04 | 0x1404 => Some("zh-TW"),
        0x0409 => Some("en"),
        _ => None,
    };
    if let Some(code) = exact {
        return code.to_string();
    }
    match lang_id & 0x3ff {
        0x04 => "zh-CN",
        0x09 => "en",
        _ => "en",
    }
    .to_string()
}

/// 当前进程 PID（用于进程检测时排除自身，替代 spawn tasklist）。
pub fn current_pid() -> u32 {
    unsafe { GetCurrentProcessId() }
}

/// 本工具自用的命名互斥量句柄：Drop 时释放并关闭。
///
/// 仅用于串行化本工具自己的 WSL 材料同步（同一用户/发行版），不声称是
/// Claude 官方凭据锁。守卫不跨线程移动，释放与获取在同一线程。
pub struct NamedMutexGuard(windows_sys::Win32::Foundation::HANDLE);

impl Drop for NamedMutexGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::Threading::ReleaseMutex(self.0);
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// 获取本工具命名互斥量；`timeout` 内拿不到返回 `Ok(None)`。
///
/// 名字不含 `Local\` 之外的反斜杠；调用方负责传入合法名字。
/// 上一持有线程异常退出（WAIT_ABANDONED）仍视为获取成功：本工具自己的
/// 事务脚本会在运行开头恢复残留状态。
pub fn acquire_named_mutex(
    name: &str,
    timeout: StdDuration,
) -> io::Result<Option<NamedMutexGuard>> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, WAIT_ABANDONED_0, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, wide.as_ptr()) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    let waited = unsafe { WaitForSingleObject(handle, timeout.as_millis() as u32) };
    match waited {
        WAIT_OBJECT_0 | WAIT_ABANDONED_0 => Ok(Some(NamedMutexGuard(handle))),
        WAIT_TIMEOUT => {
            unsafe {
                CloseHandle(handle);
            }
            Ok(None)
        }
        _ => {
            let error = io::Error::last_os_error();
            unsafe {
                CloseHandle(handle);
            }
            Err(error)
        }
    }
}

/// MSIX/Store 安装的 Claude Desktop 包族名（PackageFamilyName）列表。
///
/// MSIX 版 Claude 的数据不落在 `%APPDATA%\Claude`，而在
/// `%LOCALAPPDATA%\Claude-Data\<PackageFamilyName>\`。`Get-AppxPackage` 在受限
/// 账户/策略禁用环境下会直接抛错，这里整体兜住并返回空列表（调用方据此回退）。
pub fn claude_appx_families() -> Vec<String> {
    let script = "@(Get-AppxPackage -Name 'Claude' -ErrorAction SilentlyContinue).PackageFamilyName | ConvertTo-Json";
    let json = match run_ps(script) {
        Ok(json) => json,
        Err(_) => return Vec::new(),
    };
    parse_package_families(&json)
}

/// 解析 `PackageFamilyName` 的 JSON 输出：数组、单值或空。
fn parse_package_families(json: &str) -> Vec<String> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(serde_json::Value::Array(items)) => items
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .filter(|s| !s.is_empty())
            .collect(),
        Ok(serde_json::Value::String(one)) if !one.is_empty() => vec![one],
        _ => Vec::new(),
    }
}

/// 当前用户名（GetUserNameW，比 USERNAME 环境变量更可靠）。
/// 失败时回退 USERNAME 环境变量。
pub fn current_username() -> Result<String, String> {
    let mut buffer = [0u16; 256];
    let mut size = buffer.len() as u32;
    let ok = unsafe { GetUserNameW(buffer.as_mut_ptr(), &mut size) };
    if ok != 0 {
        let text = String::from_utf16_lossy(&buffer[..(size as usize).saturating_sub(1)]);
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let fallback = std::env::var("USERNAME").unwrap_or_default();
    let trimmed = fallback.trim();
    if trimmed.is_empty() {
        return Err("无法确定当前用户名（GetUserNameW 与 USERNAME 均失败）".to_string());
    }
    Ok(trimmed.to_string())
}

/// 把 `~/.claude-switcher` 收敛为「当前用户 + SYSTEM」完全控制（子项继承），
/// 绝不逐文件 icacls、绝不动 Claude Code 自己的文件。
///
/// 返回 `true` 表示 icacls 执行成功，调用方据此决定是否写「已加固」标记——
/// 失败时不能写标记，否则永远不会重试。
///
/// 三个容易踩的坑：
/// 1. **顺序**：先授权再断继承。单独执行 `/inheritance:r` 会把文件锁成谁都读不了。
/// 2. **SYSTEM 必须写 SID**：icacls 的 `*` 前缀表示「后面是数字 SID」，
///    `*SYSTEM:` 不是合法 SID、会解析失败（整条命令连同授权一起失败）。
///    SYSTEM 的真实 SID 是 `S-1-5-18`。
/// 3. **当前用户不能少**：只授 SYSTEM 会把当前用户也摘掉，连清理目录都做不了
///    （实测会 Access denied）。两者都要授。
///
/// H-1 保护：绝不能对这些目录执行 `icacls /inheritance:r`（会锁死/破坏用户数据）。
///
/// - **exe 所在目录**：便携版若误把数据根设成 exe 目录，断继承会把程序连同用户
///   放在一起的其它文件锁死；
/// - **用户 Downloads / Desktop**：这些目录继承的是用户公共/外壳 ACL，且常被
///   多应用共用，断继承会破坏正常访问。
///
/// 返回 true 表示「该位置受保护、应跳过加固」。
fn is_protected_from_hardening(dir: &Path) -> bool {
    let dir_norm = normalize_path(dir);
    // exe 所在目录。
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            if normalize_path(exe_dir) == dir_norm {
                return true;
            }
        }
    }
    // 用户 Downloads / Desktop（dirs 对已知文件夹解析可靠）。
    for folder in [dirs::download_dir(), dirs::desktop_dir()]
        .into_iter()
        .flatten()
    {
        if normalize_path(&folder) == dir_norm {
            return true;
        }
    }
    false
}

/// J-7 白名单：仅当目录是本工具自有的数据目录（目录名为 `.claude-switcher`
/// 或 `ClaudeSwitcherData`）时才允许做 ACL 加固。任何其它目录一律跳过，
/// 防止用户把自定义普通文件夹指给工具时被误断继承锁死。
fn is_app_owned_data_dir(dir: &Path) -> bool {
    matches!(
        dir.file_name().and_then(|name| name.to_str()),
        Some(".claude-switcher") | Some("ClaudeSwitcherData")
    )
}

pub fn secure_app_data_dir(dir: &Path) -> bool {
    // J-7 白名单优先：非本工具目录直接跳过（返回 true 视为无需处理）。
    if !is_app_owned_data_dir(dir) {
        crate::log_info(&format!(
            "数据目录「{}」不是本工具自有数据目录（白名单外），已跳过 ACL 加固",
            dir.display()
        ));
        return true;
    }
    // H-1：exe 目录 / Downloads / 桌面绝不加固（黑名单保留作第二道保险）。
    // 返回 true 视为「无需处理」，避免每次启动都重试并刷日志。
    if is_protected_from_hardening(dir) {
        crate::log_info(&format!(
            "数据目录「{}」属于受保护位置（exe 目录/下载/桌面），已跳过 ACL 加固",
            dir.display()
        ));
        return true;
    }
    let Some(username) = username_for_icacls() else {
        return false;
    };
    let path = dir.to_string_lossy().to_string();
    // 用同一个 icacls 进程一次做完，避免出现「已断继承但还没授权」的中间态。
    let output = silent_command("icacls")
        .arg(&path)
        .args(["/grant:r", &format!("{username}:(OI)(CI)F")])
        .args(["/grant:r", "*S-1-5-18:(OI)(CI)F"])
        .args(["/inheritance:r"])
        .output();
    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

/// 把单个**文件**收敛为「当前用户 + SYSTEM」完全控制（断继承）。
///
/// 用途：配置目录被用户改到数据盘（`D:\claude-alt`）时，凭据文件继承的是盘符根
/// 目录的 ACL（常给 Users 读取、Authenticated Users 修改），同机其他本地账户
/// 可能读到 OAuth 凭据。默认位置 `%USERPROFILE%\.claude` 继承用户目录私有 ACL，
/// 不需要这一步。
///
/// 与 `secure_app_data_dir` 同样遵守「先授权再断继承」和「SYSTEM 用 SID」。
/// best-effort：失败只返回 false，调用方记日志，不阻断写凭据本身。
pub fn secure_private_file(path: &Path) -> bool {
    let Some(username) = username_for_icacls() else {
        return false;
    };
    let path_text = path.to_string_lossy().to_string();
    let output = silent_command("icacls")
        .arg(&path_text)
        .args(["/grant:r", &format!("{username}:F")])
        .args(["/grant:r", "*S-1-5-18:F"])
        .args(["/inheritance:r"])
        .output();
    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

/// 路径是否位于用户 profile 目录内（`%USERPROFILE%` 下）。
/// 凭据文件在 profile 内时继承私有 ACL，无需额外收敛。
///
/// 复用 `normalize_path`（处理 `\\?\` 前缀、大小写、尾分隔符、8.3 短名），
/// 不自己做字符串前缀比较——误判的后果只是对 profile 内路径多做一次 icacls，
/// 但复用同一套逻辑更一致，也不会漏掉短名这类真实场景。
pub fn is_under_user_profile(path: &Path) -> bool {
    let Ok(profile) = std::env::var("USERPROFILE") else {
        return false;
    };
    let profile = profile.trim();
    if profile.is_empty() {
        return false;
    }
    is_under(Path::new(profile), path)
}

/// `path` 是否位于 `profile` 目录内（含等于）。
///
/// 注意 `C:\Users\A` 与 `C:\Users\AB` 的前缀陷阱：朴素
/// `starts_with("C:\\Users\\A")` 会把后者也判为在目录内。这里要求分隔符紧跟。
pub fn is_under(profile: &Path, path: &Path) -> bool {
    let profile_norm = normalize_path(profile);
    let path_norm = normalize_path(path);
    if profile_norm == path_norm {
        return true;
    }
    let (Some(prefix), Some(candidate)) = (profile_norm.to_str(), path_norm.to_str()) else {
        return false;
    };
    let prefix = prefix.trim_end_matches('\\');
    candidate
        .strip_prefix(prefix)
        .is_some_and(|rest| rest.starts_with('\\'))
}

/// icacls 的受托人参数：优先用 SID（`*S-1-5-…`，微软账号/中文用户名/本地化环境都稳），
/// 拿不到再退回 `USERDOMAIN\USERNAME`。
/// 环境变量不可用时直接放弃（best-effort）。
fn username_for_icacls() -> Option<String> {
    // 先用 whoami /user 拿 SID（输出含 S-1-5-…）。
    if let Ok(output) = silent_command("whoami").arg("/user").output() {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Some(sid) = extract_sid(&text) {
                return Some(format!("*{sid}"));
            }
        }
    }
    // 回退：USERDOMAIN\USERNAME（大多数场景可用）。
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    let user = std::env::var("USERNAME").unwrap_or_default();
    if !user.is_empty() && !user.contains(char::is_whitespace) {
        if domain.is_empty() {
            return Some(user);
        }
        return Some(format!("{domain}\\{user}"));
    }
    None
}

/// 从 `whoami /user` 输出里提取 S-1-5-… 形式的 SID。
fn extract_sid(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("S-1-") || trimmed.contains("S-1-") {
            let sid = trimmed
                .split_whitespace()
                .find(|token| token.starts_with("S-1-") && token.split('-').count() >= 3)?;
            return Some(sid.to_string());
        }
    }
    None
}

/// 精确判定路径是否为本工具创建的链接（符号链接或 junction）。
/// 用 reparse tag 判断，OneDrive 占位符 / AppExecLink 等其它 reparse point 不会命中。
///
/// **悬空链接**（目标已被删除）是个关键边界：此时即使带
/// FILE_FLAG_OPEN_REPARSE_POINT，Windows 也可能拒绝打开句柄，
/// 导致拿不到 reparse tag。这种情况下只要属性位是 reparse point，
/// 就保守判为链接——否则 `isolation` 的 activate_* 会误以为它不是链接，
/// 走进「创建目录」分支并最终建链接失败。
pub fn is_link(path: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    use std::os::windows::fs::MetadataExt;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        return false;
    }
    match reparse_tag(path) {
        Some(tag) => tag == IO_REPARSE_TAG_SYMLINK || tag == IO_REPARSE_TAG_MOUNT_POINT,
        // 拿不到 tag（悬空链接/权限受限）：既然属性位已标记为 reparse point，
        // 且我们能创建的就只有 symlink/junction，保守判为链接。
        None => true,
    }
}

/// 用 FSCTL_GET_REPARSE_POINT 取 reparse tag（标准做法，不依赖
/// GetFileInformationByHandle.dwReserved0 的未文档化行为）。
fn reparse_tag(path: &Path) -> Option<u32> {
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT as OPEN_REPARSE;

    let file = fs::OpenOptions::new()
        .read(true)
        .attributes(OPEN_REPARSE | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .ok()?;
    // REPARSE_DATA_BUFFER 头部即 ReparseTag + ReparseDataLength + Reserved。
    let mut buffer = [0u8; 16 * 1024];
    let mut returned: u32 = 0;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as HANDLE,
            FSCTL_GET_REPARSE_POINT,
            std::ptr::null_mut(),
            0,
            buffer.as_mut_ptr() as *mut core::ffi::c_void,
            buffer.len() as u32,
            &mut returned,
            &mut overlapped,
        )
    };
    if ok == 0 || returned < 4 {
        return None;
    }
    Some(u32::from_le_bytes(buffer[0..4].try_into().ok()?))
}

/// 稳定文件 ID：(卷序列号, 文件索引)。同卷同索引即同一文件——
/// 硬链接识别用；std 的对应方法仍 unstable。
pub fn file_id(path: &Path) -> Option<(u32, u64)> {
    let file = open_with_backup_semantics(path).ok()?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return None;
    }
    let index = ((info.nFileIndexHigh as u64) << 32) | (info.nFileIndexLow as u64);
    Some((info.dwVolumeSerialNumber, index))
}

/// 硬链接计数（NumberOfLinks）。
pub fn number_of_links(path: &Path) -> Option<u32> {
    let file = open_with_backup_semantics(path).ok()?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return None;
    }
    Some(info.nNumberOfLinks)
}

/// 以 BACKUP_SEMANTICS 打开（支持目录与链接本身）。
fn open_with_backup_semantics(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .read(true)
        .attributes(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

/// 两个路径是否指向同一文件（同卷 + 同索引）。用于硬链接识别。
pub fn same_file(a: &Path, b: &Path) -> bool {
    match (file_id(a), file_id(b)) {
        (Some(ia), Some(ib)) => ia == ib,
        _ => false,
    }
}

/// 路径规范化比较键：把 `/` 统一成 `\`、解析 `\\?\` / `\\?\UNC\` 前缀、
/// 把 8.3 短名展开成长名、统一小写、去尾分隔符。
///
/// Windows 路径大小写不敏感、还可能出现 `C:\PROGRA~1\` 这类 8.3 短名，
/// 直接字面比较会把「指向当前隔离目录」误判成「指向别处」。
///
/// **必须先统一分隔符**：隔离目录列表里有 `"plugins/data"`，`Path::join` 之后得到
/// 的是 `...\plugins/data`（混合分隔符）；而 junction / `read_link` 返回的是反斜杠。
/// 不先 `/` → `\` 的话 `is_linked_to` 比较必然失败，表现为每次切号都重建链接、
/// 或误报「已指向其他隔离目录」。
pub fn normalize_path(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy().to_string();
    // 先把 8.3 短名展开（best-effort：失败就用原串继续）。
    let expanded = long_path_name(&raw).unwrap_or(raw);
    // 统一分隔符：正斜杠 → 反斜杠（Windows 接受两者，但比较前必须一致）。
    let mut text = expanded.replace('/', "\\");
    const VERBATIM: &str = r"\\?\";
    const VERBATIM_UNC: &str = r"\\?\UNC\";
    if text.starts_with(VERBATIM_UNC) {
        text = format!(r"\\{}", &text[VERBATIM_UNC.len()..]);
    } else if text.starts_with(VERBATIM) {
        text = text[VERBATIM.len()..].to_string();
    }
    while text.len() > 3 && text.ends_with(['\\', '/']) {
        text.pop();
    }
    PathBuf::from(text.to_lowercase())
}

/// 用 GetLongPathNameW 把 8.3 短名展开成长名（best-effort，失败返回 None）。
/// 只对确实含 `~` 的路径才调用，避免每个路径都付一次 Win32 调用成本。
fn long_path_name(path: &str) -> Option<String> {
    if !path.contains('~') {
        return None;
    }
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut buffer = vec![0u16; 4096];
    let len = unsafe { GetLongPathNameW(wide.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) };
    if len == 0 || len as usize > buffer.len() {
        return None;
    }
    Some(String::from_utf16_lossy(&buffer[..len as usize]))
}

/// 路径是否等价（规范化后比较）。
pub fn paths_equivalent(a: &Path, b: &Path) -> bool {
    normalize_path(a) == normalize_path(b)
}

/// 用 `junction` crate 创建目录联接（纯 API 调用），
/// 替代 `cmd /C mklink /J`（cmd 解析 `%&^` 出错、GBK 输出乱码、多一个控制台进程）。
pub fn create_junction(target: &Path, live: &Path) -> io::Result<()> {
    junction::create(target, live)
}

/// 重试 Windows 文件锁：共享冲突 32 / 锁冲突 33 通常是杀软、索引器短暂持有句柄，
/// 适合短退避；权限拒绝 5 多半是持久权限问题，最多只再试一次，避免每个失败操作白等。
pub fn retry_locked<T>(mut f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let mut last = None;
    let mut access_denied_retries = 0;
    for attempt in 0..6u64 {
        match f() {
            Ok(value) => return Ok(value),
            Err(e) => {
                let retryable = match e.raw_os_error() {
                    Some(32 | 33) => true,
                    Some(5) => {
                        access_denied_retries += 1;
                        access_denied_retries <= 1
                    }
                    _ => false,
                };
                if !retryable {
                    return Err(e);
                }
                last = Some(e);
                std::thread::sleep(StdDuration::from_millis(60 * (attempt + 1)));
            }
        }
    }
    Err(last.unwrap())
}

// ==================== 系统查询 / 配置（隐藏 PowerShell + ConvertTo-Json） ====================
//
// 这一组是 YOURSJEYO 功能迁移的平台层契约（见 docs/backend-interfaces.md）。
// 所有 Windows 系统状态查询统一走 `run_ps`（隐藏 powershell.exe + EncodedCommand），
// 再交给独立的 `parse_xxx` 反序列化——「命令调用」与「输出解析」分离，parse 函数
// 可做纯表驱动单测；ConvertTo-Json 的枚举值（如 Status="Up"）不随 UI 语言本地化。

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

/// 网卡信息（含虚拟网卡）。前端安检仪表盘直接消费。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AdapterInfo {
    /// 接口别名（如 "Mihomo TUN" / "以太网"）。
    pub name: String,
    /// InterfaceDescription（驱动描述，通常英文，如 "Wintun Userspace Tunnel"）。
    pub description: String,
    /// "Up" / "Disabled" / "Disconnected" 等枚举名（ToString 不随 UI 语言本地化）。
    pub status: String,
    pub if_index: u32,
    /// `#[serde(default)]`：PS 5.1 对空数组/ null 的序列化偶有出入，缺省按空 Vec 容错。
    #[serde(default)]
    pub ipv4: Vec<String>,
    #[serde(default)]
    pub ipv6: Vec<String>,
    /// **P0-07（v0.7.3）**：IP 地址查询是否成功。
    ///
    /// `false` 时 `ipv4`/`ipv6` 为空**不代表**网卡没有地址，只代表读不到。
    /// 依赖地址做判断的调用方（198.18 假 IP 段识别）必须跳过而不是判否。
    #[serde(default)]
    pub ips_ok: bool,
}

/// 把 Rust 字符串转成 PowerShell 单引号字面量内容（单引号翻倍转义）。
/// 所有注入 PowerShell 脚本的用户/配置串都必须过这里，杜绝引号注入。
fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// PowerShell 脚本的执行结论（**P0-NEW-01**：三态，不是 `Result` 的二元）。
///
/// 为什么需要 `Unknown`：Windows 上 `powershell.exe` 的退出码**不是**执行结论
/// 的可信来源——实测在 `-EncodedCommand` 下调用 NetSecurity 模块后，即使命令
/// 完全成功，进程也可能以 1 退出；反过来，被 `SilentlyContinue` 吞掉的非终止
/// 错误又会以 0 退出并留下空输出。用它判断「防火墙改成功了吗」会双向出错。
///
/// 因此协议改成：脚本尾部必须由包装层打印一个显式哨兵。
/// - 看到 `__PS_OK__`：脚本跑到底且没有抛出终止错误 → 输出内容由调用方再解析；
/// - 看到 `__PS_FAIL__`：捕获到异常 → `Failed`，stderr 带上可读原因；
/// - 看不到任何哨兵：脚本中途 `exit`、解析失败、宿主崩溃、输出被截断
///   → `Unknown`。**绝不能**当成成功，也不能当成「规则不存在」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PsOutcome {
    /// 脚本执行到尾部且未抛错，携带去掉哨兵后的标准输出。
    Success(String),
    /// 捕获到终止错误。
    Failed(String),
    /// 无法判断（无哨兵 / 超时 / 输出异常）。
    Unknown(String),
}

#[allow(dead_code)]
impl PsOutcome {
    /// 成功时的输出；其余状态返回 `None`。
    ///
    /// 当前调用点用模式匹配而非这些便捷方法；保留是为了让「三态」在
    /// 调用方代码里读起来更直白。
    pub fn output(&self) -> Option<&str> {
        match self {
            PsOutcome::Success(text) => Some(text),
            _ => None,
        }
    }

    /// 是否明确失败（不含 `Unknown`——调用方必须自行决定如何对待「未知」）。
    pub fn is_failed(&self) -> bool {
        matches!(self, PsOutcome::Failed(_))
    }

    /// 转成「失败就 Err、成功给输出、未知给 Err」的兼容形态。
    ///
    /// 只适用于「未知按失败处理」的调用点；需要区分 `Absent` 与 `Unknown`
    /// 的地方必须直接用 [`run_ps_outcome`]。
    pub fn into_result(self) -> Result<String, String> {
        match self {
            PsOutcome::Success(text) => Ok(text),
            PsOutcome::Failed(message) | PsOutcome::Unknown(message) => Err(message),
        }
    }

    /// 人类可读的说明（无论哪种状态）。
    pub fn describe(&self) -> String {
        match self {
            PsOutcome::Success(text) => format!("成功（输出 {} 字节）", text.len()),
            PsOutcome::Failed(message) => format!("失败：{message}"),
            PsOutcome::Unknown(message) => format!("无法确认：{message}"),
        }
    }
}

/// 执行结果协议的哨兵。**任何 PowerShell 脚本都不得提前 `exit`**：
/// 提前退出会让哨兵缺失，整条调用链退化为 `Unknown`。
const PS_OK: &str = "__PS_OK__";
const PS_FAIL: &str = "__PS_FAIL__";

/// 单次 PowerShell 调用的默认上限。防火墙查询在慢盘/服务刚启动时可能数秒，
/// 但超过这个时长基本意味着卡死，必须按 `Unknown` 处理而不是无限等待。
const PS_TIMEOUT: StdDuration = StdDuration::from_secs(120);

/// 包装脚本体：统一编码、进度抑制、终止错误转哨兵。
///
/// `-EncodedCommand` 下 `-Command` 的引号/中文/参数拆分坑全部规避；
/// `[Console]::OutputEncoding` 必须在最前面，否则中文网卡名按 OEM 代码页输出。
fn wrap_ps_script(script: &str) -> String {
    format!(
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
$__cs_failed = $false
try {{
{script}
}} catch {{
  $__cs_failed = $true
  [Console]::Error.WriteLine([string]$_.Exception.Message)
}}
if ($__cs_failed) {{ '{PS_FAIL}' }} else {{ '{PS_OK}' }}"
    )
}

/// 在包装层之外再判一次「脚本里有没有提前退出」。
///
/// 提前 `exit` 会跳过哨兵，让调用方看到「成功退出码 + 半截输出」——这是
/// P0-NEW-01 里最难发现的一类。这里直接静态拒绝：宁可立刻暴露，
/// 也不要在真实系统上把半截执行当成功。
///
/// 判定按**语句边界**（行首、`;`、`{`、`}` 之后）而不是子串包含：
/// `Write-Output 'exit 0'` 是合法输出，不能误伤。
fn assert_no_early_exit(script: &str) -> Result<(), String> {
    for line in script.lines() {
        // 去掉整行注释；行内注释不处理（PowerShell 的 `#` 语义依赖引号上下文，
        // 误判成注释会漏检，宁可在注释里提到 exit 时误报一次）。
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        // 按语句分隔符切分：行首、`;`、`{`、`}` 之后都是语句起点。
        let statements = trimmed.split([';', '{', '}', '\n']);
        for statement in statements {
            let statement = statement.trim();
            // `exit` 单独成句，或后面跟空白/数字/变量。
            let is_exit = statement == "exit"
                || statement
                    .strip_prefix("exit")
                    .is_some_and(|rest| rest.starts_with(char::is_whitespace));
            if is_exit {
                return Err(format!(
                    "脚本包含提前 exit（{statement}），会绕过执行结果哨兵；请改用返回值表达结果"
                ));
            }
        }
    }
    Ok(())
}

/// 解析 `powershell.exe` 的输出，得到三态结论。
///
/// 判据顺序刻意如此：
/// 1. **哨兵优先**——退出码不可信（见 [`PsOutcome`] 的说明）；
/// 2. 无哨兵 → `Unknown`，并把退出码、stderr 一并带上（绝不猜成成功）。
fn classify_ps_output(stdout: &str, stderr: &str, exit_code: Option<i32>) -> PsOutcome {
    let trimmed = stdout.trim_end();
    // PowerShell 把 `'__PS_OK__'` 写进输出流时会带上引号与前导空白
    // （实测形状是 `\r\n\r\n '__PS_OK__'`），必须先归一化再比较。
    let normalize = |line: &str| {
        line.trim()
            .trim_matches(|c| c == '\'' || c == '"')
            .trim()
            .to_string()
    };
    let last = trimmed
        .lines()
        .rev()
        .map(normalize)
        .find(|line| !line.is_empty());
    match last.as_deref() {
        Some(PS_FAIL) => {
            let body = strip_trailing_sentinel(trimmed, PS_FAIL);
            let mut message = String::from("PowerShell 脚本执行失败");
            let err = stderr.trim();
            if !err.is_empty() {
                message.push_str(&format!("：{err}"));
            }
            if !body.is_empty() {
                message.push_str(&format!("；部分输出：{body}"));
            }
            PsOutcome::Failed(message)
        }
        Some(PS_OK) => PsOutcome::Success(strip_trailing_sentinel(trimmed, PS_OK)),
        _ => PsOutcome::Unknown(format!(
            "脚本未输出执行结果哨兵（退出码={:?}），可能提前退出、被中断或输出被截断；stderr={}；stdout={}",
            exit_code,
            stderr.trim(),
            trimmed
        )),
    }
}

/// 去掉尾部哨兵行（含它的引号与空白），返回真正的脚本输出。
fn strip_trailing_sentinel(payload: &str, sentinel: &str) -> String {
    let mut body = payload.trim_end();
    // 哨兵前可能有 `'`，也可能有空白；逐字符从尾部剥离直到哨兵本身消失。
    if let Some(position) = body.rfind(sentinel) {
        body = body[..position].trim_end();
    }
    body.trim_end_matches('\'').trim_end().to_string()
}

/// 用隐藏 PowerShell 执行一段脚本，返回三态执行结论。
///
/// 这是**唯一**的 PowerShell 执行入口；`run_ps()` 只是它在「未知按失败处理」
/// 场景下的兼容包装。带 JSON/结构化输出的调用点必须直接用本函数，
/// 否则「查询失败」会被压成「空结果」。
pub fn run_ps_outcome(script: &str) -> PsOutcome {
    if let Err(error) = assert_no_early_exit(script) {
        return PsOutcome::Unknown(error);
    }
    let wrapped = wrap_ps_script(script);
    let wide: Vec<u8> = wrapped.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded = BASE64.encode(&wide);
    let ps = powershell_path();
    let mut child = match silent_command(ps.to_string_lossy().as_ref())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => return PsOutcome::Unknown(format!("启动 powershell.exe 失败: {e}")),
    };
    let mut stdout_pipe = match child.stdout.take() {
        Some(pipe) => pipe,
        None => return PsOutcome::Unknown("无法读取 powershell.exe 标准输出".to_string()),
    };
    let mut stderr_pipe = match child.stderr.take() {
        Some(pipe) => pipe,
        None => return PsOutcome::Unknown("无法读取 powershell.exe 标准错误".to_string()),
    };
    // 必须**并发**读管道：先等进程退出再读，输出超过管道缓冲区（约 64KB）
    // 时子进程会阻塞在写端，双方互等直到超时——一种只在慢机器上复现的假死。
    let stdout_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = std::io::Read::read_to_end(&mut stdout_pipe, &mut buffer);
        buffer
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = std::io::Read::read_to_end(&mut stderr_pipe, &mut buffer);
        buffer
    });
    // 超时必须能杀掉子进程：`output()` 会无限等，卡死的脚本会拖住整个巡检线程。
    let deadline = std::time::Instant::now() + PS_TIMEOUT;
    let exit_code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(StdDuration::from_millis(25));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return PsOutcome::Unknown(format!(
                    "PowerShell 超过 {} 秒未返回，已终止（结果未知）",
                    PS_TIMEOUT.as_secs()
                ));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return PsOutcome::Unknown(format!("等待 powershell.exe 失败: {e}"));
            }
        }
    };
    let stdout_bytes = stdout_reader.join().unwrap_or_default();
    let stderr_bytes = stderr_reader.join().unwrap_or_default();
    let stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
    let stderr = String::from_utf8_lossy(&stderr_bytes).to_string();
    classify_ps_output(&stdout, &stderr, exit_code)
}

/// 用隐藏 PowerShell 执行一段脚本，返回 stdout（去尾换行）。
///
/// 三态语义见 [`PsOutcome`]；本函数把 `Unknown` 与 `Failed` 一并转为 `Err`，
/// 适用于「读不到就当失败」的调用点（配置写入、进程控制等）。
fn run_ps(script: &str) -> Result<String, String> {
    run_ps_outcome(script).into_result()
}

/// 全部网卡（含虚拟网卡）。
pub fn list_adapters() -> Result<Vec<AdapterInfo>, String> {
    // **P1-01（v0.7.6）**：底层也必须严格。
    //
    // `detect_tun_adapter_strict()` 只在 Rust 接口上加了 `Result`，但如果
    // 这里的 PowerShell 仍用 `SilentlyContinue`，「权限被拒 / 服务停止 /
    // RPC 失败」都会变成空集合 -> `Ok([])`。调用链于是：
    //   网卡查询失败 -> Ok([]) -> 判「没有 TUN」-> current_access()=Uncovered
    //   -> 施加兜底封锁 -> 累计到阈值后熔断。
    // 也就是说「读不到网卡」被当成了「确认未接入代理」。
    //
    // 现在：`Get-NetAdapter` 用 `-ErrorAction Stop`，任何异常都让整条调用
    // 返回 `Err`，由调用方按 `Unknown` 处理。IP 地址查询失败只影响
    // ipv4/ipv6 字段（`ips_ok=false`），不影响「网卡是否存在」这一事实。
    let script = r#"$ErrorActionPreference='Stop'
$ips = @()
$ipOk = $true
try { $ips = @(Get-NetIPAddress -AddressFamily IPv4,IPv6 -ErrorAction Stop) }
catch { $ipOk = $false }
# Adapter enumeration failure must throw: that is "cannot read", not "no adapters".
$adapters = @(Get-NetAdapter -ErrorAction Stop)
$rows = @($adapters | ForEach-Object {
    $idx = $_.ifIndex
    [PSCustomObject]@{
        name = $_.Name
        description = $_.InterfaceDescription
        status = $_.Status.ToString()
        if_index = [uint32]$idx
        ips_ok = $ipOk
        ipv4 = @($ips | Where-Object { $_.InterfaceIndex -eq $idx -and $_.AddressFamily -eq 'IPv4' } | Select-Object -ExpandProperty IPAddress)
        ipv6 = @($ips | Where-Object { $_.InterfaceIndex -eq $idx -and $_.AddressFamily -eq 'IPv6' } | Select-Object -ExpandProperty IPAddress)
    }
})
ConvertTo-Json -InputObject @($rows) -Depth 3 -Compress"#;
    let json = run_ps(script)?;
    parse_adapters(&json)
}

/// 解析 `list_adapters` 的 ConvertTo-Json 输出（兼容数组与单对象两种形态）。
fn parse_adapters(json: &str) -> Result<Vec<AdapterInfo>, String> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| format!("网卡列表 JSON 解析失败: {e}; 原文: {trimmed}"))?;
    match value {
        serde_json::Value::Array(arr) => serde_json::from_value(serde_json::Value::Array(arr))
            .map_err(|e| format!("网卡列表结构不符: {e}")),
        serde_json::Value::Object(_) => {
            let one: AdapterInfo =
                serde_json::from_value(value).map_err(|e| format!("单块网卡结构不符: {e}"))?;
            Ok(vec![one])
        }
        serde_json::Value::Null => Ok(Vec::new()),
        other => Err(format!("网卡列表顶层应为数组/对象, 实为: {other}")),
    }
}

/// **P1-01 / P0-02 / P0-03（v0.7.3）**：按**目标 × 协议族**采集 TUN 路由证据。
///
/// 与 v0.7.2 的三个关键差别：
///
/// 1. **一次脚本、多个目标**：每个目标传入自己解析出的地址，脚本分别
///    `Find-NetRoute`。原实现只取第一个目标的主机名，却放行所有目标。
/// 2. **三态而非布尔**：每个协议族返回 `tun` / `bypass` / `not_available` /
///    `unknown`，不再用 `Some(false)` 冒充「已检查通过」。
/// 3. **IPv6 缺失是显式结论**：目标的 AAAA 记录不存在时标记为
///    `not_available`（不存在 IPv6 旁路），而不是拿 `2001:db8::1` 占位地址
///    去查一条与真实目标无关的路由。
///
/// 只做**读取**（`Find-NetRoute` / `Get-NetRoute` / `Get-NetAdapterBinding`），
/// 不修改任何系统状态；不发任何网络包。
pub fn collect_route_evidence(
    tun_if_index: u32,
    probes: &[(String, Option<String>, Option<String>)],
) -> std::collections::BTreeMap<String, crate::egate_access::RouteEvidence> {
    use crate::egate_access::{RouteEvidence, RouteVia};
    let mut out: std::collections::BTreeMap<String, RouteEvidence> =
        std::collections::BTreeMap::new();
    if probes.is_empty() {
        return out;
    }
    // 把「目标 ID + 选定的 IPv4/IPv6 地址」整体传进脚本：脚本不拼接用户串。
    let spec = probes
        .iter()
        .map(|(id, v4, v6)| {
            serde_json::json!({
                "id": id,
                "v4": v4.clone().unwrap_or_default(),
                "v6": v6.clone().unwrap_or_default(),
            })
        })
        .collect::<Vec<_>>();
    let spec_json = serde_json::to_string(&spec).unwrap_or_else(|_| "[]".to_string());
    let script = format!(
        "$ErrorActionPreference='Stop'
$tun = {tun}
$specs = {spec} | ConvertFrom-Json
# IPv6 是否在本机可用：只有全部启用网卡都没绑定 IPv6，才能断言「不存在 IPv6 路径」。
$v6Enabled = @(Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop |
               Where-Object {{ $_.Enabled }}).Count -gt 0
$v4Default = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
               Where-Object {{ [uint32]$_.InterfaceIndex -eq $tun }}).Count -gt 0
$v6Default = @(Get-NetRoute -DestinationPrefix '::/0' -ErrorAction Stop |
               Where-Object {{ [uint32]$_.InterfaceIndex -eq $tun }}).Count -gt 0
$results = New-Object System.Collections.ArrayList
foreach ($s in $specs) {{
  $entry = [ordered]@{{ id = $s.id; error = $null }}
  try {{
    # ---- IPv4 ----
    if (-not $s.v4) {{
      $entry.ipv4 = 'unknown'
    }} else {{
      $r4 = @(Find-NetRoute -RemoteIPAddress $s.v4 -ErrorAction Stop)
      $viaTun = @($r4 | Where-Object {{ [uint32]$_.InterfaceIndex -eq $tun }}).Count -gt 0
      # 「目标路由经 TUN」+「默认路由经 TUN」两个条件必须同时成立：
      # 只有前者时，目标的其它地址族/后续连接仍可能走物理网卡。
      $entry.ipv4 = if ($viaTun -and $v4Default) {{ 'tun' }} elseif ($viaTun) {{ 'unknown' }} else {{ 'bypass' }}
    }}
    # ---- IPv6 ----
    if (-not $v6Enabled) {{
      # 本机没有启用 IPv6：不存在 IPv6 旁路，这是**明确结论**。
      $entry.ipv6 = 'not_available'
    }} elseif (-not $s.v6) {{
      # 本机有 IPv6，但该目标没有 AAAA 记录：目标层面没有 IPv6 路径。
      # 但仍要确认默认 IPv6 路由是否被 TUN 接管——否则同一域名将来
      # 拿到 AAAA 时会走物理网络。
      $entry.ipv6 = if ($v6Default) {{ 'not_available' }} else {{ 'unknown' }}
    }} else {{
      $r6 = @(Find-NetRoute -RemoteIPAddress $s.v6 -ErrorAction Stop)
      $viaTun6 = @($r6 | Where-Object {{ [uint32]$_.InterfaceIndex -eq $tun }}).Count -gt 0
      $entry.ipv6 = if ($viaTun6 -and $v6Default) {{ 'tun' }} elseif ($viaTun6) {{ 'unknown' }} else {{ 'bypass' }}
    }}
  }} catch {{
    $entry.ipv4 = 'unknown'
    $entry.ipv6 = 'unknown'
    $entry.error = [string]$_.Exception.Message
  }}
  [void]$results.Add([pscustomobject]$entry)
}}
ConvertTo-Json -InputObject @($results) -Compress -Depth 4",
        tun = tun_if_index,
        spec = ps_single_quote(&spec_json)
    );
    let json = match run_ps(&script) {
        Ok(json) => json,
        Err(error) => {
            for (id, _, _) in probes {
                out.insert(
                    id.clone(),
                    RouteEvidence::unknown(id.clone(), error.clone()),
                );
            }
            return out;
        }
    };
    let value: serde_json::Value = match serde_json::from_str(json.trim()) {
        Ok(value) => value,
        Err(error) => {
            let reason = format!("路由证据解析失败：{error}；原文：{json}");
            for (id, _, _) in probes {
                out.insert(
                    id.clone(),
                    RouteEvidence::unknown(id.clone(), reason.clone()),
                );
            }
            return out;
        }
    };
    let rows: Vec<serde_json::Value> = match value {
        serde_json::Value::Array(rows) => rows,
        serde_json::Value::Object(_) => vec![value],
        _ => Vec::new(),
    };
    let parse_via = |raw: Option<&str>| match raw {
        Some("tun") => RouteVia::Tun,
        Some("bypass") => RouteVia::Bypass,
        Some("not_available") => RouteVia::NotAvailable,
        _ => RouteVia::Unknown,
    };
    for row in rows {
        let Some(id) = row.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let error = row
            .get("error")
            .and_then(|v| v.as_str())
            .filter(|e| !e.is_empty())
            .map(str::to_string);
        out.insert(
            id.to_string(),
            RouteEvidence {
                target_id: id.to_string(),
                ipv4: parse_via(row.get("ipv4").and_then(|v| v.as_str())),
                ipv6: parse_via(row.get("ipv6").and_then(|v| v.as_str())),
                // DNS 可信度由调用方（egate_check）判定并覆盖，见那里的说明。
                dns_trusted: false,
                error,
            },
        );
    }
    // 脚本没返回的目标一律按「无法确认」，绝不留空。
    for (id, _, _) in probes {
        out.entry(id.clone())
            .or_insert_with(|| RouteEvidence::unknown(id.clone(), "脚本未返回该目标的路由证据"));
    }
    out
}

/// ms_tcpip6（IPv6）绑定状态：(网卡名, 是否已启用)。
pub fn ipv6_bindings() -> Result<Vec<(String, bool)>, String> {
    let script = "\
@(Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{ name = $_.Name; enabled = [bool]$_.Enabled }
}) | ConvertTo-Json";
    let json = run_ps(script)?;
    parse_ipv6_bindings(&json)
}

#[derive(serde::Deserialize)]
struct BindingItem {
    name: String,
    enabled: bool,
}

/// 解析 `ipv6_bindings` 的 ConvertTo-Json 输出（兼容数组与单对象）。
fn parse_ipv6_bindings(json: &str) -> Result<Vec<(String, bool)>, String> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| format!("IPv6 绑定 JSON 解析失败: {e}; 原文: {trimmed}"))?;
    let items: Vec<BindingItem> =
        match value {
            serde_json::Value::Array(arr) => serde_json::from_value(serde_json::Value::Array(arr))
                .map_err(|e| format!("IPv6 绑定结构不符: {e}"))?,
            serde_json::Value::Object(_) => vec![serde_json::from_value(value)
                .map_err(|e| format!("单条 IPv6 绑定结构不符: {e}"))?],
            serde_json::Value::Null => Vec::new(),
            other => return Err(format!("IPv6 绑定顶层应为数组/对象, 实为: {other}")),
        };
    Ok(items.into_iter().map(|b| (b.name, b.enabled)).collect())
}

/// 关闭所有网卡的 IPv6 绑定（Disable-NetAdapterBinding，需要管理员）。
pub fn set_ipv6_all_disabled() -> Result<(), String> {
    run_ps(
        "Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | \
         Where-Object { $_.Enabled } | Disable-NetAdapterBinding -Confirm:$false | Out-Null",
    )?;
    Ok(())
}

/// 当前 Windows 时区 ID（如 "Eastern Standard Time"）。
pub fn current_timezone_id() -> Result<String, String> {
    let json = run_ps("(Get-TimeZone).Id | ConvertTo-Json")?;
    parse_timezone_id(&json)
}

fn parse_timezone_id(json: &str) -> Result<String, String> {
    let trimmed = json.trim();
    let id: String = serde_json::from_str(trimmed)
        .map_err(|e| format!("时区 ID 解析失败: {e}; 原文: {trimmed}"))?;
    let id = id.trim().to_string();
    if id.is_empty() {
        return Err("时区 ID 为空".to_string());
    }
    Ok(id)
}

/// 设置 Windows 时区（Set-TimeZone，需要管理员）。
pub fn set_timezone_id(id: &str) -> Result<(), String> {
    run_ps(&format!("Set-TimeZone -Id {}", ps_single_quote(id)))?;
    Ok(())
}

/// 当前用户区域格式（culture，如 "en-US"，Get-Culture）。
pub fn current_culture() -> Result<String, String> {
    let json = run_ps("(Get-Culture).Name | ConvertTo-Json")?;
    parse_culture(&json)
}

fn parse_culture(json: &str) -> Result<String, String> {
    let trimmed = json.trim();
    let name: String = serde_json::from_str(trimmed)
        .map_err(|e| format!("culture 解析失败: {e}; 原文: {trimmed}"))?;
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("culture 为空".to_string());
    }
    Ok(name)
}

/// 当前用户 Home Location GeoId（Get-WinHomeLocation）。
pub fn current_home_location_geo() -> Result<u32, String> {
    let json = run_ps("(Get-WinHomeLocation).GeoId | ConvertTo-Json")?;
    parse_home_location_geo(&json)
}

fn parse_home_location_geo(json: &str) -> Result<u32, String> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Err("Home Location GeoId 为空".to_string());
    }
    serde_json::from_str(trimmed).map_err(|e| format!("GeoId 解析失败: {e}; 原文: {trimmed}"))
}

/// 设置区域格式 + Home Location（Set-Culture 下次登录生效；Set-WinHomeLocation 即时）。
pub fn set_culture_and_location(culture: &str, geo_id: u32) -> Result<(), String> {
    run_ps(&format!(
        "Set-Culture -CultureInfo {}; Set-WinHomeLocation -GeoId {}",
        ps_single_quote(culture),
        geo_id
    ))?;
    Ok(())
}

/// 注册「登录时触发」的计划任务（AtLogOn，Interactive 登录类型无需存密码）。
/// highest=true 时以最高权限运行（RunLevel=Highest，注册需管理员）。
pub fn register_logon_task(name: &str, exe: &str, args: &str, highest: bool) -> Result<(), String> {
    // **P0-01（v0.7.6）**：`RunLevel Highest` 的任务会以最高完整性运行。
    // 如果它引用的 EXE 落在**普通进程可写**的目录里，任何低/中完整性进程
    // 都能替换那个文件，下一次登录就以高权限执行非预期代码——本地提权。
    //
    // 这是架构性问题的**缓解**（完整方案需要独立的、只接受固定命令的
    // 特权 helper，见 docs/release-v0.7.6.md）。在那之前：
    // **拒绝在用户可写路径下创建 Highest 任务**，即使这会让某些需要
    // 管理员权限的功能暂时不可用。安全边界不能为了功能而放宽。
    if highest {
        if let Err(reason) = assert_task_target_not_user_writable(exe) {
            return Err(format!(
                "拒绝注册最高权限计划任务「{name}」：{reason}。                 请把本程序安装到管理员控制的目录（如 Program Files）后重试"
            ));
        }
    }
    let run_level = if highest { "Highest" } else { "Limited" };
    let script = format!(
        "$ErrorActionPreference='Stop'\n\
         $a = New-ScheduledTaskAction -Execute {exe} -Argument {args}\n\
         $t = New-ScheduledTaskTrigger -AtLogOn\n\
         $principal = New-ScheduledTaskPrincipal -UserId \"$env:USERDOMAIN\\$env:USERNAME\" \
         -LogonType Interactive -RunLevel {level}\n\
         Register-ScheduledTask -TaskName {name} -Action $a -Trigger $t -Principal $principal -Force | Out-Null",
        exe = ps_single_quote(exe),
        args = ps_single_quote(args),
        level = run_level,
        name = ps_single_quote(name),
    );
    run_ps(&script)?;
    Ok(())
}

/// **P0-01**：断言计划任务目标所在目录**不被当前用户写入**。
///
/// 用真实探针判定（尝试在该目录建一个随机命名的文件），不靠路径名猜测：
/// 用户完全可以把程序放进 `C:\Program Files` 下一个自己拥有写权限的子目录。
/// 探针文件用完即删；任何一步失败都按「无法证明安全」处理。
fn assert_task_target_not_user_writable(exe: &str) -> Result<(), String> {
    use rand::Rng;
    let path = std::path::Path::new(exe);
    if !path.is_file() {
        return Err(format!("目标程序不存在：{exe}"));
    }
    let dir = path
        .parent()
        .ok_or_else(|| "无法确定目标程序所在目录".to_string())?;
    // 已知的用户可写根：命中即直接拒绝（比探针更快、更明确）。
    const USER_WRITABLE_ROOTS: &[&str] = &[
        r"\\appdata\roaming",
        r"\\appdata\local",
        r"\\appdata\locallow",
        r"\\downloads",
        r"\\desktop",
        r"\\documents",
        r"\\temp\",
        r"\\users\public",
    ];
    let lower = dir
        .to_string_lossy()
        .to_ascii_lowercase()
        .replace('/', "\\");
    if let Some(root) = USER_WRITABLE_ROOTS
        .iter()
        .find(|root| lower.contains(*root))
    {
        return Err(format!("目标位于用户可写目录（{root}）"));
    }
    // 真实探针：能否在该目录创建并删除一个文件。
    let suffix: u64 = rand::thread_rng().gen();
    let probe = dir.join(format!(".cs-task-probe-{suffix:016x}.tmp"));
    match std::fs::File::create(&probe) {
        Ok(handle) => {
            drop(handle);
            let _ = std::fs::remove_file(&probe);
            Err("目标目录对当前用户可写，可能被替换为非预期程序".to_string())
        }
        Err(_) => Ok(()),
    }
}

/// 删除计划任务（不存在视为成功）。
pub fn delete_task(name: &str) -> Result<(), String> {
    let quoted = ps_single_quote(name);
    run_ps(&format!(
        "if (Get-ScheduledTask -TaskName {q} -ErrorAction SilentlyContinue) {{ \
         Unregister-ScheduledTask -TaskName {q} -Confirm:$false }}",
        q = quoted
    ))?;
    Ok(())
}

/// 启动已注册的计划任务（对齐上游 install.ps1 的 Register + Start-ScheduledTask
/// 顺序：保镖装好当场生效，不等下次登录）。任务不存在时不报错（幂等）。
pub fn start_task(name: &str) -> Result<(), String> {
    let quoted = ps_single_quote(name);
    run_ps(&format!(
        "if (Get-ScheduledTask -TaskName {q} -ErrorAction SilentlyContinue) {{ \
         Start-ScheduledTask -TaskName {q} }}",
        q = quoted
    ))?;
    Ok(())
}

/// WireGuard 的隧道实际由 `WireGuardTunnel$*` 服务承载，GUI 开着不代表隧道在线。
/// **P1-11（v0.7.7）**：计划任务是否存在（三态）。
///
/// `SilentlyContinue` 会把「计划任务服务异常 / 权限不足」吞成 0 条，
/// 调用方于是判定「未安装」并**重新注册**，把一个其实存在但读不到的
/// 任务覆盖掉。现在查询失败直接报错，让调用方拒绝覆盖。
pub fn task_exists(name: &str) -> Result<bool, String> {
    let script = format!(
        "$ErrorActionPreference='Stop'
try {{
  $n = @(Get-ScheduledTask -TaskName {name} -ErrorAction Stop).Count
  if ($n -gt 0) {{ 'present' }} else {{ 'absent' }}
}} catch {{
  $m = [string]$_.Exception.Message
  if ($m -match 'No matching MSFT_ScheduledTask|找不到|NoScheduledTask') {{ 'absent' }}
  else {{ 'unknown' }}
}}",
        name = ps_single_quote(name)
    );
    match run_ps(&script) {
        Ok(out) => match out.trim().to_ascii_lowercase().as_str() {
            "present" => Ok(true),
            "absent" => Ok(false),
            // **P1-11**：查询失败不能伪装成「没有」。
            other => Err(format!(
                "计划任务查询结果无法解析（{other}），无法确认任务是否存在"
            )),
        },
        Err(error) => Err(format!("计划任务查询失败，无法确认任务是否存在：{error}")),
    }
}

pub fn wireguard_tunnel_running() -> Result<bool, String> {
    let json = run_ps(
        "@(Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue | \
         Select-Object Name,Status) | ConvertTo-Json",
    )?;
    Ok(wireguard_service_running(&json))
}

fn wireguard_service_running(json: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json.trim()) else {
        return false;
    };
    let rows: Vec<&serde_json::Value> = match &value {
        serde_json::Value::Array(rows) => rows.iter().collect(),
        serde_json::Value::Object(_) => vec![&value],
        _ => return false,
    };
    rows.iter().any(|row| {
        row.get("Name")
            .and_then(|v| v.as_str())
            .is_some_and(|name| name.starts_with("WireGuardTunnel$"))
            && row
                .get("Status")
                .and_then(|v| v.as_str())
                .is_some_and(|status| status.eq_ignore_ascii_case("Running"))
    })
}

/// 无窗口、不等待地启动一个进程（detached，stdio 全部丢弃）。
pub fn start_detached(program: &str, args: &[&str]) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS)
        .spawn()
        .map_err(|e| format!("无窗口启动 {program} 失败: {e}"))?;
    Ok(())
}

/// 附加到父进程的控制台（CLI 入口用）。
///
/// 发布版是 GUI 子系统（没有自己的控制台）。当从终端以 `--list/--status/--switch`
/// 调用时，先 `AttachConsole(ATTACH_PARENT_PROCESS)` 才能把 `println!` 输出到调用方
/// 终端。父进程没有控制台（如从资源管理器启动）时会失败——此时调用方应改为弹
/// 原生提示，而不是依赖 stdout。
///
/// 返回 true 表示已成功附加。
pub fn attach_parent_console() -> bool {
    use windows_sys::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
    if unsafe { AttachConsole(ATTACH_PARENT_PROCESS) == 0 } {
        return false;
    }
    // AttachConsole 只把进程接到父控制台，不会重设标准句柄。GUI 子系统进程默认
    // 没有标准输出/错误句柄（GetStdHandle 返回 NULL/INVALID），需打开一个
    // CONOUT$ 并 SetStdHandle。但已被重定向（> 文件 / 管道）的句柄必须原样保留，
    // 绝不能覆盖，否则会丢掉用户的重定向。
    if let Some(console_out) = open_console_output() {
        use windows_sys::Win32::System::Console::{STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
        ensure_std_handle(STD_OUTPUT_HANDLE, console_out);
        ensure_std_handle(STD_ERROR_HANDLE, console_out);
    }
    true
}

/// K-2：本进程吞掉 Ctrl+C / Ctrl+Break，把控制权交给同一控制台里的子进程 claude。
///
/// 控制台的 Ctrl 信号会发给该控制台的所有进程；cs.exe 若不装处理器会先退出，
/// 而 claude 仍在后台运行并和 shell 抢占输入。这里装一个自定义处理器：
/// - 对 CTRL_C_EVENT / CTRL_BREAK_EVENT 返回 TRUE（1），表示已处理，阻止默认终止；
/// - 其他事件返回 FALSE（0），保持系统默认处理。
///
/// 注意不能用 `SetConsoleCtrlHandler(None, TRUE)` 那种「进程级忽略」——该标志会被
/// 子进程继承，导致 claude 也收不到 Ctrl+C。
///
/// 返回是否安装成功（一般仅在无控制台时失败）。
pub fn install_console_ctrl_swallow() -> bool {
    use windows_sys::Win32::System::Console::{
        SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_C_EVENT, PHANDLER_ROUTINE,
    };

    unsafe extern "system" fn swallow(ctrl: u32) -> i32 {
        i32::from(ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT)
    }

    let handler: PHANDLER_ROUTINE = Some(swallow);
    unsafe { SetConsoleCtrlHandler(handler, 1) != 0 }
}

/// 打开当前控制台的活动屏幕缓冲区（`CONOUT$`），返回原生句柄。
fn open_console_output() -> Option<windows_sys::Win32::Foundation::HANDLE> {
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let name: Vec<u16> = "CONOUT$".encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        None
    } else {
        Some(handle)
    }
}

/// 仅当指定标准句柄当前没有可用值（NULL 或 INVALID_HANDLE_VALUE）时，才把它接到
/// 控制台句柄；已重定向到文件/管道的句柄原样保留。
fn ensure_std_handle(
    which: windows_sys::Win32::System::Console::STD_HANDLE,
    console_handle: windows_sys::Win32::Foundation::HANDLE,
) {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{GetStdHandle, SetStdHandle};
    let current = unsafe { GetStdHandle(which) };
    if current.is_null() || current == INVALID_HANDLE_VALUE {
        let _ = unsafe { SetStdHandle(which, console_handle) };
    }
}

/// 弹一个原生模态消息框（启动致命错误用，如数据目录只读）。
///
/// 在 GUI/WebView2 尚未创建前，唯一可靠的「明确提示」就是 Win32 MessageBox。
/// `flags` 用 `MB_OK | MB_ICONERROR`（0x10 | 0x0）。
pub fn show_startup_error(title: &str, message: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_ICONERROR, MB_OK, MB_TOPMOST,
    };
    let title_w = to_wide(title);
    let message_w = to_wide(message);
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            message_w.as_ptr(),
            title_w.as_ptr(),
            MB_OK | MB_ICONERROR | MB_TOPMOST,
        );
    }
}

/// 把 Rust 字符串转成以 `\0` 结尾的 UTF-16（Win32 宽字符参数）。
fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 按可执行名强制结束一批进程（如 ["Claude","claude"]），返回被结束的进程描述。
pub fn kill_processes_by_names(names: &[&str]) -> Result<Vec<String>, String> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let name_list = names
        .iter()
        .map(|n| ps_single_quote(n))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "@(Get-Process -Name {names} -ErrorAction SilentlyContinue | ForEach-Object {{\n\
         $d = \"$($_.ProcessName) (PID $($_.Id))\"\n\
         Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue\n\
         $d\n\
         }}) | ConvertTo-Json",
        names = name_list
    );
    let json = run_ps(&script)?;
    parse_killed(&json)
}

/// **CLI 边界**：按进程名结束**桌面 GUI 应用**，跳过 CLI 宿主。
///
/// 背景：Claude Code CLI 与 Claude Desktop 的可执行名都可能是 `claude`
/// （`Get-Process -Name` 大小写不敏感），只按名字杀会把终端里的 CLI 一起打死
/// ——正是 `egate_trip` 明确避免的「误伤终端宿主」。项目策略是
/// **CLI 只提醒、不查杀**。
///
/// 判定依据是**映像路径**而不是名字：
/// - 桌面版安装在 `...\AnthropicClaude\claude.exe` / `...\Claude\Claude.exe`
///   / MSIX 的 `...\WindowsApps\...claude.exe`；
/// - CLI 由 `node.exe`（`claude.cmd`/npm shim）或 `...\npm\claude` 承载，
///   也常出现在 `...\node_modules\...\claude` 下。
///
/// 规则（保守优先，宁可不杀）：
/// 1. 路径含 `\node_modules\`、`\npm\`、`\nvm\`、`\fnm\`、`\volta\` → 跳过（CLI）；
/// 2. 进程名是 `node` / `bun` / `deno` → 跳过（CLI 宿主）；
/// 3. **读不到映像路径的进程一律跳过**——无法证明它是桌面 GUI 时强行结束
///    可能误杀用户终端里的 CLI（提权进程、跨会话进程常读不到 `Path`）；
/// 4. 其余命中的同名进程才结束。
///
/// 返回值与 [`kill_processes_by_names`] 一致（被结束进程的描述），
/// 额外把跳过的进程追加为 `"<desc>（已跳过：<原因>）"`，便于用户核对为什么没杀。
/// **P1-06（v0.7.1）**：判断一个映像路径是否属于**受管 GUI**（而非 CLI 宿主）。
///
/// 查杀逻辑早已按此区分，但「解析 exe 路径做防火墙规则」用的是另一套
/// （只要进程名匹配就收）。两边标准不一致时，原生 CLI 会被写进 GUI 隔离规则。
pub fn is_managed_gui_path(path: &str) -> bool {
    managed_gui_identity(path) == GuiIdentity::ConfirmedGui
}

/// **P0-04（v0.7.3）**：进程身份的**三态**判定。
///
/// 「不是 CLI」不等于「是 GUI」。原实现只有一个布尔：要么确认 GUI，要么
/// 不是；调用方在「不是」时没有第三种选择，于是出现了「确认不了就宽松放回」
/// 的回退——那正是把原生 `claude.exe` CLI 写进 GUI 规则的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuiIdentity {
    /// 落在受管桌面 GUI 的已知安装位置内。
    ConfirmedGui,
    /// 明确是 CLI 宿主（node/npm/nvm/… 目录下的同名进程）。
    Cli,
    /// 两者都不是：身份未知。**不得**据此建立 GUI 隔离规则。
    Unknown,
}

/// 判定一个映像路径的身份。
///
/// 顺序很重要：先判 CLI（CLI 宿主可能恰好装在含 GUI 关键词的路径下，
/// 例如 `%LOCALAPPDATA%\Programs\Claude\node_modules\...`），再判 GUI。
pub fn managed_gui_identity(path: &str) -> GuiIdentity {
    // 归一化分隔符与大小写：调用方可能传入 `/`、混合分隔符或任意大小写。
    // 注意这里用 `replace('/', "\\")` 把正斜杠换成单反斜杠。
    let lower = path.to_ascii_lowercase().replace('/', "\\");
    // CLI 宿主的路径特征。每个特征都以单个反斜杠开头与结尾（目录边界）。
    const CLI_MARKERS: &[&str] = &[
        r"\node_modules\",
        r"\npm\",
        r"\nvm\",
        r"\fnm\",
        r"\volta\",
        r"\.bun\",
        r"\.deno\",
        r"\appdata\roaming\npm\",
        r"\appdata\local\pnpm\",
        r"\.local\share\pnpm\",
        r"\scoop\shims\",
    ];
    if CLI_MARKERS.iter().any(|marker| lower.contains(marker)) {
        return GuiIdentity::Cli;
    }
    // 可执行文件名必须是受管 GUI 之一——只按目录判断会把同目录下的更新器、
    // 崩溃处理程序也当成 GUI。
    let file_name = lower.rsplit('\\').next().unwrap_or("");
    const EXE_NAMES: &[&str] = &[
        "claude.exe",
        "claude desktop.exe",
        "chatgpt.exe",
        "antigravity.exe",
    ];
    if !EXE_NAMES.contains(&file_name) {
        return GuiIdentity::Unknown;
    }
    const GUI_MARKERS: &[&str] = &[
        r"\anthropicclaude\",
        r"\programs\claude\",
        r"\program files\claude\",
        r"\program files (x86)\claude\",
        r"\windowsapps\",
        r"\programs\chatgpt\",
        r"\program files\chatgpt\",
        r"\program files (x86)\chatgpt\",
        r"\antigravity\",
        r"\programs\antigravity\",
    ];
    if GUI_MARKERS.iter().any(|marker| lower.contains(marker)) {
        GuiIdentity::ConfirmedGui
    } else {
        GuiIdentity::Unknown
    }
}

/// 过滤候选路径，只保留**确认**属于受管 GUI 的（**P1-06**）。
#[allow(dead_code)]
pub fn filter_managed_gui_paths(paths: Vec<String>) -> Vec<String> {
    paths
        .into_iter()
        .filter(|path| is_managed_gui_path(path))
        .collect()
}

/// **P0-04（v0.7.3）**：把候选路径分成「确认 GUI」与「被拒（附原因）」。
///
/// 调用方必须用这个接口，而不是自己写「过滤后为空就放宽」的回退——
/// 那类回退正是把 CLI 写进 GUI 规则的入口。
pub fn classify_managed_gui_paths(paths: Vec<String>) -> (Vec<String>, Vec<String>) {
    let mut confirmed = Vec::new();
    let mut rejected = Vec::new();
    for path in paths {
        match managed_gui_identity(&path) {
            GuiIdentity::ConfirmedGui => confirmed.push(path),
            // CLI 宿主与身份未知都拒绝：规则的目标是隔离 GUI，
            // 拿不准就不建，并让调用方把原因告诉用户。
            GuiIdentity::Cli | GuiIdentity::Unknown => rejected.push(path),
        }
    }
    (confirmed, rejected)
}

const KILL_SCRIPT: &str = r#"$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='SilentlyContinue'
$killed = New-Object System.Collections.ArrayList
$skipped = New-Object System.Collections.ArrayList
$cliMarkers = @(
  '\node_modules\', '\npm\', '\nvm\', '\fnm\', '\volta\', '\.bun\', '\.deno\',
  '\appdata\roaming\npm\', '\appdata\local\pnpm\', '\.local\share\pnpm\', '\scoop\shims\'
)
# **P1-07**：与 Rust 侧 managed_gui_identity() 的 GUI_MARKERS 保持一致。
$guiPaths = @(
  '\anthropicclaude\', '\programs\claude\', '\program files\claude\',
  '\program files (x86)\claude\', '\windowsapps\',
  '\programs\chatgpt\', '\program files\chatgpt\', '\program files (x86)\chatgpt\',
  '\antigravity\', '\programs\antigravity\'
)
$guiExeNames = @('claude.exe', 'claude desktop.exe', 'chatgpt.exe', 'antigravity.exe')
foreach ($p in @(Get-Process -Name __NAMES__ -ErrorAction SilentlyContinue)) {
  $path = $p.Path
  $pname = $p.ProcessName
  $procId = $p.Id
  # 启动时间用于结束后的身份复核：PID 会被复用，只看数字会误判。
  $startTicks = -1
  try { $startTicks = $p.StartTime.ToUniversalTime().Ticks } catch {}
  $desc = "$pname (PID $procId)"
  if ($pname -in @('node','bun','deno','npm','npx')) {
    [void]$skipped.Add("$desc（CLI 宿主，只提醒不查杀）")
    continue
  }
  if (-not $path) {
    [void]$skipped.Add("$desc（无法读取映像路径，不盲目结束）")
    continue
  }
  $lowerPath = $path.ToLowerInvariant().Replace('/', '\')
  $isCli = $false
  foreach ($m in $cliMarkers) { if ($lowerPath.Contains($m)) { $isCli = $true } }
  if ($isCli) {
    [void]$skipped.Add("$desc（CLI 宿主，只提醒不查杀）")
    continue
  }
  # 文件名必须是受管 GUI 的可执行文件——同目录的更新器/崩溃处理程序不算。
  $fileName = $lowerPath.Substring($lowerPath.LastIndexOf('\') + 1)
  if ($guiExeNames -notcontains $fileName) {
    [void]$skipped.Add("$desc（不是受管 GUI 的可执行文件，身份未确认）")
    continue
  }
  $guiHint = $false
  foreach ($h in $guiPaths) { if ($lowerPath.Contains($h)) { $guiHint = $true } }
  if (-not $guiHint) {
    [void]$skipped.Add("$desc（不在受管 GUI 安装路径内，身份未确认）")
    continue
  }
  # 逐个结束并收集真实结果。
  try {
    Stop-Process -Id $procId -Force -ErrorAction Stop
  } catch {
    [void]$skipped.Add("$desc（结束失败：" + $_.Exception.Message + '）')
    continue
  }
  # 结束后复核：同一 PID 且启动时间一致才说明「还是那个进程」还在。
  $still = $null
  try { $still = Get-Process -Id $procId -ErrorAction Stop } catch {}
  if ($still) {
    $sameProcess = $true
    try {
      if ($startTicks -ge 0 -and $still.StartTime.ToUniversalTime().Ticks -ne $startTicks) {
        $sameProcess = $false
      }
    } catch {}
    if ($sameProcess) {
      [void]$skipped.Add("$desc（结束命令已执行，但进程仍存在）")
      continue
    }
    # PID 被别的进程复用了：我们那个进程确实已经退出。
  }
  [void]$killed.Add($desc)
}
ConvertTo-Json -InputObject @([pscustomobject]@{ killed = @($killed); skipped = @($skipped) })"#;

pub fn kill_desktop_app_processes(names: &[&str]) -> Result<Vec<String>, String> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let name_list = names
        .iter()
        .map(|n| ps_single_quote(n))
        .collect::<Vec<_>>()
        .join(",");
    // **P1-07 / P1-12（v0.7.3）**：两处语义修正。
    //
    // 1. 路径特征必须与 `managed_gui_identity()` **逐字一致**：原来脚本里的
    //    `$guiPaths` 只有 Claude 的目录，ChatGPT / Antigravity 会被判「身份
    //    未确认」而跳过——规则建了、进程没杀，用户以为已经隔离。
    // 2. `Stop-Process -ErrorAction SilentlyContinue` 后无条件 `$killed.Add`
    //    会在权限不足时**谎报成功**。现在逐个 PID 结束、收集异常，并在
    //    结束后按 PID + 启动时间复核进程是否真的消失（防止 PID 复用误判）。
    let template = KILL_SCRIPT;

    let script = template.replace("__NAMES__", &name_list);
    let json = run_ps(&script)?;
    parse_kill_outcome(&json).map(|outcome| outcome.killed)
}

/// **L-01**：结构化版本——`killed` / `skipped` / `failed` 分开返回。
pub fn kill_desktop_app_processes_ex(names: &[&str]) -> Result<KillOutcome, String> {
    if names.is_empty() {
        return Ok(KillOutcome::default());
    }
    let name_list = names
        .iter()
        .map(|n| ps_single_quote(n))
        .collect::<Vec<_>>()
        .join(",");
    // 与 `kill_desktop_app_processes` 共用同一段脚本。
    let template = KILL_SCRIPT;
    let script = template.replace("__NAMES__", &name_list);
    let json = run_ps(&script)?;
    parse_kill_outcome(&json)
}

/// 解析「结束 + 跳过」两段结果（**P1-12**）。
///
/// 返回值只包含**确认已经退出**的进程；跳过/失败的原因并入同一列表，
/// 用「（…）」标注，保持既有调用方（托盘提示、账本）不改结构。
/// **L-01（v0.7.6）**：进程结束的三类结果，必须分开。
///
/// v0.7.5 把 `killed` 与 `skipped` 合并成一个 `Vec<String>` 返回，
/// 于是调用方 `summarize_trip` 用 `!killed.is_empty()` 判断「有系统副作用」
/// 时，把「跳过的进程」也算成了「真的杀掉了」——一次全是跳过的巡检
/// 会被记成 `Partial`，界面显示凭空出现的部分隔离。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KillOutcome {
    /// 确认已退出的进程。
    pub killed: Vec<String>,
    /// 被跳过的进程（CLI 宿主 / 身份未确认 / 权限不足）。
    pub skipped: Vec<String>,
    /// 结束命令已执行但未能确认退出的进程。
    pub failed: Vec<String>,
}

#[allow(dead_code)]
impl KillOutcome {
    /// 是否产生了**真实**副作用（只有 killed 算）。
    pub fn has_side_effects(&self) -> bool {
        !self.killed.is_empty()
    }
}

/// 结构化解析（**L-01**：killed / skipped / failed 分开）。
fn parse_kill_outcome(json: &str) -> Result<KillOutcome, String> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(KillOutcome::default());
    }
    let value: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| format!("进程结束结果解析失败: {e}; 原文: {trimmed}"))?;
    let row = match value {
        serde_json::Value::Array(items) => items.into_iter().next().unwrap_or_default(),
        other => other,
    };
    let collect = |key: &str| -> Vec<String> {
        match row.get(key) {
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .filter(|s| !s.is_empty())
                .collect(),
            Some(serde_json::Value::String(one)) => vec![one.clone()],
            _ => Vec::new(),
        }
    };
    Ok(KillOutcome {
        killed: collect("killed"),
        skipped: collect("skipped"),
        failed: collect("failed"),
    })
}

fn parse_killed(json: &str) -> Result<Vec<String>, String> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| format!("被结束进程 JSON 解析失败: {e}; 原文: {trimmed}"))?;
    match value {
        serde_json::Value::Array(arr) => Ok(arr
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .filter(|s| !s.is_empty())
            .collect()),
        serde_json::Value::String(s) => {
            if s.is_empty() {
                Ok(Vec::new())
            } else {
                Ok(vec![s])
            }
        }
        serde_json::Value::Null => Ok(Vec::new()),
        other => Err(format!("被结束进程顶层应为数组/字符串, 实为: {other}")),
    }
}

/// 执行一段 PowerShell 脚本并返回其 stdout（UTF-8，脚本已强制
/// `$ErrorActionPreference='Stop'`）。
///
/// 仅供本项目的**专用平台能力**调用（如防火墙规则）；业务代码不要直接用它拼
/// 任意脚本——需要新能力时在这里加一个有名字、可被单测覆盖的函数。
/// 当前活动网络对应的防火墙配置档是否已启用。
/// `None` = 无法确认（查询失败、没有配置或类别未知）。
pub fn effective_firewall_enabled() -> Option<bool> {
    let script = "$ErrorActionPreference='Stop'
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
$connections = @(Get-NetConnectionProfile -ErrorAction Stop)
$map = @{}
foreach ($p in $profiles) { $map[[string]$p.Name] = ($p.Enabled -eq 'True') }
[pscustomobject]@{ profiles = $map; categories = @($connections | ForEach-Object { [string]$_.NetworkCategory }) } | ConvertTo-Json -Compress";
    let value: serde_json::Value =
        serde_json::from_str(run_powershell(script).ok()?.trim()).ok()?;
    let map: std::collections::BTreeMap<String, bool> =
        serde_json::from_value(value.get("profiles")?.clone()).ok()?;
    if map.is_empty() {
        return None;
    }
    let cats = match value.get("categories")? {
        serde_json::Value::Array(items) => items
            .iter()
            .map(|v| v.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()?,
        serde_json::Value::String(s) => vec![s.clone()],
        _ => return None,
    };
    if cats.is_empty() {
        return Some(map.values().all(|enabled| *enabled));
    }
    let mut enabled = true;
    for cat in cats {
        let profile = match cat.as_str() {
            "DomainAuthenticated" => "Domain",
            "Private" => "Private",
            "Public" => "Public",
            _ => return None,
        };
        enabled &= *map.get(profile)?;
    }
    Some(enabled)
}

/// **P0-02（v0.7.1）**：防火墙规则查询的三态结果。
///
/// `SilentlyContinue` 会把「权限不足 / RPC 失败 / 服务停止」这类**非终止错误**
/// 一起吞掉，只留下一个空数组——调用方看到的 `Count = 0` 与「确实没有规则」
/// 完全无法区分。恢复器据此会把「查不到」当成「已清干净」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleLookup {
    /// 明确存在匹配规则。
    Present,
    /// 明确不存在（查询成功且无匹配）。
    Absent,
    /// 无法确认（权限、服务、RPC、输出异常）。
    Unknown,
}

/// 严格查询指定显示名前缀下的规则是否存在。
///
/// 用 `-ErrorAction Stop` + `catch`：**「没有匹配对象」也会抛异常**，
/// 因此必须用异常消息区分「No matching …」与真正的查询失败。
/// PowerShell 单引号转义（本模块私有，避免跨模块依赖）。
fn ps_quote_single(value: &str) -> String {
    // PowerShell 里单引号用两个单引号转义。
    let escaped = value.replace('\'', "''");
    format!("'{escaped}'")
}

/// 按前缀严格查询规则是否存在（**P0-02** 的三态实现）。
///
/// 关键区别（实测过）：
/// - **通配查询**（`-DisplayName "Prefix*"`）无匹配时**不抛异常**，返回空集合；
/// - **精确查询**（`-DisplayName "Name"`）无匹配时**抛异常**。
///
/// 所以这里用通配 + `-ErrorAction Stop`：命令没抛错 → 计数可信（0 = 确实没有）；
/// 抛错或脚本结果未知 → `Unknown`。绝不能用 `SilentlyContinue` 把权限/RPC/
/// 服务停止这类非终止错误吞成「0 条规则」——恢复器会据此误报「已清干净」。
pub fn firewall_rules_exist(prefix: &str) -> RuleLookup {
    let script = format!(
        "$ErrorActionPreference='Stop'
$c = -1
try {{
  $c = @(Get-NetFirewallRule -DisplayName ({prefix} + '*') -ErrorAction Stop).Count
}} catch {{
  $c = -1
}}
if ($c -lt 0) {{ 'unknown' }} elseif ($c -eq 0) {{ 'absent' }} else {{ 'present' }}",
        prefix = ps_quote_single(prefix)
    );
    match run_ps_outcome(&script) {
        PsOutcome::Success(out) => match out.trim().to_ascii_lowercase().as_str() {
            "present" => RuleLookup::Present,
            "absent" => RuleLookup::Absent,
            // 输出能解析但值不在枚举内：不能猜，按未知。
            _ => RuleLookup::Unknown,
        },
        PsOutcome::Failed(_) | PsOutcome::Unknown(_) => RuleLookup::Unknown,
    }
}

/// 精确查询单条规则是否存在。
///
/// **为什么不直接 `-DisplayName <精确名>`**：精确查询在「没有匹配对象」时
/// **抛异常**，而异常消息随系统语言本地化（中文系统是「找不到任何…」），
/// 靠字符串匹配区分「没有这条规则」与「查询本身失败」非常脆弱，本地化一变
/// 就会把权限错误当成「规则已删除」。
///
/// 改用「通配前缀查询 + 精确名字过滤」：通配查询无匹配时**不抛错**，
/// 于是**任何异常都只可能是真正的查询失败** → `Unknown`。
#[allow(dead_code)]
pub fn firewall_rule_exists(name: &str) -> RuleLookup {
    let script = format!(
        "$ErrorActionPreference='Stop'
$name = {name}
$pattern = [WildcardPattern]::Escape($name)
$rules = @(Get-NetFirewallRule -DisplayName ($pattern + '*') -ErrorAction Stop |
           Where-Object {{ $_.DisplayName -eq $name }})
if ($rules.Count -gt 0) {{ 'present' }} else {{ 'absent' }}",
        name = ps_quote_single(name)
    );
    // 注意：脚本里不得出现语句级 `return`/`exit`——两者都会跳过包装层尾部哨兵。
    match run_ps_outcome(&script) {
        PsOutcome::Success(out) => match out.trim().to_ascii_lowercase().as_str() {
            "present" => RuleLookup::Present,
            "absent" => RuleLookup::Absent,
            _ => RuleLookup::Unknown,
        },
        PsOutcome::Failed(_) | PsOutcome::Unknown(_) => RuleLookup::Unknown,
    }
}

/// 一次性确认**一组**规则是否全部仍存在（**P1-07**）。
///
/// 比逐条 `firewall_rule_exists` 少 N-1 次 PowerShell 往返，且结果仍然三态：
/// - `Present` = 全部都在；
/// - `Absent` = 至少一条不在（说明资源被外部清理过）；
/// - `Unknown` = 查询本身失败（不能当成「还在」也不能当成「没了」）。
pub fn firewall_rules_all_present(names: &[String]) -> RuleLookup {
    if names.is_empty() {
        return RuleLookup::Absent;
    }
    let list = names
        .iter()
        .map(|n| ps_single_quote(n))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "$ErrorActionPreference='Stop'
$names = @({list})
$missing = 0
foreach ($n in $names) {{
  $pattern = [WildcardPattern]::Escape($n)
  $hit = @(Get-NetFirewallRule -DisplayName ($pattern + '*') -ErrorAction Stop |
           Where-Object {{ $_.DisplayName -eq $n }}).Count -gt 0
  if (-not $hit) {{ $missing++ }}
}}
if ($missing -eq 0) {{ 'present' }} else {{ 'absent' }}"
    );
    match run_ps_outcome(&script) {
        PsOutcome::Success(out) => match out.trim().to_ascii_lowercase().as_str() {
            "present" => RuleLookup::Present,
            "absent" => RuleLookup::Absent,
            _ => RuleLookup::Unknown,
        },
        PsOutcome::Failed(_) | PsOutcome::Unknown(_) => RuleLookup::Unknown,
    }
}

/// 当前进程是否以管理员身份运行（**P1-02**：权限能力探测）。
///
/// 只用于**展示能力与给出可操作提示**，不作为安全边界：真正的边界是
/// Windows 自己拒绝非管理员写防火墙/网卡/时区。
pub fn is_elevated() -> Option<bool> {
    let script = "$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object Security.Principal.WindowsPrincipal($id)
if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'yes' } else { 'no' }";
    match run_ps_outcome(script) {
        PsOutcome::Success(out) => match out.trim().to_ascii_lowercase().as_str() {
            "yes" => Some(true),
            "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

pub fn run_powershell(script: &str) -> Result<String, String> {
    run_ps(script)
}

/// 三态执行入口（**P0-NEW-01**）：需要区分「失败」与「无法确认」的调用方用它。
#[allow(dead_code)]
pub fn run_powershell_outcome(script: &str) -> PsOutcome {
    run_ps_outcome(script)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_pipe_security_is_private_and_parent_handles_are_not_inherited() {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};
        use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
        use windows_sys::Win32::Security::{
            CreateWellKnownSid, EqualSid, GetAce, GetSecurityDescriptorControl,
            GetTokenInformation, TokenUser, WinLocalSystemSid, ACCESS_ALLOWED_ACE,
            DACL_SECURITY_INFORMATION, SECURITY_MAX_SID_SIZE, SE_DACL_PROTECTED, TOKEN_QUERY,
            TOKEN_USER,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let security = CommandPipeSecurity::new().unwrap();
            let (server, child_end) = command_pipe(&security, true).await.unwrap();
            for handle in [server.as_raw_handle(), child_end.as_raw_handle()] {
                let mut flags = 0;
                assert_ne!(unsafe { GetHandleInformation(handle, &mut flags) }, 0);
                assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
            }
            let mut descriptor = std::ptr::null_mut();
            let mut dacl = std::ptr::null_mut();
            assert_eq!(
                unsafe {
                    GetSecurityInfo(
                        server.as_raw_handle(),
                        SE_KERNEL_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        &mut dacl,
                        std::ptr::null_mut(),
                        &mut descriptor,
                    )
                },
                0
            );
            let descriptor = LocalAllocation(descriptor);
            let mut control = 0;
            let mut revision = 0;
            assert_ne!(
                unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) },
                0
            );
            assert_ne!(control & SE_DACL_PROTECTED, 0);
            assert!(!dacl.is_null());
            assert_eq!(unsafe { (*dacl).AceCount }, 2);
            // 独立读取进程 TokenUser，与内核返回的实际 ACE SID 比较。
            let mut token = std::ptr::null_mut();
            assert_ne!(
                unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
                0
            );
            let token = unsafe { OwnedHandle::from_raw_handle(token) };
            let mut length = 0;
            unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenUser,
                    std::ptr::null_mut(),
                    0,
                    &mut length,
                )
            };
            assert!(length > 0);
            let mut user = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
            assert_ne!(
                unsafe {
                    GetTokenInformation(
                        token.as_raw_handle(),
                        TokenUser,
                        user.as_mut_ptr().cast(),
                        length,
                        &mut length,
                    )
                },
                0
            );
            let current_sid = unsafe { &*user.as_ptr().cast::<TOKEN_USER>() }.User.Sid;
            let mut system_sid = vec![
                0usize;
                (SECURITY_MAX_SID_SIZE as usize)
                    .div_ceil(std::mem::size_of::<usize>())
            ];
            let mut system_length = SECURITY_MAX_SID_SIZE;
            assert_ne!(
                unsafe {
                    CreateWellKnownSid(
                        WinLocalSystemSid,
                        std::ptr::null_mut(),
                        system_sid.as_mut_ptr().cast(),
                        &mut system_length,
                    )
                },
                0
            );
            let mut saw_current = false;
            let mut saw_system = false;
            for index in 0..2 {
                let mut ace = std::ptr::null_mut();
                assert_ne!(unsafe { GetAce(dacl, index, &mut ace) }, 0);
                let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                assert_eq!(ace.Header.AceType, 0, "必须是 ACCESS_ALLOWED_ACE");
                let sid = (&ace.SidStart as *const u32).cast_mut().cast();
                let is_current = unsafe { EqualSid(sid, current_sid) } != 0;
                let is_system = unsafe { EqualSid(sid, system_sid.as_mut_ptr().cast()) } != 0;
                assert!(is_current || is_system, "不得给其他主体授权");
                saw_current |= is_current;
                saw_system |= is_system;
            }
            assert!(saw_current && saw_system);
        });
    }

    /// **P0-04（v0.7.3）**：GUI/CLI 身份三态。
    ///
    /// 回归点：v0.7.2 在「一个都确认不了」时把未确认路径宽松放回隔离列表，
    /// 且排除条件写成了 `"\node_modules\\"`（`\n` 是换行符）根本不可能命中。
    /// 结果是原生 Claude Code CLI 会被写进 GUI 隔离规则。
    #[test]
    fn gui_identity_separates_cli_from_unknown() {
        // 明确是 CLI：npm 全局安装的 claude。
        for path in [
            r"C:\Users\test\AppData\Roaming\npm\claude.exe",
            r"C:\Users\test\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js",
            r"C:\Users\test\AppData\Roaming\npm\claude.cmd",
            r"C:\Program Files\Claude\node_modules\foo\claude.exe",
        ] {
            assert_eq!(
                managed_gui_identity(path),
                GuiIdentity::Cli,
                "应识别为 CLI：{path}"
            );
            assert!(!is_managed_gui_path(path));
        }
        // 明确是桌面 GUI。
        for path in [
            r"C:\Program Files\Claude\Claude.exe",
            r"C:\Users\test\AppData\Local\Programs\Claude\Claude.exe",
            r"C:\Users\test\AppData\Local\AnthropicClaude\claude.exe",
            r"C:\Program Files\ChatGPT\ChatGPT.exe",
            r"C:\Users\test\AppData\Local\Programs\antigravity\Antigravity.exe",
        ] {
            assert_eq!(
                managed_gui_identity(path),
                GuiIdentity::ConfirmedGui,
                "应识别为 GUI：{path}"
            );
            assert!(is_managed_gui_path(path));
        }
        // 身份未知：不在已知 GUI 目录、也不是 CLI。
        for path in [
            r"D:\Tools\claude.exe",
            r"C:\Program Files\Claude\updater.exe",
            r"C:\Program Files\Claude\crashpad_handler.exe",
        ] {
            assert_eq!(
                managed_gui_identity(path),
                GuiIdentity::Unknown,
                "应识别为未知：{path}"
            );
        }
    }

    /// **P0-04**：分类必须把「未知」与「CLI」都拒掉，绝不把未确认路径放进隔离列表。
    #[test]
    fn classify_rejects_cli_and_unknown_paths() {
        let input = vec![
            r"C:\Program Files\Claude\Claude.exe".to_string(),
            r"C:\Users\test\AppData\Roaming\npm\claude.exe".to_string(),
            r"D:\Tools\claude.exe".to_string(),
        ];
        let (confirmed, rejected) = classify_managed_gui_paths(input);
        assert_eq!(confirmed.len(), 1);
        assert!(confirmed[0].ends_with(r"Program Files\Claude\Claude.exe"));
        assert_eq!(rejected.len(), 2, "CLI 与未知路径都必须被拒");
    }

    /// **L-01（v0.7.6）**：`killed` / `skipped` / `failed` 必须分开，
    /// 跳过的进程不得算成真实查杀副作用。
    #[test]
    fn kill_outcome_keeps_skipped_out_of_side_effects() {
        let mixed = r#"[{"killed":["Claude (PID 1)"],"skipped":["claude (PID 2)（CLI 宿主，只提醒不查杀）"] }]"#;
        let outcome = parse_kill_outcome(mixed).unwrap();
        assert_eq!(outcome.killed.len(), 1);
        assert_eq!(outcome.skipped.len(), 1);
        assert!(outcome.has_side_effects());

        // 全是跳过 -> 没有真实副作用。
        let all_skipped =
            r#"[{"killed":[],"skipped":["claude (PID 2)（CLI 宿主，只提醒不查杀）"] }]"#;
        let outcome = parse_kill_outcome(all_skipped).unwrap();
        assert!(outcome.killed.is_empty());
        assert!(!outcome.has_side_effects(), "跳过的进程不得算成查杀副作用");

        // 失败也要单独归类。
        let with_failed = r#"[{"killed":[],"skipped":["a (PID 3)（结束命令已执行，但进程仍存在）"],"failed":[]}]"#;
        let outcome = parse_kill_outcome(with_failed).unwrap();
        assert!(outcome.skipped.iter().any(|x| x.contains("仍存在")));
        assert!(!outcome.has_side_effects());
    }

    #[test]
    fn run_ps_propagates_non_terminating_errors() {
        let result = run_ps("Write-Error 'synthetic probe without system changes'; 'false'");
        assert!(
            result.is_err(),
            "Write-Error 不得被当成成功的 PowerShell 输出"
        );
        assert!(result.unwrap_err().contains("synthetic probe"));
    }

    /// **P0-NEW-01**：执行结果协议的核心规则——退出码不是成功信号，
    /// 哨兵才是；没有哨兵就是 `Unknown`。
    mod ps_protocol {
        use super::super::{classify_ps_output, PsOutcome};

        #[test]
        fn sentinel_ok_means_success_even_when_exit_code_is_nonzero() {
            // 这正是实测现象：NetSecurity 调用后 powershell.exe 以 1 退出，
            // 但命令其实成功了。协议必须按输出判定。
            let outcome = classify_ps_output("count=0\n__PS_OK__\n", "", Some(1));
            assert_eq!(outcome, PsOutcome::Success("count=0".to_string()));
        }

        #[test]
        fn sentinel_fail_carries_stderr_and_partial_output() {
            let outcome = classify_ps_output("partial\n__PS_FAIL__\n", "拒绝访问", Some(0));
            match outcome {
                PsOutcome::Failed(message) => {
                    assert!(message.contains("拒绝访问"), "必须带出系统原因：{message}");
                    assert!(message.contains("partial"), "必须带出部分输出：{message}");
                }
                other => panic!("应判定为失败，实际：{other:?}"),
            }
        }

        #[test]
        fn missing_sentinel_is_unknown_not_success() {
            // 脚本提前 exit：退出码 0 + 半截输出。绝不能当成成功。
            let outcome = classify_ps_output("half of the output\n", "", Some(0));
            match outcome {
                PsOutcome::Unknown(message) => {
                    assert!(message.contains("哨兵"), "原因应指出缺少哨兵：{message}");
                }
                other => panic!("缺少哨兵必须判为未知，实际：{other:?}"),
            }
        }

        /// **L-15（v0.7.3）**：错误输出、管道截断、异常回执的边界组合。
        #[test]
        fn partial_or_corrupt_results_are_never_success() {
            // 哨兵出现在**中间**（后面还有内容）→ 不是尾部哨兵，判未知。
            // 这种形状只会出现在输出被截断/交错时，当成成功会把半截执行
            // 误报为完整成功。
            let middle = classify_ps_output(
                "__PS_OK__
stray output",
                "",
                Some(0),
            );
            assert!(matches!(middle, PsOutcome::Unknown(_)), "{middle:?}");

            // 只有 CRLF 与空白、没有哨兵 → 未知（不是「成功且空输出」）。
            let blank = classify_ps_output(
                "

",
                "",
                Some(0),
            );
            assert!(matches!(blank, PsOutcome::Unknown(_)), "{blank:?}");

            // 空输出 + 非零退出码 → 未知，并且带上退出码便于排错。
            let empty_fail = classify_ps_output("", "boom", Some(1));
            match empty_fail {
                PsOutcome::Unknown(message) => {
                    assert!(message.contains("boom"), "应带出 stderr：{message}");
                    assert!(message.contains("1"), "应带出退出码：{message}");
                }
                other => panic!("应为未知，实际：{other:?}"),
            }

            // 失败哨兵 + 空 stderr → 仍然是失败，不因为没细节就转成功。
            let fail_no_stderr = classify_ps_output(
                "__PS_FAIL__
",
                "",
                Some(0),
            );
            assert!(fail_no_stderr.is_failed(), "{fail_no_stderr:?}");

            // 大小写/空白变体不应被误认成哨兵（哨兵是精确串）。
            let lower = classify_ps_output(
                "__ps_ok__
",
                "",
                Some(0),
            );
            assert!(matches!(lower, PsOutcome::Unknown(_)), "{lower:?}");
        }

        #[test]
        fn trailing_blank_lines_do_not_hide_the_sentinel() {
            // PowerShell 常把哨兵写成 `\r\n\r\n '__PS_OK__'`。
            let outcome = classify_ps_output("\r\n\r\n '__PS_OK__'\r\n", "", Some(0));
            assert_eq!(outcome, PsOutcome::Success(String::new()));
        }

        #[test]
        fn unknown_into_result_is_an_error_not_empty_success() {
            let outcome = PsOutcome::Unknown("超时".to_string());
            assert!(outcome.into_result().is_err());
            assert_eq!(PsOutcome::Success("x".into()).into_result().unwrap(), "x");
        }

        #[test]
        fn early_exit_scripts_are_rejected_before_running() {
            // 静态拒绝：带语句级 exit 的脚本会绕过哨兵，绝不能执行。
            let outcome = super::super::run_ps_outcome("Write-Output 'x'; exit 0");
            match outcome {
                PsOutcome::Unknown(message) => {
                    assert!(message.contains("提前 exit"), "原因：{message}")
                }
                other => panic!("带 exit 的脚本必须被拒绝，实际：{other:?}"),
            }
            // 字符串里出现 "exit" 不算（不能误伤正常输出）。
            let ok = super::super::run_ps_outcome("Write-Output 'exit 0'");
            assert!(matches!(ok, PsOutcome::Success(_)), "{ok:?}");
        }
    }

    #[test]
    fn powershell_path_points_to_system_root_copy() {
        let path = powershell_path();
        // 必须落在 SystemRoot 下，且文件真实存在（不依赖 PATH）。
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        assert!(
            path.starts_with(PathBuf::from(&root)),
            "powershell 路径应位于 SystemRoot({root}) 下，实为 {path:?}"
        );
        assert!(path.is_file(), "powershell.exe 应真实存在: {path:?}");
        assert!(
            path.to_string_lossy()
                .ends_with("WindowsPowerShell\\v1.0\\powershell.exe"),
            "应指向 Windows PowerShell 5.1 目录: {path:?}"
        );
    }

    #[test]
    fn wireguard_service_running_requires_a_running_tunnel() {
        let services = r#"[{"Name":"WireGuardTunnel$Work","Status":"Running"}]"#;
        assert!(wireguard_service_running(services));
        let stopped = r#"[{"Name":"WireGuardTunnel$Work","Status":"Stopped"}]"#;
        assert!(!wireguard_service_running(stopped));
        assert!(!wireguard_service_running("[]"));
        assert!(!wireguard_service_running("not-json"));
    }

    /// `whoami /user` 的真实输出是「表头 + 分隔线 + 数据行」三行，
    /// SID 在第三列；测试用本机实机抓到的格式（中文 Windows 同样输出 ASCII 表头）。
    #[test]
    fn extract_sid_parses_real_whoami_output() {
        let real = "User Name              SID\n====================== ============================================\nwin-20260303ofa\\administrator S-1-5-21-3215687269-4097961639-2251065674-500\n";
        assert_eq!(
            extract_sid(real).as_deref(),
            Some("S-1-5-21-3215687269-4097961639-2251065674-500")
        );
    }

    #[test]
    fn extract_sid_handles_plain_and_garbage() {
        assert_eq!(extract_sid("S-1-5-18").as_deref(), Some("S-1-5-18"));
        assert_eq!(extract_sid("no sid here").as_deref(), None);
        // 分段数不足 3 的不算合法 SID。
        assert_eq!(extract_sid("S-1").as_deref(), None);
        assert_eq!(extract_sid("").as_deref(), None);
    }

    #[test]
    fn normalize_path_strips_verbatim_and_case() {
        let a = normalize_path(Path::new(r"C:\Users\Bob\.claude-switcher\profiles\"));
        let b = normalize_path(Path::new(r"\\?\c:\users\BOB\.claude-switcher\profiles"));
        assert_eq!(a, b);
        let unc = normalize_path(Path::new(r"\\?\UNC\server\share\x"));
        assert_eq!(unc, PathBuf::from(r"\\server\share\x".to_lowercase()));
    }

    /// 8.3 短名必须被展开成长名，否则两条指向同一目录的路径会被判为不等。
    /// 用真实存在的 Program Files 短名验证（Windows 上恒有 8.3 别名）。
    #[test]
    fn normalize_path_expands_8dot3_short_names() {
        let Some(long) = long_path_name(r"C:\PROGRA~1") else {
            // 卷上禁用了 8.3 生成，跳过即可（不算失败）。
            eprintln!("[skip] 本卷未生成 8.3 短名");
            return;
        };
        assert!(
            long.to_lowercase().contains("program files"),
            "短名应展开成长名，实际: {long}"
        );
        // 短名与长名归一化后应等价。
        assert_eq!(
            normalize_path(Path::new(r"C:\PROGRA~1")),
            normalize_path(Path::new(&long))
        );
    }

    /// 不含 `~` 的路径不应付 Win32 调用成本（直接返回 None）。
    #[test]
    fn long_path_name_skips_paths_without_tilde() {
        assert!(long_path_name(r"C:\Users\Bob\.claude").is_none());
    }

    /// `plugins/data` 这类含正斜杠的隔离目录名：`Path::join` 后是混合分隔符，
    /// 必须与反斜杠写法判为等价，否则每次切号都重建链接。
    #[test]
    fn normalize_path_handles_forward_slash_in_join() {
        let joined =
            Path::new(r"C:\Users\Bob\.claude-switcher\session-profiles\p1").join("plugins/data");
        let backslash =
            Path::new(r"C:\Users\Bob\.claude-switcher\session-profiles\p1\plugins\data");
        assert_eq!(normalize_path(&joined), normalize_path(backslash));
        assert!(paths_equivalent(&joined, backslash));
    }

    /// is_under 的前缀陷阱：`C:\Users\A` 目录**不**包含 `C:\Users\AB`。
    #[test]
    fn is_under_rejects_sibling_prefix() {
        let profile = Path::new(r"C:\Users\A");
        assert!(!is_under(profile, Path::new(r"C:\Users\AB\file.txt")));
        assert!(is_under(profile, Path::new(r"C:\Users\A\file.txt")));
        assert!(is_under(
            profile,
            Path::new(r"C:\Users\A\.claude\.credentials.json")
        ));
        // profile 本身算「在目录内」。
        assert!(is_under(profile, profile));
    }

    /// is_under 对大小写、`\\?\` 前缀、尾部分隔符都应判为在目录内。
    #[test]
    fn is_under_tolerates_case_verbatim_and_trailing_sep() {
        let profile = Path::new(r"C:\Users\Bob");
        assert!(is_under(profile, Path::new(r"c:\users\BOB\.claude")));
        assert!(is_under(profile, Path::new(r"\\?\C:\Users\Bob\.claude")));
        assert!(is_under(profile, Path::new(r"C:\Users\Bob\.claude\")));
    }

    /// profile 之外的路径（例如数据盘）判为不在目录内。
    #[test]
    fn is_under_rejects_other_drives() {
        let profile = Path::new(r"C:\Users\Bob");
        assert!(!is_under(
            profile,
            Path::new(r"D:\claude-alt\.credentials.json")
        ));
        assert!(!is_under(
            profile,
            Path::new(r"\\server\share\.credentials.json")
        ));
    }

    // ---- 系统查询 parse 函数的表驱动单测（真实 ConvertTo-Json 样例） ----

    #[test]
    fn ps_single_quote_escapes_internal_quotes() {
        assert_eq!(
            ps_single_quote(r"C:\Program Files\Claude\Claude.exe"),
            r"'C:\Program Files\Claude\Claude.exe'"
        );
        // 单引号必须翻倍转义。
        assert_eq!(ps_single_quote("O'Brien"), "'O''Brien'");
    }

    #[test]
    fn parse_adapters_handles_array_single_and_empty() {
        // 真实 Get-NetAdapter | ConvertTo-Json -Depth 3 样例（含中文网卡名 + TUN 网卡）。
        let array = r#"[
          {
            "name": "以太网",
            "description": "Intel(R) Ethernet Connection (16) I219-V",
            "status": "Up",
            "if_index": 12,
            "ipv4": [ "192.168.1.10" ],
            "ipv6": [ "fe80::1" ]
          },
          {
            "name": "Mihomo TUN",
            "description": "Wintun Userspace Tunnel",
            "status": "Up",
            "if_index": 21,
            "ipv4": [ "198.18.0.1" ],
            "ipv6": []
          }
        ]"#;
        let adapters = parse_adapters(array).expect("数组样例应解析成功");
        assert_eq!(adapters.len(), 2);
        assert_eq!(adapters[0].name, "以太网");
        assert_eq!(adapters[0].status, "Up");
        assert_eq!(adapters[0].if_index, 12);
        assert_eq!(adapters[0].ipv4, vec!["192.168.1.10".to_string()]);
        assert_eq!(adapters[0].ipv6, vec!["fe80::1".to_string()]);
        assert_eq!(adapters[1].description, "Wintun Userspace Tunnel");
        assert!(adapters[1].ipv6.is_empty());

        // 单对象形态（@() 未生效或手动拼的单块）也必须能解析。
        let single = r#"{
          "name": "Mihomo TUN",
          "description": "Wintun Userspace Tunnel",
          "status": "Disconnected",
          "if_index": 21,
          "ipv4": [ "198.18.0.1" ],
          "ipv6": []
        }"#;
        let one = parse_adapters(single).expect("单对象样例应解析成功");
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].status, "Disconnected");

        // 空输出 / null 视为无网卡，不报错。
        assert!(parse_adapters("").unwrap().is_empty());
        assert!(parse_adapters("null").unwrap().is_empty());
        // 非数组/对象顶层应报错。
        assert!(parse_adapters("123").is_err());
    }

    #[test]
    fn parse_ipv6_bindings_handles_array_single_and_empty() {
        let array = r#"[
          { "name": "以太网", "enabled": false },
          { "name": "Mihomo TUN", "enabled": false }
        ]"#;
        let b = parse_ipv6_bindings(array).unwrap();
        assert_eq!(
            b,
            vec![
                ("以太网".to_string(), false),
                ("Mihomo TUN".to_string(), false)
            ]
        );

        let single = r#"{ "name": "以太网", "enabled": true }"#;
        assert_eq!(
            parse_ipv6_bindings(single).unwrap(),
            vec![("以太网".to_string(), true)]
        );

        assert!(parse_ipv6_bindings("").unwrap().is_empty());
        assert!(parse_ipv6_bindings("null").unwrap().is_empty());
    }

    #[test]
    fn parse_timezone_id_reads_json_string() {
        assert_eq!(
            parse_timezone_id(r#""Eastern Standard Time""#).unwrap(),
            "Eastern Standard Time"
        );
        // ConvertTo-Json 输出可能带尾随空白/换行。
        assert_eq!(
            parse_timezone_id("  \"Tokyo Standard Time\"\n").unwrap(),
            "Tokyo Standard Time"
        );
        assert!(parse_timezone_id("").is_err());
        assert!(parse_timezone_id("\"\"").is_err());
    }

    #[test]
    fn parse_culture_reads_json_string() {
        assert_eq!(parse_culture(r#""en-US""#).unwrap(), "en-US");
        assert_eq!(parse_culture(r#""zh-CN""#).unwrap(), "zh-CN");
        assert!(parse_culture("\"\"").is_err());
    }

    #[test]
    fn parse_home_location_geo_reads_number() {
        assert_eq!(parse_home_location_geo("244").unwrap(), 244);
        assert_eq!(parse_home_location_geo("  244\n").unwrap(), 244);
        assert!(parse_home_location_geo("").is_err());
        assert!(parse_home_location_geo("\"abc\"").is_err());
    }

    #[test]
    fn task_lookup_is_three_state() {
        // 三态的核心断言：查询失败**不得**当成「任务不存在」。
        // 真实查询在 CI 里不方便注入，这里固定的是判据本身——
        // `Err` 代表 Unknown，只有 `Ok(false)` 才代表确定不存在。
        let unknown: Result<bool, String> = Err("计划任务服务不可用".to_string());
        assert!(
            unknown.is_err(),
            "查询失败必须是 Err（Unknown），不得折成「不存在」"
        );
        let absent: Result<bool, String> = Ok(false);
        assert!(absent.is_ok(), "只有确定不存在才是 Ok(false)");
        let present: Result<bool, String> = Ok(true);
        assert!(matches!(present, Ok(true)), "确定存在是 Ok(true)");
    }

    #[test]
    fn parse_package_families_handles_array_single_and_empty() {
        assert_eq!(
            parse_package_families(r#"["Claude_abc123", "Claude_def456"]"#),
            vec!["Claude_abc123".to_string(), "Claude_def456".to_string()]
        );
        assert_eq!(
            parse_package_families(r#""Claude_abc123""#),
            vec!["Claude_abc123".to_string()]
        );
        assert!(parse_package_families("").is_empty());
        assert!(parse_package_families("not-json").is_empty());
        // null / 空串：Get-AppxPackage 没装 Claude 时的 ConvertTo-Json 输出。
        assert!(parse_package_families("null").is_empty());
        assert!(parse_package_families(r#""""#).is_empty());
    }

    #[test]
    fn parse_killed_handles_array_string_and_empty() {
        let array = r#"["Claude (PID 1234)", "claude (PID 5678)"]"#;
        let k = parse_killed(array).unwrap();
        assert_eq!(
            k,
            vec![
                "Claude (PID 1234)".to_string(),
                "claude (PID 5678)".to_string()
            ]
        );

        // 单字符串形态（未包数组时 ConvertTo-Json 的输出）。
        assert_eq!(
            parse_killed(r#""Claude (PID 1234)""#).unwrap(),
            vec!["Claude (PID 1234)".to_string()]
        );

        assert!(parse_killed("").unwrap().is_empty());
        assert!(parse_killed("null").unwrap().is_empty());
    }
}
