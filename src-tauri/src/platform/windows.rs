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
}

/// 把 Rust 字符串转成 PowerShell 单引号字面量内容（单引号翻倍转义）。
/// 所有注入 PowerShell 脚本的用户/配置串都必须过这里，杜绝引号注入。
fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// 用隐藏 PowerShell 执行一段脚本，返回 stdout（去尾换行）。
///
/// - `-EncodedCommand`：脚本以 UTF-16LE 做 Base64，彻底绕开命令行引号、中文、
///   `-Command` 参数拆分等坑。
/// - `CREATE_NO_WINDOW`（来自 silent_command）：托盘常驻时不闪黑窗。
/// - 脚本头强制 `[Console]::OutputEncoding = UTF8`：否则中文网卡名在 OEM 代码页
///   （中文系统为 GBK）下会被 Rust 按 UTF-8 lossy 读成乱码。
/// - 非零退出码转 Err，stderr/stdout 一并带回便于排错。
fn run_ps(script: &str) -> Result<String, String> {
    let wrapped = format!(
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n\
         $OutputEncoding = [System.Text.Encoding]::UTF8\n\
         $ErrorActionPreference = 'Stop'\n\
         {script}"
    );
    let wide: Vec<u8> = wrapped.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded = BASE64.encode(&wide);
    let ps = powershell_path();
    let out = silent_command(ps.to_string_lossy().as_ref())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded,
        ])
        .output()
        .map_err(|e| format!("启动 powershell.exe 失败: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(format!(
            "PowerShell 失败(退出码={:?}): stderr={} stdout={}",
            out.status.code(),
            stderr.trim_end(),
            stdout.trim_end()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

/// 全部网卡（含虚拟网卡）。
pub fn list_adapters() -> Result<Vec<AdapterInfo>, String> {
    let script = "\
$ips = Get-NetIPAddress -AddressFamily IPv4,IPv6 -ErrorAction SilentlyContinue
@(Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
    $idx = $_.ifIndex
    [PSCustomObject]@{
        name = $_.Name
        description = $_.InterfaceDescription
        status = $_.Status.ToString()
        if_index = [uint32]$idx
        ipv4 = @($ips | Where-Object { $_.InterfaceIndex -eq $idx -and $_.AddressFamily -eq 'IPv4' } | Select-Object -ExpandProperty IPAddress)
        ipv6 = @($ips | Where-Object { $_.InterfaceIndex -eq $idx -and $_.AddressFamily -eq 'IPv6' } | Select-Object -ExpandProperty IPAddress)
    }
}) | ConvertTo-Json -Depth 3";
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

/// 计划任务是否存在。
pub fn task_exists(name: &str) -> Result<bool, String> {
    let json = run_ps(&format!(
        "@(Get-ScheduledTask -TaskName {} -ErrorAction SilentlyContinue).Count -gt 0 | ConvertTo-Json",
        ps_single_quote(name)
    ))?;
    parse_task_exists(&json)
}

fn parse_task_exists(json: &str) -> Result<bool, String> {
    let trimmed = json.trim();
    serde_json::from_str(trimmed).map_err(|e| format!("task_exists 解析失败: {e}; 原文: {trimmed}"))
}

/// WireGuard 的隧道实际由 `WireGuardTunnel$*` 服务承载，GUI 开着不代表隧道在线。
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_ps_propagates_non_terminating_errors() {
        let result = run_ps("Write-Error 'synthetic probe without system changes'; 'false'");
        assert!(
            result.is_err(),
            "Write-Error 不得被当成成功的 PowerShell 输出"
        );
        assert!(result.unwrap_err().contains("synthetic probe"));
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
    fn parse_task_exists_reads_bool() {
        assert!(parse_task_exists("true").unwrap());
        assert!(!parse_task_exists("false").unwrap());
        assert!(parse_task_exists("  true  ").unwrap());
        assert!(parse_task_exists("null").is_err());
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
