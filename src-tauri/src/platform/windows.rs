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

/// 只把 `~/.claude-switcher` 收敛为当前用户完全控制（创建目录时执行一次，
/// 子项继承 ACL），绝不逐文件 icacls、绝不动 Claude Code 自己的文件
/// （`~/.claude.json` / `settings.json` / `.credentials.json` 都继承用户目录 ACL，
/// 官方本来就是这么存的）。
///
/// 顺序固定为「先授权、再断继承」：单独执行 `/inheritance:r` 会把文件锁成谁都读不了。
/// icacls 失败不影响主流程——目录位于用户 profile 下，默认 ACL 已是当前用户私有。
pub fn secure_app_data_dir(dir: &Path) {
    let Some(username) = username_for_icacls() else {
        return;
    };
    let path = dir.to_string_lossy().to_string();
    // 用同一个 icacls 进程先 grant 再断继承，避免中间态。
    let output = silent_command("icacls")
        .arg(&path)
        .args(["/grant:r", &format!("{username}:(OI)(CI)F")])
        .args(["/inheritance:r"])
        .output();
    let _ = output;
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

/// 路径规范化比较键：解析 `\\?\` / `\\?\UNC\` 前缀、把 8.3 短名展开成长名、
/// 统一小写、去尾分隔符。
/// Windows 路径大小写不敏感、还可能出现 `C:\PROGRA~1\` 这类 8.3 短名，
/// 直接字面比较会把「指向当前隔离目录」误判成「指向别处」。
pub fn normalize_path(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy().to_string();
    // 先把 8.3 短名展开（best-effort：失败就用原串继续）。
    let expanded = long_path_name(&raw).unwrap_or(raw);
    let mut text = expanded;
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

/// 重试 Windows 文件锁（ERROR_SHARING_VIOLATION 32 / ERROR_ACCESS_DENIED 5 /
/// ERROR_LOCK_VIOLATION 33）：Claude Code、VS Code 监视器或索引器短暂持有句柄时
/// rename/删除会失败，短退避重试通常即可通过。
pub fn retry_locked<T>(mut f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let mut last = None;
    for attempt in 0..6u64 {
        match f() {
            Ok(value) => return Ok(value),
            Err(e) if matches!(e.raw_os_error(), Some(5 | 32 | 33)) => {
                last = Some(e);
                std::thread::sleep(StdDuration::from_millis(60 * (attempt + 1)));
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
