//! Unix（macOS/Linux）平台适配层：与 [`crate::platform::windows`] 保持同名 API。

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Unix 无黑窗问题；保留同名 API 以便调用方零 cfg 使用。
pub fn silent_command(program: &str) -> std::process::Command {
    std::process::Command::new(program)
}

pub fn current_pid() -> u32 {
    std::process::id()
}

pub fn current_username() -> Result<String, String> {
    if let Ok(name) = std::env::var("USER") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    // $USER 不可用时退回 whoami；两者都失败就报错，绝不写死某个用户名。
    let whoami = silent_command("whoami")
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                None
            }
        })
        .filter(|name| !name.is_empty());
    whoami.ok_or_else(|| "无法确定当前系统用户名（$USER 与 whoami 均失败）".to_string())
}

/// Unix：本工具数据目录按 0o700 收敛（创建时）。返回是否成功。
pub fn secure_app_data_dir(dir: &Path) -> bool {
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).is_ok()
}

/// Unix：单个文件按 0o600 收敛（凭据类文件，配置目录被改到 home 外时用）。
/// 调用方在 Windows cfg 分支内；unix 保留同签名实现供 API 对齐。
#[allow(dead_code)]
pub fn secure_private_file(path: &Path) -> bool {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).is_ok()
}

/// Unix：路径是否在 home 下（home 内默认私有，无需额外收敛）。
pub fn is_under_user_profile(path: &Path) -> bool {
    match dirs::home_dir() {
        Some(home) => path.starts_with(home),
        None => false,
    }
}

/// Unix：std 的 symlink 判定即足够。
pub fn is_link(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
}

/// Unix：靠 (dev, inode) 判定同一文件。
pub fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(ma), Ok(mb)) => ma.dev() == mb.dev() && ma.ino() == mb.ino(),
        _ => false,
    }
}

pub fn number_of_links(path: &Path) -> Option<u32> {
    let meta = fs::metadata(path).ok()?;
    use std::os::unix::fs::MetadataExt;
    Some(meta.nlink() as u32)
}

/// Unix 路径大小写敏感：仅做词法清理（去尾分隔符）。
pub fn normalize_path(path: &Path) -> PathBuf {
    let mut text = path.to_string_lossy().to_string();
    while text.len() > 1 && text.ends_with('/') {
        text.pop();
    }
    PathBuf::from(text)
}

pub fn paths_equivalent(a: &Path, b: &Path) -> bool {
    normalize_path(a) == normalize_path(b)
}

/// Unix 上 create_junction 不会被调用（目录直接 symlink）；提供 stub 以对齐 API。
/// 仅 Windows 路径调用，stub 供 API 对齐。
#[allow(dead_code)]
pub fn create_junction(_target: &Path, _live: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "junction 仅存在于 Windows",
    ))
}

/// Unix 无 Windows 式共享冲突；直接执行一次。
pub fn retry_locked<T>(mut f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    f()
}

// ==================== Windows 专有系统查询的 unix 占位 ====================
//
// 与 windows.rs 保持同名 API（见 docs/backend-interfaces.md）。本仓库主交付是
// Windows 版，unix 下这些系统状态查询无对应物；返回 Err 以保证整箱编译通过，
// 业务侧在 Windows 分支外不会真正调用。

/// 与 windows.rs 同形的网卡信息结构体（unix 占位，仅用于类型对齐）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AdapterInfo {
    pub name: String,
    pub description: String,
    pub status: String,
    pub if_index: u32,
    #[serde(default)]
    pub ipv4: Vec<String>,
    #[serde(default)]
    pub ipv6: Vec<String>,
}

pub fn list_adapters() -> Result<Vec<AdapterInfo>, String> {
    Err("该平台暂不支持 list_adapters".to_string())
}

pub fn ipv6_bindings() -> Result<Vec<(String, bool)>, String> {
    Err("该平台暂不支持 ipv6_bindings".to_string())
}

pub fn set_ipv6_all_disabled() -> Result<(), String> {
    Err("该平台暂不支持 set_ipv6_all_disabled".to_string())
}

pub fn current_timezone_id() -> Result<String, String> {
    Err("该平台暂不支持 current_timezone_id".to_string())
}

pub fn set_timezone_id(_id: &str) -> Result<(), String> {
    Err("该平台暂不支持 set_timezone_id".to_string())
}

pub fn current_culture() -> Result<String, String> {
    Err("该平台暂不支持 current_culture".to_string())
}

pub fn current_home_location_geo() -> Result<u32, String> {
    Err("该平台暂不支持 current_home_location_geo".to_string())
}

pub fn set_culture_and_location(_culture: &str, _geo_id: u32) -> Result<(), String> {
    Err("该平台暂不支持 set_culture_and_location".to_string())
}

pub fn register_logon_task(
    _name: &str,
    _exe: &str,
    _args: &str,
    _highest: bool,
) -> Result<(), String> {
    Err("该平台暂不支持 register_logon_task".to_string())
}

pub fn delete_task(_name: &str) -> Result<(), String> {
    Err("该平台暂不支持 delete_task".to_string())
}

pub fn start_task(_name: &str) -> Result<(), String> {
    Err("该平台暂不支持 start_task".to_string())
}

pub fn task_exists(_name: &str) -> Result<bool, String> {
    Err("该平台暂不支持 task_exists".to_string())
}

pub fn wireguard_tunnel_running() -> Result<bool, String> {
    Err("该平台暂不支持 wireguard_tunnel_running".to_string())
}

pub fn start_detached(program: &str, args: &[&str]) -> Result<(), String> {
    let _ = (program, args);
    Err("该平台暂不支持 start_detached".to_string())
}

pub fn kill_processes_by_names(names: &[&str]) -> Result<Vec<String>, String> {
    let _ = names;
    Err("该平台暂不支持 kill_processes_by_names".to_string())
}
