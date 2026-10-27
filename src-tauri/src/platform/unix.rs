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
