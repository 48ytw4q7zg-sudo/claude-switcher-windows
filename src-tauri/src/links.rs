//! 隔离链接（session/config 按 profile 隔离）。
//!
//! - macOS/Linux：符号链接。
//! - Windows：目录优先符号链接（需开发者模式/管理员），降级 junction
//!   （`junction` crate 纯 API，替代 `cmd /C mklink /J`）；
//!   文件优先符号链接，降级硬链接（GetFileInformationByHandle 识别）。
//!
//! 链接判定用 reparse tag（OneDrive 占位符等不会误命中），
//! 目标比较用归一化路径（大小写 / `\\?\` 前缀 / 尾分隔符）。

use std::fs;
use std::path::Path;

use crate::platform::imp;

/// 当前 live 链接使用的模式（UI 显示用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkMode {
    Symlink,
    Junction,
    HardLink,
    NotLinked,
}

impl LinkMode {
    pub fn label(self) -> &'static str {
        match self {
            LinkMode::Symlink => "符号链接",
            LinkMode::Junction => "Junction",
            LinkMode::HardLink => "硬链接",
            LinkMode::NotLinked => "未链接",
        }
    }

    pub fn needs_developer_mode_hint(self) -> bool {
        self == LinkMode::Junction || self == LinkMode::HardLink
    }
}

/// 路径是否为本工具创建的链接（符号链接或 junction；硬链接单独判定）。
pub fn path_is_link(path: &Path) -> bool {
    imp::is_link(path)
}

pub fn path_exists_or_link(path: &Path) -> bool {
    path.exists() || path_is_link(path)
}

/// live 处当前链接的模式（目录: symlink/junction；文件: symlink/hardlink）。
pub fn detect_link_mode(live: &Path, target: &Path) -> LinkMode {
    if path_is_link(live) {
        #[cfg(windows)]
        {
            // junction::exists 精确判定 MOUNT_POINT tag（返回 io::Result）。
            if junction::exists(live).unwrap_or(false) {
                return LinkMode::Junction;
            }
            return LinkMode::Symlink;
        }
        #[cfg(not(windows))]
        {
            return LinkMode::Symlink;
        }
    }
    if live.exists() && imp::same_file(live, target) {
        return LinkMode::HardLink;
    }
    LinkMode::NotLinked
}

/// 创建隔离链接：目录 symlink→junction；文件 symlink→hard link。
pub fn link_path(target: &Path, live: &Path, label: &str) -> Result<(), String> {
    let is_dir = fs::metadata(target).map(|m| m.is_dir()).unwrap_or(false);

    if is_dir {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(target, live).map_err(|e| format!("创建 {label} 隔离链接失败: {e}"))
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::symlink_dir;
            match symlink_dir(target, live) {
                Ok(()) => Ok(()),
                Err(_) => imp::create_junction(target, live)
                    .map_err(|e| format!("创建 {label} junction 失败: {e}")),
            }
        }
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(target, live).map_err(|e| format!("创建 {label} 隔离链接失败: {e}"))
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::symlink_file;
            match symlink_file(target, live) {
                Ok(()) => Ok(()),
                Err(_) => fs::hard_link(target, live)
                    .map_err(|e| format!("创建 {label} 隔离硬链接失败: {e}")),
            }
        }
    }
}

/// 删除 live 处的隔离链接。Unix：remove_file。
/// Windows：目录链接（符号链接/junction）直接 `remove_dir`——它只移除 reparse point，
/// 不删目标内容；文件链接走 `remove_file`。
///
/// 早期实现是先试 `remove_file` 失败再 `remove_dir`，而 `retry_locked` 把
/// ERROR_ACCESS_DENIED(5) 也当成可重试——对 junction 调 remove_file 常返回 5，
/// 于是每个目录链接都要白等约 1.3 秒（6 次退避）才降级。这里按类型直接分支。
pub fn remove_link(live: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        fs::remove_file(live).map_err(|e| format!("移除旧链接失败: {e}"))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileTypeExt;
        // 先看链接自身类型（不跟随），避免对目录链接走文件删除路径。
        let is_dir_link = fs::symlink_metadata(live)
            .map(|m| m.file_type().is_symlink_dir())
            .unwrap_or(false);
        if is_dir_link {
            // junction 也归到这里：symlink_metadata 对 junction 报 is_symlink()=true。
            return crate::fsx::remove_dir_with_retry(live)
                .map_err(|e| format!("移除旧链接失败: {}", crate::fsx::humanize_io_error(&e)));
        }
        match crate::fsx::remove_file_with_retry(live) {
            Ok(()) => Ok(()),
            Err(_) => crate::fsx::remove_dir_with_retry(live)
                .map_err(|e| format!("移除旧链接失败: {}", crate::fsx::humanize_io_error(&e))),
        }
    }
}

/// live 是否已链接到 target（符号链接/junction 归一化比较，硬链接按文件 ID）。
pub fn is_linked_to(live: &Path, target: &Path) -> bool {
    if path_is_link(live) {
        if let Ok(linked) = fs::read_link(live) {
            return imp::paths_equivalent(&linked, target);
        }
        return false;
    }
    live.exists() && imp::same_file(live, target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_link_mode_for_plain_dir() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("t");
        fs::create_dir_all(&target).unwrap();
        let live = dir.path().join("live");
        assert_eq!(detect_link_mode(&live, &target), LinkMode::NotLinked);
    }

    #[cfg(windows)]
    #[test]
    fn detect_link_mode_for_junction() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("t");
        fs::create_dir_all(&target).unwrap();
        let live = dir.path().join("live");
        imp::create_junction(&target, &live).unwrap();
        assert_eq!(detect_link_mode(&live, &target), LinkMode::Junction);
        assert!(is_linked_to(&live, &target));
    }

    #[cfg(windows)]
    #[test]
    fn is_linked_to_is_case_insensitive_on_windows() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("T-Dir");
        fs::create_dir_all(&target).unwrap();
        let live = dir.path().join("live");
        imp::create_junction(&target, &live).unwrap();
        // 同一路径换大小写写法也应认为已链接。
        let variant = dir.path().join("t-dir");
        assert!(is_linked_to(&live, &variant));
    }

    /// 悬空链接（目标已被删除）必须仍被识别为链接。
    /// 这是 activate_* 的关键前提：`live.exists()` 对悬空链接返回 false，
    /// 若不先判 path_is_link 就会走进「创建目录」分支并最终建链接失败。
    #[cfg(windows)]
    #[test]
    fn dangling_junction_is_still_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("t");
        fs::create_dir_all(&target).unwrap();
        let live = dir.path().join("live");
        imp::create_junction(&target, &live).unwrap();
        fs::remove_dir(&target).unwrap(); // 目标消失 → live 变成悬空链接

        assert!(!live.exists(), "悬空链接的 exists() 应为 false");
        assert!(path_is_link(&live), "但 path_is_link 必须仍为 true");
        assert!(path_exists_or_link(&live));
        // 悬空链接仍「指向」那个路径（只是目标暂时不存在），
        // read_link 能读出目标，故 is_linked_to 为 true —— 这是正确的：
        // 下次 activate 应重建链接，而不是把它当成「指向别处」。
        assert!(
            is_linked_to(&live, &target),
            "悬空链接的目标路径仍是 target，应判为已链接"
        );
        // remove_link 必须能清掉悬空链接。
        remove_link(&live).expect("悬空链接应可移除");
        assert!(!path_is_link(&live));
    }
}
