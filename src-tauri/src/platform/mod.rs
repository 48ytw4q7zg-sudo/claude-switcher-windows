//! 平台适配层（Windows 专用）。
//!
//! - [`crate::platform::windows`]：Windows 实现（静默子进程、ACL、junction、
//!   reparse tag、路径归一化、文件 ID、工作区、锁重试、系统查询）。
//!
//! 本项目只面向 Windows：非 Windows 目标直接编译报错，不提供 Unix 兜底。
//! 历史上这里还有 `unix.rs` 对等实现，已按「只做 Windows」的产品决定移除。

#[cfg(not(windows))]
compile_error!("claude-switcher 仅支持 Windows；macOS/Linux 适配代码已移除");

pub mod windows;
pub use windows as imp;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Windows 专有语义（`\\?\` 前缀剥离 + 大小写归一）。
    /// 必须 cfg(windows)：unix 的 normalize_path 只做词法清理，
    /// 在 macOS CI 上跑这个断言必然失败。
    #[cfg(windows)]
    #[test]
    fn normalize_path_handles_verbatim_case_and_trailing_sep() {
        let a = imp::normalize_path(Path::new(
            r"C:\Users\Bob\.claude-switcher\session-profiles\p1\projects\",
        ));
        let b = imp::normalize_path(Path::new(
            r"\\?\C:\users\BOB\.claude-switcher\session-profiles\p1\projects",
        ));
        assert_eq!(a, b, r"Windows 上 \\?\ 前缀/大小写/尾分隔符应归一化等价");
    }

    #[test]
    fn paths_equivalent_rejects_different_dirs() {
        let a = Path::new(r"C:\Users\Bob\.claude-switcher\session-profiles\p1");
        let b = Path::new(r"C:\Users\Bob\.claude-switcher\session-profiles\p2");
        assert!(!imp::paths_equivalent(a, b));
    }

    #[cfg(windows)]
    #[test]
    fn is_link_and_junction_roundtrip() {
        let dir = tempfile::tempdir().expect("创建临时目录失败");
        let target = dir.path().join("target-dir");
        std::fs::create_dir_all(&target).expect("创建目标目录失败");
        let live = dir.path().join("live");
        imp::create_junction(&target, &live).expect("创建 junction 失败");
        assert!(imp::is_link(&live), "junction 应被识别为链接");
        assert!(live.is_dir());
        // junction 与其目标的 canonical 一致（穿过链接）。
        let canon_live = std::fs::canonicalize(&live).expect("canonicalize 失败");
        let canon_target = std::fs::canonicalize(&target).expect("canonicalize 失败");
        assert_eq!(canon_live, canon_target);
    }

    #[cfg(windows)]
    #[test]
    fn same_file_detects_hard_link() {
        let dir = tempfile::tempdir().expect("创建临时目录失败");
        let a = dir.path().join("a.txt");
        std::fs::write(&a, b"hello").expect("写文件失败");
        let b = dir.path().join("b.txt");
        std::fs::hard_link(&a, &b).expect("创建硬链接失败");
        assert!(imp::same_file(&a, &b));
        assert_eq!(imp::number_of_links(&a), Some(2));
    }
}
