//! 文件系统辅助：原子写入（临时文件 + rename 覆盖 + 锁重试）、带重试的 rename/删除。
//!
//! Windows 上 Claude Code / VS Code 监视器、杀软实时扫描会短暂持有句柄，
//! 截断式 fs::write 中途崩溃会直接丢数据——所以全部落盘走「写临时文件再 rename」。

use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration as StdDuration;

use crate::platform::imp;

/// 原子替换：把 `from` rename 成 `to`，Windows 共享冲突时短退避重试。
/// RenameToFileInfo::Posix Semantics 不可用（std 未暴露），失败时退回「删目标再 rename」。
pub fn rename_with_retry(from: &Path, to: &Path) -> io::Result<()> {
    let direct = || fs::rename(from, to);
    if let Ok(result) = retry_io(direct) {
        return Ok(result);
    }
    // Windows 上目标已存在时 rename 会失败（ERROR_ALREADY_EXISTS）；
    // 先移走/删除旧目标再 rename。
    if to.exists() {
        let _ = fs::remove_file(to);
    }
    retry_io(|| fs::rename(from, to))
}

/// 带锁重试的删除（目录）。
pub fn remove_dir_with_retry(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    return imp::retry_locked(|| fs::remove_dir(path));
    #[cfg(not(windows))]
    fs::remove_dir(path)
}

/// 带锁重试的删除（文件）。
pub fn remove_file_with_retry(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    return imp::retry_locked(|| fs::remove_file(path));
    #[cfg(not(windows))]
    fs::remove_file(path)
}

/// 通用短退避重试（Windows 错误 5/32/33；其它平台执行一次）。
pub fn retry_io<T>(f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    #[cfg(windows)]
    {
        imp::retry_locked(f)
    }
    #[cfg(not(windows))]
    {
        f()
    }
}

/// 原子写入文本：同目录写 `.<原文件名>.tmp-<rand>` 临时文件 → rename 覆盖。
/// 中途崩溃/被锁时目标文件保持旧内容，绝不半截。
///
/// 临时名用「文件名 + 后缀」而不是 `with_extension`：后者会把 `.credentials.json`
/// 的 `.json` 替换掉（变成 `.credentials.tmp-xxx`），语义错误且残留物难辨认。
pub fn write_atomically(path: &Path, contents: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let tmp = path.with_file_name(format!(
        ".{file_name}.tmp-{}",
        uuid::Uuid::new_v4().simple()
    ));
    fs::write(&tmp, contents)?;
    // 确保数据先落盘（凭据文件丢不起）。
    if let Ok(file) = fs::File::open(&tmp) {
        let _ = file.sync_all();
    }
    let result = rename_with_retry(&tmp, path);
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// 给「Windows 上目录被占用导致接管失败」的错误信息补上人话提示。
pub fn humanize_io_error(error: &io::Error) -> String {
    let text = error.to_string();
    #[cfg(windows)]
    {
        if matches!(error.raw_os_error(), Some(5 | 32 | 33)) {
            return format!(
                "{text}（文件被占用：请关闭正在运行的 Claude Code / VS Code / 杀软实时扫描后重试）"
            );
        }
    }
    let _ = StdDuration::from_millis(0);
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomically_replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.json");
        fs::write(&path, "old").unwrap();
        write_atomically(&path, "new-content").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new-content");
        // 临时文件不残留。
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert_eq!(leftovers.len(), 1, "目录里应只剩目标文件: {leftovers:?}");
    }

    #[test]
    fn write_atomically_creates_parents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/c/data.json");
        write_atomically(&path, "{}").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{}");
    }

    /// 临时文件名必须保留原文件的完整文件名（含扩展名前的点）。
    /// 早期实现用 `with_extension` 会把 `.credentials.json` 变成 `.credentials.tmp-xxx`
    /// （丢掉 `.json`），语义错误且残留物难辨认。
    #[test]
    fn write_atomically_preserves_dotfile_extension_in_tmp_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".credentials.json");
        fs::write(&path, "old").unwrap();
        write_atomically(&path, "new").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        // 目标文件名必须原样保留（没被 with_extension 改写成 .credentials.tmp-*）。
        assert!(path.exists(), ".credentials.json 应仍然存在");
        assert_eq!(path.file_name().unwrap(), ".credentials.json");
        // 无临时残留。
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(names.len(), 1, "目录里应只剩目标文件: {names:?}");
    }
}
