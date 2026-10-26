//! 文件系统辅助：原子写入（临时文件 + rename 覆盖 + 锁重试）、带重试的 rename/删除。
//!
//! Windows 上 Claude Code / VS Code 监视器、杀软实时扫描会短暂持有句柄，
//! 截断式 fs::write 中途崩溃会直接丢数据——所以全部落盘走「写临时文件再 rename」。

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use crate::platform::imp;

/// 原子替换：把 `from` rename 成 `to`，Windows 共享冲突时短退避重试。
///
/// **不要在失败路径上删目标**：Rust 的 `fs::rename` 在 Windows 上本来就会替换
/// 已存在的目标（`MoveFileEx` 带 `MOVEFILE_REPLACE_EXISTING`），所以「目标已存在」
/// 从来不是失败原因。早期实现里有一个「删掉目标再 rename」的兜底分支，它只会在
/// 6 次重试全失败（杀软 / 索引器占着文件）时触发——此时旧文件已被删掉、新文件又
/// rename 不进来，目标数据整体丢失。这里写的是 `store.private.json` 和
/// `.credentials.json`，代价太大，因此失败就原样报错，旧文件保持不变。
pub fn rename_with_retry(from: &Path, to: &Path) -> io::Result<()> {
    retry_io(|| fs::rename(from, to))
}

/// 带锁重试的删除（目录）。
pub fn remove_dir_with_retry(path: &Path) -> io::Result<()> {
    imp::retry_locked(|| fs::remove_dir(path))
}

/// 带锁重试的删除（文件）。
pub fn remove_file_with_retry(path: &Path) -> io::Result<()> {
    imp::retry_locked(|| fs::remove_file(path))
}

/// 通用短退避重试（Windows 错误 5/32/33；其它平台执行一次）。
/// unix 侧的 `retry_locked` 就是直接执行一次，故无需再按平台分支。
pub fn retry_io<T>(f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    imp::retry_locked(f)
}

/// 原子写入文本：同目录写 `.<原文件名>.tmp-<rand>` 临时文件 → rename 覆盖。
/// 中途崩溃/被锁时目标文件保持旧内容，绝不半截。
///
/// 临时名用「文件名 + 后缀」而不是 `with_extension`：后者会把 `.credentials.json`
/// 的 `.json` 替换掉（变成 `.credentials.tmp-xxx`），语义错误且残留物难辨认。
///
/// 细节处理：
/// - **权限继承**：Unix 上 atomic rename 会丢掉原文件的 mode（上游对凭据类文件
///   做过 0600）。写临时文件后先把原文件的权限复制过来；原文件不存在则设 0600。
/// - **写句柄 sync**：`sync_all` 需要写权限，用只读句柄打开再 sync 在 Windows 上
///   必然失败（`FlushFileBuffers` 要求 `GENERIC_WRITE`）。这里用写模式打开、写完
///   立即 sync。
/// - **符号链接解析**：若目标本身是链接（symlink/junction/硬链接），直接 rename
///   会把链接替换成普通文件、隔离就断了。先解析到真实路径再写。
pub fn write_atomically(path: &Path, contents: &str) -> io::Result<()> {
    // 目标若是符号链接，写到链接指向的真实文件上（否则 rename 会替换掉链接本身）。
    let resolved = resolve_if_link(path);
    let path = resolved.as_path();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    // 记住原文件的权限，rename 之后要复刻回去（仅 Unix 需要；Windows 用 ACL 继承）。
    #[cfg(unix)]
    let original_mode = fs::metadata(path).ok().map(|m| m.permissions());

    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let tmp = path.with_file_name(format!(
        ".{file_name}.tmp-{}",
        uuid::Uuid::new_v4().simple()
    ));

    // 写临时文件：用写模式打开，写完立刻 sync 落盘（凭据文件丢不起）。
    let write_result = (|| -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    // 复刻权限：原文件存在则沿用其 mode；不存在（首次创建）则按 0600 收敛，
    // 避免凭据类文件在 Unix 上以默认 umask（常为 0644）落盘。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = match &original_mode {
            Some(perms) => perms.mode(),
            None => 0o600,
        };
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(mode));
    }

    let result = rename_with_retry(&tmp, path);
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// 若 `path` 是符号链接，返回它指向的真实路径；否则原样返回。
/// 用 `canonicalize` 会把相对链接也解析成绝对路径，符合写入意图。
fn resolve_if_link(path: &Path) -> std::path::PathBuf {
    if crate::platform::imp::is_link(path) {
        if let Ok(real) = fs::canonicalize(path) {
            return real;
        }
    }
    path.to_path_buf()
}

/// 清理本工具遗留的原子写临时文件（进程被杀会留下 `.<name>.tmp-<uuid>`）。
///
/// **只删修改时间超过 10 分钟的**：正在并发写入的临时文件可能刚创建几秒，
/// 删掉它会让对方的 rename 失败（Windows 允许删除已打开的文件）。
/// 10 分钟足以区分「残留」与「正在写」——本工具的写入都是毫秒级。
/// best-effort：只删本工具命名规则的残留，不碰别人的文件。
pub fn cleanup_stale_tmp_files(dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(600);
    let mut removed = 0;
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // 形如 `.store.private.json.tmp-<32位hex>`。
        if !name.starts_with('.') || !name.contains(".tmp-") {
            continue;
        }
        // 只清理陈旧的；拿不到 mtime 时保守跳过（不删）。
        let is_stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .map(|mtime| mtime < cutoff)
            .unwrap_or(false);
        if is_stale && fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
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
