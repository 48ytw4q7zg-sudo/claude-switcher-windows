//! 跨身份保留（keep-in-workspace.txt）。
//!
//! 切换账号前，把「与身份无关、跨账号保留」的通用配置（如 `settings.json`、`skills/`）
//! 从当前 Claude 数据目录收进暂存目录；载入目标账号后再合并回去。
//!
//! 语义对齐上游 `core/claude-switch.sh` 的 `stage_keep_paths` / `restore_keep_paths`：
//! - keep 列表每行一个**相对** Claude 数据目录的路径；`#` 注释、空行忽略。
//! - 绝对路径（`/x`、`C:\x`、UNC）、含 `..` 分量、路径分量上的符号链接/junction
//!   → 跳过并记 WARN，绝不收 DATA 外的内容。
//! - keep 列表缺失或为空 → no-op（与未启用完全一致）。
//! - 暂存目录若有残留（上次还原失败留下的唯一完整副本）→ 拒绝覆盖，整体报错。
//! - 合并成功后清空暂存目录；合并中途失败则保留暂存目录供排查。
//!
//! `base`（Claude 数据目录）作为参数传入，便于同时复用于 Claude Code CLI 数据目录
//! 与 Claude Desktop 数据目录；keep 列表与暂存目录固定在工具私有目录
//! （`~/.claude-switcher`）。

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::fsx::retry_io;
use crate::platform::imp;

/// 一条已通过安全校验的 keep 条目（正斜杠风格、无 `./` 前缀、无尾分隔符）。
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct KeepEntry {
    pub rel: String,
}

/// 暂存/合并结果（后续接 Tauri 命令时直接序列化回前端）。
#[derive(Debug, Clone, serde::Serialize, Default, PartialEq, Eq)]
pub struct KeepReport {
    /// `disabled`（未启用/no-op）｜`empty`（列表为空或无可收路径）｜`staged`｜`merged`。
    pub status: &'static str,
    /// 本次实际暂存 / 合并的条目数。
    pub count: usize,
    /// 因安全原因跳过的条目数。
    pub skipped: usize,
    /// 逐条 WARN（含解析期与执行期）。
    pub warnings: Vec<String>,
    /// 人话摘要。
    pub message: String,
}

impl KeepReport {
    fn disabled(msg: impl Into<String>) -> Self {
        Self {
            status: "disabled",
            count: 0,
            skipped: 0,
            warnings: Vec::new(),
            message: msg.into(),
        }
    }
}

/// keep 列表路径：`~/.claude-switcher/keep-in-workspace.txt`。
pub fn keep_list_path() -> PathBuf {
    match crate::paths::app_data_dir() {
        Ok(dir) => dir.join("keep-in-workspace.txt"),
        // HOME 不可定位是极端情况：退回相对路径，stage 会读不到文件而按 disabled 处理。
        Err(_) => PathBuf::from("keep-in-workspace.txt"),
    }
}

/// 暂存目录：`~/.claude-switcher/keep-stage`。
pub fn keep_stage_dir() -> PathBuf {
    match crate::paths::app_data_dir() {
        Ok(dir) => dir.join("keep-stage"),
        Err(_) => PathBuf::from("keep-stage"),
    }
}

/// 解析 keep 列表文本：返回（有效条目, 跳过原因 WARN）。
///
/// 规则：trim 后空行 / 以 `#` 开头忽略（不记 WARN）；绝对路径、**盘符前缀
/// （`C:` / `C:foo` 这类「盘符相对路径」，`PathBuf::join` 会整体替换 base）**、
/// 含 `..` 分量、归一化后为空或 `.` → 记 WARN 跳过。
pub fn parse_keep_list(text: &str) -> (Vec<KeepEntry>, Vec<String>) {
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if is_absolute_path(line) || has_drive_prefix(line) {
            warnings.push(format!("keep 路径必须是相对路径，已跳过: {line}"));
            continue;
        }
        let normalized = normalize_rel(line);
        if normalized.is_empty() || normalized == "." {
            warnings.push(format!("keep 路径为空或指向数据目录本身，已跳过: {line}"));
            continue;
        }
        // 分量级 .. 校验（拒绝 a/../b、../x 等任何逃逸写法）。
        if normalized.split(['/', '\\']).any(|c| c == "..") {
            warnings.push(format!("keep 路径不能包含 ..，已跳过: {line}"));
            continue;
        }
        entries.push(KeepEntry { rel: normalized });
    }
    (entries, warnings)
}

/// 是否带 Windows 盘符前缀（`C:` / `C:foo`）。
///
/// `PathBuf::join` 遇到带 prefix 的路径会**整体替换** base——`C:foo` 不是
/// 相对路径，而是「C 盘当前目录下的 foo」，join 结果完全逃出 base/stage。
/// 2 字符的 `C:` 同理（解析为 C 盘本身）。macOS/Linux 不存在此形态，照常放行。
fn has_drive_prefix(line: &str) -> bool {
    let bytes = line.as_bytes();
    bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && std::path::MAIN_SEPARATOR == '\\'
}

/// 归档当前账号之前：把 keep 列表里存在的路径收进暂存目录。
///
/// `base` 为当前 Claude 数据目录。keep 列表与暂存目录取默认位置。
pub fn stage_keep(base: &Path) -> Result<KeepReport, String> {
    stage_keep_with(base, &keep_list_path(), &keep_stage_dir())
}

/// 还原目标账号之后：把暂存内容合并回 `base`，成功后清空暂存目录。
pub fn merge_keep(base: &Path) -> Result<KeepReport, String> {
    merge_keep_with(base, &keep_stage_dir())
}

/// `stage_keep` 的可测试内核：显式传入列表路径与暂存目录（测试用 tempdir）。
fn stage_keep_with(base: &Path, list_path: &Path, stage_dir: &Path) -> Result<KeepReport, String> {
    let text = match fs::read_to_string(list_path) {
        Ok(t) => t,
        Err(_) => {
            return Ok(KeepReport::disabled(
                "keep-in-workspace.txt 不存在，跨身份保留未启用",
            ));
        }
    };
    let (entries, parse_warnings) = parse_keep_list(&text);
    if entries.is_empty() {
        return Ok(KeepReport {
            status: "empty",
            count: 0,
            skipped: 0,
            warnings: parse_warnings,
            message: "keep 列表为空，无需暂存".to_string(),
        });
    }

    // 暂存目录若有内容残留（上次还原失败），它可能是唯一完整副本——绝不覆盖。
    if dir_has_entries(stage_dir) {
        return Err(format!(
            "跨身份保留暂存目录已存在（可能是上次还原失败的残留），请检查后手动清空: {}",
            stage_dir.display()
        ));
    }
    retry_io(|| fs::create_dir_all(stage_dir)).map_err(|e| format!("创建暂存目录失败: {e}"))?;

    let mut warnings = parse_warnings;
    let mut staged = 0usize;
    let mut skipped = 0usize;
    let mut failure: Option<String> = None;

    for entry in &entries {
        let src = base.join(&entry.rel);
        // 该账号没有此路径 → 静默跳过（对齐上游 `[ -e "$src" ] || continue`）。
        if !src.exists() {
            continue;
        }
        // 逐级符号链接校验：任何中间分量或最终目标是链接/junction → 跳过。
        if !path_within_safe(base, &entry.rel) {
            warnings.push(format!("keep 路径含符号链接，已跳过: {}", entry.rel));
            skipped += 1;
            continue;
        }
        let dst = stage_dir.join(&entry.rel);
        if let Err(e) = copy_tree(&src, &dst) {
            // 中途失败：清掉本次半成品暂存（对齐上游 `rm -rf "$stage"`），整体报错。
            let _ = retry_io(|| fs::remove_dir_all(stage_dir));
            failure = Some(format!("暂存 {} 失败: {e}", entry.rel));
            break;
        }
        staged += 1;
    }

    if let Some(err) = failure {
        return Err(err);
    }
    if staged == 0 {
        // 没有任何实际需要收的路径：清掉空暂存目录，与未启用一致。
        let _ = retry_io(|| fs::remove_dir_all(stage_dir));
    }
    Ok(KeepReport {
        status: if staged > 0 { "staged" } else { "empty" },
        count: staged,
        skipped,
        warnings,
        message: format!("已跨身份暂存 {staged} 条路径"),
    })
}

/// `merge_keep` 的可测试内核。
fn merge_keep_with(base: &Path, stage_dir: &Path) -> Result<KeepReport, String> {
    if !stage_dir.exists() {
        return Ok(KeepReport::disabled("无暂存内容，无需合并"));
    }
    let entries = fs::read_dir(stage_dir).map_err(|e| format!("读取暂存目录失败: {e}"))?;
    let mut merged = 0usize;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let dst = base.join(name);
        // 文件覆盖、目录递归合并；遇到暂存里的链接 copy_tree 会自动跳过不跟随。
        if let Err(e) = copy_tree(&entry.path(), &dst) {
            // 失败保留暂存目录供排查（对齐上游行为）。
            return Err(format!(
                "跨身份保留合并失败（{}），暂存保留在 {}",
                e,
                stage_dir.display()
            ));
        }
        merged += 1;
    }
    retry_io(|| fs::remove_dir_all(stage_dir)).map_err(|e| format!("清理暂存目录失败: {e}"))?;
    Ok(KeepReport {
        status: "merged",
        count: merged,
        skipped: 0,
        warnings: Vec::new(),
        message: format!("已合并 {merged} 条跨身份保留路径"),
    })
}

/// 逐分量检查 `base/<rel>` 的每个中间分量（含最终目标）都不是符号链接/junction。
/// 对齐上游 `keep_path_safe`：避免把指向 DATA 外的链接收进暂存。
fn path_within_safe(base: &Path, rel: &str) -> bool {
    let mut current = base.to_path_buf();
    for part in rel
        .split(['/', '\\'])
        .filter(|p| !p.is_empty() && *p != ".")
    {
        current = current.join(part);
        if imp::is_link(&current) {
            return false;
        }
    }
    true
}

/// 递归复制 `src` → `dst`（文件覆盖、目录合并）。复制过程中遇到符号链接直接跳过，
/// **不跟随**（防止把数据目录外的内容拉进暂存/合并）。所有文件操作经锁重试。
fn copy_tree(src: &Path, dst: &Path) -> io::Result<()> {
    if imp::is_link(src) {
        return Ok(());
    }
    let meta = retry_io(|| fs::metadata(src))?;
    if meta.is_dir() {
        retry_io(|| fs::create_dir_all(dst))?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            copy_tree(&entry.path(), &dst.join(entry.file_name()))?;
        }
        Ok(())
    } else {
        if let Some(parent) = dst.parent() {
            retry_io(|| fs::create_dir_all(parent))?;
        }
        // fs::copy 覆盖已存在文件；包一层锁重试（杀软/索引器短暂持句柄）。
        retry_io(|| fs::copy(src, dst))?;
        Ok(())
    }
}

/// 目录是否存在且非空。
fn dir_has_entries(dir: &Path) -> bool {
    fs::read_dir(dir)
        .map(|rd| rd.filter(|e| e.is_ok()).count())
        .unwrap_or(0)
        > 0
}

/// 是否为绝对路径：Unix 根 `/`、UNC `\\server`、Windows 盘符 `X:\` / `X:/`。
/// 与宿主平台无关地同时识别两种风格（列表可能在 Windows 上手写了 `/x`）。
fn is_absolute_path(line: &str) -> bool {
    if line.starts_with('/') || line.starts_with("\\\\") {
        return true;
    }
    let chars: Vec<char> = line.chars().collect();
    chars.len() >= 3
        && chars[0].is_ascii_alphabetic()
        && chars[1] == ':'
        && (chars[2] == '\\' || chars[2] == '/')
}

/// 归一化相对路径：反斜杠转正斜杠、剥离前置 `./`、去尾分隔符。
fn normalize_rel(line: &str) -> String {
    let mut s = line.replace('\\', "/");
    while s.starts_with("./") {
        s = s[2..].to_string();
    }
    if s == "." {
        s.clear();
    }
    while s.ends_with('/') {
        s.pop();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keep_list_filters_comments_and_rejects_unsafe() {
        let text = "\
# 注释行

   # 缩进注释
settings.json
skills/
./themes/dark.json
a/b.json
/tmp/abs-unix.txt
C:\\Users\\abs.txt
C:relative-to-drive.txt
C:
relative/../escape.json
normalizer/
./
";
        let (entries, warnings) = parse_keep_list(text);
        // 有效条目：settings.json / skills / themes/dark.json / a/b.json / normalizer。
        assert_eq!(entries.len(), 5, "entries={entries:?}");
        assert!(entries.contains(&KeepEntry {
            rel: "settings.json".into()
        }));
        assert!(entries.contains(&KeepEntry {
            rel: "skills".into()
        }));
        assert!(entries.contains(&KeepEntry {
            rel: "themes/dark.json".into()
        }));
        assert!(entries.contains(&KeepEntry {
            rel: "a/b.json".into()
        }));
        assert!(entries.contains(&KeepEntry {
            rel: "normalizer".into()
        }));
        // WARN：Unix 绝对 / Windows 绝对 / 盘符相对（C:relative、C:）/
        // .. / 空（./）共 6 条。
        assert_eq!(warnings.len(), 6, "warnings={warnings:?}");
        assert!(warnings.iter().any(|w| w.contains("相对路径")));
        assert!(warnings
            .iter()
            .any(|w| w.contains("C:relative-to-drive.txt")));
        assert!(warnings.iter().any(|w| w.contains("C:")));
        assert!(warnings.iter().any(|w| w.contains("..")));
    }

    #[test]
    fn stage_then_merge_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("data");
        fs::create_dir_all(base.join("sub")).unwrap();
        // 通用配置（账号无关，需要跨身份保留）。
        fs::write(base.join("settings.json"), "{\"theme\":\"dark\"}").unwrap();
        fs::write(base.join("sub/general.txt"), "shared").unwrap();
        let list = tmp.path().join("keep.txt");
        fs::write(&list, "settings.json\nsub/general.txt\n").unwrap();
        let stage = tmp.path().join("stage");

        let report = stage_keep_with(&base, &list, &stage).unwrap();
        assert_eq!(report.status, "staged");
        assert_eq!(report.count, 2);
        assert!(stage.join("settings.json").exists());
        assert!(stage.join("sub/general.txt").exists());

        // 模拟切换：清空 base，放入「目标账号」专属文件。
        fs::remove_dir_all(&base).unwrap();
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("account-token.json"), "SECRET-B").unwrap();

        // 合并回来。
        let report = merge_keep_with(&base, &stage).unwrap();
        assert_eq!(report.status, "merged");
        assert_eq!(report.count, 2);
        // 通用文件回来且内容一致。
        assert_eq!(
            fs::read_to_string(base.join("settings.json")).unwrap(),
            "{\"theme\":\"dark\"}"
        );
        assert_eq!(
            fs::read_to_string(base.join("sub/general.txt")).unwrap(),
            "shared"
        );
        // 账号专属文件未被破坏。
        assert_eq!(
            fs::read_to_string(base.join("account-token.json")).unwrap(),
            "SECRET-B"
        );
        // 暂存目录已清空。
        assert!(!stage.exists());
    }

    #[test]
    fn stage_skips_link_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("data");
        fs::create_dir_all(base.join("real")).unwrap();
        fs::write(base.join("real/x.txt"), "inside").unwrap();
        let list = tmp.path().join("keep.txt");
        fs::write(&list, "real-link\n").unwrap();
        let stage = tmp.path().join("stage");

        #[cfg(windows)]
        {
            // junction：base/real-link -> base/real；权限不足则跳过断言。
            if crate::platform::imp::create_junction(&base.join("real-link"), &base.join("real"))
                .is_err()
            {
                return;
            }
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(base.join("real"), base.join("real-link")).unwrap();
        }

        let report = stage_keep_with(&base, &list, &stage).unwrap();
        assert_eq!(report.count, 0);
        assert_eq!(report.skipped, 1);
        assert!(
            report.warnings.iter().any(|w| w.contains("符号链接")),
            "warnings={:?}",
            report.warnings
        );
        // 零收时暂存目录应被清掉。
        assert!(!dir_has_entries(&stage));
    }

    #[test]
    fn noop_when_list_missing_empty_or_no_stage() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("data");
        fs::create_dir_all(&base).unwrap();
        let stage = tmp.path().join("stage");

        // 列表缺失 → disabled。
        let r = stage_keep_with(&base, &tmp.path().join("nope.txt"), &stage).unwrap();
        assert_eq!(r.status, "disabled");

        // 列表只有注释/空行 → empty。
        let empty = tmp.path().join("empty.txt");
        fs::write(&empty, "   \n# only comments\n").unwrap();
        let r = stage_keep_with(&base, &empty, &stage).unwrap();
        assert_eq!(r.status, "empty");
        assert!(!stage.exists());

        // 列表非空但 base 里没有对应文件 → empty，不误报错。
        let list = tmp.path().join("keep.txt");
        fs::write(&list, "settings.json\n").unwrap();
        let r = stage_keep_with(&base, &list, &stage).unwrap();
        assert_eq!(r.status, "empty");
        assert_eq!(r.count, 0);

        // 无暂存目录时 merge → disabled。
        let r = merge_keep_with(&base, &stage).unwrap();
        assert_eq!(r.status, "disabled");
    }

    #[test]
    fn stage_refuses_to_clobber_leftover_stage() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("data");
        fs::create_dir_all(base.join("x")).unwrap();
        fs::write(base.join("x/a.json"), "orig").unwrap();
        let stage = tmp.path().join("stage");
        fs::create_dir_all(&stage).unwrap();
        // 上次还原失败的残留：唯一完整副本。
        fs::write(stage.join("leftover.txt"), "ONLY-COPY").unwrap();
        let list = tmp.path().join("keep.txt");
        fs::write(&list, "x/a.json\n").unwrap();

        let err = stage_keep_with(&base, &list, &stage).unwrap_err();
        assert!(err.contains("已存在"), "err={err}");
        // 残留未被破坏。
        assert_eq!(
            fs::read_to_string(stage.join("leftover.txt")).unwrap(),
            "ONLY-COPY"
        );
    }
}
