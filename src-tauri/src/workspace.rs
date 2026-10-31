//! 功能大全：Skills / 命令（commands）/ 子代理（agents）/ CLAUDE.md 管理。
//!
//! 扫描 Claude 配置目录下的四类工作区资产，解析 Markdown 顶部的 YAML 前置元数据
//! （`name` / `description`，BOM 安全读取），并通过**重命名**实现启用/停用：
//! - 目录类（Skill）：`skills/<id>` ↔ `skills/<id>.disabled`；
//! - 文件类（命令/子代理/CLAUDE.md）：`<id>.md` ↔ `<id>.md.disabled`。
//!
//! 重命名是原子、可逆的，不改动文件内容；Windows 下目录被占用会经
//! [`fsx::retry_io`] 短退避重试。停用项不会被 Claude Code 加载（`.disabled`
//! 不在其识别范围），因此能可靠地关闭对应能力。
//!
//! 边界：只扫描/重命名配置目录内的资产，不删除任何内容；目标已存在同名项时
//! 拒绝覆盖，避免数据丢失。

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::credentials;
use crate::fsx;
use crate::jsonio;

/// 工作区资产类别（序列化为小写字符串，便于前端区分）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceKind {
    /// 技能（`skills/<id>/SKILL.md`，目录）。
    Skill,
    /// 斜杠命令（`commands/**/*.md`，文件）。
    Command,
    /// 子代理（`agents/**/*.md`，文件）。
    Agent,
    /// 项目记忆 `CLAUDE.md`（单文件）。
    Memory,
}

/// 工作区资产的前端视图（不含正文，仅元数据与状态）。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorkspaceItem {
    pub kind: WorkspaceKind,
    /// 稳定标识：技能=目录名；命令/子代理=相对路径（去 `.md`/`.disabled`，正斜杠）；
    /// 记忆固定为 `CLAUDE`。改名不影响 id。
    pub id: String,
    /// 展示名：优先取 YAML `name`，否则取文件/目录名。
    pub name: String,
    /// YAML `description`，缺失为空串。
    pub description: String,
    /// 是否处于启用状态（停用项路径带 `.disabled`）。
    pub enabled: bool,
    /// 当前生效路径的绝对路径（启用/停用后会变化）。
    pub path: String,
    /// 是否为目录（技能为目录，其余为文件）。
    pub is_directory: bool,
}

/// Markdown YAML 前置元数据中本功能关心的字段。
#[derive(Debug, Default, Deserialize)]
struct FrontMeta {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

/// 解析 Markdown 顶部 YAML 前置块（BOM 安全）。
///
/// 规则：正文以可选 BOM 开头，随后必须是独占一行的 `---`；再读到下一个独占一行
/// 的 `---` 之间为 YAML。任何一步不满足（无前置块/无闭合线/YAML 非法）都返回
/// 默认值，绝不报错——资产本身仍可展示，只是缺少元数据。
fn parse_frontmatter(text: &str) -> FrontMeta {
    let no_bom = text.strip_prefix('\u{feff}').unwrap_or(text);
    let Some(rest) = no_bom.strip_prefix("---") else {
        return FrontMeta::default();
    };
    // 开界 --- 后必须换行（兼容 CRLF）。
    let rest = if let Some(r) = rest.strip_prefix("\r\n") {
        r
    } else if let Some(r) = rest.strip_prefix('\n') {
        r
    } else {
        return FrontMeta::default();
    };
    // 找独占一行的闭合 ---（允许行尾 \r）。
    let mut closing_line = None;
    for (idx, line) in rest.split('\n').enumerate() {
        if line.trim_end_matches('\r') == "---" {
            closing_line = Some(idx);
            break;
        }
    }
    let Some(closing_idx) = closing_line else {
        return FrontMeta::default();
    };
    let yaml: String = rest
        .split('\n')
        .take(closing_idx)
        .collect::<Vec<&str>>()
        .join("\n");
    serde_yaml::from_str(&yaml).unwrap_or_default()
}

/// 列出全部工作区资产（技能/命令/子代理/记忆），按类别与 id 排序，结果稳定。
pub fn list_workspace_items() -> Result<Vec<WorkspaceItem>, String> {
    let claude_dir = credentials::claude_dir()?;
    Ok(scan_all(&claude_dir))
}

/// 扫描给定配置目录下的全部资产（纯函数，便于测试）。
fn scan_all(claude_dir: &Path) -> Vec<WorkspaceItem> {
    let mut items = Vec::new();
    items.extend(scan_skills(claude_dir));
    items.extend(scan_md_group(
        claude_dir,
        "commands",
        WorkspaceKind::Command,
    ));
    items.extend(scan_md_group(claude_dir, "agents", WorkspaceKind::Agent));
    items.extend(scan_memory(claude_dir));
    items.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.id.cmp(&b.id)));
    items
}

/// 扫描技能目录：每个含 `SKILL.md` 的子目录（含 `.disabled` 停用目录）。
fn scan_skills(claude_dir: &Path) -> Vec<WorkspaceItem> {
    let skills_dir = claude_dir.join("skills");
    let Ok(entries) = fs::read_dir(&skills_dir) else {
        return Vec::new();
    };
    let mut items = Vec::new();
    for entry in entries.filter_map(|e| e.ok()) {
        let dir_path = entry.path();
        if !dir_path.is_dir() {
            continue;
        }
        let raw_name = entry.file_name().to_string_lossy().to_string();
        let (id, enabled) = match raw_name.strip_suffix(".disabled") {
            Some(base) => (base.to_string(), false),
            None => (raw_name.clone(), true),
        };
        let skill_md = dir_path.join("SKILL.md");
        if !skill_md.is_file() {
            continue;
        }
        let text = jsonio::read_text_lossy_bom(&skill_md).unwrap_or_default();
        let meta = parse_frontmatter(&text);
        items.push(WorkspaceItem {
            kind: WorkspaceKind::Skill,
            name: meta.name.unwrap_or_else(|| id.clone()),
            description: meta.description.unwrap_or_default(),
            enabled,
            path: dir_path.to_string_lossy().to_string(),
            is_directory: true,
            id,
        });
    }
    items
}

/// 递归收集 `root` 下的全部文件路径。
fn collect_files_recursive(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            // 符号链接/联接目录不跟随，避免环。
            if crate::platform::imp::is_link(&path) {
                continue;
            }
            collect_files_recursive(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// 归类一个 Markdown 文件：返回 `(id, enabled)`。
///
/// 仅接受 `.md` 或 `.md.disabled` 后缀；其他文件（如 `REQUESTS.md` 之外的
/// 非 md 文件）返回 None。停用文件 `.md.disabled` 的 id 去掉两层后缀。
fn classify_md(rel_path: &str) -> Option<(String, bool)> {
    if let Some(before_disabled) = rel_path.strip_suffix(".disabled") {
        let id = before_disabled.strip_suffix(".md")?;
        Some((id.to_string(), false))
    } else {
        let id = rel_path.strip_suffix(".md")?;
        Some((id.to_string(), true))
    }
}

/// 扫描命令/子代理目录下的全部 `.md`（含嵌套与停用文件）。
fn scan_md_group(claude_dir: &Path, subdir: &str, kind: WorkspaceKind) -> Vec<WorkspaceItem> {
    let group_root = claude_dir.join(subdir);
    let mut files = Vec::new();
    collect_files_recursive(&group_root, &mut files);
    let mut items = Vec::new();
    for file in files {
        let Ok(rel) = file.strip_prefix(&group_root) else {
            continue;
        };
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let Some((id, enabled)) = classify_md(&rel_str) else {
            continue;
        };
        let text = jsonio::read_text_lossy_bom(&file).unwrap_or_default();
        let meta = parse_frontmatter(&text);
        let fallback = Path::new(&id)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| id.clone());
        items.push(WorkspaceItem {
            kind: kind.clone(),
            name: meta.name.unwrap_or(fallback),
            description: meta.description.unwrap_or_default(),
            enabled,
            path: file.to_string_lossy().to_string(),
            is_directory: false,
            id,
        });
    }
    items
}

/// 扫描记忆文件 `CLAUDE.md`（可能停用为 `CLAUDE.md.disabled`）。
fn scan_memory(claude_dir: &Path) -> Vec<WorkspaceItem> {
    let active = claude_dir.join("CLAUDE.md");
    let disabled = claude_dir.join("CLAUDE.md.disabled");
    let mut items = Vec::new();
    if active.is_file() {
        let text = jsonio::read_text_lossy_bom(&active).unwrap_or_default();
        let meta = parse_frontmatter(&text);
        items.push(WorkspaceItem {
            kind: WorkspaceKind::Memory,
            name: meta.name.unwrap_or_else(|| "CLAUDE".to_string()),
            description: meta.description.unwrap_or_default(),
            enabled: true,
            path: active.to_string_lossy().to_string(),
            is_directory: false,
            id: "CLAUDE".to_string(),
        });
    }
    if disabled.is_file() {
        let text = jsonio::read_text_lossy_bom(&disabled).unwrap_or_default();
        let meta = parse_frontmatter(&text);
        items.push(WorkspaceItem {
            kind: WorkspaceKind::Memory,
            name: meta.name.unwrap_or_else(|| "CLAUDE".to_string()),
            description: meta.description.unwrap_or_default(),
            enabled: false,
            path: disabled.to_string_lossy().to_string(),
            is_directory: false,
            id: "CLAUDE".to_string(),
        });
    }
    items
}

/// 计算某资产的「启用路径」与「停用路径」。
fn paths_for(kind: &WorkspaceKind, id: &str, claude_dir: &Path) -> (PathBuf, PathBuf) {
    match kind {
        WorkspaceKind::Skill => {
            let active = claude_dir.join("skills").join(id);
            let disabled = PathBuf::from(format!("{}.disabled", active.display()));
            (active, disabled)
        }
        WorkspaceKind::Command => {
            let active = claude_dir.join("commands").join(format!("{id}.md"));
            let disabled = claude_dir
                .join("commands")
                .join(format!("{id}.md.disabled"));
            (active, disabled)
        }
        WorkspaceKind::Agent => {
            let active = claude_dir.join("agents").join(format!("{id}.md"));
            let disabled = claude_dir.join("agents").join(format!("{id}.md.disabled"));
            (active, disabled)
        }
        WorkspaceKind::Memory => {
            let active = claude_dir.join("CLAUDE.md");
            let disabled = claude_dir.join("CLAUDE.md.disabled");
            (active, disabled)
        }
    }
}

/// 启用/停用指定资产，返回更新后的视图。
///
/// 幂等：已是目标状态时返回明确错误；源缺失或目标已被占用（同名项存在）时
/// 拒绝执行，绝不覆盖。重命名走 [`fsx::retry_io`]，失败不删除源。
pub fn set_workspace_enabled(
    kind: WorkspaceKind,
    id: &str,
    enable: bool,
) -> Result<WorkspaceItem, String> {
    let claude_dir = credentials::claude_dir()?;
    let (active, disabled) = paths_for(&kind, id, &claude_dir);
    let (from, to) = if enable {
        (&disabled, &active)
    } else {
        (&active, &disabled)
    };
    if !from.exists() {
        return Err(format!(
            "找不到「{id}」的{}项，可能已被移动或删除",
            if enable { "停用" } else { "启用" }
        ));
    }
    if to.exists() {
        return Err("目标位置已存在同名项，为避免覆盖已停止；请先处理冲突".to_string());
    }
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建目录失败: {e}"))?;
    }
    fsx::retry_io(|| fs::rename(from, to)).map_err(|e| fsx::humanize_io_error(&e))?;
    scan_all(&claude_dir)
        .into_iter()
        .find(|item| item.kind == kind && item.id == id)
        .ok_or_else(|| "重命名后未能重新读取该资产".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    const SKILL_BODY: &str = "---\nname: tdd\ndescription: Test driven dev\n---\n# body\n";

    #[test]
    fn parse_frontmatter_reads_name_and_description() {
        let meta = parse_frontmatter(SKILL_BODY);
        assert_eq!(meta.name.as_deref(), Some("tdd"));
        assert_eq!(meta.description.as_deref(), Some("Test driven dev"));
    }

    #[test]
    fn parse_frontmatter_handles_bom_and_crlf() {
        let body = "\u{feff}---\r\nname: bom\r\ndescription: d\r\n---\r\nhello";
        let meta = parse_frontmatter(body);
        assert_eq!(meta.name.as_deref(), Some("bom"));
        assert_eq!(meta.description.as_deref(), Some("d"));
    }

    #[test]
    fn parse_frontmatter_returns_default_without_block() {
        let meta = parse_frontmatter("# just markdown\nno frontmatter");
        assert!(meta.name.is_none());
        assert!(meta.description.is_none());
    }

    #[test]
    fn parse_frontmatter_returns_default_on_unclosed_block() {
        let meta = parse_frontmatter("---\nname: x\nno closing line");
        assert!(meta.name.is_none());
    }

    #[test]
    fn parse_frontmatter_returns_default_on_bad_yaml() {
        let meta = parse_frontmatter("---\nname: [unclosed\n---\nbody");
        assert!(meta.name.is_none());
    }

    #[test]
    fn scans_enabled_skill_command_and_memory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(&root.join("skills/tdd/SKILL.md"), SKILL_BODY);
        write(
            &root.join("commands/api-designer.md"),
            "---\nname: api-designer\ndescription: design api\n---\nbody",
        );
        write(&root.join("CLAUDE.md"), "# project memory\n");
        let items = scan_all(root);
        let skill = items
            .iter()
            .find(|i| i.kind == WorkspaceKind::Skill && i.id == "tdd")
            .unwrap();
        assert!(skill.enabled);
        assert!(skill.is_directory);
        assert_eq!(skill.name, "tdd");
        let command = items
            .iter()
            .find(|i| i.kind == WorkspaceKind::Command && i.id == "api-designer")
            .unwrap();
        assert!(command.enabled);
        assert!(!command.is_directory);
        assert_eq!(command.description, "design api");
        let memory = items
            .iter()
            .find(|i| i.kind == WorkspaceKind::Memory)
            .unwrap();
        assert!(memory.enabled);
        assert_eq!(memory.id, "CLAUDE");
    }

    #[test]
    fn scans_disabled_skill_and_command() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(&root.join("skills/tdd.disabled/SKILL.md"), SKILL_BODY);
        write(
            &root.join("commands/x.md.disabled"),
            "---\nname: x\n---\nbody",
        );
        let items = scan_all(root);
        let skill = items
            .iter()
            .find(|i| i.kind == WorkspaceKind::Skill && i.id == "tdd")
            .unwrap();
        assert!(!skill.enabled);
        let command = items
            .iter()
            .find(|i| i.kind == WorkspaceKind::Command && i.id == "x")
            .unwrap();
        assert!(!command.enabled);
    }

    #[test]
    fn scans_nested_command_and_preserves_id() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(&root.join("commands/nested/deep.md"), "# body\n");
        let items = scan_all(root);
        let command = items
            .iter()
            .find(|i| i.kind == WorkspaceKind::Command)
            .unwrap();
        assert_eq!(command.id, "nested/deep");
        assert_eq!(command.name, "deep");
    }

    #[test]
    fn ignores_skill_dir_without_skill_md() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(&root.join("skills/empty/not-skill.txt"), "x");
        let items = scan_all(root);
        assert!(!items.iter().any(|i| i.kind == WorkspaceKind::Skill));
    }

    #[test]
    fn classify_md_distinguishes_enabled_and_disabled() {
        assert_eq!(classify_md("foo.md"), Some(("foo".to_string(), true)));
        assert_eq!(
            classify_md("a/b.md.disabled"),
            Some(("a/b".to_string(), false))
        );
        assert_eq!(classify_md("not-md.txt"), None);
    }

    #[test]
    fn set_enabled_toggles_file_and_is_reversible() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let active = root.join("commands/x.md");
        write(&active, "---\nname: x\n---\nbody");
        // 直接用底层 rename 模拟（paths_for 基于 root）。
        let (act, dis) = paths_for(&WorkspaceKind::Command, "x", root);
        fsx::retry_io(|| fs::rename(&act, &dis)).unwrap();
        assert!(dis.exists());
        assert!(!act.exists());
        fsx::retry_io(|| fs::rename(&dis, &act)).unwrap();
        assert!(act.exists());
    }
}
