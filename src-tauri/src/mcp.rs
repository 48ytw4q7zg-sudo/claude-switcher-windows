//! MCP 服务器管理（P2-3 / H-7）。
//!
//! 管理全局 `~/.claude.json` 的 `mcpServers` 与项目级 `.mcp.json`：
//! - stdio 服务器启动器若是 Windows `.cmd/.bat` shim（直接 spawn 会失败），
//!   自动 [`normalize_mcp_stdio`] 包装为 `cmd /c <command> <args>`；
//!   判定不再写死 npx/npm/pnpm/yarn，而是按当前 PATH/PATHEXT 真实解析
//!   （[`resolves_to_cmd_shim`]）；
//! - 全局 `~/.claude.json` 写入走乐观并发（[`modify_json_optimistic`]），
//!   防止与 Claude Code 自身并发改写互相覆盖；
//! - 校验 stdio / http / sse 字段，并收集安全警告（[`mcp_warnings`]）；
//! - 密钥类 `env` 只做落盘与回显，**绝不写进日志**（本模块不记录任何 env 值）。
//!
//! 关于 `claude mcp add-json` CLI：本沙箱无法确认目标机版本是否支持该子命令，
//! 本轮不依赖它；若日后确认 CLI 支持 `add-json`，可优先走 CLI（由 CLI 负责
//! 并发安全与格式化），文件乐观并发作为兜底/项目作用域路径。

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;
use serde_json::{json, Value};
use sysinfo::{ProcessesToUpdate, System};

use crate::jsonio;

/// 乐观并发写入的最大冲突重试次数。
const MAX_OPT_CONFLICT_RETRIES: u32 = 3;

/// 取命令的可执行基名（去路径、去扩展名、小写）。
fn command_base_name(command: &str) -> String {
    let raw = command.trim().trim_matches('"');
    let file = Path::new(raw)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| raw.to_string());
    let stem = Path::new(&file)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or(file);
    stem.to_lowercase()
}

/// stdio 服务器是否已被 `cmd /c` 包装（幂等判断）。
fn is_cmd_wrapped(server: &Value) -> bool {
    let command = server.get("command").and_then(|c| c.as_str()).unwrap_or("");
    if command_base_name(command) != "cmd" {
        return false;
    }
    server
        .get("args")
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .and_then(|a| a.as_str())
        .map(|a| a.eq_ignore_ascii_case("/c"))
        .unwrap_or(false)
}

/// 扩展名是否为 Windows 批处理 shim（.cmd / .bat，大小写不敏感）。
fn is_cmd_ext(ext: &str) -> bool {
    // Path::extension() 不带点（"cmd"），PATHEXT 带点（".CMD"），两种都要认。
    let lower = ext.to_ascii_lowercase();
    let stripped = lower.strip_prefix('.').unwrap_or(&lower);
    stripped == "cmd" || stripped == "bat"
}

/// 解析 PATHEXT 字符串（`;` 分隔），为空时给 Windows 默认值。
fn parse_pathext(pathext: &str) -> Vec<String> {
    let mut exts: Vec<String> = pathext
        .split(';')
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .collect();
    if exts.is_empty() {
        exts = [".COM", ".EXE", ".BAT", ".CMD"]
            .iter()
            .map(|s| s.to_string())
            .collect();
    }
    exts
}

/// 纯函数：给定 PATH / PATHEXT，判断 command 是否会解析为 `.cmd/.bat` shim。
///
/// - 命令含路径分隔符（相对/绝对路径）：看扩展名，`.cmd/.bat` → true；
///   无扩展名则按 PATHEXT 顺序补全，第一个存在的补全文件决定结果。
/// - 裸名（无分隔符）：对 PATH 每个目录、按 PATHEXT 顺序拼
///   `<dir>/<name><ext>` 检查存在，第一个命中的扩展名决定结果
///   （`.cmd/.bat` → true，`.exe/.com` 等 → false）。
fn resolves_to_cmd_shim_with(command: &str, path_env: &str, pathext: &str) -> bool {
    let raw = command.trim().trim_matches('"');
    if raw.is_empty() {
        return false;
    }
    let pathexts = parse_pathext(pathext);
    let has_sep = raw.contains('/') || raw.contains('\\');

    if has_sep {
        let p = Path::new(raw);
        // 有扩展名：直接按扩展名判定（信任显式路径）。
        if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
            return is_cmd_ext(ext);
        }
        // 无扩展名：按 PATHEXT 补全并检查文件是否存在。
        for ext in &pathexts {
            let candidate = format!("{raw}{ext}");
            if Path::new(&candidate).exists() {
                return is_cmd_ext(ext);
            }
        }
        return false;
    }

    // 裸名：PATH 目录顺序 × PATHEXT 扩展名顺序，第一个命中即决定。
    for dir in path_env.split(';') {
        let dir = dir.trim();
        if dir.is_empty() {
            continue;
        }
        for ext in &pathexts {
            let candidate = Path::new(dir).join(format!("{raw}{ext}"));
            if candidate.exists() {
                return is_cmd_ext(ext);
            }
        }
    }
    false
}

/// 检测 command 在当前进程 PATH/PATHEXT 下是否解析为 `.cmd/.bat` shim。
///
/// Windows 上 npx/npm/pnpm/yarn 等 Node 启动器都是 `.cmd` shim，
/// stdio 直接 spawn 会失败，需要 `cmd /c` 包装。
pub fn resolves_to_cmd_shim(command: &str) -> bool {
    let path_env = std::env::var("PATH").unwrap_or_default();
    let pathext = std::env::var("PATHEXT").unwrap_or_default();
    resolves_to_cmd_shim_with(command, &path_env, &pathext)
}

/// 内部纯逻辑：按给定 shim 判定谓词包装 stdio 启动器（便于单测注入假 PATH）。
fn normalize_mcp_stdio_with(server: &mut Value, is_shim: impl Fn(&str) -> bool) {
    let is_stdio = match server.get("type").and_then(|t| t.as_str()) {
        Some("stdio") => true,
        Some(_) => false,
        // 无 type 但有 command → 默认按 stdio 处理。
        None => server.get("command").is_some(),
    };
    if !is_stdio {
        return;
    }
    let Some(command) = server.get("command").and_then(|c| c.as_str()) else {
        return;
    };
    if is_cmd_wrapped(server) {
        return;
    }
    if !is_shim(command) {
        return;
    }
    let old_args: Vec<Value> = server
        .get("args")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    let mut new_args: Vec<Value> = vec![json!("/c"), json!(command)];
    new_args.extend(old_args);
    server["command"] = json!("cmd");
    server["args"] = json!(new_args);
}

/// 纯函数：把解析为 `.cmd/.bat` shim 的 stdio 服务器自动包装为 `cmd /c`。
/// 幂等（已包装不重复包装）；非 stdio / 非 shim 启动器不处理。
pub fn normalize_mcp_stdio(server: &mut Value) {
    normalize_mcp_stdio_with(server, resolves_to_cmd_shim);
}

/// 纯函数：校验 MCP 服务器配置（stdio / http / sse）。
pub fn validate_mcp_server(server: &Value) -> Result<(), String> {
    let kind = server
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("stdio");
    match kind {
        "stdio" => {
            let command = server.get("command").and_then(|c| c.as_str()).unwrap_or("");
            if command.trim().is_empty() {
                return Err("stdio 服务器必须有非空 command".to_string());
            }
            if let Some(args) = server.get("args") {
                let ok = args.is_array() && args.as_array().unwrap().iter().all(Value::is_string);
                if !ok {
                    return Err("args 必须是字符串数组".to_string());
                }
            }
            if let Some(env) = server.get("env") {
                let ok = env.is_object() && env.as_object().unwrap().values().all(Value::is_string);
                if !ok {
                    return Err("env 必须是字符串到字符串的对象".to_string());
                }
            }
        }
        "http" | "sse" => {
            let url = server.get("url").and_then(|u| u.as_str()).unwrap_or("");
            if url.trim().is_empty() {
                return Err(format!("{kind} 服务器必须有非空 url"));
            }
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(format!(
                    "{kind} 服务器的 url 必须以 http:// 或 https:// 开头"
                ));
            }
        }
        other => {
            return Err(format!(
                "未知 MCP 服务器类型: {other}（仅支持 stdio/http/sse）"
            ))
        }
    }
    Ok(())
}

/// 收集 MCP 服务器配置的安全警告（不阻断写入）。
///
/// **绝不返回 env 内容**——env 可能含密钥；警告文案只引用字段类型与 url 形态。
pub fn mcp_warnings(server: &Value) -> Vec<String> {
    let mut warnings = Vec::new();
    let kind = server
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("stdio");

    if kind == "stdio" {
        if let Some(args) = server.get("args").and_then(|a| a.as_array()) {
            let has_special = args
                .iter()
                .filter_map(|a| a.as_str())
                .any(|arg| arg.chars().any(|c| matches!(c, '%' | '^' | '&' | '|')));
            if has_special {
                warnings.push(
                    "参数含特殊 shell 字符（% ^ & |），经 cmd 包装时可能被转义/解释，请核对"
                        .to_string(),
                );
            }
        }
    } else if kind == "http" || kind == "sse" {
        if let Some(url) = server.get("url").and_then(|u| u.as_str()) {
            if let Some(rest) = url.strip_prefix("http://") {
                // 取 host 部分（去 userinfo、去路径、去端口）。
                let host = rest.split('/').next().unwrap_or("");
                let host = host.rsplit('@').next().unwrap_or(host);
                let host_lower = host.to_lowercase();
                // IPv6 字面量是 [::1]:8080 形式，必须先去括号再去端口。
                let host_only: String = if let Some(inner) = host_lower.strip_prefix('[') {
                    inner.split(']').next().unwrap_or(inner).to_string()
                } else {
                    host_lower
                        .split(':')
                        .next()
                        .unwrap_or(&host_lower)
                        .to_string()
                };
                let is_local = matches!(host_only.as_str(), "localhost" | "127.0.0.1" | "::1");
                if !is_local {
                    warnings.push(
                        "使用非本机 http:// 明文地址，令牌可能明文传输，建议 https".to_string(),
                    );
                }
            }
        }
    }
    warnings
}

/// MCP 配置作用域。
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum McpScope {
    /// 全局 `~/.claude.json`。
    Global,
    /// 项目级 `<project>/.mcp.json`。
    Project,
}

/// 项目作用域的 `.mcp.json` 路径。
///
/// **必须显式提供项目目录**：不回退 `std::env::current_dir()`——GUI 进程的
/// cwd 不可控（可能是安装目录），用 cwd 会把 MCP 配置写到错误位置。
fn project_mcp_path(project_dir: Option<&str>) -> Result<PathBuf, String> {
    let dir = project_dir
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "项目作用域必须显式提供项目目录，无法用当前目录代替".to_string())?;
    Ok(PathBuf::from(dir).join(".mcp.json"))
}

fn mcp_path(scope: McpScope, project_dir: Option<&str>) -> Result<PathBuf, String> {
    match scope {
        McpScope::Global => crate::paths::claude_json_path(),
        McpScope::Project => project_mcp_path(project_dir),
    }
}

/// 文件状态快照：用于乐观并发判定（mtime + size）。
#[derive(Debug, Clone, PartialEq)]
struct FileState {
    mtime: Option<SystemTime>,
    len: u64,
}

fn file_state(path: &Path) -> Option<FileState> {
    let meta = fs::metadata(path).ok()?;
    Some(FileState {
        mtime: meta.modified().ok(),
        len: meta.len(),
    })
}

/// 在目标文件同目录写临时文件（命名与 fsx 的原子写一致，便于残留清理）。
fn write_temp_in_dir(path: &Path, contents: &str) -> Result<PathBuf, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建目录失败: {e}"))?;
    }
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let tmp = path.with_file_name(format!(
        ".{file_name}.tmp-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let mut file = fs::File::create(&tmp).map_err(|e| format!("创建临时文件失败: {e}"))?;
    let write_result = (|| -> std::io::Result<()> {
        file.write_all(contents.as_bytes())?;
        file.sync_all()
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(format!("写入临时文件失败: {e}"));
    }
    Ok(tmp)
}

/// 乐观并发修改 JSON 文件（防 Claude Code 并发改写互相覆盖）。
///
/// 每次尝试：
/// 1. 读文件（缺失按 `{}`）；
/// 2. 快照原文件 `(mtime, len)`；
/// 3. 调 `apply(&mut Value)` 做改动，返回 `Ok(true)` 表示有改动需落盘、
///    `Ok(false)` 表示无需落盘（立即返回，不动磁盘）；
/// 4. 序列化到同目录临时文件；
/// 5. rename 前重新 stat 原文件：`mtime` 与 `len` 都未变 → rename 覆盖；
///    变了 → 丢弃本次结果（删临时文件），重读重新合并，最多重试
///    [`MAX_OPT_CONFLICT_RETRIES`] 次；仍冲突返回 Err（绝不覆盖外部改动）。
///
/// 返回 `Ok(true)` = 成功写入一次；`Ok(false)` = apply 判定无改动、未落盘。
fn modify_json_optimistic(
    path: &Path,
    mut apply: impl FnMut(&mut Value) -> Result<bool, String>,
) -> Result<bool, String> {
    for _attempt in 0..MAX_OPT_CONFLICT_RETRIES {
        let mut parsed =
            jsonio::read_json_optional(path.to_path_buf())?.unwrap_or_else(|| json!({}));
        if !parsed.is_object() {
            return Err("目标文件根节点不是 JSON 对象".to_string());
        }
        // 先快照，再 apply——单测正是利用「apply 内外部改写原文件」触发冲突。
        let before = file_state(path);
        let changed = apply(&mut parsed)?;
        if !changed {
            return Ok(false);
        }
        let raw = serde_json::to_string_pretty(&parsed).map_err(|e| e.to_string())?;
        let tmp = write_temp_in_dir(path, &raw)?;
        let after = file_state(path);
        if before == after {
            crate::fsx::rename_with_retry(&tmp, path)
                .map_err(|e| format!("原子替换 {} 失败: {e}", path.display()))?;
            return Ok(true);
        }
        // 冲突：丢弃本次结果，重读合并。
        let _ = fs::remove_file(&tmp);
    }
    Err(format!(
        "MCP 配置文件 {} 并发冲突超过 {MAX_OPT_CONFLICT_RETRIES} 次，已放弃写入以避免覆盖外部改动",
        path.display()
    ))
}

/// 纯函数：给定进程名集合（小写、已去 `.exe`），是否命中 Claude Code。
fn claude_running_in(names: &HashSet<String>) -> bool {
    names.iter().any(|n| n == "claude")
}

/// 检测 Claude Code 是否正在运行（sysinfo 枚举进程名，小写去 `.exe`）。
///
/// MCP 配置改完后若 Claude Code 会话还活着，需要重启会话才生效——
/// 仅用于记录提示，不阻断写入。
fn claude_running() -> bool {
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let names: HashSet<String> = system
        .processes()
        .values()
        .map(|p| {
            let name = p.name().to_string_lossy().to_string().to_lowercase();
            name.strip_suffix(".exe").unwrap_or(&name).to_string()
        })
        .collect();
    claude_running_in(&names)
}

/// 读取某作用域的 `mcpServers`（文件缺失 / 无字段返回空对象）。
pub fn list_mcp_servers(scope: McpScope, project_dir: Option<&str>) -> Result<Value, String> {
    let path = mcp_path(scope, project_dir)?;
    let parsed = jsonio::read_json_optional(path)?.unwrap_or_else(|| json!({}));
    Ok(parsed
        .get("mcpServers")
        .cloned()
        .unwrap_or_else(|| json!({})))
}

/// 新增 / 更新一个 MCP 服务器（校验 + stdio 自动包装 + 安全警告 + 乐观并发写）。
pub fn upsert_mcp_server(
    scope: McpScope,
    project_dir: Option<&str>,
    name: &str,
    mut server: Value,
) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("服务器名称不能为空".to_string());
    }
    validate_mcp_server(&server)?;
    normalize_mcp_stdio(&mut server);
    // 警告文案不含任何 env 值，可安全进日志。
    for warning in mcp_warnings(&server) {
        crate::log_info(&warning);
    }

    let path = mcp_path(scope, project_dir)?;
    modify_json_optimistic(&path, |parsed| {
        match parsed.get_mut("mcpServers").and_then(Value::as_object_mut) {
            Some(map) => {
                map.insert(name.to_string(), server.clone());
            }
            None => {
                parsed["mcpServers"] = json!({ name: server.clone() });
            }
        }
        Ok(true)
    })?;

    if claude_running() {
        crate::log_info("Claude Code 正在运行，MCP 改动可能需要重启会话才生效");
    }
    Ok(())
}

/// 删除一个 MCP 服务器；返回是否真的删除了。
pub fn delete_mcp_server(
    scope: McpScope,
    project_dir: Option<&str>,
    name: &str,
) -> Result<bool, String> {
    let path = mcp_path(scope, project_dir)?;
    if !path.exists() {
        return Ok(false);
    }
    let mut removed = false;
    modify_json_optimistic(&path, |parsed| {
        removed = parsed
            .get_mut("mcpServers")
            .and_then(Value::as_object_mut)
            .map(|map| map.remove(name).is_some())
            .unwrap_or(false);
        Ok(removed)
    })?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn project_mcp_path_requires_explicit_dir() {
        assert!(project_mcp_path(None).is_err(), "None 必须报错");
        let err = project_mcp_path(None).unwrap_err();
        assert!(
            err.contains("项目作用域必须显式提供项目目录"),
            "错误文案: {err}"
        );
        assert!(project_mcp_path(Some("   ")).is_err(), "空白目录必须报错");
        let p = project_mcp_path(Some("D:\\code\\myproj")).unwrap();
        assert!(p.ends_with(".mcp.json"), "应拼出 .mcp.json: {p:?}");
        assert!(p.starts_with("D:\\code\\myproj"));
    }

    #[test]
    fn wraps_cmd_shim_launcher_via_predicate() {
        let mut server = json!({
            "type": "stdio",
            "command": "some-shim",
            "args": ["-y", "some-server"]
        });
        normalize_mcp_stdio_with(&mut server, |c| c == "some-shim");
        assert_eq!(server["command"], "cmd");
        assert_eq!(
            server["args"],
            json!(["/c", "some-shim", "-y", "some-server"])
        );
    }

    #[test]
    fn does_not_wrap_exe_or_remote() {
        let mut node = json!({ "type": "stdio", "command": "node", "args": ["s.js"] });
        // node 解析为 .exe → 谓词 false → 不包装。
        normalize_mcp_stdio_with(&mut node, |c| c == "npx.cmd");
        assert_eq!(node["command"], "node");
        assert_eq!(node["args"], json!(["s.js"]));

        let mut http = json!({ "type": "http", "url": "https://x/sse" });
        normalize_mcp_stdio_with(&mut http, |_| true);
        assert_eq!(http["url"], "https://x/sse");
    }

    #[test]
    fn wrapping_is_idempotent() {
        let mut server = json!({
            "type": "stdio",
            "command": "cmd",
            "args": ["/c", "npx", "-y", "server"]
        });
        normalize_mcp_stdio_with(&mut server, |_| true);
        assert_eq!(server["args"], json!(["/c", "npx", "-y", "server"]));
    }

    #[test]
    fn cmd_shim_resolution_bare_name_on_path() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        // d1: node.exe（真 exe，不包装）
        File::create(d1.path().join("node.exe")).unwrap();
        // d2: npx.cmd（shim，要包装）——d2 在 PATH 中排在 d1 之后。
        File::create(d2.path().join("npx.cmd")).unwrap();
        let path_env = format!("{};{}", d1.path().display(), d2.path().display());
        let pathext = ".COM;.EXE;.BAT;.CMD";

        assert!(
            !resolves_to_cmd_shim_with("node", &path_env, pathext),
            "node.exe 不应判定为 cmd shim"
        );
        assert!(
            resolves_to_cmd_shim_with("npx", &path_env, pathext),
            "npx.cmd 应判定为 cmd shim"
        );
        assert!(
            !resolves_to_cmd_shim_with("nobody-here", &path_env, pathext),
            "PATH 上不存在的命令不包装"
        );
    }

    #[test]
    fn cmd_shim_resolution_pathext_order_first_hit_wins() {
        let d = tempfile::tempdir().unwrap();
        // 同目录同时存在 tool.exe 与 tool.cmd；PATHEXT 里 .EXE 排在 .CMD 前。
        File::create(d.path().join("tool.exe")).unwrap();
        File::create(d.path().join("tool.cmd")).unwrap();
        let path_env = d.path().display().to_string();
        let pathext = ".EXE;.CMD";
        assert!(
            !resolves_to_cmd_shim_with("tool", &path_env, pathext),
            "第一个命中的是 tool.exe → 不应包装"
        );
    }

    #[test]
    fn cmd_shim_resolution_path_order_first_dir_wins() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        // d1 在前：只有 tool.cmd；d2 在后：有 tool.exe。
        File::create(d1.path().join("tool.cmd")).unwrap();
        File::create(d2.path().join("tool.exe")).unwrap();
        let path_env = format!("{};{}", d1.path().display(), d2.path().display());
        let pathext = ".EXE;.CMD";
        assert!(
            resolves_to_cmd_shim_with("tool", &path_env, pathext),
            "d1 先命中 tool.cmd → 应包装（即使 d2 有 tool.exe）"
        );
    }

    #[test]
    fn cmd_shim_resolution_explicit_extension() {
        // 带路径分隔符：直接看扩展名，不查文件系统。
        assert!(resolves_to_cmd_shim_with("C:\\Tools\\run.cmd", "", ""));
        assert!(resolves_to_cmd_shim_with("./scripts/run.bat", "", ""));
        assert!(!resolves_to_cmd_shim_with("C:\\Tools\\run.exe", "", ""));
        assert!(!resolves_to_cmd_shim_with("C:\\Tools\\run.com", "", ""));
        // 引号包裹也应识别。
        assert!(resolves_to_cmd_shim_with("  \"D:\\x\\y.CMD\"  ", "", ""));
    }

    #[test]
    fn cmd_shim_resolution_no_extension_path_uses_pathext() {
        let d = tempfile::tempdir().unwrap();
        // 无扩展名的相对路径 + 同目录真实存在的 .cmd 补全。
        File::create(d.path().join("launcher.cmd")).unwrap();
        let raw = format!("{}\\launcher", d.path().display());
        assert!(
            resolves_to_cmd_shim_with(&raw, "", ".EXE;.CMD"),
            "无扩展名但 PATHEXT 补全命中 .cmd → true"
        );
    }

    #[test]
    fn validates_stdio_fields() {
        assert!(validate_mcp_server(&json!({ "command": "node" })).is_ok());
        assert!(validate_mcp_server(&json!({ "type": "stdio", "command": "" })).is_err());
        assert!(validate_mcp_server(&json!({ "command": "node", "args": "x" })).is_err());
        assert!(validate_mcp_server(&json!({ "command": "node", "env": { "K": 1 } })).is_err());
    }

    #[test]
    fn validates_remote_fields() {
        assert!(validate_mcp_server(&json!({ "type": "http", "url": "https://x" })).is_ok());
        assert!(validate_mcp_server(&json!({ "type": "sse", "url": "https://x" })).is_ok());
        assert!(validate_mcp_server(&json!({ "type": "http", "url": "" })).is_err());
        assert!(validate_mcp_server(&json!({ "type": "sse", "url": "ftp://x" })).is_err());
        assert!(validate_mcp_server(&json!({ "type": "ws", "url": "wss://x" })).is_err());
    }

    #[test]
    fn warnings_flag_shell_special_chars() {
        let s = json!({"type":"stdio","command":"x","args":["run","a%b"]});
        let ws = mcp_warnings(&s);
        assert!(ws.iter().any(|w| w.contains("特殊 shell 字符")), "{ws:?}");

        let s = json!({"type":"stdio","command":"x","args":["plain","two words"]});
        assert!(mcp_warnings(&s).is_empty());
    }

    #[test]
    fn warnings_flag_remote_http_but_not_localhost_or_https() {
        assert!(
            mcp_warnings(&json!({"type":"http","url":"http://example.com/x"}))
                .iter()
                .any(|w| w.contains("明文"))
        );
        // https 不警告。
        assert!(mcp_warnings(&json!({"type":"http","url":"https://example.com/x"})).is_empty());
        // 本机 http 不警告。
        assert!(mcp_warnings(&json!({"type":"http","url":"http://localhost:8080/x"})).is_empty());
        assert!(mcp_warnings(&json!({"type":"http","url":"http://127.0.0.1/x"})).is_empty());
        assert!(mcp_warnings(&json!({"type":"http","url":"http://[::1]/x"})).is_empty());
        // sse 同样规则。
        assert!(
            mcp_warnings(&json!({"type":"sse","url":"http://1.2.3.4/x"}))
                .iter()
                .any(|w| w.contains("明文"))
        );
    }

    #[test]
    fn claude_running_in_matches_only_claude() {
        let mut set = HashSet::new();
        assert!(!claude_running_in(&set));
        set.insert("node".to_string());
        set.insert("claudia".to_string());
        assert!(!claude_running_in(&set), "claudia 不应误命中");
        set.insert("claude".to_string());
        assert!(claude_running_in(&set));
    }

    #[test]
    fn optimistic_no_conflict_writes_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.json");
        std::fs::write(&path, r#"{"mcpServers":{}}"#).unwrap();
        let calls = AtomicUsize::new(0);
        let written = modify_json_optimistic(&path, |parsed| {
            calls.fetch_add(1, Ordering::SeqCst);
            parsed["mcpServers"]["a"] = json!({"type":"stdio","command":"x"});
            Ok(true)
        })
        .unwrap();
        assert!(written);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "无冲突应一次成功");
        let final_value: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(final_value["mcpServers"]["a"].is_object());
    }

    #[test]
    fn optimistic_no_change_skips_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.json");
        std::fs::write(&path, r#"{"mcpServers":{}}"#).unwrap();
        let written = modify_json_optimistic(&path, |_| Ok(false)).unwrap();
        assert!(!written, "apply 判定无改动应返回 Ok(false)");
    }

    #[test]
    fn optimistic_retries_on_external_change_and_merges() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.json");
        std::fs::write(&path, r#"{"mcpServers":{}}"#).unwrap();

        let calls = AtomicUsize::new(0);
        let path2 = path.clone();
        let written = modify_json_optimistic(&path, |parsed| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // 第一次尝试期间，模拟外部并发改写原文件。
                let mut ext: Value =
                    serde_json::from_str(&std::fs::read_to_string(&path2).unwrap()).unwrap();
                ext["mcpServers"]["external"] = json!({"type":"stdio","command":"ext"});
                std::fs::write(&path2, serde_json::to_string_pretty(&ext).unwrap()).unwrap();
            }
            parsed["mcpServers"]["ours"] = json!({"type":"stdio","command":"ours"});
            Ok(true)
        })
        .unwrap();
        assert!(written);
        assert_eq!(calls.load(Ordering::SeqCst), 2, "应重试一次后成功");

        let final_value: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(
            final_value["mcpServers"]["ours"].is_object(),
            "我们的改动应落盘"
        );
        assert!(
            final_value["mcpServers"]["external"].is_object(),
            "外部改动必须保留（合并，不能被覆盖）"
        );
    }

    #[test]
    fn optimistic_gives_up_after_three_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.json");
        std::fs::write(&path, r#"{"mcpServers":{}}"#).unwrap();

        let counter = AtomicUsize::new(0);
        let path2 = path.clone();
        let result = modify_json_optimistic(&path, |parsed| {
            // 每次尝试都模拟外部改写（size 变化），必然冲突。
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let mut ext: Value =
                serde_json::from_str(&std::fs::read_to_string(&path2).unwrap()).unwrap();
            ext["mcpServers"]["ext"] = json!(n);
            std::fs::write(&path2, serde_json::to_string_pretty(&ext).unwrap()).unwrap();
            parsed["mcpServers"]["ours"] = json!(n);
            Ok(true)
        });
        assert!(result.is_err(), "3 次全冲突应返回 Err");
        assert!(result.unwrap_err().contains("并发冲突"));
        assert_eq!(counter.load(Ordering::SeqCst), 3, "恰好尝试 3 次");
    }

    #[test]
    fn project_scope_crud_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().to_string_lossy().to_string();

        // Initially empty.
        let list = list_mcp_servers(McpScope::Project, Some(&project)).unwrap();
        assert_eq!(list, json!({}));

        // 用 PATH 上不存在的启动器名，保证不被 cmd 包装（测试与本机环境解耦）。
        let server = json!({
            "type": "stdio",
            "command": "zz-obscure-launcher-xyz",
            "args": ["-y", "srv"],
            "env": { "TOKEN": "secret" }
        });
        upsert_mcp_server(McpScope::Project, Some(&project), "mysrv", server).unwrap();
        let list = list_mcp_servers(McpScope::Project, Some(&project)).unwrap();
        assert_eq!(list["mysrv"]["command"], "zz-obscure-launcher-xyz");
        // Secret env preserved on disk (but not logged).
        assert_eq!(list["mysrv"]["env"]["TOKEN"], "secret");

        // Delete.
        assert!(delete_mcp_server(McpScope::Project, Some(&project), "mysrv").unwrap());
        let list = list_mcp_servers(McpScope::Project, Some(&project)).unwrap();
        assert_eq!(list, json!({}));
    }

    #[test]
    fn project_scope_rejects_missing_dir() {
        // 项目作用域 + None → 明确报错，不能偷偷用 cwd。
        assert!(list_mcp_servers(McpScope::Project, None).is_err());
        assert!(upsert_mcp_server(
            McpScope::Project,
            None,
            "x",
            json!({"type":"stdio","command":"y"})
        )
        .is_err());
    }
}
