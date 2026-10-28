//! MCP 服务器管理（P2-3）。
//!
//! 管理全局 `~/.claude.json` 的 `mcpServers` 与项目级 `.mcp.json`：
//! - stdio 服务器以 `npx/npm/pnpm/yarn` 启动时，Windows 上这些是 `.cmd` shim，
//!   直接 spawn 会失败，自动 [`normalize_mcp_stdio`] 包装为 `cmd /c <command> <args>`；
//! - 校验 stdio / http / sse 字段；
//! - 密钥类 `env` 只做落盘与回显，**绝不写进日志**（本模块不记录任何 env 值）。

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{json, Value};

use crate::jsonio;

/// 需要 `cmd /c` 包装的 stdio 启动器（Windows 上是 .cmd shim）。
const STDIO_WRAPPER_COMMANDS: [&str; 4] = ["npx", "npm", "pnpm", "yarn"];

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

/// 纯函数：把 npx/npm/pnpm/yarn 启动的 stdio 服务器自动包装为 `cmd /c`。
/// 幂等（已包装不重复包装）；非 stdio / 非包装命令不处理。
pub fn normalize_mcp_stdio(server: &mut Value) {
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
    let base = command_base_name(command);
    if !STDIO_WRAPPER_COMMANDS.contains(&base.as_str()) {
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

/// MCP 配置作用域。
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum McpScope {
    /// 全局 `~/.claude.json`。
    Global,
    /// 项目级 `<project>/.mcp.json`。
    Project,
}

fn project_mcp_path(project_dir: Option<&str>) -> Result<PathBuf, String> {
    let dir = match project_dir {
        Some(p) => PathBuf::from(p),
        None => std::env::current_dir().map_err(|e| format!("无法定位当前目录: {e}"))?,
    };
    Ok(dir.join(".mcp.json"))
}

fn mcp_path(scope: McpScope, project_dir: Option<&str>) -> Result<PathBuf, String> {
    match scope {
        McpScope::Global => crate::paths::claude_json_path(),
        McpScope::Project => project_mcp_path(project_dir),
    }
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

/// 新增 / 更新一个 MCP 服务器（校验 + stdio 自动包装 + 原子写）。
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

    let path = mcp_path(scope, project_dir)?;
    let mut parsed = jsonio::read_json_optional(path.clone())?.unwrap_or_else(|| json!({}));
    if !parsed.is_object() {
        return Err("目标文件根节点不是 JSON 对象".to_string());
    }

    match parsed.get_mut("mcpServers").and_then(Value::as_object_mut) {
        Some(map) => {
            map.insert(name.to_string(), server);
        }
        None => {
            parsed["mcpServers"] = json!({ name: server });
        }
    }
    jsonio::write_json_pretty(path, &parsed)
}

/// 删除一个 MCP 服务器；返回是否真的删除了。
pub fn delete_mcp_server(
    scope: McpScope,
    project_dir: Option<&str>,
    name: &str,
) -> Result<bool, String> {
    let path = mcp_path(scope, project_dir)?;
    let Some(mut parsed) = jsonio::read_json_optional(path.clone())? else {
        return Ok(false);
    };
    let removed = parsed
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .map(|map| map.remove(name).is_some())
        .unwrap_or(false);
    if removed {
        jsonio::write_json_pretty(path, &parsed)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_npx_family_commands() {
        for cmd in ["npx", "npm", "pnpm", "yarn"] {
            let mut server = json!({
                "type": "stdio",
                "command": cmd,
                "args": ["-y", "some-server"]
            });
            normalize_mcp_stdio(&mut server);
            assert_eq!(server["command"], "cmd", "command {cmd}");
            assert_eq!(
                server["args"],
                json!(["/c", cmd, "-y", "some-server"]),
                "command {cmd}"
            );
        }
    }

    #[test]
    fn wraps_full_path_npx_cmd() {
        let mut server = json!({
            "command": "C:\\Program Files\\nodejs\\npx.cmd",
            "args": ["-y", "server"]
        });
        normalize_mcp_stdio(&mut server);
        assert_eq!(server["command"], "cmd");
        assert_eq!(
            server["args"][0],
            json!("/c"),
            "full path should be wrapped"
        );
    }

    #[test]
    fn does_not_wrap_non_wrapper_or_remote() {
        let mut node = json!({ "type": "stdio", "command": "node", "args": ["s.js"] });
        normalize_mcp_stdio(&mut node);
        assert_eq!(node["command"], "node");

        let mut http = json!({ "type": "http", "url": "https://x/sse" });
        normalize_mcp_stdio(&mut http);
        assert_eq!(http["url"], "https://x/sse");
    }

    #[test]
    fn wrapping_is_idempotent() {
        let mut server = json!({
            "type": "stdio",
            "command": "cmd",
            "args": ["/c", "npx", "-y", "server"]
        });
        normalize_mcp_stdio(&mut server);
        assert_eq!(server["args"], json!(["/c", "npx", "-y", "server"]));
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
    fn project_scope_crud_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().to_string_lossy().to_string();

        // Initially empty.
        let list = list_mcp_servers(McpScope::Project, Some(&project)).unwrap();
        assert_eq!(list, json!({}));

        // Add a stdio server (auto-wrapped).
        let server = json!({ "type": "stdio", "command": "npx", "args": ["-y", "srv"], "env": { "TOKEN": "secret" } });
        upsert_mcp_server(McpScope::Project, Some(&project), "mysrv", server).unwrap();
        let list = list_mcp_servers(McpScope::Project, Some(&project)).unwrap();
        assert_eq!(list["mysrv"]["command"], "cmd");
        // Secret env preserved on disk (but not logged).
        assert_eq!(list["mysrv"]["env"]["TOKEN"], "secret");

        // Delete.
        assert!(delete_mcp_server(McpScope::Project, Some(&project), "mysrv").unwrap());
        let list = list_mcp_servers(McpScope::Project, Some(&project)).unwrap();
        assert_eq!(list, json!({}));
    }
}
