//! 功能大全：权限规则与钩子（hooks）结构化编辑器。
//!
//! 对 `settings.json` 的 `permissions.allow/deny/ask` 与 `hooks` 做结构校验后
//! 可视化编辑，写入走 [`mcp::modify_json_optimistic`] 乐观并发（Claude Code
//! 运行时也会改这个文件，冲突会重读合并重试），其余键原样保留。
//!
//! Windows 专项校验：钩子命令里的路径分隔符（`/` vs `\`）、是否需要
//! `cmd /c` 包装（.cmd/.bat/npm shim），在读取与保存时给出明确提示。

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::mcp;
use crate::paths;

/// 权限规则三列表（缺失时均为空，兼容没有 `permissions` 块的 settings）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PermissionRules {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub ask: Vec<String>,
}

/// 扁平化后的单条钩子（一个 matcher 组内的一条 command）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookEntry {
    /// 触发事件，如 `PreToolUse` / `PostToolUse` / `Stop`。
    pub event: String,
    /// 工具匹配器，缺失为空串（表示匹配全部）。
    #[serde(default)]
    pub matcher: String,
    /// 要执行的命令行。
    pub command: String,
}

/// 编辑器读取结果：规则、钩子、文件路径与校验告警。
#[derive(Debug, Clone, Serialize)]
pub struct PermissionEditorData {
    pub permissions: PermissionRules,
    pub hooks: Vec<HookEntry>,
    pub settings_path: String,
    pub warnings: Vec<String>,
}

/// 从 settings 值中提取权限规则（缺失/类型不符返回空）。
pub fn extract_permissions(root: &Value) -> PermissionRules {
    let Some(perms) = root.get("permissions") else {
        return PermissionRules::default();
    };
    let pick = |key: &str| -> Vec<String> {
        perms
            .get(key)
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    PermissionRules {
        allow: pick("allow"),
        deny: pick("deny"),
        ask: pick("ask"),
    }
}

/// 从 settings 值中扁平化提取全部钩子。
///
/// 结构：`hooks.<Event>[]`，每个元素是 `{matcher?: string, hooks: [{type, command}]}`。
/// 非预期结构（缺 hooks 数组/命令非字符串）跳过该条，不报错。
pub fn extract_hooks(root: &Value) -> Vec<HookEntry> {
    let Some(hooks_map) = root.get("hooks").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (event, groups) in hooks_map {
        let Some(groups) = groups.as_array() else {
            continue;
        };
        for group in groups {
            let matcher = group
                .get("matcher")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let Some(hooks) = group.get("hooks").and_then(Value::as_array) else {
                continue;
            };
            for hook in hooks {
                let command = hook.get("command").and_then(Value::as_str);
                if let Some(command) = command {
                    out.push(HookEntry {
                        event: event.clone(),
                        matcher: matcher.clone(),
                        command: command.to_string(),
                    });
                }
            }
        }
    }
    out
}

/// 读取编辑器数据并做校验。
pub fn read_permission_editor() -> Result<PermissionEditorData, String> {
    let settings_path = paths::claude_settings_path()?;
    let root = crate::jsonio::read_json_optional(settings_path.clone())?.unwrap_or(json!({}));
    let permissions = extract_permissions(&root);
    let hooks = extract_hooks(&root);
    let mut warnings = validate_permissions(&permissions);
    for hook in &hooks {
        warnings.extend(validate_hook(hook));
    }
    Ok(PermissionEditorData {
        permissions,
        hooks,
        settings_path: settings_path.to_string_lossy().to_string(),
        warnings,
    })
}

/// 校验权限规则：空条目、组内重复、跨 allow/deny/ask 冲突。
pub fn validate_permissions(rules: &PermissionRules) -> Vec<String> {
    let mut warnings = Vec::new();
    let groups = [
        ("allow", &rules.allow),
        ("deny", &rules.deny),
        ("ask", &rules.ask),
    ];
    for (label, list) in groups {
        let mut seen = std::collections::HashSet::new();
        for rule in list {
            if rule.trim().is_empty() {
                warnings.push(format!("{label} 列表中存在空规则，请删除"));
            } else if !seen.insert(rule.trim().to_string()) {
                warnings.push(format!("{label} 列表中规则「{}」重复", rule.trim()));
            }
        }
    }
    // 跨列表冲突：同一规则出现在多个列表里，实际行为会互相覆盖。
    let mut owner: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
    for (label, list) in groups {
        for rule in list {
            let key = rule.trim();
            if key.is_empty() {
                continue;
            }
            if let Some(prev) = owner.get(key) {
                warnings.push(format!(
                    "规则「{key}」同时出现在 {prev} 与 {label}，只会有一个生效，请移除其一"
                ));
            } else {
                owner.insert(key, label.to_string());
            }
        }
    }
    warnings
}

/// 校验单条钩子命令（Windows 专项）。
pub fn validate_hook(entry: &HookEntry) -> Vec<String> {
    let mut warnings = Vec::new();
    let command = entry.command.trim();
    if command.is_empty() {
        warnings.push(format!("{} 事件存在空钩子命令，请删除", entry.event));
        return warnings;
    }
    // 取第一个空白分隔的 token 作为可执行程序路径。
    let first = command.split_whitespace().next().unwrap_or("");
    let lower = first.to_ascii_lowercase();
    let looks_like_path = first.contains('/') || first.contains('\\');
    // 路径分隔符检查。
    if looks_like_path && first.contains('/') && !lower.starts_with("http") {
        warnings.push(format!(
            "钩子命令「{first}」使用了正斜杠路径；Windows 原生程序建议用反斜杠「\\」，请确认可被正确解析"
        ));
    }
    if first.contains('/') && first.contains('\\') {
        warnings.push(format!(
            "钩子命令「{first}」混用了 / 与 \\ 分隔符，建议统一为反斜杠"
        ));
    }
    // .cmd/.bat 或 npm 类 shim 未经 cmd /c 包装时建议包装。
    let needs_cmd_wrap = lower.ends_with(".cmd")
        || lower.ends_with(".bat")
        || matches!(
            lower.as_str(),
            "npm" | "npx" | "pnpm" | "yarn" | "npm.cmd" | "npx.cmd"
        );
    // 取路径末尾的程序名再判断，避免把 npm.cmd 误当成 cmd 包装器。
    let prog_name = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
    let already_wrapped = prog_name == "cmd" || prog_name == "cmd.exe";
    if needs_cmd_wrap && !already_wrapped {
        warnings.push(format!(
            "钩子命令「{first}」是批处理/脚本 shim，建议用 cmd /c 包装以保证能被执行"
        ));
    }
    warnings
}

/// 由扁平钩子列表重建 `hooks` 值（按 event/matcher 分组合并）。
pub fn build_hooks_value(entries: &[HookEntry]) -> Value {
    let mut map = serde_json::Map::new();
    for entry in entries {
        let event_arr = map
            .entry(entry.event.clone())
            .or_insert_with(|| Value::Array(Vec::new()));
        let groups = event_arr.as_array_mut().unwrap();
        let existing = groups.iter_mut().find(|g| {
            let m = g.get("matcher").and_then(Value::as_str).unwrap_or("");
            m == entry.matcher
        });
        let hook_obj = json!({"type": "command", "command": entry.command});
        if let Some(group) = existing {
            group
                .get_mut("hooks")
                .and_then(Value::as_array_mut)
                .unwrap()
                .push(hook_obj);
        } else {
            let mut group = serde_json::Map::new();
            if !entry.matcher.is_empty() {
                group.insert("matcher".to_string(), Value::String(entry.matcher.clone()));
            }
            group.insert("hooks".to_string(), Value::Array(vec![hook_obj]));
            groups.push(Value::Object(group));
        }
    }
    Value::Object(map)
}

/// 保存编辑器结果：先校验，再乐观并发写入。
///
/// 校验只产生告警（允许保存），但空命令/空规则会被拒绝，避免写入无效配置。
pub fn save_permission_editor(
    permissions: PermissionRules,
    hooks: Vec<HookEntry>,
) -> Result<(), String> {
    for rule in [&permissions.allow, &permissions.deny, &permissions.ask] {
        if rule.iter().any(|r| r.trim().is_empty()) {
            return Err("存在空白权限规则，请先删除再保存".to_string());
        }
    }
    if hooks.iter().any(|h| h.command.trim().is_empty()) {
        return Err("存在空钩子命令，请先删除再保存".to_string());
    }
    let settings_path = paths::claude_settings_path()?;
    mcp::modify_json_optimistic(&settings_path, |root| {
        let obj = root.as_object_mut().ok_or("settings 不是 JSON 对象")?;
        let all_empty = permissions.allow.is_empty()
            && permissions.deny.is_empty()
            && permissions.ask.is_empty();
        if all_empty {
            obj.remove("permissions");
        } else {
            obj.insert("permissions".to_string(), json!(permissions));
        }
        if hooks.is_empty() {
            obj.remove("hooks");
        } else {
            obj.insert("hooks".to_string(), build_hooks_value(&hooks));
        }
        Ok(true)
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_permissions_defaults_when_missing() {
        let root = json!({"env": {}});
        assert_eq!(extract_permissions(&root), PermissionRules::default());
    }

    #[test]
    fn extract_permissions_reads_three_lists() {
        let root = json!({"permissions": {"allow": ["a"], "deny": ["b"], "ask": ["c"]}});
        let rules = extract_permissions(&root);
        assert_eq!(rules.allow, vec!["a".to_string()]);
        assert_eq!(rules.deny, vec!["b".to_string()]);
        assert_eq!(rules.ask, vec!["c".to_string()]);
    }

    #[test]
    fn extract_hooks_flattens_nested_structure() {
        let root = json!({"hooks": {"Stop": [
            {"hooks": [{"type": "command", "command": "echo hi"}]},
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "ls"}]}
        ]}});
        let hooks = extract_hooks(&root);
        assert_eq!(hooks.len(), 2);
        assert_eq!(hooks[0].event, "Stop");
        assert_eq!(hooks[0].matcher, "");
        assert_eq!(hooks[0].command, "echo hi");
        assert_eq!(hooks[1].matcher, "Bash");
        assert_eq!(hooks[1].command, "ls");
    }

    #[test]
    fn validate_permissions_flags_duplicates_and_conflicts() {
        let rules = PermissionRules {
            allow: vec!["Bash(npm test)".to_string(), "Bash(npm test)".to_string()],
            deny: vec!["Bash(npm test)".to_string()],
            ask: vec!["   ".to_string()],
        };
        let warnings = validate_permissions(&rules);
        assert!(warnings.iter().any(|w| w.contains("重复")));
        assert!(warnings.iter().any(|w| w.contains("同时出现在")));
        assert!(warnings.iter().any(|w| w.contains("空规则")));
    }

    #[test]
    fn validate_hook_flags_forward_slash_and_missing_cmd_wrap() {
        let entry = HookEntry {
            event: "Stop".to_string(),
            matcher: String::new(),
            command: "C:/tools/npm.cmd run task".to_string(),
        };
        let warnings = validate_hook(&entry);
        assert!(warnings.iter().any(|w| w.contains("正斜杠")));
        assert!(warnings.iter().any(|w| w.contains("cmd /c")));
    }

    #[test]
    fn validate_hook_recognizes_cmd_wrapper_and_does_not_suggest_wrap() {
        let entry = HookEntry {
            event: "PreToolUse".to_string(),
            matcher: String::new(),
            command: "C:\\Windows\\System32\\cmd.exe /c npm run task".to_string(),
        };
        let warnings = validate_hook(&entry);
        assert!(!warnings.iter().any(|w| w.contains("cmd /c")));
    }

    #[test]
    fn validate_hook_rejects_empty_command() {
        let entry = HookEntry {
            event: "Stop".to_string(),
            matcher: String::new(),
            command: "   ".to_string(),
        };
        let warnings = validate_hook(&entry);
        assert!(warnings.iter().any(|w| w.contains("空钩子")));
    }

    #[test]
    fn build_hooks_round_trips_back_to_structure() {
        let entries = vec![
            HookEntry {
                event: "Stop".to_string(),
                matcher: String::new(),
                command: "echo a".to_string(),
            },
            HookEntry {
                event: "Stop".to_string(),
                matcher: "Bash".to_string(),
                command: "echo b".to_string(),
            },
            HookEntry {
                event: "Stop".to_string(),
                matcher: "Bash".to_string(),
                command: "echo c".to_string(),
            },
        ];
        let value = build_hooks_value(&entries);
        let reparsed = extract_hooks(&json!({"hooks": value}));
        assert_eq!(reparsed, entries);
    }

    #[test]
    fn save_rejects_blank_rules_and_commands() {
        let bad_rules = PermissionRules {
            allow: vec!["  ".to_string()],
            ..Default::default()
        };
        assert!(save_permission_editor(bad_rules, Vec::new()).is_err());
        let bad_hooks = vec![HookEntry {
            event: "Stop".to_string(),
            matcher: String::new(),
            command: String::new(),
        }];
        assert!(save_permission_editor(PermissionRules::default(), bad_hooks).is_err());
    }
}
