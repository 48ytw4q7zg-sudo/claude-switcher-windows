//! 功能大全：权限规则与钩子（hooks）结构化编辑器。
//!
//! 对 `settings.json` 的 `permissions.allow/deny/ask` 与 `hooks` 做结构校验后
//! 可视化编辑，写入走 [`mcp::modify_json_optimistic`] 乐观并发（Claude Code
//! 运行时也会改这个文件，冲突会重读合并重试），其余键原样保留。
//!
//! Windows 专项校验：钩子命令里的路径分隔符（`/` vs `\`）、是否需要
//! `cmd /c` 包装（.cmd/.bat/npm shim），在读取与保存时给出明确提示。

use std::collections::BTreeMap;

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
///
/// 只提取 `type == "command"`（或缺 `type`）的钩子：其他类型即便也带 `command`
/// 字段，也不是本编辑器能编辑的本地命令行，混进来会在保存时被改坏。
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
                // type 存在且不是 command → 不是本地命令行，跳过。
                if let Some(kind) = hook.get("type").and_then(Value::as_str) {
                    if kind != "command" {
                        continue;
                    }
                }
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

/// 一个钩子对象是否是编辑器可编辑的本地命令行。
///
/// 条件：`type` 缺省或等于 `"command"`，且能读出字符串 `command`。
/// 不满足的（type 为 prompt/http、或没有 command 字段）编辑器看不到，保存时
/// 必须原位保留，不能覆盖也不能删除。
fn is_editable_hook(hook: &Value) -> bool {
    let is_command_type = hook
        .get("type")
        .and_then(Value::as_str)
        .is_none_or(|kind| kind == "command");
    is_command_type && hook.get("command").and_then(Value::as_str).is_some()
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

/// 纯函数：把编辑器结果合并进 settings 根对象，只改 managed 部分。
///
/// 其余键（`permissions.defaultMode`、`additionalDirectories`、hook 对象上的
/// `timeout` 等本功能不认识的字段，以及无法解析的 hook 分组）**原样保留**。
/// 编辑器看不到这些内容，一旦替换整个 `permissions`/`hooks` 子树就会静默
/// 删掉用户手写的配置。
pub fn apply_editor_to_settings(
    root: &mut Value,
    permissions: &PermissionRules,
    hooks: &[HookEntry],
) -> Result<(), String> {
    let obj = root
        .as_object_mut()
        .ok_or_else(|| "settings 不是 JSON 对象".to_string())?;
    merge_permissions_into(obj, permissions);
    merge_hooks_into(obj, hooks);
    Ok(())
}

/// 合并权限列表：只替换 allow/deny/ask 三个键，全空时删除这三个键。
fn merge_permissions_into(obj: &mut serde_json::Map<String, Value>, rules: &PermissionRules) {
    let all_empty = rules.allow.is_empty() && rules.deny.is_empty() && rules.ask.is_empty();
    if all_empty {
        // 可能整个 permissions 块都只有这三个键，此时连块一起删掉，保持干净。
        let only_managed = obj
            .get("permissions")
            .and_then(Value::as_object)
            .is_none_or(|perms| {
                perms
                    .keys()
                    .all(|key| matches!(key.as_str(), "allow" | "deny" | "ask"))
            });
        if only_managed {
            obj.remove("permissions");
            return;
        }
    }
    let perms = obj
        .entry("permissions")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .map(std::mem::take)
        .unwrap_or_default();
    let mut perms = perms;
    for (key, list) in [
        ("allow", &rules.allow),
        ("deny", &rules.deny),
        ("ask", &rules.ask),
    ] {
        if list.is_empty() {
            perms.remove(key);
        } else {
            perms.insert(key.to_string(), json!(list));
        }
    }
    obj.insert("permissions".to_string(), Value::Object(perms));
}

/// 合并钩子：逐个分组更新 command，保留分组里其他字段与无法识别的钩子。
///
/// 语义：**编辑器列表对它展示过的 (event, matcher) 分组是权威的**——
/// 用户删掉一条就得真的删掉（否则保存后 Claude 仍执行已删除的钩子）。
/// 但分组内**解析不出 command 的钩子**（编辑器根本看不到）必须原样保留，
/// 否则一次保存就静默弄丢用户手写的配置。
fn merge_hooks_into(obj: &mut serde_json::Map<String, Value>, entries: &[HookEntry]) {
    // 期望的 (event, matcher) → [command]，用于就地更新已有的钩子对象。
    let mut wanted: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for entry in entries {
        wanted
            .entry((entry.event.clone(), entry.matcher.clone()))
            .or_default()
            .push(entry.command.clone());
    }
    // 从现有结构出发，只改 command，其他字段（timeout 等）原样保留。
    let mut hooks = obj
        .get("hooks")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    // 逐事件把命令列表写回：已有分组更新 command，缺失分组补建。
    for ((event, matcher), commands) in &wanted {
        let groups = hooks
            .entry(event.clone())
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut();
        let Some(groups) = groups else { continue };
        let target = groups.iter_mut().find(|group| {
            group.get("matcher").and_then(Value::as_str).unwrap_or("") == matcher.as_str()
        });
        if let Some(group) = target {
            if let Some(hook_list) = group.get_mut("hooks").and_then(Value::as_array_mut) {
                // 逐个可见钩子按「可编辑身份」写回，不按索引：
                // 同一分组里可能混着编辑器看不到的项（type 非 command、或读不出
                // command）。按索引对齐会把可见命令写到隐藏项头上，截断也会
                // 连带删掉它们。这里只动可见槽位，隐藏项原位不动。
                let mut visible_index = 0usize;
                for slot in hook_list.iter_mut() {
                    if !is_editable_hook(slot) {
                        continue;
                    }
                    match commands.get(visible_index) {
                        Some(command) => {
                            if let Some(hook_obj) = slot.as_object_mut() {
                                hook_obj
                                    .insert("command".to_string(), Value::String(command.clone()));
                            }
                            visible_index += 1;
                        }
                        // 用户删掉了这条：先标记，稍后统一移除。
                        None => slot["__deleted__"] = json!(true),
                    }
                }
                // 数量不够：补建最小对象（追加在末尾）。
                for command in commands.iter().skip(visible_index) {
                    hook_list.push(json!({"type": "command", "command": command}));
                }
                // 移除被标记的可见钩子，隐藏项不受影响。
                hook_list.retain(|hook| !hook["__deleted__"].as_bool().unwrap_or(false));
            }
        } else {
            let hook_list: Vec<Value> = commands
                .iter()
                .map(|command| json!({"type": "command", "command": command}))
                .collect();
            let mut group = serde_json::Map::new();
            if !matcher.is_empty() {
                group.insert("matcher".to_string(), Value::String(matcher.clone()));
            }
            group.insert("hooks".to_string(), Value::Array(hook_list));
            groups.push(Value::Object(group));
        }
    }
    // 用户在编辑器里删掉了某事件/某 matcher 下的全部钩子：残留分组必须删除，
    // 否则保存后 Claude Code 仍会执行用户以为已删除的钩子。
    // 例外：分组里含「解析不出 command」的钩子时保留——编辑器从未展示过它，
    // 删掉就是静默丢失用户手写的配置。
    for (event, value) in hooks.iter_mut() {
        let Some(groups) = value.as_array_mut() else {
            continue;
        };
        groups.retain(|group| {
            let matcher = group.get("matcher").and_then(Value::as_str).unwrap_or("");
            // 编辑器展示过 → 以编辑器为准（删了就真删）。
            if wanted.contains_key(&(event.clone(), matcher.to_string())) {
                return true;
            }
            // 没展示过：只有含「读不出 command」的钩子时才保留。
            group
                .get("hooks")
                .and_then(Value::as_array)
                .is_some_and(|list| {
                    list.iter()
                        .any(|hook| hook.get("command").and_then(Value::as_str).is_none())
                })
        });
    }
    // 事件下已无分组：删掉空数组，别留空壳。
    let empty_events: Vec<String> = hooks
        .iter()
        .filter(|(_, value)| value.as_array().is_some_and(|a| a.is_empty()))
        .map(|(event, _)| event.clone())
        .collect();
    for event in empty_events {
        hooks.remove(&event);
    }
    // hooks 空了（用户删光了所有可见钩子、也没有隐藏分组）才整块删除。
    if hooks.is_empty() {
        obj.remove("hooks");
        return;
    }
    obj.insert("hooks".to_string(), Value::Object(hooks));
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
        apply_editor_to_settings(root, &permissions, &hooks)?;
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
    fn extract_hooks_skips_non_command_hook_types() {
        // 非 command 类型即便带 command 字段也不是本地命令行，不能被编辑器接管。
        let root = json!({"hooks": {"Stop": [{"hooks": [
            {"type": "command", "command": "keep-me"},
            {"type": "prompt", "command": "ignore-me"},
            {"type": "http", "command": "ignore-me-too"},
            {"command": "no-type-also-ok"}
        ]}]}});
        let hooks = extract_hooks(&root);
        let commands: Vec<&str> = hooks.iter().map(|h| h.command.as_str()).collect();
        assert_eq!(commands, vec!["keep-me", "no-type-also-ok"]);
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
    fn apply_editor_removes_stale_hook_group_user_deleted() {
        let mut root = json!({
            "hooks": {
                "Stop": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "keep"}]},
                    {"matcher": "Edit", "hooks": [{"type": "command", "command": "drop-me"}]}
                ]
            }
        });
        // 用户删掉了 Edit 分组的那条钩子，只保留 Bash。
        let hooks = vec![HookEntry {
            event: "Stop".to_string(),
            matcher: "Bash".to_string(),
            command: "keep".to_string(),
        }];
        apply_editor_to_settings(&mut root, &PermissionRules::default(), &hooks).expect("apply");
        let groups = root["hooks"]["Stop"].as_array().unwrap();
        assert_eq!(groups.len(), 1, "用户删掉的分组必须被移除");
        assert_eq!(groups[0]["matcher"], json!("Bash"));
        assert_eq!(groups[0]["hooks"][0]["command"], json!("keep"));
    }

    #[test]
    fn apply_editor_keeps_hook_events_it_never_showed() {
        let mut root = json!({
            "hooks": {
                "Stop": [{"hooks": [{"type": "command", "command": "a"}]}],
                // 编辑器看不到这条（没有 command 字段），必须原样保留。
                "PreToolUse": [{"matcher": "Bash", "hooks": [{"no_command": true}]}]
            }
        });
        let hooks = vec![HookEntry {
            event: "Stop".to_string(),
            matcher: String::new(),
            command: "a".to_string(),
        }];
        apply_editor_to_settings(&mut root, &PermissionRules::default(), &hooks).expect("apply");
        assert!(
            root["hooks"].get("PreToolUse").is_some(),
            "含解析不出 command 的钩子的分组必须保留，否则一次保存就丢用户配置"
        );
        assert_eq!(
            root["hooks"]["PreToolUse"][0]["hooks"][0],
            json!({"no_command": true})
        );
        assert!(root["hooks"].get("Stop").is_some(), "编辑过的事件不能被动");
    }

    #[test]
    fn apply_editor_removes_hook_the_user_deleted_from_a_shown_event() {
        let mut root = json!({
            "hooks": {
                "Stop": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "keep"}]},
                    {"matcher": "Edit", "hooks": [{"type": "command", "command": "deleted-by-user"}]}
                ]
            }
        });
        // 编辑器展示了两个分组，用户删掉 Edit 那条后保存。
        // 编辑器看得见的分组必须真的被删掉——否则保存后 Claude 仍执行已删除的钩子。
        let hooks = vec![HookEntry {
            event: "Stop".to_string(),
            matcher: "Bash".to_string(),
            command: "keep".to_string(),
        }];
        apply_editor_to_settings(&mut root, &PermissionRules::default(), &hooks).expect("apply");
        let groups = root["hooks"]["Stop"].as_array().unwrap();
        assert_eq!(groups.len(), 1, "用户删除的分组必须移除");
        assert_eq!(groups[0]["matcher"], json!("Bash"));
        assert_eq!(groups[0]["hooks"][0]["command"], json!("keep"));
    }

    #[test]
    fn apply_editor_removes_event_when_all_its_shown_hooks_deleted() {
        let mut root = json!({
            "hooks": {
                "Stop": [{"hooks": [{"type": "command", "command": "only"}]}],
                "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "keep-me"}]}]
            }
        });
        // 编辑器展示了 Stop 与 PreToolUse；用户把 Stop 全删、只留 PreToolUse。
        let hooks = vec![HookEntry {
            event: "PreToolUse".to_string(),
            matcher: "Bash".to_string(),
            command: "keep-me".to_string(),
        }];
        apply_editor_to_settings(&mut root, &PermissionRules::default(), &hooks).expect("apply");
        assert!(
            root["hooks"].get("Stop").is_none(),
            "编辑器展示过、且用户已删空的事件必须移除"
        );
        assert!(root["hooks"].get("PreToolUse").is_some());
    }

    #[test]
    fn apply_editor_keeps_hidden_hooks_when_user_deletes_all_visible_ones() {
        let mut root = json!({
            "hooks": {
                "Stop": [{"hooks": [{"type": "command", "command": "visible"}]}],
                // 编辑器看不到这条（没有 command 字段）。
                "Notification": [{"hooks": [{"no_command": true}]}]
            }
        });
        // 用户删光了所有可见钩子（entries 为空）。
        apply_editor_to_settings(&mut root, &PermissionRules::default(), &[]).expect("apply");
        assert!(
            root["hooks"].get("Stop").is_none(),
            "用户删光的可见分组必须移除"
        );
        assert!(
            root["hooks"].get("Notification").is_some(),
            "删空可见钩子时不能连带删掉编辑器看不到的隐藏分组"
        );
        assert_eq!(
            root["hooks"]["Notification"][0]["hooks"][0],
            json!({"no_command": true})
        );
    }

    #[test]
    fn apply_editor_removes_hooks_block_only_when_nothing_left() {
        let mut root =
            json!({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "a"}]}]}});
        // 没有隐藏分组时，删光可见钩子应整块移除 hooks。
        apply_editor_to_settings(&mut root, &PermissionRules::default(), &[]).expect("apply");
        assert!(
            root.get("hooks").is_none(),
            "既无可见也无隐藏钩子时应删除整个 hooks 块"
        );
    }

    #[test]
    fn apply_editor_keeps_hidden_hook_inside_a_mixed_group() {
        let mut root = json!({
            "hooks": {
                "Stop": [{"hooks": [
                    {"type": "command", "command": "first-visible"},
                    {"type": "prompt", "command": "hidden-not-editable"},
                    {"type": "command", "command": "second-visible"}
                ]}]
            }
        });
        // 用户把两条可见钩子的命令都改掉；中间那条 type=prompt 编辑器看不到。
        let hooks = vec![
            HookEntry {
                event: "Stop".to_string(),
                matcher: String::new(),
                command: "A".to_string(),
            },
            HookEntry {
                event: "Stop".to_string(),
                matcher: String::new(),
                command: "B".to_string(),
            },
        ];
        apply_editor_to_settings(&mut root, &PermissionRules::default(), &hooks).expect("apply");
        let list = root["hooks"]["Stop"][0]["hooks"].as_array().unwrap();
        assert_eq!(list.len(), 3, "隐藏钩子不能被截断删掉");
        assert_eq!(list[0]["command"], json!("A"), "可见钩子按顺序更新");
        assert_eq!(
            list[1],
            json!({"type": "prompt", "command": "hidden-not-editable"}),
            "混在同一分组里的隐藏钩子必须原位保留，不能被可见命令覆盖"
        );
        assert_eq!(list[2]["command"], json!("B"));
    }

    #[test]
    fn apply_editor_deleting_visible_hook_in_mixed_group_keeps_hidden() {
        let mut root = json!({
            "hooks": {
                "Stop": [{"hooks": [
                    {"type": "command", "command": "keep"},
                    {"no_command": true},
                    {"type": "command", "command": "user-deleted"}
                ]}]
            }
        });
        let hooks = vec![HookEntry {
            event: "Stop".to_string(),
            matcher: String::new(),
            command: "keep".to_string(),
        }];
        apply_editor_to_settings(&mut root, &PermissionRules::default(), &hooks).expect("apply");
        let list = root["hooks"]["Stop"][0]["hooks"].as_array().unwrap();
        assert_eq!(list.len(), 2, "只应删掉用户删的那条可见钩子");
        assert_eq!(list[0]["command"], json!("keep"));
        assert_eq!(list[1], json!({"no_command": true}));
    }

    #[test]
    fn saved_hooks_round_trip_back_to_structure() {
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
        // 走真实保存路径：从空 settings 出发，保存后必须能读回同样的分组结构。
        let mut root = json!({});
        apply_editor_to_settings(&mut root, &PermissionRules::default(), &entries)
            .expect("apply into empty settings");
        let reparsed = extract_hooks(&root);
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

    fn rules(allow: &[&str]) -> PermissionRules {
        PermissionRules {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn apply_editor_keeps_unknown_permission_keys() {
        let mut root = json!({
            "permissions": {
                "allow": ["Bash(npm test)"],
                "defaultMode": "acceptEdits",
                "additionalDirectories": ["../shared"]
            },
            "env": {"KEEP": "1"}
        });
        apply_editor_to_settings(&mut root, &rules(&["Bash(cargo test)"]), &[]).expect("apply");
        let perms = &root["permissions"];
        assert_eq!(perms["allow"], json!(["Bash(cargo test)"]));
        // 本功能不认识但用户手写的键必须原样保留，替换整个子树会把它们删掉。
        assert_eq!(perms["defaultMode"], json!("acceptEdits"));
        assert_eq!(perms["additionalDirectories"], json!(["../shared"]));
        assert_eq!(root["env"]["KEEP"], json!("1"));
    }

    #[test]
    fn apply_editor_keeps_unknown_hook_fields() {
        let mut root = json!({
            "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "old", "timeout": 30}]}]}
        });
        let hooks = vec![HookEntry {
            event: "Stop".to_string(),
            matcher: String::new(),
            command: "new".to_string(),
        }];
        apply_editor_to_settings(&mut root, &PermissionRules::default(), &hooks).expect("apply");
        let hook = &root["hooks"]["Stop"][0]["hooks"][0];
        assert_eq!(hook["command"], json!("new"));
        // type / timeout 是编辑器不管理的字段，保存后必须仍在。
        assert_eq!(hook["type"], json!("command"));
        assert_eq!(hook["timeout"], json!(30));
    }

    #[test]
    fn apply_editor_keeps_unparseable_hook_groups() {
        let mut root = json!({
            "hooks": {
                "Stop": [{"matcher": "Bash", "hooks": [{"command": "keep-me"}]}],
                "Notification": [{"hooks": [{"no_command": true}]}]
            }
        });
        // 只编辑 Stop：Notification 分组没有 command 字段，编辑器根本看不到它。
        let hooks = vec![HookEntry {
            event: "Stop".to_string(),
            matcher: "Bash".to_string(),
            command: "updated".to_string(),
        }];
        apply_editor_to_settings(&mut root, &PermissionRules::default(), &hooks).expect("apply");
        assert_eq!(
            root["hooks"]["Stop"][0]["hooks"][0]["command"],
            json!("updated")
        );
        assert_eq!(
            root["hooks"]["Notification"][0]["hooks"][0],
            json!({"no_command": true}),
            "无法解析的钩子分组必须原样保留，不能被替换掉"
        );
    }

    #[test]
    fn apply_editor_drops_only_managed_lists_when_emptied() {
        let mut root =
            json!({"permissions": {"allow": ["a"], "deny": ["b"], "defaultMode": "plan"}});
        apply_editor_to_settings(&mut root, &PermissionRules::default(), &[]).expect("apply");
        // allow/deny/ask 被清空 → 三个键消失；defaultMode 保留。
        let perms = root["permissions"].as_object().expect("permissions object");
        assert!(!perms.contains_key("allow"));
        assert!(!perms.contains_key("deny"));
        assert!(!perms.contains_key("ask"));
        assert_eq!(perms["defaultMode"], json!("plan"));
    }

    #[test]
    fn apply_editor_removes_permissions_block_when_only_managed_keys() {
        let mut root = json!({"permissions": {"allow": ["a"], "deny": ["b"]}});
        apply_editor_to_settings(&mut root, &PermissionRules::default(), &[]).expect("apply");
        assert!(
            root.get("permissions").is_none(),
            "只剩受管键时整块删除，避免留下空对象"
        );
    }

    #[test]
    fn apply_editor_truncates_removed_hooks_within_group() {
        let mut root = json!({
            "hooks": {"Stop": [{"hooks": [
                {"type": "command", "command": "one"},
                {"type": "command", "command": "two"}
            ]}]}
        });
        let hooks = vec![HookEntry {
            event: "Stop".to_string(),
            matcher: String::new(),
            command: "only".to_string(),
        }];
        apply_editor_to_settings(&mut root, &PermissionRules::default(), &hooks).expect("apply");
        let list = root["hooks"]["Stop"][0]["hooks"].as_array().unwrap();
        assert_eq!(list.len(), 1, "用户删掉第二条后必须截断，不能残留旧命令");
        assert_eq!(list[0]["command"], json!("only"));
    }

    #[test]
    fn apply_editor_updates_only_the_edited_group_and_keeps_other_shown_groups() {
        let mut root = json!({
            "hooks": {
                "Stop": [{"hooks": [{"type": "command", "command": "old-stop"}]}],
                "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "keep-pre"}]}]
            }
        });
        // 两个分组编辑器都展示过，用户只改 Stop 的 command，PreToolUse 原样带回。
        let hooks = vec![
            HookEntry {
                event: "Stop".to_string(),
                matcher: String::new(),
                command: "new-stop".to_string(),
            },
            HookEntry {
                event: "PreToolUse".to_string(),
                matcher: "Bash".to_string(),
                command: "keep-pre".to_string(),
            },
        ];
        apply_editor_to_settings(&mut root, &PermissionRules::default(), &hooks).expect("apply");
        assert_eq!(
            root["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            json!("keep-pre"),
            "未改动的分组内容不能被清空"
        );
        assert_eq!(
            root["hooks"]["Stop"][0]["hooks"][0]["command"],
            json!("new-stop")
        );
    }
}
