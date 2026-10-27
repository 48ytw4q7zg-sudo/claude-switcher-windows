//! Clash 模式识别、Script.js 托管规则写入/清理、内核 `/rules` 验证与回滚。
//!
//! 行为基准（与上游逐行对照）：
//! - `core/claude-switch.sh` 的 `PY_CLASH_RULES`（托管块生成、`norm`、逐条验证）；
//! - `windows/claude-switch.ps1` 的 `Get-ClashMode` / `Write-ClashScriptRules` /
//!   `Remove-LegacyMergeRules`（global/direct 不写规则、只清 Merge）。
//!
//! 语义：
//! - **模式识别**：Mihomo API `GET /configs` 优先，失败回退 `clash-verge.yaml` /
//!   `verge.yaml` 的 `mode:` 标量；都取不到返回 `"unknown"`。
//! - **global / direct**：规则本来就不生效，不写 `Script.js`，只清理历史遗留
//!   `Merge.yaml`（有清理才重启一次 Clash）。
//! - **rule**：只写 `profiles\Script.js` 托管块（先备份），重启 Clash 后经内核
//!   `GET /rules` 逐条验证前 16 条（3 个 UDP 端口 AND 规则 + 13 个域名后缀），
//!   失败从备份回滚 `Script.js`。
//! - **unknown**：跳过，避免误伤用户配置。
//!
//! 纯逻辑（`upsert_managed_block` / `build_managed_block` / `clean_legacy_merge` /
//! `verify_pinned_rules` / `norm_payload`）全部表驱动单测，不依赖真实 Clash/网络。

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::appconfig;
use crate::fsx;
use crate::jsonio;
use crate::net;
use crate::paths;
use crate::platform::imp;

/// Script.js 托管块起始标记。
const SCRIPT_BEGIN: &str = "// >>> claude-switcher managed rules >>>";
/// Script.js 托管块结束标记。
const SCRIPT_END: &str = "// <<< claude-switcher managed rules <<<";
/// 旧版 Merge.yaml 托管块起始标记（只清理，绝不重新写入）。
const MERGE_BEGIN: &str = "# >>> claude-switcher pinned rules >>>";
/// 旧版 Merge.yaml 托管块结束标记。
const MERGE_END: &str = "# <<< claude-switcher pinned rules <<<";

/// 由切换器置顶的 Claude 相关域名（顺序即 `/rules` 期望顺序的后 13 条）。
const CLAUDE_DOMAINS: [&str; 13] = [
    "claude.ai",
    "claude.com",
    "anthropic.com",
    "claudeusercontent.com",
    "challenges.cloudflare.com",
    "datadoghq.com",
    "segment.io",
    "stripe.com",
    "stripe.network",
    "stripecdn.com",
    "intercom.io",
    "intercomcdn.com",
    "intercomassets.com",
];

/// WebRTC STUN 端口（置顶规则前 3 条，顺序固定）。
const CLAUDE_PORTS: [u16; 3] = [3478, 5349, 19302];

/// 不允许作为「代理组名」的内核内置策略名（它们不是可选择的节点组）。
const FORBIDDEN_GROUPS: [&str; 4] = ["DIRECT", "REJECT", "GLOBAL", "PASS"];

/// WebRTC 策略：proxy（UDP 走代理组）/ reject（UDP 直接 REJECT 防止真实 IP 泄露）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRtcPolicy {
    Proxy,
    Reject,
}

impl WebRtcPolicy {
    /// 解析用户配置；非 "reject" 一律按 proxy 处理（与上游「非法已存策略读时报错、
    /// 写时按默认 proxy」的安全取向一致）。
    pub fn parse(saved: Option<&str>) -> Self {
        match saved {
            Some(s) if s.eq_ignore_ascii_case("reject") => Self::Reject,
            _ => Self::Proxy,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::Reject => "reject",
        }
    }
}

/// 一键修复（ensure_rules）的结构化结果，供 UI Banner / checkdetail 直接展示。
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RulesReport {
    /// 识别到的 Clash 模式：rule / global / direct / unknown。
    pub mode: String,
    /// Script.js 是否被改动。
    pub script_changed: bool,
    /// Script.js 备份路径（改动时存在）。
    pub script_backup: Option<String>,
    /// Merge.yaml 是否被清理。
    pub merge_changed: bool,
    /// Merge.yaml 备份路径（清理时存在）。
    pub merge_backup: Option<String>,
    /// 内核 `/rules` 是否验证通过。
    pub kernel_verified: bool,
    /// 是否尝试过重启 Clash Verge。
    pub restart_attempted: bool,
    /// 人可读的过程/结果行（FIX:… 风格）。
    pub messages: Vec<String>,
}

/// `clean_legacy_merge` 的输出：清理后的文本与是否发生变化。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeCleanup {
    pub text: String,
    pub changed: bool,
}

/// 置顶规则字符串（顺序 = 内核 `/rules` 期望的前 16 条）。
///
/// - 前 3 条：`AND,((NETWORK,UDP),(DST-PORT,<port>)),<target>`；reject 时 target 为
///   `REJECT`，proxy 时为代理组名。
/// - 后 13 条：`DOMAIN-SUFFIX,<domain>,<group>`（域名永远走代理组）。
pub fn rule_strings(group: &str, policy: WebRtcPolicy) -> Vec<String> {
    let port_target = match policy {
        WebRtcPolicy::Reject => "REJECT",
        WebRtcPolicy::Proxy => group,
    };
    let mut rules: Vec<String> = CLAUDE_PORTS
        .iter()
        .map(|port| format!("AND,((NETWORK,UDP),(DST-PORT,{port})),{port_target}"))
        .collect();
    rules.extend(
        CLAUDE_DOMAINS
            .iter()
            .map(|domain| format!("DOMAIN-SUFFIX,{domain},{group}")),
    );
    rules
}

/// 生成 Script.js 托管块（IIFE 包装已有 `main`，不破坏用户原脚本）。
///
/// 块内对原 `main` 的返回值做防御性校验：必须是对象、proxy-groups 必须含配置的
/// 代理组、rules 若存在必须是数组——否则抛错，避免把坏配置静默吃下去。
pub fn build_managed_block(group: &str, policy: WebRtcPolicy) -> String {
    let encoded =
        serde_json::to_string(&rule_strings(group, policy)).unwrap_or_else(|_| "[]".to_string());
    let group_json = serde_json::to_string(group).unwrap_or_else(|_| "\"\"".to_string());
    format!(
        "{BEGIN}
;(function () {{
  const originalMain = main;
  const pinnedRules = {encoded};
  const group = {group_json};
  main = function (config, ...args) {{
    const result = originalMain(config, ...args);
    if (!result || typeof result !== \"object\" || Array.isArray(result)) throw new Error(\"claude-switcher: original main must return a config object\");
    if (!Array.isArray(result[\"proxy-groups\"]) || !result[\"proxy-groups\"].some((item) => item && item.name === group)) throw new Error(\"claude-switcher: configured proxy group missing\");
    if (result.rules !== undefined && !Array.isArray(result.rules)) throw new Error(\"claude-switcher: rules must be an array\");
    result.rules = pinnedRules.concat((result.rules || []).filter((rule) => !pinnedRules.includes(rule)));
    return result;
  }};
}})();
{END}",
        BEGIN = SCRIPT_BEGIN,
        END = SCRIPT_END,
    )
}

/// 把托管块 upsert 进 Script.js 文本（纯函数）。
///
/// - 已有托管块：begin/end 必须各恰好一个且顺序正确，整段替换；
/// - 有 end 无 begin（或反之多个）：Err，绝不覆盖用户脚本；
/// - 文件为空：先写成默认 `function main(config) { return config; }` 再追加；
/// - 有内容但找不到 `function main(`：Err，请用户手动合并；
/// - 否则：在文件末尾追加托管块（IIFE 包装，无需插函数体）。
pub fn upsert_managed_block(old: &str, block: &str) -> Result<String, String> {
    let begin_count = old.matches(SCRIPT_BEGIN).count();
    let end_count = old.matches(SCRIPT_END).count();

    if begin_count > 0 {
        if begin_count != 1 || end_count != 1 {
            return Err("Script.js 中存在未闭合的 claude-switcher 管理块".to_string());
        }
        let begin = old.find(SCRIPT_BEGIN).expect("已计数存在");
        let end = old.find(SCRIPT_END).expect("已计数存在");
        if end < begin {
            return Err("Script.js 中的管理块顺序无效".to_string());
        }
        let end_after = end + SCRIPT_END.len();
        return Ok(format!("{}{}{}", &old[..begin], block, &old[end_after..]));
    }
    if end_count > 0 {
        return Err("Script.js 中存在孤立的 claude-switcher 管理块".to_string());
    }

    let base = if old.trim().is_empty() {
        "function main(config) { return config; }\n".to_string()
    } else {
        old.to_string()
    };
    if !contains_main(&base) {
        return Err("现有 Script.js 没有可组合的 main(config)，已停止以免覆盖用户脚本".to_string());
    }
    let mut out = base;
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(block);
    out.push('\n');
    Ok(out)
}

/// 是否含 `function main(`（容忍 function/main/括号之间的空白）。
fn contains_main(text: &str) -> bool {
    let mut rest = text;
    while let Some(idx) = rest.find("function") {
        let after_keyword = &rest[idx + "function".len()..];
        let trimmed = after_keyword.trim_start();
        if let Some(after_main) = trimmed.strip_prefix("main") {
            if after_main.trim_start().starts_with('(') {
                return true;
            }
        }
        // 从关键字后继续往后找，避免 "function" 出现在字符串里就误停。
        let next_search_pos = idx + "function".len();
        rest = &rest[next_search_pos.min(rest.len())..];
    }
    false
}

/// 内核规则 payload 归一化（与上游 `norm()` 逐行对齐）：
/// 大写 → 删除空白/`(` `)` `_` `-` → `&&` 替换为 `,`。
///
/// 例：`((Network,udp) && (DstPort,3478))` → `NETWORK,UDP,DSTPORT,3478`。
fn norm_payload(value: &str) -> String {
    let stripped: String = value
        .chars()
        .map(|c| c.to_ascii_uppercase())
        .filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\r' | '(' | ')' | '_' | '-'))
        .collect();
    stripped.replace("&&", ",")
}

fn rule_disabled(rule: &Value) -> bool {
    rule.get("extra")
        .and_then(|extra| extra.get("disabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// 逐条验证内核 `/rules` 返回的规则列表是否符合置顶期望（纯函数）。
///
/// 前 3 条必须是 AND 规则（UDP + 目标端口，target 按策略为 REJECT 或代理组），
/// 随后 13 条必须是域名后缀（大小写不敏感、目标为代理组）；任一带 `extra.disabled:
/// true` 的规则视为未生效。
pub fn verify_pinned_rules(rules: &Value, group: &str, policy: WebRtcPolicy) -> Result<(), String> {
    let list = rules
        .as_array()
        .ok_or_else(|| "Clash /rules 返回格式异常".to_string())?;
    let expected_len = CLAUDE_PORTS.len() + CLAUDE_DOMAINS.len();
    if list.len() < expected_len {
        return Err(format!(
            "运行中的规则数量不足({}<{})",
            list.len(),
            expected_len
        ));
    }

    let port_target = match policy {
        WebRtcPolicy::Reject => "REJECT".to_string(),
        WebRtcPolicy::Proxy => group.to_string(),
    };

    for (index, port) in CLAUDE_PORTS.iter().enumerate() {
        let rule = &list[index];
        let typ = rule
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_uppercase();
        let payload = norm_payload(rule.get("payload").and_then(|v| v.as_str()).unwrap_or(""));
        let proxy = rule.get("proxy").and_then(|v| v.as_str()).unwrap_or("");
        if typ != "AND"
            || payload != format!("NETWORK,UDP,DSTPORT,{port}")
            || proxy != port_target
            || rule_disabled(rule)
        {
            return Err(format!("运行规则未按策略置顶:UDP/{port}"));
        }
    }

    for (offset, domain) in CLAUDE_DOMAINS.iter().enumerate() {
        let index = CLAUDE_PORTS.len() + offset;
        let rule = &list[index];
        let typ_raw = rule
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_uppercase();
        // 内核返回可能是 DOMAIN-SUFFIX / DOMAINSUFFIX / DOMAIN_SUFFIX，统一容忍。
        let typ = typ_raw.replace('_', "-");
        if typ != "DOMAIN-SUFFIX" && typ != "DOMAINSUFFIX" {
            return Err(format!("运行规则未按策略置顶:{domain}"));
        }
        let payload = rule
            .get("payload")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_lowercase();
        let proxy = rule.get("proxy").and_then(|v| v.as_str()).unwrap_or("");
        if payload != *domain || proxy != group || rule_disabled(rule) {
            return Err(format!("运行规则未按策略置顶:{domain}"));
        }
    }
    Ok(())
}

/// 校验 `/proxies` 中配置的代理组可用（纯函数）。
///
/// - 内置策略名（DIRECT/REJECT/...）不是组；
/// - 组必须存在且带 `all` 列表；沿 `now` 解析到真实节点（防循环）；
/// - 节点类型不能是 direct/reject/block；proxy 策略要求节点 `udp == true`。
pub fn validate_proxy_state(
    proxies: &Value,
    group: &str,
    policy: WebRtcPolicy,
) -> Result<(), String> {
    if FORBIDDEN_GROUPS.contains(&group) {
        return Err("请选择实际的代理组".to_string());
    }
    let all = proxies
        .get("proxies")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "Clash /proxies 返回格式异常".to_string())?;
    let entry = all
        .get(group)
        .ok_or_else(|| format!("代理组不存在:{group}"))?;
    let is_group = entry
        .get("all")
        .and_then(|v| v.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false);
    if !is_group {
        return Err(format!("配置的代理组不是可选择的组:{group}"));
    }

    let mut current = group.to_string();
    let mut visited: HashSet<String> = HashSet::new();
    let node: &Value;
    loop {
        if !visited.insert(current.clone()) {
            return Err("代理组存在循环引用".to_string());
        }
        let item = all
            .get(&current)
            .ok_or_else(|| format!("代理节点不存在:{current}"))?;
        let looks_like_group = item.get("all").is_some() || item.get("now").is_some();
        if looks_like_group {
            let next = item
                .get("now")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if next.is_empty() || next == current {
                return Err(format!("代理组没有可用的当前节点:{current}"));
            }
            current = next;
            continue;
        }
        node = item;
        break;
    }

    let node_type = node
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    if matches!(node_type.as_str(), "direct" | "reject" | "block") {
        return Err("代理组当前节点为直连或拒绝，请选择代理节点".to_string());
    }
    if policy == WebRtcPolicy::Proxy && node.get("udp").and_then(|v| v.as_bool()) != Some(true) {
        return Err("当前节点未确认支持 UDP，请更换节点或选择 reject 策略".to_string());
    }
    Ok(())
}

/// 识别 Clash 当前模式：`rule` / `global` / `direct` / `unknown`。
///
/// 先 `GET /configs` 取实时 mode（内核在用什么就是什么）；API 不可用时回退读
/// `clash-verge.yaml` / `verge.yaml` 的顶层 `mode:` 标量（磁盘上的配置值）。
pub fn clash_mode() -> Result<String, String> {
    if let Ok(configs) = net::clash_api("GET", "/configs", None) {
        if let Some(mode) = configs.get("mode").and_then(|v| v.as_str()) {
            let mode = mode.trim().to_lowercase();
            if matches!(mode.as_str(), "rule" | "global" | "direct") {
                return Ok(mode);
            }
        }
    }
    let base = paths::clash_verge_dir()?;
    for name in ["clash-verge.yaml", "verge.yaml"] {
        let path = base.join(name);
        if let Ok(Some(value)) = jsonio::read_yaml_optional(path) {
            if let Some(mode) = value.get("mode").and_then(|v| v.as_str()) {
                let mode = mode.trim().to_lowercase();
                if matches!(mode.as_str(), "rule" | "global" | "direct") {
                    return Ok(mode);
                }
            }
        }
    }
    Ok("unknown".to_string())
}

/// 清理旧版写进 `Merge.yaml` 的遗留内容（纯函数）：
///
/// 1. 整段移除 `# >>> claude-switcher pinned rules >>>` … 标记块（孤立/未闭合 → Err）；
/// 2. 删除单独成行的多文档分隔符 `---`（允许 `--- # 注释`）；
/// 3. 删除置顶规则行（`- DOMAIN-SUFFIX,<域名>,…` / `- DST-PORT,<端口>,…`）；
/// 4. 删除空的 `prepend-rules:`（用户可能只删了规则行留下空键）；
/// 5. 重复出现的顶层键只保留第一次出现的段落（后续整段跳过）。
pub fn clean_legacy_merge(input: &str) -> Result<MergeCleanup, String> {
    let mut text = input.to_string();

    // 1. 旧版标记块：整段（含标记所在行）删除。
    let begin_count = text.matches(MERGE_BEGIN).count();
    let end_count = text.matches(MERGE_END).count();
    if begin_count > 0 {
        if begin_count != 1 || end_count != 1 {
            return Err("Merge.yaml 中存在未闭合的 claude-switcher 管理块".to_string());
        }
        let begin = text.find(MERGE_BEGIN).expect("已计数存在");
        let end = text.find(MERGE_END).expect("已计数存在");
        if end < begin {
            return Err("Merge.yaml 中存在管理块顺序无效".to_string());
        }
        let line_start = text[..begin].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let line_end = text[end..]
            .find('\n')
            .map(|i| end + i + 1)
            .unwrap_or(text.len());
        text = format!("{}{}", &text[..line_start], &text[line_end..]);
    } else if end_count > 0 {
        return Err("Merge.yaml 中存在孤立的 claude-switcher 管理块".to_string());
    }

    // 行切分（兼容 CRLF）。
    let lines: Vec<&str> = text
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect();

    // 2+3. 先过一遍：多文档分隔行 / 置顶规则行直接丢。
    let mut kept: Vec<&str> = Vec::with_capacity(lines.len());
    let mut dropped_count = 0usize;
    for line in &lines {
        if is_doc_separator(line) || is_pinned_rule(line) {
            dropped_count += 1;
            continue;
        }
        kept.push(line);
    }

    // 4+5. 再走一遍：空 prepend-rules 删除；重复顶层键只保留首次段落。
    let mut out: Vec<String> = Vec::with_capacity(kept.len());
    let mut seen_top: HashSet<String> = HashSet::new();
    let mut skipping_dupe_section = false;
    let mut index = 0;
    while index < kept.len() {
        let line = kept[index];
        if is_top_level_key(line) {
            let key = top_level_key(line);
            if is_empty_prepend_header(line) && !header_has_item(&kept[index + 1..]) {
                // 空 prepend-rules：连键一起丢（其下本来就没有列表项）。
                dropped_count += 1;
                index += 1;
                continue;
            }
            if !seen_top.insert(key) {
                // 重复顶层键：跳过本行及其后续缩进行，直到下一个顶层键。
                skipping_dupe_section = true;
                dropped_count += 1;
                index += 1;
                continue;
            }
            skipping_dupe_section = false;
            out.push(line.to_string());
            index += 1;
            continue;
        }
        if skipping_dupe_section {
            dropped_count += 1;
            index += 1;
            continue;
        }
        out.push(line.to_string());
        index += 1;
    }

    let final_text = out.join("\n");
    // 无任何行被丢弃且文本逐字节相等才算「未变化」（尾随换行由 split/join 自然保留）。
    let changed = dropped_count > 0 || final_text != input;
    Ok(MergeCleanup {
        text: final_text,
        changed,
    })
}

/// `^\s*---\s*(#.*)?$`：多文档分隔行。
fn is_doc_separator(line: &str) -> bool {
    let trimmed_start = line.trim_start();
    let Some(rest) = trimmed_start.strip_prefix("---") else {
        return false;
    };
    let rest = rest.trim_start();
    rest.is_empty() || rest.starts_with('#')
}

/// `^\s*-\s*(DOMAIN-SUFFIX,<域名>,|DST-PORT,<端口>,)`：切换器旧版写入的置顶规则行。
fn is_pinned_rule(line: &str) -> bool {
    let trimmed_start = line.trim_start();
    let Some(rest) = trimmed_start.strip_prefix('-') else {
        return false;
    };
    let content = rest.trim_start();
    for domain in CLAUDE_DOMAINS {
        if content.starts_with(&format!("DOMAIN-SUFFIX,{domain},")) {
            return true;
        }
    }
    for port in CLAUDE_PORTS {
        if content.starts_with(&format!("DST-PORT,{port},")) {
            return true;
        }
    }
    false
}

/// 行首无空白、形如 `key:`（key 由字母/数字/`_.-` 组成）：顶层键。
fn is_top_level_key(line: &str) -> bool {
    let Some(first) = line.chars().next() else {
        return false;
    };
    if first.is_ascii_whitespace() || first == '#' || first == '-' {
        return false;
    }
    match line.find(':') {
        Some(colon) => {
            !line[..colon].is_empty()
                && line[..colon]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        }
        None => false,
    }
}

fn top_level_key(line: &str) -> String {
    line.split(':').next().unwrap_or("").to_string()
}

/// `^\s*prepend-rules:\s*(#.*)?$`：空 prepend-rules 键行。
fn is_empty_prepend_header(line: &str) -> bool {
    let trimmed = line.trim_start();
    let Some(rest) = trimmed.strip_prefix("prepend-rules") else {
        return false;
    };
    let rest = rest.trim_start();
    let Some(rest) = rest.strip_prefix(':') else {
        return false;
    };
    let rest = rest.trim_start();
    rest.is_empty() || rest.starts_with('#')
}

/// 跳过空行/注释行后，第一个实质行是否为 `- ` 列表项。
fn header_has_item(after: &[&str]) -> bool {
    for next in after {
        let trimmed = next.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        return next.trim_start().starts_with("- ");
    }
    false
}

/// 备份文件名：`<原名>.bak.<纳秒>`（与上游 `.bak.<时间戳>` 语义一致）。
fn backup_path_for(path: &Path) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    path.with_file_name(format!("{file_name}.bak.{nanos}"))
}

/// 重启 Clash Verge GUI（best-effort）：杀掉 GUI 进程，再从常见安装位置拉起。
///
/// 找不到 exe / 拉起失败时返回 false，由调用方提示用户手动重启；**不阻塞验证**，
/// 验证循环本身会等到内核重新加载为止。
fn restart_clash_verge(report: &mut RulesReport) {
    report.restart_attempted = true;
    // 只杀 GUI（与上游 Restart-ClashVerge 一致）；内核作为服务/子进程随 GUI 重载。
    let _ = imp::kill_processes_by_names(&["clash-verge"]);
    std::thread::sleep(Duration::from_secs(2));

    let mut candidates: Vec<PathBuf> = Vec::new();
    for var in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        if let Some(root) = std::env::var_os(var) {
            let root = PathBuf::from(root);
            candidates.push(root.join("Clash Verge\\Clash Verge.exe"));
            candidates.push(root.join("Clash Verge Rev\\Clash Verge.exe"));
            candidates.push(root.join("Programs\\clash-verge\\Clash Verge.exe"));
        }
    }
    for candidate in candidates {
        if candidate.exists() && imp::start_detached(&candidate.to_string_lossy(), &[]).is_ok() {
            report
                .messages
                .push(format!("已重启 Clash Verge: {}", candidate.display()));
            return;
        }
    }
    report
        .messages
        .push("未找到 Clash Verge 可执行文件，请手动重启 Clash Verge 使规则生效".to_string());
}

/// 轮询内核 `/rules` + `/proxies` 直到验证通过或超时（秒）。
fn wait_kernel_verified(group: &str, policy: WebRtcPolicy, timeout_secs: u64) -> bool {
    let deadline = SystemTime::now() + Duration::from_secs(timeout_secs);
    loop {
        if let Ok(rules) = net::clash_api("GET", "/rules", None) {
            if verify_pinned_rules(&rules, group, policy).is_ok() {
                if let Ok(proxies) = net::clash_api("GET", "/proxies", None) {
                    if validate_proxy_state(&proxies, group, policy).is_ok() {
                        return true;
                    }
                }
            }
        }
        if SystemTime::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    false
}

/// 一键修复的规则段：按模式决定是否写 Script.js，并在写入后验证/回滚。
///
/// 调用方必须在 `blocking(...)` 中执行（内部含 HTTP 轮询与进程操作）。
pub fn ensure_rules() -> Result<RulesReport, String> {
    let mut report = RulesReport::default();
    let mode = clash_mode()?;
    report.mode = mode.clone();

    let base = paths::clash_verge_dir()?;
    let profiles = base.join("profiles");
    let script_path = profiles.join("Script.js");
    let merge_path = profiles.join("Merge.yaml");

    // —— 1. 所有模式都先清理历史 Merge.yaml 遗留（global/direct 也需要）——
    if merge_path.exists() {
        let raw = jsonio::read_text_lossy_bom(&merge_path)?;
        match clean_legacy_merge(&raw) {
            Ok(out) if out.changed => {
                let backup = backup_path_for(&merge_path);
                std::fs::copy(&merge_path, &backup)
                    .map_err(|e| format!("备份 Merge.yaml 失败: {e}"))?;
                if out.text.trim().is_empty() {
                    fsx::remove_file_with_retry(&merge_path)
                        .map_err(|e| format!("删除空 Merge.yaml 失败: {e}"))?;
                } else {
                    fsx::write_atomically(&merge_path, &out.text)
                        .map_err(|e| format!("写入 Merge.yaml 失败: {e}"))?;
                }
                report.merge_changed = true;
                report.merge_backup = Some(backup.to_string_lossy().to_string());
                report.messages.push(format!(
                    "已清理历史遗留 Merge 规则并备份: {}",
                    backup.display()
                ));
            }
            Ok(_) => {}
            Err(e) => report.messages.push(format!("Merge.yaml 清理中止: {e}")),
        }
    }

    // —— 2. 按模式分派 ——
    match mode.as_str() {
        "unknown" => {
            report
                .messages
                .push("无法确认 Clash 模式，已跳过规则修改".to_string());
            return Ok(report);
        }
        "global" | "direct" => {
            report.messages.push(format!(
                "Clash 模式={mode}，规则不适用，未写入任何规则{}",
                if report.merge_changed {
                    "；发现并清理了历史遗留配置"
                } else {
                    "，未改动任何配置"
                }
            ));
            // 只有真的清理过 Merge 才需要重启一次让内核丢弃旧 prepend-rules。
            if report.merge_changed {
                restart_clash_verge(&mut report);
            }
            return Ok(report);
        }
        _ => {} // rule：继续往下写 Script.js
    }

    // —— 3. rule 模式：写 Script.js 托管块 ——
    let app = appconfig::load();
    let group = app.proxy_group.unwrap_or_default();
    let group_trimmed = group.trim();
    if group_trimmed.is_empty()
        || group.contains(',')
        || group.contains('\r')
        || group.contains('\n')
        || FORBIDDEN_GROUPS.contains(&group_trimmed.to_uppercase().as_str())
    {
        return Err(
            "代理组名为空、含逗号/换行或为内置策略名，请先在设置中选择 Clash 代理组".to_string(),
        );
    }
    let policy = WebRtcPolicy::parse(app.webrtc_policy.as_deref());
    report
        .messages
        .push(format!("WebRTC 策略：{}", policy.as_str()));

    let existed = script_path.exists();
    let old = if existed {
        jsonio::read_text_lossy_bom(&script_path).unwrap_or_default()
    } else {
        String::new()
    };
    let block = build_managed_block(group_trimmed, policy);
    let new_text = upsert_managed_block(&old, &block)?;

    if new_text == old {
        report.messages.push("规则已是当前版本".to_string());
    } else {
        let backup = if existed {
            let backup = backup_path_for(&script_path);
            std::fs::copy(&script_path, &backup)
                .map_err(|e| format!("备份 Script.js 失败: {e}"))?;
            Some(backup)
        } else {
            None
        };
        fsx::write_atomically(&script_path, &new_text)
            .map_err(|e| format!("写入 Script.js 失败: {e}"))?;
        report.script_changed = true;
        report.script_backup = backup.as_ref().map(|b| b.to_string_lossy().to_string());
        report.messages.push(match &report.script_backup {
            Some(backup) => format!("已写入 Script.js 规则并备份: {backup}"),
            None => "已创建 Script.js".to_string(),
        });
    }

    // —— 4. 重启内核并验证；失败回滚 ——
    restart_clash_verge(&mut report);
    report.kernel_verified = wait_kernel_verified(group_trimmed, policy, 40);
    if report.kernel_verified {
        report.messages.push("置顶规则 ✓".to_string());
    } else if report.script_changed {
        report
            .messages
            .push("置顶规则验证失败，正在回滚 Script.js...".to_string());
        match (&report.script_backup, existed) {
            (Some(backup), _) => {
                let _ = std::fs::copy(backup, &script_path);
            }
            (None, false) => {
                let _ = fsx::remove_file_with_retry(&script_path);
            }
            (None, true) => {}
        }
        restart_clash_verge(&mut report);
        report.messages.push(
            "置顶规则 FAIL: 验证失败，已回滚 Script.js，请确认 Clash Verge 已启用全局扩展脚本"
                .to_string(),
        );
    } else {
        // 块本就在文件里（未改动），但内核没加载——只告警，不回滚。
        report
            .messages
            .push("规则已写入但无法验证内核加载（控制接口不可用或未启用全局扩展脚本）".to_string());
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pinned_rule(rule_type: &str, payload: &str, proxy: &str) -> Value {
        json!({ "type": rule_type, "payload": payload, "proxy": proxy })
    }

    fn valid_rules(group: &str, policy: WebRtcPolicy) -> Value {
        let target = match policy {
            WebRtcPolicy::Reject => "REJECT",
            WebRtcPolicy::Proxy => group,
        };
        let mut rules: Vec<Value> = CLAUDE_PORTS
            .iter()
            .map(|port| {
                pinned_rule(
                    "AND",
                    &format!("((Network,udp) && (DstPort,{port}))"),
                    target,
                )
            })
            .collect();
        rules.extend(
            CLAUDE_DOMAINS
                .iter()
                .map(|domain| pinned_rule("DomainSuffix", domain, group)),
        );
        json!(rules)
    }

    // ---------- rule_strings ----------

    #[test]
    fn rule_strings_proxy_policy_targets_group() {
        let rules = rule_strings("My proxy", WebRtcPolicy::Proxy);
        assert_eq!(rules.len(), 16);
        assert_eq!(
            rules[..3],
            [
                "AND,((NETWORK,UDP),(DST-PORT,3478)),My proxy",
                "AND,((NETWORK,UDP),(DST-PORT,5349)),My proxy",
                "AND,((NETWORK,UDP),(DST-PORT,19302)),My proxy",
            ]
        );
        assert!(rules.contains(&"DOMAIN-SUFFIX,claude.ai,My proxy".to_string()));
        assert!(rules.contains(&"DOMAIN-SUFFIX,intercomassets.com,My proxy".to_string()));
    }

    #[test]
    fn rule_strings_reject_policy_rejects_udp_but_keeps_domains_on_group() {
        let rules = rule_strings("My proxy", WebRtcPolicy::Reject);
        assert_eq!(rules[0], "AND,((NETWORK,UDP),(DST-PORT,3478)),REJECT");
        assert_eq!(rules[2], "AND,((NETWORK,UDP),(DST-PORT,19302)),REJECT");
        assert_eq!(rules[3], "DOMAIN-SUFFIX,claude.ai,My proxy");
    }

    // ---------- build_managed_block ----------

    #[test]
    fn managed_block_contains_markers_and_pinned_rules() {
        let block = build_managed_block("Proxy \"one\" \\ 中文", WebRtcPolicy::Proxy);
        assert!(block.starts_with(SCRIPT_BEGIN));
        assert!(block.trim_end().ends_with(SCRIPT_END));
        // 组名经 JSON 转义，引号/反斜杠不产生代码注入。
        assert!(block.contains("\"Proxy \\\"one\\\" \\\\ 中文\""));
        assert!(block.contains("pinnedRules"));
        assert!(block.contains("originalMain"));
    }

    // ---------- upsert_managed_block ----------

    #[test]
    fn upsert_empty_script_wraps_default_main_then_appends_block() {
        let block = build_managed_block("g", WebRtcPolicy::Proxy);
        let out = upsert_managed_block("", &block).unwrap();
        assert!(out.starts_with("function main(config) { return config; }"));
        assert!(out.contains(SCRIPT_BEGIN));
        assert!(out.contains(SCRIPT_END));
    }

    #[test]
    fn upsert_replaces_existing_block_only_and_keeps_rest() {
        let old = "function main(config) {\n  config.rules.unshift(\"DOMAIN,custom.test,DIRECT\");\n  return config;\n}\n";
        let block_v1 = build_managed_block("g", WebRtcPolicy::Proxy);
        let with_block = upsert_managed_block(old, &block_v1).unwrap();
        assert!(with_block.contains(old.trim()));

        // 第二次写入（切换策略）：只换块，原脚本逐字节保留。
        let block_v2 = build_managed_block("g", WebRtcPolicy::Reject);
        let replaced = upsert_managed_block(&with_block, &block_v2).unwrap();
        assert!(replaced.contains("REJECT"));
        // 原用户脚本仍然在。
        assert!(replaced.contains("DOMAIN,custom.test,DIRECT"));
        // 托管块只出现一次。
        assert_eq!(replaced.matches(SCRIPT_BEGIN).count(), 1);
        assert_eq!(replaced.matches(SCRIPT_END).count(), 1);
    }

    #[test]
    fn upsert_rejects_orphan_end_marker() {
        let old = format!("function main(c) {{ return c; }}\n{SCRIPT_END}\n");
        assert!(upsert_managed_block(&old, "BLOCK").is_err());
    }

    #[test]
    fn upsert_rejects_multiple_markers() {
        let old = format!("{SCRIPT_BEGIN}\nA\n{SCRIPT_END}\n{SCRIPT_BEGIN}\nB\n{SCRIPT_END}\n");
        assert!(upsert_managed_block(&old, "BLOCK").is_err());
    }

    #[test]
    fn upsert_rejects_script_without_main() {
        assert!(upsert_managed_block("const x = 1;\n", "BLOCK").is_err());
    }

    // ---------- norm_payload ----------

    #[test]
    fn norm_payload_matches_upstream_behavior() {
        assert_eq!(
            norm_payload("((Network,udp) && (DstPort,3478))"),
            "NETWORK,UDP,DSTPORT,3478"
        );
        // || 不是 &&，必须失败。
        assert_ne!(
            norm_payload("((Network,udp) || (DstPort,3478))"),
            "NETWORK,UDP,DSTPORT,3478"
        );
        // 端口错配必须失败。
        assert_ne!(
            norm_payload("((Network,udp) && (DstPort,34780))"),
            "NETWORK,UDP,DSTPORT,3478"
        );
        // 下划线/连字符等价容忍。
        assert_eq!(norm_payload("domain-suffix"), "DOMAINSUFFIX");
    }

    // ---------- verify_pinned_rules ----------

    #[test]
    fn verify_accepts_valid_rule_list_case_insensitive() {
        let rules = valid_rules("g", WebRtcPolicy::Proxy);
        assert!(verify_pinned_rules(&rules, "g", WebRtcPolicy::Proxy).is_ok());
        // 域名大小写不敏感。
        let mut rules_upper = rules.clone();
        rules_upper[6] = pinned_rule("DomainSuffix", "ClaudeUserContent.COM", "g");
        assert!(verify_pinned_rules(&rules_upper, "g", WebRtcPolicy::Proxy).is_ok());
    }

    #[test]
    fn verify_rejects_missing_first_rule() {
        let mut rules = valid_rules("g", WebRtcPolicy::Proxy);
        rules.as_array_mut().unwrap().remove(0);
        assert!(verify_pinned_rules(&rules, "g", WebRtcPolicy::Proxy).is_err());
    }

    #[test]
    fn verify_rejects_wrong_target_proxy() {
        let mut rules = valid_rules("g", WebRtcPolicy::Proxy);
        rules.as_array_mut().unwrap()[0] =
            pinned_rule("AND", "((Network,udp) && (DstPort,3478))", "DIRECT");
        assert!(verify_pinned_rules(&rules, "g", WebRtcPolicy::Proxy).is_err());
    }

    #[test]
    fn verify_rejects_disabled_rule() {
        let mut rule = pinned_rule("AND", "((Network,udp) && (DstPort,3478))", "g");
        rule["extra"] = json!({ "disabled": true });
        let mut rules = valid_rules("g", WebRtcPolicy::Proxy);
        rules.as_array_mut().unwrap()[0] = rule;
        assert!(verify_pinned_rules(&rules, "g", WebRtcPolicy::Proxy).is_err());
    }

    #[test]
    fn verify_rejects_or_payload_and_wrong_port() {
        let mut rules = valid_rules("g", WebRtcPolicy::Proxy);
        rules.as_array_mut().unwrap()[0] =
            pinned_rule("AND", "((Network,udp) || (DstPort,3478))", "g");
        assert!(verify_pinned_rules(&rules, "g", WebRtcPolicy::Proxy).is_err());

        let mut rules = valid_rules("g", WebRtcPolicy::Proxy);
        rules.as_array_mut().unwrap()[0] =
            pinned_rule("AND", "((Network,udp) && (DstPort,34780))", "g");
        assert!(verify_pinned_rules(&rules, "g", WebRtcPolicy::Proxy).is_err());
    }

    #[test]
    fn verify_rejects_short_list() {
        assert!(verify_pinned_rules(&json!([]), "g", WebRtcPolicy::Proxy).is_err());
    }

    #[test]
    fn reject_policy_expects_reject_on_udp_rules() {
        let rules = valid_rules("g", WebRtcPolicy::Reject);
        assert!(verify_pinned_rules(&rules, "g", WebRtcPolicy::Reject).is_ok());
        // reject 策略下 UDP 走了组名 → 失败。
        let proxy_rules = valid_rules("g", WebRtcPolicy::Proxy);
        assert!(verify_pinned_rules(&proxy_rules, "g", WebRtcPolicy::Reject).is_err());
    }

    // ---------- validate_proxy_state ----------

    #[test]
    fn validate_group_accepts_udp_supporting_node() {
        let state = json!({
            "proxies": {
                "My proxy": { "type": "Selector", "now": "node", "all": ["node"] },
                "node": { "type": "Shadowsocks", "udp": true },
            }
        });
        assert!(validate_proxy_state(&state, "My proxy", WebRtcPolicy::Proxy).is_ok());
    }

    #[test]
    fn validate_group_rejects_direct_node_and_no_udp() {
        let state = json!({
            "proxies": {
                "g": { "type": "Selector", "now": "n", "all": ["n"] },
                "n": { "type": "Direct" },
            }
        });
        assert!(validate_proxy_state(&state, "g", WebRtcPolicy::Proxy).is_err());

        let state = json!({
            "proxies": {
                "g": { "type": "Selector", "now": "n", "all": ["n"] },
                "n": { "type": "Shadowsocks", "udp": false },
            }
        });
        assert!(validate_proxy_state(&state, "g", WebRtcPolicy::Proxy).is_err());
        // reject 策略不要求 UDP。
        assert!(validate_proxy_state(&state, "g", WebRtcPolicy::Reject).is_ok());
    }

    #[test]
    fn validate_group_rejects_builtin_names() {
        let state = json!({ "proxies": {} });
        assert!(validate_proxy_state(&state, "REJECT", WebRtcPolicy::Proxy).is_err());
    }

    // ---------- clean_legacy_merge ----------

    #[test]
    fn clean_merge_strips_marker_block_and_pinned_rules() {
        let input = concat!(
            "profile:\n  store-selected: true\n",
            "# >>> claude-switcher pinned rules >>>\n",
            "prepend-rules:\n  - DST-PORT,3478,IpEqual\n",
            "# <<< claude-switcher pinned rules <<<\n"
        );
        let out = clean_legacy_merge(input).unwrap();
        assert_eq!(out.text, "profile:\n  store-selected: true\n");
        assert!(out.changed);
    }

    #[test]
    fn clean_merge_removes_doc_separators_pinned_lines_and_empty_prepend() {
        let input = concat!(
            "profile:\n  store-selected: true\n",
            "---\n",
            "prepend-rules:\n",
            "  - DOMAIN-SUFFIX,claude.ai,My proxy\n",
            "  - DST-PORT,5349,My proxy\n",
            "other-key:\n  value: 1\n"
        );
        let out = clean_legacy_merge(input).unwrap();
        assert!(!out.text.contains("---"));
        assert!(!out.text.contains("prepend-rules"));
        assert!(!out.text.contains("DOMAIN-SUFFIX"));
        assert!(out.text.contains("profile:"));
        assert!(out.text.contains("other-key:"));
        assert!(out.changed);
    }

    #[test]
    fn clean_merge_keeps_non_pinned_prepend_rules() {
        let input = concat!(
            "prepend-rules:\n",
            "  - DOMAIN,personal.test,DIRECT\n",
            "profile:\n  store-selected: true\n"
        );
        let out = clean_legacy_merge(input).unwrap();
        assert!(out.text.contains("DOMAIN,personal.test,DIRECT"));
        assert!(out.text.contains("prepend-rules:"));
        // 用户自有规则不动 → 无变化。
        assert!(!out.changed);
    }

    #[test]
    fn clean_merge_dedupes_top_level_keys() {
        let input = concat!(
            "profile:\n  a: 1\n",
            "prepend-rules:\n  - A,B,C\n",
            "profile:\n  b: 2\n",
            "tail: 3\n"
        );
        let out = clean_legacy_merge(input).unwrap();
        // 第一个 profile 段落保留；第二个 profile 及其缩进行被丢弃；tail 保留。
        assert!(out.text.contains("a: 1"));
        assert!(!out.text.contains("b: 2"));
        assert!(out.text.contains("tail: 3"));
        assert!(out.changed);
    }

    #[test]
    fn clean_merge_rejects_orphan_marker() {
        let input = "# <<< claude-switcher pinned rules <<<\n";
        assert!(clean_legacy_merge(input).is_err());
    }
}
