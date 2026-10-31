//! F-7 / K-7：诊断包脱敏。
//!
//! 纯函数，不依赖网络/真实文件：
//! - JSON：键名命中敏感标记（token / authorization / 邮箱 / 姓名 / uuid 等）的，值整体
//!   替换为 `"***"`；其余递归处理，字符串值也走 `redact_text`；`projects` 等以绝对路径
//!   为键的条目会把路径里的用户名替换为占位符。
//! - 自由文本：用正则脱敏 `sk-ant-…` / `Bearer …` / JWT 形态，替换 `\Users\<user>` 路径，
//!   并扫描邮箱。
//! - 邮箱：保留首字符与域名，中间替换（`john@example.com` → `j***@example.com`）。

use std::sync::OnceLock;

use serde_json::{json, Value};

/// 命中即视为敏感键的子串（比较前键名转小写）。
pub const SENSITIVE_KEY_MARKERS: [&str; 11] = [
    "token",
    "authorization",
    "anthropic_",
    "apikey",
    "api_key",
    "password",
    // K-7：.claude.json oauthAccount 里的身份/标识字段。
    "emailaddress",
    "displayname",
    "organizationname",
    "accountuuid",
    "organizationuuid",
];

/// 判断一个键名是否为敏感键。
pub fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    SENSITIVE_KEY_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// 取当前用户名（来自 home 目录名），用于替换路径中的 `\Users\<user>`。
fn current_user_name() -> Option<String> {
    dirs::home_dir()?.file_name()?.to_str().map(str::to_string)
}

/// 令牌形态正则：sk-ant-… / Bearer … / JWT（eyJ 三段）。
fn token_regex() -> &'static regex::Regex {
    static TOKEN_RE: OnceLock<regex::Regex> = OnceLock::new();
    TOKEN_RE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)(sk-ant-[A-Za-z0-9_-]{8,}|Bearer\s+[A-Za-z0-9._-]{16,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
        )
        .expect("static token redaction regex must be valid")
    })
}

/// 脱敏自由文本：令牌形态 → `***`，替换用户路径，再脱敏邮箱。
pub fn redact_text(input: &str, user: &str) -> String {
    let mut out = token_regex().replace_all(input, "***").into_owned();
    if !user.is_empty() {
        out = out
            .replace(&format!("\\Users\\{user}"), "\\Users\\<user>")
            .replace(&format!("/Users/{user}"), "/Users/<user>");
    }
    redact_emails_in_text(&out)
}

/// 原地脱敏一个 JSON 值（递归）。
pub fn redact_json(value: &mut Value) {
    let user = current_user_name().unwrap_or_default();
    redact_json_for_user(value, &user);
}

/// 以指定用户名递归脱敏 JSON 值。
fn redact_json_for_user(value: &mut Value, user: &str) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *child = json!("***");
                } else {
                    redact_json_for_user(child, user);
                }
            }
            // projects 等以绝对路径为键的条目：替换路径里的用户名。
            if !user.is_empty() {
                let renames: Vec<(String, String)> = map
                    .keys()
                    .filter_map(|key| {
                        let new_key = redact_text(key, user);
                        (&new_key != key).then_some((key.clone(), new_key))
                    })
                    .collect();
                for (old_key, new_key) in renames {
                    if let Some(removed) = map.remove(&old_key) {
                        map.insert(new_key, removed);
                    }
                }
            }
        }
        Value::Array(items) => {
            for child in items.iter_mut() {
                redact_json_for_user(child, user);
            }
        }
        Value::String(text) => {
            let cleaned = redact_text(text, user);
            if cleaned != *text {
                *text = cleaned;
            }
        }
        _ => {}
    }
}

/// 脱敏单个邮箱：保留本地部分首字符 + 域名；无有效邮箱形态则整体替换。
pub fn redact_email(email: &str) -> String {
    let trimmed = email.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return "***".to_string();
    };
    let first = local
        .chars()
        .next()
        .map(|c| c.to_string())
        .unwrap_or_default();
    if domain.is_empty() {
        return "***".to_string();
    }
    format!("{first}***@{domain}")
}

/// 邮箱字符判定：字母数字与常见邮箱标点。
fn is_email_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+')
}

/// 在字符切片里找全部邮箱区间 `(start, end)`（char 索引，不含重叠）。
fn find_email_ranges(chars: &[char]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for (idx, &c) in chars.iter().enumerate() {
        if c != '@' {
            continue;
        }
        let mut start = idx;
        while start > 0 && is_email_char(chars[start - 1]) {
            start -= 1;
        }
        let mut end = idx + 1;
        while end < chars.len() && is_email_char(chars[end]) {
            end += 1;
        }
        let domain: String = chars[idx + 1..end].iter().collect();
        // 本地部分非空且域名含点才算邮箱。
        if start < idx && domain.contains('.') {
            // 跳过与上一个区间重叠的命中。
            if let Some(&(_, previous_end)) = ranges.last() {
                if start < previous_end {
                    continue;
                }
            }
            ranges.push((start, end));
        }
    }
    ranges
}

/// 脱敏自由文本里的全部邮箱。
pub fn redact_emails_in_text(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let ranges = find_email_ranges(&chars);
    if ranges.is_empty() {
        return input.to_string();
    }
    let mut out = String::new();
    let mut cursor = 0usize;
    for (start, end) in ranges {
        if start > cursor {
            out.extend(chars[cursor..start].iter());
        }
        let email: String = chars[start..end].iter().collect();
        out.push_str(&redact_email(&email));
        cursor = end;
    }
    if cursor < chars.len() {
        out.extend(chars[cursor..].iter());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_key_detection() {
        assert!(is_sensitive_key("accessToken"));
        assert!(is_sensitive_key("Authorization"));
        assert!(is_sensitive_key("ANTHROPIC_AUTH_TOKEN"));
        assert!(is_sensitive_key("apiKey"));
        assert!(is_sensitive_key("api_key"));
        assert!(is_sensitive_key("password"));
        assert!(!is_sensitive_key("name"));
        assert!(!is_sensitive_key("status"));
    }

    #[test]
    fn sensitive_key_detection_identity_fields() {
        assert!(is_sensitive_key("emailAddress"));
        assert!(is_sensitive_key("displayName"));
        assert!(is_sensitive_key("organizationName"));
        assert!(is_sensitive_key("accountUuid"));
        assert!(is_sensitive_key("organizationUuid"));
    }

    #[test]
    fn redacts_nested_json_values() {
        let mut value = serde_json::json!({
            "name": "keep",
            "env": {
                "ANTHROPIC_AUTH_TOKEN": "sk-secret",
                "CUSTOM_KEEP": "1"
            },
            "items": [
                { "refreshToken": "abc", "id": "x" }
            ]
        });
        redact_json(&mut value);
        assert_eq!(value["name"], json!("keep"));
        assert_eq!(value["env"]["ANTHROPIC_AUTH_TOKEN"], json!("***"));
        assert_eq!(value["env"]["CUSTOM_KEEP"], json!("1"));
        assert_eq!(value["items"][0]["refreshToken"], json!("***"));
        assert_eq!(value["items"][0]["id"], json!("x"));
    }

    #[test]
    fn redact_json_redacts_email_inside_non_sensitive_string() {
        let mut value = serde_json::json!({
            "note": "contact john.doe@example.com now"
        });
        redact_json(&mut value);
        let note = value["note"].as_str().unwrap();
        assert!(!note.contains("john.doe"));
        assert!(note.contains("j***@example.com"));
    }

    #[test]
    fn redact_json_renames_project_path_keys() {
        let mut value = serde_json::json!({ "projects": {
            "C:\\Users\\alice\\repo": { "mcp": "1" }
        }});
        redact_json_for_user(&mut value, "alice");
        let projects = value["projects"].as_object().unwrap();
        assert!(projects.contains_key("C:\\Users\\<user>\\repo"));
        assert!(!projects.contains_key("C:\\Users\\alice\\repo"));
    }

    #[test]
    fn redact_text_masks_sk_ant_token() {
        let text = "token sk-ant-abcdef123456 end";
        let cleaned = redact_text(text, "alice");
        assert!(!cleaned.contains("sk-ant"));
        assert!(cleaned.contains("***"));
    }

    #[test]
    fn redact_text_masks_bearer_token() {
        let text = "Bearer abcdefghijklmnop";
        let cleaned = redact_text(text, "alice");
        assert!(!cleaned.contains("abcdefghijklmnop"));
        assert!(cleaned.contains("***"));
    }

    #[test]
    fn redact_text_masks_jwt() {
        let jwt = "eyJabcdefghijkl.eyJabcdefghijkl.eyJabcdefghijkl";
        let cleaned = redact_text(jwt, "alice");
        assert!(!cleaned.contains("eyJ"));
        assert!(cleaned.contains("***"));
    }

    #[test]
    fn redact_text_replaces_user_path() {
        let text = "file at C:\\Users\\alice\\repo\\config.json";
        let cleaned = redact_text(text, "alice");
        assert!(!cleaned.contains("\\alice\\"));
        assert!(cleaned.contains("\\Users\\<user>\\"));
    }

    #[test]
    fn redact_text_redacts_email() {
        let cleaned = redact_text("mail john@example.com", "alice");
        assert!(cleaned.contains("j***@example.com"));
    }

    #[test]
    fn redact_email_keeps_first_char_and_domain() {
        assert_eq!(redact_email("john@example.com"), "j***@example.com");
        assert_eq!(redact_email("a@b.co"), "a***@b.co");
        assert_eq!(redact_email("not-an-email"), "***");
    }

    #[test]
    fn redact_emails_in_free_text() {
        let text = "contact John at john.doe@example.com for details";
        let cleaned = redact_emails_in_text(text);
        assert!(!cleaned.contains("john.doe"));
        assert!(cleaned.contains("j***@example.com"));
        assert!(cleaned.starts_with("contact John at "));
    }

    #[test]
    fn text_without_emails_unchanged() {
        let text = "no email here, just logs 123";
        assert_eq!(redact_emails_in_text(text), text);
    }
}
