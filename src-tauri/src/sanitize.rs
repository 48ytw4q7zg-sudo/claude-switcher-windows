//! F-7：诊断包脱敏。
//!
//! 纯函数，不依赖网络/真实文件：
//! - JSON：键名含 `token` / `authorization` / `anthropic_` / `apikey` / `api_key` /
//!   `password`（大小写不敏感）的，值整体替换为 `"***"`；其余递归处理。
//! - 邮箱：保留首字符与域名，中间替换（`john@example.com` → `j***@example.com`）。
//! - 自由文本（日志）：扫描并脱敏其中的邮箱地址。

use serde_json::{json, Value};

/// 命中即视为敏感键的子串（比较前键名转小写）。
pub const SENSITIVE_KEY_MARKERS: [&str; 6] = [
    "token",
    "authorization",
    "anthropic_",
    "apikey",
    "api_key",
    "password",
];

/// 判断一个键名是否为敏感键。
pub fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    SENSITIVE_KEY_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// 原地脱敏一个 JSON 值（递归）。
pub fn redact_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *child = json!("***");
                } else {
                    redact_json(child);
                }
            }
        }
        Value::Array(items) => {
            for child in items.iter_mut() {
                redact_json(child);
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
        assert!(!is_sensitive_key("email"));
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
