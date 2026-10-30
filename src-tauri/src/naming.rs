//! Windows 文件名 / 账号名合法化（F-2 开始菜单快捷方式等复用）。
//!
//! 把任意账号名转换为可安全用作 Windows 文件名的形式，规则与 [`crate::keep`]
//! 里校验路径分量的保留设备名规则保持一致，抽到这里作为公共函数。

/// Windows 保留设备名（27 个，含上标 COM/LPT 形态）。
///
/// 判断保留名时按第一个 `.` 前的整段比较，所以 `NUL.txt` 的设备名仍是 `NUL`。
/// `CONIN$` / `CONOUT$` 的 `$` 是名字的一部分，必须完整保留。
pub const RESERVED_DEVICE_NAMES: [&str; 27] = [
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM1", "COM2", "COM3", "COM4", "COM5",
    "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
    "LPT6", "LPT7", "LPT8", "LPT9",
];

/// 单个文件名分量是否为 Windows 保留设备名（大小写不敏感，含带扩展名形态）。
pub fn is_reserved_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    RESERVED_DEVICE_NAMES.contains(&stem.to_uppercase().as_str())
}

/// 合法化后的文件名最大字符数（Windows 单分量上限 255，这里留余量）。
const MAX_FILE_NAME_CHARS: usize = 100;

/// 空名时的兜底文件名。
const FALLBACK_FILE_NAME: &str = "account";

/// 把任意账号名合法化为可安全用于文件名 / 快捷方式名的形式。
///
/// 处理顺序：
/// 1. Windows 非法字符 `\ / : * ? " < > |` 与控制字符替换为 `_`；
/// 2. 去掉开头空格、结尾的点或空格（Windows 会静默剥离尾点/尾空格）；
/// 3. 结果为空 → 兜底名 `account`；
/// 4. 命中保留设备名 → 追加 `_` 后缀避开（如 `CON` → `CON_`）；
/// 5. 超过 100 字符 → 截断（按字符而非字节，避免切坏多字节字符）。
pub fn sanitize_file_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || (c as u32) < 32 {
            out.push('_');
        } else {
            out.push(c);
        }
    }
    // 去掉开头空格、结尾的点或空格。
    out = out.trim_start().to_string();
    while out.ends_with('.') || out.ends_with(' ') {
        out.pop();
    }
    if out.is_empty() {
        return FALLBACK_FILE_NAME.to_string();
    }
    if is_reserved_device_name(&out) {
        out.push('_');
        return out;
    }
    if out.chars().count() > MAX_FILE_NAME_CHARS {
        return out.chars().take(MAX_FILE_NAME_CHARS).collect();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_illegal_characters() {
        assert_eq!(sanitize_file_name("a/b\\c:d"), "a_b_c_d");
        assert_eq!(sanitize_file_name("what*?\"<>|"), "what______");
    }

    #[test]
    fn strips_leading_spaces_and_trailing_dots_spaces() {
        assert_eq!(sanitize_file_name("   name..  "), "name");
        assert_eq!(sanitize_file_name("name . "), "name");
    }

    #[test]
    fn empty_or_blank_falls_back() {
        assert_eq!(sanitize_file_name("   "), "account");
        assert_eq!(sanitize_file_name(""), "account");
    }

    #[test]
    fn reserved_names_get_suffix() {
        assert_eq!(sanitize_file_name("CON"), "CON_");
        assert_eq!(sanitize_file_name("nul.txt"), "nul.txt_");
        assert_eq!(sanitize_file_name("com1"), "com1_");
    }

    #[test]
    fn normal_names_are_unchanged() {
        assert_eq!(sanitize_file_name("美国号-1"), "美国号-1");
    }

    #[test]
    fn reserved_detection_handles_case_and_extension() {
        assert!(is_reserved_device_name("NUL"));
        assert!(is_reserved_device_name("aux.log"));
        assert!(!is_reserved_device_name("null"));
    }
}
