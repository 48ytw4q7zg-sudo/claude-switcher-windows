//! 用户 PATH 管理（F-1 / K-6）：把工具 bin 目录追加到当前用户的 PATH。
//!
//! 直接写 `HKCU\Environment` 的 `Path` 值，**必须以 REG_EXPAND_SZ 写回**，读时按
//! 字面取值、原样写回，从而保留 `%USERPROFILE%` 等环境变量不被展开；写完用
//! `SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE)` 通知其他进程刷新环境。
//!
//! K-6 修正：
//! - 去重比较走归一化（trim + 去尾反斜杠 + 小写），大小写/尾反斜杠不再误判成两项；
//! - 没有任何条目被移除时不写注册表、不广播，空段（`a;;b`）原样保留；
//! - 修改前把原值备份到 `~/.claude-switcher/path-backup.txt`；
//! - 增删判定抽成纯函数，可在不碰真实注册表的情况下做真实单测。

use std::io::ErrorKind;

use windows_sys::Win32::UI::WindowsAndMessaging::{
    SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
};
use winreg::enums::{RegType, HKEY_CURRENT_USER};
use winreg::types::FromRegValue;
use winreg::RegKey;

use crate::fsx;

const ENV_KEY_PATH: &str = "Environment";
const PATH_VALUE_NAME: &str = "Path";
const BROADCAST_TIMEOUT_MS: u32 = 5000;
const BACKUP_DIR_NAME: &str = ".claude-switcher";
const BACKUP_FILE_NAME: &str = "path-backup.txt";

/// 归一化一个 PATH 条目用于比较：去首尾空白、去尾反斜杠、转 ASCII 小写。
/// 这样 `C:\Tools\bin` 与 `c:\tools\bin\` 会被视为同一项。
fn normalize_entry(part: &str) -> String {
    part.trim().trim_end_matches('\\').to_ascii_lowercase()
}

/// 纯函数：把 `entry` 追加到 `current`。
/// 已存在（归一化后相等）→ 返回 `None`（无需修改）；否则返回新的 PATH 字符串。
fn add_to_path(current: &str, entry: &str) -> Option<String> {
    let want = normalize_entry(entry);
    if current.split(';').any(|part| normalize_entry(part) == want) {
        return None;
    }
    let entry = entry.trim();
    Some(if current.trim().is_empty() {
        entry.to_string()
    } else {
        // 保留原有内容（含空段），仅在末尾追加。
        format!("{};{entry}", current.trim_end_matches(';'))
    })
}

/// 纯函数：从 `current` 移除 `entry`。
/// 没有任何条目被移除 → 返回 `None`（保留空段、不写注册表）；否则返回新字符串。
fn remove_from_path(current: &str, entry: &str) -> Option<String> {
    let want = normalize_entry(entry);
    let mut changed = false;
    let kept: Vec<&str> = current
        .split(';')
        .filter(|part| {
            if normalize_entry(part) == want {
                changed = true;
                false
            } else {
                true
            }
        })
        .collect();
    if !changed {
        return None;
    }
    Some(kept.join(";"))
}

/// 构造 REG_EXPAND_SZ 原始值：UTF-16LE（含结尾 null），类型标记为 REG_EXPAND_SZ。
fn expand_sz_value(text: &str) -> winreg::RegValue {
    let mut bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    // 注册表字符串要求以 null 结尾。
    bytes.extend_from_slice(&0u16.to_le_bytes());
    winreg::RegValue {
        bytes,
        vtype: RegType::REG_EXPAND_SZ,
    }
}

/// 读取 HKCU\Environment\Path 的字面内容（不展开变量）；值不存在 → None。
fn read_user_path() -> Result<Option<String>, String> {
    let env = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(ENV_KEY_PATH)
        .map_err(|e| format!("打开 HKCU\\Environment 失败: {e}"))?;
    match env.get_raw_value(PATH_VALUE_NAME) {
        Ok(raw) => Ok(Some(
            String::from_reg_value(&raw).map_err(|e| format!("解析用户 PATH 失败: {e}"))?,
        )),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("读取用户 PATH 失败: {e}")),
    }
}

/// 以 REG_EXPAND_SZ 写回用户 PATH（create_subkey 保证可写）。
fn write_user_path(text: &str) -> Result<(), String> {
    let (env, _) = RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey(ENV_KEY_PATH)
        .map_err(|e| format!("创建/打开 HKCU\\Environment 失败: {e}"))?;
    env.set_raw_value(PATH_VALUE_NAME, &expand_sz_value(text))
        .map_err(|e| format!("写入用户 PATH 失败: {e}"))
}

/// 修改前把原始 PATH 备份到 `~/.claude-switcher/path-backup.txt`。
/// 已存在备份时保留最早的一份；拿不到 home 目录或备份失败不阻断主流程。
fn backup_user_path(original: &str) -> Result<(), String> {
    let Some(home) = dirs::home_dir() else {
        return Ok(());
    };
    let backup = home.join(BACKUP_DIR_NAME).join(BACKUP_FILE_NAME);
    if backup.exists() {
        return Ok(());
    }
    fsx::write_atomically(&backup, original).map_err(|e| format!("备份用户 PATH 失败: {e}"))
}

/// 广播 WM_SETTINGCHANGE，让 Explorer / 新进程感知环境变量变化。
/// 失败不阻断（PATH 已写入，新开启的进程仍能读到），仅返回是否成功。
fn broadcast_environment_change() -> bool {
    // lParam 指向宽字符串 "Environment"。
    let mut wide: Vec<u16> = "Environment".encode_utf16().collect();
    wide.push(0);
    let mut result: usize = 0;
    let lresult = unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            wide.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            BROADCAST_TIMEOUT_MS,
            &mut result,
        )
    };
    lresult != 0
}

/// 把 `bin_dir` 追加到用户 PATH（已存在则幂等跳过）。返回是否实际修改。
pub fn add_bin_to_user_path(bin_dir: &str) -> Result<bool, String> {
    let entry = bin_dir.trim();
    if entry.is_empty() {
        return Err("要写入 PATH 的目录为空".to_string());
    }
    let current = read_user_path()?.unwrap_or_default();
    let Some(updated) = add_to_path(&current, entry) else {
        return Ok(false);
    };
    backup_user_path(&current)?;
    write_user_path(&updated)?;
    let _ = broadcast_environment_change();
    Ok(true)
}

/// 从用户 PATH 中移除 `bin_dir`（不存在则无变化）。返回是否实际修改。
pub fn remove_bin_from_user_path(bin_dir: &str) -> Result<bool, String> {
    let entry = bin_dir.trim();
    if entry.is_empty() {
        return Err("要从 PATH 移除的目录为空".to_string());
    }
    let current = read_user_path()?.unwrap_or_default();
    let Some(updated) = remove_from_path(&current, entry) else {
        return Ok(false);
    };
    backup_user_path(&current)?;
    write_user_path(&updated)?;
    let _ = broadcast_environment_change();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_sz_value_is_utf16le_with_null_and_correct_type() {
        let value = expand_sz_value("%USERPROFILE%\\bin");
        assert_eq!(value.vtype, RegType::REG_EXPAND_SZ);
        // 17 个字符（"%USERPROFILE%\bin"）+ 1 个 null = 18 个 u16 = 36 字节。
        assert_eq!(value.bytes.len(), 36);
        // 末尾两个字节为小端 0。
        assert_eq!(&value.bytes[value.bytes.len() - 2..], &[0, 0]);
    }

    #[test]
    fn add_rejects_empty_entry() {
        assert!(add_bin_to_user_path("   ").is_err());
    }

    #[test]
    fn add_dedup_is_case_and_trailing_slash_insensitive() {
        // 已存在的项仅大小写/尾反斜杠不同 → 不产生修改。
        assert_eq!(add_to_path("C:\\Tools\\bin", "c:\\tools\\bin\\"), None);
        // 全新项 → 追加。
        assert_eq!(
            add_to_path("C:\\Tools\\bin", "D:\\Other"),
            Some("C:\\Tools\\bin;D:\\Other".to_string())
        );
    }

    #[test]
    fn add_to_empty_current_returns_entry_only() {
        assert_eq!(add_to_path("", "C:\\bin"), Some("C:\\bin".to_string()));
        assert_eq!(add_to_path("   ", "C:\\bin"), Some("C:\\bin".to_string()));
    }

    #[test]
    fn duplicate_add_returns_none() {
        assert_eq!(add_to_path("a;b;c", "b"), None);
    }

    #[test]
    fn remove_is_case_insensitive() {
        assert_eq!(remove_from_path("A;B;C", "a"), Some("B;C".to_string()));
    }

    #[test]
    fn remove_without_match_returns_none_and_keeps_empty_segments() {
        // 没有要移除的项 → None，且空段不被改动。
        assert_eq!(remove_from_path("a;;b", "x"), None);
        assert_eq!(remove_from_path("a;;b;", "x"), None);
    }

    #[test]
    fn remove_preserves_empty_segments_when_another_entry_removed() {
        assert_eq!(remove_from_path("a;;b", "a"), Some(";b".to_string()));
    }

    #[test]
    fn add_then_remove_restores_original() {
        let original = "C:\\one;D:\\two";
        let added = add_to_path(original, "E:\\three").expect("should add");
        let restored = remove_from_path(&added, "E:\\three").expect("should remove");
        assert_eq!(restored, original);
    }

    #[test]
    fn normalize_entry_handles_case_slash_and_whitespace() {
        assert_eq!(normalize_entry("  C:\\X\\ "), "c:\\x");
        assert_eq!(normalize_entry("c:\\x\\"), "c:\\x");
    }
}
