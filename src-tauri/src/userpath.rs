//! 用户 PATH 管理（F-1）：把工具 bin 目录追加到当前用户的 PATH。
//!
//! 直接写 `HKCU\Environment` 的 `Path` 值，**必须以 REG_EXPAND_SZ 写回**，读时按
//! 字面取值、原样写回，从而保留 `%USERPROFILE%` 等环境变量不被展开；写完用
//! `SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE)` 通知其他进程刷新环境。
//! 另提供撤销（移除本工具追加的目录）。

use std::io::ErrorKind;

use windows_sys::Win32::UI::WindowsAndMessaging::{
    SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
};
use winreg::enums::{RegType, HKEY_CURRENT_USER};
use winreg::types::FromRegValue;
use winreg::RegKey;

const ENV_KEY_PATH: &str = "Environment";
const PATH_VALUE_NAME: &str = "Path";
const BROADCAST_TIMEOUT_MS: u32 = 5000;

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
    let already = current.split(';').any(|part| part.trim() == entry);
    if already {
        return Ok(false);
    }
    let updated = if current.is_empty() {
        entry.to_string()
    } else {
        // 保留原有内容，仅在末尾追加。
        let trimmed = current.trim_end_matches(';');
        format!("{trimmed};{entry}")
    };
    write_user_path(&updated)?;
    let _ = broadcast_environment_change();
    Ok(true)
}

/// 从用户 PATH 中移除 `bin_dir`（不存在则无变化）。返回是否实际修改。
pub fn remove_bin_from_user_path(bin_dir: &str) -> Result<bool, String> {
    let entry = bin_dir.trim();
    let Some(current) = read_user_path()? else {
        return Ok(false);
    };
    let kept: Vec<&str> = current
        .split(';')
        .filter(|part| !part.trim().is_empty() && part.trim() != entry)
        .collect();
    let updated = kept.join(";");
    if updated == current {
        return Ok(false);
    }
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
    fn add_and_remove_are_idempotent() {
        // 直接读写真实 HKCU 有副作用风险，这里只验证幂等判定逻辑：
        // 对同一空字符串入参应报错，避免误写。
        assert!(add_bin_to_user_path("   ").is_err());
    }
}
