//! JSON / YAML 文件读取与原子写入。
//!
//! Windows 用户常用记事本或 PowerShell 5.1 编辑 `settings.json`，很容易把文件
//! 存成带 UTF-8 BOM 甚至 UTF-16LE。`read_to_string` 遇到这两种编码会直接失败，
//! 进而让 `get_status` 整体报错、界面打不开。因此所有文本读取都走
//! [`read_text_lossy_bom`]：识别并剥离 BOM，UTF-16 也转成 UTF-8。

use std::path::{Path, PathBuf};

use serde_json::Value;

/// 读取文本文件，自动处理 BOM 与 UTF-16LE/BE。
///
/// - UTF-8 BOM（`EF BB BF`）→ 剥离
/// - UTF-16LE BOM（`FF FE`）→ 转 UTF-8
/// - UTF-16BE BOM（`FE FF`）→ 转 UTF-8
/// - 无 BOM 的 UTF-16（记事本旧版默认）→ 按字节模式启发式判断后转换
pub fn read_text_lossy_bom(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    Ok(decode_text(&bytes))
}

/// 按 BOM / 字节特征解码文本为 UTF-8 String（永不失败，坏字节用 U+FFFD 替换）。
pub fn decode_text(bytes: &[u8]) -> String {
    // UTF-8 BOM
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(&bytes[3..]).to_string();
    }
    // UTF-16LE BOM
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16(&bytes[2..], true);
    }
    // UTF-16BE BOM
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16(&bytes[2..], false);
    }
    // 无 BOM 的 UTF-16：记事本保存的 "Unicode" 格式。
    // 启发式——JSON/YAML 的 ASCII 字符在 UTF-16LE 下呈现为 `XX 00 XX 00`。
    if bytes.len() >= 4 && looks_like_utf16(bytes) {
        return decode_utf16(bytes, true);
    }
    String::from_utf8_lossy(bytes).to_string()
}

fn looks_like_utf16(bytes: &[u8]) -> bool {
    // 前 64 字节里，奇数位大量为 0、偶数位几乎不为 0 → UTF-16LE。
    let sample = &bytes[..bytes.len().min(64)];
    let mut odd_zero = 0usize;
    let mut even_nonzero = 0usize;
    for (i, b) in sample.iter().enumerate() {
        if i % 2 == 1 && *b == 0 {
            odd_zero += 1;
        }
        if i % 2 == 0 && *b != 0 {
            even_nonzero += 1;
        }
    }
    let pairs = sample.len() / 2;
    pairs > 0 && odd_zero * 10 >= pairs * 9 && even_nonzero * 10 >= pairs * 9
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> String {
    let (units, _) = bytes.as_chunks::<2>();
    let units: Vec<u16> = units
        .iter()
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

/// 读取 JSON 文件；不存在返回 Ok(None)，解析失败返回 Err。
pub fn read_json_optional(path: PathBuf) -> Result<Option<Value>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = read_text_lossy_bom(&path)?;
    let trimmed = raw.trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    serde_json::from_str(trimmed)
        .map(Some)
        .map_err(|e| format!("JSON 解析失败（{}）: {e}", path.display()))
}

/// 读取 YAML 文件；不存在返回 Ok(None)。
pub fn read_yaml_optional(path: PathBuf) -> Result<Option<Value>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = read_text_lossy_bom(&path)?;
    if raw.trim().is_empty() {
        return Ok(None);
    }
    // Clash Verge 的配置可能是多文档 YAML（含 `---`），只取第一个文档，
    // 避免单文档解析器把整份配置判为失败。
    let mut documents = serde_yaml::Deserializer::from_str(&raw);
    let first = documents.next().map(serde::de::Deserialize::deserialize);
    first
        .transpose()
        .map_err(|e| format!("YAML 解析失败（{}）: {e}", path.display()))
}

/// 原子写入 pretty JSON（临时文件 + rename 覆盖，绝不写半截）。
/// 不再对 Claude Code 自己的文件逐个 icacls（权限继承用户目录，官方即如此）。
pub fn write_json_pretty(path: PathBuf, value: &Value) -> Result<(), String> {
    let raw = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    crate::fsx::write_atomically(&path, &format!("{raw}\n")).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_plain_utf8() {
        assert_eq!(decode_text(br#"{"a":1}"#), r#"{"a":1}"#);
    }

    #[test]
    fn decode_strips_utf8_bom() {
        let mut v = vec![0xEF, 0xBB, 0xBF];
        v.extend_from_slice(br#"{"a":1}"#);
        assert_eq!(decode_text(&v), r#"{"a":1}"#);
    }

    #[test]
    fn decode_utf16le_with_bom() {
        let mut v = vec![0xFF, 0xFE];
        for u in "{".encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(decode_text(&v), "{");
    }

    #[test]
    fn decode_utf16le_without_bom() {
        // 记事本保存的 "Unicode" 格式：无 BOM。
        let mut v = Vec::new();
        for u in "{}".encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(decode_text(&v), "{}");
    }

    #[test]
    fn decode_utf16be_with_bom() {
        let mut v = vec![0xFE, 0xFF];
        for u in "{}".encode_utf16() {
            v.extend_from_slice(&u.to_be_bytes());
        }
        assert_eq!(decode_text(&v), "{}");
    }

    #[test]
    fn decode_chinese_utf16le() {
        let mut v = vec![0xFF, 0xFE];
        for u in "账号".encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(decode_text(&v), "账号");
    }

    /// 记事本改过的 settings.json（带 BOM）必须能正常解析。
    #[test]
    fn read_json_optional_handles_bom_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let mut content = vec![0xEF, 0xBB, 0xBF];
        content.extend_from_slice(br#"{"env":{"TZ":"UTC"}}"#);
        std::fs::write(&path, content).unwrap();
        let parsed = read_json_optional(path).unwrap().unwrap();
        assert_eq!(parsed["env"]["TZ"], "UTC");
    }

    #[test]
    fn read_yaml_optional_takes_first_document() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            "external-controller: :9097\n---\nexternal-controller: :9999\n",
        )
        .unwrap();
        let parsed = read_yaml_optional(path).unwrap().unwrap();
        assert_eq!(parsed["external-controller"], ":9097");
    }
}
