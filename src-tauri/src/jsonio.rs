//! JSON / YAML 文件读取与原子写入。

use std::path::PathBuf;

use serde_json::Value;

/// 读取 JSON 文件；不存在返回 Ok(None)，解析失败返回 Err。
pub fn read_json_optional(path: PathBuf) -> Result<Option<Value>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|e| format!("JSON 解析失败: {e}"))
}

/// 读取 YAML 文件；不存在返回 Ok(None)。
pub fn read_yaml_optional(path: PathBuf) -> Result<Option<Value>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_yaml::from_str::<Value>(&raw)
        .map(Some)
        .map_err(|e| format!("YAML 解析失败: {e}"))
}

/// 原子写入 pretty JSON（临时文件 + rename 覆盖，绝不写半截）。
/// 不再对 Claude Code 自己的文件逐个 icacls（权限继承用户目录，官方即如此）。
pub fn write_json_pretty(path: PathBuf, value: &Value) -> Result<(), String> {
    let raw = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    crate::fsx::write_atomically(&path, &format!("{raw}\n")).map_err(|e| e.to_string())
}
