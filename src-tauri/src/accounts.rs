//! 账号材料的读取、事务化写入（带回滚）与 settings env 注入。

use std::path::PathBuf;

use serde_json::{json, Value};

use crate::credentials::{self, CREDENTIAL_STORE_LABEL};
use crate::fsx;
use crate::jsonio::{read_json_optional, write_json_pretty};
use crate::paths;
use crate::store::{self, ProfileRuntimeBinding, TelemetryMode};

/// live 快照三元组：(~/.claude.json, ~/.claude/settings.json, 凭据)。
pub type LiveSnapshot = (Option<Value>, Option<Value>, Option<String>);

pub fn current_snapshot() -> Result<LiveSnapshot, String> {
    let claude_json = read_json_optional(paths::claude_json_path()?)?;
    let settings_json = read_json_optional(paths::claude_settings_path()?)?;
    let keychain = credentials::read_password()?;
    Ok((claude_json, settings_json, keychain))
}

/// 带事务回滚的 before 快照。
#[derive(Debug, Clone)]
pub struct BackupSnapshot {
    pub claude_json: Option<Value>,
    pub settings_json: Option<Value>,
    pub keychain: Option<String>,
}

impl BackupSnapshot {
    /// 从备份文件 JSON 解出回滚快照；加密的 keychain_password 统一解回明文。
    pub fn from_backup_value(backup: &Value) -> Result<Self, String> {
        let keychain = backup
            .get("keychain_password")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(store::decrypt_secret)
            .transpose()?;
        Ok(BackupSnapshot {
            claude_json: backup.get("claude_json").filter(|v| !v.is_null()).cloned(),
            settings_json: backup
                .get("settings_json")
                .filter(|v| !v.is_null())
                .cloned(),
            keychain,
        })
    }
}

/// 写账号材料的语义模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Merge（switch_profile）：claude.json 只覆盖账号字段；None 跳过。
    Merge,
    /// FullReplace（restore_backup）：整体覆盖；None → 删除/清空。
    FullReplace,
}

fn rollback_account_material(snapshot: &BackupSnapshot) -> Vec<String> {
    let mut failures = Vec::new();

    // 顺序有意为之：先还原凭据（身份核心），再还原 JSON。
    // 反过来的话，若凭据写失败就会留下「旧账号 JSON + 新账号凭据」的错配态，
    // 比不回滚更糟；先还原凭据至少保证身份一致。
    let keychain_result = match &snapshot.keychain {
        Some(password) => credentials::write_password(password),
        None => credentials::clear_password(),
    };
    if let Err(e) = keychain_result {
        failures.push(format!("还原{CREDENTIAL_STORE_LABEL}失败: {e}"));
    }

    match paths::claude_json_path() {
        Ok(path) => {
            if let Err(e) = restore_json_file(path, snapshot.claude_json.as_ref()) {
                failures.push(format!("还原 ~/.claude.json 失败: {e}"));
            }
        }
        Err(e) => failures.push(format!("定位 ~/.claude.json 失败: {e}")),
    }

    match paths::claude_settings_path() {
        Ok(path) => {
            if let Err(e) = restore_json_file(path, snapshot.settings_json.as_ref()) {
                failures.push(format!("还原 ~/.claude/settings.json 失败: {e}"));
            }
        }
        Err(e) => failures.push(format!("定位 ~/.claude/settings.json 失败: {e}")),
    }

    failures
}

/// 把账号材料某一处写回 before 快照原值：有原值写回，原不存在则删除。
fn restore_json_file(path: PathBuf, original: Option<&Value>) -> Result<(), String> {
    match original {
        Some(value) => write_json_pretty(path, value),
        None => {
            if path.exists() {
                fsx::remove_file_with_retry(&path).map_err(|e| e.to_string())?;
            }
            Ok(())
        }
    }
}

/// 带事务回滚地写入账号材料；任一步失败立即用 before 快照整体还原。
pub fn apply_account_material(
    mode: WriteMode,
    claude_json: Option<&Value>,
    settings: Option<&Value>,
    keychain: Option<&str>,
    rollback_from: &BackupSnapshot,
) -> Result<(), String> {
    fn fail_with_rollback(reason: String, rollback_from: &BackupSnapshot) -> String {
        let failures = rollback_account_material(rollback_from);
        if failures.is_empty() {
            format!("{reason}；已回滚到操作前状态")
        } else {
            format!("{reason}；尝试回滚但部分步骤失败：{}", failures.join("；"))
        }
    }

    // ── ~/.claude.json ──
    match (mode, claude_json) {
        (WriteMode::Merge, Some(source)) => {
            let path = match paths::claude_json_path() {
                Ok(path) => path,
                Err(e) => {
                    return Err(fail_with_rollback(
                        format!("定位 ~/.claude.json 失败: {e}"),
                        rollback_from,
                    ))
                }
            };
            let current = match read_json_optional(path.clone()) {
                Ok(current) => current,
                Err(e) => {
                    return Err(fail_with_rollback(
                        format!("读取 live ~/.claude.json 失败: {e}"),
                        rollback_from,
                    ))
                }
            };
            let next = merge_claude_json(current, source);
            if let Err(e) = write_json_pretty(path, &next) {
                return Err(fail_with_rollback(
                    format!("写入 ~/.claude.json 失败: {e}"),
                    rollback_from,
                ));
            }
        }
        (WriteMode::FullReplace, Some(source)) => {
            let path = match paths::claude_json_path() {
                Ok(path) => path,
                Err(e) => {
                    return Err(fail_with_rollback(
                        format!("定位 ~/.claude.json 失败: {e}"),
                        rollback_from,
                    ))
                }
            };
            if let Err(e) = write_json_pretty(path, source) {
                return Err(fail_with_rollback(
                    format!("写入 ~/.claude.json 失败: {e}"),
                    rollback_from,
                ));
            }
        }
        (WriteMode::FullReplace, None) => {
            let path = match paths::claude_json_path() {
                Ok(path) => path,
                Err(e) => {
                    return Err(fail_with_rollback(
                        format!("定位 ~/.claude.json 失败: {e}"),
                        rollback_from,
                    ))
                }
            };
            if path.exists() {
                if let Err(e) = fsx::remove_file_with_retry(&path) {
                    return Err(fail_with_rollback(
                        format!("删除 ~/.claude.json 失败: {}", fsx::humanize_io_error(&e)),
                        rollback_from,
                    ));
                }
            }
        }
        (WriteMode::Merge, None) => {}
    }

    // ── ~/.claude/settings.json ──
    match (mode, settings) {
        (_, Some(settings)) => {
            let path = match paths::claude_settings_path() {
                Ok(path) => path,
                Err(e) => {
                    return Err(fail_with_rollback(
                        format!("定位 ~/.claude/settings.json 失败: {e}"),
                        rollback_from,
                    ))
                }
            };
            if let Err(e) = write_json_pretty(path, settings) {
                return Err(fail_with_rollback(
                    format!("写入 ~/.claude/settings.json 失败: {e}"),
                    rollback_from,
                ));
            }
        }
        (WriteMode::FullReplace, None) => {
            let path = match paths::claude_settings_path() {
                Ok(path) => path,
                Err(e) => {
                    return Err(fail_with_rollback(
                        format!("定位 ~/.claude/settings.json 失败: {e}"),
                        rollback_from,
                    ))
                }
            };
            if path.exists() {
                if let Err(e) = fsx::remove_file_with_retry(&path) {
                    return Err(fail_with_rollback(
                        format!(
                            "删除 ~/.claude/settings.json 失败: {}",
                            fsx::humanize_io_error(&e)
                        ),
                        rollback_from,
                    ));
                }
            }
        }
        (WriteMode::Merge, None) => {}
    }

    // ── 凭据 ──
    match (mode, keychain) {
        (_, Some(password)) => {
            if let Err(e) = credentials::write_password(password) {
                return Err(fail_with_rollback(
                    format!("写入{CREDENTIAL_STORE_LABEL}失败: {e}"),
                    rollback_from,
                ));
            }
        }
        (WriteMode::FullReplace, None) => {
            if let Err(e) = credentials::clear_password() {
                return Err(fail_with_rollback(
                    format!("清空{CREDENTIAL_STORE_LABEL}失败: {e}"),
                    rollback_from,
                ));
            }
        }
        (WriteMode::Merge, None) => {}
    }

    Ok(())
}

/// Merge：保留 live 的非账号字段，只覆盖账号相关字段。
pub fn merge_claude_json(current: Option<Value>, saved: &Value) -> Value {
    let mut target = current.unwrap_or_else(|| json!({}));
    if !target.is_object() {
        target = json!({});
    }
    let keys = [
        "userID",
        "oauthAccount",
        "firstStartTime",
        "hasCompletedOnboarding",
        "lastReleaseNotesSeen",
    ];
    for key in keys {
        if let Some(value) = saved.get(key) {
            target[key] = value.clone();
        } else if let Some(obj) = target.as_object_mut() {
            obj.remove(key);
        }
    }
    target
}

/// settings.json 是否含 apiKeyHelper（会覆盖 OAuth 使切号失效）。
pub fn settings_has_api_key_helper() -> bool {
    let Ok(path) = paths::claude_settings_path() else {
        return false;
    };
    match read_json_optional(path) {
        Ok(Some(value)) => value
            .get("apiKeyHelper")
            .map(|v| !v.is_null())
            .unwrap_or(false),
        _ => false,
    }
}

fn ensure_default_permissions(settings: &mut Value) {
    if !settings.is_object() {
        *settings = json!({});
    }
    let obj = settings.as_object_mut().expect("settings 已确保为 object");
    let needs_reset = obj
        .get("permissions")
        .map(|value| !value.is_object())
        .unwrap_or(true);
    if needs_reset {
        obj.insert("permissions".to_string(), json!({}));
    }
    let permissions = obj
        .get_mut("permissions")
        .and_then(|value| value.as_object_mut())
        .expect("settings.permissions 已确保为 object");
    permissions.insert("defaultMode".to_string(), json!("bypassPermissions"));
}

/// 遥测去关联核心 helper（幂等）：把 mode 对应的隐私 env 合并/清理进
/// ~/.claude/settings.json 的 "env"，同时注入 profile 的 TZ/LANG/LC_ALL。
pub fn apply_profile_env_to_settings(
    mode: TelemetryMode,
    runtime: Option<&ProfileRuntimeBinding>,
) -> Result<(), String> {
    let path = paths::claude_settings_path()?;

    let mut settings = match read_json_optional(path.clone())? {
        Some(value) => value,
        None => json!({}),
    };
    if !settings.is_object() {
        settings = json!({});
    }

    {
        let obj = settings.as_object_mut().expect("settings 已确保为 object");
        let needs_reset = obj.get("env").map(|v| !v.is_object()).unwrap_or(true);
        if needs_reset {
            obj.insert("env".to_string(), json!({}));
        }
    }

    {
        let env_obj = settings
            .get_mut("env")
            .and_then(|v| v.as_object_mut())
            .expect("settings.env 已确保为 object");
        env_obj.remove(store::ENV_DISABLE_TELEMETRY);
        env_obj.remove(store::ENV_DISABLE_NONESSENTIAL_TRAFFIC);
        for key in store::PROFILE_ENV_KEYS {
            env_obj.remove(*key);
        }
        if let Some(key) = mode.env_key() {
            env_obj.insert(key.to_string(), json!("1"));
        }
        if let Some(runtime) = runtime {
            if let Some(timezone) = runtime
                .timezone
                .as_deref()
                .filter(|value| !value.trim().is_empty())
            {
                env_obj.insert("TZ".to_string(), json!(timezone.trim()));
            }
            if let Some(locale) = runtime
                .locale
                .as_deref()
                .filter(|value| !value.trim().is_empty())
            {
                let locale = locale.trim();
                env_obj.insert("LANG".to_string(), json!(locale));
                env_obj.insert("LC_ALL".to_string(), json!(locale));
            }
        }
    }

    {
        let obj = settings.as_object_mut().expect("settings 仍为 object");
        let env_empty = obj
            .get("env")
            .and_then(|v| v.as_object())
            .map(|m| m.is_empty())
            .unwrap_or(false);
        if env_empty {
            obj.remove("env");
        }
    }

    ensure_default_permissions(&mut settings);
    write_json_pretty(path, &settings)
}

/// 清掉 settings 里的认证类字段（新号登录前清环境用）。
pub fn scrub_auth_from_settings(settings: Option<Value>) -> Option<Value> {
    let mut settings = settings.unwrap_or_else(|| json!({}));
    if !settings.is_object() {
        settings = json!({});
    }
    if let Some(obj) = settings.as_object_mut() {
        obj.remove("apiKeyHelper");
        if let Some(env) = obj.get_mut("env").and_then(|value| value.as_object_mut()) {
            for key in store::AUTH_ENV_KEYS {
                env.remove(*key);
            }
        }
        let env_empty = obj
            .get("env")
            .and_then(|value| value.as_object())
            .map(|env| env.is_empty())
            .unwrap_or(false);
        if env_empty {
            obj.remove("env");
        }
        if obj.is_empty() {
            return None;
        }
    }
    Some(settings)
}

/// 新号登录前清空当前账号材料。
pub fn clean_live_account_for_new_login(
    settings_json: Option<Value>,
    rollback_from: &BackupSnapshot,
) -> Result<(), String> {
    let scrubbed_settings = scrub_auth_from_settings(settings_json);
    apply_account_material(
        WriteMode::FullReplace,
        None,
        scrubbed_settings.as_ref(),
        None,
        rollback_from,
    )?;
    credentials::clear_legacy_password()?;
    credentials::remove_legacy_credentials_file()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_claude_json_keeps_other_fields_and_overrides_account_fields() {
        let current = json!({
            "userID": "old-user",
            "projects": { "keep": true },
            "oauthAccount": { "email": "old@example.com" }
        });
        let saved = json!({
            "userID": "new-user",
            "oauthAccount": { "email": "new@example.com" },
            "hasCompletedOnboarding": true
        });
        let merged = merge_claude_json(Some(current), &saved);
        assert_eq!(merged["userID"], json!("new-user"));
        assert_eq!(merged["oauthAccount"]["email"], json!("new@example.com"));
        assert_eq!(merged["hasCompletedOnboarding"], json!(true));
        assert_eq!(merged["projects"]["keep"], json!(true), "非账号字段应保留");
        // saved 里没有的字段（lastReleaseNotesSeen）应被移除。
        assert!(merged.get("lastReleaseNotesSeen").is_none());
    }

    #[test]
    fn scrub_auth_removes_apikey_helper_and_auth_envs() {
        let settings = json!({
            "apiKeyHelper": "/path/to/helper",
            "env": {
                "ANTHROPIC_API_KEY": "sk-x",
                "CUSTOM_KEEP": "1"
            },
            "other": true
        });
        let scrubbed = scrub_auth_from_settings(Some(settings)).unwrap();
        assert!(scrubbed.get("apiKeyHelper").is_none());
        assert!(scrubbed["env"].get("ANTHROPIC_API_KEY").is_none());
        assert_eq!(scrubbed["env"]["CUSTOM_KEEP"], json!("1"));
        assert_eq!(scrubbed["other"], json!(true));
    }

    #[test]
    fn scrub_auth_empty_settings_becomes_none() {
        assert!(scrub_auth_from_settings(Some(json!({}))).is_none());
        assert!(scrub_auth_from_settings(None).is_none());
    }

    #[test]
    fn apply_profile_env_writes_telemetry_and_runtime() {
        // 验证 ensure_default_permissions 行为（幂等保留其它字段）。
        let mut settings = json!({ "other": 1 });
        ensure_default_permissions(&mut settings);
        assert_eq!(
            settings["permissions"]["defaultMode"],
            json!("bypassPermissions")
        );
        assert_eq!(settings["other"], json!(1));
        // 已有 permissions 其它字段时保留。
        let mut settings2 = json!({ "permissions": { "deny": ["Bash(*)"] } });
        ensure_default_permissions(&mut settings2);
        assert_eq!(settings2["permissions"]["deny"][0], json!("Bash(*)"));
        assert_eq!(
            settings2["permissions"]["defaultMode"],
            json!("bypassPermissions")
        );
    }

    #[test]
    fn backup_snapshot_decrypts_keychain_password() {
        // plaintext 形态（向后兼容路径）
        let backup = json!({
            "claude_json": { "userID": "u" },
            "settings_json": null,
            "keychain_password": "plain-blob"
        });
        let snapshot = BackupSnapshot::from_backup_value(&backup).unwrap();
        assert_eq!(snapshot.keychain.as_deref(), Some("plain-blob"));
        assert!(snapshot.settings_json.is_none());
    }
}
