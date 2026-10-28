//! 切换前 live 身份对账 + 自动收养。
//!
//! 切换 / 新号登录前，需要先确认「此刻 live 登录的到底是谁」，再决定把 live
//! 状态回写到哪个账号。三种结果：
//! - [`LiveIdentity::Current`]：live 就是当前账号 → 原逻辑刷新快照；
//! - [`LiveIdentity::Other`]：live 是另一个已登记账号（用户手动换了号）→
//!   回写到那个账号并提示；
//! - [`LiveIdentity::Unknown`]：live 是从未登记的账号 → 用 live 材料自动收养。
//!
//! live 缺字段（读不到 ~/.claude.json / accountUuid）时**只提示、不中断切换**。

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::accounts::LiveSnapshot;
use crate::store::{self, StoredProfile};

/// live 身份对账结果。
#[derive(Debug, PartialEq, Eq)]
pub enum LiveIdentity {
    /// live 就是当前账号（`current_profile_id` 对应账号）。
    Current,
    /// live 是另一个已登记账号（含其 profile id）。
    Other(String),
    /// live 是从未登记的账号（含其 accountUuid）。
    Unknown(String),
}

/// 依据 live accountUuid 与当前账号、已登记账号列表，判定 live 身份。
///
/// 取不到 live uuid 时（live 缺字段）返回 `None`，调用方据此走
/// 「不中断、仅提示」路径。
pub fn classify_live_identity(
    live_uuid: Option<&str>,
    current_id: Option<&str>,
    profiles: &[StoredProfile],
) -> Option<LiveIdentity> {
    let live_uuid = live_uuid?;
    let matched = profiles
        .iter()
        .find(|p| p.meta.account_uuid.as_deref() == Some(live_uuid));
    match matched {
        Some(p) if Some(p.id.as_str()) == current_id => Some(LiveIdentity::Current),
        Some(p) => Some(LiveIdentity::Other(p.id.clone())),
        None => Some(LiveIdentity::Unknown(live_uuid.to_string())),
    }
}

/// 自动收养的账号名：「自动收养-<邮箱或 uuid 前 8>-<MMdd-HHmm>」。
///
/// 邮箱优先（可读性好）；没有邮箱时用 uuid 前 8 位。时间戳用 UTC 渲染
/// （与 store 里其它时间字段一致；显示层按本地时区呈现）。
pub fn auto_adopt_profile_name(email: Option<&str>, uuid: &str, now: DateTime<Utc>) -> String {
    let label = email
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| uuid.chars().take(8).collect::<String>());
    let stamp = now.format("%m%d-%H%M").to_string();
    format!("自动收养-{label}-{stamp}")
}

/// 对账并把结果落进 store（供切换 / 新号流程调用）。
///
/// 行为：
/// - Current：把 live 回写到当前账号（刷新快照）；
/// - Other(id)：把 live 回写到那个账号，把 `current_profile_id` 指向它，
///   提示「检测到手动换号」；
/// - Unknown(uuid)：用 live 材料自动新建账号，`current_profile_id` 指向它，
///   提示可重命名；
/// - 无法判定（缺材料 / 缺 uuid）：不中断，仅返回提示。
pub fn reconcile_live_into_store(
    store_data: &mut store::Store,
    snapshot: &LiveSnapshot,
    now: DateTime<Utc>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let (claude_json, settings_json, keychain_password) = snapshot;

    let Some(claude_json) = claude_json else {
        warnings.push("当前缺少 ~/.claude.json，已跳过 live 身份对账（不中断切换）".to_string());
        return warnings;
    };

    let live_uuid = lookup_string(claude_json, &["oauthAccount", "accountUuid"]);
    let identity = classify_live_identity(
        live_uuid,
        store_data.current_profile_id.as_deref(),
        &store_data.profiles,
    );

    let Some(identity) = identity else {
        warnings.push(
            "无法从 live ~/.claude.json 读取 accountUuid，已跳过身份对账（不中断切换）".to_string(),
        );
        return warnings;
    };

    let email = lookup_string(claude_json, &["oauthAccount", "email"]);

    match identity {
        LiveIdentity::Current => {
            if let Some(current_id) = store_data.current_profile_id.clone() {
                if let Some(profile) = store_data.profiles.iter_mut().find(|p| p.id == current_id) {
                    write_live_into_profile(
                        profile,
                        claude_json,
                        settings_json,
                        keychain_password,
                        now,
                    );
                }
            }
        }
        LiveIdentity::Other(other_id) => {
            let other_name = store_data
                .profiles
                .iter()
                .find(|p| p.id == other_id)
                .map(|p| p.name.clone());
            if let Some(profile) = store_data.profiles.iter_mut().find(|p| p.id == other_id) {
                write_live_into_profile(
                    profile,
                    claude_json,
                    settings_json,
                    keychain_password,
                    now,
                );
            }
            store_data.current_profile_id = Some(other_id.clone());
            warnings.push(format!(
                "检测到手动换号：live 账号是已登记的「{}」，已把 live 状态回写到该账号",
                other_name.as_deref().unwrap_or("?")
            ));
        }
        LiveIdentity::Unknown(uuid) => {
            let name = auto_adopt_profile_name(email, &uuid, now);
            let profile = build_adopted_profile(
                name.clone(),
                claude_json.clone(),
                settings_json.clone(),
                keychain_password.clone(),
                now,
            );
            let new_id = profile.id.clone();
            store_data.profiles.push(profile);
            store_data.current_profile_id = Some(new_id);
            warnings.push(format!(
                "自动收养：live 账号（{}）此前未登记，已自动新建账号「{}」，可在列表中重命名",
                email.unwrap_or(&uuid),
                name
            ));
        }
    }

    warnings
}

fn lookup_string<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = value;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_str()
}

fn write_live_into_profile(
    profile: &mut StoredProfile,
    claude_json: &Value,
    settings_json: &Option<Value>,
    keychain_password: &Option<String>,
    now: DateTime<Utc>,
) {
    profile.meta = crate::usage::extract_meta(Some(claude_json), keychain_password.as_deref());
    profile.claude_json = claude_json.clone();
    profile.settings_json = settings_json.clone();
    profile.keychain_password = keychain_password.clone();
    profile.updated_at = now;
}

fn build_adopted_profile(
    name: String,
    claude_json: Value,
    settings_json: Option<Value>,
    keychain_password: Option<String>,
    now: DateTime<Utc>,
) -> StoredProfile {
    StoredProfile {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        notes: Some("自动收养，可重命名".to_string()),
        created_at: now,
        updated_at: now,
        last_switched_at: None,
        meta: crate::usage::extract_meta(Some(&claude_json), keychain_password.as_deref()),
        claude_json,
        settings_json,
        encrypted_auth_settings: None,
        keychain_password,
        last_used_percent: None,
        clash: None,
        runtime: Some(store::ProfileRuntimeBinding::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{ProfileMeta, StoredProfile};

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-28T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn profile_with(id: &str, uuid: Option<&str>) -> StoredProfile {
        StoredProfile {
            id: id.into(),
            name: format!("Name {id}"),
            notes: None,
            created_at: now(),
            updated_at: now(),
            last_switched_at: None,
            claude_json: Value::Null,
            settings_json: None,
            encrypted_auth_settings: None,
            keychain_password: None,
            meta: ProfileMeta {
                account_uuid: uuid.map(str::to_string),
                ..ProfileMeta::default()
            },
            last_used_percent: None,
            clash: None,
            runtime: None,
        }
    }

    #[test]
    fn classify_table() {
        let profiles = vec![
            profile_with("p1", Some("uuid-1")),
            profile_with("p2", Some("uuid-2")),
        ];
        // live = 当前账号。
        assert_eq!(
            classify_live_identity(Some("uuid-1"), Some("p1"), &profiles),
            Some(LiveIdentity::Current)
        );
        // live = 另一个已登记账号。
        assert_eq!(
            classify_live_identity(Some("uuid-2"), Some("p1"), &profiles),
            Some(LiveIdentity::Other("p2".into()))
        );
        // live = 未登记账号。
        assert_eq!(
            classify_live_identity(Some("uuid-x"), Some("p1"), &profiles),
            Some(LiveIdentity::Unknown("uuid-x".into()))
        );
        // 取不到 uuid → None（不中断）。
        assert_eq!(classify_live_identity(None, Some("p1"), &profiles), None);
    }

    #[test]
    fn auto_adopt_name_uses_email_when_present() {
        let name = auto_adopt_profile_name(Some("bob@example.com"), "uuid-12345678", now());
        assert_eq!(name, "自动收养-bob@example.com-1028-1000");
    }

    #[test]
    fn auto_adopt_name_falls_back_to_uuid_prefix() {
        let name = auto_adopt_profile_name(None, "abcd1234efgh", now());
        assert_eq!(name, "自动收养-abcd1234-1028-1000");
        // 空白邮箱也回退。
        let name = auto_adopt_profile_name(Some("   "), "abcd1234efgh", now());
        assert_eq!(name, "自动收养-abcd1234-1028-1000");
    }

    fn snapshot_with(uuid: &str, email: Option<&str>) -> LiveSnapshot {
        let mut oauth = serde_json::Map::new();
        oauth.insert("accountUuid".into(), Value::String(uuid.into()));
        if let Some(email) = email {
            oauth.insert("email".into(), Value::String(email.into()));
        }
        let claude = Value::Object(serde_json::Map::from_iter([(
            "oauthAccount".into(),
            Value::Object(oauth),
        )]));
        (Some(claude), None, Some("keychain".into()))
    }

    #[test]
    fn unknown_is_auto_adopted_and_current_points_to_it() {
        let mut store_data = store::Store::default();
        let snapshot = snapshot_with("new-uuid-1234", Some("new@example.com"));
        let warnings = reconcile_live_into_store(&mut store_data, &snapshot, now());
        assert_eq!(store_data.profiles.len(), 1, "应自动新建一个账号");
        let created = &store_data.profiles[0];
        assert_eq!(created.name, "自动收养-new@example.com-1028-1000");
        assert_eq!(created.notes.as_deref(), Some("自动收养，可重命名"));
        assert_eq!(
            store_data.current_profile_id.as_deref(),
            Some(created.id.as_str())
        );
        assert!(warnings.iter().any(|w| w.contains("自动收养")));
    }

    #[test]
    fn other_is_written_back_and_manual_switch_reported() {
        let mut store_data = store::Store::default();
        store_data.profiles.push(profile_with("p1", Some("uuid-1")));
        store_data.profiles.push(profile_with("p2", Some("uuid-2")));
        store_data.current_profile_id = Some("p1".into());
        let snapshot = snapshot_with("uuid-2", None);
        let warnings = reconcile_live_into_store(&mut store_data, &snapshot, now());
        // current 指向 p2，且 p2 已回写 live 凭据。
        assert_eq!(store_data.current_profile_id.as_deref(), Some("p2"));
        let p2 = store_data.profiles.iter().find(|p| p.id == "p2").unwrap();
        assert_eq!(p2.keychain_password.as_deref(), Some("keychain"));
        assert!(warnings.iter().any(|w| w.contains("检测到手动换号")));
    }

    #[test]
    fn current_refreshes_without_adding_profile() {
        let mut store_data = store::Store::default();
        store_data.profiles.push(profile_with("p1", Some("uuid-1")));
        store_data.current_profile_id = Some("p1".into());
        let snapshot = snapshot_with("uuid-1", None);
        let warnings = reconcile_live_into_store(&mut store_data, &snapshot, now());
        assert_eq!(store_data.profiles.len(), 1, "不应新增账号");
        let p1 = &store_data.profiles[0];
        assert_eq!(p1.keychain_password.as_deref(), Some("keychain"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn missing_claude_json_does_not_abort() {
        let mut store_data = store::Store::default();
        let snapshot = (None, None, None);
        let warnings = reconcile_live_into_store(&mut store_data, &snapshot, now());
        assert!(warnings.iter().any(|w| w.contains("~/.claude.json")));
        assert_eq!(store_data.profiles.len(), 0);
    }

    #[test]
    fn missing_uuid_does_not_abort() {
        // oauthAccount 存在但没有 accountUuid。
        let claude = serde_json::json!({ "oauthAccount": {} });
        let mut store_data = store::Store::default();
        let snapshot = (Some(claude), None, None);
        let warnings = reconcile_live_into_store(&mut store_data, &snapshot, now());
        assert!(warnings.iter().any(|w| w.contains("accountUuid")));
        assert_eq!(store_data.profiles.len(), 0);
    }
}
