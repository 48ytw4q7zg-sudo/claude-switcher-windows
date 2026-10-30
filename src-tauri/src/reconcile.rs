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

/// 在 `profile.claude_json` 里按路径取字符串叶子值。
fn profile_nested_str<'a>(p: &'a StoredProfile, path: &[&str]) -> Option<&'a str> {
    let mut cur = &p.claude_json;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_str()
}

/// 某 profile 存的账号 uuid：优先 `meta.account_uuid`，回退 `claude_json.oauthAccount.accountUuid`。
///
/// 老账号（早期收养 / 迁移来的）可能 `meta.account_uuid` 为空，但 `claude_json` 里
/// 仍内嵌了 oauthAccount——对账必须回退读它，否则老账号会被误判成 Unknown、
/// 重复收养成第二个同名账号。
fn profile_account_uuid(p: &StoredProfile) -> Option<&str> {
    p.meta
        .account_uuid
        .as_deref()
        .or_else(|| profile_nested_str(p, &["oauthAccount", "accountUuid"]))
}

/// 某 profile 存的邮箱：优先 `meta.email`，回退 `claude_json.oauthAccount.email`。
fn profile_account_email(p: &StoredProfile) -> Option<&str> {
    p.meta
        .email
        .as_deref()
        .or_else(|| profile_nested_str(p, &["oauthAccount", "email"]))
}

/// 命中一个已登记 profile 后，按「它是不是 current」归到 Current / Other。
fn current_or_other(p: &StoredProfile, current_id: Option<&str>) -> LiveIdentity {
    if Some(p.id.as_str()) == current_id {
        LiveIdentity::Current
    } else {
        LiveIdentity::Other(p.id.clone())
    }
}

/// 依据 live accountUuid / email 与当前账号、已登记账号列表，判定 live 身份。
///
/// 匹配顺序：
/// 1. **uuid 精确匹配**：profile 的 `meta.account_uuid` 或
///    `claude_json.oauthAccount.accountUuid` 等于 live_uuid；
/// 2. **邮箱回退匹配**（仅当 uuid 没命中且 live_email 非空）：profile 的 `meta.email`
///    或 `claude_json.oauthAccount.email` 与 live_email 做**大小写不敏感**比较。
///
/// 邮箱回退是为老账号准备的：它们收养时 `meta.account_uuid` 可能没写进去，
/// 只靠 email 也能认出来，避免重复收养成第二个同名账号。
///
/// 两个标识都取不到 live 值时返回 `None`，调用方据此走「不中断、仅提示」路径；
/// 取到了 uuid 但都没命中 → `Unknown(uuid)`。
pub fn classify_live_identity(
    live_uuid: Option<&str>,
    live_email: Option<&str>,
    current_id: Option<&str>,
    profiles: &[StoredProfile],
) -> Option<LiveIdentity> {
    // 1) uuid 精确匹配（meta 与内嵌 claude_json 都查）。
    if let Some(uuid) = live_uuid {
        if let Some(p) = profiles
            .iter()
            .find(|p| profile_account_uuid(p) == Some(uuid))
        {
            return Some(current_or_other(p, current_id));
        }
    }

    // 2) uuid 没命中 → 邮箱大小写不敏感回退（trim 后再比）。
    // J-4①：邮箱回退只对「库里 meta.account_uuid 为空」的老账号生效。老账号即使内嵌
    // claude_json 里带 accountUuid，其 store 级 uuid 仍为空，应允许靠邮箱认亲；而带
    // meta uuid 的 profile 若 uuid 不匹配，绝不能再靠邮箱“认亲”，一律走 Unknown 收养。
    let live_email = live_email.map(str::trim).filter(|e| !e.is_empty());
    if let Some(email) = live_email {
        if let Some(p) = profiles.iter().find(|p| {
            p.meta.account_uuid.is_none()
                && profile_account_email(p)
                    .map(|e| e.eq_ignore_ascii_case(email))
                    .unwrap_or(false)
        }) {
            return Some(current_or_other(p, current_id));
        }
    }

    // 3) 都没命中：有 live uuid → Unknown；连 uuid 都读不到 → None（不中断）。
    live_uuid.map(|uuid| LiveIdentity::Unknown(uuid.to_string()))
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
/// - Unknown(uuid)：当 `auto_adopt_enabled` 为 true 时，用 live 材料自动新建账号，
///   `current_profile_id` 指向它，提示可重命名；为 false 时**只提示、不新建、不改
///   current_profile_id**，等用户手动处理；
/// - 无法判定（缺材料 / 缺 uuid）：不中断，仅返回提示。
pub fn reconcile_live_into_store(
    store_data: &mut store::Store,
    snapshot: &LiveSnapshot,
    auto_adopt_enabled: bool,
    now: DateTime<Utc>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let (claude_json, settings_json, keychain_password) = snapshot;

    let Some(claude_json) = claude_json else {
        warnings.push("当前缺少 ~/.claude.json，已跳过 live 身份对账（不中断切换）".to_string());
        return warnings;
    };

    let live_uuid = lookup_string(claude_json, &["oauthAccount", "accountUuid"]);
    let live_email = lookup_string(claude_json, &["oauthAccount", "email"]);
    let identity = classify_live_identity(
        live_uuid,
        live_email,
        store_data.current_profile_id.as_deref(),
        &store_data.profiles,
    );

    let Some(identity) = identity else {
        warnings.push(
            "无法从 live ~/.claude.json 读取 accountUuid，已跳过身份对账（不中断切换）".to_string(),
        );
        return warnings;
    };

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
            store_data.current_profile_id = Some(other_id);
            warnings.push(format!(
                "检测到手动换号：live 账号是已登记的「{}」，已把 live 状态回写到该账号",
                other_name.as_deref().unwrap_or("?")
            ));
        }
        LiveIdentity::Unknown(uuid) => {
            if !auto_adopt_enabled {
                warnings.push(format!(
                    "检测到未登记账号（{}），但自动收养已关闭，未自动新建，可手动处理",
                    live_email.unwrap_or(&uuid)
                ));
                return warnings;
            }
            let name = auto_adopt_profile_name(live_email, &uuid, now);
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
                live_email.unwrap_or(&uuid),
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

/// 把 live 快照回写到已登记 profile。
///
/// **绝不拿空凭据覆盖已存凭据**：live 读不到 keychain（`None`）或拿到空白串时，
/// `profile.keychain_password` 保持原值；只有 live 真给了一段非空白凭据才更新。
/// meta 提取时用的「生效凭据」也跟着这个规则走——live 有就用 live 的，没有就用
/// profile 已存的，保证 `has_keychain_credentials` / `subscription_type` 等字段
/// 不会因一次「没读到 keychain」的刷新被错误重置。
///
/// claude_json / settings_json / updated_at 仍照常整体刷新。
/// 从 keychain 凭据 blob 解析 `claudeAiOauth.expiresAt`（毫秒 epoch）。
///
/// 兼容嵌套 `{ "claudeAiOauth": { ... } }` 与扁平 `{ ... }` 两种形状
/// （与 [`crate::usage`] 里读取 accessToken 的处理一致）。
fn oauth_expires_at_ms(blob: &str) -> Option<u64> {
    let parsed: Value = serde_json::from_str(blob).ok()?;
    let oauth = parsed.get("claudeAiOauth").unwrap_or(&parsed);
    oauth.get("expiresAt").and_then(|v| v.as_u64())
}

fn write_live_into_profile(
    profile: &mut StoredProfile,
    claude_json: &Value,
    settings_json: &Option<Value>,
    keychain_password: &Option<String>,
    now: DateTime<Utc>,
) {
    // live 凭据是否真的可用：Some 且 trim 后非空。
    let live_cred_raw: Option<&str> = keychain_password
        .as_deref()
        .filter(|raw| !raw.trim().is_empty());

    // J-4③：能解析双方 claudeAiOauth.expiresAt（毫秒）时，live 比 stored 更旧说明
    // live 是更老的 token（陈旧快照），不覆盖已存凭据，按「没有 live 凭据」处理。
    let stale = match live_cred_raw {
        Some(live) => match (
            oauth_expires_at_ms(live),
            profile
                .keychain_password
                .as_deref()
                .and_then(oauth_expires_at_ms),
        ) {
            (Some(live_at), Some(stored_at)) => live_at < stored_at,
            _ => false,
        },
        None => false,
    };
    let live_cred = if stale { None } else { live_cred_raw };

    if let Some(cred) = live_cred {
        profile.keychain_password = Some(cred.to_string());
    }

    // meta 提取用生效凭据：live 有就用 live 的，否则沿用 profile 已存的。
    let effective_cred = live_cred.or(profile.keychain_password.as_deref());
    profile.meta = crate::usage::extract_meta(Some(claude_json), effective_cred);
    profile.claude_json = claude_json.clone();
    // J-4②：live 没有 settings（None）时不覆盖已存 settings，只在 live 真给了值时更新。
    if let Some(settings) = settings_json {
        profile.settings_json = Some(settings.clone());
    }
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

    /// 构造一个最小已登记 profile；需要 email / 内嵌 claude_json / keychain 时
    /// 在返回值上原地改字段即可。
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
        // live = 当前账号（uuid 命中 meta.account_uuid）。
        assert_eq!(
            classify_live_identity(Some("uuid-1"), None, Some("p1"), &profiles),
            Some(LiveIdentity::Current)
        );
        // live = 另一个已登记账号。
        assert_eq!(
            classify_live_identity(Some("uuid-2"), None, Some("p1"), &profiles),
            Some(LiveIdentity::Other("p2".into()))
        );
        // live = 未登记账号。
        assert_eq!(
            classify_live_identity(Some("uuid-x"), None, Some("p1"), &profiles),
            Some(LiveIdentity::Unknown("uuid-x".into()))
        );
        // 取不到 uuid → None（不中断）。
        assert_eq!(
            classify_live_identity(None, None, Some("p1"), &profiles),
            None
        );
    }

    #[test]
    fn classify_email_fallback_is_case_insensitive() {
        // 老账号 p1：meta.account_uuid 为空，只在 meta.email 里存了地址。
        let mut p1 = profile_with("p1", None);
        p1.meta.email = Some("Bob@Example.com".into());
        let profiles = vec![p1, profile_with("p2", Some("uuid-2"))];

        // live 没带 uuid，但 email 大小写不同 → 命中同一账号（Current）。
        assert_eq!(
            classify_live_identity(None, Some("bob@example.com"), Some("p1"), &profiles),
            Some(LiveIdentity::Current)
        );
        // uuid 命中 p2 时仍优先走 uuid，current 是 p1 → Other(p2)。
        assert_eq!(
            classify_live_identity(Some("uuid-2"), Some("other@x.com"), Some("p1"), &profiles),
            Some(LiveIdentity::Other("p2".into()))
        );
        // email 带前后空白也应 trim 后命中。
        assert_eq!(
            classify_live_identity(None, Some("  BOB@example.com  "), Some("p1"), &profiles),
            Some(LiveIdentity::Current)
        );
    }

    #[test]
    fn classify_reads_identity_from_embedded_claude_json() {
        // 老账号 p1：meta 全空，但 claude_json.oauthAccount 里嵌了身份。
        let mut p1 = profile_with("p1", None);
        p1.claude_json = serde_json::json!({
            "oauthAccount": {
                "accountUuid": "old-uuid",
                "email": "Old@Example.com"
            }
        });
        let profiles = vec![p1];

        // live uuid 命中 json 内嵌 uuid。
        assert_eq!(
            classify_live_identity(Some("old-uuid"), None, Some("p1"), &profiles),
            Some(LiveIdentity::Current)
        );
        // live 没带 uuid，email 大小写不同 → 回退 json 内嵌 email。
        assert_eq!(
            classify_live_identity(None, Some("old@example.com"), Some("p1"), &profiles),
            Some(LiveIdentity::Current)
        );
    }

    #[test]
    fn classify_no_uuid_no_email_match_is_unknown() {
        let mut p1 = profile_with("p1", Some("uuid-1"));
        p1.meta.email = Some("a@x.com".into());
        let profiles = vec![p1];
        // uuid 与 email 都对不上。
        assert_eq!(
            classify_live_identity(Some("uuid-x"), Some("b@x.com"), Some("p1"), &profiles),
            Some(LiveIdentity::Unknown("uuid-x".into()))
        );
    }

    #[test]
    fn classify_both_identities_missing_is_none() {
        let profiles = vec![profile_with("p1", Some("uuid-1"))];
        // live 既没 uuid 也没 email → None（不中断）。
        assert_eq!(
            classify_live_identity(None, None, Some("p1"), &profiles),
            None
        );
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
        let warnings = reconcile_live_into_store(&mut store_data, &snapshot, true, now());
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
    fn unknown_not_adopted_when_switch_off() {
        let mut store_data = store::Store::default();
        store_data.profiles.push(profile_with("p1", Some("uuid-1")));
        store_data.current_profile_id = Some("p1".into());
        let snapshot = snapshot_with("new-uuid-9999", Some("new@example.com"));
        let warnings = reconcile_live_into_store(&mut store_data, &snapshot, false, now());
        assert_eq!(store_data.profiles.len(), 1, "开关关闭时不新建账号");
        assert_eq!(
            store_data.current_profile_id.as_deref(),
            Some("p1"),
            "开关关闭时不应改 current_profile_id"
        );
        assert!(
            warnings.iter().any(|w| w.contains("自动收养已关闭")),
            "应提示自动收养已关闭：{warnings:?}"
        );
    }

    #[test]
    fn other_is_written_back_and_manual_switch_reported() {
        let mut store_data = store::Store::default();
        store_data.profiles.push(profile_with("p1", Some("uuid-1")));
        store_data.profiles.push(profile_with("p2", Some("uuid-2")));
        store_data.current_profile_id = Some("p1".into());
        let snapshot = snapshot_with("uuid-2", None);
        let warnings = reconcile_live_into_store(&mut store_data, &snapshot, true, now());
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
        let warnings = reconcile_live_into_store(&mut store_data, &snapshot, true, now());
        assert_eq!(store_data.profiles.len(), 1, "不应新增账号");
        let p1 = &store_data.profiles[0];
        assert_eq!(p1.keychain_password.as_deref(), Some("keychain"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn missing_claude_json_does_not_abort() {
        let mut store_data = store::Store::default();
        let snapshot = (None, None, None);
        let warnings = reconcile_live_into_store(&mut store_data, &snapshot, true, now());
        assert!(warnings.iter().any(|w| w.contains("~/.claude.json")));
        assert_eq!(store_data.profiles.len(), 0);
    }

    #[test]
    fn missing_uuid_does_not_abort() {
        // oauthAccount 存在但没有 accountUuid。
        let claude = serde_json::json!({ "oauthAccount": {} });
        let mut store_data = store::Store::default();
        let snapshot = (Some(claude), None, None);
        let warnings = reconcile_live_into_store(&mut store_data, &snapshot, true, now());
        assert!(warnings.iter().any(|w| w.contains("accountUuid")));
        assert_eq!(store_data.profiles.len(), 0);
    }

    // ── write_live_into_profile：空凭据不得覆盖已存凭据 ──

    #[test]
    fn write_live_keeps_existing_keychain_when_live_has_none() {
        let mut p = profile_with("p1", Some("uuid-1"));
        p.keychain_password = Some("existing-cred".into());
        let live_claude = serde_json::json!({
            "oauthAccount": { "accountUuid": "uuid-1", "email": "a@x.com" }
        });

        // live 没读到凭据（None）。
        write_live_into_profile(&mut p, &live_claude, &None, &None, now());

        assert_eq!(p.keychain_password.as_deref(), Some("existing-cred"));
        assert!(
            p.meta.has_keychain_credentials,
            "meta 仍应标记 has_keychain_credentials=true"
        );
        // claude_json 仍被刷新。
        assert_eq!(p.claude_json, live_claude);
    }

    #[test]
    fn write_live_updates_keychain_when_new_cred_present() {
        let mut p = profile_with("p1", Some("uuid-1"));
        p.keychain_password = Some("old".into());
        let live_claude = serde_json::json!({ "oauthAccount": { "accountUuid": "uuid-1" } });

        write_live_into_profile(&mut p, &live_claude, &None, &Some("new".into()), now());

        assert_eq!(p.keychain_password.as_deref(), Some("new"));
        assert!(p.meta.has_keychain_credentials);
    }

    #[test]
    fn write_live_ignores_blank_keychain() {
        let mut p = profile_with("p1", Some("uuid-1"));
        p.keychain_password = Some("existing-cred".into());
        let live_claude = serde_json::json!({ "oauthAccount": { "accountUuid": "uuid-1" } });

        // 空白串（含纯空格）不得覆盖。
        write_live_into_profile(&mut p, &live_claude, &None, &Some("   ".into()), now());

        assert_eq!(p.keychain_password.as_deref(), Some("existing-cred"));
        assert!(p.meta.has_keychain_credentials);
    }
}
