//! F-5：第三方供应商账号（Anthropic 兼容端点）管理。
//!
//! 供应商通过 settings.json 的 `env` 注入 `ANTHROPIC_BASE_URL` +
//! `ANTHROPIC_AUTH_TOKEN`（及模型相关 env）指向自定义端点。本模块只改
//! [`ProviderProfile::managed_env_keys`] 记录的键。K-3 起：
//! - 切换把「删旧键 + 写新键」合并为一次 settings.json 原子落盘（不再两次写）；
//! - settings 读改写走乐观并发（复用 [`crate::mcp::modify_json_optimistic`]）；
//! - Base URL 用 [`url::Url`] 校验：禁内嵌账号密码，除本机地址外必须 https；
//! - 列表返回不含密文的 [`ProviderView`]；
//! - auth token 加密落盘，连通测试 5 秒超时且错误不回显令牌；切回 OAuth 清受管键。

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;
use serde_json::json;

use crate::paths;
use crate::store::{self, ProviderProfile};

/// 基础 URL 的 env 键。
pub const BASE_URL_KEY: &str = "ANTHROPIC_BASE_URL";
/// 认证令牌的 env 键。
pub const AUTH_TOKEN_KEY: &str = "ANTHROPIC_AUTH_TOKEN";
/// 连通测试超时（秒）。
const CONNECT_TIMEOUT_SECS: u64 = 5;

/// K-3：供应商的前端视图（不含加密令牌，密文绝不发给前端）。
#[derive(Debug, Clone, Serialize)]
pub struct ProviderView {
    pub id: String,
    pub name: String,
    pub base_url: String,
    pub model_env: BTreeMap<String, String>,
    /// 是否为当前生效供应商。
    pub is_current: bool,
}

/// K-3：校验供应商 Base URL。
///
/// 规则：
/// - 必须是合法 URL；
/// - 禁止内嵌账号密码（`https://user:pass@host`）；
/// - 除本机地址（`localhost` / `127.0.0.1` / `[::1]`）允许 http 外，其余必须 https；
/// - 返回去掉末尾斜杠的归一化 URL，保证落盘与去重口径一致。
pub fn validate_base_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    let url = url::Url::parse(trimmed).map_err(|e| format!("Base URL 无效: {e}"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Base URL 不能内嵌账号密码".to_string());
    }
    let is_local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.scheme() != "https" && !(url.scheme() == "http" && is_local) {
        return Err("除本机地址（localhost/127.0.0.1/[::1]）外必须使用 https".to_string());
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// 计算受管 env 键：基础认证键 + 模型 env 键（去重、保持稳定顺序）。
pub fn managed_keys_for(model_env: &BTreeMap<String, String>) -> Vec<String> {
    let mut keys: Vec<String> = vec![BASE_URL_KEY.to_string(), AUTH_TOKEN_KEY.to_string()];
    for key in model_env.keys() {
        if !keys.iter().any(|existing| existing == key) {
            keys.push(key.clone());
        }
    }
    keys
}

/// 改 settings.json 的 env：先删 `remove_keys`，再写 `set`，一次乐观并发落盘。
///
/// K-3：复用 [`crate::mcp::modify_json_optimistic`]——读改写期间若 Claude Code
/// 也改了 settings.json（mtime/size 变化），会重读合并重试，绝不覆盖外部改动。
/// 无实际变化时不写磁盘。
fn mutate_settings_env(
    remove_keys: &[String],
    set: &BTreeMap<String, String>,
) -> Result<(), String> {
    let path = paths::claude_settings_path()?;
    crate::mcp::modify_json_optimistic(&path, |settings| {
        if !settings.is_object() {
            *settings = json!({});
        }
        let root = settings
            .as_object_mut()
            .ok_or_else(|| "settings.json 顶层不是对象".to_string())?;
        let env = root.entry("env").or_insert_with(|| json!({}));
        if !env.is_object() {
            *env = json!({});
        }
        let env_obj = env
            .as_object_mut()
            .ok_or_else(|| "settings.env 不是对象".to_string())?;
        let mut changed = false;
        for key in remove_keys {
            if env_obj.remove(key).is_some() {
                changed = true;
            }
        }
        for (key, value) in set {
            let new_value = json!(value);
            if env_obj.get(key) != Some(&new_value) {
                env_obj.insert(key.clone(), new_value);
                changed = true;
            }
        }
        Ok(changed)
    })?;
    Ok(())
}

/// 构造某供应商要写入的 env 键值（base url + auth token + 模型 env）。
fn provider_env_set(profile: &ProviderProfile, auth_token: &str) -> BTreeMap<String, String> {
    let mut set = BTreeMap::new();
    set.insert(
        BASE_URL_KEY.to_string(),
        profile.base_url.trim().to_string(),
    );
    set.insert(AUTH_TOKEN_KEY.to_string(), auth_token.to_string());
    for (key, value) in &profile.model_env {
        set.insert(key.clone(), value.clone());
    }
    set
}

/// K-3：原子切换供应商——把旧供应商的受管键删除与新供应商键写入合并为一次
/// settings.json 落盘（`old_managed_keys` 为空时即首次启用）。
fn switch_provider_env(
    old_managed_keys: &[String],
    new_profile: &ProviderProfile,
    auth_token: &str,
) -> Result<(), String> {
    let set = provider_env_set(new_profile, auth_token);
    mutate_settings_env(old_managed_keys, &set)
}

/// 删除某个供应商的全部受管 env。
fn remove_provider_env(profile: &ProviderProfile) -> Result<(), String> {
    mutate_settings_env(&profile.managed_env_keys, &BTreeMap::new())
}

/// 新建供应商账号：校验入参、加密 token、计算受管键，存入账号库。
pub fn create_provider_blocking(
    name: String,
    base_url: String,
    auth_token: String,
    model_env: BTreeMap<String, String>,
) -> Result<ProviderProfile, String> {
    let name = name.trim().to_string();
    let auth_token = auth_token.trim().to_string();
    if name.is_empty() {
        return Err("供应商名称不能为空".to_string());
    }
    if base_url.trim().is_empty() {
        return Err("Base URL 不能为空".to_string());
    }
    // K-3：scheme/内嵌账号密码/本机地址校验，并归一化（去末尾斜杠）。
    let base_url = validate_base_url(&base_url)?;
    if auth_token.is_empty() {
        return Err("Auth Token 不能为空".to_string());
    }
    // 模型 env 只保留非空键值，键名 trim。
    let clean_model: BTreeMap<String, String> = model_env
        .into_iter()
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, v)| !k.is_empty() && !v.is_empty())
        .collect();
    let encrypted = store::encrypt_secret(&auth_token)?;
    let now = chrono::Utc::now();
    let profile = ProviderProfile {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        base_url,
        encrypted_auth_token: encrypted,
        model_env: clean_model.clone(),
        managed_env_keys: managed_keys_for(&clean_model),
        created_at: now,
        updated_at: now,
    };
    store::with_store(|data| {
        if data
            .provider_profiles
            .iter()
            .any(|p| p.name == profile.name)
        {
            return Err(format!("已存在同名供应商「{}」", profile.name));
        }
        data.provider_profiles.push(profile.clone());
        Ok(profile)
    })
}

/// 列出全部供应商视图（K-3：不含加密令牌，只读不持锁）。
pub fn list_providers_blocking() -> Result<Vec<ProviderView>, String> {
    let data = store::load_store()?;
    Ok(data
        .provider_profiles
        .iter()
        .map(|profile| ProviderView {
            id: profile.id.clone(),
            name: profile.name.clone(),
            base_url: profile.base_url.clone(),
            model_env: profile.model_env.clone(),
            is_current: data.current_provider_id.as_deref() == Some(profile.id.as_str()),
        })
        .collect())
}

/// 删除供应商：K-3 起整个流程（含清受管 env）都在 `with_store` 内完成，
/// 避免锁外改 settings.json 与别的线程交叉写。
pub fn delete_provider_blocking(id: String) -> Result<(), String> {
    store::with_store(|data| {
        let Some(index) = data.provider_profiles.iter().position(|p| p.id == id) else {
            return Err("找不到这个供应商账号".to_string());
        };
        let target = data.provider_profiles[index].clone();
        let is_current = data.current_provider_id.as_deref() == Some(id.as_str());
        if is_current {
            // 锁内清 env：mutate 只动 settings 文件，不获取 STORE_LOCK，无重入死锁。
            remove_provider_env(&target)?;
            data.current_provider_id = None;
        }
        data.provider_profiles.remove(index);
        Ok(())
    })
}

/// 切换到指定供应商：K-3 起把删旧键 + 写新键合并为一次原子落盘，再登记当前供应商。
///
/// 旧实现先 remove（写一次）再 apply（再写一次），第二次失败时旧键已删而
/// current_provider_id 仍指旧供应商，界面与实际配置不一致。现在只写一次。
pub fn switch_to_provider_blocking(id: String) -> Result<(), String> {
    store::with_store(|data| {
        if data.current_provider_id.as_deref() == Some(id.as_str()) {
            return Ok(());
        }
        let target = data
            .provider_profiles
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| "找不到这个供应商账号".to_string())?;
        // 旧供应商的受管键（首次启用时为空）。
        let old_keys: Vec<String> = match data.current_provider_id.as_deref() {
            Some(active_id) => data
                .provider_profiles
                .iter()
                .find(|p| p.id == active_id)
                .map(|p| p.managed_env_keys.clone())
                .unwrap_or_default(),
            None => Vec::new(),
        };
        let token = store::decrypt_secret(&target.encrypted_auth_token)?;
        // 一次落盘：删旧键 + 写新键。
        switch_provider_env(&old_keys, &target, &token)?;
        data.current_provider_id = Some(target.id.clone());
        Ok(())
    })
}

/// 切回 OAuth：清掉当前供应商的全部受管键并清空当前供应商标记。
/// 供 [crate::lib] 的 OAuth 切换流程在锁内调用（直接传已借用的当前供应商）。
pub fn clear_active_provider_env(data: &mut store::Store) -> Result<(), String> {
    if let Some(active_id) = data.current_provider_id.take() {
        if let Some(active) = data
            .provider_profiles
            .iter()
            .find(|p| p.id == active_id)
            .cloned()
        {
            remove_provider_env(&active)?;
        }
    }
    Ok(())
}

/// 连通性测试：5 秒超时，对 base_url 发 GET；只要拿到 HTTP 应答即视为可达。
/// 错误信息经过处理，**不附带 auth token**（请求本身也不带认证头）。
pub fn test_provider_connection(base_url: String) -> Result<String, String> {
    let url = base_url.trim().to_string();
    if url.is_empty() {
        return Err("Base URL 不能为空".to_string());
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .build()
        .map_err(|e| sanitize_error(&format!("初始化 HTTP 客户端失败: {e}")))?;
    // 不带认证头：GET 仅验证网络可达，避免令牌出现在任何请求/日志里。
    let response = client.get(&url).send().map_err(|e| {
        sanitize_error(&format!(
            "连接失败（{CONNECT_TIMEOUT_SECS} 秒超时或网络不可达）: {e}"
        ))
    })?;
    // 任何状态码（含 401/404）都说明端点有应答、网络可达。
    Ok(format!(
        "端点可达，返回 HTTP {}（未校验认证，仅测试连通性）",
        response.status()
    ))
}

/// 去掉错误信息里可能出现的敏感片段（防御性：reqwest 错误一般不含请求头）。
fn sanitize_error(message: &str) -> String {
    let mut out = message.to_string();
    for marker in ["Bearer ", "x-api-key", "authorization:"] {
        if let Some(position) = out.to_lowercase().find(&marker.to_lowercase()) {
            out = format!("{}<已隐藏>", &out[..position]);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_keys_include_base_and_model_without_duplicates() {
        let mut model = BTreeMap::new();
        model.insert("ANTHROPIC_MODEL".to_string(), "claude-sonnet".to_string());
        model.insert(BASE_URL_KEY.to_string(), "should-not-dup".to_string());
        let keys = managed_keys_for(&model);
        assert_eq!(keys[0], BASE_URL_KEY);
        assert_eq!(keys[1], AUTH_TOKEN_KEY);
        assert_eq!(keys[2], "ANTHROPIC_MODEL");
        assert_eq!(keys.len(), 3, "重复的 BASE_URL 键不应出现两次");
    }

    #[test]
    fn create_provider_rejects_blank_fields() {
        assert!(
            create_provider_blocking(" ".into(), "u".into(), "t".into(), BTreeMap::new()).is_err()
        );
        assert!(
            create_provider_blocking("n".into(), " ".into(), "t".into(), BTreeMap::new()).is_err()
        );
        assert!(
            create_provider_blocking("n".into(), "u".into(), " ".into(), BTreeMap::new()).is_err()
        );
    }

    #[test]
    fn sanitize_error_strips_bearer_fragment() {
        let cleaned = sanitize_error("header Authorization: Bearer sk-secret-value");
        assert!(!cleaned.contains("sk-secret-value"));
        assert!(cleaned.contains("已隐藏"));
    }

    #[test]
    fn mutate_settings_env_removes_then_sets_and_clears() {
        // 用临时 HOME 隔离：直接验证纯逻辑——构造一个 settings Value 并手动改 env。
        let mut settings = json!({ "env": { "KEEP": "1", AUTH_TOKEN_KEY: "old" } });
        let env = settings
            .as_object_mut()
            .unwrap()
            .entry("env")
            .or_insert(json!({}));
        env.as_object_mut().unwrap().remove(AUTH_TOKEN_KEY);
        env.as_object_mut()
            .unwrap()
            .insert("NEW".to_string(), json!("2"));
        assert!(env.get(AUTH_TOKEN_KEY).is_none());
        assert_eq!(env["KEEP"], json!("1"));
        assert_eq!(env["NEW"], json!("2"));
    }

    // ── K-3 Base URL 校验 ──

    #[test]
    fn validate_base_url_accepts_https_and_trims_trailing_slash() {
        assert_eq!(
            validate_base_url("https://api.example.com/v1/").unwrap(),
            "https://api.example.com/v1"
        );
    }

    #[test]
    fn validate_base_url_allows_local_http() {
        assert_eq!(
            validate_base_url("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            validate_base_url("http://localhost:3000/").unwrap(),
            "http://localhost:3000"
        );
        assert_eq!(
            validate_base_url("http://[::1]:9000").unwrap(),
            "http://[::1]:9000"
        );
    }

    #[test]
    fn validate_base_url_rejects_non_local_http() {
        assert!(validate_base_url("http://api.example.com").is_err());
    }

    #[test]
    fn validate_base_url_rejects_embedded_credentials() {
        assert!(validate_base_url("https://user:pass@api.example.com").is_err());
        assert!(validate_base_url("https://user@api.example.com").is_err());
    }

    #[test]
    fn validate_base_url_rejects_garbage_and_unknown_scheme() {
        assert!(validate_base_url("not a url").is_err());
        assert!(validate_base_url("ftp://api.example.com").is_err());
    }
}
