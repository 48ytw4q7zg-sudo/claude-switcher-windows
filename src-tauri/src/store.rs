//! store（账号快照库）数据结构与读写。
//!
//! C2 加密设计：
//! - 只加密敏感字段 keychain_password（OAuth blob）；其余明文便于调试。
//! - 主密钥 32B：macOS 存独立 Keychain 项；Windows 存 Credential Manager（keyring）。
//! - 密文表示 "enc:v1:" + base64(nonce(12B) || ciphertext)；nonce 每次重新随机。
//! - 旧明文向后兼容：不以 ENC_PREFIX 开头视为明文，下次落盘自动加密。

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::credentials;
use crate::jsonio::write_json_pretty;
use crate::paths;

pub const ENC_PREFIX: &str = "enc:v1:";
pub const DEFAULT_CLASH_GROUP: &str = "Auto-Claude";

/// 遥测去关联 env keys。
pub const ENV_DISABLE_TELEMETRY: &str = "DISABLE_TELEMETRY";
pub const ENV_DISABLE_NONESSENTIAL_TRAFFIC: &str = "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC";
/// 会覆盖 OAuth 的认证环境变量（提示用户清理）。
pub const AUTH_ENV_KEYS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
    "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR",
];
pub const PROFILE_ENV_KEYS: &[&str] = &["TZ", "LANG", "LC_ALL"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProfile {
    pub id: String,
    pub name: String,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_switched_at: Option<DateTime<Utc>>,
    pub claude_json: Value,
    pub settings_json: Option<Value>,
    pub keychain_password: Option<String>,
    pub meta: ProfileMeta,
    #[serde(default)]
    pub clash: Option<ProfileClashBinding>,
    #[serde(default)]
    pub runtime: Option<ProfileRuntimeBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileClashBinding {
    pub enabled: bool,
    pub group: String,
    pub node: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfileRuntimeBinding {
    pub timezone: Option<String>,
    pub locale: Option<String>,
    pub chrome_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfileMeta {
    pub email: Option<String>,
    pub account_uuid: Option<String>,
    pub organization_uuid: Option<String>,
    pub organization_name: Option<String>,
    pub user_id_hash: Option<String>,
    pub has_oauth_account: bool,
    pub has_keychain_credentials: bool,
    pub has_trusted_device_token: bool,
    pub subscription_type: Option<String>,
    pub rate_limit_tier: Option<String>,
}

/// 遥测去关联模式（三态，前后端契约里序列化成 camelCase 字符串）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TelemetryMode {
    Default,
    DisableTelemetry,
    EssentialOnly,
}

impl TelemetryMode {
    pub fn env_key(self) -> Option<&'static str> {
        match self {
            TelemetryMode::Default => None,
            TelemetryMode::DisableTelemetry => Some(ENV_DISABLE_TELEMETRY),
            TelemetryMode::EssentialOnly => Some(ENV_DISABLE_NONESSENTIAL_TRAFFIC),
        }
    }
}

/// 老 store 缺字段 / 全新安装时默认 DisableTelemetry（默认开启去关联）。
fn default_telemetry_mode() -> TelemetryMode {
    TelemetryMode::DisableTelemetry
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Store {
    pub profiles: Vec<StoredProfile>,
    pub current_profile_id: Option<String>,
    #[serde(default)]
    pub pending_new_account: Option<PendingNewAccount>,
    #[serde(default = "default_telemetry_mode")]
    pub telemetry_mode: TelemetryMode,
}

impl Default for Store {
    fn default() -> Self {
        Store {
            profiles: Vec::new(),
            current_profile_id: None,
            pending_new_account: None,
            telemetry_mode: default_telemetry_mode(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingNewAccount {
    pub id: String,
    pub name: String,
    pub notes: Option<String>,
    pub group: String,
    pub node: String,
    pub runtime: ProfileRuntimeBinding,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileSummary {
    pub id: String,
    pub name: String,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_switched_at: Option<DateTime<Utc>>,
    pub meta: ProfileMeta,
    pub clash: Option<ProfileClashBinding>,
    pub runtime: Option<ProfileRuntimeBinding>,
    pub is_current: bool,
}

/// 新账号的默认运行时绑定（时区 / 语言 / Chrome Profile）。
///
/// 只保留**明确无误**的地区关键词映射，其余一律留空让用户自己填：
/// - 早前版本用 `contains("us")` / `contains("38")` 做子串判断，
///   `russia`、`austria`、`Japan38` 都会被误判成美国区；
/// - `Profile 4` / `Profile 35` 是上游作者自己机器上的 Chrome Profile 编号，
///   对其它用户毫无意义，照抄只会把账号绑到错误的浏览器 profile。
///
/// 时区/语言只是 Claude Code 的运行时提示，猜错的代价高于留空。
pub fn default_runtime_for_profile(name: &str, node: Option<&str>) -> ProfileRuntimeBinding {
    let haystack = format!(
        "{} {}",
        name.to_lowercase(),
        node.unwrap_or("").to_lowercase()
    );
    // 尼日利亚/南非区：明确的非洲节点关键词。
    if haystack.contains("nigeria") || haystack.contains("尼日") || haystack.contains("南非") {
        return ProfileRuntimeBinding {
            timezone: Some("Africa/Lagos".to_string()),
            locale: Some("en_US.UTF-8".to_string()),
            chrome_profile: None,
        };
    }
    // 美国区：只认明确写法，不做 `us` / 数字子串猜测。
    if haystack.contains("united states")
        || haystack.contains("usa")
        || haystack.contains("美国")
        || haystack.contains("洛杉")
        || haystack.contains("los angeles")
    {
        return ProfileRuntimeBinding {
            timezone: Some("America/Los_Angeles".to_string()),
            locale: Some("en_US.UTF-8".to_string()),
            chrome_profile: None,
        };
    }
    ProfileRuntimeBinding::default()
}

// ───────────────────────── store 加密主密钥 ─────────────────────────

/// 读取 store 加密主密钥：不存在返回 Ok(None)。
/// **解密路径只用这个**——绝不在缺密钥时生成新密钥（否则会铸新钥解旧密，
/// 污染恢复路径导致已加密数据不可逆丢失）。
fn read_store_key() -> Result<Option<[u8; 32]>, String> {
    let username = credentials::current_username()?;
    let b64 = read_store_key_raw(&username)?;
    let Some(b64) = b64 else {
        return Ok(None);
    };
    let bytes = BASE64
        .decode(b64.trim().as_bytes())
        .map_err(|e| format!("store 加密密钥 base64 解码失败: {e}"))?;
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "store 加密密钥长度异常（应为 32 字节）".to_string())?;
    Ok(Some(key))
}

#[cfg(windows)]
fn read_store_key_raw(username: &str) -> Result<Option<String>, String> {
    let entry = keyring::Entry::new(credentials::STORE_KEY_KEYCHAIN_SERVICE, username)
        .map_err(|e| format!("读取 store 加密密钥失败: {e}"))?;
    match entry.get_password() {
        Ok(b64) => Ok(Some(b64)),
        Err(keyring::Error::NoEntry) => Ok(None),
        // 关键：Windows Credential Manager 在「条目存在但读不出」（DPAPI 解密失败、
        // 凭据库损坏、条目被其它安全策略挡住）时返回的是 PlatformFailure 而非 NoEntry。
        // 若这里把它当「不存在」返回 Ok(None)，调用方 load_or_create_store_key 就会
        // 铸一把新密钥并覆盖旧条目——所有已加密快照永久无法解密。
        // 因此除 NoEntry 之外的一切错误都必须是致命 Err，绝不静默降级。
        Err(e) => Err(format!(
            "读取 store 加密密钥失败（条目存在但无法读取，请勿覆盖保存 store）: {e}"
        )),
    }
}

#[cfg(not(windows))]
fn read_store_key_raw(username: &str) -> Result<Option<String>, String> {
    use std::process::Command;

    let output = Command::new("security")
        .arg("find-generic-password")
        .arg("-a")
        .arg(username)
        .arg("-s")
        .arg(credentials::STORE_KEY_KEYCHAIN_SERVICE)
        .arg("-w")
        .output()
        .map_err(|e| format!("读取 store 加密密钥失败: {e}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

/// 进程内的密钥创建锁。
/// 首次运行时托盘刷新线程与命令线程可能同时发现「没有密钥」并各生成一把，
/// 后写入的覆盖先写入的——先加密的数据从此解不开。用 Mutex 串行化，
/// 持锁后再读一次，第二个线程就会拿到第一个线程写好的密钥。
static STORE_KEY_CREATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// **加密路径专用**：读现有密钥，缺失才生成 32B 新密钥写入凭据存储。
fn load_or_create_store_key() -> Result<[u8; 32], String> {
    // 快路径：不加锁读一次，命中就直接返回（绝大多数调用走这里）。
    if let Some(key) = read_store_key()? {
        return Ok(key);
    }

    // 慢路径：持锁后再读一次，避免并发铸钥互相覆盖。
    let _guard = STORE_KEY_CREATE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(key) = read_store_key()? {
        return Ok(key);
    }

    let username = credentials::current_username()?;
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let b64 = BASE64.encode(key);

    #[cfg(windows)]
    {
        let entry = keyring::Entry::new(credentials::STORE_KEY_KEYCHAIN_SERVICE, &username)
            .map_err(|e| format!("定位 store 加密密钥条目失败: {e}"))?;
        entry
            .set_password(&b64)
            .map_err(|e| format!("写入 store 加密密钥失败: {e}"))?;
    }
    #[cfg(not(windows))]
    {
        keychain_write_raw(&username, credentials::STORE_KEY_KEYCHAIN_SERVICE, &b64)
            .map_err(|e| format!("写入 store 加密密钥失败: {e}"))?;
    }
    Ok(key)
}

/// 把明文加密成 "enc:v1:" + base64(nonce(12B) || ciphertext)。
pub fn encrypt_secret(plaintext: &str) -> Result<String, String> {
    let key_bytes = load_or_create_store_key()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("加密 token 失败: {e}"))?;
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(format!("{ENC_PREFIX}{}", BASE64.encode(blob)))
}

/// 解密 "enc:v1:..."；不以 ENC_PREFIX 开头视为旧明文原样返回（向后兼容）。
pub fn decrypt_secret(value: &str) -> Result<String, String> {
    let Some(b64) = value.strip_prefix(ENC_PREFIX) else {
        return Ok(value.to_string());
    };
    let blob = BASE64
        .decode(b64.as_bytes())
        .map_err(|e| format!("解密 token 失败（base64 解码）: {e}"))?;
    if blob.len() < 12 {
        return Err("解密 token 失败：密文长度不足（缺少 nonce）".to_string());
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let key_bytes = read_store_key()?.ok_or_else(|| {
        "解密 token 失败：找不到 store 加密主密钥（claude-switcher-store-key）。\
         可能密钥被删除 / 换机 / 系统用户名变化，已加密数据无法解开。\
         请勿在此状态下覆盖保存 store，先恢复该凭据项。"
            .to_string()
    })?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("解密 token 失败（认证/解密错误，密钥不匹配或数据被篡改）: {e}"))?;
    String::from_utf8(plaintext).map_err(|e| format!("解密 token 失败（非 UTF-8 明文）: {e}"))
}

/// 把可能为明文的 keychain_password 落盘前加密；已是密文则透传避免二次加密。
pub fn encrypt_keychain_field(value: &str) -> Result<String, String> {
    if value.starts_with(ENC_PREFIX) {
        return Ok(value.to_string());
    }
    encrypt_secret(value)
}

/// macOS：写 keychain（hex -X 形式；payload 走 stdin 避免 ps 泄露）。
#[cfg(not(windows))]
fn keychain_write_raw(account: &str, service: &str, value: &str) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let hex: String = value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let command = format!("add-generic-password -U -a \"{account}\" -s \"{service}\" -X {hex}\n");
    const STDIN_LINE_LIMIT: usize = 4096 - 64;

    if command.len() <= STDIN_LINE_LIMIT {
        let mut child = Command::new("security")
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("写入 Keychain 失败: {e}"))?;
        child
            .stdin
            .take()
            .ok_or_else(|| "写入 Keychain 失败：无法获取 security stdin".to_string())?
            .write_all(command.as_bytes())
            .map_err(|e| format!("写入 Keychain 失败: {e}"))?;
        let out = child
            .wait_with_output()
            .map_err(|e| format!("写入 Keychain 失败: {e}"))?;
        if out.status.success() {
            return Ok(());
        }
        return Err(format!(
            "写入 Keychain 失败: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let out = Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-a",
            account,
            "-s",
            service,
            "-X",
            &hex,
        ])
        .output()
        .map_err(|e| format!("写入 Keychain 失败: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "写入 Keychain 失败: {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

// ───────────────────────── store 读写 ─────────────────────────

pub fn load_store() -> Result<Store, String> {
    paths::ensure_app_dirs()?;
    let path = paths::store_path()?;
    if !path.exists() {
        return Ok(Store::default());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut store: Store =
        serde_json::from_str(&raw).map_err(|e| format!("store.private.json 解析失败: {e}"))?;

    for profile in &mut store.profiles {
        if let Some(enc) = profile.keychain_password.take() {
            let plain = decrypt_secret(&enc)
                .map_err(|e| format!("解密账号「{}」的凭据失败: {e}", profile.name))?;
            profile.keychain_password = Some(plain);
        }
        if profile.runtime.is_none() {
            profile.runtime = Some(default_runtime_for_profile(
                &profile.name,
                profile.clash.as_ref().map(|binding| binding.node.as_str()),
            ));
        }
    }
    Ok(store)
}

/// 从 settings_json 里清除认证类 env（`AUTH_ENV_KEYS` 列出的那些明文密钥），
/// 以及会覆盖 OAuth 的 `apiKeyHelper`。
///
/// 与 `accounts::scrub_auth_from_settings` 的区别：那个用于「新号登录前清空 live」，
/// 会把整个空 settings 收敛成 `None`；这个只做「脱敏」，保留其余配置原样。
fn scrub_auth_env_from_settings(settings: Value) -> Option<Value> {
    let mut obj = match settings {
        Value::Object(map) => map,
        _ => return None,
    };
    obj.remove("apiKeyHelper");
    if let Some(env) = obj.get_mut("env").and_then(|v| v.as_object_mut()) {
        for key in AUTH_ENV_KEYS {
            env.remove(*key);
        }
    }
    if obj
        .get("env")
        .and_then(|v| v.as_object())
        .map(|env| env.is_empty())
        .unwrap_or(false)
    {
        obj.remove("env");
    }
    if obj.is_empty() {
        return None;
    }
    Some(Value::Object(obj))
}

pub fn save_store(store: &Store) -> Result<(), String> {
    paths::ensure_app_dirs()?;
    let path = paths::store_path()?;

    // 在 clone 上加密，不污染调用方内存里的明文。
    let mut to_persist = store.clone();
    for profile in &mut to_persist.profiles {
        if let Some(plain) = profile.keychain_password.take() {
            let enc = encrypt_keychain_field(&plain)
                .map_err(|e| format!("加密账号「{}」的凭据失败: {e}", profile.name))?;
            profile.keychain_password = Some(enc);
        }
        // settings_json 里可能残留认证类 env（ANTHROPIC_API_KEY 等）——这些同样是
        // 明文密钥，不能因为「只加密 keychain_password」就留在 store 里。
        // 落盘前统一清除；不影响切换功能（auth env 本来就会让切号失效）。
        if let Some(settings) = profile.settings_json.take() {
            profile.settings_json = scrub_auth_env_from_settings(settings);
        }
    }

    let value = serde_json::to_value(&to_persist).map_err(|e| e.to_string())?;
    write_json_pretty(path, &value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 加解密往返（走真实 keyring/Keychain；Windows CI 上 Credential Manager 可用）。
    /// 在拿不到凭据存储的环境会失败——标记 ignore，手动跑。
    #[test]
    #[ignore]
    fn encrypt_decrypt_roundtrip() {
        let secret = "claudeAiOauth {\"accessToken\":\"abc-测试\"}";
        let enc = encrypt_secret(secret).unwrap();
        assert!(enc.starts_with(ENC_PREFIX));
        assert_ne!(enc, secret);
        assert_eq!(decrypt_secret(&enc).unwrap(), secret);
    }

    #[test]
    fn decrypt_secret_passthrough_plaintext() {
        // 旧明文（不以 enc:v1: 开头）原样返回。
        assert_eq!(decrypt_secret("plain-blob").unwrap(), "plain-blob");
    }

    #[test]
    fn encrypt_keychain_field_idempotent_for_cipher() {
        let cipher_text = format!("{ENC_PREFIX}AAAA");
        assert_eq!(
            encrypt_keychain_field(&cipher_text).unwrap(),
            cipher_text,
            "已是密文的值应透传，不二次加密"
        );
    }

    #[test]
    fn store_default_telemetry_is_disable() {
        let store = Store::default();
        assert_eq!(store.telemetry_mode, TelemetryMode::DisableTelemetry);
    }

    /// 地区启发式不能误判：`russia` / `austria` 含 "us" 子串、`Japan38` 含 "38"，
    /// 早期版本会把它们全绑到美国时区。现在这些必须落到「不猜」的默认值。
    #[test]
    fn default_runtime_does_not_misfire_on_substrings() {
        for name in ["russia-node", "austria", "Japan38", "sydney", "frankfurt"] {
            let runtime = default_runtime_for_profile(name, None);
            assert_eq!(
                runtime.timezone, None,
                "「{name}」不应被猜出时区（子串误判）"
            );
            assert_eq!(
                runtime.chrome_profile, None,
                "「{name}」不应被绑到别人的 Chrome Profile"
            );
        }
    }

    #[test]
    fn default_runtime_matches_explicit_regions() {
        let ng = default_runtime_for_profile("尼日", Some("Nigeria-1"));
        assert_eq!(ng.timezone.as_deref(), Some("Africa/Lagos"));
        let us = default_runtime_for_profile("美国号", None);
        assert_eq!(us.timezone.as_deref(), Some("America/Los_Angeles"));
        // 都不应写死 Chrome Profile。
        assert_eq!(ng.chrome_profile, None);
        assert_eq!(us.chrome_profile, None);
    }

    /// settings_json 落盘前必须脱敏：认证 env 与 apiKeyHelper 不能以明文留在 store。
    #[test]
    fn save_store_scrubs_auth_env_from_settings() {
        let settings = serde_json::json!({
            "env": {
                "ANTHROPIC_API_KEY": "sk-ant-secret",
                "TZ": "Africa/Lagos",
                "CUSTOM_KEEP": "1"
            },
            "permissions": { "defaultMode": "bypassPermissions" }
        });
        let scrubbed = scrub_auth_env_from_settings(settings).expect("不应被清成 None");
        assert!(scrubbed["env"].get("ANTHROPIC_API_KEY").is_none());
        assert_eq!(scrubbed["env"]["TZ"], "Africa/Lagos");
        assert_eq!(scrubbed["env"]["CUSTOM_KEEP"], "1");
        assert!(scrubbed["permissions"]["defaultMode"] == "bypassPermissions");
    }

    #[test]
    fn scrub_auth_env_drops_apikey_helper() {
        let settings = serde_json::json!({
            "apiKeyHelper": "/path/to/helper",
            "env": { "ANTHROPIC_AUTH_TOKEN": "tok" }
        });
        // 这个用例里删完认证项后 settings 已空，脱敏结果应为 None（不写回文件）。
        assert!(scrub_auth_env_from_settings(settings).is_none());
    }

    #[test]
    fn scrub_auth_env_keeps_non_sensitive_settings() {
        let settings = serde_json::json!({
            "apiKeyHelper": "/path/to/helper",
            "env": { "ANTHROPIC_AUTH_TOKEN": "tok", "TZ": "UTC" },
            "permissions": { "defaultMode": "bypassPermissions" }
        });
        let scrubbed = scrub_auth_env_from_settings(settings).expect("非敏感配置必须保留");
        assert!(scrubbed.get("apiKeyHelper").is_none());
        assert!(scrubbed["env"].get("ANTHROPIC_AUTH_TOKEN").is_none());
        assert_eq!(scrubbed["env"]["TZ"], "UTC");
        assert_eq!(scrubbed["permissions"]["defaultMode"], "bypassPermissions");
    }

    #[test]
    fn telemetry_env_key_mapping() {
        assert_eq!(TelemetryMode::Default.env_key(), None);
        assert_eq!(
            TelemetryMode::DisableTelemetry.env_key(),
            Some(ENV_DISABLE_TELEMETRY)
        );
        assert_eq!(
            TelemetryMode::EssentialOnly.env_key(),
            Some(ENV_DISABLE_NONESSENTIAL_TRAFFIC)
        );
    }
}
