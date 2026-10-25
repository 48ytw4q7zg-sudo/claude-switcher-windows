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

pub fn default_runtime_for_profile(name: &str, node: Option<&str>) -> ProfileRuntimeBinding {
    let haystack = format!(
        "{} {}",
        name.to_lowercase(),
        node.unwrap_or("").to_lowercase()
    );
    if haystack.contains("尼") || haystack.contains("nigeria") || haystack.contains("南非") {
        ProfileRuntimeBinding {
            timezone: Some("Africa/Lagos".to_string()),
            locale: Some("en_US.UTF-8".to_string()),
            chrome_profile: Some("Profile 4".to_string()),
        }
    } else if haystack.contains("美") || haystack.contains("us") || haystack.contains("38") {
        ProfileRuntimeBinding {
            timezone: Some("America/Los_Angeles".to_string()),
            locale: Some("en_US.UTF-8".to_string()),
            chrome_profile: Some("Profile 35".to_string()),
        }
    } else {
        ProfileRuntimeBinding {
            timezone: Some("America/Los_Angeles".to_string()),
            locale: Some("en_US.UTF-8".to_string()),
            chrome_profile: None,
        }
    }
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

/// **加密路径专用**：读现有密钥，缺失才生成 32B 新密钥写入凭据存储。
fn load_or_create_store_key() -> Result<[u8; 32], String> {
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
