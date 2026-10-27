//! 快照加密导出 / 导入（单文件格式）。
//!
//! 场景：换机迁移或离线冷备。Credential Manager 主密钥不能跨机器迁移，
//! 所以导出时用**用户口令**重新封装（Argon2id 派生密钥 + AES-256-GCM）。
//!
//! 文件格式（`CSBK1`）：
//! ```text
//! magic  "CSBK1"          5B
//! salt                   16B   Argon2id 输入盐
//! nonce                  12B   AES-GCM nonce
//! ciphertext             ...   AES-256-GCM(store.private.json 明文 JSON)
//! ```
//! 口令 ≥ 8 位；解密失败（口令错/文件损坏）只报错，绝不覆盖现有 store。

use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use serde::Serialize;

use crate::fsx;
use crate::paths;
use crate::store;

const MAGIC: &[u8; 5] = b"CSBK1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const MIN_PASSWORD_LEN: usize = 8;

/// Argon2id 参数：m=64MiB, t=3, p=1（OWASP 推荐下限之上，桌面场景可接受）。
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params =
        Params::new(64 * 1024, 3, 1, Some(32)).map_err(|e| format!("Argon2 参数错误: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("口令派生密钥失败: {e}"))?;
    Ok(key)
}

#[derive(Debug, Serialize)]
pub struct ExportResult {
    pub path: String,
    pub bytes: usize,
}

/// 导出：把 store 路径的文件用口令加密写到 `dest`。
/// 读的是**落盘原文**（不解密再序列化，避免「导出动作本身」依赖主密钥——
/// 导出应在主密钥丢失后仍可用于抢救密文，用户口令就是新的封装钥匙）。
pub fn export_store_encrypted_blocking(
    dest: &Path,
    password: &str,
) -> Result<ExportResult, String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!("口令至少 {MIN_PASSWORD_LEN} 位"));
    }
    let store_path = paths::store_path()?;
    let plaintext = fs::read_to_string(&store_path)
        .map_err(|e| format!("读取 store 失败（还没有任何账号快照？）: {e}"))?;

    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let key_bytes = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
        .map_err(|e| format!("加密失败: {e}"))?;

    let mut blob = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(dest, &blob).map_err(|e| format!("写入导出文件失败: {e}"))?;
    Ok(ExportResult {
        path: dest.to_string_lossy().to_string(),
        bytes: blob.len(),
    })
}

#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub imported_bytes: usize,
    pub backup_of_previous: String,
}

/// 导入：口令解密 `src` 并原子替换 store。
/// 导入前先把现有 store 备份成 `store.private.json.pre-import-<时间戳>`——
/// 口令对但内容不是用户想要的情况（导错文件）可无损回退。
pub fn import_store_encrypted_blocking(src: &Path, password: &str) -> Result<ImportResult, String> {
    let blob = fs::read(src).map_err(|e| format!("读取导出文件失败: {e}"))?;
    if blob.len() < MAGIC.len() + SALT_LEN + NONCE_LEN + 1 {
        return Err("文件格式错误：不是本工具导出的 CSBK1 文件".to_string());
    }
    if &blob[..MAGIC.len()] != MAGIC.as_slice() {
        return Err("文件格式错误：魔数不匹配（不是 CSBK1 导出文件）".to_string());
    }
    let salt = &blob[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let nonce_start = MAGIC.len() + SALT_LEN;
    let nonce = &blob[nonce_start..nonce_start + NONCE_LEN];
    let ciphertext = &blob[nonce_start + NONCE_LEN..];

    let key_bytes = derive_key(password, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| "解密失败：口令错误或文件损坏（现有数据未改动）".to_string())?;
    let text =
        String::from_utf8(plaintext).map_err(|e| format!("解密成功但内容不是 UTF-8 JSON: {e}"))?;
    // 校验确实是 store 形状再落盘，防止导错文件把垃圾写进 store。
    let parsed: store::Store = serde_json::from_str(&text)
        .map_err(|e| format!("解密成功但不是有效的 store JSON（现有数据未改动）: {e}"))?;

    // 跨机检测：密文只有用**导出机器**的 store 主密钥才能解开。早期实现到此
    // 就直接落盘，导入"成功"之后任何 load_store() 都会因解密失败整体报错——
    // 账号管理全瘫且没有自愈路径。因此在落盘前拦下外机密文。
    let (encrypted, total) = count_encrypted_secrets(&parsed);
    if encrypted > 0 {
        return Err(format!(
            "该快照含 {encrypted} 项由**另一台机器**的加密密钥保护的凭据（共 {total} 项凭文字段）。\
             store 主密钥按设计不跨机迁移，在本机导入后这些账号将永远无法解密，\
             并导致整个账号库不可用。如需迁移，请在目标机器上重新捕获账号快照。"
        ));
    }

    // 备份现有 store（不存在则跳过）。
    let store_path = paths::store_path()?;
    let mut backup_label = String::from("(原先没有 store，直接写入)");
    if store_path.exists() {
        let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let backup_path =
            store_path.with_file_name(format!("store.private.json.pre-import-{stamp}"));
        fs::copy(&store_path, &backup_path).map_err(|e| format!("备份现有 store 失败: {e}"))?;
        backup_label = backup_path.to_string_lossy().to_string();
    }

    fsx::write_atomically(&store_path, &text).map_err(|e| format!("写入 store 失败: {e}"))?;
    Ok(ImportResult {
        imported_bytes: text.len(),
        backup_of_previous: backup_label,
    })
}

/// 统计 store 里带 `enc:v1:` 前缀的凭文字段数量，以及凭文字段总数。
///
/// 覆盖 `keychain_password`（OAuth blob）与 `encrypted_auth_settings`（从
/// settings.json 拆出的认证字段）两类：两者都依赖本机 store 主密钥，
/// 换机后必然解不开。
fn count_encrypted_secrets(store: &store::Store) -> (usize, usize) {
    let mut encrypted = 0usize;
    let mut total = 0usize;
    for profile in &store.profiles {
        for value in [
            profile.keychain_password.as_deref(),
            profile.encrypted_auth_settings.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            total += 1;
            if value.starts_with(store::ENC_PREFIX) {
                encrypted += 1;
            }
        }
    }
    (encrypted, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_only_encrypted_credential_fields() {
        let mut store = store::Store::default();
        // 一个带密文凭据的账号 + 一个明文（旧格式）账号。
        store.profiles.push(store::StoredProfile {
            id: "a".into(),
            name: "A".into(),
            notes: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_switched_at: None,
            claude_json: serde_json::json!({}),
            settings_json: None,
            encrypted_auth_settings: Some(format!("{}abc", store::ENC_PREFIX)),
            keychain_password: Some(format!("{}def", store::ENC_PREFIX)),
            meta: store::ProfileMeta::default(),
            clash: None,
            runtime: None,
        });
        store.profiles.push(store::StoredProfile {
            id: "b".into(),
            name: "B".into(),
            notes: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_switched_at: None,
            claude_json: serde_json::json!({}),
            settings_json: None,
            encrypted_auth_settings: None,
            // 旧版明文凭据：不计入「外机密文」，可跨机导入。
            keychain_password: Some("plain-oauth-blob".into()),
            meta: store::ProfileMeta::default(),
            clash: None,
            runtime: None,
        });

        let (encrypted, total) = count_encrypted_secrets(&store);
        assert_eq!(encrypted, 2, "两条 enc:v1: 凭文应被识别");
        assert_eq!(total, 3, "凭文字段共 3 个（含 1 条明文）");
    }

    #[test]
    fn plaintext_only_store_is_importable_across_machines() {
        let mut store = store::Store::default();
        store.profiles.push(store::StoredProfile {
            id: "a".into(),
            name: "A".into(),
            notes: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_switched_at: None,
            claude_json: serde_json::json!({}),
            settings_json: None,
            encrypted_auth_settings: None,
            keychain_password: Some("plain".into()),
            meta: store::ProfileMeta::default(),
            clash: None,
            runtime: None,
        });
        let (encrypted, _) = count_encrypted_secrets(&store);
        assert_eq!(encrypted, 0, "无密文时不应拦截跨机导入");
    }
}
