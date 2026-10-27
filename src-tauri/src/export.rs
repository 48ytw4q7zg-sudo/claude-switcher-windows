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
    serde_json::from_str::<store::Store>(&text)
        .map_err(|e| format!("解密成功但不是有效的 store JSON（现有数据未改动）: {e}"))?;

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
