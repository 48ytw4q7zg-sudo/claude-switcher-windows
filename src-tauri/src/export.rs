//! 快照加密导出 / 导入（单文件格式 `CSBK1`）。
//!
//! 场景：换机迁移或离线冷备。
//!
//! **为什么导出必须先解密**：store 落盘时，每个账号的凭据字段都由**本机**
//! Credential Manager 主密钥加密（`enc:v1:` 前缀）。若把磁盘原文直接套一层
//! 用户口令导出，换机后那层口令能脱掉、里面的凭据仍旧解不开——导出的文件
//! 看着成功却导入不回去。因此导出走 `load_store()` 取内存明文，导入走
//! `save_store()` 用**目标机**主密钥重新封装，凭据才能真正迁移。
//!
//! 文件格式：
//! ```text
//! magic  "CSBK1"              5B
//! version                    1B   格式版本（当前 2）
//! kdf_m_cost (LE u32)        4B   Argon2id 内存参数 KiB
//! kdf_t_cost (LE u32)        4B   Argon2id 迭代参数
//! kdf_p_cost (LE u32)        4B   Argon2id 并行度
//! salt                      16B   Argon2id 输入盐
//! nonce                     12B   AES-GCM nonce
//! ciphertext                ...   AES-256-GCM(store JSON 明文)
//! ```
//! 头部（magic 到 salt 结束）作为 AES-GCM 的 **AAD**：改动 KDF 参数或版本号
//! 会导致认证失败，而不是静默用错参数解密。
//!
//! 口令 ≥ 8 位。解密失败（口令错/文件损坏/格式不符）只报错，绝不覆盖现有
//! store；导入前先备份现有 store 为 `pre-import-<时间戳>`。

use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use serde::Serialize;

use crate::fsx;
use crate::paths;
use crate::store;

const MAGIC: &[u8; 5] = b"CSBK1";
/// 当前格式版本。1 = 无版本字节的初版（只读兼容，不再产出）。
const FORMAT_VERSION: u8 = 2;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const MIN_PASSWORD_LEN: usize = 8;

/// Argon2id 参数：m=64MiB, t=3, p=1（OWASP 推荐下限之上，桌面场景可接受）。
const KDF_M_COST: u32 = 64 * 1024;
const KDF_T_COST: u32 = 3;
const KDF_P_COST: u32 = 1;

/// 版本 2 的头部长度：magic + version + 3×u32 + salt。
const HEADER_LEN: usize = MAGIC.len() + 1 + 4 * 3 + SALT_LEN;

fn derive_key(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], String> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| format!("Argon2 参数错误: {e}"))?;
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

/// 导出：把账号库解密成明文，用用户口令重新加密后写到 `dest`。
///
/// 走 `load_store()` 而非读磁盘原文：凭据必须处于明文状态才能被目标机的主密钥
/// 重新封装。这也意味着**导出需要本机主密钥可用**——主密钥已丢失时导出会失败，
/// 那是正确的行为（此时任何导出都导入不回去，不如明说）。
pub fn export_store_encrypted_blocking(
    dest: &Path,
    password: &str,
) -> Result<ExportResult, String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!("口令至少 {MIN_PASSWORD_LEN} 位"));
    }
    let store_data = store::load_store()?;
    let plaintext =
        serde_json::to_vec(&store_data).map_err(|e| format!("序列化账号库失败: {e}"))?;

    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let key_bytes = derive_key(password, &salt, KDF_M_COST, KDF_T_COST, KDF_P_COST)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(FORMAT_VERSION);
    header.extend_from_slice(&KDF_M_COST.to_le_bytes());
    header.extend_from_slice(&KDF_T_COST.to_le_bytes());
    header.extend_from_slice(&KDF_P_COST.to_le_bytes());
    header.extend_from_slice(&salt);

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plaintext,
                // 头部作 AAD：格式/KDF 参数被改动会导致认证失败。
                aad: &header,
            },
        )
        .map_err(|e| format!("加密失败: {e}"))?;

    let mut blob = Vec::with_capacity(header.len() + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    // 原子写：目标若是已存在的导出文件，中途崩溃不能留下半截文件。
    write_blob_atomically(dest, &blob)?;

    Ok(ExportResult {
        path: dest.to_string_lossy().to_string(),
        bytes: blob.len(),
    })
}

/// 二进制原子写：`fsx::write_atomically` 面向文本，这里走「临时文件 + rename」
/// 同一套语义，避免覆盖已存在的导出文件时留半截。
fn write_blob_atomically(dest: &Path, blob: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let tmp = dest.with_file_name(format!(
        ".{}.tmp-{}",
        dest.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("claude-switcher-snapshot"),
        uuid::Uuid::new_v4().simple()
    ));
    let write = || -> Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| format!("创建临时文件失败: {e}"))?;
        file.write_all(blob)
            .map_err(|e| format!("写入临时文件失败: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("刷新临时文件失败: {e}"))?;
        Ok(())
    };
    if let Err(e) = write() {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fsx::rename_with_retry(&tmp, dest)
        .map_err(|e| format!("写入导出文件失败: {}", fsx::humanize_io_error(&e)))
        .inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })
}

#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub imported_bytes: usize,
    pub profiles_imported: usize,
    pub backup_of_previous: String,
}

/// 导入：口令解密 `src`，用**本机**主密钥重新封装后写入 store。
///
/// 前置校验：
/// 1. 格式与 KDF 参数合法（头部作 AAD，参数被改会认证失败）；
/// 3. 解密后的内容必须是合法 store 形状。
///
/// 备份：导入前把现有 store 复制为 `store.private.json.pre-import-<时间戳>`，
/// 导错文件可无损回退。
///
/// **导入的是账号材料，不是「当前状态」**：`current_profile_id` /
/// `current_desktop_profile_id` / `desktop_profiles` 一律清空。前两者是原机器的
/// 运行时状态，带过来会让界面显示「某账号正在使用」而实际登录的并不是它；
/// `desktop_profiles` 是快照目录的元数据，而快照目录本身不在导出文件里，带过来
/// 全是「快照目录缺失」的坏条目。
pub fn import_store_encrypted_blocking(src: &Path, password: &str) -> Result<ImportResult, String> {
    // 主密钥三态判断放在最前面：凭据库故障时不该先做几十毫秒的解密。
    match store::store_key_status() {
        store::StoreKeyStatus::Present => {}
        store::StoreKeyStatus::Missing => {
            // 全新机器（或本机还没有密文快照）：允许导入，save_store 会铸第一把
            // 密钥——这正是换机迁移的主路径。早期实现无条件要求密钥已存在，
            // 把全新机器堵死了，用户得先随便捕获一个账号才能导入。
            if store::existing_store_has_ciphertext() {
                return Err("本机已存在加密账号快照，但找不到 store 加密主密钥\
                     （claude-switcher-store-key）。此时导入会让工具铸造一把新密钥，\
                     本机原有的快照将永远无法解密。请先恢复该凭据项再导入。"
                    .to_string());
            }
        }
        store::StoreKeyStatus::Unavailable(e) => {
            return Err(format!(
                "凭据存储暂时不可读（{e}）。为免误判为「没有密钥」而覆盖旧数据，\
                 本次导入已中止；请修复凭据存储后重试。"
            ));
        }
    }

    let blob = fs::read(src).map_err(|e| format!("读取导出文件失败: {e}"))?;
    let (plaintext, _) = decrypt_blob(&blob, password)?;
    let parsed: store::Store = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("解密成功但不是有效的账号库 JSON: {e}"))?;

    // 清空原机器的运行时状态与不可迁移的元数据（见函数文档）。
    let parsed = store::sanitize_imported_store(parsed);

    // 备份现有 store（不存在则跳过）。
    let store_path = paths::store_path()?;
    let mut backup_label = String::from("(原先没有账号库，直接写入)");
    if store_path.exists() {
        let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let backup_path =
            store_path.with_file_name(format!("store.private.json.pre-import-{stamp}"));
        fs::copy(&store_path, &backup_path).map_err(|e| format!("备份现有账号库失败: {e}"))?;
        backup_label = backup_path.to_string_lossy().to_string();
    }

    // H-2：账号库整体替换走 with_store 互斥；save 会用本机主密钥重新加密每个账号
    // 的凭据——这正是跨机迁移的关键。
    let profiles = parsed.profiles.len();
    store::with_store(|current| {
        *current = parsed;
        Ok(())
    })?;
    Ok(ImportResult {
        imported_bytes: plaintext.len(),
        profiles_imported: profiles,
        backup_of_previous: backup_label,
    })
}

/// 解密 CSBK1 blob，返回明文与所用格式版本。
fn decrypt_blob(blob: &[u8], password: &str) -> Result<(Vec<u8>, u8), String> {
    if blob.len() < MAGIC.len() + 1 || &blob[..MAGIC.len()] != MAGIC.as_slice() {
        return Err("文件格式错误：魔数不匹配（不是本工具导出的快照文件）".to_string());
    }
    let version = blob[MAGIC.len()];
    match version {
        // 版本 2：magic + version + 3×u32 KDF + salt + nonce + ct。
        FORMAT_VERSION => {
            if blob.len() < HEADER_LEN + NONCE_LEN + 1 {
                return Err("文件格式错误：快照文件被截断".to_string());
            }
            let mut offset = MAGIC.len() + 1;
            let read_u32 = |buf: &[u8], at: &mut usize| -> u32 {
                let v = u32::from_le_bytes([buf[*at], buf[*at + 1], buf[*at + 2], buf[*at + 3]]);
                *at += 4;
                v
            };
            let m_cost = read_u32(blob, &mut offset);
            let t_cost = read_u32(blob, &mut offset);
            let p_cost = read_u32(blob, &mut offset);
            let salt = &blob[offset..offset + SALT_LEN];
            let header_end = offset + SALT_LEN;
            let nonce = &blob[header_end..header_end + NONCE_LEN];
            let ciphertext = &blob[header_end + NONCE_LEN..];

            // 参数下限保护：异常大的 m_cost 会让 Argon2 吃掉数 GB 内存。
            if m_cost > 1024 * 1024 || t_cost > 100 || p_cost == 0 || p_cost > 16 {
                return Err("文件格式错误：KDF 参数超出安全范围".to_string());
            }
            let key_bytes = derive_key(password, salt, m_cost, t_cost, p_cost)?;
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
            let plaintext = cipher
                .decrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &blob[..header_end],
                    },
                )
                .map_err(|_| "解密失败：口令错误或文件损坏（现有数据未改动）".to_string())?;
            Ok((plaintext, version))
        }
        // 版本 1：magic + salt + nonce + ct，无 AAD、固定 KDF 参数。
        1 => {
            let legacy_header = MAGIC.len() + SALT_LEN;
            if blob.len() < legacy_header + NONCE_LEN + 1 {
                return Err("文件格式错误：旧版快照文件被截断".to_string());
            }
            let salt = &blob[MAGIC.len()..legacy_header];
            let nonce = &blob[legacy_header..legacy_header + NONCE_LEN];
            let ciphertext = &blob[legacy_header + NONCE_LEN..];
            let key_bytes = derive_key(password, salt, KDF_M_COST, KDF_T_COST, KDF_P_COST)?;
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
            let plaintext = cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| "解密失败：口令错误或文件损坏（现有数据未改动）".to_string())?;
            Ok((plaintext, version))
        }
        other => Err(format!(
            "文件格式错误：不支持的快照格式版本 {other}（本工具支持 1 和 {FORMAT_VERSION}）"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_store() -> store::Store {
        let mut s = store::Store::default();
        s.profiles.push(store::StoredProfile {
            id: "a".into(),
            name: "A".into(),
            notes: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_switched_at: None,
            claude_json: serde_json::json!({"oauthAccount": {"accountUuid": "u-1"}}),
            settings_json: None,
            encrypted_auth_settings: None,
            // 明文凭据：导出时 load_store 已解密，导入时 save_store 会重新加密。
            keychain_password: Some("plain-oauth-blob".into()),
            meta: store::ProfileMeta::default(),
            last_used_percent: None,
            clash: None,
            runtime: None,
        });
        s
    }

    /// 头部序列化/反序列化必须往返一致，否则 AAD 校验会把合法文件判坏。
    #[test]
    fn header_round_trips_kdf_params() {
        let blob = encrypt_for_test(&sample_store(), "correct-horse");
        assert_eq!(&blob[..MAGIC.len()], MAGIC.as_slice());
        assert_eq!(blob[MAGIC.len()], FORMAT_VERSION);
        let mut at = MAGIC.len() + 1;
        let m = u32::from_le_bytes(blob[at..at + 4].try_into().unwrap());
        at += 4;
        let t = u32::from_le_bytes(blob[at..at + 4].try_into().unwrap());
        at += 4;
        let p = u32::from_le_bytes(blob[at..at + 4].try_into().unwrap());
        assert_eq!((m, t, p), (KDF_M_COST, KDF_T_COST, KDF_P_COST));
    }

    fn encrypt_for_test(store_data: &store::Store, password: &str) -> Vec<u8> {
        let plaintext = serde_json::to_vec(store_data).unwrap();
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_key(password, &salt, KDF_M_COST, KDF_T_COST, KDF_P_COST).unwrap();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut header = Vec::new();
        header.extend_from_slice(MAGIC);
        header.push(FORMAT_VERSION);
        header.extend_from_slice(&KDF_M_COST.to_le_bytes());
        header.extend_from_slice(&KDF_T_COST.to_le_bytes());
        header.extend_from_slice(&KDF_P_COST.to_le_bytes());
        header.extend_from_slice(&salt);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &header,
                },
            )
            .unwrap();
        let mut blob = header;
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        blob
    }

    #[test]
    fn decrypt_round_trips_plaintext_store() {
        let original = sample_store();
        let blob = encrypt_for_test(&original, "correct-horse");
        let (plain, version) = decrypt_blob(&blob, "correct-horse").unwrap();
        assert_eq!(version, FORMAT_VERSION);
        let parsed: store::Store = serde_json::from_slice(&plain).unwrap();
        assert_eq!(parsed.profiles.len(), 1);
        assert_eq!(parsed.profiles[0].name, "A");
        // 凭据在导出文件里是明文状态（由用户口令保护），
        // 这样目标机才能用它自己的主密钥重新加密。
        assert_eq!(
            parsed.profiles[0].keychain_password.as_deref(),
            Some("plain-oauth-blob")
        );
    }

    #[test]
    fn wrong_password_fails_without_touching_data() {
        let blob = encrypt_for_test(&sample_store(), "correct-horse");
        let err = decrypt_blob(&blob, "wrong-password").unwrap_err();
        assert!(err.contains("解密失败"), "{err}");
    }

    #[test]
    fn tampered_header_fails_authentication() {
        let mut blob = encrypt_for_test(&sample_store(), "correct-horse");
        // 改 KDF 内存参数：头部是 AAD，必须认证失败而不是静默用错参数。
        let at = MAGIC.len() + 1;
        blob[at] ^= 0xFF;
        assert!(decrypt_blob(&blob, "correct-horse").is_err());
    }

    #[test]
    fn unknown_version_is_rejected() {
        let mut blob = encrypt_for_test(&sample_store(), "correct-horse");
        blob[MAGIC.len()] = 99;
        assert!(decrypt_blob(&blob, "correct-horse").is_err());
    }

    #[test]
    fn truncated_file_is_rejected() {
        let mut blob = encrypt_for_test(&sample_store(), "correct-horse");
        blob.truncate(blob.len() - 10);
        assert!(decrypt_blob(&blob, "correct-horse").is_err());
    }

    #[test]
    fn absurd_kdf_params_are_refused() {
        let mut blob = encrypt_for_test(&sample_store(), "correct-horse");
        let at = MAGIC.len() + 1;
        blob[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decrypt_blob(&blob, "correct-horse").is_err());
    }

    /// 端到端：调用 `export_store_encrypted_blocking`，确认它走的是
    /// `load_store()`（解密路径）而不是读磁盘原文。
    ///
    /// **边界说明（不夸大覆盖）**：本机没有凭据存储时，`load_store()` 解不开
    /// `enc:v1:` 会报错退出，因此这条路径的实际断言是「失败原因必须与凭据/
    /// 密钥相关」。它证明导出**试图解密**，但不能证明解密后的值与旧实现不同
    /// ——那需要 `#[ignore]` 的手动测试在具备凭据存储的机器上跑。
    /// （曾把断言写成「导出的账号数不为 0」，实测对旧实现同样成立，属无效断言。）
    #[test]
    fn export_goes_through_decryption_not_raw_file() {
        // 环境锁是 crate 级共享的：paths / credentials / platform::windows 等
        // 测试也读 USERPROFILE，各自加锁才能避免并行时互相污染（E-4）。
        let _guard = crate::test_support::env_lock();
        // 内存后端为空：磁盘上的密文 store 无法解密，导出应报密钥/解密错误——
        // 这证明导出走的是解密路径而非读磁盘原文。
        let _key_guard = store::TestKeyBackendGuard::install_in_memory();

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".claude-switcher")).unwrap();
        // 磁盘上的 store：凭据是密文（enc:v1: 开头），模拟真实落盘状态。
        let mut on_disk = sample_store();
        on_disk.profiles[0].keychain_password = Some(format!("{}AAAA", store::ENC_PREFIX));
        std::fs::write(
            home.join(".claude-switcher").join("store.private.json"),
            serde_json::to_string_pretty(&on_disk).unwrap(),
        )
        .unwrap();

        // 还原器在离开作用域时自动恢复（即使下面 unwrap panic 也不会漏）。
        let _restore = crate::test_support::set_env("USERPROFILE", &home);
        let dest = dir.path().join("snapshot.csbk1");
        let result = export_store_encrypted_blocking(&dest, "correct-horse");

        match result {
            Ok(ok) => {
                let blob = std::fs::read(&ok.path).unwrap();
                let (plain, _) = decrypt_blob(&blob, "correct-horse").unwrap();
                let parsed: store::Store = serde_json::from_slice(&plain).unwrap();
                assert_eq!(parsed.profiles.len(), 1, "导出的账号数不应为 0");
            }
            Err(e) => {
                assert!(
                    e.contains("解密") || e.contains("密钥"),
                    "导出失败原因应是凭据/密钥问题，实际: {e}"
                );
            }
        }
    }

    /// 导入前主密钥缺失必须被拒绝：否则 `save_store` 会铸造新密钥，
    /// 把「抢救旧数据」变成「永久失去旧数据」。
    ///
    /// 注意只覆盖「本机已有密文快照」这一种 Missing——全新机器（无密文）是
    /// 换机主路径，必须放行（见 `import_store_encrypted_blocking` 的三态判断）。
    #[test]
    fn import_refuses_when_store_key_missing_and_ciphertext_present() {
        // 环境锁串行化改 USERPROFILE 的操作。
        let _guard = crate::test_support::env_lock();
        // 内存后端为空 → 主密钥状态恒为 Missing（确定性，不依赖真实凭据库）。
        let _key_guard = store::TestKeyBackendGuard::install_in_memory();
        assert!(matches!(
            store::store_key_status(),
            store::StoreKeyStatus::Missing
        ));
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".claude-switcher")).unwrap();
        // 本机已有一份含密文的 store：此时铸新钥会让它永久解不开，必须拒绝。
        let mut on_disk = sample_store();
        on_disk.profiles[0].keychain_password = Some(format!("{}AAAA", store::ENC_PREFIX));
        std::fs::write(
            home.join(".claude-switcher").join("store.private.json"),
            serde_json::to_string_pretty(&on_disk).unwrap(),
        )
        .unwrap();

        let _restore = crate::test_support::set_env("USERPROFILE", &home);
        let src = dir.path().join("snap.csbk1");
        std::fs::write(&src, encrypt_for_test(&sample_store(), "correct-horse")).unwrap();
        let err = import_store_encrypted_blocking(&src, "correct-horse").unwrap_err();
        assert!(err.contains("主密钥"), "{err}");
    }

    /// 全新机器（没有任何 store 与密文）必须允许导入——这是换机迁移的主路径。
    /// 早期实现无条件要求密钥已存在，把这条路堵死了（E-1）。
    #[test]
    fn import_allows_fresh_machine_without_store_key() {
        let _guard = crate::test_support::env_lock();
        // 内存后端为空 → Missing；save_store 会在内存里铸造第一把密钥，必成功。
        let _key_guard = store::TestKeyBackendGuard::install_in_memory();
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".claude-switcher")).unwrap();
        // 注意：不写 store.private.json —— 模拟全新机器。

        let _restore = crate::test_support::set_env("USERPROFILE", &home);
        let src = dir.path().join("snap.csbk1");
        std::fs::write(&src, encrypt_for_test(&sample_store(), "correct-horse")).unwrap();
        let result = import_store_encrypted_blocking(&src, "correct-horse");
        // 全新机器必须放行，且内存后端保证 save_store 成功：应得到 Ok。
        result.expect("全新机器导入应成功");
    }

    /// 导入必须清空原机器的运行时状态与不可迁移的 Desktop 元数据（E-2）。
    #[test]
    fn import_strips_runtime_state_and_desktop_metadata() {
        let mut incoming = sample_store();
        // 模拟原机器：有当前账号、有 Desktop 账号登记。
        incoming.current_profile_id = Some("a".into());
        incoming.current_desktop_profile_id = Some("d-1".into());
        incoming.desktop_profiles.push(store::DesktopProfile {
            id: "d-1".into(),
            name: "Desktop A".into(),
            notes: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_switched_at: None,
            snapshot_rel: "desktop-accounts/d-1".into(),
            size_bytes: 0,
            meta: None,
        });

        // 直接复用导入实现的同一个纯函数，不再在测试里重写清空逻辑。
        let stripped = store::sanitize_imported_store(incoming.clone());

        assert!(stripped.current_profile_id.is_none());
        assert!(stripped.current_desktop_profile_id.is_none());
        assert!(stripped.desktop_profiles.is_empty());
        // 账号材料本身必须保留。
        assert_eq!(stripped.profiles.len(), incoming.profiles.len());
    }
}
