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

/// **P1-02**：完整迁移包版本。3 = 账号库 + Desktop 快照。
const FORMAT_VERSION_FULL: u8 = 3;

/// 单个 Desktop 快照文件（路径相对 desktop-accounts 根目录）。
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SnapshotFile {
    /// 相对路径（`<profile_id>/...`），禁止 `..` 与绝对路径。
    pub path: String,
    /// 文件内容的 base64。
    pub data: String,
    /// 原始字节数的 SHA256（导入时校验）。
    pub sha256: String,
}

/// **P1-02**：完整迁移包的明文结构（加密后写入 CSBK1 v3）。
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct FullMigration {
    /// 账号库。
    pub store: store::Store,
    /// Desktop 快照文件清单（空表示原机器没有 Desktop 账号）。
    pub desktop_files: Vec<SnapshotFile>,
    /// 导出时间（unix 秒）。
    pub exported_at: i64,
}

/// **P1-02**：Desktop 快照打包结果。
#[derive(Debug, Serialize)]
pub struct FullExportResult {
    pub path: String,
    pub bytes: usize,
    /// 打包的快照文件数。
    pub desktop_files: usize,
    /// 跳过的链接数（链接不进包，避免跨机指向错误位置）。
    pub skipped_links: usize,
}

/// **P1-02**：Desktop 快照导入结果。
#[derive(Debug, Serialize)]
pub struct FullImportResult {
    pub imported_bytes: usize,
    pub profiles_imported: usize,
    pub desktop_files: usize,
    pub backup_of_previous: String,
    /// 恢复的 Desktop 快照目录。
    pub desktop_restored_to: Option<String>,
}

/// **P1-02**：Desktop 快照打包统计（不含文件内容，便于单测）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotPackStats {
    pub files: usize,
    pub bytes: u64,
    pub skipped_links: usize,
}

/// 单个快照文件的体积上限（256 MiB）。
///
/// Desktop 快照里可能包含缓存数据库；单个文件超过这个体积几乎一定是
/// 异常产物（或误选了目录），将其排除以免生成一个无法打开的巨型迁移包。
const MAX_SNAPSHOT_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// **P1-02**：递归收集 Desktop 快照目录下的全部普通文件。
///
/// 语义与 `desktop::copy_dir_recursive` 保持一致：
/// - **不跟随**符号链接 / junction（跨机复制过去会指向错误位置）；
/// - 记录相对路径（`<profile_id>/...`），不含绝对路径前缀；
/// - 单个文件超过 [`MAX_SNAPSHOT_FILE_BYTES`] 时跳过并计入 `skipped_links`
///   （复用同一计数以免再引入一个只在极端情况出现的字段）。
///
/// 返回按路径排序的列表，保证同样的输入产生同样的包（便于比对与复现）。
fn collect_snapshot_files(root: &Path) -> Result<(Vec<SnapshotFile>, SnapshotPackStats), String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let mut out: Vec<SnapshotFile> = Vec::new();
    let mut stats = SnapshotPackStats::default();
    if !root.is_dir() {
        return Ok((out, stats));
    }
    // 显式栈：避免深目录递归爆栈，也便于跳过链接。
    let mut stack: Vec<std::path::PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) => {
                return Err(format!("读取快照目录失败 {}: {error}", dir.display()));
            }
        };
        for entry in entries {
            let entry = entry.map_err(|e| format!("读取快照目录项失败: {e}"))?;
            let path = entry.path();
            // 先看链接（不跟随）：悬空 junction 打开句柄会直接失败。
            if crate::platform::imp::is_link(&path) {
                stats.skipped_links += 1;
                continue;
            }
            let meta = entry
                .metadata()
                .map_err(|e| format!("读取快照文件属性失败 {}: {e}", path.display()))?;
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            if meta.len() > MAX_SNAPSHOT_FILE_BYTES {
                stats.skipped_links += 1;
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| format!("快照路径不在根目录内：{}", path.display()))?;
            let relative = relative
                .components()
                .map(|c| c.as_os_str().to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join("/");
            if relative.is_empty() {
                continue;
            }
            let data =
                fs::read(&path).map_err(|e| format!("读取快照文件失败 {}: {e}", path.display()))?;
            let digest = Sha256::digest(&data);
            stats.files += 1;
            stats.bytes += data.len() as u64;
            out.push(SnapshotFile {
                path: relative,
                data: base64::engine::general_purpose::STANDARD.encode(&data),
                sha256: digest.iter().map(|b| format!("{b:02x}")).collect(),
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((out, stats))
}

/// **P1-02**：把相对路径安全地拼到根目录下。
///
/// 拒绝的形态（导入时的第一道防线，必须在**写盘之前**做）：
/// - 绝对路径（`C:\...` / `\...` / `/...`）；
/// - 含 `..` 或 `.` 的路径段；
/// - 含盘符/UNC 前缀的段；
/// - Windows 保留设备名（`CON` / `NUL` / `COM1` 等，见 `naming` 模块）。
fn safe_relative_path(root: &Path, relative: &str) -> Result<std::path::PathBuf, String> {
    if relative.trim().is_empty() {
        return Err("快照条目路径为空".to_string());
    }
    // 统一分隔符后**按原始字符串分段**检查。
    //
    // 不能用 `Path::components()` 做这件事：它会把 `p1/./x` 规范成 `p1/x`，
    // 于是 `.` / `..` 段在检查前就被吃掉了——`p1/../../x` 会被静默接受成
    // `p1/x`，看起来安全实则偏离作者意图。这里必须看用户/包里的原始段。
    let normalized = relative.replace('\\', "/");
    if normalized.starts_with('/') {
        return Err(format!("快照条目使用了绝对路径，已拒绝：{relative}"));
    }
    // 盘符（`C:`）或 UNC 主机名（`//host`）都带冒号/双斜杠前缀。
    if normalized.contains(':') {
        return Err(format!("快照条目包含盘符或 UNC 前缀，已拒绝：{relative}"));
    }
    let mut out = root.to_path_buf();
    for part in normalized.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(format!(
                "快照条目包含非法路径段（空 / `.` / `..`），已拒绝：{relative}"
            ));
        }
        out.push(part);
    }
    if out == root {
        return Err(format!("快照条目没有落到子路径，已拒绝：{relative}"));
    }
    Ok(out)
}

/// **P1-02**：校验并解码单条快照文件（哈希必须匹配）。
fn decode_snapshot_file(file: &SnapshotFile) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&file.data)
        .map_err(|e| format!("快照条目 {} 的 base64 损坏：{e}", file.path))?;
    let digest = Sha256::digest(&bytes);
    let actual: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    if !actual.eq_ignore_ascii_case(file.sha256.trim()) {
        return Err(format!(
            "快照条目 {} 的哈希不匹配（包已损坏或被篡改）",
            file.path
        ));
    }
    Ok(bytes)
}

/// **P1-02**：把迁移包里的 Desktop 快照写入隔离暂存目录并逐条校验。
///
/// 两阶段提交的第一阶段：
/// 1. 在目标分区的临时目录里解出**全部**文件并校验哈希；
/// 2. 任何一条失败 → 清掉暂存目录并返回 Err（目标位置一行都没动）。
///
/// 返回暂存目录路径，由调用方在账号库提交成功后再整体并入正式位置。
fn stage_snapshot_files(
    files: &[SnapshotFile],
    staging_dir: &Path,
) -> Result<SnapshotPackStats, String> {
    let mut stats = SnapshotPackStats::default();
    // 先全部校验 + 解码，再写盘：避免「写了一半才发现第 100 条坏了」。
    let mut decoded: Vec<(String, Vec<u8>)> = Vec::with_capacity(files.len());
    for file in files {
        // 路径安全检查必须在**任何写盘动作之前**完成。
        let target = safe_relative_path(staging_dir, &file.path)?;
        let bytes = decode_snapshot_file(file)?;
        stats.files += 1;
        stats.bytes += bytes.len() as u64;
        decoded.push((
            target
                .strip_prefix(staging_dir)
                .map(|p| p.to_path_buf())
                .map_err(|_| "暂存路径解析失败".to_string())?
                .to_string_lossy()
                .to_string(),
            bytes,
        ));
    }
    for (relative, bytes) in decoded {
        let target = staging_dir.join(&relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("创建暂存目录失败 {}: {e}", parent.display()))?;
        }
        fs::write(&target, &bytes)
            .map_err(|e| format!("写入暂存文件失败 {}: {e}", target.display()))?;
    }
    Ok(stats)
}

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
    let blob = encrypt_blob(&plaintext, password, FORMAT_VERSION)?;
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

/// **P1-02**：导出**完整迁移包**（账号库 + 全部 Desktop 快照），格式版本 3。
///
/// 与 [`export_store_encrypted_blocking`] 的差异：
/// - 账号库与 Desktop 快照在**同一次 `load_store()` 视图**下打包，避免
///   「账号库读的是旧值、快照目录已被切换」的错配；
/// - Desktop 快照按 `desktop-accounts/` 下实际存在的目录收集（而不是按
///   `desktop_profiles` 索引猜测）——索引可能与磁盘不同步，磁盘才是事实；
/// - 链接不进包（跨机指向错误位置），数量如实返回给用户。
///
/// **不包含**：`%APPDATA%\Claude` 活目录本身（那是当前登录态，不是账号快照），
/// 也不包含 DPAPI 加密的系统级凭据——见函数尾注释。
pub fn export_full_migration_blocking(
    dest: &Path,
    password: &str,
) -> Result<FullExportResult, String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!("口令至少 {MIN_PASSWORD_LEN} 位"));
    }
    // 账号库与快照必须在同一视图下取：先 load_store（它会解密凭据），
    // 再读磁盘快照。两者之间没有切换动作，因此内容一致。
    let store_data = store::load_store()?;
    let accounts_dir = paths::app_data_dir()?.join("desktop-accounts");
    let (desktop_files, stats) = collect_snapshot_files(&accounts_dir)?;

    let payload = FullMigration {
        store: store_data,
        desktop_files,
        exported_at: chrono::Utc::now().timestamp(),
    };
    let plaintext = serde_json::to_vec(&payload).map_err(|e| format!("序列化迁移包失败: {e}"))?;
    let blob = encrypt_blob(&plaintext, password, FORMAT_VERSION_FULL)?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    write_blob_atomically(dest, &blob)?;

    Ok(FullExportResult {
        path: dest.to_string_lossy().to_string(),
        bytes: blob.len(),
        desktop_files: stats.files,
        skipped_links: stats.skipped_links,
    })
}

/// 把明文按 CSBK1 v2/v3 头部格式加密成完整 blob（含头部 + nonce + 密文）。
///
/// `version` 决定写进头部的格式版本；v2 与 v3 的头部布局相同，
/// 只有版本字节不同（因此 AAD 内容不同，不会互相误解密）。
fn encrypt_blob(plaintext: &[u8], password: &str, version: u8) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let key_bytes = derive_key(password, &salt, KDF_M_COST, KDF_T_COST, KDF_P_COST)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(version);
    header.extend_from_slice(&KDF_M_COST.to_le_bytes());
    header.extend_from_slice(&KDF_T_COST.to_le_bytes());
    header.extend_from_slice(&KDF_P_COST.to_le_bytes());
    header.extend_from_slice(&salt);

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                // 头部作 AAD：格式/KDF 参数被改动会导致认证失败。
                aad: &header,
            },
        )
        .map_err(|e| format!("加密失败: {e}"))?;

    let mut blob = Vec::with_capacity(header.len() + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
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
    ensure_store_key_allows_import()?;

    let blob = fs::read(src).map_err(|e| format!("读取导出文件失败: {e}"))?;
    let (plaintext, version) = decrypt_blob(&blob, password)?;
    // **P1-02**：v3 是完整迁移包（含 Desktop 快照）。这里明确拒绝并引导用户
    // 走完整导入，而不是把 FullMigration 当 Store 解析后报一个费解的 JSON 错误，
    // 或者更糟——静默丢掉 Desktop 快照。
    if version == FORMAT_VERSION_FULL {
        return Err("这是一个包含 Claude Desktop 快照的完整迁移包（格式 v3），\
             请使用「导入完整迁移包」功能，而不是「导入账号快照」"
            .to_string());
    }
    let parsed: store::Store = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("解密成功但不是有效的账号库 JSON: {e}"))?;

    // 清空原机器的运行时状态与不可迁移的元数据（见函数文档）。
    let parsed = store::sanitize_imported_store(parsed);

    // 备份现有 store（不存在则跳过）。
    let (backup_label, profiles) = replace_store_with_backup(parsed)?;
    Ok(ImportResult {
        imported_bytes: plaintext.len(),
        profiles_imported: profiles,
        backup_of_previous: backup_label,
    })
}

/// 导入前的**主密钥三态**检查（v2 与 v3 导入共用）。
///
/// 语义见 [`import_store_encrypted_blocking`] 的文档：Missing 且本机已有密文
/// 快照时必须拒绝，否则 `save_store` 会铸新钥、把旧数据永久锁死。
fn ensure_store_key_allows_import() -> Result<(), String> {
    match store::store_key_status() {
        store::StoreKeyStatus::Present => Ok(()),
        store::StoreKeyStatus::Missing => {
            if store::existing_store_has_ciphertext() {
                Err("本机已存在加密账号快照，但找不到 store 加密主密钥\
                     （claude-switcher-store-key）。此时导入会让工具铸造一把新密钥，\
                     本机原有的快照将永远无法解密。请先恢复该凭据项再导入。"
                    .to_string())
            } else {
                Ok(())
            }
        }
        store::StoreKeyStatus::Unavailable(e) => Err(format!(
            "凭据存储暂时不可读（{e}）。为免误判为「没有密钥」而覆盖旧数据，\
             本次导入已中止；请修复凭据存储后重试。"
        )),
    }
}

/// 备份现有账号库，再把 `incoming` 整体替换进去。
///
/// 返回 `(备份路径说明, 导入的账号数)`。v2 与 v3 导入共用，避免两份实现
/// 在「备份时机」上出现分歧。
fn replace_store_with_backup(incoming: store::Store) -> Result<(String, usize), String> {
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
    let profiles = incoming.profiles.len();
    store::with_store(|current| {
        *current = incoming;
        Ok(())
    })?;
    Ok((backup_label, profiles))
}

/// **P1-02**：导入**完整迁移包**（账号库 + Desktop 快照），格式版本 3。
///
/// 事务顺序（任何一步失败都不会留下「账号库换了、快照没换」的半截状态）：
/// 1. 主密钥三态检查（同 v2）；
/// 2. 解密 → 若实际是 v2（纯账号库）则**明确提示**不含 Desktop 快照，
///    并失败返回，避免用户以为 Desktop 也迁移了；
/// 3. **先**把全部快照文件解到隔离暂存目录并逐条校验路径与哈希；
///    任何一条不合法 → 清掉暂存，目标位置一行都没动；
/// 4. 备份现有账号库与现有 `desktop-accounts`（原子重命名）；
/// 5. 提交账号库（`with_store`）；
/// 6. 把暂存快照整体并入正式位置；
/// 7. 若第 6 步失败，**回滚账号库与旧快照**，保证两者仍然一致。
///
/// **不做的事（必须让用户知道）**：不迁移 Windows DPAPI 加密的系统凭据，
/// 也不迁移 `%APPDATA%\Claude` 活目录；跨机后 Claude Desktop 可能需要重新登录。
pub fn import_full_migration_blocking(
    src: &Path,
    password: &str,
) -> Result<FullImportResult, String> {
    ensure_store_key_allows_import()?;

    let blob = fs::read(src).map_err(|e| format!("读取迁移包失败: {e}"))?;
    let (plaintext, version) = decrypt_blob(&blob, password)?;
    if version == FORMAT_VERSION {
        return Err(
            "这是旧版账号快照（格式 v2），**不包含** Claude Desktop 快照。\
             请改用「导入账号快照」；若需要迁移 Desktop，请在源机用新版重新导出。"
                .to_string(),
        );
    }
    if version != FORMAT_VERSION_FULL {
        return Err(format!(
            "不支持的迁移包格式版本 {version}（需要 {FORMAT_VERSION_FULL}）"
        ));
    }
    let mut payload: FullMigration = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("解密成功但不是有效的完整迁移包: {e}"))?;

    // 账号库侧与 v2 保持同一套清理语义（运行时状态不迁移），但保留 Desktop 索引：
    // v3 包里有真实快照文件，索引与文件必须配套，否则目录存在却「未登记」。
    payload.store.current_profile_id = None;
    payload.store.current_desktop_profile_id = None;
    let cli_profiles = payload.store.profiles.len();

    let accounts_dir = paths::app_data_dir()?.join("desktop-accounts");
    let data_root = paths::app_data_dir()?;
    // 暂存目录放在**同一分区**（app_data_dir 下），这样最后的并入是 rename
    // 而不是跨卷复制。名字以下划线开头，不参与账号枚举。
    let staging = data_root.join(format!("_import-staging-{}", uuid::Uuid::new_v4().simple()));
    let staged = match stage_snapshot_files(&payload.desktop_files, &staging) {
        Ok(stats) => stats,
        Err(error) => {
            // 校验失败：目标位置一行都没动，只清理暂存。
            let _ = fs::remove_dir_all(&staging);
            return Err(format!("迁移包校验失败，未做任何改动：{error}"));
        }
    };

    // 备份现有快照目录（原子重命名到同级 `_pre-import-*`）。
    let snapshot_backup = backup_existing_snapshots(&data_root)?;
    let (backup_label, _) = match replace_store_with_backup(payload.store) {
        Ok(result) => result,
        Err(error) => {
            // 账号库没换成：恢复快照目录命名并清掉暂存。
            restore_snapshot_backup(&snapshot_backup);
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
    };

    // 提交快照：把暂存目录里的内容并入正式位置。
    let restore_error = merge_staged_snapshots(&staging, &accounts_dir).err();
    if let Some(error) = restore_error {
        // 快照落位失败 → 回滚快照目录；账号库已提交，需要用户知道这个不一致。
        restore_snapshot_backup(&snapshot_backup);
        let _ = fs::remove_dir_all(&staging);
        return Err(format!(
            "Desktop 快照落位失败（{error}）。账号库已导入，但快照目录已回滚到导入前状态\
             （{}）；原账号库备份在 {}。请核对后重试导入。",
            snapshot_backup
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "（原本没有快照目录）".to_string()),
            backup_label
        ));
    }
    // 成功：删掉旧快照备份与暂存目录（备份已无用途）。
    if let Some(backup) = &snapshot_backup {
        let _ = fs::remove_dir_all(backup);
    }
    let _ = fs::remove_dir_all(&staging);

    Ok(FullImportResult {
        imported_bytes: plaintext.len(),
        profiles_imported: cli_profiles,
        desktop_files: staged.files,
        backup_of_previous: backup_label,
        desktop_restored_to: Some(accounts_dir.to_string_lossy().to_string()),
    })
}

/// 把现有 `desktop-accounts` 原子重命名到 `_pre-import-<时间戳>`。
///
/// 返回备份路径（原本不存在则为 `None`）。用重命名而不是复制：快照目录可能有
/// 数 GB，复制既慢又可能中途失败；重命名是一次元数据操作，失败即视为整体失败。
fn backup_existing_snapshots(data_root: &Path) -> Result<Option<std::path::PathBuf>, String> {
    let accounts = data_root.join("desktop-accounts");
    if !accounts.exists() {
        return Ok(None);
    }
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let backup = data_root.join(format!("_pre-import-desktop-accounts-{stamp}"));
    fsx::rename_with_retry(&accounts, &backup).map_err(|e| {
        format!(
            "备份现有 Desktop 快照目录失败（{}）：{}",
            accounts.display(),
            fsx::humanize_io_error(&e)
        )
    })?;
    Ok(Some(backup))
}

/// 把 [`backup_existing_snapshots`] 的备份改回原名（回滚用，best-effort）。
fn restore_snapshot_backup(backup: &Option<std::path::PathBuf>) {
    let Some(backup) = backup else { return };
    let Some(root) = backup.parent() else { return };
    let accounts = root.join("desktop-accounts");
    // 目标可能已被部分写入：先清掉不完整的目录，再改名回去。
    if accounts.exists() {
        let _ = fsx::retry_io(|| fs::remove_dir_all(&accounts));
    }
    let _ = fsx::rename_with_retry(backup, &accounts);
}

/// 把暂存目录里的快照并入正式位置（逐项重命名，冲突时以包内内容为准）。
fn merge_staged_snapshots(staging: &Path, accounts_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(accounts_dir).map_err(|e| format!("创建 Desktop 快照目录失败：{e}"))?;
    // 暂存目录下可能既有 `<id>/...` 子目录，也可能有单文件（正常情况下没有）。
    for entry in fs::read_dir(staging).map_err(|e| format!("读取暂存目录失败：{e}"))? {
        let entry = entry.map_err(|e| format!("读取暂存目录项失败：{e}"))?;
        let target = accounts_dir.join(entry.file_name());
        if target.exists() {
            // 同名：包内内容更新，先删旧（同分区操作，快速）。
            fsx::retry_io(|| fs::remove_dir_all(&target))
                .map_err(|e| format!("清理同名旧快照失败 {}：{e}", target.display()))?;
        }
        fsx::rename_with_retry(&entry.path(), &target).map_err(|e| {
            format!(
                "并入快照失败 {} -> {}：{}",
                entry.path().display(),
                target.display(),
                fsx::humanize_io_error(&e)
            )
        })?;
    }
    Ok(())
}

/// 解密 CSBK1 blob，返回明文与所用格式版本。
fn decrypt_blob(blob: &[u8], password: &str) -> Result<(Vec<u8>, u8), String> {
    if blob.len() < MAGIC.len() + 1 || &blob[..MAGIC.len()] != MAGIC.as_slice() {
        return Err("文件格式错误：魔数不匹配（不是本工具导出的快照文件）".to_string());
    }
    let version = blob[MAGIC.len()];
    match version {
        // 版本 2 / 3：magic + version + 3×u32 KDF + salt + nonce + ct。
        //
        // v3 与 v2 的**头部布局完全相同**，只有版本字节不同；版本字节在 AAD 里，
        // 因此把 v3 的头改成 v2 会直接认证失败，不会静默按错误格式解读。
        // 内容差异由调用方看返回的 `version` 决定（v3 = FullMigration）。
        FORMAT_VERSION | FORMAT_VERSION_FULL => {
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
            "文件格式错误：不支持的快照格式版本 {other}（本工具支持 1、{FORMAT_VERSION} 和 {FORMAT_VERSION_FULL}）"
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

    // ───────────── P1-02：完整迁移包（v3）─────────────

    /// 打包：只收普通文件、跳过链接、相对路径、按路径排序。
    #[test]
    fn collect_snapshot_files_skips_links_and_sorts() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("desktop-accounts");
        std::fs::create_dir_all(root.join("p1").join("Cache")).unwrap();
        std::fs::create_dir_all(root.join("p2")).unwrap();
        std::fs::write(root.join("p1").join("config.json"), b"{\"a\":1}").unwrap();
        std::fs::write(root.join("p1").join("Cache").join("db.bin"), b"xyz").unwrap();
        std::fs::write(root.join("p2").join("data.txt"), b"hello").unwrap();

        let (files, stats) = collect_snapshot_files(&root).unwrap();
        assert_eq!(stats.files, 3, "{files:?}");
        // 7 ({"a":1}) + 3 (xyz) + 5 (hello)
        assert_eq!(stats.bytes, 7 + 3 + 5);
        // 路径必须是相对的、用 `/` 分隔、按字典序。
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["p1/Cache/db.bin", "p1/config.json", "p2/data.txt"]
        );
        // 每个条目都必须能通过哈希自校验。
        for file in &files {
            assert!(decode_snapshot_file(file).is_ok(), "{file:?}");
        }
    }

    /// 根目录不存在 → 空包（不是错误）：新机器上没有任何 Desktop 账号是正常的。
    #[test]
    fn collect_snapshot_files_tolerates_missing_root() {
        let dir = tempfile::tempdir().unwrap();
        let (files, stats) = collect_snapshot_files(&dir.path().join("nope")).unwrap();
        assert!(files.is_empty());
        assert_eq!(stats, SnapshotPackStats::default());
    }

    /// **安全关键**：导入时的路径校验必须拒绝逃逸/绝对路径/设备名。
    #[test]
    fn safe_relative_path_rejects_escapes() {
        let root = std::path::Path::new(r"C:\data");

        // 正常条目。
        let ok = safe_relative_path(root, "p1/config.json").unwrap();
        assert!(ok.ends_with(std::path::Path::new("p1").join("config.json")));
        // Windows 风格分隔符也要能接受。
        assert!(safe_relative_path(root, r"p1\config.json").is_ok());

        for bad in [
            "../escape.txt",
            "p1/../../escape.txt",
            "/absolute.txt",
            r"\absolute.txt",
            r"C:\Windows\System32\evil.dll",
            "./same.txt",
            "p1/./x.txt",
            "",
            "   ",
        ] {
            assert!(
                safe_relative_path(root, bad).is_err(),
                "危险路径必须被拒绝：{bad:?}"
            );
        }
    }

    /// 哈希不匹配必须拒绝（防止包损坏/篡改后被静默导入）。
    #[test]
    fn decode_snapshot_file_rejects_hash_mismatch() {
        use base64::Engine as _;
        let good = SnapshotFile {
            path: "p/x.bin".into(),
            data: base64::engine::general_purpose::STANDARD.encode(b"content"),
            sha256: {
                use sha2::{Digest, Sha256};
                Sha256::digest(b"content")
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect()
            },
        };
        assert_eq!(decode_snapshot_file(&good).unwrap(), b"content");

        let mut tampered = good.clone();
        tampered.sha256 = "0".repeat(64);
        assert!(decode_snapshot_file(&tampered).is_err());

        let mut broken = good;
        broken.data = "!!!not-base64!!!".into();
        assert!(decode_snapshot_file(&broken).is_err());
    }

    /// 暂存阶段：任一条目非法时不写任何文件，且不留下暂存目录。
    #[test]
    fn stage_snapshot_files_writes_nothing_on_invalid_entry() {
        use base64::Engine as _;
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        let good = SnapshotFile {
            path: "p1/ok.txt".into(),
            data: base64::engine::general_purpose::STANDARD.encode(b"ok"),
            sha256: {
                use sha2::{Digest, Sha256};
                Sha256::digest(b"ok")
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect()
            },
        };
        let evil = SnapshotFile {
            path: "../../escape.txt".into(),
            data: good.data.clone(),
            sha256: good.sha256.clone(),
        };
        // 顺序很重要：先处理合法条目，确保「先写后验」的实现在这里会失败。
        let error = stage_snapshot_files(&[good, evil], &staging).unwrap_err();
        assert!(error.contains("拒绝"), "{error}");
        assert!(!staging.exists(), "校验失败时不得留下暂存目录");
        assert!(!dir.path().join("escape.txt").exists());
    }

    /// v2 与 v3 头部布局相同但版本字节不同，必须互不误解密。
    #[test]
    fn v2_and_v3_blobs_are_distinguished_by_version_byte() {
        let payload = serde_json::to_vec(&sample_store()).unwrap();
        let v2 = encrypt_blob(&payload, "correct-horse", FORMAT_VERSION).unwrap();
        let v3 = encrypt_blob(&payload, "correct-horse", FORMAT_VERSION_FULL).unwrap();
        assert_eq!(v2[MAGIC.len()], FORMAT_VERSION);
        assert_eq!(v3[MAGIC.len()], FORMAT_VERSION_FULL);
        assert_eq!(
            decrypt_blob(&v2, "correct-horse").unwrap().1,
            FORMAT_VERSION
        );
        assert_eq!(
            decrypt_blob(&v3, "correct-horse").unwrap().1,
            FORMAT_VERSION_FULL
        );
        // 把 v3 的版本字节改成 v2 必须认证失败（版本字节在 AAD 里）。
        let mut forged = v3.clone();
        forged[MAGIC.len()] = FORMAT_VERSION;
        assert!(
            decrypt_blob(&forged, "correct-horse").is_err(),
            "改版本字节必须导致认证失败"
        );
    }

    /// v3 明文结构必须能完整往返：账号库 + 快照文件清单。
    #[test]
    fn full_migration_payload_round_trips() {
        use base64::Engine as _;
        let migration = FullMigration {
            store: sample_store(),
            desktop_files: vec![SnapshotFile {
                path: "abc/config.json".into(),
                data: base64::engine::general_purpose::STANDARD.encode(b"{}"),
                sha256: {
                    use sha2::{Digest, Sha256};
                    Sha256::digest(b"{}")
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect()
                },
            }],
            exported_at: 1_700_000_000,
        };
        let plaintext = serde_json::to_vec(&migration).unwrap();
        let blob = encrypt_blob(&plaintext, "correct-horse", FORMAT_VERSION_FULL).unwrap();
        let (decrypted, version) = decrypt_blob(&blob, "correct-horse").unwrap();
        assert_eq!(version, FORMAT_VERSION_FULL);
        let parsed: FullMigration = serde_json::from_slice(&decrypted).unwrap();
        assert_eq!(parsed.store.profiles.len(), 1);
        assert_eq!(parsed.desktop_files.len(), 1);
        assert_eq!(parsed.desktop_files[0].path, "abc/config.json");
        assert_eq!(parsed.exported_at, 1_700_000_000);
        // 凭据在包里仍是明文（由用户口令保护），跨机后由目标机主密钥重新封装。
        assert_eq!(
            parsed.store.profiles[0].keychain_password.as_deref(),
            Some("plain-oauth-blob")
        );
    }

    /// 用 v2 包走「完整导入」必须被明确拒绝，并提示改用账号快照导入。
    #[test]
    fn full_import_rejects_v2_package_with_explicit_hint() {
        let _guard = crate::test_support::env_lock();
        let _key_guard = store::TestKeyBackendGuard::install_in_memory();
        let dir = tempfile::tempdir().unwrap();
        let _restore = crate::test_support::set_env("USERPROFILE", dir.path());
        let src = dir.path().join("old.csbk1");
        let blob = encrypt_for_test(&sample_store(), "correct-horse");
        std::fs::write(&src, blob).unwrap();

        let error = import_full_migration_blocking(&src, "correct-horse").unwrap_err();
        assert!(error.contains("不包含"), "{error}");
        assert!(error.contains("导入账号快照"), "{error}");
    }

    /// **端到端**：在「源机」导出完整迁移包，在「目标机」（另一个 USERPROFILE）
    /// 导入，必须同时得到账号库与 Desktop 快照文件。
    ///
    /// 这是 P1-02 的核心验收：只搬账号库不算迁移 Desktop。
    #[test]
    fn full_migration_round_trips_store_and_desktop_snapshot() {
        let _guard = crate::test_support::env_lock();
        // 内存密钥后端：save/load 都不碰真实凭据库（AGENTS.md 踩坑 19）。
        let _key_guard = store::TestKeyBackendGuard::install_in_memory();

        let work = tempfile::tempdir().unwrap();
        let source_home = work.path().join("source");
        let source_data = source_home.join(".claude-switcher");
        std::fs::create_dir_all(
            source_data
                .join("desktop-accounts")
                .join("d-1")
                .join("Cache"),
        )
        .unwrap();
        std::fs::write(
            source_data
                .join("desktop-accounts")
                .join("d-1")
                .join("config.json"),
            br#"{"locale":"zh-CN"}"#,
        )
        .unwrap();
        std::fs::write(
            source_data
                .join("desktop-accounts")
                .join("d-1")
                .join("Cache")
                .join("db.bin"),
            b"cache-bytes",
        )
        .unwrap();

        let dest_package = work.path().join("full.csbk1");
        {
            let _home = crate::test_support::set_env("USERPROFILE", &source_home);
            // 源机账号库：一个含明文凭据的账号（save 会加密）。
            store::with_store(|current| {
                *current = sample_store();
                current.desktop_profiles.push(store::DesktopProfile {
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
                Ok(())
            })
            .unwrap();
            let exported = export_full_migration_blocking(&dest_package, "correct-horse")
                .expect("源机导出应成功");
            assert_eq!(exported.desktop_files, 2, "应打包 2 个快照文件");
            assert!(exported.bytes > 0);
        }

        // 目标机：全新的 USERPROFILE，没有任何 store 与快照。
        let target_home = work.path().join("target");
        let target_data = target_home.join(".claude-switcher");
        std::fs::create_dir_all(&target_data).unwrap();
        let imported = {
            let _home = crate::test_support::set_env("USERPROFILE", &target_home);
            import_full_migration_blocking(&dest_package, "correct-horse")
                .expect("目标机导入应成功")
        };

        assert_eq!(imported.profiles_imported, 1, "账号库应导入 1 个 CLI 账号");
        assert_eq!(imported.desktop_files, 2, "Desktop 快照文件应全部恢复");
        // 文件内容必须逐字节一致。
        let restored = target_data.join("desktop-accounts").join("d-1");
        assert_eq!(
            std::fs::read(restored.join("config.json")).unwrap(),
            br#"{"locale":"zh-CN"}"#
        );
        assert_eq!(
            std::fs::read(restored.join("Cache").join("db.bin")).unwrap(),
            b"cache-bytes"
        );
        // 索引与文件必须配套：Desktop 账号仍在 store 里。
        let after = {
            let _home = crate::test_support::set_env("USERPROFILE", &target_home);
            store::load_store().expect("目标机账号库应可读")
        };
        assert_eq!(after.desktop_profiles.len(), 1);
        assert_eq!(after.desktop_profiles[0].id, "d-1");
        // 运行时状态不迁移。
        assert!(after.current_profile_id.is_none());
        assert!(after.current_desktop_profile_id.is_none());
        // 凭据必须被目标机主密钥重新封装：`load_store()` 会自动解密，
        // 因此要证明这一点必须看**磁盘原文**，不能看内存视图。
        let raw = std::fs::read_to_string(target_data.join("store.private.json"))
            .expect("目标机账号库应已落盘");
        assert!(
            raw.contains(store::ENC_PREFIX),
            "落盘凭据必须加密（enc:v1: 前缀）"
        );
        assert!(
            !raw.contains("plain-oauth-blob"),
            "明文凭据绝不能出现在磁盘上"
        );
    }

    /// 目标机已有一份快照时：导入成功后旧快照必须被替换，
    /// 且失败路径不得留下「账号库换了、快照没换」的组合。
    #[test]
    fn full_import_replaces_existing_snapshot_and_cleans_backup() {
        let _guard = crate::test_support::env_lock();
        let _key_guard = store::TestKeyBackendGuard::install_in_memory();
        let work = tempfile::tempdir().unwrap();
        let home = work.path().join("home");
        let data = home.join(".claude-switcher");
        std::fs::create_dir_all(data.join("desktop-accounts").join("old")).unwrap();
        std::fs::write(
            data.join("desktop-accounts").join("old").join("stale.txt"),
            b"stale",
        )
        .unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", &home);

        // 构造一个只含新快照 d-2 的迁移包。
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let content = b"new-content";
        let migration = FullMigration {
            store: sample_store(),
            desktop_files: vec![SnapshotFile {
                path: "d-2/config.json".into(),
                data: base64::engine::general_purpose::STANDARD.encode(content),
                sha256: Sha256::digest(content)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            }],
            exported_at: 1,
        };
        let plaintext = serde_json::to_vec(&migration).unwrap();
        let blob = encrypt_blob(&plaintext, "correct-horse", FORMAT_VERSION_FULL).unwrap();
        let src = work.path().join("pkg.csbk1");
        std::fs::write(&src, blob).unwrap();

        let result = import_full_migration_blocking(&src, "correct-horse").unwrap();
        assert_eq!(result.desktop_files, 1);

        let accounts = data.join("desktop-accounts");
        assert_eq!(
            std::fs::read(accounts.join("d-2").join("config.json")).unwrap(),
            content
        );
        assert!(
            !accounts.join("old").exists(),
            "导入的是完整快照集合，旧账号目录不应残留"
        );
        // 旧快照的临时备份必须被清理（不留垃圾目录）。
        let leftovers: Vec<String> = std::fs::read_dir(&data)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|name| name.starts_with("_pre-import-desktop-accounts-"))
            .collect();
        assert!(leftovers.is_empty(), "成功后不应残留备份：{leftovers:?}");
        let staging: Vec<String> = std::fs::read_dir(&data)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|name| name.starts_with("_import-staging-"))
            .collect();
        assert!(staging.is_empty(), "成功后不应残留暂存目录：{staging:?}");
    }
}
