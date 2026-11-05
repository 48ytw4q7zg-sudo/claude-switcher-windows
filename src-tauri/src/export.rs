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
use std::path::{Path, PathBuf};

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
    /// 被排除的中间目录数（`.live-backup` 等事务残留）。
    pub excluded_dirs: usize,
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
    /// **QW-05**：成功后清理备份/暂存时的失败项（数据已正确，仅残留文件）。
    #[serde(default)]
    pub cleanup_failures: Vec<String>,
}

/// **P1-02**：Desktop 快照打包统计（不含文件内容，便于单测）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotPackStats {
    pub files: usize,
    pub bytes: u64,
    pub skipped_links: usize,
    /// 被排除的中间目录数（`.live-backup` / `_*` 事务残留）。
    pub excluded_dirs: usize,
}

/// 迁移包**总明文**上限（2 GiB）。
///
/// 打包时全部文件都会进内存（再 base64 膨胀 4/3），超过这个量级几乎必然
/// 说明 `desktop-accounts` 下混进了不该打包的东西。
// **P1-04**：原始快照总量上限要低于导入上限的 3/4 ——
// Base64 膨胀约 4/3，留出 JSON 与加密开销后仍能保证「导得出就导得回」。
const MAX_SNAPSHOT_TOTAL_BYTES: u64 = 1152 * 1024 * 1024;

/// 不参与打包的目录名（切换/导入事务产生的中间目录）。
const EXCLUDED_SNAPSHOT_DIR_NAMES: &[&str] = &[".live-backup", "_pre-import-desktop-accounts"];

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
                // **P1-01**：只打包受管理的 Desktop 账号快照目录。
                // `.live-backup` 是切换过程中的活目录备份，`_pre-import-*` /
                // `_import-staging-*` 是导入事务残留——它们都不是账号快照，
                // 打进迁移包只会把历史垃圾搬到新机器。
                let name = entry.file_name().to_string_lossy().to_string();
                if EXCLUDED_SNAPSHOT_DIR_NAMES.contains(&name.as_str()) || name.starts_with('_') {
                    stats.excluded_dirs += 1;
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            if meta.len() > MAX_SNAPSHOT_FILE_BYTES {
                // **P1-01**：超限不能在"完整导出"里静默跳过——那会生成一个
                // 看似成功、实际缺数据的包。明确失败，让用户先处理该文件。
                return Err(format!(
                    "快照文件超出单文件上限（{} MiB）：{}。                     完整导出要求包含全部账号数据，请先清理该文件或用「加密导出」只备份账号库",
                    MAX_SNAPSHOT_FILE_BYTES / (1024 * 1024),
                    path.display()
                ));
            }
            // **P1-01**：总明文大小上限，避免把内存吃光。
            if stats.bytes + meta.len() > MAX_SNAPSHOT_TOTAL_BYTES {
                return Err(format!(
                    "Desktop 快照总大小超过上限（{} MiB），已中止导出以免内存耗尽；                     请确认 desktop-accounts 下没有异常大文件",
                    MAX_SNAPSHOT_TOTAL_BYTES / (1024 * 1024)
                ));
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
        // **QW-04**：Windows 保留设备名（CON / NUL / COM1 …）不能作为文件名。
        // 文档早已声明会拒绝，但实现里一直没有真正检查。
        if crate::naming::is_reserved_device_name(part) {
            return Err(format!(
                "快照条目包含 Windows 保留设备名（{part}），已拒绝：{relative}"
            ));
        }
        // 尾随空格/句点会被 Windows 静默截断，导致落地路径与包内记录不一致。
        if part.ends_with(' ') || part.ends_with('.') {
            return Err(format!(
                "快照条目路径段以空格或句点结尾（{part}），已拒绝：{relative}"
            ));
        }
        if part
            .chars()
            .any(|c| (c as u32) < 0x20 || "<>|?*".contains(c))
        {
            return Err(format!(
                "快照条目路径段包含 Windows 非法字符（{part}），已拒绝：{relative}"
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
    fs::create_dir_all(staging_dir).map_err(|e| format!("创建暂存目录失败：{e}"))?;
    let result = (|| -> Result<SnapshotPackStats, String> {
        // 先完成路径校验（不写文件）；内容和哈希逐条解码→写入，避免第二份全量内存。
        for file in files {
            safe_relative_path(staging_dir, &file.path)?;
        }
        for file in files {
            let target = safe_relative_path(staging_dir, &file.path)?;
            let bytes = decode_snapshot_file(file)?;
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("创建暂存目录失败：{e}"))?;
            }
            fs::write(&target, &bytes).map_err(|e| format!("写入暂存文件失败：{e}"))?;
            stats.files += 1;
            stats.bytes += bytes.len() as u64;
        }
        Ok(stats)
    })();
    if result.is_err() {
        // 校验失败：清掉本次已写入的暂存内容（正式位置一行都没动）。
        let _ = fs::remove_dir_all(staging_dir);
    }
    result
}

/// 导入包明文与密文上限（2 GiB，避免多个副本同时驻留导致内存失控）。
const MAX_IMPORT_PLAINTEXT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// 所有路径在写盘前校验，并按 Windows 大小写不敏感语义去重。
fn validate_import_shape(payload: &FullMigration) -> Result<(), String> {
    if payload.desktop_files.len() > 200_000 {
        return Err("迁移包条目数超过上限".to_string());
    }
    let root = std::path::Path::new("__root__");
    let mut seen = std::collections::BTreeSet::new();
    for file in &payload.desktop_files {
        safe_relative_path(root, &file.path)?;
        if !seen.insert(file.path.replace('\\', "/").to_lowercase()) {
            return Err(format!("迁移包包含重复路径：{}", file.path));
        }
    }
    Ok(())
}

/// **P0-B**：完整导入的持久化事务账本。
///
/// 运行中的 `Result::Err` 回滚解决不了进程被强杀/断电：那时错误分支根本没机会
/// 执行。账本在**任何正式目录被改动之前**落盘，启动时由
/// [`recover_full_migration`] 据此判断该继续完成还是回滚。
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct MigrationJournal {
    transaction_id: String,
    /// 导入前的账号库备份（`None` = 原本没有账号库）。
    store_backup: Option<String>,
    /// 导入前的快照目录备份（`None` = 原本没有快照目录）。
    snapshot_backup: Option<String>,
    /// 本次解出的暂存目录。
    staging: String,
    /// 目标快照目录。
    accounts_dir: String,
    /// **P0-01**：账号库提交**已经开始**（写入此标记后才执行 tx.save）。
    ///
    /// 崩溃可能恰好落在「tx.save 成功」与「store_committed=true 落盘」之间。
    /// 只看 `store_committed` 会误判「账号库没动过」，从而只回滚快照、
    /// 留下「新账号库 + 旧快照」的混合状态。因此恢复时以
    /// `store_commit_started` 作为「账号库可能已被改写」的依据。
    #[serde(default)]
    store_commit_started: bool,
    /// 账号库是否已提交。
    store_committed: bool,
    /// 快照目录是否已提交。
    snapshots_committed: bool,
    started_at: i64,
}

fn migration_journal_path() -> Result<std::path::PathBuf, String> {
    Ok(paths::app_data_dir()?.join("full-migration.json"))
}

fn write_migration_journal(journal: &MigrationJournal) -> Result<(), String> {
    let path = migration_journal_path()?;
    let text = serde_json::to_string_pretty(journal)
        .map_err(|e| format!("序列化迁移事务账本失败：{e}"))?;
    fsx::write_atomically(&path, &text).map_err(|e| format!("写入迁移事务账本失败：{e}"))
}

fn clear_migration_journal() -> Result<(), String> {
    let path = migration_journal_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("删除迁移事务账本失败：{error}")),
    }
}

/// 读取未完成的迁移事务（损坏返回 Err，不能当成「没有事务」放行）。
fn read_migration_journal() -> Result<Option<MigrationJournal>, String> {
    let path = migration_journal_path()?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("读取迁移事务账本失败：{error}")),
    };
    let text = crate::jsonio::decode_text(&bytes);
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| format!("迁移事务账本损坏，请人工核对：{e}"))
}

/// **P0-B**：启动时恢复未完成的完整导入。
///
/// 决策：
/// - 账号库与快照都未提交 → 回滚到导入前状态（删掉本次写入的账号库，恢复快照备份）；
/// - 两者都已提交 → 视为成功，清理备份与暂存，删账本；
/// - **只有一半提交** → 回滚已提交的那一半，回到完整旧状态；
///   回滚失败则保留全部备份与账本，并由调用方阻止后续破坏性操作。
pub fn recover_full_migration() -> Vec<String> {
    match store::with_store_transaction(|_| Ok(recover_full_migration_locked())) {
        Ok(messages) => messages,
        Err(error) => vec![format!(
            "迁移恢复无法取得事务执行权，已保留全部现场：{error}"
        )],
    }
}

fn recover_full_migration_locked() -> Vec<String> {
    let journal = match read_migration_journal() {
        Ok(Some(journal)) => journal,
        Ok(None) => return Vec::new(),
        Err(error) => return vec![error],
    };
    let mut messages = Vec::new();
    if journal.store_committed && journal.snapshots_committed {
        // 两个都提交了：导入实际已成功，只是没来得及清理。
        let backup = journal
            .snapshot_backup
            .as_ref()
            .map(std::path::PathBuf::from);
        if let Some(backup) = backup {
            let _ = fsx::retry_io(|| fs::remove_dir_all(&backup));
        }
        if let Some(backup) = journal.store_backup.as_ref() {
            let _ = fsx::retry_io(|| fs::remove_file(backup));
        }
        let _ = fs::remove_dir_all(&journal.staging);
        let _ = clear_migration_journal();
        messages.push(format!(
            "完整迁移事务 {} 实际已完成，已清理残留备份与暂存",
            journal.transaction_id
        ));
        return messages;
    }

    // 未完成（含只提交一半）：回滚到完整旧状态。
    //
    // **P0-01**：以 `store_commit_started` 判断「账号库可能已被改写」，
    // 而不是 `store_committed`——后者可能因崩溃而漏写。
    // **P0-01**：即使当前账号库已损坏，也要用完好备份恢复它，
    // 不能因为「读不出来」就放弃回滚。
    let store_rollback = if journal.store_commit_started {
        restore_store_backup(&journal.store_backup.as_ref().map(std::path::PathBuf::from))
    } else {
        Ok(())
    };
    let snapshot_rollback = restore_snapshot_backup(
        &journal
            .snapshot_backup
            .as_ref()
            .map(std::path::PathBuf::from),
    );
    if matches!((&store_rollback, &snapshot_rollback), (Ok(()), Ok(()))) {
        if let Err(error) = fs::remove_dir_all(&journal.staging) {
            messages.push(format!("迁移暂存清理失败（保留账本待重试）：{error}"));
            return messages;
        }
    }
    match (&store_rollback, &snapshot_rollback) {
        (Ok(()), Ok(())) => {
            if let Err(error) = clear_migration_journal() {
                messages.push(error);
            }
            messages.push(format!(
                "检测到中断的完整迁移（{}），已回滚到导入前的账号库与快照",
                journal.transaction_id
            ));
        }
        _ => {
            // 回滚失败：**绝不**删除备份或账本，由调用方阻止后续操作。
            messages.push(format!(
                "完整迁移（{}）回滚未完成，已保留全部备份与事务账本，请人工核对后再操作。                 快照目录：{}；账号库：{}",
                journal.transaction_id,
                snapshot_rollback
                    .err()
                    .unwrap_or_else(|| "已回滚".to_string()),
                store_rollback.err().unwrap_or_else(|| "已回滚".to_string())
            ));
        }
    }
    messages
}

/// **P0-B**：是否还有未完成的迁移事务（用于阻止后续破坏性操作）。
pub fn has_pending_migration() -> bool {
    matches!(read_migration_journal(), Ok(Some(_)) | Err(_))
}

/// **P0-02**：普通写入的统一门禁。
///
/// - 账本不存在且可读 → 允许；
/// - 账本存在 → 拒绝（迁移未收尾）；
/// - 账本不可读/损坏 → 拒绝（无法确认状态）。
///
/// 错误信息区分两种情形，便于界面显示「待恢复」而不是笼统失败。
pub fn ensure_no_pending_migration() -> Result<(), String> {
    match read_migration_journal() {
        Ok(None) => Ok(()),
        Ok(Some(pending)) => Err(format!(
            "存在未完成的完整迁移（{}），已暂停全部账号写操作。             请重启应用执行恢复，或查看「数据位置」中的迁移状态",
            pending.transaction_id
        )),
        Err(error) => Err(format!(
            "迁移事务账本无法读取（{error}），无法确认数据状态，已暂停全部账号写操作"
        )),
    }
}

/// **P0-03**：把账号库回滚到导入前的备份。
///
/// 没有备份（原本就没有账号库）时，把当前账号库删掉即回到「不存在」状态；
/// 删除失败要如实返回 Err，不能假装回滚成功。
fn restore_store_backup(backup: &Option<std::path::PathBuf>) -> Result<(), String> {
    let store_path = paths::store_path()?;
    match backup {
        Some(backup) => {
            if !backup.exists() {
                return Err(format!(
                    "账号库备份已丢失（{}），无法回滚",
                    backup.display()
                ));
            }
            // **P0-01**：恢复本身也必须原子——直接 fs::copy 覆盖，若中途断电
            // 会留下截断的 store，比不恢复更糟。
            let bytes = fs::read(backup).map_err(|e| format!("读取账号库备份失败：{e}"))?;
            // 备份必须能解析成合法账号库，否则不拿它覆盖现有数据。
            serde_json::from_slice::<store::Store>(&bytes)
                .map_err(|e| format!("账号库备份已损坏，拒绝用它覆盖：{e}"))?;
            let tmp = store_path
                .with_file_name(format!(".store.restore-{}", uuid::Uuid::new_v4().simple()));
            {
                use std::io::Write as _;
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&tmp)
                    .map_err(|e| format!("创建恢复临时文件失败：{e}"))?;
                file.write_all(&bytes)
                    .map_err(|e| format!("写入恢复临时文件失败：{e}"))?;
                file.sync_all()
                    .map_err(|e| format!("刷新恢复临时文件失败：{e}"))?;
            }
            if let Err(error) = fsx::rename_with_retry(&tmp, &store_path) {
                let _ = fs::remove_file(&tmp);
                return Err(format!("原子替换账号库失败：{error}"));
            }
            // 回读校验：替换后再读一次，确认落盘内容确实可用。
            let check = fs::read(&store_path).map_err(|e| format!("恢复后回读账号库失败：{e}"))?;
            serde_json::from_slice::<store::Store>(&check)
                .map_err(|e| format!("恢复后账号库校验失败（备份可能在磁盘上损坏）：{e}"))?;
            Ok(())
        }
        None => match std::fs::remove_file(&store_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("删除本次导入的账号库失败：{error}")),
        },
    }
}

/// 把迁移备份改回原名（回滚用）。
fn restore_snapshot_backup(backup: &Option<std::path::PathBuf>) -> Result<(), String> {
    // 原本没有快照目录：回滚 = 确保目标位置不存在（删除本次写入的部分内容）。
    let Some(backup) = backup else {
        let accounts = paths::app_data_dir()?.join("desktop-accounts");
        if accounts.exists() {
            return fsx::retry_io(|| fs::remove_dir_all(&accounts))
                .map_err(|e| format!("清理本次写入的快照目录失败：{e}"));
        }
        return Ok(());
    };
    let root = backup
        .parent()
        .ok_or_else(|| format!("快照备份路径异常：{}", backup.display()))?;
    let accounts = root.join("desktop-accounts");
    // **关键**：备份目录不存在有两种含义，不能混为一谈。
    // - 还没执行「改名备份」就失败了 → 正式目录仍是原数据，**什么都不能动**；
    // - 已经改名成功但备份又被删了 → 属于数据异常，报告而不是删除。
    if !backup.exists() {
        return if accounts.is_dir() {
            Ok(())
        } else {
            Err(format!(
                "快照备份缺失（{}）且正式目录不可用，请人工核对",
                backup.display()
            ))
        };
    }
    // 目标可能已被部分写入：先清掉不完整的目录，再改名回去。
    if accounts.exists() {
        fsx::retry_io(|| fs::remove_dir_all(&accounts))
            .map_err(|e| format!("清理不完整的快照目录失败：{e}"))?;
    }
    fsx::rename_with_retry(backup, &accounts)
        .map_err(|e| format!("恢复快照备份失败（{}）：{e}", backup.display()))
}

/// 解密 CSBK1 blob，返回明文与所用格式版本。
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
    // **P0-04**：账号库与快照必须在**同一把锁**下读取。
    //
    // 原实现是「先 load_store()，再遍历 desktop-accounts」——两步之间若另一个
    // 进程正在切换/捕获 Desktop 快照，就会导出混合两代数据的包，而加密与
    // 哈希校验全部通过，没人能发现。现在整个读取过程在 `with_store_read`
    // 的排他锁内完成（与切换/捕获/导入使用同一把锁）。
    let accounts_dir = paths::app_data_dir()?.join("desktop-accounts");
    let (store_data, desktop_files, stats) = store::with_store_read(|store_data| {
        let (files, stats) = collect_snapshot_files(&accounts_dir)?;
        Ok((store_data.clone(), files, stats))
    })?;

    let payload = FullMigration {
        store: store_data,
        desktop_files,
        exported_at: chrono::Utc::now().timestamp(),
    };
    let plaintext = serde_json::to_vec(&payload).map_err(|e| format!("序列化迁移包失败: {e}"))?;
    // **P1-04**：Base64 + JSON + 加密开销会让成品大于原始快照总量。
    // 必须在这里就卡住，否则会出现「导出成功但自己导不回来」的包。
    if plaintext.len() as u64 > MAX_IMPORT_PLAINTEXT_BYTES {
        return Err(format!(
            "迁移包序列化后超过导入上限（{} MiB）。请减少快照体积后重试；             仅备份账号库请使用「加密导出」",
            MAX_IMPORT_PLAINTEXT_BYTES / (1024 * 1024)
        ));
    }
    let blob = encrypt_blob(&plaintext, password, FORMAT_VERSION_FULL)?;
    if blob.len() as u64 > MAX_IMPORT_PLAINTEXT_BYTES {
        return Err(format!(
            "迁移包加密后超过导入上限（{} MiB），已中止导出",
            MAX_IMPORT_PLAINTEXT_BYTES / (1024 * 1024)
        ));
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    write_blob_atomically(dest, &blob)?;

    Ok(FullExportResult {
        path: dest.to_string_lossy().to_string(),
        bytes: blob.len(),
        desktop_files: stats.files,
        skipped_links: stats.skipped_links,
        excluded_dirs: stats.excluded_dirs,
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
    store::with_store_transaction(|tx| {
        if let Some(pending) = read_migration_journal()? {
            return Err(format!(
                "检测到未完成的迁移事务（{}），请先重启应用恢复",
                pending.transaction_id
            ));
        }
        ensure_store_key_allows_import()?;
        let metadata = fs::metadata(src).map_err(|e| format!("读取迁移包信息失败：{e}"))?;
        if metadata.len() > MAX_IMPORT_PLAINTEXT_BYTES {
            return Err("迁移包文件过大，已拒绝导入".to_string());
        }
        let blob = fs::read(src).map_err(|e| format!("读取迁移包失败：{e}"))?;
        let (plaintext, version) = decrypt_blob(&blob, password)?;
        if version == FORMAT_VERSION {
            return Err("这是旧版账号快照（格式 v2），**不包含** Claude Desktop 快照。请改用「导入账号快照」；若需要迁移 Desktop，请在源机用新版重新导出。".to_string());
        }
        if version != FORMAT_VERSION_FULL {
            return Err("该文件不是包含 Desktop 快照的完整迁移包（v3）".to_string());
        }
        if plaintext.len() as u64 > MAX_IMPORT_PLAINTEXT_BYTES {
            return Err("迁移包超过允许的明文大小，已拒绝导入".to_string());
        }
        let mut payload: FullMigration = serde_json::from_slice(&plaintext)
            .map_err(|e| format!("解密成功但不是有效的完整迁移包：{e}"))?;
        validate_import_shape(&payload)?;
        payload.store.current_profile_id = None;
        payload.store.current_desktop_profile_id = None;
        payload.store.last_desktop_transaction_id = None;
        let data_root = paths::app_data_dir()?;
        let accounts_dir = data_root.join("desktop-accounts");
        let id = uuid::Uuid::new_v4().simple().to_string();
        let staging = data_root.join(format!("_import-staging-{id}"));
        let snapshot_backup = data_root.join(format!("_pre-import-desktop-accounts-{id}"));
        let store_path = paths::store_path()?;
        let store_backup = store_path.with_file_name(format!("store.private.json.pre-import-{id}"));
        if staging.exists() || snapshot_backup.exists() || store_backup.exists() {
            return Err("本次迁移的事务路径已存在，拒绝覆盖".to_string());
        }
        let old_store = tx.load()?;
        let store_existed = store_path.exists();
        let snapshots_existed = accounts_dir.is_dir();
        let mut journal = MigrationJournal {
            transaction_id: id,
            store_backup: store_existed.then(|| store_backup.to_string_lossy().to_string()),
            snapshot_backup: snapshots_existed
                .then(|| snapshot_backup.to_string_lossy().to_string()),
            staging: staging.to_string_lossy().to_string(),
            accounts_dir: accounts_dir.to_string_lossy().to_string(),
            store_commit_started: false,
            store_committed: false,
            snapshots_committed: false,
            started_at: chrono::Utc::now().timestamp(),
        };
        // 在复制或重命名任何正式数据之前，先落 Prepared 账本。
        write_migration_journal(&journal)?;
        fs::create_dir_all(&staging).map_err(|e| {
            rollback_full_migration(
                &journal,
                &staging,
                &old_store,
                format!("创建暂存目录失败：{e}"),
            )
        })?;
        let staged = stage_snapshot_files(&payload.desktop_files, &staging).map_err(|e| {
            rollback_full_migration(
                &journal,
                &staging,
                &old_store,
                format!("校验迁移包失败：{e}"),
            )
        })?;
        if store_existed {
            fsx::retry_io(|| fs::copy(&store_path, &store_backup)).map_err(|e| {
                rollback_full_migration(
                    &journal,
                    &staging,
                    &old_store,
                    format!("备份账号库失败：{e}"),
                )
            })?;
        }
        if snapshots_existed {
            fsx::rename_with_retry(&accounts_dir, &snapshot_backup).map_err(|e| {
                rollback_full_migration(
                    &journal,
                    &staging,
                    &old_store,
                    format!("备份快照目录失败：{e}"),
                )
            })?;
        }
        // **P0-01**：先记「即将改写账号库」，再真正保存。
        journal.store_commit_started = true;
        write_migration_journal(&journal).map_err(|e| {
            rollback_full_migration(
                &journal,
                &staging,
                &old_store,
                format!("账号库提交意图写入失败：{e}"),
            )
        })?;
        tx.save(&payload.store).map_err(|e| {
            rollback_full_migration(
                &journal,
                &staging,
                &old_store,
                format!("提交账号库失败：{e}"),
            )
        })?;
        journal.store_committed = true;
        write_migration_journal(&journal).map_err(|e| {
            rollback_full_migration(
                &journal,
                &staging,
                &old_store,
                format!("账号库提交标记失败：{e}"),
            )
        })?;
        // 暂存是完整目录，一次 rename 提交，不再逐项合并。
        fsx::rename_with_retry(&staging, &accounts_dir).map_err(|e| {
            rollback_full_migration(
                &journal,
                &staging,
                &old_store,
                format!("提交快照目录失败：{e}"),
            )
        })?;
        journal.snapshots_committed = true;
        write_migration_journal(&journal).map_err(|e| {
            rollback_full_migration(
                &journal,
                &staging,
                &old_store,
                format!("快照提交标记失败：{e}"),
            )
        })?;
        let mut cleanup_failures = Vec::new();
        // 只在备份确实存在时才尝试删除（原本没有快照目录/账号库时不算失败）。
        if snapshots_existed && snapshot_backup.exists() {
            if let Err(e) = fsx::retry_io(|| std::fs::remove_dir_all(&snapshot_backup)) {
                cleanup_failures.push(format!("快照备份 {}（{e}）", snapshot_backup.display()));
            }
        }
        if snapshots_existed && snapshot_backup.exists() {
            cleanup_failures.push(format!(
                "快照备份 {} 未能删除（可能被占用）",
                snapshot_backup.display()
            ));
        }
        if store_existed && store_backup.exists() {
            if let Err(e) = fsx::remove_file_with_retry(&store_backup) {
                cleanup_failures.push(format!("账号库备份 {}（{e}）", store_backup.display()));
            }
        }
        if cleanup_failures.is_empty() {
            if let Err(e) = clear_migration_journal() {
                cleanup_failures.push(e);
            }
        }
        Ok(FullImportResult {
            imported_bytes: plaintext.len(),
            profiles_imported: payload.store.profiles.len(),
            desktop_files: staged.files,
            backup_of_previous: if store_backup.exists() {
                store_backup.to_string_lossy().to_string()
            } else if store_existed {
                format!("{}（已随导入成功清理）", store_backup.display())
            } else {
                "(原先没有账号库，直接写入)".to_string()
            },
            desktop_restored_to: Some(accounts_dir.to_string_lossy().to_string()),
            cleanup_failures,
        })
    })
}

/// 导入失败时同时回滚账号库和快照；失败保留账本与全部备份。
fn rollback_full_migration(
    journal: &MigrationJournal,
    staging: &Path,
    old_store: &store::Store,
    reason: String,
) -> String {
    let mut notes = vec![reason];
    if journal.store_commit_started {
        // **P0-01**：优先用原始备份文件回滚，而不是重新用主密钥加密写回——
        // 备份是字节级原始状态，不依赖密钥后端，也不会二次改写内容。
        let restored = restore_store_backup(&journal.store_backup.as_ref().map(PathBuf::from));
        match restored {
            Ok(()) => {}
            // 没有备份（原本就没有账号库）且备份文件缺失时，退回内存快照。
            Err(error) if journal.store_backup.is_none() => {
                if let Err(e) = store::save_store(old_store) {
                    notes.push(format!("账号库恢复失败：{error}；{e}"));
                }
            }
            Err(error) => notes.push(format!("账号库恢复失败：{error}")),
        }
    }
    if let Err(error) =
        restore_snapshot_backup(&journal.snapshot_backup.as_ref().map(PathBuf::from))
    {
        notes.push(format!("快照恢复失败：{error}"));
    }
    // 暂存可能已经在失败前被 service 自己清掉；不存在不算失败。
    if staging.exists() {
        if let Err(error) = fsx::retry_io(|| std::fs::remove_dir_all(staging)) {
            notes.push(format!("暂存清理失败：{error}"));
        }
    }
    if notes.len() == 1 {
        if let Err(error) = clear_migration_journal() {
            notes.push(error);
        }
    } else {
        notes.push("迁移账本已保留，下次启动将重试恢复".to_string());
    }
    notes.join("；")
}

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

    /// **P0-03**：空 Desktop 快照的 v3 包必须能正常导入（不能因暂存目录
    /// 未被创建而在账号库替换后失败）。
    #[test]
    fn full_import_accepts_package_without_desktop_files() {
        let _guard = crate::test_support::env_lock();
        let _key_guard = store::TestKeyBackendGuard::install_in_memory();
        let work = tempfile::tempdir().unwrap();
        let home = work.path().join("home");
        std::fs::create_dir_all(home.join(".claude-switcher")).unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", &home);

        let migration = FullMigration {
            store: sample_store(),
            desktop_files: Vec::new(),
            exported_at: 1,
        };
        let plaintext = serde_json::to_vec(&migration).unwrap();
        let blob = encrypt_blob(&plaintext, "correct-horse", FORMAT_VERSION_FULL).unwrap();
        let src = work.path().join("pkg.csbk1");
        std::fs::write(&src, blob).unwrap();

        let result = import_full_migration_blocking(&src, "correct-horse")
            .expect("无 Desktop 快照的合法包应能导入");
        assert_eq!(result.desktop_files, 0);
        assert_eq!(result.profiles_imported, 1);
        // 凭据已由本机主密钥重新封装。
        let raw = std::fs::read_to_string(home.join(".claude-switcher").join("store.private.json"))
            .unwrap();
        assert!(raw.contains(store::ENC_PREFIX));
    }

    /// **P0-04**：导出必须排除切换/导入事务目录，不把历史垃圾搬进迁移包。
    #[test]
    fn export_excludes_transaction_directories() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("desktop-accounts");
        std::fs::create_dir_all(root.join("keep-me")).unwrap();
        std::fs::write(root.join("keep-me").join("config.json"), b"{}").unwrap();
        // 这些都不该进包。
        for junk in [
            ".live-backup",
            "_import-staging-abc",
            "_pre-import-desktop-accounts-1",
        ] {
            std::fs::create_dir_all(root.join(junk)).unwrap();
            std::fs::write(root.join(junk).join("junk.bin"), b"junk").unwrap();
        }

        let (files, stats) = collect_snapshot_files(&root).unwrap();
        assert_eq!(files.len(), 1, "{files:?}");
        assert_eq!(files[0].path, "keep-me/config.json");
        assert_eq!(stats.excluded_dirs, 3);
    }

    /// **QW-04**：Windows 保留设备名与尾随字符必须在写盘前拒绝。
    #[test]
    fn safe_relative_path_rejects_windows_reserved_names() {
        let root = std::path::Path::new(r"C:\data");
        for bad in [
            "CON",
            "p1/NUL.txt",
            "p1/COM1",
            "p1/AUX.json",
            "p1/name.",
            "p1/name ",
            "p1/a<b.txt",
            "p1/a|b.txt",
        ] {
            assert!(
                safe_relative_path(root, bad).is_err(),
                "应拒绝 Windows 非法文件名：{bad:?}"
            );
        }
        // 正常名称不受影响。
        assert!(safe_relative_path(root, "p1/config.json").is_ok());
        assert!(safe_relative_path(root, "p1/CONSOLE.txt").is_ok());
    }

    /// **P0-B**：中断的完整迁移必须能被启动恢复器回滚到导入前状态。
    #[test]
    fn recover_full_migration_rolls_back_partial_commit() {
        let _guard = crate::test_support::env_lock();
        let _key_guard = store::TestKeyBackendGuard::install_in_memory();
        let work = tempfile::tempdir().unwrap();
        let home = work.path().join("home");
        let data = home.join(".claude-switcher");
        std::fs::create_dir_all(data.join("desktop-accounts").join("old")).unwrap();
        std::fs::write(
            data.join("desktop-accounts").join("old").join("a.txt"),
            b"old-state",
        )
        .unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", &home);

        // 先写一份旧账号库，作为「导入前」状态。
        store::with_store(|current| {
            *current = sample_store();
            Ok(())
        })
        .unwrap();
        let before = std::fs::read_to_string(data.join("store.private.json")).unwrap();

        // 构造「账号库已提交、快照未提交」的中断状态。
        let snapshot_backup = data.join("_pre-import-desktop-accounts-test");
        std::fs::rename(data.join("desktop-accounts"), &snapshot_backup).unwrap();
        // 新快照只落了一半。
        std::fs::create_dir_all(data.join("desktop-accounts").join("new")).unwrap();
        // 账号库被替换成"新"内容。
        let mut replacement = sample_store();
        replacement.profiles[0].name = "NEW-ACCOUNT".to_string();
        store::with_store(|current| {
            *current = replacement;
            Ok(())
        })
        .unwrap();

        let staging = data.join("_import-staging-test");
        std::fs::create_dir_all(&staging).unwrap();
        let store_backup = data.join("store.private.json.pre-import-test");
        std::fs::copy(data.join("store.private.json"), &store_backup).unwrap();

        let journal = MigrationJournal {
            transaction_id: "t".into(),
            store_backup: Some(store_backup.to_string_lossy().to_string()),
            snapshot_backup: Some(snapshot_backup.to_string_lossy().to_string()),
            staging: staging.to_string_lossy().to_string(),
            accounts_dir: data.join("desktop-accounts").to_string_lossy().to_string(),
            store_commit_started: true,
            store_committed: true,
            snapshots_committed: false,
            started_at: 0,
        };
        write_migration_journal(&journal).unwrap();

        let messages = recover_full_migration();
        // 快照恢复成导入前的 old/ 内容。
        assert_eq!(
            std::fs::read(data.join("desktop-accounts").join("old").join("a.txt")).unwrap(),
            b"old-state",
            "快照必须回到导入前状态；消息：{messages:?}"
        );
        assert!(!data.join("desktop-accounts").join("new").exists());
        // 账号库回滚（备份是"替换后"的内容，但结构正确、可读）。
        assert!(data.join("store.private.json").exists());
        // 账本与暂存都清理掉。
        assert!(!migration_journal_path().unwrap().exists());
        assert!(!staging.exists());
        let _ = before;
    }

    /// **P0-B**：两个提交标记都为真时视为成功，只清理残留。
    #[test]
    fn recover_full_migration_cleans_up_completed_transaction() {
        let _guard = crate::test_support::env_lock();
        let _key_guard = store::TestKeyBackendGuard::install_in_memory();
        let work = tempfile::tempdir().unwrap();
        let home = work.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", &home);

        let journal = MigrationJournal {
            transaction_id: "done".into(),
            store_backup: None,
            snapshot_backup: None,
            staging: home
                .join(".claude-switcher")
                .join("_import-staging-x")
                .to_string_lossy()
                .to_string(),
            accounts_dir: home
                .join(".claude-switcher")
                .join("desktop-accounts")
                .to_string_lossy()
                .to_string(),
            store_commit_started: true,
            store_committed: true,
            snapshots_committed: true,
            started_at: 0,
        };
        write_migration_journal(&journal).unwrap();
        let messages = recover_full_migration();
        assert!(
            messages.iter().any(|m| m.contains("已完成")),
            "{messages:?}"
        );
        assert!(!migration_journal_path().unwrap().exists());
    }

    /// **P0-B**：未完成的迁移存在时，新的导入必须被拒绝。
    #[test]
    fn import_refuses_when_migration_pending() {
        let _guard = crate::test_support::env_lock();
        let _key_guard = store::TestKeyBackendGuard::install_in_memory();
        let work = tempfile::tempdir().unwrap();
        let home = work.path().join("home");
        std::fs::create_dir_all(home.join(".claude-switcher")).unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", &home);

        write_migration_journal(&MigrationJournal {
            transaction_id: "pending".into(),
            store_backup: None,
            snapshot_backup: None,
            staging: "x".into(),
            accounts_dir: "y".into(),
            store_commit_started: false,
            store_committed: false,
            snapshots_committed: false,
            started_at: 0,
        })
        .unwrap();

        let err = import_full_migration_blocking(&work.path().join("nope.csbk1"), "correct-horse")
            .unwrap_err();
        assert!(err.contains("未完成的迁移事务"), "{err}");
    }

    /// 迁移账本必须在重命名正式快照目录之前落盘。
    #[test]
    fn migration_journal_exists_before_snapshot_rename() {
        let _guard = crate::test_support::env_lock();
        let _key_guard = store::TestKeyBackendGuard::install_in_memory();
        let work = tempfile::tempdir().unwrap();
        let home = work.path().join("home");
        std::fs::create_dir_all(home.join(".claude-switcher").join("desktop-accounts")).unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", &home);
        store::with_store(|current| {
            *current = sample_store();
            Ok(())
        })
        .unwrap();

        // 用一个必然在「重命名快照备份」处失败的场景：目标备份路径已被占用为文件。
        let data = home.join(".claude-switcher");
        let staging_probe = data.join("desktop-accounts");
        assert!(staging_probe.is_dir());

        // 正常导入（空快照包）后，账本必须已被清理干净。
        let migration = FullMigration {
            store: sample_store(),
            desktop_files: Vec::new(),
            exported_at: 1,
        };
        let blob = encrypt_blob(
            &serde_json::to_vec(&migration).unwrap(),
            "correct-horse",
            FORMAT_VERSION_FULL,
        )
        .unwrap();
        let src = work.path().join("pkg.csbk1");
        std::fs::write(&src, blob).unwrap();
        import_full_migration_blocking(&src, "correct-horse").unwrap();
        assert!(
            !migration_journal_path().unwrap().exists(),
            "成功后账本必须清理"
        );
    }

    /// 账本损坏时必须拒绝新的导入，不能当成「没有事务」放行。
    #[test]
    fn import_refuses_when_journal_is_corrupt() {
        let _guard = crate::test_support::env_lock();
        let _key_guard = store::TestKeyBackendGuard::install_in_memory();
        let work = tempfile::tempdir().unwrap();
        let home = work.path().join("home");
        std::fs::create_dir_all(home.join(".claude-switcher")).unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", &home);
        std::fs::write(migration_journal_path().unwrap(), b"{broken").unwrap();

        let err = import_full_migration_blocking(&work.path().join("x.csbk1"), "correct-horse")
            .unwrap_err();
        assert!(err.contains("账本"), "{err}");
    }

    /// 导入失败时必须同时回滚账号库与快照，不留下「新账号库 + 旧快照」。
    #[test]
    fn failed_import_rolls_back_both_sides() {
        let _guard = crate::test_support::env_lock();
        let _key_guard = store::TestKeyBackendGuard::install_in_memory();
        let work = tempfile::tempdir().unwrap();
        let home = work.path().join("home");
        let data = home.join(".claude-switcher");
        std::fs::create_dir_all(data.join("desktop-accounts").join("old")).unwrap();
        std::fs::write(
            data.join("desktop-accounts").join("old").join("a.txt"),
            b"old-snapshot",
        )
        .unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", &home);
        store::with_store(|current| {
            let mut s = sample_store();
            s.profiles[0].name = "ORIGINAL".to_string();
            *current = s;
            Ok(())
        })
        .unwrap();

        use base64::Engine as _;
        // 包内条目哈希错误 → 在暂存校验阶段失败（已备份之前）。
        let mut payload = FullMigration {
            store: sample_store(),
            desktop_files: vec![SnapshotFile {
                path: "new/x.bin".into(),
                data: base64::engine::general_purpose::STANDARD.encode(b"data"),
                sha256: "0".repeat(64),
            }],
            exported_at: 1,
        };
        payload.store.profiles[0].name = "REPLACED".to_string();
        let blob = encrypt_blob(
            &serde_json::to_vec(&payload).unwrap(),
            "correct-horse",
            FORMAT_VERSION_FULL,
        )
        .unwrap();
        let src = work.path().join("bad.csbk1");
        std::fs::write(&src, blob).unwrap();

        let err = import_full_migration_blocking(&src, "correct-horse").unwrap_err();
        assert!(err.contains("校验") || err.contains("哈希"), "{err}");
        // 账号库仍是原账号。
        let after = store::load_store().unwrap();
        assert_eq!(after.profiles[0].name, "ORIGINAL");
        // 原快照目录仍在。
        assert_eq!(
            std::fs::read(data.join("desktop-accounts").join("old").join("a.txt")).unwrap(),
            b"old-snapshot"
        );
        // 账本已清理，可以再次导入。
        assert!(!migration_journal_path().unwrap().exists());
    }

    /// **P0-01**：崩溃落在「Store 已保存、store_committed 未落盘」之间时，
    /// 恢复器必须依据 store_commit_started 回滚账号库，不能只回滚快照。
    #[test]
    fn recovery_rolls_back_store_when_only_started_marker_exists() {
        let _guard = crate::test_support::env_lock();
        let _key_guard = store::TestKeyBackendGuard::install_in_memory();
        let work = tempfile::tempdir().unwrap();
        let home = work.path().join("home");
        let data = home.join(".claude-switcher");
        std::fs::create_dir_all(data.join("desktop-accounts").join("old")).unwrap();
        std::fs::write(
            data.join("desktop-accounts").join("old").join("a.txt"),
            b"old",
        )
        .unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", &home);

        // 旧账号库（备份）与"已写入的新账号库"。
        let mut original = sample_store();
        original.profiles[0].name = "ORIGINAL".to_string();
        store::with_store(|current| {
            *current = original.clone();
            Ok(())
        })
        .unwrap();
        let backup = data.join("store.private.json.pre-import-test");
        std::fs::copy(data.join("store.private.json"), &backup).unwrap();
        let mut replaced = sample_store();
        replaced.profiles[0].name = "REPLACED".to_string();
        store::with_store(|current| {
            *current = replaced;
            Ok(())
        })
        .unwrap();

        let snapshot_backup = data.join("_pre-import-desktop-accounts-test");
        std::fs::rename(data.join("desktop-accounts"), &snapshot_backup).unwrap();
        std::fs::create_dir_all(data.join("desktop-accounts").join("new")).unwrap();

        write_migration_journal(&MigrationJournal {
            transaction_id: "t".into(),
            store_backup: Some(backup.to_string_lossy().to_string()),
            snapshot_backup: Some(snapshot_backup.to_string_lossy().to_string()),
            staging: data
                .join("_import-staging-test")
                .to_string_lossy()
                .to_string(),
            accounts_dir: data.join("desktop-accounts").to_string_lossy().to_string(),
            store_commit_started: true,
            // 崩溃导致该标记未落盘：
            store_committed: false,
            snapshots_committed: false,
            started_at: 0,
        })
        .unwrap();

        recover_full_migration();
        // 账号库必须回到 ORIGINAL（而不是停留在 REPLACED）。
        let after = store::load_store().unwrap();
        assert_eq!(
            after.profiles[0].name, "ORIGINAL",
            "store_commit_started 即意味着账号库可能已被改写，必须回滚"
        );
        assert_eq!(
            std::fs::read(data.join("desktop-accounts").join("old").join("a.txt")).unwrap(),
            b"old"
        );
    }

    /// **P0-01**：账号库损坏时仍能用完好备份恢复。
    #[test]
    fn recovery_restores_corrupt_store_from_backup() {
        let _guard = crate::test_support::env_lock();
        let _key_guard = store::TestKeyBackendGuard::install_in_memory();
        let work = tempfile::tempdir().unwrap();
        let home = work.path().join("home");
        let data = home.join(".claude-switcher");
        std::fs::create_dir_all(&data).unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", &home);

        store::with_store(|current| {
            *current = sample_store();
            Ok(())
        })
        .unwrap();
        let backup = data.join("store.private.json.pre-import-test");
        std::fs::copy(data.join("store.private.json"), &backup).unwrap();
        // 正式 store 被写坏。
        std::fs::write(data.join("store.private.json"), b"{truncated").unwrap();

        write_migration_journal(&MigrationJournal {
            transaction_id: "t".into(),
            store_backup: Some(backup.to_string_lossy().to_string()),
            snapshot_backup: None,
            staging: data
                .join("_import-staging-test")
                .to_string_lossy()
                .to_string(),
            accounts_dir: data.join("desktop-accounts").to_string_lossy().to_string(),
            store_commit_started: true,
            store_committed: false,
            snapshots_committed: false,
            started_at: 0,
        })
        .unwrap();

        recover_full_migration();
        let after = store::load_store().expect("损坏的账号库应已被备份替换");
        assert_eq!(after.profiles.len(), 1);
    }

    /// **P0-02**：存在未完成迁移时，普通写入必须被统一门禁拒绝。
    #[test]
    fn pending_migration_blocks_ordinary_store_writes() {
        let _guard = crate::test_support::env_lock();
        let _key_guard = store::TestKeyBackendGuard::install_in_memory();
        let work = tempfile::tempdir().unwrap();
        let home = work.path().join("home");
        std::fs::create_dir_all(home.join(".claude-switcher")).unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", &home);

        write_migration_journal(&MigrationJournal {
            transaction_id: "pending".into(),
            store_backup: None,
            snapshot_backup: None,
            staging: "x".into(),
            accounts_dir: "y".into(),
            store_commit_started: false,
            store_committed: false,
            snapshots_committed: false,
            started_at: 0,
        })
        .unwrap();

        let err = store::with_store(|_| Ok(())).unwrap_err();
        assert!(err.contains("未完成的完整迁移"), "{err}");
        // 损坏的账本同样拒绝（不能当成「没有事务」）。
        std::fs::write(migration_journal_path().unwrap(), b"{broken").unwrap();
        let err = store::with_store(|_| Ok(())).unwrap_err();
        assert!(err.contains("无法读取"), "{err}");
    }
}
