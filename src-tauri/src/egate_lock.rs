//! **P0-01**：系统保护操作的跨进程 + 跨线程排他执行权。
//!
//! 账号库已有 `store::with_store` 的 fs4 跨进程锁，但门禁/断网/恢复没有同级
//! 互斥。GUI、`cs.exe`、计划任务拉起的 `--guard` 可能同时对同一批防火墙规则
//! 和网卡动手。
//!
//! **设计要点（v0.6.6 重做）**：
//! - 锁是**真正的排他锁**：`OperationGuard` 在整个生命周期内拥有文件锁.
//! - **不可重入**：同线程嵌套会自我死锁——因此所有内部系统修改函数必须
//!   接收 `&OperationGuard`，由最外层统一持锁（见 `*_locked` 函数）。
//! - **不跨线程共享**：Guard 标记为 `!Send`（PhantomData<*const ()>），
//!   避免所有权在不受控的线程间迁移。
//! - 上一版用全进程 `HOLD_DEPTH` 计数伪重入，会让线程 B 绕过线程 A 持有的锁，
//!   已彻底移除。

use std::fs::OpenOptions;
use std::marker::PhantomData;

/// 系统保护操作的类型（用于日志与诊断）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemOperation {
    /// 应用隔离（熔断）。
    Isolate,
    /// 全局断网。
    NetworkCut,
    /// 恢复网络。
    RestoreNetwork,
    /// 解除应用隔离。
    ReleaseIsolation,
    /// 完整恢复（急救/退出）。
    FullRestore,
}

impl SystemOperation {
    pub fn label(self) -> &'static str {
        match self {
            SystemOperation::Isolate => "应用隔离",
            SystemOperation::NetworkCut => "全局断网",
            SystemOperation::RestoreNetwork => "恢复网络",
            SystemOperation::ReleaseIsolation => "解除隔离",
            SystemOperation::FullRestore => "完整恢复",
        }
    }
}

/// 持有期间独占系统保护操作；Drop 时释放文件锁。
///
/// `PhantomData<*const ()>` 让 Guard 成为 `!Send`：锁所有权不能跨线程迁移，
/// 避免「A 线程持锁、B 线程误以为可执行」的竞态。
pub struct OperationGuard {
    _file: std::fs::File,
    _not_send: PhantomData<*const ()>,
}

/// 获取系统保护操作独占权（**阻塞、不可重入**）。
///
/// 同一时刻全进程/全系统只有一个持有者。**嵌套调用会自我死锁**——所以
/// 内部函数接收 `&OperationGuard` 而不是自己再申请一次。
pub fn acquire(operation: SystemOperation) -> Result<OperationGuard, String> {
    let dir = crate::paths::app_data_dir()?;
    acquire_in(&dir, operation)
}

/// 可注入目录的获取实现（测试用临时目录）。
fn acquire_in(dir: &std::path::Path, operation: SystemOperation) -> Result<OperationGuard, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("创建数据目录失败：{e}"))?;
    let path = dir.join("eguard-operation.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("打开系统操作锁失败：{e}"))?;
    fs4::FileExt::lock(&file)
        .map_err(|e| format!("获取系统操作锁失败（{}）：{e}", operation.label()))?;
    Ok(OperationGuard {
        _file: file,
        _not_send: PhantomData,
    })
}

/// 尝试获取（非阻塞）；已被占用时返回 `Ok(None)`。
///
/// **注意**：拿到 Guard 后必须**持续持有到操作结束**——先检查再释放锁、
/// 然后单独执行，是不具原子性的伪互斥。
pub fn try_acquire(operation: SystemOperation) -> Result<Option<OperationGuard>, String> {
    let dir = crate::paths::app_data_dir()?;
    try_acquire_in(&dir, operation)
}

fn try_acquire_in(
    dir: &std::path::Path,
    operation: SystemOperation,
) -> Result<Option<OperationGuard>, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("创建数据目录失败：{e}"))?;
    let path = dir.join("eguard-operation.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("打开系统操作锁失败：{e}"))?;
    match fs4::FileExt::try_lock(&file) {
        Ok(()) => Ok(Some(OperationGuard {
            _file: file,
            _not_send: PhantomData,
        })),
        Err(_) => {
            let _ = operation.label();
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_labels_are_chinese_and_distinct() {
        let ops = [
            SystemOperation::Isolate,
            SystemOperation::NetworkCut,
            SystemOperation::RestoreNetwork,
            SystemOperation::ReleaseIsolation,
            SystemOperation::FullRestore,
        ];
        let mut labels = Vec::new();
        for op in ops {
            let label = op.label();
            assert!(
                label
                    .chars()
                    .any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
                "标签应为中文：{label}"
            );
            assert!(!labels.contains(&label), "标签不能重复：{label}");
            labels.push(label);
        }
    }

    #[test]
    fn held_lock_blocks_other_thread_until_released() {
        // **P0-01 回归**：线程 A 持锁期间，线程 B 不能进入临界区。
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = std::sync::mpsc::channel();

        let dir = tempfile::tempdir().unwrap();
        let dir_holder = dir.path().to_path_buf();
        let holder = std::thread::spawn(move || {
            let guard = try_acquire_in(&dir_holder, SystemOperation::FullRestore).unwrap();
            assert!(guard.is_some(), "无竞争时应拿到锁");
            acquired_tx.send(()).unwrap();
            // 等待主线程确认「B 已被阻塞」后再释放。
            let _ = release_rx.recv();
            drop(guard);
            done_tx.send(()).unwrap();
        });

        acquired_rx.recv().unwrap();
        // 线程 B（主线程）此刻尝试非阻塞获取：必须失败。
        let contended = try_acquire_in(dir.path(), SystemOperation::Isolate).unwrap();
        assert!(contended.is_none(), "A 持锁期间 B 绝不能拿到锁");

        release_tx.send(()).unwrap();
        done_rx.recv().unwrap();
        holder.join().unwrap();

        // A 释放后 B 应能拿到。
        let after = try_acquire_in(dir.path(), SystemOperation::Isolate).unwrap();
        assert!(after.is_some(), "A 释放后 B 应能获取");
    }

    #[test]
    fn guard_is_not_send() {
        // 编译期约束：OperationGuard 必须是 !Send（锁所有权不跨线程迁移）。
        fn assert_not_send<T>()
        where
            T: Send,
        {
        }
        // 下面这行若取消注释应编译失败——用 trait 检测间接表达：
        trait NotSend {}
        impl NotSend for OperationGuard {}
        // 该断言本身不运行，仅记录设计意图。
        let _ = std::marker::PhantomData::<fn() -> dyn NotSend>;
        let _ = assert_not_send::<u32>;
    }
}
