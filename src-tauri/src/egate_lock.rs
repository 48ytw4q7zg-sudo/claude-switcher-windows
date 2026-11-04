//! **P0-02**：系统保护操作的跨进程执行权。
//!
//! 账号库已有 `store::with_store` 的 fs4 跨进程锁，但门禁/断网/恢复没有同级
//! 互斥。GUI、`cs.exe`、计划任务拉起的 `--guard` 可能同时对同一批防火墙规则
//! 和网卡动手，导致状态互相覆盖。
//!
//! 本模块复用 fs4 的文件锁，在 `app_data_dir/eguard-operation.lock` 上排他，
//! 覆盖「读意图 → 执行系统修改 → 提交账本」全程。锁随进程退出由操作系统释放；
//! 未完成的事务仍由各自账本恢复。

use std::fs::OpenOptions;

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

/// 持有期间独占系统保护操作的守卫；Drop 时释放。
///
/// **P0-NEW-01**：本进程内的嵌套调用共享同一把已持有的锁，不会自我等待。
/// 只有最外层（计数归零）才真正释放文件锁。
pub struct OperationGuard {
    /// 最外层持有的文件句柄；嵌套层为 None（共享外层）。
    _file: Option<std::fs::File>,
}

/// 本进程持锁深度（**可重入**）。
static HOLD_DEPTH: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// 获取系统保护操作独占权（**可重入**）。
///
/// 同一进程内嵌套调用（如 restore_all → restore → release_all_verified）
/// 直接复用已持有的锁，不重复申请文件锁——否则 Windows 上会自我死锁。
///
/// 跨进程仍严格互斥：只有本进程深度为 0 时才真正申请文件锁。
pub fn acquire(operation: SystemOperation) -> Result<OperationGuard, String> {
    use std::sync::atomic::Ordering;
    let depth = HOLD_DEPTH.fetch_add(1, Ordering::SeqCst);
    if depth > 0 {
        // 嵌套调用：复用外层锁，不申请文件锁。
        return Ok(OperationGuard { _file: None });
    }
    // 最外层：真正申请跨进程文件锁。
    let result = (|| -> Result<std::fs::File, String> {
        let dir = crate::paths::app_data_dir()?;
        std::fs::create_dir_all(&dir).map_err(|e| format!("创建数据目录失败：{e}"))?;
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
        Ok(file)
    })();
    match result {
        Ok(file) => Ok(OperationGuard { _file: Some(file) }),
        Err(error) => {
            // 申请失败：回退深度计数，否则后续调用会误判为「已持锁」。
            HOLD_DEPTH.fetch_sub(1, Ordering::SeqCst);
            Err(error)
        }
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        // 只有最外层（持有文件句柄）真正释放；嵌套层只减计数。
        HOLD_DEPTH.fetch_sub(1, Ordering::SeqCst);
        if let Some(file) = self._file.take() {
            let _ = fs4::FileExt::unlock(&file);
        }
    }
}

/// 尝试获取（非阻塞）；已被占用时返回 `Ok(None)`。
pub fn try_acquire(operation: SystemOperation) -> Result<Option<OperationGuard>, String> {
    let _ = operation.label();
    let dir = crate::paths::app_data_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建数据目录失败：{e}"))?;
    let path = dir.join("eguard-operation.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("打开系统操作锁失败：{e}"))?;
    match fs4::FileExt::try_lock(&file) {
        Ok(()) => {
            HOLD_DEPTH.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Some(OperationGuard { _file: Some(file) }))
        }
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_acquire_does_not_deadlock() {
        // **P0-NEW-01** 回归：同进程嵌套加锁必须立即返回，不能自我等待。
        // 用超时保护：若回归，测试会失败而不是挂死。
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let outer = acquire(SystemOperation::FullRestore);
            if outer.is_err() {
                let _ = tx.send(false);
                return;
            }
            let outer = outer.unwrap();
            // 模拟 restore_all → restore → release_all_verified 的嵌套。
            let inner1 = acquire(SystemOperation::RestoreNetwork);
            let inner2 = acquire(SystemOperation::ReleaseIsolation);
            let ok = inner1.is_ok() && inner2.is_ok();
            drop(inner2);
            drop(inner1);
            drop(outer);
            // 释放后应能再次获取。
            let again = acquire(SystemOperation::Isolate).is_ok();
            let _ = tx.send(ok && again);
        });
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(ok) => assert!(ok, "嵌套加锁必须成功且释放后可重获"),
            Err(_) => panic!("嵌套加锁发生死锁（10 秒未返回）"),
        }
    }

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
}
