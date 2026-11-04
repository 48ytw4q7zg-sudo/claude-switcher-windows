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
pub struct OperationGuard {
    _file: std::fs::File,
}

/// 获取系统保护操作独占权。
///
/// 阻塞等待直到拿到锁（同一时刻只允许一个进程修改系统保护资源）。
/// 获取失败返回 `Err`——调用方**不得**在未持有锁的情况下执行系统修改。
pub fn acquire(operation: SystemOperation) -> Result<OperationGuard, String> {
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
    Ok(OperationGuard { _file: file })
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
        Ok(()) => Ok(Some(OperationGuard { _file: file })),
        Err(_) => Ok(None),
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
}
