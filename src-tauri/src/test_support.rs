//! 测试共享基础设施。
//!
//! **为什么需要这个模块**：Rust 的单元测试默认在同一进程内多线程并行运行，
//! 而 `std::env::set_var` 改的是**进程级**环境变量。某个测试改掉 `USERPROFILE`
//! 之后，同一时刻并行跑的其他测试（`paths` / `credentials` / `platform::windows`
//! 都读它）会读到被改掉的值——表现为难以复现的偶发失败。
//!
//! 因此凡是要动环境的测试，必须先拿到这里的 [`env_lock`]，把环境操作串行化。
//! 还原时注意：原值不存在要用 `remove_var`，不能用 `set_var("")`——设成空串
//! 和「没有这个变量」在 `env::var_os` 的语义下不同（前者是 `Some("")`）。

use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard};

/// 串行化所有改环境的测试。
///
/// 拿锁后务必尽快释放（`drop(guard)` 或让 guard 离开作用域），否则会把本来
/// 并行的测试全变成串行，拖慢整套测试。
pub static ENV_LOCK: Mutex<()> = Mutex::new(());

/// 取环境锁（锁中毒时取内部数据继续，不因某测试 panic 而连带全部失败）。
pub fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 环境变量的还原器：`Drop` 时把变量恢复成设置前的样子。
///
/// 用 `Drop` 而不是返回闭包，是为了让调用方即使在中途 `return` / `unwrap()`
/// panic 时也能还原——早期实现靠手动调用还原闭包，测试失败时就漏掉了。
pub struct EnvRestore {
    key: String,
    previous: Option<OsString>,
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        // SAFETY: 调用方持有 ENV_LOCK，同一进程内不会有其他线程并发读写环境变量。
        unsafe {
            match &self.previous {
                Some(old) => std::env::set_var(&self.key, old),
                // 原值不存在时必须 remove_var：设成空串会让 env::var_os 返回
                // Some("")，与「没有这个变量」语义不同。
                None => std::env::remove_var(&self.key),
            }
        }
    }
}

/// 设置环境变量，返回 [`EnvRestore`]（离开作用域时自动还原）。
///
/// 调用方必须持有 [`env_lock`]，否则会与并行测试互相污染。
pub fn set_env(key: &str, value: &std::path::Path) -> EnvRestore {
    let previous = std::env::var_os(key);
    // SAFETY: 调用方持有 ENV_LOCK。
    unsafe {
        std::env::set_var(key, value.as_os_str());
    }
    EnvRestore {
        key: key.to_string(),
        previous,
    }
}
