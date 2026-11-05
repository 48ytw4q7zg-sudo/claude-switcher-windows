# v0.6.13 — 第十四轮审计收口（保护原因分离与事务门禁）

发布日期：2026-11-05
基线：v0.6.12（`d6eaf75`）→ 本版
依据：GPT-6 第十四轮源码审计（固定 `d6eaf75`）

本轮六项 P0 中，**P0-01 会让「解除一种保护」误删另一种保护的全部规则**，
其余五项都是事务/入口闭环问题。

## 一、P0-01：兜底锁误删普通熔断（最严重）

原实现所有隔离共用 `ClaudeSwitcher AppIsolation` 前缀，解除「未接入兜底锁」
调用 `release_verified()`，按整个前缀删除——**普通熔断的规则被一起删掉**，
而熔断状态仍写着 tripped，防火墙却已经放行。

修复：
- 新增 `IsolationReason::{EgressTrip, Uncovered}`，各自独立规则名前缀
  （`ClaudeSwitcher AppIsolation` / `ClaudeSwitcher UncoveredLock`）。
- 新增 `release_isolation_reason(reason)`：只删除**本来源**的规则，
  并用 **同前缀**回查剩余条数，不靠总数判断。
- `expected_rules_for(reason, ..)` 统一生成预期集合，建立与核验共用。
- 解除触发条件从 `path != "uncovered"` 改为
  `matches!(path, "system_proxy" | "tun")` —— **Unknown 不再触发自动放行**。

## 二、P0-04：等待锁期间用户停止保护

`enforce_uncovered_outbound()` 拿到系统操作锁后**没有**重新核验用户意图，
会出现「急救刚完成，迟到的后台任务又把规则加回来」。

- 新增 `egate_trip::can_apply_isolation_now()`（Armed 且未暂停），
  普通 `trip()` 与兜底封锁共用；
- 兜底路径在**取锁之后**调用它，不允许则直接返回「未执行」。

## 三、P0-02：Desktop 快照子事务的恢复依据被覆盖

- 外层不再用最初创建的 `base_ledger` 覆盖，改为**以磁盘账本为基底**
  重新读取（保留 `snapshot_swap` 等内层写入的字段）；账本损坏时直接报错、保留现场。
- `touched_files` 判定增加 `snapshot_swap.is_some()`：当前账号快照已
  `A → A.old` 时同样必须保留账本。

## 四、P0-03：删除账本可被后续操作覆盖

- 新增 `read_pending_delete_journal()`：开始新删除前检查，
  已有未完成事务则**拒绝**，账本损坏则报错（不覆盖）。
- 新增 `desktop::has_pending_delete()` 并接入统一门禁：
  `store::with_store()` 与完整迁移入口都拒绝在删除未收尾时写数据。
- `heal_desktop_delete()` 账号库读取失败时**不再猜「有登记」**，
  保留现场并报告，等待人工核对。

## 五、P0-05：GUI 未分派急救命令

`lib.rs::run()` 原先只提前分派 `--exit-restore` 与 `--list/--status`，
因此 `ClaudeSwitcher.exe --egate-restore` 会进入 GUI 流程——而卸载钩子与
故障提示让用户运行的正是这条命令。

- 改为统一分派 `ExitRestore / EgateRestore / EgateCheck / EgateStatus / List / Status`，
  全部在 WebView/托盘初始化之前执行并透传真实退出码。

## 六、P0-06：卸载恢复的异常路径

- `installer-hooks.nsh`：找不到恢复执行器时**不再默认放行**——
  「程序文件不在」不等于「防火墙规则不存在」，改为报错并中止卸载。
- 恢复成功后补删 `ClaudeBodyguard` 计划任务，避免留下指向已卸载程序的引用。
- **停止发布 MSI**（`targets` 改为 `["nsis"]`）：MSI 生命周期不同，
  无法套用 NSIS 钩子，在完成专用恢复机制前不宣称「支持安全卸载」。

## 七、必要 P1 与低成本项

| 编号 | 处理 |
| --- | --- |
| **P1-01** | Clash 回滚改为 Script/Merge **分别判定**，两者都成功才删账本；Script 回滚改用原子写入 + 回读校验（不再 `fs::copy` 覆盖） |
| **P1-03** | 迁移「已提交、清理失败」分支：逐项检查并如实报告，清理失败**保留账本**，数据不回滚 |
| **QW-01** | 兜底封锁只建**出站**规则（`outbound_only` 参数），不再把入站当作必要覆盖 |
| **QW-02** | `heal_desktop_delete` 读账号库失败时不再 `unwrap_or(true)` 猜登记存在 |
| **QW-03** | `clear_uncovered_lock()` 返回 `Result`，删除失败不再当成成功 |

## 八、验证

| 项 | 结果 |
| --- | --- |
| `cargo fmt --check` | 通过 |
| `cargo clippy --all-targets -- -D warnings` | **零警告** |
| `cargo test --lib` | **640 / 640 通过**（v0.6.12 为 636） |
| `npx tsc --noEmit` | 通过 |
| 前端构建 | 通过 |

新增回归：

- `isolation_reasons_use_separate_namespaces`：两种来源前缀不重叠、兜底仅出站
- `isolation_blocked_while_paused`：暂停期间不得施加隔离
- `pending_delete_blocks_second_delete` / `pending_delete_blocks_store_writes`

## 九、已知边界

- **未做**：防火墙特权助手与权限检测、TUN 可信路由证明、更新签名与维护事务、
  统一网络策略模块。这些需要独立提权进程或可信发布链。
- 应用仍以 `asInvoker` 启动：**非提权时防火墙规则可能创建失败**，
  如实报告 Degraded，不宣称已保护。
- 真实 Windows 破坏性验证（防火墙实际阻断、网卡恢复、NSIS 卸载流程、计划任务、托盘）
  未执行，需在可回滚虚拟机中进行。
- 许可证提示：上游 YOURSJEYO 主分支为 AGPL-3.0，本项目 Apache-2.0；
  继续移植其最新代码前需兼容性审查，本轮未移植。
