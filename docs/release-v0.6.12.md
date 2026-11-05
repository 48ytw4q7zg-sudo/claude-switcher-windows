# v0.6.12 — 第十三轮审计收口（误判修复与生命周期）

发布日期：2026-11-05
基线：v0.6.11（`f9c81c0`）→ 本版
依据：GPT-6 第十三轮源码复核（固定 `f9c81c01bc24`）

本轮五项 P0 中，**P0-B 是一条会直接导致误判的安全缺陷**：我上一版补防火墙端口/Profile
核验时，把 `$ok = $true` 放进了独立条件链的末尾，导致「动作/方向/程序已经不符，
只要后半段通过仍判成功」。

## 一、P0-B：防火墙核验条件链被覆盖（最严重）

| 问题 | 处理 |
| --- | --- |
| `egate_trip` 的核验脚本把端口/地址/Profile 写成**独立** `if` 链，末尾 `else { $ok = $true }` 会覆盖前面的动作/方向/程序判定 | 合并为**单一条件链**：`Enabled → Action → Direction → Program → 过滤器完整 → 端口 → 地址 → Profile → else $ok = $true`。任何一项不符都不会落到成功分支 |
| `egate_netcut` 把「过滤器查询不到」当成「没有限制」（`Any`） | 改为查不到即 `unknown`，不再把未知判成全局 |

**验证方式**：把核验脚本抽成真实 PowerShell 用例跑组合，覆盖
`all-good` / `bad-action` / `bad-direction` / `domain-only`，结果分别为
`True` / `False(bad-action)` / `False(bad-direction)` / `False(profile-limited)`。该组合已固化为回归测试。

## 二、P0-A：Desktop 失败后可能删除唯一恢复账本

原实现用**外层最初创建的** `base_ledger`（阶段 `Prepared`）判断「有没有动过文件」。
但内层可能已经推进到 `FilesSwitching`、清空了一半活目录后才失败——此时外层仍认为
「没动过」，于是把需要恢复的现场账本删掉。

修复：
- `DesktopTransaction` 增加 `phase` 字段（`Cell<DesktopSwitchPhase>`），
  `persist_backup_path` 与 `advance_ledger_phase` 成功后**回写真实阶段**；
- 失败时取「内存记录」与「磁盘账本」中**更靠后**的阶段作为判定依据；
- 只有确认未动过文件才清账本；动过则保留并写明实际阶段。
- 顺带为 `DesktopTransaction` 提供 `Default`，避免构造点遗漏字段。

## 三、P0-C：未接入兜底封锁的生命周期

原实现四个问题：意图文件一存在就跳过补齐、接入恢复后不解除、意图在规则之后写、
直接用 `trip()` 会**结束进程**。

修复：
- 新增 `egate_trip::enforce_uncovered_outbound()`：只建出站隔离规则，**不结束进程**；
  `quarantine_agent_with(.., kill=false)` 复用同一套规则逻辑，不新增第二套实现。
- **先写意图再动防火墙**；写入失败则本轮不施加规则（避免无归属的规则）。
- **每轮重新核验并补齐**：`all_isolated` 才标记 ready；部分生效保持 Degraded 并在下轮重试。
- 新增 `release_uncovered_lock()`：按「接入是否恢复」独立解除，不依赖普通熔断的
  `TRIP_STATE`——原实现只有在 `already_tripped` 时才进入 `Recover` 分支。
- 新增 `eguard-uncovered-lock-ready.json` 区分「打算锁」与「已全部生效」。

## 四、P0-D：删除快照的崩溃一致性

原实现「改名 → 存库 → 删目录」没有账本：崩在改名之后、存库之前时，登记还在、
正式目录却已不存在，数据只躺在待删目录里。

修复：
- 新增 `DesktopDeleteJournal`（事务 ID / 快照 ID / 原目录 / 待删目录 / 两个提交标记），
  在动文件**之前**落盘，每步推进后更新。
- 新增 `heal_desktop_delete()`：按「账号库登记 + 文件实际状态」判断——
  登记仍在 → 把目录改回正式名；登记已删 → 继续清理；状态不明 → 保留现场并报告。
- 回滚改名失败时**同时报告两个错误**（QW-03），不再声称「已恢复快照目录」。

## 五、P0-E：卸载前恢复

- 新增 `--exit-restore` 子命令：与 `--egate-restore` 同一条恢复协议，
  在 **GUI 初始化之前**执行，主界面起不来也能跑。
- 新增 `installer-hooks.nsh` 并通过 `nsis.installerHooks` 接入：
  `NSIS_HOOK_PREUNINSTALL` 调用该命令，**退出码非 0 则中止卸载**，
  提示用户先运行 `--egate-restore`。
- MSI 未接钩子（Windows Installer 生命周期不同），文档如实标注为未覆盖。

## 六、低成本项

| 项 | 处理 |
| --- | --- |
| QW-01 | 迁移清理失败逐项列出并保留账本，不再一律忽略 |
| QW-02 | 导出扫描排除 `<id>.old`、`<id>.new`、`.<id>.delete-pending-*`，事务残留不进迁移包 |

## 七、验证

| 项 | 结果 |
| --- | --- |
| `cargo fmt --check` | 通过 |
| `cargo clippy --all-targets -- -D warnings` | **零警告** |
| `cargo test --lib` | **636 / 636 通过**（v0.6.11 为 630） |
| `npx tsc --noEmit` | 通过 |
| 前端构建 | 通过 |

新增回归：

- `verification_chain_rejects_earlier_mismatch`：真实 PowerShell 跑四种组合，
  确认「前半段错、后半段对」不再判成功
- `failed_after_files_switching_keeps_ledger`：内层推进阶段后失败，事务上下文能反映
- `delete_journal_restores_directory_when_store_not_committed`
- `delete_journal_cleans_pending_when_store_committed`
- `uncovered_lock_state_files_are_independent`、`uncovered_enforcement_does_not_kill_processes`

## 八、已知边界

- **未做**：防火墙特权助手 / 自动开启防火墙、TUN 可信路由证明、更新签名与维护事务、
  MSI 卸载钩子、统一网络策略模块。这些需要独立提权进程、可信发布链或架构级改动。
- 应用仍以 `asInvoker` 启动：**非提权时防火墙规则可能创建失败**，此时如实报告
  Degraded，不会假装成功。
- 真实 Windows 破坏性验证（防火墙实际阻断、禁用网卡恢复、卸载流程、计划任务、托盘）
  仍未执行，需在可回滚虚拟机中进行。
- 许可证提示：上游 YOURSJEYO 当前主分支为 AGPL-3.0（此前版本为 MIT）。
  本项目为 Apache-2.0，继续移植其**最新**代码前需做兼容性审查；本轮未移植新上游代码。
