# v0.6.10 — 第十一轮审计收口（事务归属与入口分离）

发布日期：2026-11-05
基线：v0.6.9（`0b8ab32`）→ 本版
依据：GPT-6 第十一轮源码审计（固定 `0b8ab32001e7`）

本轮不再新增功能。重点是三件会让用户操作直接失效或恢复错账的问题：
**迁移账本写得太晚**、**手动解除被自动恢复的检查拦住**、**第二个实例在主实例确认前就执行恢复**。

## 一、迁移事务（P0-01 / 02 / 03 / 07）

| 缺陷 | 处理 |
| --- | --- |
| 账本在「旧快照目录已改名」之后才落盘 | 顺序改为：生成事务 ID 与两个计划备份路径 → **只写新增路径**的 `Prepared` 账本 → 暂存校验 → 备份账号库 → 改名快照 → 提交账号库 → 提交快照。任何一步失败都按账本恢复 |
| 最终提交标记写入失败仍继续清理并报成功 | 提交标记失败立即回滚（账号库 + 快照），不再继续删除备份、不再返回成功 |
| 账本损坏时新导入仍可继续 | 入口改为：`Ok(None)` 才允许导入；`Ok(Some)` 拒绝；`Err`（损坏/不可读）同样拒绝 |
| 导入/切换/捕获/删除之间缺少统一互斥 | 新增 `store::with_store_transaction()`：与账号库共用同一把跨进程锁，完整导入、迁移恢复、Desktop 切换/捕获/删除都在同一执行权内完成 |
| 快照提交是逐项合并，中断会留下半成品 | 暂存目录是完整目录，**一次 rename** 提交 |
| 备份路径用秒级时间戳，可能撞名 | 改用事务 UUID；已存在则拒绝覆盖 |

## 二、Desktop 事务归属（P0-05 / 06）

- 账号库新增 `last_desktop_transaction_id`（`#[serde(default)]`），与 `current_desktop_profile_id` **在同一次原子保存**中写入。
- 恢复器改为比较**事务 ID**，不再只看「目标账号相同」。新增回归：当前账号本来就是 B、但本次事务未提交时，必须回滚而不是误判成功。
- 新增回存子事务 `snapshot_swap`：`A → A.old` 之前先把恢复依据写进账本；启动时若正式快照缺失且 `.old` 完整，自动请回；`.new` 半成品清理失败则保留账本。

## 三、隔离解除入口分离（P0-04）

- 新增 `ReleaseReason::{Automatic, UserRequested, Emergency}`：
  - **Automatic**（监控）：持锁后仍检查 `ManualHold`，`Held`/`Unknown` 一律放弃解除；
  - **UserRequested**（用户点「解除隔离」）：不受手动保持拦截，解除并核验后清除意图；
  - **Emergency**（急救/恢复）：走已持锁入口，明确按停止保护协议执行。
- 修复了「手动隔离后，普通解除按钮也被拦住」的死锁式体验。

## 四、单实例与启动顺序（P0-10）

- 断网自愈、迁移恢复、Desktop 恢复、熔断状态重建与监控启动**全部移入 `setup`**，即单实例插件完成转交之后。
- 第二个实例不会再触碰正在运行主实例管理的事务。
- CLI 急救（`--egate-restore`）仍保留独立恢复能力。

## 五、防火墙有效性（P0-09）

- 新增共享 `platform::effective_firewall_enabled()`：按 `Get-NetFirewallProfile -PolicyStore ActiveStore` +
  `Get-NetConnectionProfile` 判定**当前活动网络**所属配置档是否开启。
- 应用级隔离核验补齐 `ActiveStore` 中的**方向与程序过滤条件**；活动网络防火墙关闭时判为未生效。
- 全局断网规则同样复用它，两个模块不再各判一套。
- 本机实跑确认：三档配置全部关闭、活动连接为 `Public`，函数返回 `Some(false)`。

## 六、Clash 双文件崩溃账本（P1-01）

- 新增 `rules-transaction.json`：修改前记录两个文件的原始内容，每个文件提交与内核验证分别推进阶段。
- 启动时 `heal_rules_transaction()` 按精确记录恢复；恢复失败保留账本不删除现场。

## 七、其他

| 项 | 处理 |
| --- | --- |
| 切号使用上一笔事务的备份回滚 | 日志加 `transaction_id`；新切换发现残留日志即拒绝；回滚只接受本次事务 ID 的备份 |
| `read_switch_journal()` 把损坏当「没有日志」 | 改为三态：不存在 `Ok(None)`、损坏 `Err` |
| 导入内存峰值 | 密文文件大小前置校验；暂存改为逐条解码→写入，不再同时保留整份解码结果 |
| P1-02 进程身份 | 上一版已实现 GUI 安装路径白名单；本版未改动 |

## 八、验证

| 项 | 结果 |
| --- | --- |
| `cargo fmt --check` | 通过 |
| `cargo clippy --all-targets -- -D warnings` | **零警告** |
| `cargo test --lib` | **625 / 625 通过**（v0.6.9 为 615） |
| `npx tsc --noEmit` | 通过 |
| 前端构建 | 通过 |

新增回归测试：

- `migration_journal_exists_before_snapshot_rename`、`import_refuses_when_journal_is_corrupt`、
  `failed_import_rolls_back_both_sides`（失败时账号库与快照同时回滚）
- `heal_requires_matching_transaction_id_not_just_target`、`heal_restores_snapshot_from_retired`
- `corrupt_switch_journal_is_an_error_not_none`、`rollback_rejects_foreign_transaction_backup`
- `manual_hold_blocks_only_automatic_release`

## 九、已知边界

- 真实 Windows 系统行为（防火墙真实阻断、禁用网卡后恢复、计划任务、托盘交互）仍未做破坏性故障注入；
  该部分必须在可回滚虚拟机中进行。本机实测仅覆盖非破坏性 PowerShell 查询与脚本执行。
- 本轮未做：TUN 可信路由证明（P1-04）、未接入时的独立兜底封锁、切号前强制环境审计（P1-05）。
  这些属于「按需能力」，不影响已实现路径的正确性。
- 安装器仍无 Authenticode 发布者核验（P1-03）：当前保留 SHA256 校验 + 用户确认安装，
  不宣称满足完整签名更新契约。
