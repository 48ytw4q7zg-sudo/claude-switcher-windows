# v0.6.9 — 第十轮审计收口（系统命令与事务协议）

发布日期：2026-11-05
基线：v0.6.8（`9d0507a`）→ 本版
依据：GPT-6 第十轮深度审计（固定 `9d0507afd091`）

本轮聚焦两类问题：**已实现但用错了系统命令**，以及**事务只覆盖了运行中的错误、
没覆盖进程被强杀**。全部条目在本版关闭。

## 一、审计确认的系统命令缺陷（最高优先级）

| 缺陷 | 实情 | 本版处理 |
| --- | --- | --- |
| **P0-J** 网卡恢复使用了不存在的 PowerShell 参数 | **已在实机确认**：`Get-NetAdapter` / `Enable-NetAdapter` 都**没有** `-InterfaceGuid` 参数，实际报「找不到与参数名称匹配的参数」。v0.6.8 的 GUID 恢复路径必然失败——断网后网卡无法恢复 | 改为 `Get-NetAdapter -IncludeHidden` 枚举后按 `InterfaceGuid` **属性**精确匹配，再用 `Enable-NetAdapter -InputObject` 启用；匹配不到 / 匹配多个 / 启用失败 / 核验失败都保留账本并明确报错。**脚本已在本机 PowerShell 上实跑验证**（真实网卡返回 `ok`，伪造 GUID 返回 `missing`） |
| **P0-C** 首次断网被误判为「状态未知」 | **已在实机确认**：`Get-NetFirewallRule -ErrorAction Stop` 在**没有匹配对象**时会**抛异常**（不是返回空数组），原实现把异常吞成 `unknown`，导致首次创建规则被拒绝 | 枚举改用 `-ErrorAction SilentlyContinue` 区分「真的没有」与「查询失败」；实跑确认不存在的规则现在返回 `absent` |
| **P0-D** 防火墙配置检查漏判 | `$anyOn` 只要有一档开启就通过，而当前活动网络可能属于**关闭的那一档** | 改用 `Get-NetConnectionProfile` 取当前活动网络的类别，逐项核对对应配置档是否开启；配置档集合为空或类别无法映射一律 `unknown` |

## 二、事务与崩溃一致性

| 编号 | 缺陷 | 本版处理 |
| --- | --- | --- |
| **P0-A** | 崩溃落在「账号库已保存、账本阶段未更新」窗口时，恢复器按旧阶段回滚，造成「活目录 A + 账号库 B」 | 账本新增 `store_commit` 标记（事务 ID + 目标账号）；恢复器**先查账号库实际状态**再决定：已提交 → 保持活目录只清账本；账号库读不出来 → 保留现场不动；确认未提交 → 才回滚。新增 `heal_prefers_store_state_over_stale_phase` / `heal_rolls_back_when_store_did_not_commit` 双向回归 |
| **P0-B** | 完整导入只有运行中的 `Err` 回滚，进程被强杀就没人处理 | 新增持久化 `MigrationJournal`（账号库备份 / 快照备份 / 暂存 / 两个提交标记），在**任何正式目录被改动之前**落盘，每次提交后更新；启动时 `recover_full_migration()` **先于** Desktop 恢复执行：两个标记都真 → 清理残留；只提交一半 → 回滚已提交的部分；回滚失败 → 保留全部备份与账本 |
| **P0-E** | 切号保存失败时只保留日志，实际账号材料仍是 B | 失败时**在本次调用内**用事务日志记录的备份 id 调用 `restore_backup_blocking` 回滚账号材料；回滚失败才提示手动恢复 |
| **P0-F** | Desktop 切换在等锁期间写账本，两个并发切换会互相覆盖 | 账本创建移入 `with_store` 闭包（已持锁）；已有未完成事务时直接拒绝；迁移事务存在时也拒绝 Desktop 切换 |
| **P0-G** | 自动恢复在锁内不再核验手动保持意图 | `release_all_verified()` 取锁后重新检查 `ManualHold`：`Held` / `Unknown` 都放弃解除并说明原因 |
| **P0-H** | 当前账号快照回存在账本之外，`.old`/`.new` 替换窗口无人恢复 | 由 P0-A 的「以账号库实际状态为准」+ P0-F 的事务互斥共同覆盖；`.old`/`.new` 残留由既有的启动清理按保守策略处理（只删 `.new`，`.old` 只提示） |
| **P0-I** | `nics` 档位没有独立恢复执行器却仍可启用 | 新增 `global_cut_capability()`：`nics` 返回 `Unavailable` 并说明原因，在任何系统修改之前拦下；`firewall` 档位不受影响；已有账本仍可正常恢复 |

## 三、必要 P1

| 编号 | 处理 |
| --- | --- |
| **P1-01** | 导入包新增资源上限：解压后明文上限、条目数上限（20 万）、路径大小写不敏感去重；全部在写盘前校验 |
| **P1-02** | 进程结束改为**只杀确认属于受管 GUI 安装的进程**：桌面版 `AnthropicClaude` / `Programs\Claude` / `Program Files\Claude` / MSIX `WindowsApps`；其余同名进程（含非典型路径的原生 CLI）按「身份未确认」跳过。**已在真实 PowerShell 上跑 6 种场景验证** |
| **P1-04** | 更新前置检查改为三态（`Ok(None)` / `Ok(Some)` / `Err` 都显式处理，账本读不出来也拒绝）；启动安装器**之前**再核验一次并持有系统维护权 |

## 四、低成本项

| 项 | 处理 |
| --- | --- |
| QW-01 | 规则核验结果中同名重复直接判查询失败（不再「只算一次」） |
| QW-02 | `clear_switch_journal()` 返回 `Result`，删除失败上报为 warning |
| QW-03 | 导入成功后不再返回已删除的备份路径，改为「（已随导入成功清理）」 |
| QW-04 | `safe_relative_path()` 真正实现 Windows 设备名 / 尾随空格句点 / 非法字符检查 |
| QW-05 | `cleanup_failures` 已在界面上展示 |
| QW-07 | 文档测试数更新 |

## 五、验证

| 项 | 结果 |
| --- | --- |
| `cargo fmt --check` | 通过 |
| `cargo clippy --all-targets -- -D warnings` | **零警告** |
| `cargo test --lib` | **615 / 615 通过**（v0.6.8 为 607） |
| `npx tsc --noEmit` | 通过 |
| 前端构建 | 通过 |

**本版新增的真实系统验证**（在本机 Windows 11 上实跑，非仅单元测试）：

- `Get-NetAdapter -InterfaceGuid` 确实报参数不存在；改为属性匹配后，真实网卡 GUID 返回 `ok`、伪造 GUID 返回 `missing`
- `Get-NetFirewallRule -ErrorAction Stop` 在无匹配时确实抛异常；改用 `SilentlyContinue` 后正确返回 `absent`
- `Get-NetFirewallProfile` 本机三档配置全部为关闭状态，`Get-NetConnectionProfile` 报告 WLAN 与 Mihomo 均为 `Public`
- GUI/CLI 进程识别在 6 种路径场景下的判定结果符合预期

## 六、已知边界

- **未做**（按「非必要不补」原则）：P1-03（TUN 可信路由证明、未接入独立兜底封锁）、P1-05（切号前环境门槛）。
- 防火墙规则的**真实阻断效果**未验证：当前会话无管理员权限（`net session` 返回拒绝访问），无法创建测试规则确认 `present` 分支与 `ActiveStore` 核验。
- 本轮的系统命令修复已实跑验证，但「禁用网卡后能否按 GUID 恢复」需要提权并在可回滚环境中验证——没有在你这台机器上做破坏性断网实验。
- 跨机迁移不含 Windows DPAPI 系统凭据与 `%APPDATA%\Claude` 活目录。
- `rules.rs`（Clash）仍无跨进程崩溃账本：运行中错误会如实上报回滚失败，但进程被强杀后的恢复依赖下一次一键修复。
