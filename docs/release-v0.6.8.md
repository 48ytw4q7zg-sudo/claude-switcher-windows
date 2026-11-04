# v0.6.8 — 第九轮审计收口（小修订版）

发布日期：2026-11-05
基线：v0.6.7（`36764f7`）→ 本版
依据：GPT-6 第九轮深度审计（固定 `36764f731e86e6b36a5b914e4889ac90cd5e7634`）

本轮**不新增功能**。审计指出的「已实现但事务不完整」项逐条补成可确认、可回滚、
可恢复的完整事务。全部条目在本版关闭。

## 一、审计点名的四个不可跳过项

| 编号 | 缺陷 | 本版处理 | 证据 |
| --- | --- | --- | --- |
| **P0-01** | 新防火墙规则**创建**用 `rule_name_for_exe()`（带路径哈希后缀），**核验**却在 PowerShell 里重新拼旧格式名字——新建规则永远核验不到，`coverage_complete` 恒为 false | 新增 `expected_rules()` 作为**唯一**规则标识来源：创建与核验共用同一份清单，预期规则（名称+方向+程序）整体序列化后传给脚本，脚本不再自行拼接。解析端按名称**逐项匹配**，未出现/重复/非预期名称都不计入通过 | `egate_trip.rs` `expected_rules` / `count_rules_for` / `parse_rule_verification_expected`；`rule_verification_matches_expected_names` 含「旧格式名字必须判失败」回归 |
| **P0-02** | 新增的 `backup_verified` 阶段没有进入恢复器，关键崩溃窗口无人回滚 | 阶段改为可序列化枚举 `DesktopSwitchPhase`（Prepared / BackupVerified / FilesSwitching / FilesSwitched / StoreCommitted / Completed / Unknown），恢复器改为**穷尽 match**——新增阶段忘记处理会编译失败。`BackupVerified` 与两个 Files 阶段统一走回滚；`StoreCommitted` 明确不回滚；`Unknown` 绝不删除。不可逆修改前先落 `FilesSwitching`；`clear_switch_ledger` 改为返回 `Result`；账本读不到时拒绝继续破坏性修改 | `desktop.rs`；`heal_handles_every_phase` 逐阶段模拟崩溃、`heal_keeps_live_when_backup_missing`、`legacy_string_phase_deserializes_to_unknown` |
| **P0-03** | 完整迁移导入失败时只回滚快照目录，账号库已被替换 → 新旧混合状态 | 导入改为五步事务：备份账号库 → 备份快照目录 → 提交账号库 → 提交快照 → 清理。快照落位失败时**同时回滚账号库与快照**；回滚失败保留备份与暂存并逐项报告。新增 `backup_current_store_for_import` / `restore_store_backup` | `export.rs`；`full_import_*` 系列测试 |
| **P0-04** | 导出号称「同一快照视图」，实际先 `load_store()` 再遍历目录，两步之间无锁 | 新增 `store::with_store_read()`（与 `with_store` 同一把跨进程锁 + 进程内 Mutex，只读不写回），导出的账号库读取与快照收集全部在该锁内完成 | `store.rs` `with_store_read`；`export_full_migration_blocking` |
| **P0-05** | 全局账号切换在 `with_store` 闭包内就删除切换日志，而账号库保存发生在闭包**之后** | `write_switch_journal()` 改为返回 `Result` 并在动数据前强制落盘（失败即中止）；`clear_switch_journal()` 移出闭包，只在 `with_store` 真正返回 Ok 之后调用；失败时保留日志并在错误信息中说明 | `lib.rs` `switch_profile_blocking` |

## 二、其余 P0

| 编号 | 缺陷 | 本版处理 |
| --- | --- | --- |
| **P0-06** | 网卡快照已保存 GUID，但恢复仍按名称 Enable | 新增 `enable_nics_by_guid()`：按 `InterfaceGuid` 定位并核验 `AdminStatus`，只恢复「本次禁用过且原始状态为 Up」的设备；GUID 找不到时保留账本并报出具体设备，**不拿同名设备顶替**；只有旧账本（无 GUID）才回退名称路径 |
| **P0-07** | 断网规则只查第一条同名规则，不验证生效策略 | `query_cut_rule()` 改为：全部同名规则属性必须正确 + 必须出现在 `ActiveStore` + 防火墙配置档至少一档开启，否则返回新增的 `RuleState::Unknown`；`Unknown` 时 `ensure_firewall_cut_rule` **既不重建也不宣称成功** |
| **P0-08** | 手动保持隔离写盘失败被忽略、读取失败当「没有手动保持」、且是在施加隔离**之后**才写意图 | `mark_manual_hold` / `clear_manual_hold` 改为返回 `Result`；新增 `ManualHold { Held, None, Unknown }` 三态，`Unknown` **不允许自动解除**；手动隔离改为**先持久化意图再施加隔离**，写入失败则取消本次隔离 |
| **P0-09** | 新门禁 `kill_agent_processes()` 仍调用通用按名查杀 | 改为复用 `kill_desktop_app_processes()`；该函数同时加强：读不到映像路径的进程**一律跳过**（无法证明是 GUI 时不盲目结束） |
| **P0-10** | MSIX 的 `InstallLocation`（目录）被直接当成 exe 传给 `-Program` | 改为解析 `AppxManifest.xml` 的 `Application Executable`，拼成完整路径并确认是文件（`-PathType Leaf`），取不到就跳过 |
| **P0-11** | Clash 回滚失败被 `let _ = restore_merge(...)` 吞掉 | 新增 `rollback_merge_or_report()`，所有错误分支改用并把回滚失败拼进错误信息 |
| **P0-12** | 托盘/窗口退出直接 `app.exit(0)`，隔离与断网规则留在系统上 | 新增 `tray::request_safe_exit()`：先 `restore_all()`，`complete` 才退出；失败则保持应用可用并给出未恢复资源与 `--egate-restore` 急救指令。托盘与窗口两个入口共用同一函数 |
| **P0-13** | 系统代理模式只看内核进程存在 | 新增 `proxy_port_reachable()`（300ms TCP connect）与 `is_loopback_host()`；代理「地址有效」与「端口可连」分开判定，只有回环地址才做端口探测。真实出口仍由门禁的显式代理探测决定 |

## 三、必要 P1

| 编号 | 处理 |
| --- | --- |
| **P1-01** | 完整导出只打包受管账号快照：排除 `.live-backup` 与 `_*` 事务目录；单文件超限与总大小超限改为**拒绝导出**（不再静默跳过）；空 Desktop 快照的 v3 包可正常导入（暂存目录总是创建） |
| **P1-04** | 更新前置检查：存在断网账本、隔离中、或隔离状态无法确认时拒绝安装 |

## 四、低成本高收益

| 项 | 处理 |
| --- | --- |
| QW-01 | `--egate-status` 在有无法确认项时返回退出码 **3**（0=全部已知） |
| QW-02 | 配置迁移备份改为「毫秒时间戳 + 唯一后缀 + `create_new`」，绝不覆盖已有备份 |
| QW-03 | 规则核验按名称逐项匹配，重复结果不能凑数，非预期名称直接判查询失败 |
| QW-04 | `verify_nics_up()` 严格解析（已在前版完成，本版保持） |
| QW-05 | 导入备份/暂存清理失败不再静默：`FullImportResult.cleanup_failures` 如实列出 |
| QW-06 | 对等文档中的旧测试数更新为当前值 |

## 五、验证

| 项 | 结果 |
| --- | --- |
| `cargo fmt --check` | 通过 |
| `cargo clippy --all-targets -- -D warnings` | **零警告** |
| `cargo test --lib` | **607 / 607 通过**（v0.6.7 为 599） |
| `npx tsc --noEmit` | 通过 |
| `npm run build` | 通过（346.34 kB / gzip 105.64 kB） |

新增测试覆盖：

- `egate_trip`：预期规则名与核验名一致（含旧格式名字必须判失败的回归）、重复结果不凑数、缺失条目判失败、非预期形状判查询失败
- `desktop`：**逐个事务阶段**模拟崩溃（Prepared / BackupVerified / FilesSwitching / FilesSwitched / StoreCommitted / Unknown）、备份缺失时不删活目录、旧字符串阶段反序列化为 Unknown
- `export`：空 Desktop 快照的 v3 包可导入、导出排除事务中间目录
- `egate_access`：回环地址判定、监听端口可达、已关闭端口不可达

## 六、已知边界（不影响本轮关闭项）

- 系统级行为（防火墙真实阻断、网卡禁用/恢复、计划任务、托盘交互）仍只有逻辑、
  解析与故障注入层面的测试；**真实 Windows 行为验证需要在可回滚的虚拟机中进行**。
- 跨机迁移**不包含** Windows DPAPI 系统凭据与 `%APPDATA%\Claude` 活目录，
  换机后 Claude Desktop 可能需要重新登录。
- TUN 模式仍未实现可信路由证明，当前策略是准确报告「路由未验证，主动探测已跳过」；
  未接入时的独立兜底封锁也未与 ClaudeGuard 的 `lockdown_on_uncovered` 完全对齐。
- 全局断网的 `nics` 档位仍依赖启动自愈与 `--egate-restore` 恢复，
  尚无独立于主程序的恢复执行器。
