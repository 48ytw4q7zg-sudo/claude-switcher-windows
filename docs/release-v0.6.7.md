# v0.6.7 — 第八轮审计收口（小修订版）

发布日期：2026-11-05
基线：v0.6.6（`00c0716`）→ 本版
依据：GPT-6 第八轮审计（固定 `00c071686e0cdbca9db5b4a5d1c4f5c32ff0218e`）

本轮**不再堆功能**，只把审计指出的缺陷逐条落到源码并补上验收测试。
所有条目在本版内关闭，不留下轮。

## 一、审计确认的五个关键缺陷

| 编号 | 缺陷 | 本版处理 | 证据 |
| --- | --- | --- | --- |
| **P0-01** | Desktop 崩溃恢复账本存在时间窗口：备份完成后才记账，崩溃时 `backup_path=None` 会让恢复器删掉唯一副本 | 备份一落地即 `persist_backup_path` 写盘（失败即中止切换，原账号未动）；自愈遇到「原本有数据 + 缺备份」**绝不清理**，保留现场；清理失败时保留账本待重试 | `desktop.rs` `persist_backup_path` / `heal_desktop_switch` |
| **P0-02** | 网卡快照枚举后即被 `map` 成名字丢弃 | 保留完整 `Vec<AdapterSnapshot>`（`guid` + 原始 `admin_up`），计划/进度/最终账本全部携带同一份快照 | `egate_netcut.rs` `cut()` / `CutState.adapter_snapshots` |
| **P0-03** | 全局断网规则只按名字查存在，未核验属性 | `RuleState` 三态（Present / Absent / WrongAttributes）+ 属性核验 + 删除重建 + 创建后回读；查询输出非预期一律报错，不再当成「不存在」 | `egate_netcut.rs` `query_cut_rule` / `ensure_firewall_cut_rule` |
| **P0-04** | Clash 双文件回滚存在提前返回漏洞 | 代理组校验、托管块生成、Script 备份、Script 写入、内核验证失败均统一回滚 Merge.yaml；「Script 未改但 Merge 已改」也回滚 | `rules.rs` `ensure_rules()` |
| **P0-05** | 旧保镖把 `Unsupported` 系统代理当成可用 | 改为只接受 `ProxyParse::Http(addr)`；`Unsupported` / `Empty` 一律不算代理可用 | `guard.rs` `use_system_proxy` |

## 二、其余 P0

| 编号 | 缺陷 | 本版处理 |
| --- | --- | --- |
| **P0-06** | 熔断决策在拿到系统操作锁后仍按旧意图执行 | `egate_trip::trip()` 取锁后**重新核验**保护意图与暂停状态；`guard_tick()` 在真正 `kill` 前同样复核 |
| **P0-07** | 手动封锁会被下一轮自动恢复解除 | 新增持久化 `ManualHold` 意图（`eguard-manual-hold.json`）；手动熔断写入、手动解除清除、`RecoveryEligibility.manual_hold` 读真实意图 |
| **P0-08** | 应用隔离只取「第一个运行中的进程」，未运行的已安装应用无法预先隔离，且不核验 `ActiveStore` | 新增 `resolve_agent_exe_candidates()`：运行进程 + 注册表 `App Paths`/`Uninstall` + MSIX 三源合并去重；每个路径**独立规则名**（路径哈希后缀）逐条建立；核验要求属性正确**且**出现在 `ActiveStore`；新路径生效后才清理指向旧路径的失效规则（`prune_stale_rule_targets`）；解析不到路径时明确报告「保护未完成」 |

## 三、必要 P1

| 编号 | 缺陷 | 本版处理 |
| --- | --- | --- |
| **P1-01（本轮新增实现）** | 加密导出包只含账号库，不含 Desktop 快照 | 新增 **CSBK1 v3 完整迁移包**：账号库 + `desktop-accounts/` 全部文件。导出在**同一次 `load_store()` 视图**下打包；每条文件记 SHA256；导入先解到隔离暂存目录、严格校验路径（拒绝绝对路径/`..`/盘符/设备名）与哈希，再事务性落位；账号库与快照目录任一步失败都回滚，不留半截状态。v2 包仍兼容，但走完整导入时会**明确提示不含 Desktop 快照** |
| **P1-02** | 配置迁移未覆盖所有入口 | `update()` 改走 `load_from_migrated`，写入路径同样受版本校验 |
| **P1-03** | `--egate-status` 把读取失败吞成 `None`，且读本进程内存冒充全系统状态 | 断网账本错误单独输出 `network_cut_error`；`tripped` 改为按实际隔离规则数判定，查询失败输出 `null`（unknown） |
| **P1-04** | 安装器「启动」被报告成「已安装」 | `installed` 恒为 `false`，文案明确「仅表示安装向导已启动，需按向导完成并重启」 |

## 四、低成本高收益

| 项 | 本版处理 |
| --- | --- |
| 关闭检查被计入失败 | `ChecksSummary` 增加 `skipped` 计数；skipped 既不算 ok 也不算 fail，不影响 `passed` |
| 关闭 DNS 检查后仍发解析请求 | 按 `enabled("dns")` 决定是否执行 |
| 禁用核心检查会部分提交 | 先整体校验，存在核心项直接拒绝，**不写入任何内容** |
| 熔断状态查询失败被当成「未熔断」 | 新增 `trip_state_unknown` 三态；GUI 显示「隔离状态无法确认」，启动门禁**阻止启动**并说明原因，监控循环不动作 |
| 暂停状态文件损坏静默回退 | 损坏/不可读时记日志并按「未暂停」处理（保护继续生效，而非延长暂停） |
| `guard_is_not_send()` 实际没测 | 改为真正的**编译期负向断言**（`AmbiguousIfImpl` 歧义推断）：把 `PhantomData<*const ()>` 换成 `PhantomData<u8>` 会直接 E0283 编译失败。已实测正反两向 |
| TUN 下 `probed` 误报「已探测」 | `probed` 改为按**最终 `ProbeRoute`** 判定；TUN 明确输出「路由未验证，主动探测已跳过」 |
| 保镖误杀 CLI | 新增 `kill_desktop_app_processes()`：按映像路径识别 `node`/`npm`/`nvm`/`fnm`/`volta`/`node_modules` 等 CLI 宿主并**跳过**，只结束桌面 GUI；跳过的进程如实记入结果 |

## 五、验证

| 项 | 结果 |
| --- | --- |
| `cargo fmt --check` | 通过 |
| `cargo clippy --all-targets -- -D warnings` | **零警告** |
| `cargo test --lib` | **599 / 599 通过**（v0.6.6 为 584） |
| `npx tsc --noEmit` | 通过 |
| `npm run build` | 通过（346.21 kB / gzip 105.58 kB） |

新增测试覆盖：

- `egate_lock`：`!Send` 编译期反证（正反两向实测）
- `egate_trip`：多路径规则名隔离与幂等、核验解析严格性、候选路径去重
- `egate_launch`：未知隔离状态阻止启动且理由与「已熔断」区分
- `egate_check`：TUN 跳过探测的原因文案、接入计数不因 `probed` 语义变化而丢失
- `export`：v2/v3 版本字节互斥、完整迁移包端到端往返（导出→另一 USERPROFILE 导入→账号库与快照同时恢复、凭据在目标机重新加密）、路径逃逸拒绝、哈希不匹配拒绝、暂存失败不落盘、旧快照替换后无残留

## 六、已知边界（不影响本轮关闭项）

- 系统级操作（防火墙、网卡、计划任务、Tray）仍只有逻辑/拼接测试与静态核验；
  真实 Windows 故障注入需在可回滚的虚拟机中执行。
- 跨机迁移**不包含** Windows DPAPI 系统凭据与 `%APPDATA%\Claude` 活目录，
  换机后 Claude Desktop 可能需要重新登录。这一点在导入确认框里明示。
- TUN 模式仍未实现可信路由证明，当前策略是**准确地报告未验证**而非假装通过。
