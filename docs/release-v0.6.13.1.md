# v0.6.13.1 — 第十五轮审计收口（恢复完整性与放行条件）

发布日期：2026-11-05
基线：v0.6.13（`e954b01`）→ 本版
依据：GPT-6 第十五轮深度复审（固定 `e954b01`）

本轮四项 P0 中，**P0-01 是 v0.6.13 拆分命名空间后引入的回归**：
全量恢复只删了其中一个命名空间。

## 一、P0-01：紧急恢复漏掉兜底封锁规则（回归）

v0.6.13 把隔离拆成 `ClaudeSwitcher AppIsolation` 与 `ClaudeSwitcher UncoveredLock`
两个命名空间，但：

- `release_all_verified_locked()` 仍只按 `AppIsolation` 前缀删除；
- `rule_count()` 也只统计该前缀。

后果：用户执行紧急恢复 / 退出 / 卸载前恢复时，程序报告「应用隔离已全部解除」，
**兜底封锁规则仍留在防火墙里**继续拦截受管应用。

修复：
- 全量解除改为遍历**两个**现行前缀 + 旧版遗留规则，分别删除、分别统计；
  每个前缀的清理失败单独记录进 `failures`。
- `rule_count()` 同时统计两个命名空间 + 旧版规则——「AppIsolation 为 0」
  不再等于「没有任何隔离」。

## 二、P0-02：接入路径未验证就解除兜底封锁

原实现只要 `path` 是 `system_proxy` 或 `tun` 就放行：

- 代理开着但端口不通 / 服务已挂 → 应用实际仍在裸连；
- TUN 网卡 Up 但没有路由证据 → 流量可能仍走物理网卡。

新增 `can_release_uncovered()`，四个条件**同时**满足才允许解除：
1. 本轮确实执行了探测（`probed == true`）；
2. 所有启用目标 `Pass`；
3. 接入路径有可信证据（当前仅 `system_proxy`；TUN 无路由证明一律不放行）；
4. 保护意图允许自动恢复（Armed、未暂停、无手动保持）。

## 三、P0-03：熔断后不再复核，规则被外部删除也不补齐

`rebuild_trip_state_from_system()` 只在启动时调用，运行中 `already_tripped`
且出口仍不合格时直接 `Idle`——规则被其他程序/组策略删除后，
界面仍显示「完整保护」。

修复：
- 新增 `egate_trip::verify_current_isolation()`：复用 `ActiveStore` + 属性 +
  过滤器全覆盖核验（不是数规则条数）；
- 巡检中若已标记完整熔断，**每轮重新核验**：覆盖不足 → 降级为 Partial 并补齐；
  查询失败 → 标记「无法确认」；
- `decide()` 在 `already_tripped + partial_protection` 时返回 `RetryProtection`，
  使降级后能真正补齐。

## 四、P0-04：停止保护意图写入失败后仍继续恢复

原顺序是「写 Disarmed → 失败也继续恢复网络与防火墙 → 最后报未完整」。
此时后台仍是 Armed，下一轮会立刻把刚解除的隔离重新加上——
用户看到「恢复了，然后又断了」。

改为**强制前置门禁**：`disarm()` 失败立即返回，不执行任何网络/隔离恢复，
并在报告里明确写出「本次未执行恢复」。

## 五、低成本项

| 项 | 处理 |
| --- | --- |
| **L-01** | 前端 `TripReport` 字段与 Rust 契约不一致：Rust 返回 `any_isolated`/`all_isolated`，前端读 `isolated`。已改正类型并分别显示「全部隔离 / 部分隔离 / 未确认隔离」 |
| **L-02** | `--egate-check` 改用 `load_checked()`：配置损坏时明确报错并返回非零，不再用默认目标得出与 GUI 不一致的结论 |
| **L-03** | `egate_monitor_status()` 增加 `uncovered_lock` / `uncovered_lock_verified`；面板显示「兜底封锁中 / 覆盖不完整」，依据真实核验而非仅看意图文件 |
| **L-04** | 为 WebView 设置 CSP（`default-src 'self'`，允许 Tauri IPC 与本地开发端口），不再为 `null` |

## 六、验证

| 项 | 结果 |
| --- | --- |
| `cargo fmt --check` | 通过 |
| `cargo clippy --all-targets -- -D warnings` | **零警告** |
| `cargo test --lib` | **643 / 643 通过**（v0.6.13 为 640） |
| `npx tsc --noEmit` | 通过 |
| 前端构建 | 通过（含 CSP 变更） |

新增回归：

- `full_release_and_count_cover_both_namespaces`：两个前缀互不包含、都被统计
- `release_eligibility_requires_verified_access`：仅 `system_proxy` 可放行
- `restore_aborts_when_disarm_fails`：意图写不进去时恢复不执行

## 七、安装包

- `ClaudeSwitcher_0.6.13_x64-setup.exe`（NSIS）
- `ClaudeSwitcher-portable.zip`

**安装包版本号仍为 `0.6.13`**（Tauri bundle 版本需三段式），
源码版本为 `0.6.13.1`。MSI 继续停发。

## 八、已知边界

- **未做**：防火墙特权助手与权限检测（P1-02）、TUN-only 路由验证（P1-01）、
  更新签名清单（P1-03）、系统证据读取错误分类（P1-04）。
  其中 P1-04 影响「读取失败被当成未接入」的判断，下一轮优先。
- 应用以 `asInvoker` 启动，**非提权时防火墙规则可能创建失败**，如实报告 Degraded。
- 真实 Windows 破坏性验证（防火墙实际阻断、网卡恢复、NSIS 卸载、计划任务、托盘）
  未执行，需在可回滚虚拟机中进行。
- `CutMode::Nics` 仍明确不可用（无独立恢复执行器），这是有意保留的安全门控。
- 许可证：上游 YOURSJEYO 主分支为 AGPL-3.0，本项目 Apache-2.0；
  `docs/upstream-baseline.md` 中「MIT」的表述已标注需重新核实。
