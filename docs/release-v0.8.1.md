# v0.8.1 发布说明（崩溃恢复与事务身份收口）

> 日期：2026-11-06｜基线：v0.7.7 → **v0.8.1**
> 版本号跳过 v0.8.0：本轮是事务/崩溃恢复层面的大修订，留一个空号便于区分
> 「已发布的 v0.7.7」与本地中间态。
>
> 主题：**崩溃之后系统还得是安全的**——要么保住有效保护，要么停下来报错，
> 不能因为一次可恢复的错误就先失去所有阻断。

## 0. 一句话结论

v0.7.7 修好了「同一事实只有一个判据」。这一版修它的下一层：
**「事务中间崩溃之后，系统处在什么状态」**。三个 P0 都是「中间态」问题——
`::pending` 规则可能被当成垃圾删掉、同一次封锁拿到两个事务号、
自动解除绕过了刚立的事务保护。

---

## 1. P0-01：`::pending` 规则可能在新规则验证前被删

**问题**：替换流程是「删掉 `::pending` → 新建 → 核验 → 删旧 → 改名」。
但 `::pending` **不一定是垃圾**。

真实崩溃序列：上次操作已建好并核验了临时阻断规则，但在「删旧规则、改回正式名」
之前进程崩了。此时临时规则是**实际生效的保护资源**。下一轮先把它删掉、再尝试
重建——新建一旦失败，就从「有保护」变成「没保护」。

**修复**（含 L-01）：

1. 正式名规则已完整有效 → `existing`，不动任何东西；
2. 存在**已核验**的 pending → **继续完成上次未完成的改名**，不删它（`resumed`）；
3. 否则新建一条**带唯一后缀**的 pending（不先删任何现有阻断资源），核验通过后
   才清理旧规则与无效 pending，最后改名；
4. 改名失败 → 保留已验证的 pending，报告可恢复状态。

**L-10** 同时修掉：`Test-Rule` 改成三态 `ok / unhealthy / query-failed`。
「读不到旧规则属性」不是「属性不健康」，那种情况**不能**盲目进入替换流程。

---

## 2. P0-02：阶段推进换了事务身份，且提交不在锁内

**两个问题**：

**其一**：`mark_uncovered_lock_with_phase()` 每次调用都 `Uuid::new_v4()`。
于是同一次封锁从 `Preparing` 到 `Applied` 会拿到两个事务号——
「旧事务不删新事务」的保护因此失效。

**其二**：`Applied` 与 `ready` 的写入在**规则执行器的系统锁之外**。封锁 A
建完规则、还没写 `Applied` 时，急救恢复 B 可以拿到锁、停保护、删规则与意图，
随后 A 又把 `Applied` 写回去——一份与真实系统状态对不上的残留记录。

**修复**：

- 事务号只在**新建意图**时生成一次，阶段推进沿用同一个号；
- 新增 `transition_uncovered_phase(expected_txn, phase, reason)`：事务号不符
  就拒绝推进（旧事务改写不了新事务的状态）；
- 规则执行、`Applied` 提交、`ready` 写入全部在**同一段系统锁**内；
- `Releasing` 阶段真正投入使用（自动解除时标记）。

**测试**：`phase_transition_preserves_transaction_id`、
`stale_transaction_cannot_advance_phase`。

---

## 3. P0-03：自动解除绕过「旧事务不自动清理」的约束

```rust
match &txn {
    Some(txn) => clear_uncovered_lock_if_txn(txn)?,
    None => clear_uncovered_lock()?,   // ← 正好绕过了刚立的约束
}
```

`clear_uncovered_lock_if_txn()` 刚加上「旧格式 / 事务不明 / 读不到一律拒绝清理」，
但这个 `None` 分支直接调了不带校验的版本；而且删规则发生在识别 `None` 之后、
清意图之前。

**修复**：**删规则之前**先读意图并判归属——

| 意图状态 | 处理 |
| --- | --- |
| `Current` 且阶段可清理 | 标 `Releasing` → 删规则 → 复核 → 清同一个事务 |
| `Current` 但 `Preparing` | 拒绝（事务进行中） |
| `Legacy`（旧格式） | **拒绝，一条规则都不删** |
| `Unreadable` | **拒绝，一条规则都不删** |
| `Absent` | 走对账路径，不冒充自动解除 |

---

## 4. P1

| 编号 | 修复 |
| --- | --- |
| **P1-01** 远程代理被记成可用 | v0.7.7 的注释写「未证实」，代码却 `Some((addr, true))`。改成 `ProxyHealth::{Verified, Unavailable, Unknown}`——远程代理只能是 `Unknown`；`Unknown` 或注册表证据不完整时本轮按 **Degraded** 处理，不查杀、不报健康成功、不推进离线防抖 |
| **P1-02** 配置在取锁前就保存 | `apply=true` 先取锁、再写配置、再改系统、回读通过才算完成；取锁失败时报「配置未改动」而不是留下半事务 |
| **P1-03** 急救不清理 ManualHold | `restore_all()` 在隔离确认清除后清理手动保持意图；失败计入 `pending` 让 `complete=false` |
| **P1-04** 每次读配置都重写标记 | 标记已存在且有效时只读不写；只有真实首次初始化/旧版迁移才创建。避免正常配置因暂时写不进标记被判 `Corrupt` |
| **P1-05** 卸载忽略任务删除失败 | 新增 `--egate-guard-task-state` 三态 CLI（0=不存在/1=存在/2=无法确认）；NSIS 钩子**只有确认不存在才放行**，否则中止卸载并给出可操作提示。纯 `schtasks` 的退出码分不清「不存在」与「服务异常」 |
| **P1-12** 配置开启 ≠ 实际生效 | 新增 `egate_strict_leak_status`：`configured` / `effective` / `blockers`。UI 分三种显示：生效中 / 已配置未生效（列出缺项）/ 未开启 |

---

## 5. 高收益小改动

| 编号 | 改动 |
| --- | --- |
| L-01 | 不在新规则核验前删除可能有效的 `::pending`（并入 P0-01） |
| L-02 | Applied 沿用 Preparing 的事务号；ready 记录增加事务号（并入 P0-02） |
| L-03 | 移除 `None => clear_uncovered_lock()` 退化分支（并入 P0-03） |
| L-04 | 远程代理健康改 `ProxyHealth::Unknown`（并入 P1-01） |
| L-05 | 取锁失败不提前提交「已应用」地区状态（并入 P1-02） |
| L-06 | 初始化标记只读不重写（并入 P1-04） |
| L-07 | `uncovered_lock_snapshot()` 只有「意图存在 + 阶段 Applied + ready 事务号一致」才返回 verified |
| L-08 | 完整急救后清理 ManualHold（并入 P1-03） |
| L-09 | 卸载钩子严格回查，失败阻止卸载（并入 P1-05） |
| L-10 | `Test-Rule` 区分查询失败与属性不健康（并入 P0-01） |
| L-11 | UI 区分「已配置 / 生效中 / 部分 / 未知 / 未生效」 |
| L-12 | 本轮 4 组新增回归已纳入共享脚本 |

---

## 5.1 发布构建过程中修掉的 NSIS 缺陷

首次打 `v0.8.1` tag 时，**质量门禁全过、`Build app` 失败**：

```
Error in macro NSIS_HOOK_PREUNINSTALL on macroline 40
Error in script "installer.nsi" on line 796 -- aborting creation process
Error failed to bundle project: `Failed to bundle app with makensis`
```

原因：`installer-hooks.nsh` 的消息文案里用 `\\"` 内嵌引号，而 NSIS 字符串里
这不是合法转义（应当是 `$\"`）。makensis 直接解析失败。

**修复**：文案不再内嵌双引号（改用「」与裸命令行示例），从根上消除转义歧义；
`MessageBox` 统一为单行写法，减少解析面。

**验证**：本地 `npm run tauri build` 跑通，makensis 产出
`ClaudeSwitcher_0.8.1_x64-setup.exe`（7.94 MiB）。

> **教训**（已记入 `AGENTS.md` 踩坑 38）：NSIS 钩子是**唯一不被
> `cargo test` / `clippy` 覆盖**的发布面。改 `installer-hooks.nsh` 后必须本地
> 跑 `tauri build` 验证 makensis，不能只靠 CI 的 Build app 去试。

## 6. 必要 P2

| 编号 | 状态 |
| --- | --- |
| P2-01 Windows VM 故障注入 | `02/03/04` 三个脚本**均已在管理员实机通过**（本轮复跑）。矩阵中的并发/崩溃场景（pending 崩溃恢复、Applied 前急救、双进程并发、IPv6 中断、NSIS 任务删不掉）仍需可回滚 VM |
| P2-02 发布门禁 | 沿用共享脚本；本轮新增 4 组，**46/46 组**点名验证 |
| P2-03 许可追溯 | 沿用 `docs/upstream-baseline.md` §7 矩阵 |
| P2-04 能力边界 | README「验收边界」与本文件 §7 已按四层状态标注 |

---

## 7. 明确未做

| 项 | 原因 |
| --- | --- |
| P1-06 受限特权 helper + ACL 验证 | 当前是「可写性探针 + 已知用户可写根黑名单」，误判方向是安全侧（宁可拒绝注册）。完整 ACL 判定 + 独立 helper 需要安全描述符解析与 IPC 协议设计，独立提交 |
| P1-07 环境完整恢复账本 | IPv6 / Culture / GeoID 原状态快照与资源级恢复，需可回滚 VM |
| P1-08 独立出口监控守护 | 监控核心与 Tauri 窗口解耦 + 单一所有者 |
| P1-09 可信 TUN DNS | 仍是 `TRUSTED_DNS_AVAILABLE = false` |
| P1-10 可信更新签名根 | 仍保持「不自动运行下载的安装包」 |
| P1-11 企业策略代理来源 | HKLM/组策略代理读取需真实域环境验证 |

---

## 8. 质量门禁（本版实际执行）

```text
cargo fmt --check                          通过
cargo clippy --all-targets -- -D warnings  零警告
cargo test --lib                           709 passed / 0 failed / 0 ignored
npx tsc --noEmit                           通过
npm run build                              通过（350.05 kB / gzip 106.89 kB）
scripts/check-security-regressions.ps1     46/46 组通过
```

真实系统（管理员，本机）：

```text
02-firewall-isolation.ps1  PASS  rules 4 -> 0, exit 0, idempotent
03-restore-ledger.ps1      PASS  真实账本 + 意图 + ready 全部收敛
04-corrupt-ledger.ps1      PASS  账本损坏时 exit 1, 规则与账本均保留
```

---

## 8.1 发布产物（2026-11-06 已发布）

| 资产 | 大小 | SHA-256 |
| --- | --- | --- |
| `ClaudeSwitcher_0.8.1_x64-setup.exe` | 8,337,776 B | `07c1e0a01404fef92723c417bfbf5d28c2210df72f7b3a508ec1d2d2e46d2f0c` |
| `ClaudeSwitcher-portable.zip` | 9,792,362 B | `938d7eff4ccbc266a98fcd93e774c0b706819f760e74b155a8f4f2f2d048800b` |
| `SHA256SUMS.txt` | 195 B | 随包分发 |

- Release：<https://github.com/48ytw4q7zg-sudo/claude-switcher-windows/releases/tag/v0.8.1>
- 哈希已用 `sha256sum -c SHA256SUMS.txt` 与独立重算**双重核对**，两者一致。
- 构建来源证明已通过 `gh attestation verify`（含 sigstore 证书），绑定
  `windows-build.yml` @ `refs/tags/v0.8.1`。
- 发布工作流里 **`Security regression scenarios` 与 CI 是同一份脚本**，
  本次构建该步骤 `success`（46/46 组）；`Build app` 亦 `success`
  （即 §5.1 的 NSIS 修复已在发布构建中验证）。
- 安装包是 **NSIS** 自解压 PE32，未代码签名（SmartScreen 提示属预期，
  请用上述哈希或 attestation 自行核对）。

## 9. 行为变化（升级须知）

1. **远程代理不再被当成「接入正常」**：保镖会按「未知」处理（不查杀、不报健康成功），
   自动解除兜底封锁时保守拒绝并保留封锁。
2. **卸载时若保镖计划任务删不掉，卸载会中止**并给出可操作提示——不再默默继续。
3. **地区锁定在取锁失败时不会改动配置**，提示会明确写「配置未改动」。
4. **完整急救会清理手动保持隔离意图**，下次重新布防后自动恢复不再受旧意图限制。
5. **严格防泄漏面板区分「已配置」与「生效中」**，缺项逐一列出。
