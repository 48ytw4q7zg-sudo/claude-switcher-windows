# Windows 故障注入集成测试（P2-01，手动 / 可回滚虚拟机）

> **不要在日常开发机上运行。** 本目录的脚本会创建/删除真实的防火墙规则、
> 禁用网卡、修改系统时区。仅限**可快照回滚的 Windows 虚拟机**。
>
> 这些脚本**不接入** `cargo test`（默认 CI 不会跑）：它们需要管理员权限与
> 可回滚的真实系统，属于发布前的系统级验收，不属于单元测试。

## 为什么单独放这里

`src-tauri` 的 677 项单元测试覆盖的是**判定逻辑**（策略表、解析、状态机）。
它们无法证明「真实 Windows 防火墙是否照我们以为的方式工作」——v0.7.2 之前
踩过的 `-EncodedCommand` 退出码问题就是典型例子：逻辑全绿，系统行为不同。

因此这一组测试的定位是：**在真实系统上把判定链走一遍**，并把现场证据
（退出码、规则库存、账本文件）打印出来供人工核对。

## 运行方式

```powershell
# 1. 在虚拟机上以管理员身份打开 PowerShell
# 2. 构建被测二进制
cd src-tauri
cargo build --bin cs
cd ..

# 3. 逐组执行（每组都可独立回滚）
.\tests\windows-integration\02-firewall-isolation.ps1
.\tests\windows-integration\03-restore-ledger.ps1
.\tests\windows-integration\04-network-cut.ps1
```

每组脚本结束时会：
1. 打印 `PASS` / `FAIL` 与关键证据；
2. 调用 `--egate-restore` 做最后清理；
3. 检查 `ClaudeSwitcher*` 规则计数为 0。

任何一步失败都会以非 0 退出码结束。

## 测试矩阵与当前状态（v0.7.3）

| # | 场景 | 脚本 | 本版状态 |
| --- | --- | --- | --- |
| 01 | 管理员 / 非管理员下的防火墙读写能力 | `01-privilege.ps1` | 管理员路径已在开发机验证；**非管理员路径未验证** |
| 02 | 三类规则共存 → `--exit-restore` 清零 | `02-firewall-isolation.ps1` | **已在开发机验证**（4 → 0，退出码 0） |
| 03 | 断网账本 + 规则 + 意图文件的一致性恢复 | `03-restore-ledger.ps1` | 未验证 |
| 04 | 网卡禁用/恢复（含 GUID 匹配） | `04-network-cut.ps1` | **未验证**（会切断网络，必须在虚拟机里做） |
| 05 | PersistentStore 与 ActiveStore 不一致 | `05-store-divergence.ps1` | 未验证 |
| 06 | 防火墙配置档关闭 / 多档并存 | `06-profile-disabled.ps1` | 未验证 |
| 07 | 并发：GUI + 保镖 + 急救同时运行 | `07-concurrency.ps1` | 未实现（需要可编排的进程控制） |
| 08 | 进程中断 / 输出截断 / 规则被外部删除 | `08-injection.ps1` | 未实现 |
| 09 | NSIS 安装 / 升级 / 卸载回归 | 手工 | 未验证（需要干净虚拟机） |
| 10 | TUN IPv4 正常 + IPv6 旁路 → 必须 Skip | 手工 | 需要真实 TUN 环境 |
| 11 | 目标 A 走 TUN、目标 B 走物理网卡 → 只有 A 可探测 | 手工 | 需要真实多路径环境 |
| 12 | 严格保护下 OAuth/API 不得直连 | 手工 | 需要可观测的代理与抓包 |

## 已实现脚本的验收标准

### 02 防火墙隔离与恢复（`02-firewall-isolation.ps1`）

1. 创建 4 条测试规则（AppIsolation ×2、UncoveredLock ×1、旧版 Egate ×1）；
2. 断言创建后计数为 4；
3. 运行 `cs.exe --exit-restore`；
4. 断言退出码为 **0** 且计数为 **0**；
5. 再次运行，断言幂等（退出码仍为 0）。

### 03 恢复账本一致性（`03-restore-ledger.ps1`）

1. 制造一份「断网账本 + 兜底意图 + 规则」的现场；
2. 运行 `--exit-restore`；
3. 断言：规则为 0、账本文件不存在、兜底意图文件不存在、退出码 0。

## 独立测试命名空间

所有测试规则统一使用 `ClaudeSwitcher Test*` 前缀，并在脚本结束时删除。
**不要**复用产品前缀（`ClaudeSwitcher AppIsolation` / `UncoveredLock` / `Egate`），
否则测试清理会与产品恢复逻辑互相干扰。

## 回滚

虚拟机快照是最可靠的回滚手段。若没有快照：

```powershell
Get-NetFirewallRule -DisplayName 'ClaudeSwitcher Test*' | Remove-NetFirewallRule
.\src-tauri\target\debug\cs.exe --egate-restore
```
