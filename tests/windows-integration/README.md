# Windows 故障注入集成测试（P2-01，手动 / 可回滚虚拟机）

> **不要在日常开发机上运行。** 本目录的脚本会创建/删除真实的防火墙规则、
> 写入产品状态文件、构造断网账本。仅限**可快照回滚的 Windows 虚拟机**。
>
> **L-18（v0.7.5）**：脚本自身会**拒绝**在已有产品状态的机器上运行。
> 它们不是「清理工具」——把测试脚本当清理工具用会破坏真实用户的隔离状态。

这些脚本**不接入** `cargo test`（默认 CI 不会跑）：它们需要管理员权限与
可回滚的真实系统，属于发布前的系统级验收，不属于单元测试。

## 为什么单独放这里

`src-tauri` 的 690 项单元测试覆盖的是**判定逻辑**（策略表、解析、状态机）。
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
.\tests\windows-integration\04-corrupt-ledger.ps1
```

每组脚本结束时会：
1. 打印 `PASS` / `FAIL` 与关键证据；
2. 调用 `--egate-restore` 做最后清理；
3. 检查 `ClaudeSwitcher*` 规则计数为 0。

任何一步失败都会以非 0 退出码结束。

## 已实现脚本的验收标准

### 02 防火墙隔离与恢复（`02-firewall-isolation.ps1`）

1. **严格前置**：机器上已有 `ClaudeSwitcher*` 规则 → 退出码 3，拒绝运行。
2. 创建 4 条测试规则（AppIsolation ×2、UncoveredLock ×1、旧版 Egate ×1）；
3. 断言创建后计数为 4（逐条创建都要成功，失败即记录）；
4. 运行 `cs.exe --exit-restore`；
5. 断言退出码为 **0** 且计数为 **0**；
6. 再次运行，断言幂等（退出码仍为 0）。

> 规则计数用 `-ErrorAction Stop`：查询失败必须报错，不能当成「零条规则」
> 然后宣布 PASS。

### 03 恢复账本一致性（`03-restore-ledger.ps1`）

1. **严格前置**：已有产品状态 → 退出码 3，拒绝运行。
2. **构造一份真实断网事务账本**（`netcut.json`：`mode=firewall`、
   `phase=firewall_applied`，不带网卡，避免真的断网）；
3. 加上真实阻断规则 + 兜底意图 + ready 记录；
4. 运行 `--exit-restore`；
5. 断言：规则 0、**账本文件被清除**、意图文件被清除、ready 文件被清除、退出码 0。

> v0.7.3 之前这条只检查「碰巧存在的文件」，PASS 不能证明真实的断网账本
> 恢复通过了验证。现在账本是被真正构造出来的。

### 04 账本损坏不得猜（`04-corrupt-ledger.ps1`，P2-01）

1. 加上真实阻断规则 + 一份**无法解析**的 `netcut.json`；
2. 运行 `--exit-restore`；
3. 断言：
   - 退出码 **非 0**（不得报告成功）；
   - 规则数**不变**（不得据此删除任何东西）；
   - **账本被保留**——它是「到底断了什么」的唯一记录，销毁了就再也恢复不了。
4. 脚本自己清理夹具（这是个故意制造的死胡同）。

> 这一条验证的是**保守性**：系统状态不明时宁可什么都不做，
> 也不要猜一个结果出来。用户卡住时的出路是手动修复账本，
> 而不是让工具悄悄抹掉最后的线索。

## 测试矩阵与当前状态（v0.7.5）

| # | 场景 | 脚本 | 状态 |
| --- | --- | --- | --- |
| 01 | 管理员 / 非管理员下的防火墙读写能力 | — | 管理员路径已验证；**非管理员路径未验证** |
| 02 | 三类规则共存 → `--exit-restore` 清零 | `02-firewall-isolation.ps1` | **已验证** |
| 03 | 真实断网账本 + 规则 + 意图文件一致恢复 | `03-restore-ledger.ps1` | **已验证** |
| 04 | 断网账本损坏不得猜、不删恢复信息 | `04-corrupt-ledger.ps1` | **已验证** |
| 05 | PersistentStore 与 ActiveStore 不一致 | — | 未实现 |
| 06 | 防火墙配置档关闭 / 多档并存 | — | 未实现 |
| 07 | 并发：GUI + 保镖 + 急救同时运行 | — | 未实现 |
| 08 | 进程中断 / 输出截断 / 规则被外部删除 | — | 未实现 |
| 09 | NSIS 安装 / 升级 / 卸载回归 | 手工 | 未验证（需要干净虚拟机） |
| 10 | TUN IPv4 正常 + IPv6 旁路 → 必须 Skip | 单测已覆盖判定 | **需真实 TUN 环境** |
| 11 | 目标 A 走 TUN、目标 B 走物理网卡 | 单测已覆盖判定 | **需真实多路径环境** |
| 12 | 严格保护下 OAuth/API 不得直连 | 单测已覆盖（零连接断言） | 需可观测的代理与抓包 |
| 13 | 网卡禁用/恢复 | — | **故意不做**（见下） |

### 为什么没有网卡故障注入

`04-network-cut.ps1` **有意不做**：禁用物理网卡后，恢复如果失败就是彻底断网，
而且当前产品在 `nics` 档位上仍被能力门控限制（没有独立于主程序的恢复执行器）。
在「独立恢复机制 + 虚拟机快照」两个前提都具备之前，做这个测试的收益不抵风险。

## 独立测试命名空间

所有测试规则统一使用 `ClaudeSwitcher ... integration-test ...` 名称，
并在脚本结束时删除。`03` / `04` 用的 `ClaudeSwitcher Egate Cut All` 是
**产品真实命名空间**——那正是要验证的恢复路径，因此必须用真名。

## 回滚

虚拟机快照是最可靠的回滚手段。若没有快照：

```powershell
Get-NetFirewallRule -DisplayName 'ClaudeSwitcher*' | Remove-NetFirewallRule
Remove-Item "$env:USERPROFILE\.claude-switcher\netcut.json" -Force -ErrorAction SilentlyContinue
.\src-tauri\target\debug\cs.exe --egate-restore
```
