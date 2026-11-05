# v0.7.5 发布说明（安全与状态机修订）

> 日期：2026-11-06｜基线：v0.7.3 → **v0.7.5**
> 版本号跳过 v0.7.4：本轮是继 v0.7.2/v0.7.3 之后的第三次大修订，
> 留一个空号便于区分「已发布的 v0.7.3」与「本地中间态」。
>
> 主题：**结论必须由全部应处理对象与实际副作用算出，策略失败时必须失败，
> 而不是悄悄退化成另一种行为。**

## 0. 一句话结论

v0.7.3 修好了「检查通过 ≠ 流量安全」。这一版修它的孪生问题：**「返回值
看起来对 ≠ 事实就是那样」**。四个 P0 全是这类——两个是把「非严格模式」与
「严格但无代理」混成同一个值，一个是把「处理了 1 个」当成「处理完 3 个」，
一个是挡住了 HTTP 却没挡住前面那次 DNS。

---

## 1. P0-01：严格出口模式在「找不到代理」时会退回直连

**这是最危险的一条**：带 `Authorization: Bearer …` 的请求。

**根因**：`strict_oauth_proxy() -> Option<String>` 把两种完全不同的含义折叠成
同一个 `None`：

| 实际情况 | 返回值 | 调用方的处理 |
| --- | --- | --- |
| 用户关闭了严格保护 | `None` | 走直连（合理） |
| 严格保护开启，但代理不可用 | `None` | **也走直连（漏洞）** |
| 配置损坏，读不出来 | `None` | **也走直连（漏洞）** |

于是门禁开着、代理挂了的时候，代码会带着凭据从真实家宽出口发请求——
这正是严格模式要防的事。

**修复**：改成显式三态 `OauthPolicy::{Unrestricted, StrictProxy, StrictBlocked}`，
判定抽成纯函数 `oauth_policy_decide`，可表驱动测试。`StrictBlocked` **绝不**
进入任何发送分支。同时收紧严格路径的 HTTP 客户端：

1. `.no_proxy()` 必须**先**调用再 `.proxy()` —— reqwest 的 `system-proxy`
   特性会在 `build()` 时把系统代理也加进列表，顺序颠倒会让请求走系统代理
   而不是我们指定的那个（这个漏洞一直在，顺手修掉）；
2. 不跟随重定向（3xx 会把带凭据的请求转到别处）；
3. 没有任何直连回退分支。

**测试**：`strict_oauth_policy_never_allows_direct_when_gate_is_on` 覆盖
门禁关闭/开启+代理有效/代理缺失/socks 不可复用/注册表读取失败/配置损坏/兜底代理/空代理 八种分支。
`strict_blocked_makes_zero_outbound_connections` 用本地 TCP 夹具**统计真实连接
次数**——被拦住时一次连接都不建立，而不是「发了但失败」。
`strict_proxy_path_is_used_and_redirects_are_refused` 证明只连指定代理且拒绝 302。

---

## 2. P0-02：熔断中途被取消，可能报「全部隔离成功」

**根因 A**：`all_isolated = agents.iter().all(|a| a.coverage_complete)` 只对
**已经处理的**对象求值。3 个对象只处理了 1 个就中止，而那 1 个是完整的
→ `all_isolated = true` → `outcome = Applied` → 界面显示「已完整熔断」，
另外两个应用根本没被隔离。

**根因 B**：`if aborted && !any_isolated { AbortedStale }`。已查杀进程、
建规则失败、之后配置变更 —— `any_isolated` 是 false → 判成 `AbortedStale`
（＝什么都没做）。用户进程没了，报告里却没有任何痕迹。

**修复**：结论计算抽成纯函数 `summarize_trip(requested, processed, aborted,
side_effects, applicable, complete)`，两个执行器（熔断 / 兜底封锁）共用同一口径：

- `all_isolated` 要求**处理完全部请求对象**且无中断；
- `AbortedStale` **只**用于「确实没有产生任何副作用」的主动放弃；
- 已查杀/已建规则的中断一律 `Partial`；
- 新增 `TripOutcome::NoApplicable`：全部对象确认未安装时**不是**「成功建立隔离」。

`TripReport` 同时记录 `requested / processed / side_effects / aborted`，
让调用方与界面能说清「发生了什么」。

**测试**：`trip_summary_never_claims_complete_when_objects_were_skipped`
（3 处理 1 / 3 处理 3 / 2 of 3 完整 / 1 个未安装 / 全部未安装 五种组合）、
`trip_summary_keeps_side_effects_visible_after_abort`、
`trip_outcome_state_policy_matches_meaning`。

---

## 3. P0-03：兜底封锁自动解除缺少持锁复核

**流程问题**：`can_release_uncovered()` 在**取锁之前**检查，`release_isolation_reason`
在**锁内**只做「按来源删除」，不复核任何东西。

```
can_release_uncovered() 通过  ← 用户此刻代理还通
  ↓
  …等待系统操作锁（可能被别的保护操作占着）…
  ↓
release_isolation_reason(Uncovered) → 直接删规则
```

等待锁期间代理断开、用户暂停、手动保持隔离、配置变更 —— 旧的放行判断
仍会被执行。

**修复**：新增 `release_uncovered_with_evidence(expected_revision)`，
与普通熔断的 `release_verified_with_revision` 对齐，**持锁后**复核：

1. 手动保持状态是 `None`（`Unknown` 也不放行）；
2. 保护意图仍是 `Armed`、未暂停；
3. 配置代次未变；
4. **接入路径重新取证** —— 系统代理端口必须还能连上（回环代理做一次本地 TCP 探测），
   TUN 必须有完整路由证据，否则拒绝解除。

用户显式执行的紧急恢复走独立接口，不受此限（但保持完整资源核验）。

**测试**：`uncovered_auto_release_aborts_when_state_changed_under_lock`
（暂停 / 代次变化 / 停止保护 / 手动保持 四种）、
`uncovered_auto_release_refuses_when_access_no_longer_safe`。

---

## 4. P0-04：TUN 探测跳过了 HTTP，却没跳过 DNS

v0.7.3 把 `dns_trusted` 固定为 false，让 HTTP 直连探测全部 Skip——这是对的。
但代码顺序仍然是：

```
检测到 TUN → resolve_host_addresses() → **系统 DNS 解析**
     → 采路由证据 → dns_trusted = false → 跳过 HTTP 探测
```

挡住了 HTTP，**没挡住前面那次 DNS 查询**。当系统 DNS 走物理网络时，域名
查询照样从不受保护的路径发出去——而且更隐蔽（HTTP 看起来什么都没做）。

**修复**：新增 `TRUSTED_DNS_AVAILABLE`（恒为 `false`）。没建立可信解析通道
就直接返回 `Unverified`，**连 DNS 都不问**。路由采集代码保留，
等接入 TUN 内 DNS 或经证明的 DoH 后再打开。

**测试**：`tun_route_issuses_zero_dns_queries_until_trusted_channel_exists`
用计数器断言**零解析请求**；`trusted_dns_channel_is_not_available_yet`
让「打开 DNS 查询」必须是一次有意识的决定。

> 这是 v0.7.3 的保守策略再收紧一层，不是功能退步。要放行 TUN 出口验证，
> 必须先有可证明安全的解析路径。

---

## 5. P1 批次

| 编号 | 修复 |
| --- | --- |
| P1-05 安装枚举吞错 | PowerShell 逐来源记录「成功 / 明确为空 / 查询失败」；`-ErrorAction Stop` + try/catch。可选路径不存在是正常语义，权限拒绝/服务异常/解析失败不是。只有三来源都可靠完成且无证据才报 `NotInstalled` |
| P1-06 未安装对象汇总 | 有候选但**一个都认不出身份**时记 `Unknown` 而非 `Installed`；`summarize_trip` 把 `NotInstalled` 从「应隔离」集合排除，`Unknown` 不排除。全部未安装 → `NoApplicable` |
| P1-07 ready 来源混算 | 只认 `inventory.uncovered`（旧版遗留**不**再拿来凑数）；并按**预期规则名**逐条对账，被外部删除立刻降级 |
| P1-08 兜底沿用旧配置 | `enforce_uncovered_outbound_with_revision`：与 `trip_with_revision` 对齐，每个对象动手前比代次 |
| P1-09 布防校验+保存原子化 | 新增 `appconfig::try_update(f, validate)`，校验与落盘在**同一把配置锁**内完成，失败则一个字段都不写 |
| P1-10 界面读损坏配置 | `get_appconfig` / `egate_get_targets` / `egate_leak_watch` / `egate_trip_now` 全部改成 `Result`，损坏时报错而不返回默认值（默认值的 `egate_enabled=false` 会骗用户「保护没开」）。`egate_monitor_status` 改为一次取全兜底状态 |
| P1-11 网卡恢复文本匹配 | `nic_restore_ok` 结构化标志取代 `failures.iter().any(\|f\| f.contains("网卡"))` |
| P1-12 配置写入推进代次 | 新增 `security_fingerprint()`；只有接入策略/门禁判定/保护对象/恢复资格变化才递增 `egate_revision`。`last_egress_ip`、日志、额度提醒不再让探测过期 |
| P1-13 严格防泄漏模式 | 新增 `strict_leak_protection`（默认关）。开启后 `unknown` / 未证明的 `tun` 也进**出站兜底封锁**（只挡受管 GUI 出站，不杀进程、不全局断网）；意图文件记录触发原因 |
| P1-14 失败计数不回滚 | `run_round` 在工作副本上算，判定有效才提交；配置变更时**清空**共享计数（同一目标 ID 下内容可能已完全不同） |

---

## 6. 高收益小改动

| 编号 | 改动 |
| --- | --- |
| L-01 | `Option` 不再同时表达普通模式与严格失效（`OauthPolicy` 三态） |
| L-02 | `all_isolated` 对完整应处理集合计算 |
| L-03 | `AbortedStale` 依据实际副作用判断 |
| L-04 | 兜底自动解除前持锁重核验（含代理端口复探） |
| L-05 | TUN 无可信 DNS 时不调用系统域名解析 |
| L-06 | 严格区分安装证据缺失与枚举异常 |
| L-07 | 未安装对象返回「不适用」而非隔离失败 |
| L-08 | ready 只核对所属兜底来源 + 预期规则名 |
| L-09 | 布防校验与保存合并成一次配置事务 |
| L-10 | 安全状态配置损坏时返回错误，不回退默认值 |
| L-11 | 只有安全相关配置变化才递增 `egate_revision` |
| L-12 | 失败计数按配置代次提交，过期结果不污染 streak |
| L-13 | 用结构化网卡恢复结果代替中文字符串匹配 |
| L-14 | 手动隔离产生副作用后**不**清除手动保持意图 |
| L-15 | 补齐隔离分支同样处理 `AbortedStale`/`NoApplicable` |
| L-16 | 界面区分「当前核验通过 / 历史核验已失效 / 尚未核验 / 覆盖不完整」 |
| L-17 | OAuth 策略复用 `network_policy::usable_system_proxy`，避免两套「什么算可用代理」分叉 |
| L-18 | 集成脚本：查询改 `-ErrorAction Stop`、拒绝在有产品状态的机器上运行、真实账本夹具 |

**L-18 的实际效果**：改写夹具时发现 `CutPhase` 枚举值写错，脚本当场 FAIL
而不是 PASS——这正是「测试失败不能被报告成 PASS」要防的。同时也确认了
「账本损坏时不猜、不删」的保守行为是对的（另立 `04` 验证）。

---

## 7. 必要 P2

| 编号 | 状态 |
| --- | --- |
| P2-01 故障注入 | 新增 `04-corrupt-ledger.ps1`（账本损坏 → 拒绝、保留规则与账本）。`02`/`03` 加固为严格前置 + `-ErrorAction Stop`。**02/03/04 均已在管理员实机通过** |
| P2-02 端到端安装验收 | 未做（需要干净 Win10/Win11 虚拟机） |
| P2-03 许可追溯 | 沿用 `docs/upstream-baseline.md` §7 矩阵；本轮新增模块归入「本仓库自有」 |

---

## 8. 明确未做

| 项 | 原因 |
| --- | --- |
| P1-01 受限特权 helper | 需要独立 helper 可执行文件、固定命令枚举、调用方校验、UAC 交接；架构级改动 |
| P1-02 可信更新签名根 | 需要密钥托管与发布基础设施。v0.7.3 的「不自动运行安装包」限制**保留** |
| P1-03 完整独立守护进程 | 需要监控核心与 Tauri 窗口解耦 + 跨进程唯一所有者 + 所有权交接 |
| P1-04 可信 TUN DNS | 本版把 DNS 也挡住了（P0-04）；真正放行需要 TUN 内 DNS 或经证明的 DoH |
| P2-02 干净虚拟机端到端 | 需要可回滚的 Win10/Win11 虚拟机 |
| 网卡故障注入（04-network-cut） | **有意不做**：禁用物理网卡后恢复失败就是彻底断网，且产品 `nics` 档仍被能力门控限制。在「独立恢复机制 + 虚拟机快照」都具备前，收益不抵风险 |

---

## 9. 质量门禁（本版实际执行）

```text
cargo fmt --check                          通过
cargo clippy --all-targets -- -D warnings  零警告
cargo test --lib                           690 passed / 0 failed / 0 ignored
npx tsc --noEmit                           通过
npm run build                              通过（349.24 kB / gzip 106.61 kB）
```

真实系统（管理员，本机）：

```text
02-firewall-isolation.ps1  PASS  rules 4 -> 0, exit 0, idempotent exit 0
03-restore-ledger.ps1      PASS  真实账本 + 意图 + ready 全部清除, exit 0
04-corrupt-ledger.ps1      PASS  账本损坏时 exit 1, 规则与账本均保留
```

---

## 9.1 发布产物（2026-11-06 已发布）

| 资产 | 大小 | SHA-256 |
| --- | --- | --- |
| `ClaudeSwitcher_0.7.5_x64-setup.exe` | 8,235,609 B | `7515f615c0542e56d818e4e922bfe356fc2196e4d498a501e39e0eec2526b697` |
| `ClaudeSwitcher-portable.zip` | 9,709,422 B | `fd1ff32dfade80beadc273450834c8466d5aece2e61e6b7ed6d9d0077f7b4487` |
| `SHA256SUMS.txt` | 195 B | 随包分发 |

- Release：<https://github.com/48ytw4q7zg-sudo/claude-switcher-windows/releases/tag/v0.7.5>
- 哈希已用 `sha256sum -c SHA256SUMS.txt` 与独立重算**双重核对**，两者一致。
- 构建来源证明已通过 `gh attestation verify`（含 sigstore 证书），绑定到
  `windows-build.yml` @ `refs/tags/v0.7.5`。
- 安装包是 **NSIS** 自解压 PE32，未代码签名（SmartScreen 提示属预期，
  请用上述哈希或 attestation 自行核对）。

> **发布后发现并修复**：CI 的「安全回归场景」步骤因为一个陈旧组名
> `strict_oauth_mode`（v0.7.2 的测试名，本轮重写后已不存在）而失败。
> 发布构建不受影响——它跑的是无过滤的 `cargo test --lib`。
> 修复同时把「0 项匹配」的检测从 `running 0 tests` 改成看 `test result` 行
> 的 passed 计数：cargo 对「过滤出 0 项」仍然返回 0，原检测会漏判。

> 发布源码基线是 tag 指向的 `3d1f80b`。main 上的 `a161bf9` 是构建完成后
> 追加的一行测试串行化加固，不影响产物。

## 10. 行为变化（升级须知）

1. **配置损坏时界面不再显示默认值**，而是报错。这比「看起来正常但其实是
   默认配置」更安全——用户会知道该修配置。
2. **改日志级别、记录出口 IP 不再让门禁探测过期**（响应更快、状态更稳）。
3. **手动隔离如果产生了副作用但覆盖不完整**，会保留手动保持意图而不是清掉；
   自动恢复不会擅自解除它。
4. **新增「严格防泄漏」开关**（默认关）：开启后接入无法证明时也会封锁受管
   应用出站。想启用请在出口门禁面板点「严格防泄漏」。
5. **TUN 模式下出口检查仍显示「未验证」**，且现在**连 DNS 都不发**。
   这是有意的保守，见 §4。
6. **集成测试脚本会拒绝在已有产品状态的机器上运行**——它们不是清理工具。
