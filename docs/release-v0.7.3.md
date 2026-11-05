# v0.7.3 发布说明（安全修订）

> 日期：2026-11-05｜基线：v0.7.2 → **v0.7.3**
> 主题：把「看起来安全的判定」换成「有证据的安全判定」，并关掉几条会
> 悄悄泄露真实出口的路径。

## 0. 一句话结论

v0.7.2 解决了「命令跑完了 ≠ 系统真的变了」。这一版解决它的孪生问题：
**「检查通过了 ≠ 流量真的安全」**。共修 8 个 P0，其中 3 个是可以用源码
直接证明的确定性逻辑缺陷（IPv6 旁路被放行、只验第一个目标、未配置白名单
却能布防），2 个是会主动把真实出口发出去的请求路径（OAuth 直连优先、STUN
主动探测）。

---

## 1. P0-01：IPv6 明确旁路仍被放行（确定性缺陷）

**根因**：`RouteEvidence::proves_tun_path()` 用 `ipv6_via_tun.is_some()` 判定。
`Some(false).is_some() == true`，于是「确认 IPv6 走物理网卡」反而通过检查，
`plan_route_with_evidence()` 返回 `Direct`，随后 `probe_via(target, None)`
用 `no_proxy()` 直连——真实出口就这样暴露了。

**修复**：用一个布尔同时表达四件事本身就是错的，改成显式四态
`RouteVia::{Tun, Bypass, NotAvailable, Unknown}`：

| 状态 | 含义 | 能否放行 |
| --- | --- | --- |
| `Tun` | 出接口是 TUN 且默认路由由 TUN 接管 | 可以 |
| `Bypass` | 明确不经过 TUN | **否** |
| `NotAvailable` | 系统确实没有该协议族路径 / 目标无 AAAA | 可以（不存在旁路） |
| `Unknown` | 无法确认 | **否** |

`unverified_reason()` 对 `Bypass` 现在会明确输出「发现 IPv6 旁路：…」，
不再返回空串让界面显示「未获证实：」却无下文。

**测试**：`tun_path_requires_both_families_and_trusted_dns` 覆盖审计要求的
六种组合（双 TUN / IPv6 旁路 / IPv6 未知 / IPv4 未过 TUN / IPv6 关闭 /
DNS 不可信）。

---

## 2. P0-02 / P0-03：逐目标取证，且不再假设 DNS 是安全的

**P0-02**：`collect_tun_route_evidence()` 原来用 `find_map` 只取**第一个**
启用目标的主机名取证，却用这份证据放行**所有**目标的直连探测。目标 A 走 TUN、
目标 B 走物理网卡时，B 会被一起放行。

现在证据是 `BTreeMap<target_id, RouteEvidence>`，平台层一次脚本内对每个目标
分别 `Find-NetRoute`；`run_round` 里每个目标用自己的 `ProbeRoute`，
`access_info.tun_proven` 只有**全部启用目标**都证明时才为真。

**P0-03**：原来的顺序是「系统 DNS 解析 → 证明该 IP 走 TUN → 放行」。这个推理
漏了一步：**DNS 查询本身**可能已经走物理网卡把真实出口暴露给了解析服务器，
而且验证的地址也可能不是实际连接的地址（多 A 记录、TTL 变化）。

v0.7.3 的处理是**保守收紧**：

- 删除 `2001:db8::1` 占位地址（占位地址的路由与真实目标无关）；
- `RouteEvidence.dns_trusted` 成为判定条件之一；
- 由于当前没有「已证明安全的解析通道」，`dns_trusted` **恒为 false**——
  **TUN 直连探测在本版仍全部 Skip**。

也就是说：`Direct` 分支的策略已经正确，但要真正放行，需要先接入一条可证明
安全的解析路径（TUN 内 DNS 或经过验证的 DoH）。这是明确的后续工作，不是遗漏。

> 这一条会让某些用户觉得「TUN 模式下出口检查什么都测不出来」。这是有意的：
> 在无法证明 DNS 路径之前，宁可直接消失在界面上显示 `Unverified`
> （配 `tun_route_note` 说明原因），也不冒险把家宽 IP 发出去。

---

## 3. P0-04：GUI/CLI 身份回退会把 CLI 写进 GUI 规则

两处问题：

1. v0.7.2 在「一个 GUI 路径都确认不了」时**宽松回退**，把未确认路径重新放回
   隔离列表——原生 `claude.exe` CLI 会被写成 GUI 规则，而查杀端按 GUI 身份
   跳过它。结果是「规则建了、进程还在跑」，用户看到「已隔离」但应用照常联网。
2. 那个回退里的 `"\\node_modules\\\\"` 是 Rust 转义错误的产物（`\n` 是换行符），
   排除条件根本不可能命中。

**修复**：新增 `GuiIdentity::{ConfirmedGui, Cli, Unknown}` 与
`classify_managed_gui_paths()`；**无法确认身份 = 不建 GUI 规则**，并把被拒路径
与原因写进报告。加入可执行文件名白名单（`claude.exe` / `chatgpt.exe` /
`antigravity.exe`），同目录的更新器、崩溃处理程序不再被当成 GUI。

**P1-07** 一并修掉：`kill_desktop_app_processes` 的 `$guiPaths` 原来只有 Claude
目录，ChatGPT / Antigravity 会被判「身份未确认」而跳过。现在与 Rust 侧
`GUI_MARKERS` 逐字对齐。

**P1-06**：`agent_pids()` 也接同一套判定——直连泄露观察不再把终端里的 CLI
的公网连接算成 GUI 泄露。

---

## 4. P0-05：全新安装可以直接布防，然后熔断

`validate_arm_readiness()` 原来在 `egate_targets.is_empty()` 时直接
`return Ok(())`，理由是「内置默认表自带期望值」。但 `builtin_targets()`
的 `expect_ips` / `expect_regions` **全是空的**，而 `evaluate()` 对
「拿到出口信息但白名单为空」判 `Fail`。于是新用户一开开关，第一次真的拿到
出口信息就判失败，达到阈值后自动熔断——结束正在用的桌面程序。

**修复**：按**实际生效的目标表**校验（用户配置为空就用内置默认表），
`AnchorKind::Reachability` 单独放行（它本来就不看 IP/地区）。
新增 `arm_readiness_tests`：内置目标必须判定为未就绪、可达性锚点不需要白名单、
停用的目标不阻断布防。

---

## 5. P0-06 / P1-01：自动解除的持锁复核

监控线程判定「出口已恢复」后要等系统操作锁；等待期间用户可能改配置、暂停、
手动保持隔离。原来 `release_verified_locked(Automatic)` 只检查手动保持。

**修复**：新增 `release_verified_with_revision(reason, expected_revision)`，
**持锁之后**复核：Armed、未暂停、手动保持为 None、配置代次未变。
`run_monitor_round` 把本轮代次传进去。

**L-05** 同时修掉：配置读不出来时原来回退成「代次未变」（`_ => revision`），
等于假设配置没改过——恰恰是最危险的假设。现在按「本轮结果作废」处理。

---

## 6. P0-07：`list_adapters` 底层仍吞错误

`detect_tun_adapter_strict()` 在 Rust 接口上加了 `Result`，但底层
`Get-NetAdapter -ErrorAction SilentlyContinue` 会把「权限被拒 / 服务停止 /
RPC 失败」变成空集合 → `Ok([])`。调用链于是：

```
网卡查询失败 → Ok([]) → 判「没有 TUN」→ current_access()=Uncovered
→ 施加兜底封锁 → 累计到阈值后熔断
```

**修复**：`Get-NetAdapter` 改 `-ErrorAction Stop`（读不到就 `Err`）；
IP 地址查询单独降级为 `AdapterInfo.ips_ok`——读不到地址不再被当成
「没有 198.18 地址」，`tun_status_from_adapters` 会跳过该判据而不是判否。

---

## 7. P0-08：带凭据的 OAuth 请求仍「直连优先」

`claude_oauth_api()` 原来先 `no_proxy()` 直连、失败才走代理。请求携带
`Authorization: Bearer …`，严格保护开启时这就意味着**带着凭据从真实出口发出
请求**。

**修复**：顺序改由保护策略决定。

- 严格模式（门禁开启 + 接入为系统代理或 Clash 代理可用）→ **只走代理**，
  代理不可用则报错，绝不直连；
- 非严格模式 → 保留原来的直连优先 + 代理兜底（那是用户明确选择的普通用法）。

TUN 路线**不算**严格模式下的可用通道：在路由证据成立前，不能凭「有 TUN 网卡」
就发带凭据的直连请求。

新增 `strict_oauth_mode_is_off_when_gate_disabled` 与
`strict_oauth_mode_requires_a_proxy_when_gate_enabled`。

---

## 8. P1-14：STUN/WebRTC 是**主动**探测，不能静默发

`stun::probe_one()` 直接 `UdpSocket::bind("0.0.0.0:0")` 向公开 STUN 服务器
`send_to()`。系统 HTTP 代理**管不住 UDP**——开着系统代理并不能阻止这些包从
物理网卡出去，而它们的目的正是让对方看到真实来源。

**修复**：

- 巡检里的 WebRTC 检查改为**不自动发包**，报告 `warn` 并说明「UDP 路径未经
  证实，主动发包会暴露真实出口」；
- 新增 `stun_probe_manual(egress_ip, confirmed)` 命令，必须显式确认才执行；
- `auto_probe_allowed()` + `StunSkip::RouteNotProven` 把这条策略写成可测逻辑。

---

## 9. 其余 P1

| 编号 | 状态 |
| --- | --- |
| P1-08 兜底 ready 对账实际规则 | `uncovered_ready_state()` 现在比对**当前防火墙库存**；规则被外部删除或查询失败都会立即判失效，不再在有效期内显示「已核验」 |
| P1-09 解除报告语义 | `ReleaseReport` 拆开「资源已核实清除」与「过程错误」；新增 `fully_cleared()`。`verified` 现在要求无失败项 |
| P1-10 TUN 接回后自动解除兜底锁 | `access_verified(path, tun_proven)`：TUN 只有在**带路由证明**时才有效。既不再一律拒绝，也不凭网卡 Up 放行 |
| P1-11 Unknown 状态可自愈 | 新增 `reconfirm_unknown_state()` + 指数退避（30s → 上限 5 分钟），查询恢复后按真实库存重建并重置退避 |
| P1-12 查杀返回真实结果 | 逐 PID `Stop-Process -ErrorAction Stop` + 结束后按「PID + 启动时间」复核；`Killed / AlreadyExited / Skipped / Failed` 不再混成一个字符串列表 |
| P1-13 网络策略覆盖 | 出口诊断已 `StrictProxy`；更新检查/下载、Clash 控制器、OAuth API 各自显式声明策略 |

---

## 10. 高收益小改动

| 编号 | 改动 |
| --- | --- |
| L-01 / L-02 | IPv6 旁路不再放行；`unverified_reason()` 输出真实原因 |
| L-03 | 删除不安全的 GUI 宽松回退与 `"\n"` 转义错误 |
| L-04 | 首次布防按实际默认目标校验白名单 |
| L-05 | 配置读不出来时不回退成「代次未变」 |
| L-06 | 兜底状态读取时核对实际规则 |
| L-07 | `cleanup_legacy_rules()` 的错误不再被 `unwrap_or(0)` 丢掉 |
| L-08 | 「已完整解除」的回执不再携带未处理失败项 |
| L-09 | `Stop-Process` 不再静默报成功 |
| L-10 | `agent_pids()` 排除 CLI 路径 |
| L-11 | 下载改**有界流式**：边读边写边算哈希，超限立即中止（缺 `Content-Length` 也拦得住） |
| L-12 | 未建立签名根前**不自动运行**安装包（`TRUSTED_UPDATE_CHAIN_AVAILABLE = false`） |
| L-13 | 熔断因配置过期被取消时不再写成「部分熔断」（`TripOutcome::AbortedStale`） |
| L-14 | 规则本来已存在时不计入 `rules_added` |
| L-15 | 哨兵协议的截断/错误输出/异常回执组合测试 |
| L-16 | CI 按名字点名跑 16 组安全回归场景（少一个即失败） |

---

## 11. 必要 P2

| 编号 | 状态 |
| --- | --- |
| P2-01 故障注入 | 新增 `tests/windows-integration/`：README 矩阵 + 两个可执行脚本。<br>**02 已在实机通过**（4 条三类规则 → 0，退出码 0，幂等）；**03 已通过**（规则 + 意图 + ready → 全部清除）。<br>未实现：网卡禁用/恢复、PersistentStore/ActiveStore 不一致、并发、进程中断注入、NSIS 回归——都需要可回滚 VM，矩阵里逐项标注 |
| P2-02 发布门禁 | 沿用 v0.7.2；本版未改动结构 |
| P2-03 许可追溯 | 沿用 v0.7.2 的逐模块矩阵；`network_policy.rs` 等新增模块已归入「本仓库自有」 |
| P2-04 安装状态三态 | 沿用 v0.7.2 |

---

## 12. 明确未做

| 项 | 原因 |
| --- | --- |
| P1-02 受限特权 helper | 需要独立 helper 可执行文件、固定命令枚举、调用方校验、UAC 交接；架构级改动，半成品会扩大攻击面 |
| P1-03 可信更新签名根 | 需要密钥托管与发布基础设施 |
| P1-05 独立守护进程 | 需要把监控核心与 Tauri 窗口解耦 + 单一所有者 + 所有权交接 |
| P2-01 中需要 VM 的场景 | 需要可快照回滚的 Windows 虚拟机 |
| 可信 DNS 通道（P0-03 的完整解） | 需要 TUN 内 DNS 或经证明的 DoH，属独立工作项 |

---

## 13. 质量门禁（本版实际执行）

```text
cargo fmt --check                          通过
cargo clippy --all-targets -- -D warnings  零警告
cargo test --lib                           678 passed / 0 failed / 0 ignored
npx tsc --noEmit                           通过
npm run build                              通过
```

真实系统（管理员，本机）：

```text
tests/windows-integration/02-firewall-isolation.ps1   PASS
  BEFORE 0 → CREATED 4 → restore exit 0 → AFTER 0 → second restore exit 0
tests/windows-integration/03-restore-ledger.ps1       PASS
  restore exit 0 → rules 0 → lock file removed → ready file removed
```

---

## 14. 行为变化（升级须知）

1. **TUN 模式下出口检查仍会显示「未验证」**：证据链已经不缺逻辑，缺的是可证明
   安全的 DNS 解析通道。这是有意的保守，不是回归。
2. **未接入代理时不会自动发 STUN 探测**：WebRTC 一项会显示「已跳过」并说明原因；
   需要主动诊断请用界面上的显式确认入口。
3. **更新不再自动弹出安装向导**：只下载 + 校验，然后引导去官方 Release 手动安装。
4. **全新安装若未配置白名单，无法开启门禁**：会明确提示缺哪几个目标，而不是
   开起来之后熔断。
5. **身份未知的可执行文件不会建立 GUI 隔离规则**：报告中会列出被拒路径与原因。
