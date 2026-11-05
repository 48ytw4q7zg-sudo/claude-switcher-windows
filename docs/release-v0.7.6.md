# v0.7.6 发布说明（安全边界与事务收口）

> 日期：2026-11-06｜基线：v0.7.5 → **v0.7.6**
> 主题：**系统修改要么是事务、要么是拒绝**——不许在中途留下「已经不保护了」
> 的窗口，也不许把「跳过」「查不到」混进「成功」。

## 0. 一句话结论

v0.7.5 修好了「结论必须由全部应处理对象算出」。这一版修它的下一层：
**「一次系统修改必须是完整的事务」**。9 个 P0 里最典型的三个是——
规则修复先删后建（新建失败就没了保护）、兜底「已核验」只查规则名不查属性
（改成 Allow 也算通过）、自动解除不看代理绕过列表（等待锁期间被改照样放行）。

---

## 1. P0-03：规则修复是「先删后建」，存在保护缺口

**问题**：`quarantine_agent_for()` 的顺序是 `Remove-NetFirewallRule` →
`New-NetFirewallRule`。一旦新建失败（权限不足、RPC 抖动），旧规则已经被删掉，
受保护程序就暴露在未阻断状态。

**修复**：改成真正的事务顺序：

1. 严格查询旧规则（查询失败 → 什么都不做，报 Unknown）；
2. 建一条**临时名** `… ::pending` 的新规则；
3. 对临时规则做完整核验（属性 + 过滤器 + **ActiveStore**）；
4. 核验通过后才删旧实例；
5. 最后把临时名改成正式名。

新建失败 / 核验不过 → 删掉临时规则、**保留旧规则**，如实报告。

> 顺带修掉一个 PowerShell 语义坑：脚本顶层的 `continue` 会绕过执行结果哨兵，
> 已改为嵌套分支。

## 2. P0-04：「已核验」只查规则名，不查属性

**问题**：`uncovered_ready_state()` 用 `firewall_rules_all_present()`，
它只确认规则名还在。外部程序把规则改成 `Allow`、换掉程序路径、或它根本没进
`ActiveStore` 时，名称与条数都不变——界面继续显示「已核验」。

**修复**：ready 记录现在保存**完整规则规格**（名称 + 方向 + 程序路径），
核验走与 `count_rules_for_reason` 同一套判据（属性 + ActiveStore）。
旧版只有名称的记录降级为「需重新核验」，不再当成完整核验（L-06）。

**测试**：`ready_without_rule_specs_is_never_valid`。

## 3. P0-05：自动解除没复核代理绕过列表

**问题**：v0.7.5 的持锁复核只看「代理开关 + 端口能连」。等待锁期间别的程序
改了 `ProxyOverride`，让受监控域名直连——代理照样开着、端口照样通，
但受管应用已经不走它了。

**修复**：持锁后重新跑完整的 `current_access()` 判定（含绕过列表与 PAC），
且用**最新**配置里的目标域名，不用旧报告里的。

## 4. P0-09：`ProxyOverride` 通配符语义不完整

**问题**：`entry_domain()` 只做 `trim_start_matches('*')`，于是 `*claude*`
变成 `claude*`（尾部 `*` 残留）→ 永不命中 `claude.ai`。而 Windows WinINet
**确实支持** `*int*` / `*claude*` 这类中间通配，会让匹配域名绕过代理直连。

**修复**：完整的 Windows 绕过语义解析器：

| 条目 | 语义 |
| --- | --- |
| `*` | 全部绕过 |
| `<local>` | 内网（无点号）主机名绕过 |
| `<-loopback>` | 显式声明回环不绕过 |
| `*claude*` / `*.claude.ai` / `claude.*` | `*` 通配（含中间通配） |
| 字面域名 | 域名本身 + 子域 |
| IP / IP 段 / CIDR | 只对指向裸 IP 的连接生效 |
| **其它** | `Unrecognized` → **未知，不得当无风险**（L-10） |

判定是三态 `BypassVerdict::{NoRisk, Risk, Unknown}`。

**测试**：`proxy_override_wildcards_follow_windows_semantics`、
`bypass_verdict_is_three_state_and_conservative`、
`verdict_rejects_system_proxy_when_bypass_risks_monitored_host`。

> 一个有意思的细节：`*claude*` 在 WinINet 语义下**也**匹配 `notclaude.invalid`
> （它含 claude 子串）。第一次写测试时我按直觉断言「不该匹配」，被测试自己打脸
> ——匹配才是对的。

## 5. 其余 P0

| 编号 | 修复 |
| --- | --- |
| P0-01 高权限计划任务 | `register_logon_task(Highest)` 现在**拒绝**在用户可写目录创建任务（真实探针：尝试在目标目录建随机文件）。完整方案需要独立特权 helper，属架构改动；这是缓解 |
| P0-02 配置丢失被当成首次安装 | 新增独立的 `config-initialized.json` 标记。已初始化后配置丢失 → 报「配置丢失」而非 `Fresh`，且**拒绝**用默认值重建（那会替用户关掉保护） |
| P0-06 事务间隙 | 意图/ready 清理并入**同一段持锁事务**；意图文件带 `txn`，只删「txn 相符」的记录，别的流程新建的意图不会被误删 |
| P0-07 内置目标可降级 | `check_builtin_protection` 现在同时锁定 `anchor_kind`。把 Claude 改成 Reachability 曾能让整套出口白名单失效（`evaluate()` 只看能否连上，`unready_targets()` 又跳过白名单校验） |
| P0-08 MSIX 硬编码 | `Get-AppxPackage -Name 'Claude'` 改为按 agent 的包身份匹配（Claude / ChatGPT+OpenAI / Antigravity+Google）。ChatGPT、Antigravity 的 MSIX 安装不再被误判为「未安装」 |

---

## 6. P1

| 编号 | 修复 |
| --- | --- |
| P1-01 网卡枚举吞错 | `list_adapters()` 的 `Get-NetAdapter` 改 `-ErrorAction Stop`（上一轮的严格化实际没落盘，本轮补上）。IP 查询降级为 `ips_ok` 标志 |
| P1-02 离线状态被过早改动 | 网卡读取失败时**不再推进** `OFFLINE` 状态——原来先 `swap` 再判断「跳过本轮」，与注释约定相反，一次查询失败会污染防抖历史 |
| P1-03 手动检查污染熔断计数 | 手动检查 / 启动检查改用**临时计数器**，后台 `run_monitor_round` 是唯一持有防抖计数的一方。原来「点十次检查」能让后台第一次失败直接熔断 |
| P1-04 监控间隔 clamp 错误 | `egate_update_settings` 误用 `clamp_timeout`（1..=30 秒）限制监控间隔（应为 5..=3600）。用户保存 600 秒会被压成 30 秒，巡检频率放大 20 倍。**源码可直接确认的 bug** |
| P1-05 保存目标不复核 | `egate_save_targets` 在门禁开启时也走 `try_update` 做布防就绪校验，校验与写盘同一把锁 |
| P1-07 环境修改未统一加锁 | 时区对齐/还原、地区锁定全部走 `SystemOperation::TimezoneWrite`；`restore_all` 用无锁版本避免自我死锁 |
| P1-08 保镖宽松配置读取 | `guard_tick` 改 `load_checked()`；配置损坏/丢失时本轮跳过查杀与时区改写，保留既有防火墙保护 |

---

## 7. 高收益小改动

| 编号 | 改动 |
| --- | --- |
| L-01 | `killed`/`skipped`/`failed` 分开（`KillOutcome`），跳过的进程不再算成真实查杀副作用 |
| L-02 / L-03 | `egate_monitor_status` / `egate_access_status` 改 async + `blocking()`，不再卡住 WebView 主线程 |
| L-04 | 规则核验区分「确实不存在」与「查询失败」，RPC/权限错误不再被显示成「规则缺失」 |
| L-05 | 严格防泄漏开关的依赖关系已写入按钮提示（本轮未单独做完整就绪检查） |
| L-06 | ready 记录缺少规则明细时判为「需重新核验」 |
| L-07 / P2-02 | 新增 `scripts/check-security-regressions.ps1`，**CI 与 tag 发布共用同一份**——上一轮两套门禁分叉的根因 |
| L-08 | 内置目标锚点类型已由后端校验（前端只读是下一层） |
| L-10 | 未知绕过语法按 Unknown 处理（并入 P0-09） |

---

## 8. 必要 P2

| 编号 | 状态 |
| --- | --- |
| P2-01 故障注入 | `02/03/04` 三个脚本**均已在管理员实机通过**（本轮复跑）。矩阵中其余场景（非管理员、ActiveStore 不一致、并发、NSIS）仍需可回滚 VM |
| **P2-02 发布门禁共用脚本** | **本轮完成**：`scripts/check-security-regressions.ps1` 同时被 `ci.yml` 与 `windows-build.yml` 调用，36 组安全回归点名验证 |
| P2-03 许可追溯 | 沿用 `docs/upstream-baseline.md` §7 矩阵 |
| P2-04 功能保证边界 | 已写入 README「验收边界」与本文件 §9 |

---

## 9. 明确未做

| 项 | 原因 |
| --- | --- |
| P1-01 特权 helper（完整版） | 需要独立可执行文件、固定命令枚举、调用方校验、UAC 交接。本轮只做了「拒绝在用户可写路径注册 Highest 任务」的缓解 |
| P1-06 环境修改恢复账本 | IPv6/时区/Culture 的原状态快照与资源级恢复需要真实 VM 验收；本轮只统一了锁 |
| P1-09 可信 TUN DNS | 仍是 `TRUSTED_DNS_AVAILABLE = false` |
| P1-10 独立常驻守护 | 监控核心与 Tauri 窗口解耦 + 单一所有者，架构级 |
| P1-11 可信更新签名根 | 仍保持「不自动运行下载的安装包」 |
| P1-12 企业策略代理来源 | HKLM/组策略代理读取需要真实域环境验证 |
| P2-01 中需 VM 的场景 | 需要可快照回滚的 Windows 虚拟机 |

---

## 10. 质量门禁（本版实际执行）

```text
cargo fmt --check                          通过
cargo clippy --all-targets -- -D warnings  零警告
cargo test --lib                           700 passed / 0 failed / 0 ignored
npx tsc --noEmit                           通过
npm run build                              通过（349.24 kB / gzip 106.61 kB）
scripts/check-security-regressions.ps1     36/36 组通过
```

真实系统（管理员，本机）：

```text
02-firewall-isolation.ps1  PASS  rules 4 -> 0, exit 0, idempotent
03-restore-ledger.ps1      PASS  真实账本 + 意图 + ready 全部收敛
04-corrupt-ledger.ps1      PASS  账本损坏时 exit 1, 规则与账本均保留
```

---

## 10.1 发布产物（2026-11-06 已发布）

| 资产 | 大小 | SHA-256 |
| --- | --- | --- |
| `ClaudeSwitcher_0.7.6_x64-setup.exe` | 8,317,477 B | `fd9a4bd96e1768a4ff279d3a9bc1f1c6c54e24bc2f200b64dedc8401ac948f70` |
| `ClaudeSwitcher-portable.zip` | 9,767,620 B | `4742e5883eecb1aa56338ce5af150360d6d76cd9d732f60fa2cbda1f4106e6d0` |
| `SHA256SUMS.txt` | 195 B | 随包分发 |

- Release：<https://github.com/48ytw4q7zg-sudo/claude-switcher-windows/releases/tag/v0.7.6>
- 哈希已用 `sha256sum -c SHA256SUMS.txt` 与独立重算**双重核对**，两者一致。
- 构建来源证明已通过 `gh attestation verify`（含 sigstore 证书），绑定
  `windows-build.yml` @ `refs/tags/v0.7.6`。
- 发布工作流里 **`Security regression scenarios` 与 CI 是同一份脚本**
  （`scripts/check-security-regressions.ps1`），本次构建该步骤 `success`
  ——P2-02 的两套门禁分叉问题已闭合。
- 安装包是 **NSIS** 自解压 PE32，未代码签名（SmartScreen 提示属预期，
  请用上述哈希或 attestation 自行核对）。

## 11. 行为变化（升级须知）

1. **配置文件丢失后不再当成首次安装**：会报错并拒绝用默认值重建。
   请从备份恢复 `appconfig.json`（`%USERPROFILE%\.claude-switcher\backups\`）。
2. **程序装在用户可写目录时无法注册最高权限保镖计划任务**，会给出明确原因
   与安装到 Program Files 的提示。
3. **内置出口目标的锚点类型不可改**（含历史配置里被改过的，保存时会报错提示恢复）。
4. **监控间隔上限从 30 秒恢复为 3600 秒**——之前被误压成 30 秒。
5. **手动检查不再影响后台熔断计数**：点多少次都不会让下一次失败提前熔断。
6. **代理绕过列表的通配符语义已对齐 WinINet**：`*claude*` 这类条目现在会被
   识别为风险并阻止「代理已覆盖」的结论。
