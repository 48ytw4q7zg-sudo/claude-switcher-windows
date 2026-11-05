# v0.7.2 发布说明（大修订）

> 日期：2026-11-05｜基线：v0.7.1（本地未推送）→ **v0.7.2**
> 本版聚焦**执行结果可信度**：把「命令跑完了」与「系统真的变了」彻底分开。

## 0. 一句话结论

第十七轮审计里最关键的发现不是又多了几个缺陷，而是**本地 0.7.1 在真实 Windows
验证阶段暴露出「恢复命令退出码非 0，但规则其实已经全部清掉」**。本版先修这个底层
协议，再补 P0/P1 的收口与低成本高收益项，并在本机做了真实防火墙端到端复测。

---

## 1. P0-NEW-01：PowerShell 执行结果与真实系统结果不一致

### 1.1 实测到的现象（本机复现）

- `-EncodedCommand` + NetSecurity 模块时，`powershell.exe` **可能以 1 退出但命令成功**；
- 反过来，`-ErrorAction SilentlyContinue` 会把「拒绝访问 / RPC 失败 / 服务停止」
  吞掉，脚本以 0 退出、输出空集 —— 与「确实没有规则」完全无法区分；
- **语句级 `exit` 会跳过尾部哨兵**，让调用方看到「退出码 0 + 半截输出」。

### 1.2 修复

| 位置 | 改动 |
| --- | --- |
| `platform/windows.rs::run_ps_outcome` | 新增**三态** `PsOutcome::{Success, Failed, Unknown}`；退出码仅作参考，**以哨兵为准**；无哨兵一律 `Unknown` |
| 同上 | 新增 120 秒硬超时并 `kill` 子进程（原 `output()` 会无限等）；stdout/stderr **并发读取**，避免大输出时管道互锁假死 |
| 同上 | `assert_no_early_exit`：**执行前静态拒绝**含语句级 `exit` 的脚本（按 `;` `{` `}` 语句边界判定，`Write-Output 'exit 0'` 不误伤） |
| `platform/windows.rs::firewall_rules_exist` | 改用 `-ErrorAction Stop` + 通配前缀查询；异常 → `Unknown`，**绝不当成 Absent** |
| `platform/windows.rs::firewall_rule_exists`（新增） | 用「转义前缀通配 + 精确名过滤」代替精确 `-DisplayName`：通配无匹配不抛错，于是**任何异常都只能是真查询失败**（不依赖本地化的异常文案） |
| `egate_trip.rs::cleanup_legacy_rules` | 见 §2 的回归修复 |
| `egate_trip.rs::release_isolation_reason_locked` / `release_all_verified_locked` | 删除改 `-ErrorAction Stop`；删除失败进 `failures`，不再被吞成「删除 0 条」 |
| `egate_trip.rs::quarantine_agent_for` | 建规则改 `-ErrorAction Stop`，权限不足直接带出系统原因 |
| `egate_trip.rs::count_rules_with_prefix` / `rule_count` / `count_legacy_rules` | 全部改严格查询；查询失败返回 `None`（= 无法确认），不再返回 0 |
| `egate_netcut.rs::remove_cut_rule` | 区分「本来就不存在（幂等成功）」与「存在但删不掉（失败）」 |
| `egate_netcut.rs::enable_nics` | 逐块启用并收集失败；不再静默 |
| `egate_netcut.rs::query_cut_rule` | 持久/生效策略与网络配置查询改严格模式 |
| `cli.rs::run_egate_restore` | 报告与**一次独立的系统残留复查**交叉核对；有残留或无法查询一律返回非 0 |
| `egate_launch.rs::launch_claude` | 移除脚本内 `exit`，改用返回值表达结果 |

### 1.3 真实系统验证（本机，管理员）

| 场景 | 结果 |
| --- | --- |
| 创建 `AppIsolation` ×2 + `UncoveredLock` ×1 + 旧版 `Egate claude Out` ×1（共 4 条） | `BEFORE = 4` |
| `cs.exe --exit-restore` | 输出「已完整恢复」；**退出码 0**；`AFTER = 0` |
| 无残留时重复执行 | **退出码 0**（幂等） |
| 单独创建 `ClaudeSwitcher Egate Cut All` 后执行恢复 | 规则被网络恢复阶段正确清掉；**退出码 0** |
| `cs.exe --egate-status` | `isolation_rules: 0`、`network_cut: null`、退出码 0 |

> 未验证：非管理员运行时的拒绝路径、被组策略接管的规则、进程中断/输出截断的真实注入。

---

## 2. 回归修复：解除隔离会误删全局断网规则

**这是 0.7.1 本地改动引入的新缺陷**，比原审计项更危险：

- 0.7.1 把 `cleanup_legacy_rules()` 改成按 `ClaudeSwitcher Egate *` 通配删除；
- 而全局断网规则叫 `ClaudeSwitcher Egate Cut All`，**正好落在这个前缀下**；
- 于是「解除应用隔离」会把用户的全局断网一起解除，`restore_all()` 的账本却仍写着断网中。

修复：恢复为**精确名称 × 精确谓词**删除（旧版内置 agent × 出入站共 6 个名字），
额外的 `Where-Object { $_.DisplayName -eq $n }` 再挡一层。新增回归测试
`legacy_cleanup_never_targets_the_global_cut_rule`。

---

## 3. 上一轮 P0 的复核与补强

| 编号 | 本轮动作 |
| --- | --- |
| P0-01 来源库存隔离 | `IsolationInventory` 按来源分开计数；只有兜底规则时**不**走 `trip()`（不杀进程）。新增 `isolation_inventory_separates_sources` |
| P0-02 规则查询三态 | 统一到 `RuleLookup`；`count_*` 失败返回 `None`；恢复流程 `Unknown` 一律不报成功 |
| P0-03 有效策略核验 | `verify_current_isolation` 前置 `effective_firewall_enabled()`（ActiveStore + 当前活动 Profile） |
| P0-04 配置代次 | **补强**：新增 `can_apply_isolation_with_revision` 与 `trip_with_revision`；**持锁后**、以及**每个应用动手前**都比对 `egate_revision`；监控线程把本轮代次传进去。新增 `isolation_refuses_when_expected_revision_is_stale` |
| P0-05 保镖/恢复互斥 | 保镖查杀持 `GuardKill` 锁、时区看门狗持 `TimezoneWrite` 锁，**持锁后**再次核验意图与目标 |

---

## 4. P1 完成情况

| 编号 | 本轮 |
| --- | --- |
| P1-01 TUN 真实出口 | 新增 `RouteEvidence` + `plan_route_with_evidence`；平台层 `collect_route_evidence`（`Find-NetRoute` 按目标地址查实际出接口 + 默认路由是否由 TUN 承接 + IPv6 启用状态）。只有**证据完整**才 `Direct`，否则保持 `Skip`（Unverified）。界面新增 `tun_route_note` 说明「为什么没探测」 |
| P1-02 权限隔离 | 新增 `is_elevated()`；`egate_monitor_status` 返回 `elevated`，界面区分「权限不足（需管理员）」「权限状态无法确认」。**受限 helper 进程模型未实现**（架构级改动，见 §6 未做项） |
| P1-03 读取错误分类 | `ProxyEvidence` 增加 `complete`/`error` 与 `read_error()`；键不存在=确定的未配置，拒绝访问=Unknown；`verdict()` 对不完整证据给 `Unknown`。新增 `detect_tun_adapter_strict()`；`current_access` 网卡枚举失败也升级为 `Unknown`。**保镖 `list_adapters().unwrap_or_default()` 改为显式跳过本轮判定**（读不到 ≠ 离线） |
| P1-04 更新信任链 | 已实现：参数校验、体积上限、**随机暂存目录**（`create_dir` 保证新建）、安装前后事务门禁。**未实现**：发布清单签名与内嵌公钥（无可信签名根）。README 已明确「在此之前自动运行安装包不视为完整可信更新路径」 |
| P1-05 首次布防就绪 | 已实现（0.7.1），本轮保留 |
| P1-06 GUI/CLI 身份 | 已实现（0.7.1），本轮把 `egate_launch` 的判定函数**与 `is_managed_gui_path` 对齐**，并修正 raw string 里 `\` 导致的永不匹配 |
| P1-07 恢复后意图一致 | 已实现（0.7.1），并接入 L-13 的代次绑定 |
| P1-08 严格配置读取 | 已实现（0.7.1） |
| P1-09 版本号与 tag | 三处版本统一为 **0.7.2**；新增**四段旧版本兼容**（`0.6.13.1` 可正常收到更新）；发布工作流新增 tag 与 Cargo 版本一致性校验。新增 `legacy_four_segment_installed_version_still_sees_updates` |
| P1-10 统一 NetworkPolicy | 新增 `network_policy.rs`：`Loopback`/`Standard`/`StrictProxy` 三策略 + 单一 `apply_policy` 实现；出口 IP 诊断改 **StrictProxy**（无可用代理时**拒绝请求**而不是静默直连）；更新检查/下载、Clash 控制器显式声明策略 |
| P1-11 独立守护 | **未做**（架构级，见 §6） |
| P1-12 已存在但属性错误的规则 | 已实现（0.7.1 的健康检查与重建） |
| P1-13 Clash Verge 自定义目录 | 重写 `restart_clash_verge`：**先确认可拉起，才结束进程**；优先用运行中进程的真实路径；排除内核 exe；新增 `RestartResult` 四态（未处理/已重启/找不到程序未结束/已结束但拉起失败） |

---

## 5. 低成本高收益

| 编号 | 状态 |
| --- | --- |
| L-01 手动保持 Unknown | 已实现；新增 `manual_hold_unknown` 到状态与界面（不再显示成「未保持」） |
| L-02 核验降级后重建 Gate | 已实现 |
| L-03 ReleaseReport 语义 | 已实现 |
| L-04 跳过的 CLI 不计入 killed | 已实现 |
| L-05 字段对齐 | 已实现；本轮补齐 `rules_expected`/`query_ok`/`coverage_complete`/`failed_rules`/`installation`/`access_trip`/`tun_route_note` |
| L-06 更新参数校验 | 已实现（版本字符集、SHA-256 格式、体积上限） |
| L-07 文档去除 MSI 声明 | 已实现 |
| L-08 CI 版本预检 | 已实现，并扩展到发布工作流 |
| **L-09 界面状态模型** | 本轮完成：新增「权限不足（需管理员）」「权限状态无法确认」「手动保持状态无法确认」「兜底封锁（未核验：原因）」 |
| L-10 CSP 分离 | 已实现（`csp` / `devCsp`） |
| **L-11 启动入口身份** | 本轮完成（见 P1-06） |
| L-12 自定义安装路径 | 合并进 P1-13 |
| **L-13 ready 有效期** | 本轮完成：`eguard-uncovered-lock-ready.json` 改为 `{verified_at, revision, rules, agents}`；配置代次/受管清单变化或超过 15 分钟即失效，界面显示失效原因 |
| L-14 空集合不等于没有规则 | 合并进 P0-NEW-01 |
| L-15 run_ps 兼容测试 | 新增 6 项协议测试（含「退出码非 0 但哨兵 OK」「缺哨兵=Unknown」「提前 exit 被拒」） |

---

## 6. 四项必要 P2

| 编号 | 状态 |
| --- | --- |
| P2-01 Windows 故障注入集成测试 | **未实现**（需要可回滚的 Windows 虚拟机与独立测试规则命名空间，不适合在日常开发机上做破坏性测试）。本版用**受控的真实防火墙测试**替代了一部分：创建 4 条测试规则 → 恢复 → 核对清零，并在结束后确认无残留 |
| **P2-02 发布质量门禁** | 本轮完成：发布工作流在 `tauri build` 之前执行 `fmt --check` / `clippy -D warnings` / `cargo test --lib` / `tsc --noEmit` / `npm run build`；tag 必须等于 `v<Cargo.toml 版本>`；发版前校验安装包与便携 zip 数量 |
| **P2-03 许可证追溯** | 本轮完成：`docs/upstream-baseline.md` §7 新增逐模块「行为来源 → 许可结论」矩阵，并写明「不得从 AGPL 版本复制代码」的红线 |
| **P2-04 安装状态区分** | 本轮完成：新增 `InstallationLookup`（`Installed`/`NotInstalled`/`Unknown`）与 `QuarantineReport.installation`；「已确认未安装」显示为不适用、「无法确认」显示为保护未知，两者都不再等于「隔离失败」 |

---

## 7. 明确未做（不在本版范围）

| 项 | 原因 |
| --- | --- |
| P1-02 受限特权 helper 进程模型 | 需要新增独立 helper 可执行文件、固定命令枚举、调用方校验与 UAC 交接；属于架构级改动，做成半成品反而扩大攻击面 |
| P1-04 发布清单签名 + 内嵌公钥 | 需要密钥托管与发布基础设施；没有可信签名根时，宣称「已签名」比不做更危险 |
| P1-11 独立守护进程承载完整监控 | 需要把监控算法与 Tauri 窗口解耦、单一监控所有者机制、所有权交接；属于架构级改动 |
| P2-01 故障注入集成测试 | 需要可回滚虚拟机 |
| gRPC/飞书通知、独立仪表盘、首启向导、FlClash SQLite 事务 | 按用户既定范围排除 |

---

## 8. 质量门禁（本版实际执行）

```text
cargo fmt --check                         通过
cargo clippy --all-targets -- -D warnings 零警告
cargo test --lib                          660 passed / 0 failed / 0 ignored
npx tsc --noEmit                          通过
npm run build                             通过（347.88 kB / gzip 106.11 kB）
```

真实系统：见 §1.3。

---

## 9. 发布判断

本版**满足发布条件的前提**是：

1. 上述门禁在 tag 构建时由发布工作流**再跑一遍**（已写入 `windows-build.yml`）；
2. 安装包在**干净虚拟机**里完成一次升级/卸载回归 —— 这一项本机无法替代，
   仍然标记为**未验证**。

在 2 完成之前，本版应视为「源码与本地验证就绪」，而不是「已通过全部发布验收」。
