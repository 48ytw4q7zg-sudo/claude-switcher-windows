# 上游基线记录（upstream baseline）

> 目的：把「迁移目标」固定成可复现的具体 commit，而不是会变化的 `main`。
> 任何人复核时按这里的 SHA 拉取，看到的代码与本次审查一致。

## 当前迁移状态（v0.6.7，2026-11-05）

三个上游的核心能力均已实现并接入生产入口。**当前准确的项目状态以
[`docs/release-v0.6.7.md`](release-v0.6.7.md) 与 [`docs/parity-gap-final-2026-11-04.md`](parity-gap-final-2026-11-04.md) 为准**；
本文件只负责固定上游 SHA 与记录逐项对应关系。

本节下方「早期矩阵」保留历史写法用于追溯，其中的「待实现」描述已不成立——
v0.6.6 / v0.6.7 已逐项落地：48 小时出口历史（`ip_history.rs`）、六项非关键检查配置
（`checks.rs` `disabled_checks`）、加密快照携带真实 Desktop 数据（`export.rs` CSBK1 v3）、
自动更新下载与 SHA256 校验（`update.rs`）、出口门禁全套（`egate_*.rs`）。

验收层次需要区分：**测试函数存在 ≠ 断言有效**，**判定逻辑通过 ≠ 真实系统行为正确**。
系统级行为（防火墙、网卡、计划任务、托盘）的实机验收状态统一记录在 README 的
「验收边界」一节，不在本文件重复断言。

## 1. 三代码基线（实现来源）

本仓库是**三个上游能力的融合**，统一落在一个 Tauri 2 + Rust + React 应用里：

| 基线 | 仓库 | 管理对象 | 技术栈 | 固定 commit |
| --- | --- | --- | --- | --- |
| A. CLI 切换器 | https://github.com/VallierDev/claude-switcher | Claude Code **CLI**（`~/.claude`、`~/.claude.json`、OAuth 凭据） | Tauri 2 + Rust + React | [`68979843313a0cb7da3cda32765184436ba9598e`](https://github.com/VallierDev/claude-switcher/commit/68979843313a0cb7da3cda32765184436ba9598e) |
| B. 环境/桌面版 | https://github.com/YOURSJEYO/claude-switcher | Claude **桌面版**（`%APPDATA%\Claude`）+ 环境安全 | bash/PowerShell 核心 + Swift/macOS + WPF Windows Beta | [`870c4ca0754234965878ef58144d7a755d965037`](https://github.com/YOURSJEYO/claude-switcher/commit/870c4ca0754234965878ef58144d7a755d965037) |
| C. 出口门禁 | https://github.com/daha1216/ClaudeGuard | 受管 GUI 应用的**出网路径**（目标出口校验 + 按 exe 隔离） | Rust | [`1967377bec393bcba82199f038550d6fa5f677ec`](https://github.com/daha1216/ClaudeGuard/commit/1967377bec393bcba82199f038550d6fa5f677ec) |

记录日期：2026-10-27（v0.6.0 于 2026-10-31 复核上游 `main`；基线 C 于
v0.6.7 补充）。

**许可证状态（2026-11-05 复核，需持续跟踪）**：
- 基线 A：本仓库固定提交处未声明 LICENSE。
- 基线 B：**当前主分支为 AGPL-3.0**（早期版本曾是 MIT）。本仓库固定的是
  早期提交，其授权按当时版本判断；但**继续移植基线 B 的最新代码前必须做
  许可证兼容性审查**——AGPL-3.0 与本项目的 Apache-2.0 存在冲突风险。
- 基线 C：MIT。

本项目为 Apache-2.0。上述为事实记录，不构成法律意见。

### 1.0 基线 C（ClaudeGuard）的对应关系

ClaudeGuard 是出口门禁的语义来源，其 [v3.10 保护状态契约](https://github.com/daha1216/ClaudeGuard/blob/1967377bec393bcba82199f038550d6fa5f677ec/docs/CONTRACT-v3.10.md)
定义了本仓库 `egate_*` 模块族的四条硬约束：

| 契约要求 | 本仓库实现 |
| --- | --- |
| 保护意图（Armed / Disarmed / Unknown）与「是否已隔离」是两个独立维度 | `egate_monitor::ProtectionIntent` + `is_tripped` / `is_partial` / `is_trip_state_unknown` |
| 自动恢复必须有明确资格，不能只看目标是否 Pass | `RecoveryEligibility`（目标 / 接入 / 泄漏 / 手动保持四项） |
| 用户手动 lockdown 与自动熔断生命周期独立 | 持久化 `ManualHold`（`eguard-manual-hold.json`），自动恢复不解除 |
| 系统修改必须独占，且锁内重新核验意图 | `egate_lock::OperationGuard`（fs4 排他 + 编译期 `!Send`）+ `egate_trip::trip()` 锁内重读意图 |

> 关于仓库名：用户链接里的 `claude-switch` 是笔误，经 `gh api users/YOURSJEYO/repos`
> 核实真实仓库名为 `claude-switcher`。

### 1.1 上游基线之后的增量（v0.6.0 对等范围）

基线 B 固定于 `870c4ca`，但上游 `main` 仍在演进（v0.6.0 复核时为 `f37cb26`，
含标签 v1.0.0~v1.7.1）。新增内容已逐项对照，Windows 相关增量及本仓库处置：

| 上游新增 | 上游位置 | 本仓库处置 |
| --- | --- | --- |
| MSIX Claude 数据目录发现 | `Find-ClaudeDataPath` | 已对等：`desktop::resolve_desktop_live_dir` + `platform::claude_appx_families` |
| FlClash 客户端识别 | `Test-ProxyAlive` | 已对等：`guard::required_process` 加 `flclash → flclashcore` |
| 客户端语言按系统 UI 语言、不一致降 warn | `Invoke-CheckDetail` | 历史实现，已被 1.1.1 的 Claude 配置语言方案替换 |
| 48h 出口 IP 变化计数 | `Add-IpHistory` / `iphistory.log` | 已对等：`ip_history.rs`（48 小时窗口累计，仅在 IP 一致性检查启用时读写） |
| Claude 由 Appx/AUMID 兜底启动 | `Find-ClaudeAumid` | 已对等：`egate_launch` 用 `shell:AppsFolder\<PFN>!<AppId>` 拉起；Desktop 账号切换本身不负责拉起 |
| 切换目录改用暂存+换位（不先删活目录） | `Switch-DataDir` | 已有等价保护：先 staging 备份再清空，失败自动回滚 |
| 优雅关闭后再强杀 | `Stop-ClaudeApp` | 已对等：`kill_desktop_processes` 两段式 |

### 1.1.1 2026-11-01 增量复核

上游最新为 `dfd2a5012a2633ebfe0d435cb3c15a089be58184`，相对上述 `f37cb26` 新增
`6600bf9`（Windows 语言与 ASN 检查修正）和一项文档提交。
客户端语言现已对齐：读取 Claude `config.json` 的 `locale`，传统配置缺失时查询 MSIX，
不再用 Windows 显示语言代替；缺失/损坏/不一致为 warn。临时目录与编码回归通过，
真实 MSIX 安装及运行时语言仍未验证，见 [本轮记录](optimization-client-language-2026-11-01.md)。
ASN 网络类型查询、48h IP 历史和 Desktop 启动等剩余差异继续保留，不因本次修复改成已完成。

### 1.1.2 关键决定反转（以用户最新指令为准）

早期版本（含旧 AGENTS.md / 本文件）记录「YOURSJEYO 已明确不移植」。
**项目 owner 已明确推翻该决定，要求把 YOURSJEYO 的全部功能一模一样地迁移到 Windows，
并与本仓库融合；功能不能少，可适当增加。** 因此：

- 基线 B 的全部能力（14 项检查、一键修复、保镖/看门狗、地区锁定、Clash 规则、
  STUN/open-safe/diagnose/fingerprint/cli-info、加密快照、自动更新、桌面版管理）
  均须以 Rust + React 实现并纳入本应用，现有对应模块仍有上述功能与验证缺口；
- 上游 PowerShell / bash / Swift 仅作为**逐行行为基准**，主交付是 Tauri 应用；
- 本文件旧版「不实现 YOURSJEYO」整段作废。

### 1.2 目标架构

保留并扩展 Tauri 2 + Rust + React 作为**唯一主产品**：Rust 后端 + React 前端 +
MSI/NSIS 安装包。融合后的应用同时管理两类对象：

- **Claude Code CLI**：`~/.claude`、`~/.claude.json`（固定 home，`CLAUDE_CONFIG_DIR`
  不跟随）、`~/.claude/.credentials.json`；
- **Claude Desktop 桌面版**：活目录 `%APPDATA%\Claude`（`dirs::config_dir()\Claude`），
  切换前必须完全退出（含托盘）。

## 2. 早期新增 Rust 模块与职责（历史统计）

所有平台差异收拢在 `src-tauri/src/platform/`，业务代码不写 `#[cfg(windows)]`；
阻塞操作走 `blocking(...).await`；落盘一律 `fsx::write_atomically`。

| 模块 | 职责 | 单测数 |
| --- | --- | --- |
| `appconfig.rs` | 全局配置 `~/.claude-switcher/appconfig.json`（country/tz/locale/proxy_mode/webrtc_policy/last_egress_ip） | 3 |
| `egress.rs` | 出口 IP 探测（Cloudflare trace + ipinfo）、住宅/机房 ASN 启发式 | 5 |
| `region.rs` | 国家→时区/locale/GeoID 映射、IANA→Windows 时区 ID、地区锁定计划 | 9 |
| `stun.rs` | UDP STUN 探针（XOR-MAPPED-ADDRESS 解析、真实 IP 泄漏判定） | 7 |
| `desktop.rs` | Claude Desktop 快照/捕获/切换/删除/重命名（含备份回滚） | 10 |
| `guard.rs` | 保镖 kill-switch + 时区看门狗 + 计划任务注册 | 4 |
| `rules.rs` | Clash 模式识别、Script.js 托管规则、内核 `/rules` 验证与回滚 | 24 |
| `diagnostics.rs` | open-safe、代理诊断、系统指纹、CLI 体检 | 10 |
| `keep.rs` | 跨身份保留 keep-in-workspace（stage/merge） | 5 |
| `checks.rs` | 14 项检查 + 静默总检 + 一键修复 | 15 |
| `platform/windows.rs` | 新增网卡/时区/区域/IPv6/计划任务/进程等平台 API | +8 |
| `store.rs` | 新增 `DesktopProfile` 数据模型（向后兼容） | +1 |

## 3. 早期功能对等矩阵（历史定位）

早期记录曾将有 `#[test]` 覆盖标为「已验证」，将实现存在但系统交互未测标为「待实机」。
这些标签仅保留历史含义，不构成本轮验收结论。尤其测试存在、分类逻辑通过、功能完整实现、
真实运行通过是不同层次；已发现的覆盖不足与功能缺口按本文开头和全量进度处理。

### 3.1 基线 A（CLI，VallierDev）

| 上游功能 | 本仓库实现 | 测试 | 状态 |
| --- | --- | --- | --- |
| 读取/写入/清除 OAuth 凭据 | `credentials::{read,write,clear}_password` | `fsx::write_atomically_*`（间接） | 待实机 |
| store 加密主密钥 | `store::read_store_key` | `encrypt_decrypt_roundtrip`（#[ignore]） | 待实机 |
| 账号快照保存/切换 | `capture_current_profile` / `switch_profile` | `accounts::merge_claude_json_*` | 部分验证 |
| 备份 / 还原 | `create_backup_with_label` / `restore_backup` | `accounts::backup_snapshot_*` | 部分验证 |
| 一键新号向导 | `prepare_new_account_login` / `complete_new_account_login` | 无 | 待实机 |
| session / 本地目录 / config 隔离 | `isolation::activate_profile_*` | `platform::is_link_*`、`links::*`、`store::split_auth_settings_*` | 部分验证 |
| Clash 节点绑定/切换 | `clash::switch_clash_node_internal` | `net::controller_normalization_table` | 待实机 |
| 用量统计（本地/OAuth） | `usage::claude_usage_snapshot` / `apply_oauth_usage` | `usage::*`（多个） | 部分验证 |
| 托盘 + 弹窗 | `tray::toggle_tray_popup` | 无 | 待实机 |
| 进程检测 / 结束 | `processes::claude_code_processes` | `processes::claude_code_process_matching_table` | 已验证 |
| 遥测去关联注入 | `accounts::apply_profile_env_to_settings` | `accounts::apply_profile_env_writes_telemetry_and_runtime` | 已验证 |
| 路径归一化 / 编码兼容 / 控制器归一化 | `platform::windows::normalize_path`、`jsonio::*`、`net::normalize_controller` | 对应 `*_table` | 已验证 |

### 3.2 基线 B（YOURSJEYO，全部功能）

| # | 功能 | 本仓库实现 | 测试 | 状态 |
| --- | --- | --- | --- | --- |
| 1 | 代理内核检查（多客户端进程/服务） | `checks::judge_proxy_core` + `guard::client_alive` | `checks::*proxy_core*`、`guard::client_alive_logic_table` | 部分验证 |
| 2 | TUN 网卡检查（198.18 优先，回退描述匹配） | `guard::tun_status_from_adapters` | `guard::tun_detection_table` | 已验证 |
| 3 | 出口 IP 检查（国家==目标） | `checks::judge_egress_country` + `egress` | `checks::*egress*`、`egress::*` | 部分验证 |
| 4 | IP 一致性检查（lastip） | `checks::judge_ip_consistency` | `checks::*ip_*` | 已验证 |
| 5 | 时区检查（Windows 时区 ID==目标） | `checks::judge_timezone` | `checks::*timezone*` | 已验证 |
| 6 | 地区检查（文化区域，**按出口动态**） | `checks::judge_region` + `region` | `checks::*region*`、`region::*` | 已验证 |
| 7 | IPv6 检查（全网卡已禁用） | `checks::judge_ipv6` + `platform::ipv6_bindings` | `checks::*ipv6*` | 已验证 |
| 8 | DNS 检查（解析走 198.18） | `checks::judge_dns` | `checks::*dns*` | 已验证 |
| 9 | WebRTC 检查（STUN 探针比对） | `checks::judge_webrtc` + `stun::probe_stun_leak` | `checks::*webrtc*`、`stun::*` | 部分验证 |
| 10 | 保镖检查（已安装/运行） | `checks::judge_guard` + `guard::guard_installed` | `checks::*guard*`、`guard::*` | 已验证 |
| 11 | 规则置顶检查（模式识别 + 内核 /rules 前 16 条） | `checks::judge_rules` + `rules::verify_pinned_rules` | `rules::*`（24 个） | 已验证 |
| 12 | 客户端语言检查（Claude 配置与目标主语言比较） | `desktop::client_locale` + `checks::judge_client_language` | `desktop::*client_locale*`、`checks::*language*` | 文件读取/判定已验证，真实 MSIX 与运行时语言未验证 |
| 13 | ASN 属性检查（住宅 vs 机房） | `checks::judge_asn` + `egress::is_datacenter_org` | `checks::*asn*`、`egress::*` | 已验证 |
| 14 | 生态可达性检查（claude.ai + api.anthropic.com） | `checks::judge_reachability` | `checks::*reachability*` | 已验证（分类），实机待验 |
| fix | 一键修复（拉起内核/TUN→锁时区→关 IPv6→写规则→注册保镖→复测） | `checks::run_fix_blocking` | `checks::*fix*` | 部分验证 |
| — | 保镖 kill-switch（fail-closed，10s 巡检） | `guard::guard_tick` + `run_guard_loop` | `guard::tick_decision_*` | 已验证（逻辑），实机待验 |
| — | 时区看门狗（被改动自动回滚） | `guard::tz_watchdog_tick` | `guard::*` | 已验证（逻辑） |
| — | set-region（换节点后一键重锁） | `lock_region`（lib.rs） | `region::*` | 部分验证 |
| — | set-client（更换代理客户端） | `set_client`（lib.rs） | `appconfig::*` | 已验证 |
| — | 多客户端存活判定（auto/other 只查 TUN） | `guard::client_alive` | `guard::client_alive_logic_table` | 已验证 |
| — | Clash 模式识别（Mihomo API，回退 verge.yaml） | `rules::clash_mode` | `rules::*clash_mode*` | 已验证 |
| — | 规则只写 Script.js 托管块 + 清理 Merge + 重启验证回滚 | `rules::ensure_rules` | `rules::*` | 已验证（逻辑），实机待验 |
| — | WebRTC 策略（proxy/reject，UDP 3478/5349/19302） | `rules::{rule_strings,WebRtcPolicy}` | `rules::rule_strings_*` | 已验证 |
| — | open-safe 一次性隔离浏览器 | `diagnostics::open_safe` / `close_safe` | `diagnostics::*safe*` | 已验证（逻辑），实机待验 |
| — | diagnose-proxy 代理无认证可达性（401/403 标注） | `diagnostics::diagnose_proxy` | `diagnostics::*probe*` | 已验证 |
| — | fingerprint 指纹体检（字体/GPU/Canvas/WebGL 由 webview 补） | `diagnostics::system_fingerprint` | `diagnostics::vm_detection_table` | 已验证（系统侧） |
| — | cli-info（PATH 顺序/版本/安装方式/多份告警） | `diagnostics::cli_info` | `diagnostics::*cli*` | 已验证 |
| — | 加密快照导出/导入（CSBK1，Argon2id+AES-GCM，口令≥8） | `export::{export,import}_store_encrypted_*` | `export::*` | 已验证（逻辑） |
| — | 跨身份保留 keep-in-workspace | `keep::{stage,merge}_keep` | `keep::*`（5 个） | 已验证（逻辑） |
| — | 自动更新（GitHub Release，校验和，备份回滚） | `update::check_for_update_blocking` | 更新检查专项测试已通过 | 检查已修复；下载、校验与回滚待实现 |
| — | Desktop 账号管理（捕获/切换/删除/重命名） | `desktop::*` | `desktop::*`（10 个） | 已验证（逻辑），实机待验 |

## 4. 早期测试与构建结果（非当前全量结果）

- `cargo fmt --check`：通过。
- `cargo clippy --all-targets -- -D warnings`：**零警告**。
- `cargo test --lib`：**156 passed / 0 failed / 1 ignored**（测试总数随新模块从 57 增至 156）。
- `npx tsc --noEmit`：前端融合后通过（见前端交付）。
- `npm run tauri build`：产出 MSI + NSIS（见发布记录）。

## 5. 未实机验证项

- 保镖真实 kill（Claude Desktop + CLI）、计划任务 highest 权限注册与 AtLogOn 触发；
- TUN 网卡、verge.yaml TUN 开关恢复后 Clash Verge 实机重启加载；
- 真实代理到 claude.ai / api.anthropic.com 的连通性与 401/403 分类；
- open-safe 真实浏览器拉起、WebRTC 标志生效、窗口关闭后 profile 销毁；
- 多显示器/任务栏位置/DPI 托盘弹窗定位；开机自启（任务管理器禁用后再开）；
- 安装包升级/卸载回归、自动更新全流程。

## 6. 上游升级差异审查流程

```bash
# 基线 A
git fetch https://github.com/VallierDev/claude-switcher.git main
git diff 6897984..FETCH_HEAD -- src-tauri/src src package.json
# 基线 B
git fetch https://github.com/YOURSJEYO/claude-switcher.git master
git diff 870c4ca..FETCH_HEAD -- core windows app
```

1. 对每个变化的功能，按上表找到本仓库对应模块，判断是否需要同步。
2. Windows 专属行为（junction、icacls、sysinfo、计划任务）不要反向同步回上游。
3. 更新本文件的固定 commit。
