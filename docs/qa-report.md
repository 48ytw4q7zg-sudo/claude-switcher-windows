# QA 测试与覆盖报告（v0.2.0）

> 测试对象：`claude-switcher-windows`（Tauri 2 + Rust + React），融合
> VallierDev（CLI）与 YOURSJEYO（环境/桌面版）两个上游的全部功能。
> 报告日期：2026-10-27。

## 一、发布结论

**conditional_go（有条件发布）。**

- 全部静态门禁与单元测试在本机通过（见下），14 项检查、一键修复、保镖/看门狗、
  地区锁定、规则托管、STUN/诊断、加密快照、桌面版管理均有代码与单测证据；
- 但保镖真实 kill、TUN、UAC、真实浏览器/代理、托盘定位、安装升级等**依赖真实
  管理员/网络/显示器/登录态的链路无法在当前环境实机验证**，需用户在实机按
  「未验证清单」回归；
- 已产出 MSI + NSIS 安装包，可作为 v0.2.0 候选发布。

## 二、执行证据（真实命令结果）

| 门禁 | 命令 | 结果 |
| --- | --- | --- |
| 格式 | `cargo fmt --check` | exit 0 |
| 静态检查 | `cargo clippy --all-targets -- -D warnings` | exit 0，**零警告** |
| 单元测试 | `cargo test --lib` | **156 passed / 0 failed / 1 ignored** |
| 前端类型 | `npx tsc --noEmit` | exit 0 |
| 前端构建 | `npm run build`（vite） | 成功，1719 modules |
| 发布构建 | `npm run tauri build` | 成功，2 bundles |

测试数量从基线 57 增至 156（新增 99 个，分布：appconfig 3、egress 5、region 9、
stun 7、desktop 10、guard 4、rules 24、diagnostics 10、keep 5、checks 15、
platform/windows +8、store +1）。

## 三、功能对等核对（逐条）

### 14 项安全检查（checkdetail）

| # | 检查项 | 判定实现 | 单测 | 实机 |
| --- | --- | --- | --- | --- |
| 1 | 代理内核（多客户端进程/服务） | `judge_proxy_core`/`guard::client_alive` | ✓ | 待验 |
| 2 | TUN 网卡（198.18 优先，回退描述匹配） | `guard::tun_status_from_adapters` | ✓ | 待验 |
| 3 | 出口 IP（国家==目标） | `judge_egress_country` | ✓ | 待验 |
| 4 | IP 一致性（lastip） | `judge_ip_consistency` | ✓ | 待验 |
| 5 | 时区（Windows 时区 ID==目标） | `judge_timezone` | ✓ | 待验 |
| 6 | 地区（文化区域，**按出口动态**） | `judge_region` | ✓ | 待验 |
| 7 | IPv6（全网卡已禁用） | `judge_ipv6` | ✓ | 待验 |
| 8 | DNS（解析走 198.18） | `judge_dns` | ✓ | 待验 |
| 9 | WebRTC（STUN 探针比对） | `judge_webrtc`/`stun::probe_stun_leak` | ✓ | 待验 |
| 10 | 保镖（已安装/运行） | `judge_guard` | ✓ | 待验 |
| 11 | 规则置顶（模式 + 内核 /rules 前 16） | `judge_rules`/`verify_pinned_rules` | ✓ | 待验 |
| 12 | 客户端语言（跟随系统） | `judge_client_language` | ✓ | 待验 |
| 13 | ASN 属性（住宅 vs 机房） | `judge_asn`/`is_datacenter_org` | ✓ | 待验 |
| 14 | 生态可达性（claude.ai + api） | `judge_reachability` | ✓ | 待验 |

其余功能：一键修复（`run_fix_blocking`）、保镖 kill-switch（`guard_tick`/
`run_guard_loop`，fail-closed）、时区看门狗（`tz_watchdog_tick`）、set-region
（`lock_region`）、set-client（`set_client`）、Clash 模式识别（`clash_mode`）、
规则托管（`ensure_rules`，只写 Script.js）、WebRTC 策略（proxy/reject）、
open-safe（`open_safe`/`close_safe`）、代理诊断（`diagnose_proxy`）、指纹
（`system_fingerprint`）、cli-info（`cli_info`）、加密快照（`export`，CSBK1）、
跨身份保留（`keep`）、自动更新（`update`）、桌面版管理（`desktop`）——均已实现，
对应单测见 `docs/upstream-baseline.md` 功能对等矩阵。

## 四、本轮发现并修复的缺陷（执行过程）

| # | 问题 | 修复 |
| --- | --- | --- |
| 1 | `set_client`/`set_webrtc_policy` 闭包 move 出捕获变量（E0507） | 闭包内 `clone()` |
| 2 | 5 处 `blocking(|| f())` redundant_closure | 无参函数改传函数指针 |
| 3 | `run_fix_blocking` 直接返回 report，不满足 `blocking` 的 Result 约束 | `blocking(|| Ok(report))` |
| 4 | `GuardTick` 未 derive `Serialize`，无法作为命令返回 | 补 `serde::Serialize` |
| 5 | `dir_size` 未被生产代码使用（dead_code） | 切换后刷新 `size_bytes` |
| 6 | keep 模块未接线（整组 dead_code） | 接入 CLI/Desktop 切换的 stage/merge |
| 7 | `current_home_location_geo` 未使用 | `lock_region` 应用后回读验证 |
| 8 | checks.rs 最终格式不符 rustfmt | `cargo fmt` |

## 五、风险用例（需重点回归）

1. **保镖 fail-closed**：代理内核或 TUN 丢失时，是否在 10s 内强制结束 Claude
   Desktop + CLI；恢复后不误杀。
2. **规则回滚**：Script.js 写入后内核 `/rules` 验证失败，是否自动回滚备份、
   不留半截规则。
3. **桌面版切换回滚**：快照覆盖失败时，是否用 staging 备份自动还原活目录。
4. **keep 安全边界**：绝对路径 / 含 `..` / 符号链接条目被跳过并 WARN；残留暂存
   （上次还原的唯一副本）拒绝覆盖。
5. **快照安全**：目标槽位非空拒绝；口令 <8 拒绝；导入先备份 pre-import。
6. **STUN 无响应**：判 warn，不视为零泄漏。
7. **代理诊断**：401/403/407 分别正确分类；不回显代理凭据。

## 六、未实机验证范围（`unverified`，非空）

- 保镖真实 kill、计划任务 highest 权限注册与 AtLogOn 触发；
- TUN 网卡、verge.yaml TUN 恢复后 Clash Verge 实机重启；
- 真实代理到 claude.ai / api.anthropic.com 的连通性与 401/403 分类；
- open-safe 真实浏览器拉起、WebRTC 标志生效、profile 销毁；
- UAC 提权弹窗、`lock_region` 真实写入系统时区/区域；
- 多显示器/任务栏位置/DPI 托盘弹窗定位；开机自启；
- 安装包升级/卸载回归、自动更新全流程。

## 七、覆盖上游 tests 的关键场景

| 上游 tests | 本仓库对应 |
| --- | --- |
| test_multi_account | `accounts::*`、`desktop::*`、`checks::*` |
| test_open_safe | `diagnostics::*safe*` |
| test_snapshot_safety / transfer | `export::*`、`keep::*` |
| test_webrtc_rules | `rules::*`、`stun::*` |
| test_proxy_diagnose | `diagnostics::*probe*` |
| test_set_client | `appconfig::*`、`guard::client_alive_*` |
| test_cli_info | `diagnostics::*cli*` |
| test_windows_rules_static / update_static | `rules::*`、`update`（实机待验） |
