# QA 测试与覆盖报告（v0.2.0 + 第二轮全量复核）

> 测试对象：`claude-switcher-windows`（Tauri 2 + Rust + React），融合
> VallierDev（CLI）与 YOURSJEYO（环境/桌面版）两个上游的全部功能。
> 报告日期：2026-10-27（v0.2.0 发布 + 第二轮逐行复核与缺陷修复）。

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

> 第一轮（v0.2.0 发布前）修复 8 项，第二轮（v0.2.0 全量逐行复核）修复下列项。
> 第二轮由三条独立只读审查 lane（账号快照链路 / 诊断网络前端链路 / 父会话环境安全链路）
> 交叉比对，并逐条回读源码证实后实施。

| # | 问题 | 根因 | 修复 |
| --- | --- | --- | --- |
| 1 | `set_client`/`set_webrtc_policy` 闭包 move 出捕获变量（E0507） | 闭包 move | 闭包内 `clone()` |
| 2 | 5 处 `blocking(|| f())` redundant_closure | clippy | 无参函数改传函数指针 |
| 3 | `run_fix_blocking` 直接返回 report，不满足 `blocking` 的 Result 约束 | 类型 | `blocking(|| Ok(report))` |
| 4 | `GuardTick` 未 derive `Serialize`，无法作为命令返回 | 缺 derive | 补 `serde::Serialize` |
| 5 | `dir_size` 未被生产代码使用（dead_code） | 未接线 | 切换后刷新 `size_bytes` |
| 6 | keep 模块未接线（整组 dead_code） | 未接线 | 接入 CLI/Desktop 切换的 stage/merge |
| 7 | `current_home_location_geo` 未使用 | 未接线 | `lock_region` 应用后回读验证 |
| 8 | checks.rs 最终格式不符 rustfmt | 格式 | `cargo fmt` |
| 9 | **PowerShell `Write-Error` 被当成成功**（P0，已实测复现） | `run_ps` 只看退出码，而 PS 非终止错误不改退出码 | 脚本头加 `$ErrorActionPreference='Stop'`；新增回归测试实跑真实 `run_ps` |
| 10 | **规则验证恒失败 → 置顶规则整体不可用**（P0） | 内核 `GET /rules` 返回 `{"rules":[...]}`，`verify_pinned_rules` 直接 `as_array()` 对象 → 恒 Err，写完 Script.js 必回滚 | 先取 `rules.get("rules")` 再回退裸数组；新增 envelope 形态回归测试 |
| 11 | **`proxy_group` 全工程无写入路径 → 规则功能默认必失败**（P0） | `appconfig.proxy_group` 只有 3 处读、0 处写，默认空串直接 Err | 未配置时回落 `store::DEFAULT_CLASH_GROUP`；新增 `set_proxy_group` 命令 + 前端输入框 + `get_appconfig` 回读 |
| 12 | **Clash 重启是空操作**（P0） | `kill(&["clash-verge"])` 与自家启动的 `Clash Verge.exe`（ProcessName `Clash Verge`）不匹配，内核 `verge-mihomo` 也没杀 → Script.js 改了不重载 | 进程名改 `["Clash Verge","clash-verge","verge-mihomo"]`（GUI+内核），同步修 `reenable_tun_mode` 同一错误 |
| 13 | **Desktop 切换静默回退活账号数据**（P0，数据丢失） | 切 Desktop 只把活目录拷进一次性 staging，从不回写当前账号快照；上游有 `Save-Account $cur` | `Store` 新增 `current_desktop_profile_id`；切换前把活目录回存当前账号快照，capture 时置位，删除时清理；新增 2 个回归测试 |
| 14 | **跨机导入砖化整个账号库**（P0） | 导入只校验 JSON 形状，外机 `enc:v1:` 密文本机解不开 → 之后所有 `load_store()` 整体 Err | 落盘前统计密文占比，有外机密文即拒绝并说明；新增 2 个纯函数测试 |
| 15 | **keep 列表接受盘符相对路径逃出沙箱**（中） | `is_absolute_path` 只查 `chars[2]` 是分隔符，`C:foo`/`C:` 放行，而 `PathBuf::join` 遇 prefix 会整体替换 base | 新增 `has_drive_prefix` 拒绝 `^[A-Za-z]:`；表测补 2 例 |
| 16 | **非回环 Clash 控制器照样外发 secret**（中，安全） | `normalize_controller` 放行任意远程主机 | 改为 `Result` 返回，只接受回环（含 `127.*`/`localhost`/`::1`），拒绝 https 与远程；调用方记日志回落本机；表测补 6 个拒绝用例 |
| 17 | **diagnose-proxy 声明支持 socks5 但 reqwest 未启用**（中） | `Cargo.toml` 缺 `socks` feature，`Proxy::all` 对 socks scheme 直接 builder error | reqwest features 加 `"socks"` |
| 18 | **WireGuard 存活按 GUI 进程判定**（中） | `wireguard.exe` 开着≠隧道在线 | 改查 `WireGuardTunnel$*` 服务 Running；fail-closed（查询失败按离线） |
| 19 | **保镖注册后不启动**（中） | `install_guard` 只 Register，上游 install.ps1 是 Register+Start | 注册后 `start_task`；新增 `ensure_guard_running` 供一键修复幂等补启 |
| 20 | **Desktop 杀进程按名、判活按路径不一致**（中） | `kill(&["Claude"])` 杀不到 `AnthropicClaude\app.exe` 形态 → 15s 超时功能不可用 | 新增 `kill_desktop_processes` 按 `is_claude_desktop_exe` 同源 PID 列表 taskkill /T /F |
| 21 | **IPv6 出口时 STUN 误报泄漏**（低） | STUN 只解析 IPv4，拿 IPv6 出口比对必然不等 | 出口含 `:` 时跳过探测并输出明确 warn |
| 22 | **`usage.rs` 锁中毒 panic 连锁**（低） | 一处用 `.expect()`，同文件其他位置用 `into_inner()` | 统一中毒恢复 |
| 23 | **appconfig 损坏静默回默认**（低） | 无日志，用户以为配置还在 | 解析/读取失败记 `log_error` 并说明下次保存会覆盖 |
| 24 | **`cli_info` 对 PATH 上每个 claude 执行 `--version` 无超时**（低） | 挂起的 `claude.cmd` 会永久卡死体检命令与 spawn_blocking 线程 | 轮询 `try_wait` + 8s 超时后 kill，按无版本处理 |
| 25 | **open-safe 找不到用户级安装的浏览器**（低） | 只查 4 个系统级路径 | 覆盖 `LOCALAPPDATA` 下用户级 Edge/Chrome |
| 26 | **前端 appconfig 不回读，UI 与已保存值不符**（低） | 无读取命令，`webrtc`/`clientMode` 恒初值，用户一点就覆盖旧选择 | 新增 `get_appconfig` 命令；ClashModePanel/RegionPanel 初始化回读；ClashModePanel 加代理组输入 |
| 27 | **`guard_status`/`list_backups` 在主线程阻塞**（低） | 同步命令里跑 PowerShell / 串行读 30 个大 JSON | 改 `async` + `blocking()` 壳 |

## 四之二、已核实但**未**在第二轮改动的问题（如实记录）

| # | 问题 | 状态 |
| --- | --- | --- |
| a | 自动更新只有版本检查、无下载安装 | **有意取舍**：未签名场景下 `tauri-plugin-updater` 的签名密钥方案不现实；上游 Windows 版靠 SHA256SUMS + 手动 zip 替换。已在前端提供 Release 页跳转。若用户要求补齐需单独授权 |
| b | 上游 48 小时出口 IP 漂移历史（`iphist_count`，变化 ≥3 次亮 warn） | **功能缺口**：当前 `judge_ip_consistency` 只比上一次。需要新增 `iphistory.log` 维护与裁剪，属新功能而非缺陷修复 |
| c | `ensure_rules` 缺少写前 `/proxies` 预检（上游零改动中止） | 当前会先写 Script.js+备份+重启+40s 等待再回滚；体验差但最终状态正确 |
| d | Desktop/`session-backups` staging 目录只增不减 | 磁盘增长风险，需保留策略 |
| e | `merge_keep` dst 侧不查链接 | 上游 shell 同样不防，属对齐上游的既有弱点 |
| f | `list_desktop_profiles` 吞 store 错误成空列表 | 会诱导重复 capture |
| g | `credentials.rs` 读凭据不处理 BOM/UTF-16 | 概率低、后果确定（界面打不开） |
| h | 多个同步命令仍在主线程做 store 解密（`list_profiles` 等） | 卡顿风险，无数据损坏 |
| i | `update.rs` 硬编码 repo 名 | 若 org/repo 有误则检查永远失败 |

## 四之三、独立审查通道资格记录（不虚报）

| 通道 | 结果 |
| --- | --- |
| Codex（`codex exec`，模型 `gpt-6-astra`） | **失败**：服务端返回 `model_not_found`（该模型不支持当前 ChatGPT 账号）。未产出任何审查结论 |
| `claude -p --model claude-fable-5` | 运行成功但自报身份为 Kimi（Moonshot AI），与请求模型不符 → **不计入** Anthropic 旗舰审核 |
| `claude -p --model claude-fable-5-1`（按官方文档核实的最新旗舰，精确 ID `claude-fable-5-1`） | 运行成功，但 stream 中实际响应标识为 `kimi-k3.1-pro` → **存在路由替换，不计入** Anthropic 旗舰审核 |
| pi（`pic -p`） | **失败**：`pic --check` 报安装不完整（package version 不符 + bridge 过期），未运行 |
| 结论 | 本轮**未取得**符合 §D「OpenAI 或 Anthropic 当前最新旗舰」资格的独立审核。三条审查 lane 的产出按「参考证据」使用，全部 finding 均经父会话回读源码独立证实；跨 harness 签署状态记为**未满足**，需在修复完成后补一次合格审核 |

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
