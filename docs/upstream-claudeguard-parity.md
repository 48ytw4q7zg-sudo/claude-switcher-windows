# ClaudeGuard 融合功能矩阵（daha1216/ClaudeGuard）

> 固定上游：`daha1216/ClaudeGuard@1967377bec393bcba82199f038550d6fa5f677ec`（master，MIT，
> pushed 2026-11-01）。本地研究副本位于 `.tmp-tool-results/upstream-claudeguard/repo`
> （独立空目录克隆，只读行为基准，不执行其中脚本）。
> 行为基准：`docs/SPEC-v3.md` + `docs/CONTRACT-v3.10.md` + README（v3.12.5）。
> 记录日期：2026-11-04。

ClaudeGuard 是 AI 桌面应用的「网络出口门禁」：按每个监控目标自己的域名校验此刻出口
IP/地区是否在白名单，全部通过才允许启动，任一启用目标不符合就熔断（杀进程 + 防火墙
隔离 + 可选断网），恢复后自动解除。Windows 完整支持。

## 与本项目既有能力的关系

融合原则：**相同能力复用既有模块，不并行实现两套互相竞争的后台任务**；新增能力按
单一职责进新模块 + Tauri 命令 + 简体中文界面。本项目现有 guard/kill-switch、14 项安检、
region 锁定继续保留（它们是「主动锁环境」，ClaudeGuard 是「持续验出口」，语义互补）。

## 逐入口功能矩阵

| # | ClaudeGuard 能力（入口） | 上游位置 | 本项目现状 | 处置 |
| --- | --- | --- | --- | --- |
| 1 | 监控目标模型（Target：名称/锚点/期望 IP+地区/开关，增删改/恢复默认，内置 local/claude/codex/antigravity） | `model.rs` `targets.rs` | **已完成模型层** `egate.rs`（25 测试）；CRUD/内置默认表与配置持久化待接 | 部分完成 |
| 2 | 锚点四类 + auto 探测（Cloudflare trace / JSON IP / Gemini 地区标记 / 仅可达性；alpha-3→alpha-2 归一；解析失败=Unverified） | `anchors.rs` | **已完成** `egate.rs`（解析/归一）+ `egate_probe.rs`（网络，URL 校验/3MB 上限/不跟随跨主机跳转） | 已完成 |
| 3 | 判定矩阵（Pass/Fail/Unverified/Disabled；期望为空宁可错杀；信息缺失不熔断；整体判定） | `policy.rs` | **已完成** `egate::evaluate` + `egate::overall`（表测） | 已完成 |
| 4 | 接入路径检查（系统代理/TUN/Uncovered；ProxyOverride 绕过清单按 AI 域名判定；未接入不直连探测） | `access.rs` | **已完成判定层** `egate_access.rs`（18 测试）+ `egate_check.rs`（注册表读取/TUN 枚举/路由/防抖） | 已完成 |
| 5 | 防火墙兜底封锁（未接入→每守护对象出站 Block；fw_ensure_on 只开不关；手动封锁/解除；intent 差分） | `guard.rs` `netcut.rs` §3.6 | **部分完成**：`egate_trip` 已做按 exe 出/入站隔离 + 回查核验 + 解除；「未接入选出站 Block 的意图差分」未做 | 部分完成 |
| 6 | 直连泄露观察（GetExtendedTcpTable 筛守护对象连接，Proxy/Local/Public 分类；默认只告警） | `netwatch.rs` | **已完成** `egate_netwatch`（9 项单测）+ 命令 + 界面按钮 | 已完成 |
| 7 | 环境一致性检查/对齐（tz/locale vs 出口；离线地点表；账本式自动对齐与一键还原） | `envcheck.rs` `envfix.rs` `geo.rs` | 部分（region.rs 锁定时区/区域，checks 查一致性；无账本还原） | **扩展** region：补账本式对齐/还原 |
| 8 | 监控循环 + 防抖（fail_streak、trip_threshold、预警一次、暂停守护 30 分钟、间隔可调） | `monitor.rs` | **已完成** `egate_monitor`（常驻线程 / 暂停 30 分钟 / 熔断门控纯函数 / 间隔 5–3600 收敛）；9 项单测含「暂停绝不超过熔断」 | 已完成 |
| 9 | 熔断动作（杀 GUI 进程 + CLI 仅提醒 + 防火墙隔离 + 断网两档 off/firewall/nics；TripInfo） | `guard.rs` `netcut.rs` | **部分完成**：`egate_trip` 已实现杀 GUI + 防火墙隔离 + 回查；CLI 只提醒语义一致；**断网两档未做** | 部分完成 |
| 10 | 断网现场持久化与自愈（netcut.json 账本、启动恢复、规则去重、--restore 急救） | `netcut.rs` `recover.rs` | **已完成** `egate_netcut`（账本 netcut.json / 启动 heal / 两档 / 先恢复网卡后删规则）；`--restore` CLI 急救未接 | 基本完成 |
| 11 | Claude 进程清理引擎（桌面/CLI 二分、一键全清/熔断清/退出清残留、残留监视线程） | `guard.rs` §5 | 部分（processes.rs 精确检测/结束） | **扩展** processes：补 sweep 三态 |
| 12 | 桌面通知六类 + AUMID 幂等登记（trip/recover/launch_blocked/warning/client_update/self_update） | `notify.rs` | **已完成六类语义** `egate_notify`（4 项文案测试 + 监控/启动/测试命令接线）；AUMID 由 tauri-plugin 以 bundle id 承担 | 基本完成 |
| 13 | 飞书群通知（签名校验、DPAPI 加密凭据、持久队列、失败补发） | `feishu.rs` | 无 | **新增** `feishu.rs` |
| 14 | Claude/Codex 客户端更新（只走官方 MSIX 源、签名校验、原位升级、注册版本核验） | `claude_update.rs` `claude_package.ps1` | 无 | **新增** `msix_update.rs` |
| 15 | 自身更新（GitHub Releases 静默周期检查 + 下载自替换 + 同版本只提醒一次） | `update.rs` | 部分（update.rs 只有检查；下载/安装/回滚缺——与 YOURSJEYO 缺口重合） | **扩展** update.rs |
| 16 | 启动门禁（全部启用目标 Pass 才允许启动 Claude；失败阻止 + 通知 + 记录） | `monitor.rs` launch | **已完成** `egate_launch`（同步判定 + AUMID/exe 双路径启动 + 暂停放行）；通知未接 | 基本完成 |
| 17 | CLI（--check JSON/退出码、--restore、--settings、--tray、--install/--uninstall、--notify-test、状态查询） | `main.rs` | **部分完成**：`--egate-check`（JSON+0/2）/`--egate-restore` 已加；--settings/--install 等未接 | 部分完成 |
| 18 | 托盘菜单（显示/立即检测/暂停守护/解除隔离恢复网络/打开数据目录/退出） | `main.rs` | 部分（tray.rs 一键切换等） | **扩展** tray |
| 19 | 首启向导（代理端口 → 白名单 → 守护对象/自启 三步） | UI + `config.rs` | 未实现；当前由「出口门禁」分区手动配目标 | 待实现 |
| 20 | 设置 8 组折叠（目标 CRUD、熔断与清理、通知、客户端更新、自启等）+ 主界面仪表盘（状态环/目标瓦片/保护卡/CTA） | `ui/` | **目标 CRUD 与检查界面已完成**（`EgatePanel`）；仪表盘与设置分组待接 | 部分完成 |
| 21 | 单实例 / 日志 1MB 裁剪 / 数据目录 %APPDATA% 独立 | `main.rs` `guard.rs` | 已有等价（single-instance、日志滚动、便携数据目录） | 复用 |
| 22 | 配置版本化迁移（v2→v3→v4、损坏备份 config.json.bak-{ts}、升级前备份） | `config.rs` | 部分（appconfig.json 严格读取 + 锁；无版本迁移） | **扩展** appconfig |

## 非目标（上游 SPEC §13，融合时同样不做）

- 代理控制器/端口联动（不读 mihomo API、不改用户分流脚本）——本项目的 Clash 规则托管是
  既有 YOURSJEYO 功能，保持现状，不因 ClaudeGuard 扩张。
- 域名级拦截（熔断按进程 + 网络档位）。
- 云同步/账号体系；不自动启动 Claude。

## 实施顺序（与 YOURSJEYO 剩余缺口合并排批）

1. **B3a 核心门禁**：#1–#3 目标/探测/判定 + #4 接入路径判定已完成（50 项测试）；目标 CRUD/配置持久化、#8 监控循环与 #9 熔断编排待接。
2. **B3b 熔断执行**：#5 防火墙、#10 断网账本/自愈、#11 进程清理、#16 启动门禁。
3. **B3c 通知与外围**：#12 六类通知、#13 飞书、#17 CLI、#18 托盘、#19 向导、#20 UI 分区。
4. **B3d 客户端更新**：#14 MSIX 更新（与 YOURSJEYO 自动更新回滚 #15 一并闭环）。

每个能力先写失败路径测试再实现；防火墙/网卡/注册表写入均为真实系统修改，
自动化只到合成注入边界，实机验收单列。

## 验证边界（如实记录）

- 本矩阵来自固定 commit 的 README + SPEC-v3 + CONTRACT-v3.10 与源码文件清单；
  逐文件行级核验在各实施批次内随修复补做，不以本表替代。
- 合成测试不覆盖真实防火墙、网卡、MSIX 源、飞书连通与 Toast 投递；这些单列实机项。
- 上游 macOS 移植预览不在 Windows 融合范围。
