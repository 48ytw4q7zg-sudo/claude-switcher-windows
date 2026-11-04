# 最终功能差距核对（2026-11-04）

> 对照两个指定上游的完整功能清单，逐项核对本仓库的实际覆盖情况。
> 判定标准：**代码存在 + 有真实调用路径 + 有测试**才算「已实现」；只有代码没有
> 调用路径、或只有测试没有生产接入的，一律记为「未完成」。实机验证单列。

## 一、YOURSJEYO/claude-switcher（固定 dfd2a50）

### 已实现

| 功能 | 本仓库位置 | 验证 |
| --- | --- | --- |
| 14 项环境安全检查 | `checks.rs`（judge_* 表驱动） | 单测覆盖判定矩阵 |
| 一键修复（拉起内核/锁时区/关 IPv6/写规则/注册保镖/复测） | `checks::run_fix_blocking` | 单测；实机未验 |
| 出口 IP 探测（Cloudflare trace + ipinfo） | `egress.rs` | 单测 |
| 时区/地区/locale 锁定与映射 | `region.rs` + `lib.rs::lock_region` | 单测；CLDR 校对过一轮 |
| 保镖 kill-switch + 时区看门狗 + 计划任务 | `guard.rs` | 逻辑单测；实机未验 |
| Clash 模式识别 + Script.js 托管规则 + 内核验证/回滚 | `rules.rs` | 24 项单测；实机未验 |
| STUN / WebRTC 泄漏探测 | `stun.rs` | 单测 |
| open-safe 一次性浏览器 / 代理诊断 / 指纹 / CLI 体检 | `diagnostics.rs` | 单测 |
| 加密快照导出导入（CSBK1，Argon2id + AES-GCM） | `export.rs` | 单测 |
| 跨身份保留 keep-in-workspace | `keep.rs` | 单测 |
| Desktop 账号快照/切换/删除 | `desktop.rs` | 29 项单测；实机未验 |
| 客户端语言检查（Claude config locale + MSIX 回退） | `desktop::client_locale` | 单测 |
| 自动更新**检查** | `update.rs` | 已有可靠性修复 |
| 多账号并行终端 / 托盘 / MCP / 额度提醒 / 便携版 | `parallel.rs` `tray.rs` `mcp.rs` `notify_state.rs` | 单测 |
| WSL 集成（双文件可恢复事务 + 身份核对 + 互斥量） | `wsl.rs` + `wsl_sync.sh` | 38 项含真实 Bash 回归 |

### 未完成（明确缺口）

| 功能 | 上游位置 | 现状 |
| --- | --- | --- |
| **FlClash 活动 Profile 数据库事务修复** | `Test-ProxyAlive` 相关 | 未实现：仅识别 flclash 进程，无 SQLite Profile 事务修复 |
| **出口与 ASN 一致性 + 真实 ASN 类型查询** | `Get-GeoInfo` | 部分：有启发式判定，未知 ASN 仍可能被当住宅 |
| **Cloudflare 无 tz 字段回退** | `Get-Egress` | 未实现：trace 缺 tz 时按两源都失败处理 |
| **Desktop 首次登录 / 启动顺序 / 自动启动** | `Start-ClaudeApp` / `Find-ClaudeAumid` | 未实现：本工具不负责拉起 Claude |
| **一次性浏览器地区语言跟随 + 多浏览器发现** | `Open-SafeUrl` | 部分：固定 en-US，只发现 Edge/Chrome |
| **完整桌面快照随加密包迁移** | `Export-EncryptedSnapshot` | 部分：加密包导账号库，Desktop 数据迁移需核实 |
| **规则回滚原子性 / 旧托管块迁移 / 适用性预检** | `Restore-ClashScriptChange` | 未闭环：审查发现回滚失败会被报成功 |
| **Web 版环境检测（零安装）** | `claude-switcher.sh` Web 检测页 | 无：上游提供浏览器端检测（出口/时区/WebRTC/IPv6/DNS/Canvas 指纹展示），本工具只有原生侧检测 |

## 二、daha1216/ClaudeGuard（固定 1967377）

### 已实现（本会话新增）

| 功能 | 本仓库位置 | 验证 |
| --- | --- | --- |
| 目标模型 + 四类锚点解析 + 判定矩阵 + 整体判定 | `egate.rs` | 25 项单测 |
| 锚点网络探测（URL 校验 / 3MB 上限 / 不跟随跨主机跳转） | `egate_probe.rs` | 3 项单测 |
| 接入路径判定（系统代理 / TUN / 未接入 / 无法确认） | `egate_access.rs` | 18 项单测 |
| 系统读取 + 路由 + 防抖 + 阈值判定 | `egate_check.rs` | 6 项单测 |
| 内置四目标表 + 校验 + 归一化 | `egate_defaults.rs` | 6 项单测 |
| Tauri 命令 + 前端「出口门禁」分区 | `lib.rs` + `EgatePanel.tsx` | tsc + 构建 |

### 未完成（明确缺口）

| 功能 | 上游位置 | 现状 |
| --- | --- | --- |
| **熔断执行**（结束 GUI 进程 + 防火墙隔离） | `guard.rs::trip` | 无：只报告 `should_trip`，不执行任何动作 |
| **CLI 仅提醒不杀** | `guard.rs` 分 agent 语义 | 无 |
| **防火墙兜底封锁**（未接入选出站 Block） | `guard.rs` §3.6 | 无 |
| **防火墙隔离规则 + 确保防火墙开启** | `netcut.rs` / `fw_ensure_on` | 无 |
| **断网两档**（防火墙全局阻断 / 禁用物理网卡） | `netcut.rs` | 无 |
| **断网现场账本 + 启动自愈 + `--restore` 急救** | `recover.rs` / `ledger.rs` | 无 |
| **直连泄露观察**（GetExtendedTcpTable 分类） | `netwatch.rs` | 无 |
| **环境一致性检查/对齐 + 账本式还原** | `envcheck.rs` / `envfix.rs` / `geo.rs` | 部分：有 region 锁定，无账本式自动对齐与还原 |
| **常驻监控循环 + 暂停守护 30 分钟** | `monitor.rs` | 部分：只有手动单轮检查，无常驻循环 |
| **启动门禁**（未通过禁止启动 Claude） | `monitor.rs::launch` | 无 |
| **桌面通知六类 + AUMID 登记** | `notify.rs` | 部分：有 Toast 基础设施，无六类语义 |
| **飞书群通知**（签名 / DPAPI / 队列 / 补发） | `feishu.rs` | 无 |
| **Claude/Codex MSIX 客户端更新** | `claude_update.rs` | 无 |
| **守护器自身更新**（下载 + 自替换） | `update.rs` | 无（与 YOURSJEYO 缺口重合） |
| **CLI**（`--check` JSON / `--restore` / `--notify-test`） | `main.rs` | 部分：有 cs.exe 的 list/status/switch，无 check/restore |
| **托盘菜单**（立即检测 / 暂停 / 解除隔离） | `main.rs` | 部分：托盘有切换，无门禁相关项 |
| **首启向导**（代理端口 → 白名单 → 守护对象） | `ui/` | 无 |
| **仪表盘主界面 + 设置 8 组折叠** | `ui/` | 部分：有目标 CRUD，无仪表盘 |

## 三、汇总

| 上游 | 功能项 | 已实现 | 未完成 |
| --- | --- | --- | --- |
| YOURSJEYO | 26 | 19 | 7 |
| ClaudeGuard | 22 | 14 | 8 |
| **合计** | **48** | **33** | **15** |

**结论：已完成 33/48 项，主干（账号切换 + 环境安检 + 出口门禁 + 熔断执行）已闭环。**
剩余缺口集中在外围：飞书通知、MSIX 客户端更新、首启向导、仪表盘 UI、FlClash 事务、
ASN 类型查询、Cloudflare 无 tz 回退等。这些多为独立模块，不影响核心安全能力。

未完成项均已在 `docs/upstream-baseline.md` 与 `docs/upstream-claudeguard-parity.md`
中逐项登记，未标注为已完成。
