# QA 记录 · v0.4.0（真实缺陷 / 竞态收口 + 命令行入口）

## 背景：第二轮审查针对真实缺陷与竞态

v0.3.x 完成了「功能大全」。v0.4.0 不加新功能，而是按 Sonnet 5.5 第二轮审查的
**H-1 ~ H-9** 逐项修复真实缺陷与并发竞态，并补齐命令行入口
（`--list` / `--status` / `--switch <名称>`）。环境安检 / 地区 / 保镖 / 规则 /
指纹那组保持不动。**P2-2 凭据锁本轮仍不做**，继续标「待实机调研」。

## 修复清单

### H-1 便携版数据隔离（paths.rs / platform/windows.rs / lib.rs）

- 新增 `paths::portable_data_dir()`：便携模式下数据根固定为 exe 旁的
  `ClaudeSwitcherData` 子目录（常量 `PORTABLE_DATA_SUBDIR`），不再把数据写进
  exe 目录本身。
- 便携模式 `WEBVIEW2_USER_DATA_FOLDER` 改指该子目录，且在 WebView2 创建前设置
  （时序要求）。
- 新增 `paths::probe_data_dir_writable()`：启动早期探测数据目录可写，解压到
  Program Files 等只读位置时，弹原生错误（`show_startup_error`）并退出，而非
  静默失败。
- 新增 `is_protected_from_hardening()`：exe 所在目录、用户 Downloads / Desktop
  命中时跳过 `icacls` 加固，避免断继承锁死用户数据。
- 新增 `usage_cache_path()` 等数据目录解析，随数据根一起收拢。

### H-2 用量缓存独立 + 账号库互斥（usage.rs / store.rs / lib.rs）

- 新增独立 `usage-cache.json`（`UsageCache` / `UsagePoint`，只含
  `five_hour_pct` / `seven_day_pct` / `at`，**不含任何密钥**）。托盘与后台
  线程只读这个 JSON，不再解密 / 重写账号库。
- 新增 `store::with_store`（进程内 `STORE_LOCK` 互斥）：所有账号库读—改—写
  统一走它，闭包返回 Ok 后原子保存，消除并发写互踩。
- 新增 `record_usage_from_snapshot`、`is_fresh`（60 分钟新鲜窗口
  `FRESH_MAX_MINUTES`）、`pick_recommended`（排除当前、仅选新鲜缓存点、取最低
  百分比）；`RecommendedAccount` 加 `minutes_ago`。
- 删除旧的 `pick_most_remaining` 与每次记录都解密重写整库的
  `record_current_usage_percent`。

### H-3 并行终端播种（parallel.rs）

- 新增 `seed_if_missing`：只在目标文件缺失时原子播种，返回 bool，避免覆盖已有
  内容。
- 新增 `sync_parallel_credentials_back`：切换后经 `with_store` 回写更新凭据，
  错误全吞、不阻断主流程。
- 新增 `is_dual_open`：禁止同一账号同时全局 + 并行双开（两处刷新同一令牌可能
  导致登录失效）。

### H-4 并行终端执行策略（parallel.rs）

- `parallel_powershell_args`：参数序固定为 `-NoExit -ExecutionPolicy Bypass
  -EncodedCommand`，保证受限执行策略下也能启动。
- 脚本结尾改用 `Get-Command claude -CommandType Application` 解析真实 claude
  应用，找不到则 return，再 `& $cmd.Source` 启动，不再硬编码路径。

### H-5 并行终端非阻塞启动（parallel.rs）

- 新增 `spawn_and_probe` / `launch_verdict`：`Stdio::null` + `spawn` 非阻塞，
  sleep 800ms 后 `try_wait` 探测存活，不加 `CREATE_NO_WINDOW`，避免误判启动
  失败。

### H-6 对账三边界（reconcile.rs / appconfig.rs）

- **不覆盖空凭据**：`write_live_into_profile` 仅在 live 凭据 `Some` 且非空白时
  才覆盖，否则沿用 profile 已存凭据，`has_keychain_credentials` 等字段不被误
  重置。
- **uuid / 邮箱回退**：`classify_live_identity` 先按 uuid（meta 与内嵌
  claude_json 两条来源）精确命中，未命中再按邮箱 `eq_ignore_ascii_case`
  回退（trim 处理）。
- **收养开关**：`reconcile_live_into_store` 接收 `auto_adopt_enabled`；关闭时
  Unknown 账号只提示、不收养、不改 current。AppConfig 新增
  `auto_adopt_enabled`（默认开启）。

### H-7 MCP 管理（mcp.rs）

- `project_mcp_path` 去掉 `current_dir()` 回退，缺显式项目目录直接报错。
- 新增 `resolves_to_cmd_shim`（读真实 PATH / PATHEXT，`.cmd` / `.bat` 才包装
  `cmd /c`），替代硬编码命令表。
- 新增 `modify_json_optimistic`：写前记录 mtime/size，rename 前重 stat，外部
  有改动则重读合并，最多 3 次，冲突绝不覆盖。
- 新增 `claude_running`（sysinfo 精确匹配 `claude`，不误伤 `claudia`）与
  `mcp_warnings`（shell 特殊字符、远程 http 明文令牌）；env 值不进日志。

### H-8 通知双窗口去重（notify_state.rs）

- 新增 `round_to_five_minutes`（`div_euclid(300)` 取整）与 `reset_key_of`，
  收敛秒级抖动。
- 5 小时 / 7 天两个窗口独立 reset_key 与 notified levels，旧状态文件 serde
  default 向后兼容。
- uuid 缺失或轻量读取失败时直接跳过，**绝不回退固定 "current" 键**，避免错号
  误通知。

### H-9 托盘轻量读取（tray.rs / store.rs）

- 新增 `store::read_lightweight` / `LightProfile`：只取 id / name /
  account_uuid / email，不解密，托盘 rebuild 不再触发整库解密。
- `build_tray_menu` 改走轻量读取，失败只记日志、不 panic；新增纯函数
  `account_menu_rows`。
- `refresh_tray_status` 拿到快照后 best-effort 落用量缓存，60s 后台线程已无
  任何 load / save_store。

### 命令行入口（cli.rs / lib.rs）

- 新增 `cli.rs`：`CliCommand` 枚举 + `parse`；只读子命令 list / status 走
  `run_readonly`，`--switch` 唯一实例走 `run_switch_first_instance`，已有实例
  时经单实例插件 `forward_switch` 转交给运行实例，避免双进程并发写。
- GUI 子系统默认无控制台，命中 CLI 时先 `AttachConsole(ATTACH_PARENT_PROCESS)`
  再输出，最后 `process::exit`。

## 验证结果（本地真实执行）

| 检查 | 结果 |
|---|---|
| `cargo fmt --check` | 通过，exit 0 |
| `cargo clippy --all-targets -- -D warnings` | 零警告，exit 0 |
| `cargo test --lib` | **250 passed / 0 failed / 0 ignored**（v0.3.1 为 208，新增 42） |
| `npx tsc --noEmit` | 通过，exit 0 |
| `npm run tauri build` | 成功，出 MSI + NSIS |

### 各模块新增测试分布

- reconcile.rs：16 个（新增 8）；mcp.rs：20 个（新增 13）。
- usage / notify_state / tray：模块 22 个（新增 10）。
- cli.rs：5 个（全新）；paths.rs H-1 相关 3 个（含修复后的稳定错误路径）。
- 其余为保留 / 更新的既有测试。

## 仍无法实机验证项（如实标注）

当前环境无显示器、无登录态，以下只做了单测 / 表驱动验证，未在真实系统端到端跑：

- 真实 Toast / AUMID 弹出与 5h / 7d 标题区分、托盘右键菜单实际渲染（含子菜单）。
- 并行终端 wt / cmd 真实拉起、`cmd /c` 包装后真实 MCP stdio 握手、npx 启动
  真实 server。
- 便携版解压运行、`ClaudeSwitcherData` 真实落盘、AttachConsole 附加输出。
- 真实 claude.exe 进程检测、自动更新全流程、UAC、安装包升级 / 卸载回归。
- 老账号 uuid 为空但邮箱命中的真实识别路径、自动收养关闭时上层 UI 提示。
- 并发冲突测试用单进程内文件改写模拟，真实多进程同时写 `~/.claude.json` 的
  交错场景未实机验证。

## P2-2 凭据锁

仍待 Process Monitor 实机抓取 claude.exe / node.exe 刷新令牌时的锁文件行为，
本轮不凭猜测实现，AGENTS.md 继续保留「待实机调研」。
