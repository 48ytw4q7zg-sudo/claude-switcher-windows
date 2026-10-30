# QA 记录 · v0.5.0（第二轮真实缺陷 J-1~J-8 + 新功能 F-1~F-7）

## 背景

v0.4.0 完成缺陷/竞态收口与命令行入口。v0.5.0 一次性交付第二轮审查的
**J-1 ~ J-8 真实缺陷**与 **F-1 ~ F-7 新功能**，仅面向 Windows。
基线 v0.4.0（HEAD=f1800c5）已由 owner 独立复跑确认全绿：fmt / clippy
(-D warnings) / 250 测试 / tsc / tauri build 均通过。

两项按实机事实处理（见下「F-4」「F-6」）：本机无 Process Monitor，
F-4 保留待调研；WSL 仅 docker-desktop 发行版，F-6 实验、默认关闭。

## 缺陷修复（J）

### J-1 命令行只做一半（cs.rs / cli.rs / store.rs / 打包配置）

- 新增 `src/bin/cs.rs` 控制台子系统程序（`[[bin]] name="cs"`，**不设**
  windows_subsystem，默认控制台），与主程序共用库，同步执行并
  `std::process::exit` 返回真实退出码，支持 `--list/--status/--switch`。
- `attach_parent_console` 增强：AttachConsole 后对 STD_OUTPUT/STD_ERROR，
  仅当 `GetStdHandle` 为空或 `INVALID_HANDLE_VALUE` 时才
  `CreateFileW("CONOUT$") + SetStdHandle`；已被文件/管道重定向的句柄保留。
- `with_store` 增加 fs4 跨进程文件锁（`app_data_dir/store.lock`，
  `fs4::FileExt::lock` 排他），覆盖 load→f→save，创建失败返回 Err。
- 分发：`tauri.conf.json` 加 `bundle.externalBin=["binaries/cs"]`，
  MSI/NSIS 安装目录均落 `cs.exe`；便携 zip 与 CI 同步打包 cs.exe。

### J-2 重入保护 + Clash 顺序（store.rs / lib.rs）

- 新增 thread_local `IN_STORE_TX` 重入检测 + Drop guard，嵌套调用
  `with_store` 立即返回 Err「with_store 不可嵌套调用」而非死锁。
- Clash 节点切换移到材料应用（`apply_account_material` +
  `apply_profile_env_to_settings`）成功之后、activate 之前；材料已落盘
  但切节点失败时转 warning（clash_result=None），不返回 Err。

### J-3 并行回写身份校验（parallel.rs / lib.rs / tray.rs）

- 回写前纯本地解析凭据 blob 的 accountUuid（复用 `usage::extract_meta`，
  不发网络），与 profile 的 uuid 比对：两者都能解析且不一致 → 拒绝回写，
  提示「该并行目录已换成别的账号，可收养为新账号」；一致或无法解析 →
  best-effort 回写（值不同才更新 keychain 与 updated_at）。
- 新增同步点：全局切换 preflight 后、托盘 refresh 开头扫描
  `accounts/*/.credentials.json`，仅处理 mtime 晚于 updated_at 的文件。

### J-4 reconcile 三细节（reconcile.rs）

- ① 邮箱回退只对 `meta.account_uuid` 为 None 的老账号生效（内嵌 json 带
  uuid 但 store 级 uuid 为空的老账号仍可认亲）；其余 uuid 不匹配走
  Unknown 收养。
- ② live `settings_json` 为 None 时不覆盖 profile.settings_json。
- ③ 能解析 `claudeAiOauth.expiresAt`（毫秒）且 live 比 stored 更旧时，
  不覆盖 keychain。

### J-5 MCP 乐观并发（mcp.rs / fsx.rs）

- `modify_json_optimistic` 先 file_state(stat) 再读；`rename_with_retry`
  失败分支 `remove_file(from)` 清理临时文件（from 全是临时文件，绝不删
  目标）；删除本地 claude_running 枚举，统一复用
  `processes::claude_code_running()`（区分桌面版）。

### J-6 通知 key 边界（notify_state.rs）

- 放弃取整相等，改为 `same_reset_period`：能 parse 则两次重置时间差
  abs ≤ `RESET_PERIOD_TOLERANCE_SECS`(600) 视为同一周期，无法解析时
  字符串相等回退；删除 `round_to_five_minutes`。

### J-7 ACL 白名单（platform/windows.rs）

- 新增 `is_app_owned_data_dir`：仅目录名 `.claude-switcher` 或
  `ClaudeSwitcher` 才做 `icacls /inheritance:r`；非本工具目录一律跳过；
  原 `is_protected_from_hardening` 黑名单保留作第二道保险。

### J-8 逐行审查（usage.rs / ReconcileSettings.tsx / lib.rs）

- 通读 usage-cache 全链路（OAuth token 指纹、45s 缓存、snapshot 去重/
  窗口聚合、is_fresh/load/save/record/pick_recommended/quota_reminder）：
  逻辑闭合、token 指纹防串号，无硬缺陷。
- ReconcileSettings 为 appconfig auto_adopt 开关，读写正确。
- 单实例回调（Switch→forward_switch，其余 show_main_window）与
  generate_handler 注册完整，无缺陷。

## 新功能（F）

### F-1 目录绑定 + cs run + PATH（dirbinding.rs / userpath.rs / cli.rs）

- 标记文件 `.claude-switcher-account`（内容账号名），`find_account_marker`
  逐级向上查找首个命中；`cs run` 复用
  `parallel::ensure_parallel_account_dir`，设 `CLAUDE_CONFIG_DIR` 后
  `cmd /c claude <extra>` 启动并透传退出码。
- 用户 PATH 写 `HKCU\Environment`，以 `REG_EXPAND_SZ` 写回（get_raw_value
  按字面读、保留 %USERPROFILE% 等变量），`SendMessageTimeoutW`
  广播 WM_SETTINGCHANGE；提供移除撤销，幂等。

### F-2 开始菜单快捷方式（naming.rs / shortcuts.rs）

- 新增 mslnk 依赖；在
  `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Claude Switcher\`
  每账号生成 .lnk，参数 `--switch "<名称>"`。
- 账号名合法化：`sanitize_file_name` 去非法字符/尾点空格、避开 27 个
  保留设备名（CON/NUL 等）；重命名/删除后 best-effort 同步，支持全部清理。

### F-3 令牌状态列（token_status.rs / App.tsx）

- 纯本地、不发网络：读 expiresAt（毫秒）判定 有效 / 即将过期(≤10 分钟) /
  已过期 / 未知；前端徽标区分两种过期文案——有刷新令牌「使用时自动续期」，
  无刷新令牌「需重新登录」。

### F-5 第三方供应商（provider.rs / store.rs）

- 新增 ProviderProfile（base_url、加密 auth_token、模型 env），Store 记录
  `managed_env_keys` 与 `current_provider_id`。
- 切换只改受管 env 键，先删旧键再写新键避免残留；切回 OAuth 清键；连通
  测试 5 秒超时、错误脱敏不回显令牌。界面说明 ANTHROPIC_AUTH_TOKEN 优先级。

### F-6 WSL 集成（wsl.rs / appconfig.rs）

- 实验功能，默认关闭（`appconfig.wsl_integration_enabled`，serde default）。
- `parse_wsl_distros` 剥 BOM 后 UTF-16LE 解码；仅用户显式选择发行版时
  写入；固定 bash 脚本 mkdir + umask 077 + chmod 600，blob 经 stdin 管道
  不进 argv。界面明确「目标 0600 权限无法从 Windows 侧保证」。

### F-7 诊断/多语言/完整便携/更新

- 诊断包：`build_diagnostic_bundle` 生成脱敏 zip（敏感键值替换 ***，
  邮箱保留首字符+域名），含 diagnostic-info.json 与日志。
- 多语言：新增 `src/i18n.ts`（zh/en 词典、跟随系统语言、可切换），新面板
  全部走 `t()`；旧界面按增量迁移（见下）。
- 完整便携：`fixed_webview2_dir()` 检测便携根 `webview2\` 目录，run() 设
  `WEBVIEW2_BROWSER_EXECUTABLE_FOLDER`；固定运行时组装见
  `scripts/build-full-portable.ps1`。
- 自动更新：维持无签名只打开 Release 页的务实做法（update.rs 现状）。

## 验证结果

| 检查 | 结果 |
|---|---|
| `cargo fmt --check` | 通过 |
| `cargo clippy --all-targets -- -D warnings` | 零警告 |
| `cargo test --lib` | **288 passed / 0 failed / 0 ignored**（v0.4.0 为 250，新增 38） |
| `npx tsc --noEmit` | 通过 |
| `tauri build` | 由 CI（windows-latest）构建 MSI + NSIS，externalBin 含 cs.exe |

## CI 构建修复（externalBin 鸡生蛋）

首次 tag 触发的 Windows Build（run 41048632718）在「Stage cs external binary」
步骤失败，报错：

```
tauri build failed: resource path `binaries\cs-x86_64-pc-windows-msvc.exe` doesn't exist
```

根因：tauri-build 的 build.rs 在编译本 crate 任何目标（含 `--bin cs`）之前就
校验 sidecar 路径存在；干净检出时该文件还不存在，而 `cargo build --bin cs`
本身先触发 build.rs 即 panic，等构建完再 Copy 已来不及。

修复（workflow 该步骤）：先在目标路径落一个 0 字节占位文件让存在性校验通过
（tauri-utils 只查 `.exists()`、不校验是否有效 PE），再 `cargo build --bin cs`，
最后用真实 cs.exe 覆盖占位。本地已用 release 全流程验证：

- `cargo build --release --bin cs` 不再 panic，产出 cs.exe **4,349,952 字节**、
  有效 MZ PE；sidecar 与该文件字节一致、SHA256 相同
  （`199D3A6D5A63817DC7CB60D8580CDF78F1B9CB0E6FCC212BDB5E19933E2425B7`）。
- 实机运行：`cs --status` 退出 0（输出「当前没有全局账号」）；无参打印用法
  退出 2。

## 本轮测试中发现并修复的真实 bug

1. `usage::string_field` 把同级备选键误当逐层下钻路径，导致邮箱/uuid 回退
   永远 None；新增 `first_string_field` 做同级回退。
2. J-4① 邮箱回退条件过严（误用合并后的 uuid 判空）；改为按
   `meta.account_uuid.is_none()` 判空。
3. userpath 测试字节数误算（`%USERPROFILE%\bin` 实为 18 u16=36 字节）；
   ReentryGuard 未 derive Debug，测试改用 `if let Err` 而非 unwrap_err。

## 多语言增量迁移说明

i18n 框架与本轮新增面板（IntegrationPanel/ProviderPanel/WslPanel）及令牌
徽标已支持 zh/en 并跟随系统；应用原有的硬编码中文界面（安检/地区/保镖/
桌面版/备份等）尚未逐串替换，后续按模块继续接入 `t()`，词典集中在
`src/i18n.ts`。

## 仍无法实机验证项（如实标注）

当前环境无显示器、无登录态、无托盘，以下仅做单测/表驱动验证：

- 真实 Toast/AUMID、托盘菜单/单实例转交、并行终端 wt/cmd 真实拉起。
- 便携版解压运行、ClaudeSwitcherData 落盘、AttachConsole 附加输出。
- 完整便携版固定 WebView2（约 150MB）：本环境无固定运行时，未实机验证，
  需按 `scripts/build-full-portable.ps1` 下载组装。
- PATH 注册表写入/广播、开始菜单 .lnk、MCP 真实握手、UAC、安装包升级回归。
- 第三方供应商真实连通与切换、WSL 真实写入/0600 权限（本机仅 docker-desktop）。

## F-4 凭据锁（本轮不做）

本机未安装 Process Monitor。按踩坑20铁律禁止凭猜测实现。解锁条件与步骤：

1. 安装 Sysinternals Process Monitor（Procmon）。
2. 过滤操作含 `CreateFile`/路径匹配 `.credentials.json`、进程为 claude.exe /
   node.exe，捕获令牌刷新时刻的文件打开与锁（ShareMode/Disposition）。
3. 据真实锁文件行为再实现；抓不到则继续标「待实机调研」，代码不加猜测锁。
