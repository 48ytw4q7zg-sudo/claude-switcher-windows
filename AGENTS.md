# AGENTS.md — Claude Switcher Windows 维护交接

给后续 AI 助手 / 维护者的工程说明。**先读本文再动手。**

## 这是什么

Windows 版 Claude 账号切换器（Tauri 2 + Rust + React），**同时管理
Claude Code CLI 与 Claude Desktop 桌面版**。

融合两个上游（基线 commit 与功能对等矩阵见 [`docs/upstream-baseline.md`](docs/upstream-baseline.md)）：
- **VallierDev/claude-switcher**：macOS 桌面应用（同为 Tauri 2 + Rust + React，非 Swift），CLI 账号切换；
- **YOURSJEYO/claude-switcher**：环境安全 + 桌面版（bash/PowerShell/Swift）。

> **决定反转**：旧文档曾写「YOURSJEYO 已明确不移植」。项目 owner 已明确推翻，
> 要求把 YOURSJEYO 全部功能一模一样迁移并融合，**不再有「不移植」的说法**。
> 上游 PowerShell/bash/Swift 仅作逐行行为基准，主交付是 Tauri 应用。

## 构建与验证命令

```powershell
npm ci
$env:Path = "$env:USERPROFILE\.cargo\bin;C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64;$env:Path"
cd src-tauri
cargo fmt --check
cargo clippy --all-targets -- -D warnings   # 必须零警告
cargo test --lib                            # 必须全绿
cd ..
npx tsc --noEmit                            # 前端类型
npm run tauri build                        # 出 MSI + NSIS
```

**MSVC bin 路径随机器版本号变化**，用通配探测：
`Get-ChildItem "C:\Program Files*\Microsoft Visual Studio\*\*\VC\Tools\MSVC" -Directory | Sort Name -Desc | Select -First 1`

`rust-version = "1.88"`：`slice::as_chunks` 等 API 需要 1.88+。

## 架构约定

### cfg 收拢（重要）

**所有平台差异必须收拢在 `platform/` 模块**，业务代码不写 `#[cfg(windows)]`。
本项目只面向 Windows（`platform/mod.rs` 对非 Windows 目标 `compile_error!`），
macOS/Linux 适配代码已按产品决定移除：

```
src-tauri/src/
├── platform/{windows,mod}.rs   # Windows 平台适配（唯一允许写 cfg 的地方）
├── paths.rs        # 路径解析 + 目录保障（CLAUDE_CONFIG_DIR 跟随）
├── credentials.rs  # 凭据读写（Windows 凭据文件）
├── store.rs        # 账号快照 + AES-GCM 加密（含 DesktopProfile / KeyBackend trait）
├── accounts.rs     # 账号材料事务写入 + settings env 注入
├── reconcile.rs    # 切换前对账 + 自动收养（Current/Other/Unknown）
├── parallel.rs     # 按终端并行多账号（独立 CLAUDE_CONFIG_DIR）
├── mcp.rs          # MCP 服务器管理（stdio cmd /c 包装）
├── notify_state.rs # 额度阈值通知状态（每周期每档一次）
├── isolation.rs    # 按 profile 接管/激活本地状态（CLI）
├── desktop.rs      # Claude Desktop 快照/捕获/切换/删除（含备份回滚）
├── appconfig.rs    # 全局配置 appconfig.json（country/tz/locale/proxy_mode/webrtc/quota）
├── egress.rs       # 出口 IP 探测（Cloudflare/ipinfo）+ 住宅/机房 ASN
├── region.rs       # 国家→时区/locale/GeoID，IANA→Windows 时区
├── stun.rs         # UDP STUN 探针（WebRTC 泄漏判定）
├── checks.rs       # 14 项安全检查 + 静默总检 + 一键修复
├── guard.rs        # 保镖 kill-switch + 时区看门狗 + 计划任务
├── rules.rs        # Clash 模式识别 + Script.js 托管规则 + 内核验证/回滚
├── diagnostics.rs  # open-safe / 代理诊断 / 指纹 / cli-info
├── keep.rs         # 跨身份保留 keep-in-workspace
├── export.rs       # 加密快照导出/导入（Argon2id + AES-GCM，CSBK1）
├── update.rs       # GitHub Release 自动更新
├── links.rs        # symlink / junction / 硬链接
├── fsx.rs          # 原子写入 + 锁重试
├── processes.rs    # Claude Code 进程检测（sysinfo）
├── net.rs          # reqwest HTTP（OAuth + Clash）
├── usage.rs        # 用量统计 + 独立 usage-cache.json（不解密账号库）
├── tray.rs         # 托盘 / 弹窗定位（read_lightweight 轻量读取）
├── cli.rs          # 命令行入口 --list/--status/--switch/run（AttachConsole + 单实例转交）
├── bin/cs.rs       # 控制台子系统程序 cs.exe（[[bin]]，不设 windows_subsystem）
├── naming.rs       # 文件名合法化 + 保留设备名（CON/NUL 等）
├── shortcuts.rs    # 开始菜单 .lnk（mslnk，每账号 --switch）
├── token_status.rs # 令牌状态纯函数（有效/即将过期/已过期/未知）
├── dirbinding.rs   # 目录绑定标记 + cs run（CLAUDE_CONFIG_DIR）
├── userpath.rs     # 用户 PATH（HKCU，REG_EXPAND_SZ + WM_SETTINGCHANGE）
├── provider.rs     # 第三方供应商（加密 token，受管 env 键）
├── wsl.rs          # WSL 实验集成（UTF-16LE，默认关，stdin 传 blob）
├── sanitize.rs     # 诊断脱敏（敏感键 ***，邮箱留首字符+域名）
└── lib.rs          # Tauri 命令层（--guard / --autostart / CLI 在此分发；写路径走 with_store）
```

新增平台相关能力时：先在 `platform/windows.rs` 加同名函数，再在业务里调 `platform::imp::xxx`。

### 阻塞命令必须走 `blocking()`

Tauri 2 中非 `async` 命令跑在主线程。任何可能阻塞的（网络、进程扫描、目录 rename、
凭据读取）都必须：

```rust
#[tauri::command]
async fn xxx() -> Result<T, String> {
    blocking(|| xxx_blocking()).await
}
```

**不要**用 `#[tauri::command(async)]` 包同步函数——那会跑在 tokio 工作线程，
里面调 `reqwest::blocking` 有 panic 风险。

### 写文件一律原子

`fsx::write_atomically`：临时文件 + rename。**绝不要** `fs::write` 直接写
`store.private.json` / `.credentials.json` / `~/.claude.json`——截断式写入中途
崩溃会丢数据。`rename_with_retry` 失败时**不要**删目标文件（旧数据必须保留）。

### 账号库写操作必须走 `with_store`

任何对账号库的读—改—写都用 `store::with_store(|store| { ... Ok(...) })`，闭包
返回 Ok 后统一原子保存，杜绝并发写互踩。锁顺序为「重入检测 → fs4 跨进程锁 →
进程内 STORE_LOCK Mutex → load → f → save」。只读路径用 `read_lightweight()`
（不解密）或 `load_store()`（不持锁）。

- **重入检测**：thread_local `IN_STORE_TX` + Drop guard，嵌套调用 `with_store`
  立即返回 Err「with_store 不可嵌套调用」而非死锁。闭包内禁止再调任何获取
  STORE_LOCK 的函数（见踩坑 22）。
- **跨进程锁**：fs4 在 `app_data_dir/store.lock` 上 `fs4::FileExt::lock` 排他
  阻塞，覆盖 load→f→save 全程；锁文件创建失败按 Err 返回。便携模式锁文件在
  `ClaudeSwitcherData` 下。

### 凭据与密钥边界

- OAuth blob：存 `<claude_dir>\.credentials.json`（官方主存储）。
- store 主密钥：Windows Credential Manager（`claude-switcher-store-key`），32B AES-256-GCM。
- `settings_json` 里的认证字段（`AUTH_ENV_KEYS` + `apiKeyHelper`）落盘前必须
  `store::split_auth_settings` 拆出加密，读时 `restore_auth_settings` 合并回去。
- **解密路径绝不生成新密钥**：缺密钥时报错，让用户恢复，绝不覆盖。
- `keyring::Error` 除 `NoEntry` 外一律致命 Err（PlatformFailure 可能是 DPAPI 失败，
  当「不存在」会铸新钥覆盖旧数据）。

## 踩过的坑（按踩坑时间倒序）

1. **winreg `open_subkey` 是 KEY_READ 只读**：`set_value` 必返回拒绝访问。
   写注册表必须 `create_subkey`（KEY_ALL_ACCESS）。见 `lib.rs` set_autostart。
2. **winreg 的 `Vec<u8>` 没实现 FromRegValue**：读二进制注册表值必须
   `get_raw_value()` 拿 `RegValue.bytes`。
3. **`icacls` 的 `*` 前缀只接受 SID**：`*SYSTEM:` 非法，整条命令失败。
   SYSTEM 的真实 SID 是 `*S-1-5-18`。且必须**先 grant 再 /inheritance:r**。
4. **Windows 路径比较必须归一化**：`\\?\` 前缀、大小写、`/` vs `\`、尾分隔符、
   8.3 短名都要处理（`platform::windows::normalize_path`）。`plugins/data` 这种
   含 `/` 的相对 join 会产生混合分隔符。
5. **悬空 junction 打不开句柄**：`reparse_tag` 拿不到时要按「属性位是 reparse
   point」保守判为链接，否则 activate 会走错分支。
6. **`entry.file_type()` 不跟随链接**：遍历目录时符号链接/junction 子目录会被
   误判为非目录，要回退 `metadata()`。见 `usage::collect_jsonl_files`。
7. **`std::env::args()` 在 GUI 启动时读不到终端设的环境变量**：所以提供
   `claude-config-dir.txt` 手动覆盖文件。
8. **`CLAUDE_CONFIG_DIR` 不会让 `.claude.json` 搬家**（claude 2.1.310 实测）：
   凭据跟随、全局配置不跟随。`claude_json_path()` 固定 home。
9. **`--type=` 是 Electron 子进程标志**：Claude Desktop 的 renderer/gpu 进程
   也带 `--type=`，进程检测用它排除。`WindowsApps` 排除只对 `claude.exe` 生效
   （Store 版 Node 也在那个目录）。
10. **reqwest `default-features = false` 会丢掉 `system-proxy`**：Clash 系统代理
    开关就读不到。还要 `rustls-tls-native-roots` 信任 Windows 证书库。
11. **Tauri command 的返回类型必须 `Serialize`**：新增的 `GuardTick` 一开始只
    derive(Debug,Clone)，注册进 generate_handler 后报 `async_kind` trait bound 不满足；
    补 `serde::Serialize` 即可。
12. **STUN 无响应 ≠ 零泄漏**：UDP 可能被丢弃，必须判为 warn，不能当作没暴露真实 IP。
13. **Clash 规则只写 `profiles\Script.js` 托管块**（`// >>>/<<< claude-switcher
    managed rules`），不再写 Merge.yaml；写完重启内核并以 `/rules` 前 16 条验证，
    失败回滚备份。旧 prepend-rules / 多文档要清理。
14. **地区按出口动态锁定，不固定 en-US**：Windows beta 把区域写死 en-US 是缺陷；
    换国家节点后必须能 `set-region`（重锁国家/时区/locale/GeoID）。
15. **`blocking(|| f())` 对无参函数是 redundant_closure**：clippy 要求直接传函数
    指针 `blocking(f)`；但被调函数返回非 Result（如直接返回 report）时仍要
    `blocking(|| Ok(report))`。
16. **Windows 上 npx/npm/pnpm/yarn 是 .cmd shim**：MCP stdio 直接 spawn 会失败，
    必须 `cmd /c <command> <args>` 包装（`mcp::normalize_mcp_stdio`），且要幂等。
17. **额度阈值通知必须按重置周期去重**：以官方 usage 的 `resets_at` 为 key，
    周期变化才清档；状态落 `notify-state.json` 原子写。Toast 需 AUMID，
    开发模式显示成宿主（PowerShell）身份属正常。
18. **便携模式的 WEBVIEW2_USER_DATA_FOLDER 必须在 WebView2 创建前设置**：
    在 `run()` 里 Builder 之前 set_var；`portable.flag` 在 exe 旁。
19. **测试绝不读写真实凭据库**：主密钥走 `KeyBackend` trait，测试注入内存后端
    （`TestKeyBackendGuard`），避免中断时残留测试密钥；密钥测试用全局锁串行。
20. **P2-2 凭据锁禁止凭猜测实现**：须先用 Process Monitor 实机抓 claude.exe/
    node.exe 刷新令牌时的锁文件，抓不到就在文档标「待实机调研」。
21. **不要依赖 PATH 按名启动 `powershell.exe`**：部分精简/安装环境（以及被改写过的
    进程 PATH）里不含 `System32\WindowsPowerShell\v1.0`，按名启动报「系统找不到指定的
    文件」，会让所有走 `run_ps` 的系统状态查询（网卡/服务/进程/计划任务…）整体失败。
    统一用 `platform::powershell_path()`（从 `SystemRoot` 拼权威路径）；并行终端把
    powershell 作为参数传给 wt/cmd 时同样用完整路径。
22. **`store::with_store` 的锁是 std `Mutex`，不可重入**：闭包内再调任何获取
    `STORE_LOCK` 的函数会自死锁。`cancel_pending` 因内部要调 `switch`（自带锁），
    改成「只读 load 预检 → 调 switch → 窄 with_store 清 pending」，绝不持锁进
    switch。新增写路径先确认它调用的函数不获取 STORE_LOCK。
23. **提权 Administrator 下「只读目录」测试不可靠**：提权进程对只读目录仍可写，
    断言「只读目录创建失败」会误判。需要稳定的失败路径时，用「父级是普通文件时
    `create_dir_all` 必然失败」代替（`probe_data_dir_writable_fails_when_parent_is_a_file`）。
24. **`std::fs::Metadata::clone_permissions()` 是 Unix-only**：Windows 上没有该方法，
    跨平台复制权限用 `std::fs::File::set_permissions(metadata.permissions())`。
25. **便携版数据根是 exe 旁的 `ClaudeSwitcherData` 子目录，不是 exe 目录**：
    `WEBVIEW2_USER_DATA_FOLDER` 与全部用户数据都落在子目录；exe 目录 / Downloads /
    Desktop 命中 `is_protected_from_hardening` 时跳过 icacls 加固。
26. **通知 uuid 缺失绝不回退固定 "current" 键**：否则会把通知记到错误账号上；
    取不到 uuid 直接跳过、不写状态。J-6 已弃用 `round_to_five_minutes`，改
    `same_reset_period`（时间差 abs ≤600s 视为同周期，无法解析则字符串回退），
    5h/7d 两个窗口独立去重。
27. **manifest 必须纯 ASCII**：`windows-app.manifest` 含中文注释时，embed-resource
    调 rc.exe 不传 `/c 65001`，rc.exe 按 GBK 回写而文件头声明 UTF-8，导致所有
    exe 无法启动（事件日志 SideBySide Id=59，c101008c）。manifest 改英文注释、
    非 ASCII 字节=0（保留 `{{VERSION}}` 与全部功能 XML）。
28. **本机 vcvars64 的 Windows SDK 检测失效**：INCLUDE 缺 Windows Kits 路径，
    但 SDK 10.0.26100.0 实际已装。统一用 agent workspace 的 `cargo-msvc.ps1`
    （显式 PATH/INCLUDE/LIB、`CARGO_HTTP_CHECK_REVOKE=false`、代理变量）跑
    check/fetch/test/clippy，勿依赖 vcvars。
29. **PowerShell 新会话 PATH 不含 System32**：按名启动 powershell/wsl/cmd 会失败，
    系统命令用 `C:\Windows\System32\...` 全路径；wsl.exe/powershell.exe 均从
    SystemRoot 拼权威路径。
30. **Tauri externalBin 在 build.rs 阶段就校验文件存在**：`externalBin=["binaries/cs"]`
    要求磁盘上有 `binaries/cs-<target-triple>.exe`（本机 triple
    x86_64-pc-windows-msvc），否则任何 cargo build/check 直接 panic。安装时落成无后缀的
    cs.exe。**鸡生蛋顺序坑**：干净检出时该 sidecar 还不存在，而 `cargo build --bin cs`
    本身就会先跑 build.rs 触发存在性校验而 panic，等构建完再 Copy 已来不及。正确顺序：
    先在目标路径落一个 0 字节占位文件（tauri-utils 只查 `.exists()`、不校验是否有效 PE，
    见 resources.rs `resource_from_path`），再 `cargo build --bin cs`，最后用真实
    `target/release/cs.exe` 覆盖占位。本地已用 release 构建验证：cs.exe 4,349,952 字节、
    有效 MZ、`--status` 退出 0、无参打印用法退出 2。
31. **winreg 写 REG_EXPAND_SZ 用 set_raw_value**：`RegValue{bytes: UTF-16LE(含尾
    null), vtype: RegType::REG_EXPAND_SZ}`；读用 get_raw_value +
    `String::from_reg_value` 按字面读、不展开，保留 %USERPROFILE% 等变量。
32. **同级备选键用 `first_string_field`，不是 `string_field`**：后者把多个 key 当
    逐层下钻，备选键（email/accountEmail/username 等）会永远返回 None。
33. **PowerShell 5.1 会吞掉裸 `--`**：经脚本转发 `cargo clippy -- -D warnings`
    时 `--` 被 PS 参数绑定剥离，clippy 报 unexpected argument '-D'。把 `--` 写成
    引号字符串 `'--'` 即可保留。
34. **诊断/便携新增 zip 依赖**：`zip = { version="2", default-features=false,
    features=["deflate"] }`（拉入 flate2/crc32fast/miniz_oxide）；诊断包写前先
    `sanitize::redact_json`，日志走 `redact_emails_in_text`，令牌绝不进包。
35. **windows-sys 语言/锁的 feature 归属**：`GetUserDefaultUILanguage` 在
    Win32_Globalization；`CreateFileW` 在 Win32_Security；`SendMessageTimeoutW`
    在 Win32_UI_WindowsAndMessaging。缺 feature 是编译期长报错，先核对归属。

## 实机未验证项（改相关代码后优先测）

- 开机自启：任务管理器禁用后点「开启」能否真的启动（`StartupApproved\Run` 已写启用值）。
- 多显示器 + 任务栏在左/上/右的托盘弹窗定位。
- Clash 实机节点切换（控制器地址归一化只有表格测试）。
- 配置目录切换后的凭据迁移与隔离重建。
- 保镖真实 kill（Desktop+CLI）、计划任务 highest 注册与 AtLogOn 触发。
- TUN 网卡、verge.yaml TUN 恢复后 Clash Verge 实机重启。
- open-safe 真实浏览器拉起/WebRTC 标志/profile 销毁；自动更新全流程。
- 安装包升级/卸载回归。
- 托盘一键切换（动态菜单/通知/重建）、按终端并行多账号（wt/cmd 拉起）。
- 额度阈值通知/提醒（Toast/AUMID）、MCP 真实拉起、便携版解压运行。
- 完整便携版固定 WebView2（约 150MB）：本环境无固定运行时，用
  `scripts/build-full-portable.ps1` 下载组装后验证；cs run、PATH 注册表写入/广播、
  开始菜单 .lnk 均未实机验证。
- 第三方供应商真实连通/切换、WSL 真实写入（本机仅 docker-desktop，0600 无法保证）。
- F-4 凭据锁（原 P2-2）：待 Process Monitor 实机调研，本轮不实现、不加猜测锁。
