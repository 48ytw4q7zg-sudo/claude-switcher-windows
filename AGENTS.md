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
├── store.rs        # 账号快照 + AES-GCM 加密（含 DesktopProfile）
├── accounts.rs     # 账号材料事务写入 + settings env 注入
├── isolation.rs    # 按 profile 接管/激活本地状态（CLI）
├── desktop.rs      # Claude Desktop 快照/捕获/切换/删除（含备份回滚）
├── appconfig.rs    # 全局配置 appconfig.json（country/tz/locale/proxy_mode/webrtc）
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
├── usage.rs        # 用量统计 + 缓存
├── tray.rs         # 托盘 / 弹窗定位
└── lib.rs          # Tauri 命令层（--guard / --autostart 在此分发）
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

## 实机未验证项（改相关代码后优先测）

- 开机自启：任务管理器禁用后点「开启」能否真的启动（`StartupApproved\Run` 已写启用值）。
- 多显示器 + 任务栏在左/上/右的托盘弹窗定位。
- Clash 实机节点切换（控制器地址归一化只有表格测试）。
- 配置目录切换后的凭据迁移与隔离重建。
- 保镖真实 kill（Desktop+CLI）、计划任务 highest 注册与 AtLogOn 触发。
- TUN 网卡、verge.yaml TUN 恢复后 Clash Verge 实机重启。
- open-safe 真实浏览器拉起/WebRTC 标志/profile 销毁；自动更新全流程。
- 安装包升级/卸载回归。
