# AGENTS.md — Claude Switcher Windows 维护交接

给后续 AI 助手 / 维护者的工程说明。**先读本文再动手。**

## 这是什么

Windows 版 Claude Code CLI 账号切换器（Tauri 2 + Rust + React）。
上游是 macOS 桌面应用（**同为 Tauri 2 + Rust + React**，非 Swift），
基线 commit 与功能映射见 [`docs/upstream-baseline.md`](docs/upstream-baseline.md)。
**不是** YOURSJEYO/claude-switcher（那是 Claude 桌面版环境管理器，已明确不移植）。

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

**所有平台差异必须收拢在 `platform/` 模块**，业务代码不写 `#[cfg(windows)]`：

```
src-tauri/src/
├── platform/{windows,unix,mod}.rs   # 唯一允许写 cfg 的地方
├── paths.rs        # 路径解析 + 目录保障（CLAUDE_CONFIG_DIR 跟随）
├── credentials.rs  # 凭据读写（Windows 文件 / macOS Keychain）
├── store.rs        # 账号快照 + AES-GCM 加密
├── accounts.rs     # 账号材料事务写入 + settings env 注入
├── isolation.rs    # 按 profile 接管/激活本地状态
├── links.rs        # symlink / junction / 硬链接
├── fsx.rs          # 原子写入 + 锁重试
├── processes.rs    # Claude Code 进程检测（sysinfo）
├── net.rs          # reqwest HTTP（OAuth + Clash）
├── usage.rs        # 用量统计 + 缓存
├── tray.rs         # 托盘 / 弹窗定位
└── lib.rs          # Tauri 命令层
```

新增平台相关能力时：先在 `platform/{windows,unix}.rs` 加同名函数，再在业务里调 `platform::imp::xxx`。

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

- OAuth blob：Windows 存 `<claude_dir>\.credentials.json`；macOS 存 Keychain。
- store 主密钥：Credential Manager（Windows）/ Keychain（macOS），32B AES-256-GCM。
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

## 实机未验证项（改相关代码后优先测）

- 开机自启：任务管理器禁用后点「开启」能否真的启动（`StartupApproved\Run` 已写启用值）。
- 多显示器 + 任务栏在左/上/右的托盘弹窗定位。
- Clash 实机节点切换（控制器地址归一化只有表格测试）。
- 配置目录切换后的凭据迁移与隔离重建。
