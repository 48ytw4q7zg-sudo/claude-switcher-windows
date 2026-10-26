# Claude Switcher（Windows 版）

一个 Windows 桌面工具，用来管理多个本机 Claude Code 账号：保存账号快照、切换 OAuth 凭据、按账号隔离 Claude Code 本地痕迹，并把每个账号绑定到 Clash Verge 的 `Auto-Claude` 节点。

基于 **Tauri 2 + Rust + React 19 + TypeScript** 构建。

## 项目出处与平台分工

| 项目 | 面向系统 | 说明 |
| --- | --- | --- |
| [VallierDev/claude-switcher](https://github.com/VallierDev/claude-switcher) | **macOS** | 上游原项目（迁移基线：commit [`6897984`](https://github.com/VallierDev/claude-switcher/commit/68979843313a0cb7da3cda32765184436ba9598e)）。感谢原作者 **@VallierDev**。 |
| 本仓库 | **Windows 10 / 11（x64）** | 在保持上游全部功能的前提下完成 Windows 适配、模块化重构与加固，并额外增加了单实例、开机自启、Clash 控制器覆盖等增强功能。 |

**迁移范围**：OAuth 凭据读写与清除、账号快照切换、备份/还原、一键新号向导、session/config 隔离、Clash 节点绑定、用量展示、托盘弹窗与数据目录入口——上游功能**一个不少**。Windows 上没有沿用 macOS 的 Keychain / `pgrep` / `security` 命令，而是替换为等价的系统 API（见「架构」）。

## 安装使用教程

### 一、小白版（只需要双击，适合第一次用）

1. **打开下载页**：进入本仓库的 `Releases`，下载 `Claude Switcher_0.1.0_x64-setup.exe`（推荐，NSIS 安装包）；也可用 `Claude Switcher_0.1.0_x64_zh-CN.msi`。
2. **双击安装包**，按提示点「下一步」直到安装完成。安装包内置 WebView2 引导器（`embedBootstrapper`），无需提前安装运行库。
3. 若 Windows 弹出 **SmartScreen**「Windows 已保护你的电脑」，点「更多信息」→「仍要运行」。
   > 这是**未签名安装包**的正常提示；本仓库未配置代码签名证书。请只从本仓库 Release 下载，不要从来路不明的链接安装。
4. 从开始菜单打开 **Claude Switcher**。
5. **先保存当前账号**：在「保存当前账号」面板输入名称（如「Claude 主号」），点「保存快照」。前提：你已经在 Claude Code 中登录过至少一个账号。
6. **切换账号**：在「账号快照」里点对应卡片的「切换」。提示重启正在运行的 Claude Code 会话。
7. **托盘用法**：点桌面右下角托盘的彩色图标可弹出用量窗口；**双击**图标直接打开主窗口；**右键**托盘图标有「打开主窗口 / 刷新用量 / 退出 Claude Switcher」。
   > Windows 11 默认会把新装的托盘图标收进「^」溢出区。想一直看到它：右键任务栏 → 任务栏设置 → 打开「其他系统托盘图标」/「选择哪些图标显示在任务栏上」→ 找到 Claude Switcher → 打开。
8. 主窗口点 **X** 只是**隐藏到托盘**，不会退出；要彻底退出请用托盘右键菜单或主窗口「退出」按钮。
9. （可选）在「数据位置」面板点「开启开机自启」，电脑重启后自动运行（只影响当前 Windows 用户）。
10. （可选）「一键新号」向导：选节点 → 准备环境 → 手动打开 Claude Code 完成 OAuth → 回到本工具点「登录完成后保存」。

### 二、高手版（源码构建 / 命令行）

环境要求：Windows 10/11 x64、Node.js 20+、Rust stable、**Visual Studio Build Tools（含「使用 C++ 的桌面开发」与 Windows SDK）**。

```powershell
# 1. 克隆
git clone https://github.com/48ytw4q7zg-sudo/claude-switcher-windows.git
cd claude-switcher-windows

# 2. 前端依赖
npm ci

# 3. 若报 `linker link.exe not found`，把 MSVC 的 bin 加进 PATH（版本号随机器而异）
$msvc = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio\*\*\VC\Tools\MSVC" -Directory | Sort-Object Name -Descending | Select-Object -First 1
$env:Path = "$($msvc.FullName)\bin\Hostx64\x64;$env:USERPROFILE\.cargo\bin;$env:Path"
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"

# 4. 质量门禁（与 CI 相同）
cd src-tauri
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --lib
cd ..

# 5. 开发模式（带热更新）
npm run tauri dev

# 6. 出安装包（MSI + NSIS）
npm run tauri build
```

产物位置：

```text
src-tauri\target\release\claude-switcher.exe                       # 免安装可执行文件
src-tauri\target\release\bundle\msi\Claude Switcher_0.1.0_x64_zh-CN.msi
src-tauri\target\release\bundle\nsis\Claude Switcher_0.1.0_x64-setup.exe
```

补充：

- **WiX 下载超时**：首次打 MSI 时 Tauri 会下载 `wix314-binaries.zip`（GitHub release）。国内网络超时的话，手动下载放到 `%LOCALAPPDATA%\tauri\WixTools\` 后重跑。
- **开发者模式**：Windows 的「设置 → 系统 → 开发者选项 → 开发者模式」打开后，目录隔离会用**符号链接**；不开则自动降级为 **junction（目录）/ 硬链接（文件）**。本工具在「数据位置」面板显示当前链接模式。
- **Clash 控制器覆盖**（便携模式 / 端口被改 / secret 有自定义时）：编辑 `%USERPROFILE%\.claude-switcher\clash.json`：
  ```json
  {
    "controller": "http://127.0.0.1:9097",
    "secret": "你的secret",
    "proxyPort": 7897
  }
  ```
  留空或删除文件则自动探测：先读 Clash Verge 的 `config.yaml`，没有有效配置再按 **9097 → 9090** 依次探测 `/version`（1 秒超时，结果缓存 60 秒）。
- **`CLAUDE_CONFIG_DIR`**：若你设置了这个环境变量，本工具会跟随它读写配置目录，而不是写死 `%USERPROFILE%\.claude`；`~/.claude.json` 仍在用户主目录。
- **数据备份**：所有快照与备份都在 `%USERPROFILE%\.claude-switcher\`，复制该目录即可迁移；加密主密钥在 Windows 凭据管理器（`claude-switcher-store-key`），换机需同用户名下保留该条目才能解出已加密凭据。

## 架构

### 技术栈

| 层 | 选型 |
| --- | --- |
| 桌面壳 | Tauri 2.11（`tauri.conf.json`，Windows x64，WebView2 `embedBootstrapper`，NSIS 简体中文 + WiX zh-CN） |
| 后端 | Rust（16 个模块，原 4229 行单文件 `lib.rs` 拆分）；28 个 `#[tauri::command]` |
| 前端 | React 19 + TypeScript + Vite + lucide-react；`src/App.tsx` 主窗口、`src/components/ClaudeTrayPopup.tsx` 托盘弹窗 |
| HTTP | `reqwest` + rustls（替代 `curl.exe`，读系统/环境代理，JSON body 走 socket 不走 argv） |
| 加密 | AES-256-GCM（`enc:v1:` + base64(nonce 12B ‖ ciphertext)）；主密钥存 Windows 凭据管理器 |
| 系统 API | `sysinfo`（进程）、`windows-sys`（文件 ID、reparse tag、SID、长路径）、`junction` crate、`keyring`（凭据管理器） |

### 模块划分（src-tauri/src/）

| 模块 | 职责 |
| --- | --- |
| `lib.rs` | 28 个命令处理器、返回类型、应用启动（单实例、关窗到托盘） |
| `accounts.rs` | 账号材料快照、Merge / FullReplace 两种写入语义、事务回滚、settings env 注入 |
| `store.rs` | `store.private.json` 读写；AES-GCM 加解密；密钥「只读现有、解密绝不铸新钥」 |
| `credentials.rs` | Windows 凭据文件 / macOS Keychain 的读写与清除（cfg 收拢） |
| `isolation.rs` | 按 profile 接管/激活 `projects`、`telemetry`、`file-history`、`shell-snapshots`、`cache`、`debug`、`plugins/data`、`config.json` 共 8 个隔离面 |
| `links.rs` | 符号链接 / junction / 硬链接的创建、识别与链接模式上报 |
| `platform/windows.rs` | 全部 Win32 细节：`CREATE_NO_WINDOW`、icacls（SID、先授权再断继承）、reparse tag（含悬空链接）、`GetFileInformationByHandle`、`GetLongPathNameW`、锁重试 |
| `platform/unix.rs` | 同名 API 的 Unix 实现，保持 macOS 行为不回归 |
| `paths.rs` | 路径解析（`CLAUDE_CONFIG_DIR` → `USERPROFILE` → `home_dir`）与目录保障 |
| `fsx.rs` | 原子写入（`.原文件名.tmp-<rand>` + rename）与 Windows 错误 5/32/33 短退避重试 |
| `processes.rs` | Claude Code CLI 检测与结束（精确匹配，防误杀） |
| `net.rs` | Clash 控制器 / OAuth 请求、默认端口真实探测、代理回退与超时预算 |
| `usage.rs` | 本地日志聚合 + OAuth usage/profile 的 TTL 缓存与 in-flight 合并 |
| `clash.rs` | 节点组状态、切换、节点 alive 与到 `api.anthropic.com` 的延迟检查 |
| `tray.rs` | 托盘 tooltip、弹窗定位（工作区/多屏）、失焦防抖、右键菜单 |

### 关键数据流

```
React 主窗口 / 托盘弹窗
        │  invoke (28 个命令)
        ▼
lib.rs（命令层）
   ├─ accounts.rs ── credentials.rs ──► %USERPROFILE%\.claude\.credentials.json
   │        │                          %USERPROFILE%\.claude.json
   │        │                          <claude_dir>\settings.json
   │        └─ store.rs ──► %USERPROFILE%\.claude-switcher\store.private.json（AES-GCM）
   │                          主密钥 → Windows 凭据管理器 claude-switcher-store-key
   ├─ isolation.rs ── links.rs ──► session-profiles/<profile-id>/ 的链接与备份
   ├─ processes.rs ── sysinfo ──► Claude Code CLI 进程
   ├─ net.rs / clash.rs ──► Clash 控制器（127.0.0.1:9097 / 9090）
   └─ usage.rs ──► <claude_dir>\projects\**\*.jsonl  +  api.anthropic.com OAuth usage
```

### Windows 适配清单（与 macOS 功能一一对应）

| 能力 | macOS 上游 | Windows 本仓库 |
| --- | --- | --- |
| OAuth 凭据 | `security` 操作 Keychain | 直接读写 `<claude_dir>\.credentials.json`（官方主存储），跟随 `CLAUDE_CONFIG_DIR`；「删除遗留凭据文件」在 Windows 上是空操作（不能删主存储） |
| 加密主密钥 | Keychain | Windows 凭据管理器（`keyring`） |
| 进程检测 / 结束 | `pgrep` / `kill` | `sysinfo` + `taskkill /T`（温和）→ `/T /F`（强制） |
| 目录隔离 | symlink | symlink → junction（无需特权） |
| 文件隔离 | symlink | symlink → 硬链接（同卷同索引识别） |
| 权限收敛 | `chmod 600` | 只在 `%USERPROFILE%\.claude-switcher` 创建时执行一次 icacls（当前用户 SID、先授权再断继承、子项继承），不动 Claude 自己的文件 |
| 网络请求 | `curl` | `reqwest` + rustls（无黑窗、无 PATH 依赖、读系统代理） |
| 托盘弹窗 | 图标下方弹出 | 图标上方弹出，按点击坐标所在显示器 + 工作区夹紧，失焦 500ms 防抖，双击图标打开主窗口 |
| 打开数据目录 | `open` | `explorer`（spawn，忽略非零退出码） |

### 本仓库额外增强

- 单实例（避免双开并发写 store）
- 关窗到托盘 + 右键退出 + 开机自启（`HKCU\...\Run`，带 `--autostart` 静默启动参数）
- Clash 控制器 / secret / 代理端口手动覆盖；默认端口 9097 → 9090 真实探测
- 用量 TTL 缓存 + 并发 in-flight 合并 + 本地快照 45 秒缓存
- 链接模式显示与开发者模式一键引导（`ms-settings:developers`）
- 手动指定 Claude 配置目录（解决 GUI 启动读不到终端环境变量的问题）
- 原子写入、文件锁重试（32/33 退避、5 只重试一次）、悬空链接识别、路径归一化（`\\?\` 前缀 / 大小写 / 8.3 短名 / 正斜杠统一）
- 读 JSON 自动处理 UTF-8 BOM 与 UTF-16（记事本改过的 settings.json 不会让界面打不开）
- 事务回滚顺序「先凭据后 JSON」；账号材料已切换后链接激活失败降级为 warning（避免「显示失败、实际已切」）
- 本机日志（`~/.claude-switcher/logs/`，1MB 滚动）+ panic hook + 诊断信息一键复制
- 新增单元测试：链接识别、悬空链接、路径归一化、原子写入、merge/scrub 逻辑、BOM/UTF-16 解码、进程匹配表格、Windows 反斜杠 `subagents` 过滤等

## 隐私与安全

- 账号快照只保存在本机 `%USERPROFILE%\.claude-switcher\`，不会上传任何账号凭据。
- OAuth blob 写入 store 前用 AES-256-GCM 加密，主密钥在 Windows 凭据管理器；token 不显示在 UI，也不进入本仓库。
- 进程检测只匹配 `claude.exe` 或 `node`/`bun` 且命令行含 `@anthropic-ai/claude-code`，并排除本工具自身与 Claude Desktop，**不会**因为命令行里出现 `claude-code` 字样就误杀别的进程。
- 本仓库 CI 只构建源码，不访问本机凭据、`~/.claude-switcher` 数据或 Claude 账号快照。

## 构建与发布

- `CI`：push / PR 时在 macOS 与 Windows 上跑前端构建、`cargo fmt --check`、
  `cargo clippy --all-targets -- -D warnings`、`cargo test --lib`、Tauri build。
  （macOS runner 的 host 与 target 不同，会额外按 target 再跑一遍 clippy；
  Windows runner 两者相同，不重复。）
- `Windows Build`：手动触发或打 `v*` tag，产出 MSI / NSIS。
- 未配置代码签名证书；首次运行安装包会有 SmartScreen 提示，属预期。
  有条件可接 Azure Trusted Signing 或自持证书消除该提示。

## 出处与许可

- 本仓库是 [VallierDev/claude-switcher](https://github.com/VallierDev/claude-switcher)（macOS 版）
  的 Windows 迁移版，迁移基线 commit [`6897984`](https://github.com/VallierDev/claude-switcher/commit/68979843313a0cb7da3cda32765184436ba9598e)。
- **上游仓库未声明许可证**（无 LICENSE 文件）。若上游后续补充许可，本仓库的许可
  应与之对齐；在此之前请联系上游作者确认授权范围。
- 涉及 Anthropic / Claude Code 的商标与名称归其权利人所有。本工具只在本地操作
  Claude Code 已生成的文件，不修改、不分发任何 Anthropic 专有代码。

## 致谢

- 上游原项目与作者：**[@VallierDev](https://github.com/VallierDev)** — [VallierDev/claude-switcher](https://github.com/VallierDev/claude-switcher)
- 本 Windows 迁移版在保持原功能的基础上做了系统适配与加固，感谢上游的设计。
