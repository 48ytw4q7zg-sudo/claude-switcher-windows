# Claude Switcher（Windows 版）

[![CI](https://github.com/48ytw4q7zg-sudo/claude-switcher-windows/actions/workflows/ci.yml/badge.svg)](https://github.com/48ytw4q7zg-sudo/claude-switcher-windows/actions/workflows/ci.yml)

一个 Windows 桌面工具，用来管理多个本机 **Claude Code CLI** 账号：保存账号快照、切换 OAuth 凭据、按账号隔离 Claude Code 本地痕迹（会话历史 / 配置 / 遥测等 8 个隔离面），并把每个账号绑定到 Clash Verge 的 `Auto-Claude` 节点。

基于 **Tauri 2 + Rust + React 19 + TypeScript** 构建，桌面壳为 Windows 原生 WebView2。

---

## 项目地址与出处

| 项目 | 地址 |
| --- | --- |
| 本仓库（源码） | [48ytw4q7zg-sudo/claude-switcher-windows](https://github.com/48ytw4q7zg-sudo/claude-switcher-windows) |
| 安装包下载 | 本仓库 [Releases](https://github.com/48ytw4q7zg-sudo/claude-switcher-windows/releases)（MSI / NSIS，SHA256 见 Release 说明） |
| 上游原项目 | [VallierDev/claude-switcher](https://github.com/VallierDev/claude-switcher)（macOS 版，本仓库的直接迁移基线） |
| 相关项目（同名不同产品） | [YOURSJEYO/claude-switcher](https://github.com/YOURSJEYO/claude-switcher)（Claude 桌面版环境管理器，见下） |

### 平台分工（不同项目对应不同系统）

| 项目 | 面向系统 | 说明 |
| --- | --- | --- |
| [VallierDev/claude-switcher](https://github.com/VallierDev/claude-switcher) | **macOS** | 上游原项目，同为 Tauri 2 + Rust + React。本仓库的迁移基线为 commit [`6897984`](https://github.com/VallierDev/claude-switcher/commit/68979843313a0cb7da3cda32765184436ba9598e)。感谢原作者 **[@VallierDev](https://github.com/VallierDev)**。 |
| **本仓库** | **Windows 10 / 11（x64）** | 保持上游全部功能的前提下完成 Windows 适配、模块化重构与加固，并额外增加单实例、开机自启、Clash 控制器覆盖等增强。 |
| [YOURSJEYO/claude-switcher](https://github.com/YOURSJEYO/claude-switcher) | macOS 为主 + Windows（Beta） | **另一个产品**：Claude **桌面版** 环境管理器（环境审计、守护进程、系统时区与地区锁定、指纹体检等），技术栈 Swift + bash/Python 核心 + PowerShell/WPF Windows Beta。感谢 **[@YOURSJEYO](https://github.com/YOURSJEYO)** 在同类工具生态上的工作。 |

### 与 YOURSJEYO/claude-switcher 的关系（避免混淆）

两个项目**同名，但不是同一个产品，也没有代码血缘关系**：

| 对比项 | 本仓库 | YOURSJEYO/claude-switcher |
| --- | --- | --- |
| 管理对象 | Claude Code **CLI**（`~/.claude`、`~/.claude.json`、OAuth 凭据） | Claude **桌面版**（`%APPDATA%\Claude`） |
| 技术栈 | Tauri 2 + Rust + React（迁移自 VallierDev 上游） | Swift + bash/Python 核心 + PowerShell/WPF Windows Beta |
| 核心能力 | 账号快照 / 凭据切换 / 会话隔离 / Clash 节点绑定 | 环境审计、守护进程、系统时区与地区锁定、指纹体检 |
| 许可 | Apache-2.0（本仓库） | MIT |

本仓库的功能全部迁移自 VallierDev 上游，**不包含** YOURSJEYO 项目的任何代码或功能。若你在找 Claude 桌面版的环境管理工具，请访问 [YOURSJEYO/claude-switcher](https://github.com/YOURSJEYO/claude-switcher)。

**迁移范围**：OAuth 凭据读写与清除、账号快照切换、备份/还原、一键新号向导、session/config 隔离、Clash 节点绑定、用量展示、托盘弹窗与数据目录入口——上游功能**一个不少**。Windows 上没有沿用 macOS 的 Keychain / `pgrep` / `security` 命令，而是替换为等价的系统 API（见「架构」）。

---

## 当前交付状态

- 源码：`main` 分支。
- 安装包：**Release v0.1.0**，由 `.github/workflows/windows-build.yml` 在 GitHub Actions 上构建（MSI + NSIS），产物来源可审计，SHA256 见 Release 说明。
- 开发与实测环境：**Windows 11 Pro x64**（build 26300）。Windows 10 未实机验证（见「验收边界」）。
- 安装包**未做代码签名**：干净系统首次运行会弹 SmartScreen，属预期（见「常见问题」）。

---

## 系统介绍（这是什么、能做什么）

Claude Code CLI 的登录凭据、全局配置和会话历史都散落在用户目录里，多账号使用时会互相覆盖。本工具把这些材料按账号做**快照 + 切换 + 隔离**：

- **保存当前账号**：一键把当前登录态的凭据、`~/.claude.json`、`settings.json` 存成账号快照。
- **切换账号**：一键把目标账号的材料写回 Claude Code 的存储位置，并把会话历史、配置等本地痕迹换成该账号自己的（切换前自动备份，可回滚）。
- **会话隔离**：`projects`、`telemetry`、`file-history`、`shell-snapshots`、`cache`、`debug`、`plugins/data`、`config.json` 共 **8 个隔离面**，账号之间互不可见。
- **Clash 节点绑定**：每个账号可绑定 Clash Verge 的节点（默认组 `Auto-Claude`），切换账号时自动切节点。
- **一键新号**：向导式登录新账号（准备环境 → 手动完成 OAuth → 自动存成快照）。
- **备份与恢复**：快照备份带标签管理，切换前自动创建 `before-switch-to-<id>` 备份。
- **用量展示**：本地 jsonl 日志聚合 + OAuth API 用量，托盘弹窗随时看。
- **常驻托盘**：单实例、关窗到托盘、开机自启。

### 主窗口面板

当前本机状态 · 保存当前账号 · 一键新号 · 账号快照 · 网络节点（Clash）· Claude 用量 · 备份与恢复 · 数据位置（链接模式 / 配置目录 / 开机自启）· 遥测去关联 · 隐私环境变量注入

### 托盘

| 操作 | 行为 |
| --- | --- |
| 单击托盘图标 | 弹出用量窗口 |
| 双击托盘图标 | 打开主窗口 |
| 右键托盘图标 | 打开主窗口 / 刷新用量 / 退出 Claude Switcher |

> Windows 11 默认把新装的托盘图标收进「^」溢出区，找不到时见「常见问题」。

---

## 项目结构

```
claude-switcher-windows/
├── src-tauri/
│   ├── src/
│   │   ├── lib.rs                 # ★ 命令层：34 个 #[tauri::command] + 应用启动
│   │   ├── main.rs                # 桌面程序入口（无控制台窗口）
│   │   ├── accounts.rs            # 账号材料事务写入 + settings env 注入
│   │   ├── store.rs               # 账号快照库 + AES-GCM 加密
│   │   ├── credentials.rs         # 凭据读写/清除（平台差异收拢）
│   │   ├── isolation.rs           # 8 个隔离面的接管/激活/取消
│   │   ├── links.rs               # symlink / junction / 硬链接
│   │   ├── fsx.rs                 # 原子写入 + 锁重试
│   │   ├── jsonio.rs              # BOM / UTF-16 容错读写
│   │   ├── paths.rs               # 路径解析 + 目录保障 + ACL 收敛标记
│   │   ├── processes.rs           # Claude Code 进程检测/结束
│   │   ├── net.rs                 # reqwest HTTP（Clash + OAuth）
│   │   ├── clash.rs               # Clash 节点状态/切换/延迟检查
│   │   ├── usage.rs               # 用量统计 + 缓存
│   │   ├── tray.rs                # 托盘/弹窗定位
│   │   └── platform/              # ★ 唯一允许写 #[cfg] 的地方
│   │       ├── mod.rs             # 平台分发入口（imp）
│   │       ├── windows.rs         # 全部 Win32 细节
│   │       └── unix.rs            # 同名 API 的 Unix 实现（macOS 不回归）
│   ├── Cargo.toml
│   ├── tauri.conf.json            # 窗口/托盘/打包（WebView2 embedBootstrapper）
│   └── icons/
├── src/
│   ├── App.tsx                    # 主窗口（React 19 + TypeScript）
│   ├── components/ClaudeTrayPopup.tsx  # 托盘用量弹窗
│   └── *.css
├── docs/
│   └── upstream-baseline.md       # 上游基线记录 + 功能映射 + 升级审查流程
├── .github/workflows/
│   ├── ci.yml                     # push / PR 质量门禁（macOS + Windows）
│   ├── windows-build.yml          # 手动 / v* tag → MSI + NSIS
│   └── macos-build.yml            # 手动 → macOS app + DMG
├── AGENTS.md                      # 维护者交接说明（踩坑记录全文）
├── LICENSE                        # Apache-2.0
└── README.md                      # 本文件
```

---

## 运行形态总览

| 形态 | 入口 | 适用场景 |
| --- | --- | --- |
| **NSIS 安装版** | Release 中 `Claude Switcher_0.1.0_x64-setup.exe` | 普通用户，双击安装（推荐） |
| **MSI 安装版** | Release 中 `Claude Switcher_0.1.0_x64_zh-CN.msi` | 企业分发 / 域管理 |
| **免安装可执行文件** | 源码构建产物 `src-tauri\target\release\claude-switcher.exe` | 高手自用，便携 |
| **开发模式** | `npm run tauri dev` | 二次开发，带热更新 |

---

## 安装使用教程

### 选你的教程

| 你是谁 | 看哪一段 |
| --- | --- |
| 电脑新手，要一步一步点鼠标 | **小白版** |
| 会用终端、想源码构建 / 命令行排障 | **高手版** |

> **重要前提（官方验收边界，别跳过）**
>
> - 仅支持 **Windows 10/11 的 64 位（x64）**；32 位、Windows 7/8.1、原生 ARM64 不在支持范围。
> - 实测环境为 Windows 11 Pro x64（build 26300）；**Windows 10 未实机验证**。
> - 安装包未做代码签名，SmartScreen 提示属预期。
> - WebView2 运行时由安装包自动引导安装（`embedBootstrapper`），无需手动安装运行库。

### 一、小白版（只需要双击，适合第一次用）

1. **确认是 64 位系统**：设置 → 系统 → 系统信息 →「系统类型」应含 **64 位操作系统，x64**。若是 ARM64 或 32 位，本工具跑不了。
2. **下载安装包**：打开本仓库 [Releases](https://github.com/48ytw4q7zg-sudo/claude-switcher-windows/releases) → v0.1.0，下载 `Claude Switcher_0.1.0_x64-setup.exe`（推荐，NSIS 安装包）；也可用 `Claude Switcher_0.1.0_x64_zh-CN.msi`。SHA256 校验值在 Release 说明里。
3. **双击安装包**，按提示点「下一步」直到安装完成。
4. 若 Windows 弹出 **SmartScreen**「Windows 已保护你的电脑」，点「更多信息」→「仍要运行」。
   > 这是**未签名安装包**的正常提示。请只从本仓库 Release 下载，不要从来路不明的链接安装。
5. 从开始菜单打开 **Claude Switcher**。
6. **先保存当前账号**：在「保存当前账号」面板输入名称（如「Claude 主号」），点「保存快照」。前提：你已经在 Claude Code 中登录过至少一个账号。
7. **切换账号**：在「账号快照」里点对应卡片的「切换」。若 Claude Code 还在运行，工具会提示你**切换后重启 Claude Code**（正在运行的会话不会自动换账号）。
8. **托盘用法**：点右下角托盘的彩色图标弹出用量窗口；**双击**图标打开主窗口；**右键**托盘图标有「打开主窗口 / 刷新用量 / 退出 Claude Switcher」。
9. 主窗口点 **X** 只是**隐藏到托盘**，不会退出；要彻底退出请用托盘右键菜单或主窗口「退出」按钮。
10. （可选）在「数据位置」面板点「开启开机自启」，电脑重启后自动运行（只影响当前 Windows 用户）。
11. （可选）「一键新号」向导：选节点 → 准备环境 → 手动打开 Claude Code 完成 OAuth 登录 → 回到本工具点「登录完成后保存」。

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

# 4. 质量门禁（与 CI 相同，全部通过后再继续）
cd src-tauri
cargo fmt --check
cargo clippy --all-targets -- -D warnings   # 必须零警告
cargo test --lib                            # 必须全绿
cd ..
npx tsc --noEmit                            # 前端类型

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
- **`CLAUDE_CONFIG_DIR`**：若你设置了这个环境变量，本工具会跟随它读写配置目录，而不是写死 `%USERPROFILE%\.claude`；`~/.claude.json` 仍在用户主目录（claude 2.1.310 实测不会跟随搬家）。
- **数据备份**：所有快照与备份都在 `%USERPROFILE%\.claude-switcher\`，复制该目录即可迁移；加密主密钥在 Windows 凭据管理器（`claude-switcher-store-key`），换机需同用户名下保留该条目才能解出已加密凭据。

### 三、常见问题（两种教程都适用）

| 问题 | 处理 |
| --- | --- |
| SmartScreen 拦截安装包 | 未签名属预期。点「更多信息」→「仍要运行」。只从本仓库 Release 下载。 |
| 托盘图标找不到 | Windows 11 会收进「^」溢出区：右键任务栏 → 任务栏设置 →「其他系统托盘图标」→ 找到 Claude Switcher → 打开。 |
| 点 X 之后工具不见了 | X 只是隐藏到托盘，没有退出。托盘右键 →「退出 Claude Switcher」才彻底退出。 |
| 切换账号后 Claude Code 还是旧账号 | 切换只作用于**之后启动**的会话。重启 Claude Code 再试。 |
| 「链接模式」显示降级（junction） | 正常。打开开发者模式可升级为符号链接：「数据位置」面板有引导按钮。 |
| 换机 / 重装系统后快照解不开 | 加密主密钥在凭据管理器里，换机需复制 `~\.claude-switcher` 并保留同用户名下的 `claude-switcher-store-key` 条目。 |
| 删除账号快照时误删会话历史 | 删除范围由弹窗三选项确认（默认焦点不在破坏项上），会话历史删除**不可恢复**，请确认后再点。 |

---

## 验收边界（实机未验证项）

以下功能已实现并有单元测试或代码审查覆盖，但**未在真实 Windows 环境实机验证**（沙箱无显示器、无 Claude Code 登录态）：

| 项 | 状态 |
| --- | --- |
| 开机自启：任务管理器禁用后点「开启」能否真的启动 | 未实机验证 |
| 多显示器 + 任务栏在左/上/右的托盘弹窗定位 | 未实机验证 |
| Clash 实机节点切换（控制器地址归一化只有表格测试） | 未实机验证 |
| 配置目录切换后的凭据迁移与隔离重建 | 未实机验证 |
| 安装包升级 / 卸载回归（需要干净虚拟机） | 未实机验证 |

---

## 架构

### 技术栈

| 层 | 选型 |
| --- | --- |
| 桌面壳 | Tauri 2.11（`tauri.conf.json`，Windows x64，WebView2 `embedBootstrapper`，NSIS 简体中文 + WiX zh-CN） |
| 后端 | Rust（16 个模块，原 4229 行单文件 `lib.rs` 拆分）；34 个 `#[tauri::command]` |
| 前端 | React 19 + TypeScript + Vite + lucide-react；`src/App.tsx` 主窗口、`src/components/ClaudeTrayPopup.tsx` 托盘弹窗 |
| HTTP | `reqwest` + rustls（替代 `curl.exe`，读系统/环境代理，JSON body 走 socket 不走 argv） |
| 加密 | AES-256-GCM（`enc:v1:` + base64(nonce 12B ‖ ciphertext)）；主密钥存 Windows 凭据管理器 |
| 系统 API | `sysinfo`（进程）、`windows-sys`（文件 ID、reparse tag、SID、长路径）、`junction` crate、`keyring`（凭据管理器） |

### 设计原则（四条硬规则）

1. **cfg 收拢**：所有平台差异必须收拢在 `platform/{windows,unix}.rs`，业务代码不写 `#[cfg(windows)]`。新增平台能力时：先在 platform 加同名函数，再在业务里调 `platform::imp::xxx`。
2. **阻塞命令走 `blocking()`**：Tauri 2 中非 `async` 命令跑在主线程，任何可能阻塞的（网络、进程扫描、目录 rename、凭据读取）都必须 `blocking(|| ...)` 包装。**不用** `#[tauri::command(async)]` 包同步函数（会跑在 tokio 工作线程，调 `reqwest::blocking` 有 panic 风险）。
3. **写文件一律原子**：`fsx::write_atomically`（临时文件 + rename）。绝不用 `fs::write` 直接写 `store.private.json` / `.credentials.json` / `~/.claude.json`——截断式写入中途崩溃会丢数据。rename 失败时**不删**目标文件（旧数据必须保留）。
4. **凭据与密钥边界**：`settings_json` 里的认证字段（`AUTH_ENV_KEYS` + `apiKeyHelper`）落盘前 `split_auth_settings` 拆出加密，读时 `restore_auth_settings` 合并回去；解密路径**绝不生成新密钥**（缺密钥报错让用户恢复，绝不覆盖）；`keyring::Error` 除 `NoEntry` 外一律致命（PlatformFailure 可能是 DPAPI 失败，当「不存在」会铸新钥覆盖旧数据）。

### 模块划分（src-tauri/src/，16 个模块）

| 模块 | 职责 |
| --- | --- |
| `lib.rs` | 34 个命令处理器、返回类型、应用启动（单实例、关窗到托盘）、日志与 panic hook |
| `main.rs` | 桌面程序入口（`windows_subsystem = "windows"` 无黑窗），调 `claude_switcher_lib::run()` |
| `accounts.rs` | 账号材料事务写入：Merge / FullReplace 两种语义、回滚「先凭据后 JSON」、settings env 注入（遥测 + runtime） |
| `store.rs` | `store.private.json` 读写；AES-GCM 加解密；`split_auth_settings` / `restore_auth_settings`；密钥「只读现有、解密绝不铸新钥」 |
| `credentials.rs` | Windows 凭据文件 / macOS Keychain 的读写与清除（差异收拢进 platform） |
| `isolation.rs` | 按 profile 接管/激活 `projects`、`telemetry`、`file-history`、`shell-snapshots`、`cache`、`debug`、`plugins/data`、`config.json` 共 8 个隔离面 |
| `links.rs` | 符号链接 / junction / 硬链接的创建、识别（含悬空链接）、移除与链接模式上报 |
| `fsx.rs` | 原子写入（`.原文件名.tmp-<rand>` + rename）、rename/删除锁重试（Windows 错误 5/32/33 短退避）、错误人性化 |
| `jsonio.rs` | 文本读取自动处理 UTF-8 BOM 与 UTF-16LE/BE（记事本改过的 settings.json 不会让界面打不开） |
| `paths.rs` | 路径解析（`CLAUDE_CONFIG_DIR` → `USERPROFILE` → `home_dir`）与目录保障、ACL 一次性收敛标记 |
| `processes.rs` | Claude Code CLI 检测与结束（精确匹配防误杀，`taskkill /T` → `/T /F`） |
| `net.rs` | Clash 控制器 / OAuth 请求、默认端口真实探测（9097 → 9090）、代理回退与超时预算 |
| `clash.rs` | 节点组状态、切换、节点 alive 与到 `api.anthropic.com` 的延迟检查 |
| `usage.rs` | 本地日志聚合 + OAuth usage/profile 的 TTL 缓存与 in-flight 合并 + 本地快照 45 秒缓存 |
| `tray.rs` | 托盘 tooltip、弹窗定位（工作区/多屏）、失焦防抖、右键菜单 |
| `platform/mod.rs` | **平台分发唯一入口**：`#[cfg]` 只出现在这里与 `windows.rs` / `unix.rs`；两文件提供同名 API |

### 命令清单（34 个 `#[tauri::command]`，按域分组）

| 域 | 命令 |
| --- | --- |
| 本机状态 | `get_status`、`get_platform`、`inspect_local_files`、`get_diagnostic_info` |
| 配置目录 | `get_claude_config_dir`、`get_claude_config_dir_override`、`set_claude_config_dir` |
| 账号快照 | `list_profiles`、`capture_current_profile`、`switch_profile`、`rename_profile`、`delete_profile` |
| 一键新号 | `prepare_new_account_login`、`complete_new_account_login`、`cancel_pending_new_account_login` |
| Clash | `get_clash_status`、`switch_clash_node`、`switch_profile_clash_node`、`set_profile_clash_binding`、`set_profile_runtime_binding` |
| 用量 | `get_claude_usage` |
| 备份 | `create_backup`、`list_backups`、`restore_backup` |
| 窗口 / 托盘 | `show_main_window_cmd`、`hide_main_window_cmd`、`quit_app_cmd` |
| 设置 | `set_telemetry_mode`、`set_autostart`、`get_autostart`、`open_developer_settings` |
| 数据目录 | `open_data_dir`、`open_logs_dir`、`get_logs_dir` |

### 关键数据流

```
React 主窗口 / 托盘弹窗
        │  invoke（34 个命令）
        ▼
lib.rs（命令层，阻塞操作全部经 blocking() 移出主线程）
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

### 数据与存储布局

```text
%USERPROFILE%\
├── .claude\                        # Claude Code CLI 配置目录（跟随 CLAUDE_CONFIG_DIR）
│   ├── .credentials.json           # OAuth 凭据主存储（本工具直接读写，官方主存储）
│   ├── settings.json               # 全局设置（认证字段加密拆分后入 store）
│   ├── config.json                 # 被隔离（链接 → session-profiles/<id>/config.json）
│   ├── projects\                   # 会话历史（被隔离）
│   └── telemetry\ file-history\ shell-snapshots\ cache\ debug\ plugins\data\   # 被隔离
├── .claude.json                    # Claude Code 全局配置（CLAUDE_CONFIG_DIR 不搬家，实测）
└── .claude-switcher\               # 本工具私有数据（快照与备份全在这里，复制即迁移）
    ├── store.private.json          # 账号快照库（OAuth blob AES-GCM 加密）
    ├── .acl-hardened               # 目录 ACL 一次性收敛标记（失败下次启动重试）
    ├── backups\                    # 备份（切换前自动 before-switch-to-<id>）
    ├── session-profiles\<id>\      # 每个账号的 7 个隔离目录 + config.json 副本
    ├── session-backups\            # 接管（adopt）时的中转备份
    ├── clash.json                  # Clash 控制器覆盖（可选，不存在则自动探测）
    └── logs\claude-switcher.log    # 本机日志（1MB 滚动）

Windows 凭据管理器：claude-switcher-store-key（32B AES-256-GCM 主密钥）
```

### 安全模型

- **C2 加密设计**：只加密敏感字段——`keychain_password`（OAuth blob）与认证类 settings 字段（`AUTH_ENV_KEYS` + `apiKeyHelper`）；其余字段明文便于调试。密文格式 `enc:v1:` + base64(nonce 12B ‖ ciphertext)，nonce 每次随机。旧明文向后兼容：不以 `enc:v1:` 开头视为明文，下次落盘自动加密。
- **主密钥只读现有**：解密路径缺密钥直接报错让用户恢复，**绝不自动生成新密钥覆盖旧数据**。`keyring::Error` 除 `NoEntry` 外一律按致命错误处理。
- **原子写**：所有落盘走临时文件 + rename；rename 失败**不删**目标文件。
- **权限收敛**：`~/.claude-switcher` 创建时一次性 icacls（当前用户 SID、先授权再断继承、子项继承），不动 Claude 自己的文件；凭据文件在用户 profile 之外时额外收敛为「当前用户 + SYSTEM」。
- **进程检测精确匹配**：只匹配 `claude.exe` 或 `node`/`bun` 且命令行含 `@anthropic-ai/claude-code`，并排除本工具自身与 Claude Desktop（`--type=` 是 Electron 子进程标志），不会误杀。
- **隐私日志**：切号日志只记账号 id 前 8 位；token 不显示在 UI，不进入仓库，不上传任何凭据。

### 核心流程

#### 切换账号（switch_profile）

1. 校验目标快照存在。
2. 检测 Claude Code 仍在运行 → 附加 warning（切换不作用于已运行会话，提示重启）。
3. 自动创建备份 `before-switch-to-<id>`。
4. 刷新**当前**账号快照（把 live 状态并入当前 profile，避免丢新会话）。
5. 接管（adopt）当前账号的 live 隔离目录（回收链接，内容接回当前账号）。
6. 切换 Clash 节点（若该账号绑定了且启用）。
7. 写入新账号材料：凭据 → settings → `~/.claude.json`，**先凭据后 JSON**，带备份回滚点。
8. 注入隐私环境变量（遥测模式 + runtime 的 `TZ`/`LANG`/`LC_ALL`）。
9. 激活新账号的隔离链接。**失败降级为 warning 不阻断**——此刻材料已切换成功，返回 Err 会让「界面显示失败、磁盘实际已切」，用户重跑一次切换即可补上链接。
10. 落盘 `current_profile_id` + 日志（含链接模式与 Clash 结果）。

#### 一键新号（prepare → complete）

1. **准备环境**（prepare）：选节点 → 备份当前登录 → 保存现场 → 清空 OAuth 凭据并激活临时隔离环境。
2. 用户**手动打开 Claude Code 完成 OAuth 登录**。
3. **登录完成后保存**（complete）：抓取新凭据 → 存成新账号快照（可取消恢复现场）。

#### 删除账号（delete_profile）

三选项确认弹窗（取消 / 仅删除快照 / 同时删除会话历史——破坏性选项不设默认焦点）→ 取消隔离链接（**只删指向该账号的链接**，任一项失败即中止，不删任何数据）→ 删除会话历史目录 → 删除快照条目。**不删除 Claude Code 当前的登录态**。无论目录清理是否成功都刷新列表，保证界面与磁盘一致。

#### 备份与还原

- `create_backup`（带标签）/ `list_backups` / `restore_backup`；备份存 `~/.claude-switcher\backups\`。
- 切换账号前自动备份，`restore_backup` 从备份快照回滚账号材料。

### 会话隔离机制

- **8 个隔离面**：7 个目录（`projects`、`telemetry`、`file-history`、`shell-snapshots`、`cache`、`debug`、`plugins/data`）+ 1 个文件（`config.json`）。激活后 `~/.claude` 下的这些位置变成指向 `~/.claude-switcher\session-profiles\<id>\` 的链接，Claude Code 读写时落盘到账号自己的副本。
- **链接模式自动降级**：开发者模式开启 → 符号链接；未开启 → junction（目录，无需特权）/ 硬链接（文件，同卷同索引识别）。「数据位置」面板显示当前模式并提供开发者模式引导。
- **悬空链接识别**：目标被删后 `exists()` 返回 false 但必须仍判为链接（属性位是 reparse point 即保守判为链接），否则激活会走错「创建目录」分支。
- **接管（adopt）**：切换前把当前账号的 live 内容接回其 profile，避免新会话丢失；用 `session-backups\` 做中转。

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
- 原子写入、文件锁重试（32/33 退避、5 只重试一次）、悬空链接识别、路径归一化（`\\?\` 前缀 / 大小写 / 8.3 短名 / 正斜杠统一，含 `C:\Users\A` vs `C:\Users\AB` 前缀陷阱防护）
- 读 JSON 自动处理 UTF-8 BOM 与 UTF-16（记事本改过的 settings.json 不会让界面打不开）
- 事务回滚顺序「先凭据后 JSON」；账号材料已切换后链接激活失败降级为 warning（避免「显示失败、实际已切」）
- 删除账号三选项确认弹窗（破坏性选项不设默认焦点）
- 本机日志（`~/.claude-switcher/logs/`，1MB 滚动）+ panic hook + 诊断信息一键复制
- 新增单元测试：链接识别、悬空链接、路径归一化、原子写入、merge/scrub 逻辑、BOM/UTF-16 解码、进程匹配表格、Windows 反斜杠 `subagents` 过滤、删除链路 `deactivate_in` 等

### 踩过的坑（摘要，全文见 AGENTS.md）

| # | 坑 | 教训 |
| --- | --- | --- |
| 1 | winreg `open_subkey` 是 KEY_READ 只读，`set_value` 必拒绝访问 | 写注册表必须 `create_subkey`（KEY_ALL_ACCESS） |
| 2 | winreg 的 `Vec<u8>` 没实现 FromRegValue | 读二进制值必须 `get_raw_value()` 拿 `RegValue.bytes` |
| 3 | `icacls` 的 `*` 前缀只接受 SID，`*SYSTEM:` 非法 | 用真实 SID `*S-1-5-18`，且**先 grant 再 /inheritance:r** |
| 4 | Windows 路径比较直接比会误判 | 归一化 `\\?\` 前缀、大小写、`/` vs `\`、尾分隔符、8.3 短名 |
| 5 | 悬空 junction 打不开句柄，拿不到 reparse_tag | 属性位是 reparse point 就保守判为链接 |
| 6 | `entry.file_type()` 不跟随链接 | 遍历目录时链接子目录要回退 `metadata()` |
| 7 | GUI 启动时 `std::env::args()` 读不到终端环境变量 | 提供 `claude-config-dir.txt` 手动覆盖文件 |
| 8 | `CLAUDE_CONFIG_DIR` 不会让 `.claude.json` 搬家（claude 2.1.310 实测） | 凭据跟随、全局配置不跟随，`claude_json_path()` 固定 home |
| 9 | Claude Desktop 的 renderer/gpu 进程也带 `--type=` | 进程检测用 `--type=` 排除 Desktop；`WindowsApps` 排除只对 `claude.exe` 生效 |
| 10 | reqwest `default-features = false` 丢掉 `system-proxy` | Clash 系统代理读不到；还要 `rustls-tls-native-roots` 信任 Windows 证书库 |

### 质量门禁与测试

本地门禁（与 CI 相同，全部必须通过）：

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings   # 必须零警告
cargo test --lib                            # 必须全绿
npx tsc --noEmit                            # 前端类型
npm run tauri build                         # 出 MSI + NSIS
```

当前测试状态：**52 通过 + 1 ignored**（`encrypt_decrypt_roundtrip` 需实机凭据存储）。测试覆盖亮点：链接识别与悬空链接、路径归一化（含 8.3 短名）、原子写入、merge/scrub 逻辑、BOM/UTF-16 解码、进程匹配表格（16 例）、Clash 控制器地址归一化（11 例，含 IPv6）、`is_under` 前缀陷阱、删除链路 `deactivate_in`（只删本账号链接）。

---

## 隐私与安全

- 账号快照只保存在本机 `%USERPROFILE%\.claude-switcher\`，不会上传任何账号凭据。
- OAuth blob 写入 store 前用 AES-256-GCM 加密，主密钥在 Windows 凭据管理器；token 不显示在 UI，也不进入本仓库。
- 进程检测只匹配 `claude.exe` 或 `node`/`bun` 且命令行含 `@anthropic-ai/claude-code`，并排除本工具自身与 Claude Desktop，**不会**因为命令行里出现 `claude-code` 字样就误杀别的进程。
- 本仓库 CI 只构建源码，不访问本机凭据、`~/.claude-switcher` 数据或 Claude 账号快照。

## 构建与发布

- `CI`（`.github/workflows/ci.yml`）：push / PR 时在 macOS 与 Windows runner 上跑前端构建、`cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test --lib`、Tauri build。（macOS runner 的 host 与 target 不同，会额外按 target 再跑一遍 clippy；Windows runner 两者相同，不重复。）
- `Windows Build`（`.github/workflows/windows-build.yml`）：手动触发或打 `v*` tag，产出 MSI / NSIS 并上传为 Actions 产物。**Release v0.1.0 的安装包即由此工作流构建。**
- `macOS Build`（`.github/workflows/macos-build.yml`）：手动触发，产出 macOS app + DMG（供上游功能回归对比）。
- 未配置代码签名证书；首次运行安装包会有 SmartScreen 提示，属预期。有条件可接 Azure Trusted Signing 或自持证书消除该提示。

## 出处与许可

- 本仓库是 [VallierDev/claude-switcher](https://github.com/VallierDev/claude-switcher)（macOS 版）的 Windows 迁移版，迁移基线 commit [`6897984`](https://github.com/VallierDev/claude-switcher/commit/68979843313a0cb7da3cda32765184436ba9598e)，逐功能对等迁移，平台差异替换为 Windows 等价实现。基线记录与功能映射见 [docs/upstream-baseline.md](docs/upstream-baseline.md)。
- 本仓库 LICENSE 为 **Apache-2.0**（见 `LICENSE` 文件）。
- **上游仓库未声明许可证**（无 LICENSE 文件）。若上游后续补充许可，本仓库的许可应与之对齐；在此之前请联系上游作者确认授权范围。
- 涉及 Anthropic / Claude Code 的商标与名称归其权利人所有。本工具只在本地操作 Claude Code 已生成的文件，不修改、不分发任何 Anthropic 专有代码。

## 致谢

- 上游原项目与作者：**[@VallierDev](https://github.com/VallierDev)** — [VallierDev/claude-switcher](https://github.com/VallierDev/claude-switcher)。本 Windows 迁移版在保持原功能的基础上做了系统适配与加固，感谢上游的设计。
- 同名工具生态：**[@YOURSJEYO](https://github.com/YOURSJEYO)** — [YOURSJEYO/claude-switcher](https://github.com/YOURSJEYO/claude-switcher)。与本仓库定位不同（Claude 桌面版环境管理器），感谢其在同类工具上的工作。
- 本仓库维护者：[48ytw4q7zg-sudo](https://github.com/48ytw4q7zg-sudo)。

## 维护与贡献

- 工程说明（构建命令、架构约定、踩坑记录全文）：见 [AGENTS.md](AGENTS.md)。
- 上游基线、功能映射与升级差异审查流程：见 [docs/upstream-baseline.md](docs/upstream-baseline.md)。
- 提交 PR 前请跑完「质量门禁与测试」一节的本地门禁；CI 会在 macOS 与 Windows 上再跑一遍。
