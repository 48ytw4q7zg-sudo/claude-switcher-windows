# Claude Switcher（Windows 版）

一个 Windows 桌面工具，**同时管理 Claude Code CLI 与 Claude Desktop 桌面版**：
- **CLI**：保存账号快照、切换 OAuth 凭据、按账号隔离 Claude Code 本地痕迹（会话历史 / 配置 / 遥测等 8 个隔离面），并把每个账号绑定到 Clash Verge 的 `Auto-Claude` 节点；
- **桌面版**：`%APPDATA%\Claude` 整体快照/切换；
- **环境安全**：14 项安全检查、一键修复、保镖 kill-switch、时区/地区锁定、Clash 规则托管、STUN/WebRTC 泄漏探测、指纹与 CLI 体检、加密快照、自动更新；
- **多账号增强（v0.3.0）**：按终端并行多账号（每账号独立配置目录）、托盘一键切换、额度阈值提醒 + 一键切换、MCP 服务器管理、便携版 zip。
- **缺陷/竞态收口（v0.4.0）**：便携版数据隔离到 `ClaudeSwitcherData` 子目录、账号库 `with_store` 互斥、独立用量缓存（不解密账号库）、并行终端播种/执行策略/非阻塞探测、对账不覆盖空凭据 + uuid/邮箱回退 + 收养开关、MCP 乐观并发 + 通用 cmd shim、通知 5h/7d 双窗口去重、托盘轻量读取，并新增命令行入口 `--list`/`--status`/`--switch`。

基于 **Tauri 2 + Rust + React 19 + TypeScript** 构建，桌面壳为 Windows 原生 WebView2。

---

## 一、原项目地址与平台分工（不同项目对应不同系统）

本项目**融合了两个上游的全部功能**，它们是**面向不同系统的独立项目**，请勿混用：

| 项目 | 地址 | 面向系统 | 说明 |
| --- | --- | --- | --- |
| 上游 A（CLI 切换器） | [VallierDev/claude-switcher](https://github.com/VallierDev/claude-switcher) | **macOS** | macOS 原版，同为 Tauri 2 + Rust + React。本仓库的 CLI 账号切换迁移基线为 commit [`6897984`](https://github.com/VallierDev/claude-switcher/commit/68979843313a0cb7da3cda32765184436ba9598e)。感谢原作者 **[@VallierDev](https://github.com/VallierDev)**。 |
| 上游 B（环境/桌面版） | [YOURSJEYO/claude-switcher](https://github.com/YOURSJEYO/claude-switcher) | **macOS 为主 + Windows（Beta）+ Linux（Beta）** | bash/PowerShell/Swift 实现的环境安全套件。本仓库的第二个融合基线为 commit [`870c4ca`](https://github.com/YOURSJEYO/claude-switcher/commit/870c4ca0754234965878ef58144d7a755d965037)。感谢原作者 **[@YOURSJEYO](https://github.com/YOURSJEYO)**。 |
| **本仓库** | [48ytw4q7zg-sudo/claude-switcher-windows](https://github.com/48ytw4q7zg-sudo/claude-switcher-windows) | **Windows 10 / 11（x64）** | 把两个上游的能力融合进**同一个 Tauri 应用**，并完成 Windows 适配、模块化重构与加固。 |

> **关于平台分工**：上游 A 是 macOS 的 Claude Code CLI 账号切换器；上游 B 以 macOS 为主，同时提供 Windows（Beta，PowerShell + WPF）与 Linux（Beta，bash + systemd）版本。**三者是不同的项目、面向不同的操作系统**。本仓库是上游 B 的 Windows 能力的**原生重写版**——不再依赖 PowerShell/WPF 脚本，而是用 Rust + React 实现，与上游 A 的 Tauri 技术栈统一，因此同时具备两边的全部功能。
>
> **功能融合说明**：本仓库把两个上游的能力统一到一个 Tauri 应用中——
>
> | 维度 | 来自 VallierDev（基线 A） | 来自 YOURSJEYO（基线 B） |
> | --- | --- | --- |
> | 管理对象 | Claude Code CLI（`~/.claude`、`~/.claude.json`、OAuth 凭据） | Claude Desktop 桌面版（`%APPDATA%\Claude`） |
> | 核心能力 | 账号快照 / 凭据切换 / 会话隔离 / Clash 节点绑定 / 用量 | 14 项检查、一键修复、保镖/看门狗、地区锁定、规则托管、STUN/指纹/CLI 体检、加密快照、自动更新 |
>
> 上游 B 的 PowerShell / bash / Swift 脚本仅作为**逐行行为基准**，所有能力均用 Rust + React 重新实现。Windows 上没有沿用 macOS 的 Keychain / `pgrep` / `security`，而是替换为等价的 Rust + 系统 API。
>
> 早期版本的本文件曾写「不包含 YOURSJEYO 的任何代码或功能」，**该表述已作废**：项目 owner 已明确要求融合全部功能。

### 当前交付状态

| 项 | 状态 |
| --- | --- |
| 源码 | `main` 分支（本仓库） |
| 安装包 | **Release v0.5.0**（v0.6.0 合并后由 `.github/workflows/windows-build.yml` 自动构建 MSI + NSIS + 便携 zip），产物来源可审计，SHA256 见 Release 说明 |
| 测试 | `cargo test --lib` **369 passed / 0 failed / 0 ignored**；`cargo clippy --all-targets -- -D warnings` 零警告；`npx tsc --noEmit` 通过 |
| 实测环境 | 无显示器环境本地构建；Windows 10/11 端到端实机验证项见文末清单 |
| 代码签名 | **未签名**，干净系统首次运行弹 SmartScreen 属预期 |

---

## 二、项目结构

```text
claude-switcher-windows/
├── src-tauri/
│   ├── src/
│   │   ├── lib.rs                 # ★ 命令层：#[tauri::command] + 应用启动（--guard 分发）
│   │   ├── main.rs                # 桌面程序入口（无控制台窗口）
│   │   ├── accounts.rs            # 账号材料事务写入 + settings env 注入
│   │   ├── reconcile.rs           # 切换前对账 + 自动收养（Current/Other/Unknown）
│   │   ├── parallel.rs            # 按终端并行多账号（独立 CLAUDE_CONFIG_DIR）
│   │   ├── mcp.rs                 # MCP 服务器管理（stdio cmd /c 包装）
│   │   ├── notify_state.rs        # 额度阈值通知状态（每周期每档一次）
│   │   ├── store.rs               # 账号快照库 + AES-GCM 加密（KeyBackend trait）
│   │   ├── credentials.rs         # 凭据读写/清除（平台差异收拢）
│   │   ├── isolation.rs           # 8 个隔离面的接管/激活/取消
│   │   ├── links.rs               # symlink / junction / 硬链接
│   │   ├── fsx.rs                 # 原子写入 + 锁重试
│   │   ├── jsonio.rs              # BOM / UTF-16 容错读写
│   │   ├── paths.rs               # 路径解析 + 目录保障 + ACL 收敛标记
│   │   ├── processes.rs           # Claude Code CLI 进程检测/结束
│   │   ├── net.rs                 # reqwest HTTP（Clash 控制器 + OAuth）
│   │   ├── clash.rs               # Clash 节点状态/切换/延迟检查
│   │   ├── usage.rs               # 用量统计 + 独立 usage-cache.json
│   │   ├── tray.rs                # 托盘/弹窗定位（轻量读取）
│   │   ├── cli.rs                 # 命令行入口 --list/--status/--switch
│   │   ├── export.rs              # 加密快照导出/导入（CSBK1：Argon2id + AES-GCM）
│   │   ├── update.rs              # GitHub Release 版本检查
│   │   ├── appconfig.rs           # 全局配置 appconfig.json（country/tz/locale/proxy_mode/proxy_group/webrtc）
│   │   ├── egress.rs              # 出口 IP 探测（Cloudflare trace + ipinfo）+ 住宅/机房 ASN
│   │   ├── region.rs              # 国家→时区/locale/GeoID 映射、IANA→Windows 时区
│   │   ├── stun.rs                # UDP STUN 探针（WebRTC 泄漏判定）
│   │   ├── desktop.rs             # Claude Desktop 快照/捕获/切换/删除（含回存与回滚）
│   │   ├── guard.rs               # 保镖 kill-switch + 时区看门狗 + 计划任务
│   │   ├── rules.rs               # Clash 模式识别 + Script.js 托管规则 + 内核验证/回滚
│   │   ├── checks.rs              # 14 项安全检查 + 静默总检 + 一键修复
│   │   ├── keep.rs                # 跨身份保留 keep-in-workspace（stage/merge）
│   │   ├── diagnostics.rs         # open-safe / 代理诊断 / 指纹 / cli-info
│   │   ├── bin/cs.rs              # 控制台子系统 cs.exe（--list/--status/--switch/run）
│   │   ├── dirbinding.rs          # 目录绑定标记 + cs run（CLAUDE_CONFIG_DIR）
│   │   ├── userpath.rs            # 用户 PATH（HKCU，REG_EXPAND_SZ + WM_SETTINGCHANGE）
│   │   ├── shortcuts.rs           # 开始菜单 .lnk（每账号 --switch-id）
│   │   ├── naming.rs              # 文件名合法化 + 保留设备名
│   │   ├── token_status.rs        # 令牌状态纯函数（有效/即将过期/已过期/未知）
│   │   ├── provider.rs            # 第三方供应商（加密 token，受管 env 键）
│   │   ├── wsl.rs                 # WSL 实验集成（stdin 传凭据，默认关）
│   │   ├── sanitize.rs            # 诊断脱敏（敏感键/令牌形态/邮箱/用户名路径）
│   │   ├── workspace.rs           # Skills/命令/子代理/CLAUDE.md 启用停用
│   │   ├── permissions.rs         # 权限与钩子编辑器（合并写入，保留未托管字段）
│   │   └── platform/              # ★ Windows 平台适配（唯一允许写 cfg 的地方）
│   │       ├── mod.rs             # 平台入口（非 Windows 目标直接编译报错）
│   │       └── windows.rs         # 全部 Win32 细节
│   ├── Cargo.toml
│   ├── tauri.conf.json            # 窗口/托盘/打包（WebView2 embedBootstrapper）
│   ├── windows-app.manifest       # asInvoker / longPathAware / comctl32 v6
│   └── icons/
├── src/
│   ├── App.tsx                    # 主窗口（React 19 + TypeScript）
│   ├── App.css
│   ├── main.tsx
│   ├── useModalDialog.ts          # 弹窗 Esc/焦点陷阱/滚动锁定
│   ├── components/
│   │   ├── ClaudeTrayPopup.tsx    # 托盘用量弹窗
│   │   ├── SecurityPanel.tsx      # 14 项安检 + 一键修复
│   │   ├── GuardPanel.tsx         # 保镖安装/巡检
│   │   ├── RegionPanel.tsx        # 地区锁定 + 代理客户端
│   │   ├── ClashModePanel.tsx     # Clash 模式/规则/WebRTC 策略/代理组
│   │   ├── DesktopProfiles.tsx    # Claude Desktop 账号管理
│   │   ├── QuotaReminder.tsx      # 额度阈值提醒 + 一键切换
│   │   ├── ReconcileSettings.tsx  # 对账自动收养开关
│   │   ├── McpPanel.tsx           # MCP 服务器管理
│   │   ├── PrivacyTools.tsx       # open-safe / 代理诊断 / 指纹 / cli-info
│   │   ├── IntegrationPanel.tsx   # PATH / 目录绑定 / 开始菜单 / 诊断包
│   │   ├── ProviderPanel.tsx      # 第三方供应商
│   │   ├── WslPanel.tsx           # WSL 集成（实验）
│   │   ├── WorkspacePanel.tsx     # 工作区资产管理
│   │   ├── PermissionPanel.tsx    # 权限与钩子编辑器
│   │   └── types.ts               # 前后端契约类型
├── docs/
│   ├── upstream-baseline.md       # 双上游基线记录 + 功能对等矩阵 + 升级审查流程
│   ├── backend-interfaces.md      # 平台层契约
│   ├── qa-report.md               # QA 报告（含第二轮全量复核的 19 项修复记录）
│   ├── qa-v0.3.0.md               # v0.3.0 账号管理增强 QA 报告
│   ├── qa-v0.3.1.md               # v0.3.1 PowerShell 路径补丁 QA 报告
│   ├── qa-v0.4.0.md               # v0.4.0 缺陷/竞态收口 QA 报告
│   ├── release-v0.1.0.md          # v0.1.0 发布记录
│   └── prior-session-recovery.md  # 前序会话恢复报告
├── .github/workflows/
│   ├── ci.yml                     # push / PR 质量门禁（Windows）
│   ├── windows-build.yml          # 手动 / v* tag → MSI + NSIS + Release
├── AGENTS.md                      # 维护者交接说明（踩坑记录全文）
├── LICENSE                        # Apache-2.0
└── README.md                      # 本文件
```

---

## 三、运行形态总览

| 形态 | 入口 | 适用场景 |
| --- | --- | --- |
| **NSIS 安装版** | Release 中 `ClaudeSwitcher_0.4.0_x64-setup.exe` | 普通用户，双击安装（推荐） |
| **MSI 安装版** | Release 中 `ClaudeSwitcher_0.4.0_x64_zh-CN.msi` | 企业分发 / 域管理 |
| **便携版 zip** | Release 中 `ClaudeSwitcher-portable.zip` | 解压即用，数据随 exe 目录的 `ClaudeSwitcherData` 携带 |
| **命令行** | exe 加 `--list` / `--status` / `--switch <名称>` | 终端脚本 / 无 GUI 调用 |
| **开发模式** | `npm run tauri dev` | 二次开发，带热更新 |

### 这是什么、能做什么

Claude Code CLI 的登录凭据、全局配置和会话历史都散落在用户目录里，多账号使用时会互相覆盖。本工具把这些材料按账号做**快照 + 切换 + 隔离**，并对 Claude Desktop 桌面版做同样的事，外加一整套环境安全审计：

- **CLI 账号管理**：保存当前账号（凭据 + `~/.claude.json` + `settings.json`）→ 一键切换（自动备份、可回滚）→ 一键新号向导。
- **会话隔离**：`projects`、`telemetry`、`file-history`、`shell-snapshots`、`cache`、`debug`、`plugins/data`、`config.json` 共 **8 个隔离面**，账号之间互不可见。
- **Clash 节点绑定**：每个账号可绑定 Clash Verge 节点（默认组 `Auto-Claude`），切换账号时自动切节点。
- **Claude Desktop 管理**：`%APPDATA%\Claude` 整体快照/切换，**切换前自动把当前使用变更回存**，失败自动回滚。
- **环境安全**：14 项检查 + 一键修复 + 保镖 kill-switch（代理掉线秒级杀进程）+ 时区看门狗。
- **隐私工具**：STUN 泄漏探测、一次性隔离浏览器、代理诊断、系统指纹体检、CLI 安装体检。
- **数据迁移**：加密快照导出/导入（CSBK1），换机冷备。

### 多账号增强（v0.3.0）

- **切换前对账 + 自动收养**：切换前读取 live 身份，分为 Current / Other(id) / Unknown(uuid)。手动登录过别的号会被识别并回写对应账号（提示「检测到手动换号」）；live 身份在仓库里没有对应账号时，用 live 材料自动新建账号（名「自动收养-<邮箱或 uuid 前8>-<MMdd-HHmm>」，标注可重命名）。live 缺字段不会中断切换。
- **托盘一键切换**：右键托盘菜单按账号动态生成（当前账号 ● 标记，超长截断，>10 个收进「切换账号」子菜单），点击即切换，结果弹系统通知并重建菜单。
- **按终端并行多账号**：每个账号开一个独立终端，`CLAUDE_CONFIG_DIR` 指向 `~/.claude-switcher/accounts/<id>/`，多终端可同时登录不同账号；优先用 Windows Terminal（`-EncodedCommand` UTF-16LE base64），未装则退回 `cmd start powershell`；共享 skills 走复制。与「全局切换」（接管唯一的 `~/.claude`）互不影响。
- **额度阈值通知**：80% / 95% 两档系统通知，每个重置周期每档只通知一次（`notify-state.json` 原子写）。
- **额度阈值提醒 + 一键切换**：当前账号达阈值（默认 90%，可配）时提醒，一键切到缓存里余量最多的账号；**只做提醒，不做后台自动换号**（其他账号用量会过时、后台刷新令牌风险高）；默认关闭。
- **MCP 服务器管理**：管理全局 `~/.claude.json` 的 `mcpServers` 与项目 `.mcp.json`；`npx/npm/pnpm/yarn` 启动的 stdio 自动 `cmd /c` 包装；校验 stdio/http/sse 字段；密钥类 env 不进日志。
- **便携版 zip**：exe 旁放 `portable.flag` 即进入便携模式，数据目录与 WebView2 用户数据都指向 exe 目录，整体解压即用、拷走即迁移。

### 主窗口面板

当前本机状态 · 保存当前账号 · 一键新号 · 账号快照（含并行终端）· 网络节点（Clash）· Claude 用量 · 备份与恢复 · 数据位置（链接模式 / 配置目录 / 开机自启）· 遥测去关联 · **环境安检**（14 项 + 一键修复）· **保镖**（安装 / 立即巡检 / 卸载）· **地区与代理客户端**（set-region / set-client / 代理组）· **Clash 模式与规则**（模式识别 / 写规则 / WebRTC 策略）· **Claude Desktop 账号** · **额度阈值提醒** · **MCP 服务器** · **隐私与诊断工具**

### 托盘

- **左键单击**：弹出用量窗口；**左键双击**：打开主窗口。
- **右键菜单**：账号列表（当前账号 ● 标记，点击一键切换）+ 打开主窗口 / 刷新用量 / 退出。
- 主窗口点 X 只是隐藏到托盘，彻底退出走托盘菜单。

### 便携版

解压 `ClaudeSwitcher-portable.zip`，exe 同目录已附带空的 `portable.flag`，双击 `ClaudeSwitcher.exe` 即以便携模式运行：账号库、日志、配置与 WebView2 数据全部落在 exe 旁的 **`ClaudeSwitcherData` 子目录**（不直接写 exe 目录，也不写注册表/用户目录）；整个目录拷走即迁移，删除即净。

### 命令行入口

发布版是 GUI 子系统，默认无控制台；在终端对 exe 加子命令时会自动附加父控制台再输出：

```powershell
.\ClaudeSwitcher.exe --list                 # 列出全部账号（当前账号 [*]）
.\ClaudeSwitcher.exe --status               # 显示当前账号
.\ClaudeSwitcher.exe --switch "Claude 主号"  # 按名称精确切换
```

若已有一个实例在运行，`--switch` 会经单实例机制转交给运行实例执行，不会启动第二个进程并发写账号库。命令行输出的真实渲染需在实机终端验证。

---

## 四、安装使用教程

1. **确认是 64 位系统**：设置 → 系统 → 系统信息 →「系统类型」应含 **64 位操作系统，x64**。若是 ARM64 或 32 位，本工具跑不了。
2. **下载安装包**：打开本仓库 [Releases](https://github.com/48ytw4q7zg-sudo/claude-switcher-windows/releases) → 最新版，下载 `ClaudeSwitcher_0.4.0_x64-setup.exe`（推荐，NSIS 安装包）；也可用 `ClaudeSwitcher_0.4.0_x64_zh-CN.msi`；想免安装则下载 `ClaudeSwitcher-portable.zip`。SHA256 校验值在 Release 说明与 `SHA256SUMS.txt` 里。
3. **双击安装包**，按提示点「下一步」直到安装完成。
4. 若 Windows 弹出 **SmartScreen**「Windows 已保护你的电脑」，点「更多信息」→「仍要运行」。
   > 这是**未签名安装包**的正常提示。请只从本仓库 Release 下载，不要从来路不明的链接安装。
5. 从开始菜单打开 **Claude Switcher**。
6. **先保存当前账号**：在「保存当前账号」面板输入名称（如「Claude 主号」），点「保存快照」。前提：你已经在 Claude Code 中登录过至少一个账号。
7. **切换账号**：在「账号快照」里点对应卡片的「切换」。若 Claude Code 还在运行，工具会提示你**切换后重启 Claude Code**（正在运行的会话不会自动换账号）。
8. **托盘用法**：点右下角托盘的彩色图标弹出用量窗口；**双击**图标打开主窗口；**右键**托盘图标可直接在账号列表里点账号一键切换（当前账号 ● 标记），也有「打开主窗口 / 刷新用量 / 退出 Claude Switcher」。
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

# 7. 便携版 zip（CI 自动；本地可手动打包）
$staging = "portable-staging"
New-Item -ItemType Directory -Force $staging | Out-Null
Copy-Item src-tauri\target\release\claude-switcher.exe $staging\ClaudeSwitcher.exe
New-Item -ItemType File $staging\portable.flag | Out-Null
Compress-Archive -Path "$staging\*" -DestinationPath ClaudeSwitcher-portable.zip -Force
```

产物位置：

```text
src-tauri\target\release\claude-switcher.exe                       # 免安装可执行文件
src-tauri\target\release\bundle\msi\ClaudeSwitcher_0.4.0_x64_zh-CN.msi
src-tauri\target\release\bundle\nsis\ClaudeSwitcher_0.4.0_x64-setup.exe
ClaudeSwitcher-portable.zip                                       # 便携版
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

以下功能已实现并有单元测试或代码审查覆盖，但**未在真实 Windows 环境实机验证**（沙箱无管理员权限、无显示器、无 Claude Code 登录态）：

| 项 | 状态 |
| --- | --- |
| 开机自启：任务管理器禁用后点「开启」能否真的启动 | 未实机验证 |
| 多显示器 + 任务栏在左/上/右的托盘弹窗定位 | 未实机验证 |
| Clash 实机节点切换（控制器地址归一化只有表格测试） | 未实机验证 |
| 配置目录切换后的凭据迁移与隔离重建 | 未实机验证 |
| 安装包升级 / 卸载回归（需要干净虚拟机） | 未实机验证 |
| **保镖真实 kill**（Desktop + CLI）、计划任务 highest 权限注册与 AtLogOn 触发 | 未实机验证 |
| **TUN 网卡探测**、`verge.yaml` TUN 开关恢复后 Clash Verge 实机重启加载 | 未实机验证 |
| **14 项检查的真实网络链路**（出口 IP / DNS / WebRTC / 生态可达性） | 未实机验证 |
| **UAC 提权弹窗**、`lock_region` 真实写入系统时区/区域/GeoID | 未实机验证 |
| **open-safe 真实浏览器拉起**、WebRTC 标志生效、profile 销毁 | 未实机验证 |
| **一键修复全流程**（拉起内核 → 恢复 TUN → 写规则 → 内核验证 → 注册保镖 → 复测） | 未实机验证 |
| **Claude Desktop 切换**（进程结束、活目录回存、快照载入、回滚） | 未实机验证 |
| **自动更新全流程** | 未实机验证 |
| **加密快照跨机导入** | 未实机验证（导入侧已加外机密文拒绝，但换机场景未实测） |
| **托盘一键切换**（动态菜单、点击切换、系统通知、菜单重建） | 未实机验证（无显示器/无托盘环境） |
| **按终端并行多账号**（wt/cmd 拉起、独立配置目录、共享 skills） | 未实机验证 |
| **额度阈值通知 / 提醒**（Toast、notify-state、一键切换） | 未实机验证（Toast 需 AUMID；开发模式显示成 PowerShell 身份属正常） |
| **MCP 服务器管理**（stdio 拉起、cmd /c 包装、.mcp.json 读写） | 未实机验证（纯逻辑有单测，真实拉起未测） |
| **便携版 zip**（portable.flag、数据目录与 WebView2 重定向） | 未实机验证（需在 WebView2 创建前设置，真实解压运行未测） |

> **P2-2 凭据锁：本轮不实现（待实机调研）**。必须先用 Process Monitor 实机抓取
> `claude.exe` / `node.exe` 刷新令牌时的锁文件（路径、句柄、持续时间），确认后再实现，
> 禁止凭猜测写。当前在文档中标记为「待实机调研」。

> 另有两项**已知功能缺口**（非缺陷，未在第二轮补齐）：
> ① 自动更新目前只做版本检查并提供下载页链接，不自动下载安装（未签名场景下 updater 插件方案不现实）；
> ② 上游的「48 小时出口 IP 漂移历史」警告未实现（当前只比对上一次出口）。
> 详见 `docs/qa-report.md` 第四之二节。

---

## 架构

### 技术栈

| 层 | 选型 |
| --- | --- |
| 桌面壳 | Tauri 2.11（`tauri.conf.json`，Windows x64，WebView2 `embedBootstrapper`，NSIS 简体中文 + WiX zh-CN） |
| 后端 | Rust（**27 个 `.rs` 文件**：`lib.rs` + `main.rs` + 23 个业务模块 + `platform/` 3 个文件；原 4229 行单文件 `lib.rs` 拆分）；**36 个 `#[tauri::command]`** |
| 前端 | React 19 + TypeScript + Vite + lucide-react；`src/App.tsx` 主窗口 + 7 个功能面板组件 |
| HTTP | `reqwest` + rustls（替代 `curl.exe`，读系统/环境代理，JSON body 走 socket 不走 argv，含 `socks` feature） |
| 加密 | AES-256-GCM（`enc:v1:` + base64(nonce 12B ‖ ciphertext)）；主密钥存 Windows 凭据管理器；快照导出用 Argon2id + AES-256-GCM（CSBK1） |
| 系统 API | `sysinfo`（进程）、`windows-sys`（文件 ID、reparse tag、SID、长路径）、`junction` crate、`keyring`（凭据管理器） |
| 系统查询 | 隐藏 PowerShell + `ConvertTo-Json`（网卡/时区/区域/IPv6/计划任务/服务；枚举值不随 UI 语言本地化） |

### 设计原则（五条硬规则）

1. **cfg 收拢**：所有平台差异必须收拢在 `platform/{windows,unix}.rs`，业务代码不写 `#[cfg(windows)]`。新增平台能力时：先在 platform 加同名函数，再在业务里调 `platform::imp::xxx`。
2. **阻塞命令走 `blocking()`**：Tauri 2 中非 `async` 命令跑在主线程，任何可能阻塞的（网络、进程扫描、目录 rename、凭据读取、PowerShell 查询）都必须 `blocking(|| ...)` 包装。**不用** `#[tauri::command(async)]` 包同步函数（会跑在 tokio 工作线程，调 `reqwest::blocking` 有 panic 风险）。
3. **写文件一律原子**：`fsx::write_atomically`（临时文件 + rename）。绝不用 `fs::write` 直接写 `store.private.json` / `.credentials.json` / `~/.claude.json`——截断式写入中途崩溃会丢数据。rename 失败时**不删**目标文件（旧数据必须保留）。
4. **凭据与密钥边界**：`settings_json` 里的认证字段（`AUTH_ENV_KEYS` + `apiKeyHelper`）落盘前 `split_auth_settings` 拆出加密，读时 `restore_auth_settings` 合并回去；解密路径**绝不生成新密钥**（缺密钥报错让用户恢复，绝不覆盖）；`keyring::Error` 除 `NoEntry` 外一律致命（PlatformFailure 可能是 DPAPI 失败，当「不存在」会铸新钥覆盖旧数据）。
5. **PowerShell 错误必须显式传播**：PowerShell 的非终止错误（`Write-Error`）**不改变进程退出码**，所以 `run_ps` 的脚本头强制 `$ErrorActionPreference = 'Stop'`，把非终止错误转成非零退出码；否则「设置失败」会被当成成功上报。

### 模块划分（src-tauri/src/，27 个 `.rs` 文件：23 个业务模块 + `lib.rs`/`main.rs` + `platform/` 3 个）

**来自上游 A（VallierDev，CLI 账号切换）——13 个模块：**

| 模块 | 职责 |
| --- | --- |
| `lib.rs` | 36 个命令处理器、返回类型、应用启动（单实例、关窗到托盘、`--guard`/`--autostart` 分发）、日志与 panic hook |
| `main.rs` | 桌面程序入口（`windows_subsystem = "windows"` 无黑窗），调 `claude_switcher_lib::run()` |
| `accounts.rs` | 账号材料事务写入：Merge / FullReplace 两种语义、回滚「先凭据后 JSON」、settings env 注入（遥测 + runtime） |
| `store.rs` | `store.private.json` 读写；AES-GCM 加解密；`split_auth_settings` / `restore_auth_settings`；`DesktopProfile` 与 `current_desktop_profile_id`；密钥「只读现有、解密绝不铸新钥」 |
| `credentials.rs` | Windows 凭据文件 / macOS Keychain 的读写与清除（差异收拢进 platform） |
| `isolation.rs` | 按 profile 接管/激活 `projects`、`telemetry`、`file-history`、`shell-snapshots`、`cache`、`debug`、`plugins/data`、`config.json` 共 8 个隔离面 |
| `links.rs` | 符号链接 / junction / 硬链接的创建、识别（含悬空链接）、移除与链接模式上报 |
| `fsx.rs` | 原子写入（`.原文件名.tmp-<rand>` + rename）、rename/删除锁重试（Windows 错误 5/32/33 短退避）、陈旧临时文件清理 |
| `jsonio.rs` | 文本读取自动处理 UTF-8 BOM 与 UTF-16LE/BE（记事本改过的 settings.json 不会让界面打不开） |
| `paths.rs` | 路径解析（`CLAUDE_CONFIG_DIR` → `USERPROFILE` → `home_dir`）与目录保障、ACL 一次性收敛标记 |
| `processes.rs` | Claude Code CLI 检测与结束（精确匹配防误杀，`taskkill /T` → `/T /F`） |
| `clash.rs` | 节点组状态、切换、节点 alive 与到 `api.anthropic.com` 的延迟检查 |
| `usage.rs` | 本地日志聚合 + OAuth usage/profile 的 TTL 缓存与 in-flight 合并 + 本地快照 45 秒缓存 + token 指纹防串号 |
| `tray.rs` | 托盘 tooltip、弹窗定位（工作区/多屏）、失焦防抖、右键菜单 |

**来自上游 B（YOURSJEYO，环境安全 / 桌面版）——10 个模块：**

| 模块 | 职责 |
| --- | --- |
| `appconfig.rs` | 全局配置 `~/.claude-switcher/appconfig.json`：`country_target` / `tz_target` / `locale_target` / `proxy_mode` / `proxy_group` / `webrtc_policy` / `last_egress_ip`；读取失败记日志（不静默覆盖） |
| `egress.rs` | 出口 IP 探测：Cloudflare `cdn-cgi/trace` 优先、`ipinfo.io/json` 兜底；住宅 vs 机房 ASN 启发式 |
| `region.rs` | 国家 → 时区 / locale / GeoID 映射表（11 国）；IANA → Windows 时区 ID（约 60 条）；未知回退 US / UTC |
| `stun.rs` | 手写 RFC 5389 STUN 协议栈：并发向 5 台服务器（含 3 台国内节点）发 Binding Request，解析 XOR-MAPPED / MAPPED-ADDRESS；**无响应判 warn，绝不视为零暴露** |
| `desktop.rs` | Claude Desktop（`%APPDATA%\Claude`）快照 / 捕获 / 切换 / 删除 / 重命名；**切换前把活目录回存当前账号快照**（上游 `Save-Account` 语义）；失败用 staging 备份回滚 |
| `guard.rs` | 保镖 kill-switch（10s 巡检、fail-closed、杀 Desktop + CLI）+ 时区看门狗（偏离 `tz_target` 自动回滚）+ `ClaudeBodyguard` 计划任务注册/启动 |
| `rules.rs` | Clash 模式识别（Mihomo `/configs` → 回退 yaml `mode:`）；只写 `profiles\Script.js` 托管块（不写 Merge.yaml）；重启后经内核 `/rules` 逐条验证前 16 条，失败从备份回滚 |
| `checks.rs` | **14 项安全检查** + 静默总检（N/14）+ 一键修复（拉起内核 → 恢复 TUN 开关 → 锁时区 → 关 IPv6 → 写规则 → 注册保镖 → 复测） |
| `keep.rs` | 跨身份保留 `keep-in-workspace.txt`：stage（切换前收进暂存）/ merge（还原后合并）；**拒绝绝对路径、`..`、盘符前缀、符号链接**；残留暂存拒绝覆盖 |
| `diagnostics.rs` | open-safe（一次性隔离浏览器，禁用非代理 UDP，关闭即销毁 profile）/ diagnose-proxy（无认证传输可达性，401/403 分类，不回显凭据）/ fingerprint（系统侧指纹 + 虚拟机启发式）/ cli-info（PATH 顺序、版本、安装方式、多份告警；**带 8s 超时**） |
| `export.rs` | 加密快照导出/导入（CSBK1：magic + salt16 + nonce12 + AES-256-GCM，Argon2id m=64MiB/t=3/p=1，口令 ≥8）；**导入前检测外机密文并拒绝**（避免换机后整个账号库不可用） |
| `update.rs` | GitHub Releases latest 版本比对（只提示不自动安装；API 限流静默） |
| `net.rs`（扩展） | Clash 控制器运行时配置探测：手动覆盖 > yaml > 端口探测（9097 → 9090）；**只接受回环控制器**（拒绝远程主机，防止 secret 外发） |
| `platform/windows.rs`（扩展） | 新增：网卡列表、IPv6 绑定、时区读写、区域/GeoID、计划任务注册/删除/**启动**、WireGuard 隧道服务查询、无窗口进程拉起、按名/按 PID 结束进程 |

**平台分发：**

| 模块 | 职责 |
| --- | --- |
| `platform/mod.rs` | **Windows 平台适配唯一入口**：非 Windows 目标直接 `compile_error!`（本项目只做 Windows） |

### 命令清单（36 个 `#[tauri::command]`，按域分组）

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
| **环境安检** | `run_security_checks`、`run_security_fix`、`detect_egress` |
| **地区 / 客户端** | `lock_region`、`set_client`、`get_appconfig`、`set_proxy_group`、`set_webrtc_policy` |
| **保镖** | `guard_status`、`guard_run_tick`、`install_guard_cmd`、`uninstall_guard_cmd` |
| **Clash 规则** | `get_clash_mode`、`ensure_clash_rules` |
| **Claude Desktop** | `list_desktop_profiles_cmd`、`capture_desktop_profile_cmd`、`switch_desktop_profile_cmd`、`delete_desktop_profile_cmd`、`rename_desktop_profile_cmd` |
| **隐私 / 诊断** | `open_safe_cmd`、`close_safe_cmd`、`diagnose_proxy_cmd`、`system_fingerprint_cmd`、`cli_info_cmd` |
| **加密快照** | `export_store_encrypted`、`import_store_encrypted`、`check_for_update` |

### 关键数据流

```
React 主窗口（7 个面板） / 托盘弹窗
        │  invoke（36 个命令，阻塞操作全部经 blocking() 移出主线程）
        ▼
lib.rs（命令层）
   ├─ accounts.rs ── credentials.rs ──► %USERPROFILE%\.claude\.credentials.json
   │        │                          %USERPROFILE%\.claude.json
   │        │                          <claude_dir>\settings.json
   │        └─ store.rs ──► %USERPROFILE%\.claude-switcher\store.private.json（AES-GCM）
   │                          主密钥 → Windows 凭据管理器 claude-switcher-store-key
   ├─ isolation.rs ── links.rs ──► session-profiles/<profile-id>/ 的链接与备份
   ├─ processes.rs ── sysinfo ──► Claude Code CLI 进程
   ├─ net.rs / clash.rs ──► Clash 控制器（仅回环 127.0.0.1:9097 / 9090）
   ├─ usage.rs ──► <claude_dir>\projects\**\*.jsonl  +  api.anthropic.com OAuth usage
   │
   ├─【YOURSJEYO 融合链路】
   ├─ checks.rs ──┬─ guard.rs ──► 计划任务 ClaudeBodyguard（10s 巡检、fail-closed）
   │              ├─ egress.rs ──► cloudflare trace / ipinfo.io
   │              ├─ stun.rs ──► 5 台 STUN 服务器（UDP Binding）
   │              ├─ rules.rs ──► profiles\Script.js + 内核 /rules 验证
   │              ├─ region.rs + platform::imp ──► 系统时区 / 区域 / GeoID
   │              └─ platform::imp ──► 网卡 / IPv6 绑定 / DNS 解析
   ├─ desktop.rs ──► %APPDATA%\Claude 活目录 ↔ desktop-accounts/<id> 快照
   ├─ keep.rs ──► keep-in-workspace.txt ↔ keep-stage/
   ├─ diagnostics.rs ──► 隔离浏览器 / 代理诊断 / 指纹 / CLI 体检
   └─ export.rs ──► CSBK1 加密快照文件（Argon2id + AES-256-GCM）
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
| **环境查询** | `ifconfig` / `scutil` / `launchctl` / `dig` | 隐藏 PowerShell + `ConvertTo-Json`（网卡、IPv6 绑定、时区、区域、GeoID、计划任务、服务；**枚举值不随 UI 语言本地化**） |
| **计划任务** | `launchctl` LaunchDaemon | Windows 计划任务 `ClaudeBodyguard`（AtLogOn + RunLevel Highest），注册后**立即启动**（不等下次登录） |
| **WireGuard 存活** | `scutil --nc list` | `Get-Service WireGuardTunnel*` 查 Running（GUI 开着≠隧道在线） |
| **kill-switch** | `pkill claude` | `taskkill /T /F` 结束 Desktop + CLI；**Desktop 按 exe 路径判定 PID 后终止**（主程序镜像名可能不是 `Claude`） |
| **规则托管** | `profiles/Script.js` 全局扩展脚本 | 同名同机制；内核验证用 `GET /rules`，**必须容忍 `{"rules":[...]}` 包装** |
| **地区锁定** | `defaults write` / `systemsetup` | `Set-TimeZone` / `Set-Culture` / `Set-WinHomeLocation`（需管理员） |
| **加密快照** | `hdiutil` AES-256 DMG | 单文件 CSBK1（Argon2id + AES-256-GCM），跨平台可用 |

### 本仓库额外增强

- 单实例（避免双开并发写 store）
- 关窗到托盘 + 右键退出 + 开机自启（`HKCU\...\Run`，带 `--autostart` 静默启动参数）
- Clash 控制器 / secret / 代理端口手动覆盖；默认端口 9097 → 9090 真实探测；**只接受回环控制器**（拒绝远程主机，防止 secret 外发）
- 用量 TTL 缓存 + 并发 in-flight 合并 + 本地快照 45 秒缓存 + token 指纹防串号
- 链接模式显示与开发者模式一键引导（`ms-settings:developers`）
- 手动指定 Claude 配置目录（解决 GUI 启动读不到终端环境变量的问题）
- 原子写入、文件锁重试（32/33 退避、5 只重试一次）、悬空链接识别、路径归一化（`\\?\` 前缀 / 大小写 / 8.3 短名 / 正斜杠统一，含 `C:\Users\A` vs `C:\Users\AB` 前缀陷阱防护）
- 读 JSON 自动处理 UTF-8 BOM 与 UTF-16（记事本改过的 settings.json 不会让界面打不开）
- 事务回滚顺序「先凭据后 JSON」；账号材料已切换后链接激活失败降级为 warning（避免「显示失败、实际已切」）
- 删除账号三选项确认弹窗（破坏性选项不设默认焦点；Esc=取消、初始焦点在「取消」、焦点陷阱、背景滚动锁定）
- **切换前预检**（v0.2.0）：目标快照凭据可解密 / 配置目录可写，任一失败在动数据前中止（无损放弃点）
- **切换事务日志**（v0.2.0）：`switch-journal.json` 记录切换目标/步骤/备份 id；正常完成即清除，中断残留会在状态里提示按备份回滚
- **快照加密导出/导入**（v0.2.0）：单文件 CSBK1 格式（Argon2id + AES-256-GCM，口令 ≥8 位），换机迁移/冷备；导入前自动备份现有 store，**并检测外机密文拒绝导入**（避免换机后整个账号库不可用）；口令错/文件损坏绝不覆盖现有数据
- **应用内版本检查**（v0.2.0）：GitHub Releases 比对，有新版提示并给下载页链接（不自动安装；API 限流静默）
- **Desktop 活目录回存**：切换前把当前账号的使用变更写回它的快照（对齐上游 `Save-Account`），不会静默回退到上次 capture
- **keep 沙箱加固**：拒绝绝对路径、`..`、**盘符相对路径**（`C:foo`/`C:`，`PathBuf::join` 会整体替换 base）、符号链接
- **cli_info 带 8 秒超时**：PATH 上挂起的 `claude.cmd` 不会让体检永久卡死
- **前端配置回读**：`get_appconfig` 让面板显示已保存值，不会重启后显示默认值并覆盖旧选择
- **代理组可配置**：`set_proxy_group` + 面板输入框；未配置时回落默认组 `Auto-Claude`（装完即可用）
- 本机日志（`~/.claude-switcher/logs/`，1MB 滚动）+ panic hook + 诊断信息一键复制
- **单元测试 161 个**（基线 57 → 新增 104）：链接识别、悬空链接、路径归一化、原子写入、merge/scrub 逻辑、BOM/UTF-16 解码、进程匹配表格、删除链路 `deactivate_in`、版本号比较、14 项检查判定表、TUN 检测表、STUN 协议解析、规则验证（含内核 `{"rules":[...]}` 包装）、地区映射、Desktop 回存与回滚、keep 沙箱、控制器回环校验、PowerShell 错误传播等

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

当前测试状态（v0.2.2）：**175 通过 + 1 ignored**（`encrypt_decrypt_roundtrip` 需实机凭据存储；以 `cargo test --lib` 实际输出为准）。测试覆盖亮点：链接识别与悬空链接、路径归一化（含 8.3 短名）、原子写入、merge/scrub 逻辑、BOM/UTF-16 解码、进程匹配表格（16 例）、Clash 控制器地址归一化（11 例，含 IPv6）、`is_under` 前缀陷阱、删除链路 `deactivate_in`（含硬链接 config.json、悬空 junction、移除失败中止保现场）、版本号比较（含预发布后缀）、CSBK1 快照加解密（AAD 防篡改、KDF 参数上限）、keep 路径沙箱（备用数据流/设备名/尾点尾空格/大小写重复）。

---

## 隐私与安全

- 账号快照只保存在本机 `%USERPROFILE%\.claude-switcher\`，不会上传任何账号凭据。
- OAuth blob 写入 store 前用 AES-256-GCM 加密，主密钥在 Windows 凭据管理器；token 不显示在 UI，也不进入本仓库。
- 进程检测只匹配 `claude.exe` 或 `node`/`bun` 且命令行含 `@anthropic-ai/claude-code`，并排除本工具自身与 Claude Desktop，**不会**因为命令行里出现 `claude-code` 字样就误杀别的进程。
- 本仓库 CI 只构建源码，不访问本机凭据、`~/.claude-switcher` 数据或 Claude 账号快照。

## 构建与发布

- `CI`（`.github/workflows/ci.yml`）：push / PR 时在 macOS 与 Windows runner 上跑前端构建、`cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test --lib`、Tauri build。（macOS runner 的 host 与 target 不同，会额外按 target 再跑一遍 clippy；Windows runner 两者相同，不重复。）
- `Windows Build`（`.github/workflows/windows-build.yml`）：打 `v*` tag 自动构建 MSI / NSIS 并**自动创建 Release**（含 `SHA256SUMS.txt`，裸文件名可直接 `sha256sum -c`）；手动触发只出 Actions 产物。**构建来源证明（v0.2.0 起）**：安装包带 GitHub attestation，可验证确实来自本仓库 CI：`gh attestation verify .\ClaudeSwitcher_0.2.2_x64-setup.exe -R 48ytw4q7zg-sudo/claude-switcher-windows`。**从 v0.1.0 升级请先卸载旧版**（v0.2.0 更换了应用标识与发布者署名；用户数据在 `%USERPROFILE%\.claude-switcher\` 不受影响，装完新版自动继续使用）。
- 未配置代码签名证书；首次运行安装包会有 SmartScreen 提示，属预期。有条件可接 Azure Trusted Signing 或自持证书消除该提示。**路线图**：可申请 SignPath Foundation 面向开源项目的免费代码签名（需项目审核通过）。

## 出处与许可

- 本仓库是两个上游的融合：[VallierDev/claude-switcher](https://github.com/VallierDev/claude-switcher)（CLI，基线 commit [`6897984`](https://github.com/VallierDev/claude-switcher/commit/68979843313a0cb7da3cda32765184436ba9598e)）与 [YOURSJEYO/claude-switcher](https://github.com/YOURSJEYO/claude-switcher)（环境/桌面版，基线 commit [`870c4ca`](https://github.com/YOURSJEYO/claude-switcher/commit/870c4ca0754234965878ef58144d7a755d965037)），逐功能对等迁移，平台差异替换为 Windows 等价实现。基线记录与功能对等矩阵见 [docs/upstream-baseline.md](docs/upstream-baseline.md)。
- 本仓库 LICENSE 为 **Apache-2.0**（见 `LICENSE` 文件）。
- **上游仓库未声明许可证**（无 LICENSE 文件）。若上游后续补充许可，本仓库的许可应与之对齐；在此之前请联系上游作者确认授权范围。
- 涉及 Anthropic / Claude Code 的商标与名称归其权利人所有。本工具只在本地操作 Claude Code 已生成的文件，不修改、不分发任何 Anthropic 专有代码。

## 致谢

- 上游原项目与作者：**[@VallierDev](https://github.com/VallierDev)** — [VallierDev/claude-switcher](https://github.com/VallierDev/claude-switcher)。本 Windows 迁移版在保持原功能的基础上做了系统适配与加固，感谢上游的设计。
- 第二个融合基线：**[@YOURSJEYO](https://github.com/YOURSJEYO)** — [YOURSJEYO/claude-switcher](https://github.com/YOURSJEYO/claude-switcher)。本仓库的环境安全与桌面版能力（14 项检查、保镖、地区锁定、规则托管、STUN/指纹、桌面版管理）均来自该上游的行为基准，感谢其设计。
- 本仓库维护者：[48ytw4q7zg-sudo](https://github.com/48ytw4q7zg-sudo)。

## 维护与贡献

- 工程说明（构建命令、架构约定、踩坑记录全文）：见 [AGENTS.md](AGENTS.md)。
- 上游基线、功能映射与升级差异审查流程：见 [docs/upstream-baseline.md](docs/upstream-baseline.md)。
- 提交 PR 前请跑完「质量门禁与测试」一节的本地门禁；CI 会在 macOS 与 Windows 上再跑一遍。
