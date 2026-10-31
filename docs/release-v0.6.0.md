# v0.6.0 — K 批次收尾 + 上游新功能对等

## 安装包与校验

| 文件 | 大小 | SHA256 |
| --- | --- | --- |
| `ClaudeSwitcher_0.6.0_x64_zh-CN.msi` | 10,735,616 字节 (10.24 MiB) | `d6cd9284c7383a553a756435346b2f0ec75b9b892c81b311182c77da782b0687` |
| `ClaudeSwitcher_0.6.0_x64-setup.exe` | 7,503,413 字节 (7.16 MiB) | `49e3003deee02e47f25f3f6566f15428d4041ed29050ddd4e3e2a50a364b1090` |
| `ClaudeSwitcher-portable.zip` | 8,825,508 字节 (8.42 MiB) | `64671b9019f09e07dd927dbc16e99f2a8c7e625694e833f9559475e8c8cddf40` |

校验方式（任选其一）：

```powershell
# PowerShell
Get-FileHash .\ClaudeSwitcher_0.6.0_x64_zh-CN.msi -Algorithm SHA256

# Git Bash / WSL（下载 SHA256SUMS.txt 到同目录）
sha256sum -c SHA256SUMS.txt
```

> 代码**未签名**，干净系统首次运行弹 SmartScreen 属预期，点「更多信息 → 仍要运行」。

## 本版内容

在 v0.5.0 的 J-1~J-8 缺陷修复与 F-1~F-7 功能之上，收尾第三轮审查（K 项）遗留问题，
并把上游 YOURSJEYO 在基线 commit 之后新增的 Windows 功能补齐。仅面向 Windows。

### 缺陷修复（跨账号凭据覆盖，本版重点）

| 编号 | 问题 | 影响 |
| --- | --- | --- |
| Critical 1 | 账号库未登记 uuid 时，并行终端换号后的凭据会被写进原账号快照 | 切回该账号即写入别人的登录态 |
| Critical 2 | WSL 回写只比过期时间，不核对账号身份 | WSL 里登着别的账号时会串号 |
| Important 3 | 权限/钩子编辑器保存时丢失用户配置 | 隐藏分组被删、删掉的钩子仍在执行 |
| Important 4 | 工作区启停命令未约束 id 路径边界 | 越界 id 可能误移配置目录外的文件 |
| Minor 5 | 后台回写无去重 | 断网时同一账号反复起线程争锁 |

以上均补了回归测试，并逐条记录在 `docs/qa-v0.6.0.md`。

### 其他修复

- **权限/钩子编辑器合并写入**：保存只改 `permissions.allow/deny/ask` 与钩子的
  `command`，`defaultMode`、`additionalDirectories`、hook 上的 `timeout` 等本工具
  不认识的字段原样保留。
- **并行 skills 改用目录联接**：账号目录用 junction 指向全局 `skills`，省空间且不会
  各改各的；联接失败自动降级为复制。
- **WSL 不再覆盖更新的远端凭据**：WSL 内令牌更新时不再用本机旧副本覆盖它。
- **MSIX 版 Claude Desktop 支持**：自动发现 `%LOCALAPPDATA%\Claude-Data\` 下的数据
  目录（传统 EXE 安装仍优先用 `%APPDATA%\Claude`）。
- **FlClash 代理客户端**：新增客户端选项，按 `FlClashCore` 进程判定在线。
- **客户端语言检查**：改读系统 UI 语言，不一致时按上游降级为 warn（不再硬 fail
  阻断静默总检）。

### 功能（延续 v0.5.0）

工作区资产管理（Skills / 命令 / 子代理 / CLAUDE.md 启停）、权限与钩子编辑器、
第三方供应商、WSL 集成（实验，默认关）、目录绑定 + `cs run`、用户 PATH、
开始菜单快捷方式、令牌状态徽标、诊断包脱敏、多语言（zh/en）。

## 升级说明

直接覆盖安装即可，账号库与配置目录不变。新版会额外读取 MSIX 数据目录，未安装
MSIX 版 Claude Desktop 的机器行为与之前完全一致。

## 已知限制

- **未实机验证项**：MSIX 版 Claude Desktop 数据目录、真实 WSL 写入与 0600 权限、
  并行终端 wt/cmd 真实拉起、托盘菜单、Toast 通知、安装包升级/卸载回归。
  （本机无显示器、无登录态、无 MSIX 版 Desktop、WSL 仅 docker-desktop。）
- **F-4 凭据锁**：仍待 Process Monitor 实机调研，未实现、未加猜测锁。
- **上游 48h IP 历史**（`iphistory.log`）：未实现，只影响「IP一致」的 warn 档文案，
  不改变 fail 判定。
- 代码未签名。

## 出处

本仓库是 Tauri 2 + Rust + React 应用，同时管理 Claude Code CLI 与 Claude Desktop。
代码实际迁移自 [VallierDev/claude-switcher](https://github.com/VallierDev/claude-switcher)
（CLI 账号切换，Tauri 2 + Rust + React）与
[YOURSJEYO/claude-switcher](https://github.com/YOURSJEYO/claude-switcher)
（环境安全 + 桌面版，bash/PowerShell/Swift）两个上游，逐行行为基线与对等矩阵见
[`docs/upstream-baseline.md`](https://github.com/48ytw4q7zg-sudo/claude-switcher-windows/blob/main/docs/upstream-baseline.md)。
