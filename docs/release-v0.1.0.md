# Claude Switcher Windows v0.1.0

Windows 10/11 (x64) 桌面工具：管理多个本机 Claude Code CLI 账号（快照切换、凭据管理、本地痕迹隔离、Clash 节点绑定、用量展示、托盘）。Tauri 2 + Rust + React 19。

**源码**：[48ytw4q7zg-sudo/claude-switcher-windows](https://github.com/48ytw4q7zg-sudo/claude-switcher-windows) · **完整文档**：[README](https://github.com/48ytw4q7zg-sudo/claude-switcher-windows#readme)

## 出处

- Windows 迁移自 [VallierDev/claude-switcher](https://github.com/VallierDev/claude-switcher)（macOS 版，基线 commit `6897984`），感谢 **[@VallierDev](https://github.com/VallierDev)**。
- 同名不同产品：[YOURSJEYO/claude-switcher](https://github.com/YOURSJEYO/claude-switcher)（Claude 桌面版环境管理器），感谢 **[@YOURSJEYO](https://github.com/YOURSJEYO)**。两个项目定位不同、无代码血缘。

## 安装包（GitHub Actions 构建，来源可审计）

| 资产 | 用途 | SHA256 |
| --- | --- | --- |
| `Claude Switcher_0.1.0_x64-setup.exe` | NSIS 安装包（推荐） | `511b7098ef41c256beb7655ff0f7f65e0f89c2d6f3781fd3964a0bf81c7044c7` |
| `Claude Switcher_0.1.0_x64_zh-CN.msi` | MSI 安装包（企业分发） | `014d587ba476c0011bd5a549fdad97dda943886a4b86b40d900df55f5496f572` |
| `SHA256SUMS.txt` | 校验和汇总 | — |

构建来源：GitHub Actions `Windows Build` run（workflow_dispatch，tag v0.1.0 对应代码 `465e93a`，构建辅助提交 `ff85c73` 仅修复 CI 上传配置、不含应用代码变更）。

**校验方法**（PowerShell）：

```powershell
Get-FileHash .\Claude* -Algorithm SHA256   # 与上表 / SHA256SUMS.txt 比对
```

## 安装（小白版要点）

1. 确认 64 位 Windows 10/11（x64）。
2. 下载 `Claude Switcher_0.1.0_x64-setup.exe` 并双击安装。
3. SmartScreen 弹窗 →「更多信息」→「仍要运行」（安装包未签名，属预期；请只从本仓库下载）。
4. 开始菜单打开 **Claude Switcher** → 「保存当前账号」→ 切换账号。详见 [README 小白版教程](https://github.com/48ytw4q7zg-sudo/claude-switcher-windows#readme)。

源码构建、Clash 控制器覆盖、`CLAUDE_CONFIG_DIR` 等高级用法见 [README 高手版](https://github.com/48ytw4q7zg-sudo/claude-switcher-windows#readme)。

## 本版内容

- 上游功能全量迁移：OAuth 凭据读写与清除、账号快照切换、备份/还原、一键新号向导、session/config 隔离（8 个隔离面）、Clash 节点绑定、用量展示、托盘弹窗与数据目录入口。
- Windows 适配：凭据文件直写（跟随 `CLAUDE_CONFIG_DIR`）、Windows 凭据管理器存主密钥、sysinfo 进程检测、junction/硬链接隔离、icacls 权限收敛、reqwest + rustls 网络请求。
- 额外增强：单实例、关窗到托盘、开机自启、Clash 控制器覆盖、原子写入、BOM/UTF-16 容错、删除三选项安全确认、诊断一键复制。
- 质量：52 个单元测试全绿 + 1 个需实机（ignored）；`cargo fmt/clippy(-D warnings)/test` + `tsc` 门禁通过；CI 在 macOS + Windows 双端验证。

## 已知边界

- Windows 10 未实机验证（实测环境 Windows 11 Pro x64）。
- 未做代码签名，SmartScreen 提示属预期。
- 开机自启、多显示器托盘定位、Clash 实机节点切换、配置目录迁移为待实机项（详见 README「验收边界」）。
