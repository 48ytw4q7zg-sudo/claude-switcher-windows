# 上游基线记录（upstream baseline）

> 目的：把「迁移目标」固定成可复现的具体 commit，而不是会变化的 `main`。
> 任何人复核时按这里的 SHA 拉取，看到的代码与本次审查完全一致。

## 1. 代码基线（实现来源）

| 项 | 值 |
| --- | --- |
| 仓库 | https://github.com/VallierDev/claude-switcher |
| 类型 | Claude Code **CLI** 账号切换器（macOS 桌面应用） |
| 技术栈 | **Tauri 2 + Rust + React + TypeScript**（与上游仓库结构一致） |
| Commit | [`68979843313a0cb7da3cda32765184436ba9598e`](https://github.com/VallierDev/claude-switcher/commit/68979843313a0cb7da3cda32765184436ba9598e) |
| 记录日期 | 2026-10-27 |
| 许可 | 上游仓库**未声明** LICENSE（见 README「出处与许可」） |

本仓库以上述 commit 的 Rust 实现为行为基线，逐功能对等迁移，
并把所有平台差异（Keychain → 凭据文件、pgrep → sysinfo、symlink → junction 等）
替换为 Windows 等价实现。

> 修正记录：早期版本误记上游为「macOS 原生 Swift」。经克隆核对，上游与
> 本仓库同为 Tauri 2 + Rust 结构（`src-tauri/src/lib.rs` + `package.json`），
> 无任何 `.swift` 文件。迁移基线、功能映射与升级审查命令均已按此更正。

## 2. 本仓库不包含的功能（重要）

用户曾提到另一个仓库 https://github.com/YOURSJEYO/claude-switcher ——
那是**另一个产品**，与本仓库不是同一 lineage：

| 对比项 | VallierDev/claude-switcher（本仓库基线） | YOURSJEYO/claude-switcher |
| --- | --- | --- |
| 管理对象 | Claude Code **CLI**（`~/.claude`、`~/.claude.json`、OAuth 凭据） | Claude **桌面版**（`%APPDATA%\Claude`） |
| 技术栈 | Tauri 2 + Rust + React（macOS） | Swift + bash/Python 核心 + PowerShell/WPF Windows Beta |
| 核心能力 | 账号快照 / 凭据切换 / 会话隔离 / Clash 节点绑定 | 环境审计、守护进程、系统时区与地区锁定、指纹体检 |
| 许可 | 未声明 | MIT |

**因此不存在「把 YOURSJEYO 的功能一模一样搬到本仓库」的关系。**

本仓库明确**不实现**以下 YOURSJEYO 特性（它们的设计目的是规避平台风控与
地区限制检测，不属于合法的本地账号管理）：

- 出口 IP / ASN / WebRTC / DNS / IPv6 泄漏探测与阻断
- 系统时区、地区格式的强制锁定（看门狗）
- 字体 / GPU / 虚拟机指纹体检与伪装
- 代理掉线时终止 Claude 的「保镖」进程
- 置顶路由（policy routing）与「出口为 CN 则拒绝安装」门禁

本仓库保留的 Clash 节点绑定与账号运行时（时区/语言）注入来自 VallierDev 上游，
只在「功能是否正确工作」的范围内维护，不往规避检测方向增强。

## 3. 功能映射（feature parity）

状态定义：
- **已验证** = 有本仓库自动化测试直接覆盖（下方「测试」列给出具体测试名）。
- **待验证** = 实现完成，但仓库里**没有**对应测试，需真实 Windows 环境确认
  （见 README「构建与发布」的实机清单）。

本仓库没有 `src-tauri/tests/` 集成测试目录；下表「测试」列只填真实存在的
`#[test]` 用例名，不把「应该有测试」写成已验证。

| 上游功能（lib.rs） | 本仓库实现 | 测试 | 状态 |
| --- | --- | --- | --- |
| 读取 OAuth 凭据 | `credentials::read_password` | 无直接测试 | 待验证 |
| 写入 OAuth 凭据 | `credentials::write_password`（原子写） | `fsx::write_atomically_*`（间接） | 待验证 |
| 清除 OAuth 凭据 | `credentials::clear_password` | 无直接测试 | 待验证 |
| store 加密主密钥 | `store::read_store_key` | `encrypt_decrypt_roundtrip`（#[ignore]，需实机凭据存储） | 待验证 |
| 账号快照保存/切换 | `lib::capture_current_profile` / `switch_profile` | `accounts::merge_claude_json_*`（部分） | 待验证 |
| 备份 / 还原 | `create_backup_with_label` / `restore_backup` | `accounts::backup_snapshot_*`（部分） | 待验证 |
| 一键新号向导 | `prepare_new_account_login` / `complete_new_account_login` | 无直接测试 | 待验证 |
| session 隔离（projects） | `isolation::activate_profile_sessions` | `platform::is_link_and_junction_roundtrip`、`links::dangling_junction_*` | 部分验证 |
| 本地目录隔离（6 个） | `isolation::activate_profile_claude_dir` | `links::detect_link_mode_*` | 部分验证 |
| config.json 隔离 | `isolation::activate_profile_claude_config` | `platform::same_file_detects_hard_link` | 部分验证 |
| Clash 节点绑定/切换 | `clash::switch_clash_node_internal` | `net::controller_normalization_table`（仅地址归一化） | 待验证（需 Clash 实机） |
| 用量统计（本地日志） | `usage::claude_usage_snapshot` | `usage::compact_token_count_formatting`、`should_scan_usage_file_matches_windows_path_subagents` | 部分验证 |
| 用量统计（OAuth API） | `usage::apply_oauth_usage` | `usage::oauth_access_token_parses_both_shapes` | 待验证（需网络） |
| 托盘 + 弹窗 | `tray::toggle_tray_popup` | 无（UI 行为） | 待验证 |
| 进程检测 / 结束 | `processes::claude_code_processes` | `processes::claude_code_process_matching_table`（16 例） | 已验证 |
| 数据目录入口 | `lib::open_data_dir` | 无 | 待验证 |
| 遥测去关联注入 | `accounts::apply_profile_env_to_settings` | `accounts::apply_profile_env_writes_telemetry_and_runtime` | 已验证 |
| 路径归一化 | `platform::windows::normalize_path` | `platform::*normalize_path*`（4 例，含 8.3 短名、正斜杠） | 已验证 |
| 凭据字段加密 | `store::split_auth_settings` / `restore_auth_settings` | `store::split_auth_settings_*`（4 例往返） | 已验证 |
| 文件编码兼容 | `jsonio::read_text_lossy_bom` | `jsonio::*`（8 例 BOM/UTF-16/多文档 YAML） | 已验证 |

## 4. 上游升级差异审查流程

上游与本仓库同为 Tauri 2 + Rust 结构，diff 要按 Rust / 前端 / 配置看：

```bash
git fetch https://github.com/VallierDev/claude-switcher.git main
git diff 6897984..FETCH_HEAD -- src-tauri/src src package.json src-tauri/Cargo.toml
```

1. 对每个变化的功能，按上表找到本仓库对应模块，判断是否需要同步。
2. Windows 专属行为（junction、icacls、sysinfo）不要反向同步回上游。
3. 更新本文件的「代码基线」commit，并在 README「出处与许可」同步。


## 5. 本次审查未覆盖的部分

- 未在真实 Windows 10/11 实机运行（沙箱无显示器、无 Claude Code 登录态）。
- 安装包升级 / 卸载回归未测（需要干净虚拟机）。
- 多显示器、任务栏位置、DPI 缩放的托盘弹窗定位未测。
