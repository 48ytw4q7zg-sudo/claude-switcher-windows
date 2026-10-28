# QA 记录 · v0.3.1（PowerShell 路径健壮性补丁）

## 背景：独立验收发现的真实失败

v0.3.0 发布后，MainAgent 独立复跑 `cargo test --lib`，发现 1 个真实失败用例，
与当时报告的「207 全绿」不符：

```
test platform::windows::tests::run_ps_propagates_non_terminating_errors ... FAILED
panicked at src\platform\windows.rs:765:
    assertion failed: result.unwrap_err().contains("synthetic probe")
结果：206 passed / 1 failed / 0 ignored
```

## 根因（已核实）

- 该机器 / 该进程的 `PATH` **不包含** `System32\WindowsPowerShell\v1.0`，
  `Get-Command powershell.exe` 解析为空；
- 但 `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` 真实存在。
- `run_ps` 用 `Command::new("powershell.exe")` 按名启动，触发「系统找不到指定的
  文件」，于是返回错误 `启动 powershell.exe 失败: ...`，`is_err()` 成立、
  但错误文本不含测试期望的 `synthetic probe`，断言失败。

这不是单纯的测试问题：**所有系统状态查询（网卡 / 服务 / 进程 / 计划任务 /
IPv6 绑定…）都走 `run_ps`**，在 PATH 缺 WindowsPowerShell 的环境上，整个
安全检查 / 地区 / 保镖相关查询会整体失败，属生产健壮性缺陷。

## 修复

1. 新增 `platform::windows::powershell_path()`：从 `SystemRoot` 环境变量拼出
   `System32\WindowsPowerShell\v1.0\powershell.exe` 权威路径（`SystemRoot`
   缺失时回退 `C:\Windows`），不依赖 PATH。
2. `run_ps` 改用该完整路径启动。
3. `parallel.rs` 并行终端把 `powershell` 作为参数传给 `wt.exe` / `cmd start`
   时，同样改用完整路径（`launch_wt` / `launch_via_cmd_start`）。
4. 新增回归测试 `powershell_path_points_to_system_root_copy`：断言路径位于
   `SystemRoot` 下、文件真实存在、且指向 Windows PowerShell 5.1 目录。

## 验证结果（MainAgent 本地真实执行）

| 检查 | 结果 |
|---|---|
| `cargo fmt --check` | 通过 |
| `cargo clippy --all-targets -- -D warnings` | 零警告，exit 0 |
| `cargo test --lib` | **208 passed / 0 failed / 0 ignored**（v0.3.0 为 207，新增 1） |
| 原失败用例 `run_ps_propagates_non_terminating_errors` | 通过 |
| `npx tsc --noEmit` | 通过 |
| `npm run tauri build` | 成功，出 MSI + NSIS |

## 说明

- 本次为补丁版本，不改变任何功能行为，仅修复「PowerShell 按名启动失败」。
- 未实机验证项与 v0.3.0 一致（托盘、并行终端、通知、MCP 真实拉起、便携版、
  自动更新、UAC、安装包升级/卸载），见 `qa-v0.3.0.md` 与 AGENTS.md。
- P2-2 凭据锁仍待实机 Process Monitor 调研，未凭猜测实现。
