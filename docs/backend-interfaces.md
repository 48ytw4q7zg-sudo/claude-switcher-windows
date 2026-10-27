# 后端新增模块接口约定（平台层契约）

> 本文件是 YOURSJEYO 功能迁移的**平台层契约**。平台层（`platform/windows.rs` /
> `platform/unix.rs`）必须实现下列**同名函数**；业务模块（checks/guard/desktop/
> rules/diagnostics/region/stun/keep）一律通过 `crate::platform::imp::xxx` 调用，
> **业务代码里禁止出现 `#[cfg(windows)]`**。

## 铁律（沿用 AGENTS.md）

- 所有平台差异收拢在 `platform/`；阻塞操作走 `blocking(|| ...).await`；
  写文件一律 `fsx::write_atomically`；解密路径绝不生成新密钥。
- 禁止裸 `unwrap()`/`expect()`（除 `#[cfg(test)]` 与确实不可失败处并注释说明）。
- 所有 Windows 查询优先用**隐藏 PowerShell + `ConvertTo-Json`**（枚举值如
  `Status="Up"` 不随 UI 语言本地化），把「命令调用」与「输出解析」拆成两个函数，
  解析函数做表驱动单测。子进程必须无窗口（沿用现有 `silent_command` / `CREATE_NO_WINDOW`）。

## 平台层新增函数（签名必须一致）

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AdapterInfo {
    pub name: String,        // 接口别名，如 "Mihomo TUN" / "Wintun Userspace Tunnel"
    pub description: String, // InterfaceDescription
    pub status: String,      // "Up" / "Disabled" / "Disconnected" ...
    pub if_index: u32,
    pub ipv4: Vec<String>,   // 如 ["198.18.0.1"]
    pub ipv6: Vec<String>,
}

/// 全部网卡（含虚拟网卡）。
pub fn list_adapters() -> Result<Vec<AdapterInfo>, String>;

/// 每个网卡的 ms_tcpip6（IPv6）绑定是否启用：(adapter name, enabled)。
pub fn ipv6_bindings() -> Result<Vec<(String, bool)>, String>;

/// 关闭所有网卡的 IPv6 绑定（Disable-NetAdapterBinding -ComponentID ms_tcpip6）。
pub fn set_ipv6_all_disabled() -> Result<(), String>;

/// 当前 Windows 时区 ID（如 "Eastern Standard Time"）。
pub fn current_timezone_id() -> Result<String, String>;

/// 设置 Windows 时区（Set-TimeZone / tzutil /s）。
pub fn set_timezone_id(id: &str) -> Result<(), String>;

/// 当前用户区域格式（culture，如 "en-US"，Get-Culture）。
pub fn current_culture() -> Result<String, String>;

/// 当前用户 Home Location GeoId（Get-WinHomeLocation）。
pub fn current_home_location_geo() -> Result<u32, String>;

/// 设置区域格式 + Home Location（Set-Culture + Set-WinHomeLocation）。
pub fn set_culture_and_location(culture: &str, geo_id: u32) -> Result<(), String>;

/// 注册「登录时触发」的计划任务（ONLOGON，隐藏窗口；highest=true 时以最高权限运行）。
pub fn register_logon_task(name: &str, exe: &str, args: &str, highest: bool) -> Result<(), String>;

/// 删除计划任务（不存在视为成功）。
pub fn delete_task(name: &str) -> Result<(), String>;

/// 计划任务是否存在。
pub fn task_exists(name: &str) -> Result<bool, String>;

/// 无窗口启动一个进程（detached，不等待）。
pub fn start_detached(program: &str, args: &[&str]) -> Result<(), String>;

/// 按可执行名强制结束一批进程（如 ["Claude","claude"]），返回被结束的进程描述。
pub fn kill_processes_by_names(names: &[&str]) -> Result<Vec<String>, String>;
```

`platform/unix.rs` 提供同名函数（macOS/Linux 可返回 `Err("该平台暂不支持")` 或
给出基本实现），保证整箱编译通过。

## 业务模块职责（各自独立文件，互不编辑他人文件）

| 模块 | 职责 | 关键产物 |
|---|---|---|
| `region.rs` | 国家→(时区/locale/GeoId) 映射；IANA→Windows 时区 ID；按出口 IP 生成 RegionPlan | `RegionPlan`、`plan_for_country`、`iana_to_windows_tz` |
| `stun.rs` | 并发向多个 STUN（含国内）发 UDP Binding，硬超时，解析 XOR-MAPPED/MAPPED-ADDRESS | `StunResult`、`probe_stun_leak` |
| `rules.rs` | Clash 模式识别（Mihomo /configs，回退 yaml）；Script.js 托管块写入/清理；内核 /rules 前 16 条验证；失败回滚；WebRTC 策略 | `ensure_rules`、`clash_mode`、`verify_rules` |
| `desktop.rs` | Claude Desktop（%APPDATA%\Claude）账号快照/切换；切换前完全退出（含托盘） | Desktop 快照/切换函数 |
| `guard.rs` | 保镖计划任务（exe --guard 常驻，10s 巡检：代理内核/TUN 丢即杀 Claude[Desktop+CLI]，fail-closed）；时区看门狗 | install/uninstall、`guard_tick_loop` |
| `diagnostics.rs` | open-safe（一次性隔离浏览器）、diagnose-proxy（无认证可达性 JSON）、fingerprint（字体/GPU/虚拟机/Canvas/WebGL）、cli-info（where/版本/安装方式/多份） | 四个诊断函数 |
| `keep.rs` | keep-in-workspace.txt 相对路径暂存/合并；绝对路径/含 `..`/符号链接跳过并 WARN | `stage_keep`、`merge_keep` |
| `checks.rs` | 14 项检查 checkdetail + 静默 check + 一键修复 fix | `run_checks`、`run_fix` |
