# 功能对等核对（v0.6.7 更新）

> **本文件已于 v0.6.6 重写，v0.6.7 再次更新**：旧版 33/48（69%）统计与
> 「熔断/断网/常驻监控未实现」等描述已过时——这些功能在 v0.6.1~v0.6.7
> 已实现并接入生产入口。
>
> 当前准确状态以 `docs/upstream-claudeguard-parity.md` 与
> `docs/release-v0.6.7.md` 为准。v0.6.7 补齐：应用隔离多安装路径 +
> `ActiveStore` 有效策略核验、熔断状态未知三态、Desktop 加密快照迁移、
> 保镖 CLI 边界。

## 已实现（截至 v0.6.6，均有生产入口）

### ClaudeGuard 核心
| 能力 | 实现 |
| --- | --- |
| 目标模型 / 四类锚点 / 判定矩阵 | `egate.rs` |
| 网络探测（URL 校验/3MB 上限/不跟跳转） | `egate_probe.rs` |
| 接入路径判定 | `egate_access.rs` |
| 系统读取 / 路由 / 防抖 | `egate_check.rs` |
| 内置目标表 | `egate_defaults.rs` |
| **熔断执行**（进程+防火墙+回查） | `egate_trip.rs` |
| **直连泄露观察** | `egate_netwatch.rs` |
| **断网档位 + 自愈账本** | `egate_netcut.rs` |
| **常驻监控 + 暂停 + 停止保护** | `egate_monitor.rs` |
| **启动门禁** | `egate_launch.rs` |
| **六类通知** | `egate_notify.rs` |
| **环境一致性 + 账本对齐** | `egate_env.rs` |
| **跨进程操作锁（真排他）** | `egate_lock.rs` |
| CLI（--egate-check/restore/status） | `cli.rs` |

### YOURSJEYO 核心
| 能力 | 实现 |
| --- | --- |
| 14 项环境安检 + 一键修复 | `checks.rs` |
| 出口探测 / 时区地区锁定 | `egress.rs` `region.rs` |
| 保镖 kill-switch + 看门狗 | `guard.rs` |
| Clash 规则托管（双文件事务） | `rules.rs` |
| STUN / 诊断 / 指纹 | `stun.rs` `diagnostics.rs` |
| 加密快照导出导入（含 Desktop 快照，CSBK1 v3） | `export.rs` |
| Desktop 账号管理（精确事务+崩溃恢复） | `desktop.rs` |
| WSL 集成（可恢复双文件事务） | `wsl.rs` |
| 自动更新（下载+校验+安装） | `update.rs` |
| 检查开关 / 日志开关 / 48h IP 历史 | `checks.rs` `appconfig.rs` `ip_history.rs` |
| 配置版本化迁移 | `appconfig.rs` |

## 明确不在范围内（用户决定）

FlClash SQLite 事务、飞书通知、Web 检测页、独立仪表盘、首启视觉向导、
MSIX 客户端自动更新。

## 验证边界

- 所有能力均有单元测试（**v0.6.10 起 625 项全绿**，见 `docs/release-v0.6.10.md`）、clippy 零警告、tsc 通过。
- **系统级操作（防火墙/网卡/断网/Desktop 切换）的真实 Windows 管理员权限
  故障注入验收未执行**——需要可回滚的 Windows 虚拟机与独立管理通道。
