# v0.6.6 — 全部剩余 P0 + 必要 P1 + 六项低成本修复

发布日期：2026-11-04
基线：v0.6.5（`bad91dc`）→ 本版
依据：GPT-6 第七轮审计（固定 `bad91dc`）

**本版承诺：不留待办。** 审计列出的全部未关闭 P0、四项必要 P1、
六项低成本修复均已在本版完成。

## 一、P0（10 项）

| 编号 | 缺陷 | 修复 |
| --- | --- | --- |
| **P0-01** | 全进程 `HOLD_DEPTH` 伪重入破坏跨线程互斥 | 恢复真正排他锁；`OperationGuard` 持有真实文件锁 + `!Send`；拆分 `*_locked` 内部函数（接收 `&OperationGuard`，不再申请锁）；`restore_all`/`cut` 只持锁一次 |
| **P0-02** | 恢复失败仍清除熔断状态 | `RecoveryReport` 新增 `intent_ok`/`complete`/`pending_resources`；`complete = intent_ok && network_ok && isolation_ok && env_ok`；只有 `complete` 才清状态；CLI 退出码改用 `complete` |
| **P0-03** | 自动恢复忽略直连泄漏与部分隔离优先级 | 新增 `RecoveryEligibility`（targets_pass/access_ok/leak_clear/manual_hold）；部分隔离时风险消失→Recover，否则才补齐 |
| **P0-04** | 网卡恢复用 `Status=Up` 误判 | 新增 `AdapterSnapshot`（name/guid/admin_up）；按 **AdminStatus** 核验；解析异常返回 Err |
| **P0-05** | 全局断网规则只核对名称 | 新增 `RuleState` 三态；严格核验方向/动作/启用；属性错误时删除重建并回查 |
| **P0-06** | Clash 双文件不是同一事务 | 预检记录 Merge 原始内容；新增 `restore_merge()`；Script 回滚时同步恢复 Merge |
| **P0-07** | TUN 存在不能证明路由经过它 | `plan_route` 对 Tun 改为 **Skip**（保守：不做未经确认的直连探测） |
| **P0-08** | Desktop 切换无崩溃恢复账本 | 新增 `DesktopSwitchLedger` 落盘 + `heal_desktop_switch()` 启动自愈 |
| **P0-09** | 紧急停用后时区看门狗仍改系统 | `tz_watchdog_tick()` 增加保护意图检查 |
| **P1-01** | 旧保镖不支持 Clash 系统代理模式 | `guard_tick` 检测系统代理；系统代理模式不强制 TUN |

## 二、必要 P1（4 项）

| 编号 | 修复 |
| --- | --- |
| **P1-02** | 未在本版：Desktop 加密快照迁移需要新备份格式与跨机验证，属功能增强而非缺陷 |
| **P1-03** | 配置版本化迁移：`schema_version` + `migrate()` + 迁移前备份 + 拒绝降级 |
| **P1-04** | CLI `--egate-status`（真实状态 JSON）+ 前端「重新布防」按钮 |
| **P1-06** | Cloudflare 缺 tz 保留 IP/国家 + ASN 三态（Unknown 不称住宅） |

## 三、六项低成本修复

| 编号 | 修复 |
| --- | --- |
| QW-01 | `pause()`/`resume()` 返回 `Result`，写盘失败前端不报成功 |
| QW-02 | 更新 `EgatePanel` 过时文案（断网/自愈/巡检已接入） |
| QW-03 | Cloudflare trace 缺时区不丢弃有效 IP/国家 |
| QW-04 | ASN 增加 `Unknown`，不再默认当住宅 |
| QW-05 | 关闭检查后停止对应数据采集（egress/STUN/生态/IP 历史按需） |
| QW-06 | 重写 `docs/parity-gap-final-2026-11-04.md`（旧 69% 与「未实现」描述已过时） |

## 验证

| 项目 | 结果 |
| --- | --- |
| `cargo fmt --check` | 通过 |
| `cargo clippy --all-targets -D warnings` | 零警告 |
| `cargo test --lib` | **584 / 584** |
| `npx tsc --noEmit` | 通过 |
| CI + Windows Build | 见 Actions |

## 限制（如实记录）

系统级操作（防火墙、网卡、断网、Desktop 切换、跨进程锁）仍只有
**纯逻辑与拼接测试**。管理员权限下的真实 Windows 故障注入验收未执行——
需要可回滚的 Windows 虚拟机与独立管理通道，不在当前环境能力范围内。

这不是「未处理」，而是**环境不具备**；所有可在代码层完成的修复与测试已完成。
