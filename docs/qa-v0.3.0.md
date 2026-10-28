# QA 报告：v0.3.0「功能大全」账号管理增强

> 范围：v0.2.0 已迁移的环境安检 / 地区 / 保镖 / 规则 / 指纹等功能**保留不动**；
> 本轮只实现与「规避检测」无关的账号管理增强。基线 `v0.2.2`（commit a282419）。

## 一、本轮功能清单

| 编号 | 功能 | 落点 | 测试 |
| --- | --- | --- | --- |
| G-1 | 导入清空纯函数 `sanitize_imported_store` | `store.rs` / `export.rs` | 导入测试复用 |
| G-2 | 主密钥 `KeyBackend` trait（生产 Credential Manager / 测试内存） | `store.rs` | 往返、缺钥报错 |
| G-3 | 清 Windows-only 后 cfg 噪音（tray/isolation/keep/desktop/…） | 多文件 | 编译 + 既有测试 |
| P1-1 | 切换前对账 + 自动收养（Current/Other/Unknown） | `reconcile.rs` | 8 个 |
| P1-2 | 托盘一键切换（动态菜单/●/截断/子菜单/通知/重建） | `tray.rs` | 4 个 |
| P1-3 | 按终端并行多账号（独立 CLAUDE_CONFIG_DIR，wt/cmd 拉起） | `parallel.rs` | 4 个 |
| P1-4 | 额度阈值通知（80%/95%，每周期每档一次） | `notify_state.rs` | 4 个 |
| P2-3 | MCP 管理（mcpServers / .mcp.json，cmd /c 包装，校验） | `mcp.rs` | 7 个 |
| P2-4 | 便携版 zip（portable.flag，数据目录与 WebView2 重定向） | `paths.rs` / `lib.rs` / CI | 2 个 |
| P2-1 | 阈值提醒 + 一键切换（默认关闭，不做后台自动换号） | `usage.rs` / `QuotaReminder.tsx` | 1 个 |

## 二、关键设计与取舍

- **G-1**：`sanitize_imported_store` 清空 `current_profile_id` / `current_desktop_profile_id`
  / `desktop_profiles`（前两者是原机器运行时状态，desktop 快照目录不在导出文件里）。
- **G-2**：`KeyBackend` trait + 全局可注入后端（`RwLock<Option<Box<dyn …>>>`），
  测试用 `InMemoryKeyBackend` + `TestKeyBackendGuard`，杜绝读写真实凭据库。
- **P1-1**：live 身份三分类；Unknown 自动收养（名「自动收养-<邮箱或 uuid 前8>-<MMdd-HHmm>」），
  Other 回写并提示「检测到手动换号」；live 缺字段只提示不中断。
- **P1-3**：`-EncodedCommand`（UTF-16LE base64）启动 wt powershell，失败退回
  `cmd start powershell`（显示窗口，不用 silent_command）；共享 skills 走复制。
- **P1-4**：以 `resets_at` 为周期 key，`notify-state.json` 原子写，每周期每档一次。
- **P2-3**：`npx/npm/pnpm/yarn` stdio 自动 `cmd /c`；密钥 env 只落盘/回显，不进日志。
- **P2-4**：`WEBVIEW2_USER_DATA_FOLDER` 在 WebView2 创建前（Builder 之前）设置。
- **P2-1**：只提醒 + 推荐，不做后台自动换号（其他账号用量会过时、后台刷新令牌风险高）。

## 三、门禁结果

| 门禁 | 结果 |
| --- | --- |
| `cargo fmt --check` | 通过 |
| `cargo clippy --all-targets -- -D warnings` | 零警告 |
| `cargo test --lib` | **207 passed / 0 failed / 0 ignored** |
| `npx tsc --noEmit` | 通过 |
| `npm run tauri build` | 见发布记录（MSI + NSIS） |

## 四、未实机验证项（如实标注）

- 托盘一键切换（动态菜单 / 点击 / 通知 / 重建）——无显示器/托盘环境。
- 按终端并行多账号（wt/cmd 真实拉起、窗口显示、共享 skills）。
- 额度阈值通知 / 提醒（Toast 需 AUMID；开发模式显示成 PowerShell 身份属正常）。
- MCP 真实拉起（stdio 包装、.mcp.json 读写有单测，真实进程未测）。
- 便携版解压运行（WebView2 重定向、数据目录随 exe）。
- 自动更新全流程。

## 五、本轮不做：P2-2 凭据锁（待实机调研）

必须先用 **Process Monitor** 实机抓取 `claude.exe` / `node.exe` 刷新令牌时的锁文件
（路径、句柄、持续时间），确认后再实现，禁止凭猜测写。当前标记为「待实机调研」。
