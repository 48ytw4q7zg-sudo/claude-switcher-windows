# Claude Desktop 语言检查对齐

基线为本仓库 `5fbbc05`，上游依据为
[YOURSJEYO/claude-switcher 的 6600bf9](https://github.com/YOURSJEYO/claude-switcher/commit/6600bf90db63b946286f3801f6b735aa01e7918c)。
此前检查读取 Windows 显示语言，无法代表 Claude 自身设置。

目标：读取 Claude `config.json` 的 `locale` 并与目标地区的主语言比较；传统目录存在但仅剩
MCP 配置时，仍能发现 MSIX 的实际语言配置。缺失、损坏、未设置或格式无效时警告。
读取配置不代表已验证运行中的 `navigator.language`。

文件与风险：

- `src-tauri/src/desktop.rs`：共用 MSIX 目录发现，增加只读配置解析。
  传统 `config.json` 存在时优先，即使损坏也不拿另一份配置掩盖错误；仅文件不存在时回退 MSIX。
  现有账号快照的活目录选择规则保留，由既有回归测试验证。
- `src-tauri/src/checks.rs`：第 12 项改接 Claude 配置，仍以主语言比较，错误/不一致保持 warn。
- `src-tauri/src/platform/windows.rs`：移除失去调用方的 PowerShell 系统 UI 语言查询及其专属测试。
  应用自身界面的 `user_default_ui_language` 继续保留。
- `README.md`、`docs/upstream-baseline.md`：同步当前测试数与 Windows-only CI 描述，
  按真实状态记录语言对齐和剩余差异，区分迁移目标与已经验证的交付。

语言格式对齐上游：主语言为 2–3 位 ASCII 字母，其后为 `-` 分隔的 2–8 位 ASCII 字母/数字；
比较时忽略大小写。复用 BOM 感知 JSON 读取，兼容 Windows UTF-8 BOM 与 UTF-16 文件。
所有测试均使用临时目录和合成配置，不读取真实账号配置，不改变系统或 Claude 的语言设置。

验证计划：先复现旧目录遮蔽 MSIX 配置；覆盖传统目录优先、包族精确匹配、唯一候选、
歧义/缺失、格式损坏、BOM/UTF-16 以及只读行为；再跑 fmt、clippy、全部单元测试和打包。
Codex 负责实现与验证；由于前一批已记录 Claude 模型不匹配、pi 健康检查失败，
按任务内 fallback 由单独的合格 Codex 调用审核最终文件指纹，之后再上传。

已完成失败复现：`client_locale_falls_back_to_msix_when_legacy_only_has_mcp_config`
在旧目录选择逻辑下返回「未能读取 Claude 的语言设置」，修正后通过。
新增 9 项语言配置回归测试均通过；删除 1 项已无调用方的旧系统语言解析测试，
相对 `5fbbc05` 净增 8 项，全量 **414 passed / 0 failed / 0 ignored**。
`cargo fmt --check` 与 `cargo clippy --all-targets -- -D warnings` 均通过，零警告。
安装包构建结论及固定内容的最终审查见 `docs/review-client-language-2026-11-01.md`，
调用与产物证据见 `docs/review-client-language-runtime-2026-11-01.json`。

真实 Claude/MSIX 安装环境、运行中的语言值以及安装升级/卸载行为仍为未验证。
本批不补写 ASN 网络类型查询、48 小时 IP 历史或凭据锁，这些仍属于持续优化的待办范围。

独立审查第一轮发现两个注册包族同时存在时按首项取值，已用交换顺序的测试复现。
语言读取路径现要求注册候选唯一，歧义返回警告。该限制仅用于语言检查，快照目录解析保留既有选择规则。

Windows 大小写别名经 `platform::normalize_path` 归一化后判为同一目录，新增用例先复现误报，再验证修复。
