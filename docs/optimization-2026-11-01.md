# 2026-11-01 持续优化记录

## 目标与历史基线

沿用 Windows-only、Tauri 2 + Rust + React、同时管理 CLI 与 Desktop 的产品方向。
本轮起点为 `8926880`（v0.6.0 发布说明补全），开始时工作区干净。
已定位并核对四个 Claude 会话：`06a0c73e`、`afb3e648`、`302512fb`、`e1fb330d`；
另读取用户打开的豆包「代码迁移与优化」对话
<https://www.doubao.com/chat/38449716533078786>。
历史报告仅作为线索，当前文件与真实验证结果优先。凭据锁 F-4 仍需实机调查，不猜测实现。

## 第一批：更新检查可靠性

验收结果：检查失败后短时间内重复操作不会连续请求 GitHub；成功结果仍缓存 6 小时、
失败缓存 10 分钟；缓存过期、时钟回拨或应用升级后重新检查；版本遵循 SemVer 优先级，
构建信息不影响新旧，非法版本不得显示「已是最新」；缓存不可写时仍返回本次检查结果。
发布页必须是本项目的 HTTPS GitHub Release，缺失/无效地址属于检查失败；旧缓存也重新校验。
保持现有「检查 + 打开发布页」交互，安装升级策略不在本批范围。

具体文件：

- `src-tauri/src/update.rs`：缓存编排与回归测试、版本解析及结果校验。
- `src-tauri/Cargo.toml`、`src-tauri/Cargo.lock`：显式使用锁文件中已有的 `semver`。
- 本文：需求来源、同类项目参考、验证与审查证据、后续工作。

测试边界采用实际更新检查编排入口的参数化内部版本，注入临时缓存位置、时间与网络请求，
不改生产环境变量，不访问真实账号库，不请求真实升级服务。先记录失败测试，再修复。
旧格式缓存保持可读；异常版本的旧缓存必须失效。

车道：Codex 负责恢复上下文、设计、实现、验证和最终核对；Claude Code 独立只读审查最终内容。
第三车道不分配实现任务。独立审查须记录实际模型、退出状态和最终内容 SHA256；修改后重新审查。

验证：更新模块测试；`cargo fmt --check`；`cargo clippy --all-targets -- -D warnings`；
`cargo test --lib`；前端类型/生产构建；Tauri MSI/NSIS 构建。
使用机器已安装的 MSVC/Windows SDK，构建环境仅对子进程生效。

## 同类项目与后续清单

- [YOURSJEYO/claude-switcher](https://github.com/YOURSJEYO/claude-switcher)：
  当前 `dfd2a5012a2633ebfe0d435cb3c15a089be58184`；对照原固定基线与 v0.6.0 对等表。
  相对 v0.6.0 核对的 `f37cb26` 新增两次提交。`6600bf9` 改为读取 Claude `config.json`
  的 `locale`（传统路径缺配置时再查 MSIX），并按出口 IP/AS 号核对网络类型。
  当前本项目仍读系统 UI 语言、按组织名关键词推测 ASN，属于明确的待对齐差异。
  最新 README 另描述可关闭的非关键检查、诊断日志与 48 小时 IP 历史等行为，需逐项核对现状。
- [farion1231/cc-switch](https://github.com/farion1231/cc-switch/blob/8be840557bacd89d592f13ddc1bee0586afaea14/src/lib/updater.ts)：
  更新入口分别返回「有更新」与「已是最新」，并设超时；参考其明确状态表达，保留本项目的发布页下载方案。
- [VallierDev/claude-switcher](https://github.com/VallierDev/claude-switcher)：继续作为 CLI 原始实现基线。
- 豆包提到的 #46 共享 junction 已在 v0.6.0 完成；#47 数据体积与旧会话清理向导、
  #48 供应商空模板需对照当前入口后独立排期，不凭旧报告认定已交付。
- Desktop 启动对等、安装包升级/卸载、托盘/Toast、真实 WSL 与凭据锁仍须区分实现与实机验证。

持续优化目标保持开放；本批修复不代表全部上游功能已重新逐行审计或所有实机项目已通过。

## 验证与独立审查

本批已复现并修复：

1. `0.7.0-rc.10` 未被认为高于 `0.7.0-rc.2`。
2. 失败后立即重复检查仍调用 GitHub，未落盘短缓存。
3. 非法发布版本被返回为成功结果。
4. 旧缓存继续沿用旧版本的错误比较结果；极端缓存时间戳触发减法溢出。
5. 缺失/错误发布页仍被当作成功结果缓存（独立预审指出，基线已有）。

回归测试调用真实编排逻辑，网络边界注入合成响应，文件读写使用临时目录。
未访问真实账号库或 Credential Manager。成功/失败缓存、到期恢复、升级失效、
损坏文件、时间回拨/溢出、无法写缓存、构建信息和预发布优先级均有覆盖。

| 检查 | 结果 |
| --- | --- |
| 更新模块测试 | 15 passed |
| 全量 Rust 测试 | 406 passed / 0 failed / 0 ignored（基线 394，新增 12） |
| `cargo fmt --check` | 通过 |
| `cargo clippy --all-targets -- -D warnings` | 通过，零警告 |
| `npm run build`（TypeScript + Vite） | 通过 |
| `npm run tauri build` | 通过，产出 MSI（10.24 MiB）和 NSIS（7.16 MiB）；未执行安装/卸载 |

首次 clippy 调用的 PowerShell 参数转发吞掉了 `-D`，编译器收到多余的 `warnings`
参数；改用显式 `BuildArgs` 数组后完整执行并通过。这是验证入口修正，不是放宽检查。

审查车道记录：

- Claude Code 2.1.316 请求 `claude-opus-5-5` / max，API 消息的 `model` 实际为
  `step-5-preview`。模型身份不符合 §D，取消该调用，不计合格审查。
- `pic --check` 退出 1：包版本不符合要求 0.85.1，桥接模型列表/默认提供商过期。
  本批不扩展为全局环境修复，不将健康检查计作模型执行。
- Codex CLI 0.166.0 的独立预审使用 `gpt-6-astra` / max，退出 0；指出缺失发布页的
  既有问题，已复现并修复。预审明确不批准尚在变化的文件。
- 按 §D 的任务内 fallback，以单独 Codex 调用对最终固定内容作正式复核；
  官方模型资格依据为 [OpenAI GPT-6 Astra 文档](https://developers.openai.com/api/docs/models/gpt-6-astra)。
  最终调用单次指定 `openai` 路由与 `gpt-6-astra` / max，不改持久默认配置。
  最终结论与逐文件 SHA256 见 `docs/review-update-check-2026-11-01.md`，
  保留多车道规则，不把本次 fallback 固化为默认。

技能审查：`requesting-code-review` 的 cc-switch 登记来源为 `obra/superpowers`，
实时 API 确认公开、未归档、309917 stars、2026-10-29 更新，已静态读取技能与审查模板。
`tdd` 的本地来源登记缺失，未将它作为已准入的执行技能；测试按本项目 §C 的失败复现要求手工完成。

本次上传仅包含这批修复与工程记录，不修改已有 v0.6.0 tag 或 Release。
上游差异、Desktop 实际配置读取、ASN、48 小时历史和 #47/#48 等后续项仍未在本批交付。
