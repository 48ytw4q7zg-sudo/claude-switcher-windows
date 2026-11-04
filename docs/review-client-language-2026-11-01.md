**2026-11-01｜Ready to merge: With fixes**

范围：清单中的六个文件，基线 `5fbbc05d52943d90deaa148713b3aaabfafb970b`。发现 **1 项 P2，当前冻结版本不批准合并**；未发现 P0/P1。

**P2：多个注册包族命中时，语言检查未处理歧义。**
位置：`src-tauri/src/desktop.rs:75`、`src-tauri/src/desktop.rs:129`。

传统 `config.json` 缺失时，`resolve_msix_data_dir` 遇到首个存在的注册包族目录就返回。若两个注册包族的目录均存在，分别配置 `en-US`、`ja-JP`，目标为 `en-US`，则返回顺序会决定检查结果，首个匹配即可显示 `ok`，不符合“歧义时警告”。这是静态可确认的分支行为，本次未执行复现。

建议在**语言读取路径**中要求注册候选唯一，否则返回错误并显示 `warn`；保留快照原有选择规则。补充两个有效注册包族及交换顺序的临时目录测试。现有测试仅覆盖空列表或单个注册包族。

其他主要要求符合：已有传统配置即使损坏也优先；缺失、损坏或非法语言值进入警告；语法校验符合指定 ASCII 规则；复用 `jsonio::read_json_optional`；主语言比较忽略大小写。快照选择语义保持，`user_default_ui_language` 保留，仅删除旧查询、解析器及专属测试。新增调用位于 `run_checks_blocking`，AppX 查询仍经平台模块。

**父流程验证证据**（日志均位于 `.tmp-tool-results/client-language/`）：

| 日志 | 本次读取结果 |
| --- | --- |
| `red-msix.log` | 旧目录遮蔽 MSIX 的用例失败，符合失败复现记录 |
| `locale-tests.log` | 7 passed，0 failed |
| `all-tests.log` | 412 passed，0 failed，0 ignored；新增 7、删除 1，净增 6 |
| `fmt.log`、`clippy.log` | fmt 日志为空，通过状态来自父流程；clippy 记录完成且无警告 |
| `tauri-build.log` | 记录 `tsc && vite build` 完成及 MSI、NSIS 两个包构建完成；进程退出 0 由父流程报告 |

**实际 SHA256**：审阅前后复算一致，六项均匹配 `review-manifest.json`。

| 仓库相对路径 | SHA256 |
| --- | --- |
| `src-tauri/src/desktop.rs` | `71875062d6bc003aded86130a47976d7a64a0d557e8f8e846d98574c5aae0ca1` |
| `src-tauri/src/checks.rs` | `9c15fedf3764bebfa7f7e6670ff99bec7cbbb8e4d48661f1074a8dd292305314` |
| `src-tauri/src/platform/windows.rs` | `9780d822709214a84400da106cbc341bfe50029217378777f0913ffdfbb13f1e` |
| `README.md` | `0d4d15feb076d9c8cb81bbe3aa3da8e64053a9b2db1676a2a2a108fda7ef28b9` |
| `docs/upstream-baseline.md` | `6b7febe32be4997438fd08e7227878e3f639ef362cca864e259f9bc28a9f18e9` |
| `docs/optimization-client-language-2026-11-01.md` | `7a13b04f498aa78c8ef682a746f4c978e5e1724926a92b08778ddd071f1799a1` |

本次仅完成只读静态审阅、日志检查及哈希核对，未重跑测试或构建，未修改文件。真实 MSIX、运行时 `navigator.language`、安装升级/卸载仍为**未验证**；模型身份及最新旗舰资格本轮未核验。结论仅对应上述指纹，修复后须重新验证并审计新哈希。