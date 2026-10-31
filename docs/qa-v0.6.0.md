# QA 记录 · v0.6.0（K 批次收尾 + 上游新功能对等）

## 背景

v0.5.0（HEAD=f1800c5 之后的 3edc96f）交付 J-1~J-8 缺陷与 F-1~F-7 功能。
本版不做新功能扩张，而是收尾 Sonnet 5.5 第三轮审查（K 项）的遗留缺陷，
并把 YOURSJEYO 上游在基线 commit `870c4ca` 之后新增的 Windows 功能补齐。
分支 `k-batch-fixes`，合并范围 `3edc96f..8a1f6c5`。

## 本轮修复

### K-1 并行凭据回写：本地空操作改为后台核对（parallel.rs）

- 问题：`scan_parallel_credential_changes_into` 调 `verify_and_apply_credential`，
  而它只在磁盘 blob 能解析出 uuid 时才校验。真实 `.credentials.json` 的
  `claudeAiOauth` 通常**不含** uuid，于是本地校验恒为空操作，用户在并行终端
  `/login` 换了号，下次回写仍会覆盖原账号快照。
- 修复：新增纯函数 `classify_scanned_credential`，把处置分成
  `Reject`（本地可确认不一致）/ `Apply`（本地可确认一致）/
  `DeferToBackground`（本地解析不到身份）。扫描路径对第三种**不写**，
  交给 `sync_parallel_credentials_back` 后台线程走网络核对。
- 测试：`unknown_disk_identity_is_deferred_not_written`、
  `local_mismatch_is_rejected_with_adoption_hint`、
  `local_match_is_applied_immediately`、
  `missing_stored_uuid_defers_even_when_disk_resolves`、
  `scan_applies_verified_match_without_touching_other_profiles`。
- 状态：判定逻辑已验证；真实凭据是否含 uuid、网络核对是否取到身份 → 需实机验证。

### K-4 WSL 对账反被覆盖（wsl.rs）

- 问题：`sync_to_wsl_blocking` 判定 WSL 副本更新后，仍无条件执行
  `write_credentials_to_wsl`，紧接着又把新副本回写账号库——等于用本机旧副本
  覆盖了刚识别出的新令牌。
- 修复：新增纯函数 `should_write_local_credentials`，远端更新时跳过写入，
  只在报告里说明「已改为回写账号库」。
- 测试：`skips_write_when_remote_credential_is_newer`、
  `writes_when_remote_missing_or_older`、
  `writes_when_neither_side_has_expiry`。
- 状态：判定逻辑已验证；真实 WSL 写入需实机验证（本机仅 docker-desktop）。

### #45 权限与钩子编辑器丢配置（permissions.rs）

- 问题：`save_permission_editor` 用 `json!(permissions)` 整体替换
  `permissions` 子树、用 `build_hooks_value` 整体重建 `hooks`。用户手写的
  `permissions.defaultMode`、`additionalDirectories`、hook 上的 `timeout`
  以及本功能无法解析的钩子分组会被静默删除。
- 修复：改为纯函数 `apply_editor_to_settings` 合并写入——只替换
  allow/deny/ask 三个键、只更新已有 hook 对象的 `command`，
  其余字段与分组原样保留；全空时才删整块。
- 测试：`apply_editor_keeps_unknown_permission_keys`、
  `apply_editor_keeps_unknown_hook_fields`、
  `apply_editor_keeps_unparseable_hook_groups`、
  `apply_editor_drops_only_managed_lists_when_emptied`、
  `apply_editor_removes_permissions_block_when_only_managed_keys`、
  `apply_editor_truncates_removed_hooks_within_group`、
  `apply_editor_keeps_other_hook_events_when_editing_one`、
  `saved_hooks_round_trip_back_to_structure`。
- RED 验证：临时改回替换写法，5 个保留类测试失败（数据丢失被捕捉）。
- 状态：已验证。

### 上游新功能对等

| 上游功能 | 上游实现 | 本仓库 | 状态 |
| --- | --- | --- | --- |
| MSIX Claude 数据目录 | `Find-ClaudeDataPath`：legacy → `Get-AppxPackage` PackageFamilyName → 唯一 `claude_*` | `desktop::resolve_desktop_live_dir` + `platform::claude_appx_families` | 逻辑已验证，实机待验 |
| FlClash 代理客户端 | `Test-ProxyAlive` 判 `FlClashCore`/`FlClash` 进程 | `guard::required_process` 加 `flclash → flclashcore`；`set_client` 白名单 + 前端选项 | 已验证（纯逻辑） |
| 客户端语言按系统 UI 语言 | `CurrentUICulture`，不一致 `warn` 不 `fail` | `platform::current_ui_language` + `judge_client_language` 改主语言段比较、降级 warn | 已验证（纯逻辑） |
| 共享 skills 用联接 | Sonnet §三建议 junction 优先 | `link_or_copy_shared_skills`：junction 优先，失败降级复制 | 已验证（真实 junction 单测） |

### 上游 48h IP 历史（本轮不做）

上游 `Add-IpHistory` 记录 48 小时内出口 IP 变化次数，≥3 次时把「IP一致」
从 ok 升为 warn。本仓库 `judge_ip_consistency` 只比对上一次 IP。
该差异只影响 warn 档文案、不改变 fail 判定，本轮未实现，记录为剩余差距。

## 验证结果

| 检查 | 结果 |
| --- | --- |
| `cargo fmt --check` | 通过 |
| `cargo clippy --all-targets -- -D warnings` | 零警告 |
| `cargo test --lib` | **387 passed / 0 failed / 0 ignored**（v0.5.0 后 346 → 387，新增 41） |
| `npx tsc --noEmit` | 通过 |
| `npm run tauri build` | 本地已产出 MSI（10.22 MiB）+ NSIS（7.15 MiB）；合并后由 CI 出正式产物 |

## 独立审查

- Codex 车道两次调用均失败：默认路由 `gpt-6-astra` 与审查路由
  `deepseek-v4-pro` 都不被本账号支持（`model is not supported when using
  Codex with a ChatGPT account`），随后额度耗尽（提示 2026-11-17 恢复）。
- 按 §D fallback，改用一次独立合格审查者（Anthropic 最新旗舰，独立上下文、
  只读、不嵌套派发）审查 `3edc96f..8a1f6c5`，结论与失败证据一并记录。
- 审查发现的问题按 Critical/Important/Minor 分级处理；未闭环项如实列在下方。

## 仍无法实机验证项（如实标注）

- 真实凭据 blob 是否含 uuid 字段、OAuth profile 网络核对是否取到身份（K-1）。
- WSL 真实写入与 0600 权限（本机仅 docker-desktop 发行版）。
- MSIX 版 Claude Desktop 的数据目录（本机未安装 MSIX 版）。
- 安装包升级/卸载回归、托盘菜单、并行终端 wt/cmd 拉起、Toast 通知。
- F-4 凭据锁（原 P2-2）：仍待 Process Monitor 实机调研，本轮不实现、不加猜测锁。

## 独立审查发现并修复的问题

第一轮审查给出 ready-to-merge: No，发现 2 个 Critical。均已修复并补回归测试。

### Critical 1：账号库未登记 uuid 时跨账号覆盖（parallel.rs）

- 问题：`verify_and_apply_credential_inner` 的身份判断要求磁盘与账号库**都**解析出
  uuid。老账号快照没登记 uuid 时，后台网络核对到另一个账号的 uuid 也会直接放行
  回写——等于把并行终端里换号后的凭据写进原账号快照，之后切回去就串号。
- 修复：`(Some(disk), None)` 分支改为拒绝，并提示重新捕获该账号。
- 测试：`checked_refuses_when_stored_uuid_unknown_but_network_resolves`、
  `checked_refuses_when_stored_uuid_unknown_and_disk_uuid_unknown`。
  原有测试 `checked_applies_when_stored_uuid_unknown_but_network_resolves`
  固化了错误行为，已改名并反转断言。

### Critical 2：WSL 回写不核对账号身份（wsl.rs / lib.rs）

- 问题：`remote_newer_blob` 只按过期时间判定。WSL 里登着别的账号时，它的凭据会被
  写进当前账号快照（`lib.rs` 的 WSL 回写路径同样只看过期时间）。
- 修复：新增 `remote_blob_matches_profile`，用账号库登记的 uuid 与 WSL blob 的
  uuid 比对；`sync_to_wsl_blocking` 增加 `profile_uuid` 参数，
  `write_wsl_credentials` 传入 `profile.meta.account_uuid`。
  只有 `Some(true)` 才回写；`Some(false)` 拒绝并提示切换账号，`None` 提示重新捕获。
- 测试：`allows_writeback_only_when_remote_matches_profile`、
  `writeback_is_undecidable_when_either_uuid_missing`。

### Important 3：权限编辑器数据丢失（permissions.rs）

- 空列表删整个 `hooks` 块 → 改为保留隐藏分组，只有彻底空掉才删整块。
  测试：`apply_editor_keeps_hidden_hooks_when_user_deletes_all_visible_ones`、
  `apply_editor_removes_hooks_block_only_when_nothing_left`。
- stale 分组删不掉 → 编辑器展示过的 `(event, matcher)` 分组以编辑器为准。
  测试：`apply_editor_removes_hook_the_user_deleted_from_a_shown_event`、
  `apply_editor_removes_event_when_all_its_shown_hooks_deleted`。
- 非 command 类型钩子被接管 → `extract_hooks` 与合并都只认 `type == "command"`
  （或缺 type）的钩子。测试：`extract_hooks_skips_non_command_hook_types`。
- 混合分组按索引写回会覆盖/截断隐藏项 → 改为按 `is_editable_hook` 身份逐槽更新，
  隐藏项原位保留。测试：
  `apply_editor_keeps_hidden_hook_inside_a_mixed_group`、
  `apply_editor_deleting_visible_hook_in_mixed_group_keeps_hidden`。
- 界面增加说明：此列表是权威的，删掉即真删；读不出命令行的钩子原样保留。

### Important 4：工作区启停未约束 id（workspace.rs）

- 问题：`set_workspace_enabled` 的 id 来自前端，直接 `Path::join`。绝对 id 会丢弃
  基路径，`../` 会逃出配置目录，可能误移用户文件。
- 修复：新增 `validate_asset_id`（拒绝空、绝对/盘符/UNC、`.`/`..` 分量、反斜杠、
  控制字符），并在拼路径后加 `starts_with(claude_dir)` 双保险。
- 测试：`validate_asset_id_accepts_normal_and_nested_ids`、
  `validate_asset_id_rejects_traversal_and_absolute`、
  `paths_for_absolute_id_drops_the_base_dir`、
  `paths_for_traversal_id_builds_an_escaping_path`。

### Minor 5：后台回写无去重（parallel.rs）

- 问题：身份未知时不推进 `updated_at`，每次托盘刷新都会为同一账号再 spawn 线程。
- 修复：per-profile in-flight 集合（`try_claim_writeback` / `release_writeback`），
  Drop guard 覆盖含 panic 的所有退出路径。
- 测试：`writeback_claim_is_exclusive_and_releasable`、
  `writeback_claims_are_per_profile`。

### 审查车道可用性（如实记录）

- Codex 车道本机不可用：默认路由 `gpt-6-astra` 与审查路由 `deepseek-v4-pro`
  均不被该账号支持；随后账号额度耗尽（提示 2026-11-17 恢复）。
- 按 §D fallback，改用一次独立合格审查者（独立上下文、只读、不嵌套派发）
  完成两轮审查，失败证据与结论一并记录在此。

