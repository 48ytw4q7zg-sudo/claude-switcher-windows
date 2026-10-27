# v0.2.0 Full Parity Audit and Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 独立复核 v0.2.0 的全部受控源码、两个固定上游的功能覆盖与发布证据；对确认缺陷先做失败复现，再最小修复并重新发布，不虚报实机验证。

**Architecture:** 以 `VallierDev@6897984` 与 `YOURSJEYO@870c4ca` 为行为基线，保持现有 Tauri 2 架构。父会话负责命令层、平台层和集成；只读审查者分别覆盖快照链路与诊断/前端链路，Codex 负责环境/保镖独立审查。所有修复由父会话统一落盘，避免并发写。

**Tech Stack:** Rust 1.88+, Tauri 2, React 19, TypeScript, PowerShell 5.1, GitHub Actions/Releases.

**Spec:** `AGENTS.md`; `docs/upstream-baseline.md`; 固定上游 `D:\1\_upstream_analysis` 和独立 VallierDev 基线快照；用户本轮全量审查、优化、上传要求。

## Global Constraints

- 平台条件编译只放 `platform/`；业务模块不写 `#[cfg(windows)]`。
- 可能阻塞的 Tauri 命令走 `blocking(...)`；凭据/store/全局配置用原子写，解密失败绝不生成新密钥。
- 不读取真实凭据，不把秘密写入日志/报告/提交；测试只用临时目录和合成数据。
- 新行为/缺陷修复必须先写能失败的回归测试并记录 RED，再做最小实现并确认 GREEN。
- 不执行真实 kill、改时区/区域/IPv6、Clash 重启、保镖注册或安装/卸载等实机破坏性动作。
- GitHub 上传仅限本仓库已授权目标；内容变化后必须重新做独立审查，不能沿用旧哈希批准。

---

### Task 1: 全量覆盖与基线对账

**Files:**
- Read: all `git ls-files` source/config/docs in this repository.
- Read: `D:\1\_upstream_analysis\{core,windows,app,docs,tests,daemons,installer,linux}`.
- Read: VallierDev `src-tauri/src/lib.rs` and `src/`.
- Modify: `docs/upstream-baseline.md`, `docs/qa-report.md`.

**Interfaces:**
- Produces: confirmed findings with `file:line`, reproduction and exact reviewed commit hashes.

- [x] Record clean `3a13ddc` baseline, Release assets, test/type/build/clippy results.
- [ ] Complete disjoint read-only reviews and upstream regression baseline.
- [ ] Reproduce suspected functional gaps independently; distinguish defects from scope enhancements.
- [ ] Build final matrix: verified logic / runtime-unverified / missing / intentionally adapted.

### Task 2: 已确认行为缺陷的 RED→GREEN 修复

**Files:**
- Modify only modules implicated by confirmed findings, plus their in-module tests.

**Interfaces:**
- Each finding receives a test named after the wrong branch or missing side effect it catches.

For each confirmed defect:
- [ ] Add a minimal regression test with hand-derived expected behavior.
- [ ] Run the focused test and record the expected failure against unmodified production code.
- [ ] Implement the smallest correct fix; no speculative rewrite or unrelated feature.
- [ ] Re-run focused and affected-module tests; review the actual diff.
- [ ] Commit only after cross-lane/independent review requirements are satisfied or explicitly reported pending.

### Task 3: Windows 适配与遗漏功能补齐

**Files:**
- Candidate: `platform/{windows,unix}.rs`, `guard.rs`, `checks.rs`, `egress.rs`, `region.rs`, `rules.rs`, `update.rs`, corresponding React components.
- Exact edits follow confirmed Task 1 findings; no placeholder implementation.

**Interfaces:**
- Preserve existing command response shapes where possible; any additive field must have a TypeScript counterpart and no silent fallback.
- Any installer/update operation must verify official asset source and SHA256 before changing installed files.

- [ ] Test non-terminating PowerShell error propagation without changing system state.
- [ ] Cover missing 48-hour egress history and confirmed guard/runtime semantics with pure tests.
- [ ] Address actual update and launch/switch behavior gaps only after their baseline paths are read and reproduced.
- [ ] Record intentionally different platform behavior rather than claiming line-for-line equivalence.

### Task 4: 全量验证、独立复审与发布

**Files:**
- Modify: `README.md`, `docs/upstream-baseline.md`, `docs/qa-report.md`, `docs/superpowers/plans/2026-10-27-full-parity-audit.md`.
- Build: MSI + NSIS + `SHA256SUMS.txt`.

- [ ] Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --lib`, `npx tsc --noEmit`, `npm run build`, `npm run tauri build`.
- [ ] Obtain a fresh review of the exact final diff/hash; record model/route identity and failures accurately.
- [ ] Reconcile source/package versions, local/CI hashes, Release assets and remote `main`.
- [ ] Close out each user requirement and every skipped runtime lane as `未验证` where applicable.

## Plan Self-Review

- Spec coverage: CLI/Desktop accounts, 14 checks/fix, guard/watchdog, region/client, rules/WebRTC/STUN, diagnostics/open-safe/fingerprint/cli-info, export/keep/update, frontend/tray/build/release are assigned to a reviewer or parent read.
- No production implementation is prescribed before a failing reproduction; candidate files are not authorization for speculative edits.
- Shared writes remain with the parent; reviewers have no mutation rights and no nested delegation.
