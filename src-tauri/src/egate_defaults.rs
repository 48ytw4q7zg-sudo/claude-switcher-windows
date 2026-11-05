//! 出口门禁的内置默认目标表（融合 ClaudeGuard `src/targets.rs`）。
//!
//! 行为基准：ClaudeGuard SPEC-v3 §1 的内置四目标表（固定 commit `1967377`）。
//! 关键取舍：**`local`（本机常规流量出口）默认关闭**——普通流量的出口通常与
//! AI 代理出口不同，默认开启会让首次启动就熔断。

use crate::egate::{AnchorKind, EgateTarget};

/// 内置目标定义（不含用户填的期望值；期望值在首次启用时按当前出口或手动填入）。
struct Builtin {
    id: &'static str,
    name: &'static str,
    anchor_url: &'static str,
    anchor_kind: AnchorKind,
    enabled: bool,
}

/// 内置目标表：顺序即界面展示顺序。
const BUILTINS: &[Builtin] = &[
    Builtin {
        // 默认关闭：常规流量出口往往与 AI 代理不同。
        id: "local",
        name: "本机出口",
        anchor_url: "https://cloudflare.com/cdn-cgi/trace",
        anchor_kind: AnchorKind::Auto,
        enabled: false,
    },
    Builtin {
        id: "claude",
        name: "Claude 出口",
        anchor_url: "https://claude.ai/cdn-cgi/trace",
        anchor_kind: AnchorKind::Auto,
        enabled: true,
    },
    Builtin {
        id: "codex",
        name: "Codex 出口",
        anchor_url: "https://chatgpt.com/cdn-cgi/trace",
        anchor_kind: AnchorKind::Auto,
        enabled: true,
    },
    Builtin {
        id: "antigravity",
        name: "反重力出口",
        anchor_url: "https://cloudcode-pa.googleapis.com/",
        anchor_kind: AnchorKind::Reachability,
        enabled: true,
    },
];

/// 默认被守护的桌面应用（熔断时结束进程 + 隔离）。
pub const DEFAULT_GUARDED_AGENTS: &[&str] = &["claude", "chatgpt", "antigravity"];

/// 生成内置默认目标表（期望值留空，由用户按需填入）。
pub fn builtin_targets() -> Vec<EgateTarget> {
    BUILTINS
        .iter()
        .map(|builtin| EgateTarget {
            id: builtin.id.to_string(),
            name: builtin.name.to_string(),
            anchor_url: builtin.anchor_url.to_string(),
            anchor_kind: builtin.anchor_kind,
            expect_ips: Vec::new(),
            expect_regions: Vec::new(),
            enabled: builtin.enabled,
            timeout_secs: 10,
        })
        .collect()
}

/// 目标 id 是否是内置目标（内置目标不允许删除，只能停用）。
pub fn is_builtin(id: &str) -> bool {
    BUILTINS.iter().any(|builtin| builtin.id == id)
}

/// 校验并归一化一份目标表（保存前调用）。
///
/// 规则：id 非空且不重复、名称非空、锚点地址合法、超时收敛到合法范围、
/// 地区码归一化（无法归一的原文保留但标记问题）。返回错误列表（空表示通过）。
pub fn validate_targets(targets: &[EgateTarget]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for target in targets {
        let id = target.id.trim();
        if id.is_empty() {
            errors.push("存在目标 id 为空".to_string());
            continue;
        }
        if seen.contains(&id) {
            errors.push(format!("目标 id 重复：{id}"));
        }
        seen.push(id);
        if target.name.trim().is_empty() {
            errors.push(format!("目标 {id} 名称为空"));
        }
        if let Err(reason) = crate::egate_probe::validate_anchor_url(&target.anchor_url) {
            errors.push(format!("目标 {id} 锚点地址无效：{reason}"));
        }
        if target.timeout_secs == 0 {
            errors.push(format!("目标 {id} 超时必须大于 0"));
        }
    }
    errors
}

/// 保存前的内置目标保护：内置目标不能被删除，其探测地址不能改。
///
/// 方向很重要：校验的是**配置里所有带内置 id 的条目**。若反过来只遍历内置默认表，
/// 用户新建一个 `id: "claude"` 的自定义目标就能绕过——它会顶替内置目标参与
/// 熔断决策，却指向任意地址。
pub fn check_builtin_protection(targets: &[EgateTarget]) -> Vec<String> {
    let mut errors = Vec::new();
    let saved: Vec<&str> = targets.iter().map(|t| t.id.trim()).collect();
    for builtin in builtin_targets() {
        if !saved.contains(&builtin.id.as_str()) {
            errors.push(format!(
                "内置目标「{}」不能删除，可以取消勾选停用",
                builtin.name
            ));
        }
    }
    for target in targets {
        let id = target.id.trim();
        if !is_builtin(id) {
            continue;
        }
        if let Some(expected) = builtin_targets()
            .into_iter()
            .find(|builtin| builtin.id == id)
        {
            if expected.anchor_url != target.anchor_url.trim() {
                errors.push(format!("内置目标「{}」的探测地址不能修改", expected.name));
            }
            // **P0-07（v0.7.6）**：锚点类型同样不可改。
            //
            // `evaluate()` 对 `Reachability` 直接按「能不能连上」判 Pass，
            // 完全不看出口 IP/地区；而 `unready_targets()` 又会跳过
            // Reachability 目标的白名单校验。两者叠加的结果是：
            // 把 Claude/Codex 改成 Reachability 就能把整套出口白名单
            // 绕过去——网站能访问就等于「安全」。
            if expected.anchor_kind != target.anchor_kind {
                errors.push(format!(
                    "内置目标「{}」的锚点类型不能修改（需保持「{}」），否则会绕过出口白名单校验",
                    expected.name,
                    expected.anchor_kind.label()
                ));
            }
        }
    }
    errors
}

/// 归一化地区码：能归一的转 alpha-2，其余原样保留（判定时按原文比较）。
pub fn normalize_expect_regions(regions: &[String]) -> Vec<String> {
    regions
        .iter()
        .map(|raw| {
            crate::egate::normalize_region(raw).unwrap_or_else(|| raw.trim().to_ascii_uppercase())
        })
        .filter(|value| !value.is_empty())
        .collect()
}

/// 归一化期望 IP：无法解析的条目直接剔除（留着永远不命中，只会误导用户）。
pub fn normalize_expect_ips(ips: &[String]) -> Vec<String> {
    ips.iter()
        .filter_map(|raw| crate::egate::normalize_ip(raw))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_table_covers_four_targets_with_local_disabled() {
        let targets = builtin_targets();
        assert_eq!(targets.len(), 4);
        let ids: Vec<&str> = targets.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["local", "claude", "codex", "antigravity"]);
        let local = targets.iter().find(|t| t.id == "local").unwrap();
        assert!(!local.enabled, "本机出口必须默认关闭，否则首次启动即熔断");
        assert!(
            targets.iter().filter(|t| t.enabled).count() == 3,
            "其余三个默认启用"
        );
    }

    #[test]
    fn antigravity_is_reachability_only() {
        let target = builtin_targets()
            .into_iter()
            .find(|t| t.id == "antigravity")
            .unwrap();
        assert_eq!(target.anchor_kind, AnchorKind::Reachability);
        assert!(target.expect_ips.is_empty() && target.expect_regions.is_empty());
    }

    #[test]
    fn builtin_ids_are_recognized_and_unknown_ids_are_not() {
        assert!(is_builtin("claude"));
        assert!(is_builtin("antigravity"));
        assert!(!is_builtin("user-defined"));
        assert!(!is_builtin(""));
    }

    #[test]
    fn validate_rejects_duplicate_ids_and_bad_urls() {
        let mut targets = builtin_targets();
        let errors = validate_targets(&targets);
        assert!(errors.is_empty(), "内置默认表必须合法：{errors:?}");
        targets.push(EgateTarget {
            id: "claude".to_string(),
            name: "重复".to_string(),
            anchor_url: "https://example.invalid/".to_string(),
            anchor_kind: AnchorKind::Auto,
            expect_ips: Vec::new(),
            expect_regions: Vec::new(),
            enabled: true,
            timeout_secs: 5,
        });
        assert!(validate_targets(&targets)
            .iter()
            .any(|e| e.contains("重复")));
        let mut bad = builtin_targets();
        bad[1].anchor_url = "ftp://example.invalid/".to_string();
        assert!(validate_targets(&bad)
            .iter()
            .any(|e| e.contains("锚点地址无效")));
        let mut empty_name = builtin_targets();
        empty_name[1].name = "  ".to_string();
        assert!(validate_targets(&empty_name)
            .iter()
            .any(|e| e.contains("名称为空")));
    }

    #[test]
    fn normalization_converts_regions_and_drops_bad_ips() {
        let regions = normalize_expect_regions(&[
            "us".to_string(),
            "JPN".to_string(),
            "xx".to_string(),
            "  ".to_string(),
        ]);
        assert_eq!(
            regions,
            vec!["US".to_string(), "JP".to_string(), "XX".to_string()]
        );
        let ips = normalize_expect_ips(&[
            " 1.2.3.4 ".to_string(),
            "not-an-ip".to_string(),
            "2001:db8::1".to_string(),
        ]);
        assert_eq!(ips, vec!["1.2.3.4".to_string(), "2001:db8::1".to_string()]);
    }

    /// **P0-07（v0.7.6）**：内置目标不得被降级成「仅可达性」。
    ///
    /// 回归点：`check_builtin_protection()` 原来只保护 `anchor_url`。
    /// 把 Claude 改成 `Reachability` 后，`evaluate()` 只看「能不能连上」
    /// 就判 Pass，`unready_targets()` 又跳过白名单校验——整套出口白名单
    /// 被绕过去。
    #[test]
    fn builtin_claude_cannot_be_downgraded_to_reachability() {
        let mut targets = builtin_targets();
        let claude = targets.iter_mut().find(|t| t.id == "claude").unwrap();
        claude.anchor_kind = AnchorKind::Reachability;

        assert!(
            !check_builtin_protection(&targets).is_empty(),
            "把内置目标改成仅可达性必须被拒绝"
        );
    }

    /// **P0-07**：反向改动同样禁止（把本就 Reachability 的目标改成 Trace），
    /// 且探测地址保护仍然有效。
    #[test]
    fn builtin_anchor_kind_is_pinned_in_both_directions() {
        let mut targets = builtin_targets();
        let antigravity = targets.iter_mut().find(|t| t.id == "antigravity").unwrap();
        antigravity.anchor_kind = AnchorKind::Trace;
        assert!(!check_builtin_protection(&targets).is_empty());

        let mut t2 = builtin_targets();
        let codex = t2.iter_mut().find(|t| t.id == "codex").unwrap();
        codex.anchor_url = "https://evil.invalid/trace".to_string();
        assert!(!check_builtin_protection(&t2).is_empty());

        assert!(check_builtin_protection(&builtin_targets()).is_empty());
    }

    #[test]
    fn builtin_protection_blocks_deletion_url_override_and_id_hijack() {
        // 正常保存：内置目标齐全且地址未改 → 无错误。
        assert!(check_builtin_protection(&builtin_targets()).is_empty());

        // 1. 删除内置目标。
        let mut missing = builtin_targets();
        missing.retain(|t| t.id != "claude");
        let errors = check_builtin_protection(&missing);
        assert!(errors.iter().any(|e| e.contains("不能删除")), "{errors:?}");

        // 2. 修改内置目标的探测地址。
        let mut url_changed = builtin_targets();
        url_changed[1].anchor_url = "https://evil.invalid/trace".to_string();
        let errors = check_builtin_protection(&url_changed);
        assert!(
            errors.iter().any(|e| e.contains("探测地址不能修改")),
            "{errors:?}"
        );

        // 3. 新建自定义目标复用内置 id 指向任意地址（绕过场景）必须被拦。
        let mut hijack = builtin_targets();
        hijack.retain(|t| t.id != "claude");
        hijack.push(EgateTarget {
            id: "claude".to_string(),
            name: "伪装目标".to_string(),
            anchor_url: "https://evil.invalid/trace".to_string(),
            anchor_kind: AnchorKind::Auto,
            expect_ips: Vec::new(),
            expect_regions: Vec::new(),
            enabled: true,
            timeout_secs: 5,
        });
        let errors = check_builtin_protection(&hijack);
        assert!(
            errors.iter().any(|e| e.contains("探测地址不能修改")),
            "复用内置 id 改地址必须被拒绝：{errors:?}"
        );
    }

    #[test]
    fn default_guarded_agents_match_upstream() {
        assert_eq!(
            DEFAULT_GUARDED_AGENTS,
            &["claude", "chatgpt", "antigravity"]
        );
    }
}
