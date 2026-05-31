//! 默认策略集 —— 对应方案 §3.5 的 8 条验收。
//!
//! 该集合应该是"**干净且完备**"的最小规则:
//! - 每条规则 priority 按严厉程度分层
//! - Deny 类 priority 高(100+),Approve 类 20-80,Allow 类 10
//! - 通过 [`default_ruleset`] 返回 [`Vec<PolicyRule>`],caller 用 `PolicyEngine::new`
//!   初始化引擎。

use vigil_types::EffectKind;

use crate::engine::{
    Condition, DescriptorState, EffectField, PolicyAction, PolicyRule, PolicyValue,
};

/// 返回一套默认规则集(**含 ISS-012 PII 规则**)。caller 可在其上增补或替换。
///
/// **ISS-012 R2 BLOCKER 1 修复**:之前 `default_pii_rules()` 是旁路函数,生产默认
/// 配置下 5 条 PII 规则不生效。现在 `default_ruleset()` 显式 append
/// `default_pii_rules()`,保证 `vigil-hub-cli::serve` 等消费者拿到完整规则集。
/// caller 若只想要 v0.3 规则可用 [`default_ruleset_v03_only`]。
pub fn default_ruleset() -> Vec<PolicyRule> {
    let mut rules = default_ruleset_v03_only();
    rules.extend(default_pii_rules());
    rules
}

/// 纯 v0.3 规则集(不含 ISS-012 PII 规则),供兼容/回归测试用。
pub fn default_ruleset_v03_only() -> Vec<PolicyRule> {
    vec![
        // ---- Deny (priority 100-200) ----
        PolicyRule {
            id: "deny-destructive-shell".into(),
            match_effects: vec![EffectKind::ExecNative],
            conditions: vec![Condition::Eq {
                field: EffectField::Destructive,
                value: PolicyValue::Bool(true),
            }],
            action: PolicyAction::Deny,
            priority: 200,
        },
        PolicyRule {
            id: "deny-destructive-sql".into(),
            match_effects: vec![EffectKind::DbWrite],
            conditions: vec![Condition::Eq {
                field: EffectField::Destructive,
                value: PolicyValue::Bool(true),
            }],
            action: PolicyAction::Deny,
            priority: 200,
        },
        PolicyRule {
            id: "deny-outside-project".into(),
            match_effects: vec![EffectKind::FsWrite],
            conditions: vec![Condition::Outside {
                field: EffectField::PathsWrite,
                roots_key: "project_roots".into(),
            }],
            action: PolicyAction::Deny,
            priority: 150,
        },
        // ---- Approve (priority 50-80) ----
        PolicyRule {
            id: "approve-repo-write".into(),
            match_effects: vec![EffectKind::FsWrite],
            conditions: vec![Condition::Inside {
                field: EffectField::PathsWrite,
                roots_key: "project_roots".into(),
            }],
            action: PolicyAction::Approve,
            priority: 80,
        },
        PolicyRule {
            id: "approve-unknown-host".into(),
            match_effects: vec![EffectKind::NetOutbound],
            conditions: vec![Condition::HostNotInAllowList {
                allowlist_key: "allowed_hosts".into(),
            }],
            action: PolicyAction::Approve,
            priority: 70,
        },
        PolicyRule {
            id: "approve-comm-send".into(),
            match_effects: vec![EffectKind::CommSend, EffectKind::BrowserSubmit],
            conditions: vec![],
            action: PolicyAction::Approve,
            priority: 70,
        },
        PolicyRule {
            id: "approve-secret-use".into(),
            match_effects: vec![EffectKind::SecretUse],
            conditions: vec![],
            action: PolicyAction::Approve,
            priority: 70,
        },
        PolicyRule {
            id: "approve-exec-native".into(),
            match_effects: vec![EffectKind::ExecNative],
            conditions: vec![],
            action: PolicyAction::Approve,
            priority: 60,
        },
        // ---- Descriptor 审批/漂移(§3.5-8):match_effects 空表示适用于任何 effect 组合 ----
        PolicyRule {
            id: "approve-descriptor-drift".into(),
            match_effects: vec![],
            conditions: vec![Condition::DescriptorIs(DescriptorState::Drifted)],
            action: PolicyAction::Approve,
            priority: 140,
        },
        PolicyRule {
            id: "approve-descriptor-first-seen".into(),
            match_effects: vec![],
            conditions: vec![Condition::DescriptorIs(DescriptorState::FirstSeen)],
            action: PolicyAction::Approve,
            priority: 130,
        },
        // ---- Allow (priority 10) ----
        PolicyRule {
            id: "allow-repo-read".into(),
            match_effects: vec![EffectKind::FsRead],
            conditions: vec![
                Condition::Inside {
                    field: EffectField::PathsRead,
                    roots_key: "project_roots".into(),
                },
                // 仅当 descriptor 已审批稳定才允许直放;drift/first-seen 由上面更高优先级规则接管
                Condition::DescriptorIs(DescriptorState::ApprovedStable),
            ],
            action: PolicyAction::Allow,
            priority: 10,
        },
    ]
}

/// ISS-012:默认 PII 规则集(Stage 2)。caller 按需 extend 到现有 rule set。
///
/// **5 条规则**:
/// 1. `secret_outbound_network_deny`:含 secret + `NetOutbound` → Deny(最严;`NetworkSend` 语义)
/// 2. `email_new_host_approve`:含 email + `HostNotInAllowList(allowed_hosts)` → Approve
/// 3. `multi_pii_firstseen_approve`:email + phone 同时命中 + `FirstSeen` descriptor → Approve
///    (Condition 无"跨 label 总数 ≥ N"原语,用两条 `PiiContains` AND 组合表达"多 PII")
/// 4. `secret_shell_exec_deny`:含 secret + `ExecNative` → Deny(`ShellExec` 语义,防 argv 泄漏)
/// 5. `secret_email_body_approve`:含 secret + `CommSend` → Approve(`EmailSend` 语义,建议脱敏)
///
/// EffectKind 映射(ISS-012 prompt 语义 → vigil-types 实际 variant):
/// - `NetworkSend` → [`EffectKind::NetOutbound`](vigil_types::EffectKind::NetOutbound)
/// - `ShellExec`   → [`EffectKind::ExecNative`](vigil_types::EffectKind::ExecNative)
/// - `EmailSend`   → [`EffectKind::CommSend`](vigil_types::EffectKind::CommSend)
///
/// 字面 label 与 `vigil_redaction::PrivacyLabel::as_str()` 对齐(lowercase)。
/// 规则 id 稳定,审计日志会引用 —— 修改需同步更新 `default_pii_rules_ids_are_unique_and_stable`
/// 精确集合测试(feedback_ssot_drift_guard)。
pub fn default_pii_rules() -> Vec<PolicyRule> {
    vec![
        // 1. secret + 网络外发 → 断(最严)
        PolicyRule {
            id: "secret_outbound_network_deny".into(),
            match_effects: vec![],
            conditions: vec![
                Condition::PiiContains {
                    label: "secret".into(),
                    min_count: 1,
                },
                Condition::EffectIncludes(EffectKind::NetOutbound),
            ],
            action: PolicyAction::Deny,
            priority: 100,
        },
        // 4. secret + 原生进程执行 → 断(ShellExec 语义;防 argv/heredoc 里带 secret)
        PolicyRule {
            id: "secret_shell_exec_deny".into(),
            match_effects: vec![],
            conditions: vec![
                Condition::PiiContains {
                    label: "secret".into(),
                    min_count: 1,
                },
                Condition::EffectIncludes(EffectKind::ExecNative),
            ],
            action: PolicyAction::Deny,
            priority: 90,
        },
        // 2. email + 新 host(不在 allowed_hosts)→ 审
        PolicyRule {
            id: "email_new_host_approve".into(),
            match_effects: vec![],
            conditions: vec![
                Condition::PiiContains {
                    label: "email".into(),
                    min_count: 1,
                },
                Condition::HostNotInAllowList {
                    allowlist_key: "allowed_hosts".into(),
                },
            ],
            action: PolicyAction::Approve,
            priority: 60,
        },
        // 5. secret + 通讯外发(邮件/IM/PR comment)→ 审(EmailSend 语义)
        //    不直接 Deny,可能是合法 sysadmin 流程;建议 redact 后再发。
        PolicyRule {
            id: "secret_email_body_approve".into(),
            match_effects: vec![],
            conditions: vec![
                Condition::PiiContains {
                    label: "secret".into(),
                    min_count: 1,
                },
                Condition::EffectIncludes(EffectKind::CommSend),
            ],
            action: PolicyAction::Approve,
            priority: 55,
        },
        // 3. 多 PII(email + phone)+ 首次见 descriptor → 审
        //    Condition 层无"跨 label 总数 ≥ N"原语,用两条 PiiContains AND 组合表达
        //    "多类 PII 同时出现"(比单条 label 计数更能捕获跨域数据泄漏)。
        PolicyRule {
            id: "multi_pii_firstseen_approve".into(),
            match_effects: vec![],
            conditions: vec![
                Condition::PiiContains {
                    label: "email".into(),
                    min_count: 1,
                },
                Condition::PiiContains {
                    label: "phone".into(),
                    min_count: 1,
                },
                Condition::DescriptorIs(DescriptorState::FirstSeen),
            ],
            action: PolicyAction::Approve,
            priority: 50,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{PolicyContext, PolicyEngine};
    use vigil_types::EffectVector;

    fn ctx_with_project(root: &str) -> PolicyContext {
        let mut c = PolicyContext::default();
        c.roots.insert("project_roots".into(), vec![root.into()]);
        c.allowlists
            .insert("allowed_hosts".into(), vec!["api.github.com".into()]);
        c
    }

    #[test]
    fn default_ruleset_is_non_empty() {
        let rs = default_ruleset();
        assert!(rs.len() >= 8);
        // 验收对照需要的 id 齐全
        for need in [
            "deny-destructive-shell",
            "deny-destructive-sql",
            "deny-outside-project",
            "approve-repo-write",
            "approve-unknown-host",
            "approve-comm-send",
            "approve-secret-use",
            "allow-repo-read",
        ] {
            assert!(
                rs.iter().any(|r| r.id == need),
                "missing default rule: {}",
                need
            );
        }
    }

    #[test]
    fn repo_read_is_allowed_by_default() {
        let e = PolicyEngine::new(default_ruleset());
        let ctx = ctx_with_project("/proj");
        let eff = EffectVector {
            effects: vec![EffectKind::FsRead],
            paths_read: vec!["/proj/src/main.rs".into()],
            ..Default::default()
        };
        assert_eq!(
            e.evaluate(&eff, &ctx).unwrap().action,
            PolicyAction::Allow,
            "主方案 §3.5-1: repo 内读文件 → allow"
        );
    }

    // ───────────────────────── ISS-012:default_pii_rules ─────────────────────────

    #[test]
    fn default_pii_rules_count_is_5() {
        let rules = default_pii_rules();
        assert_eq!(rules.len(), 5, "ISS-012 默认 5 条 PII 规则");
    }

    #[test]
    fn default_pii_rules_ids_are_unique_and_stable() {
        // feedback_ssot_drift_guard:精确集合双向 diff,防改名漏测
        use std::collections::BTreeSet;
        let rules = default_pii_rules();
        let ids: BTreeSet<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids.len(), 5, "规则 id 重复");
        let expected: BTreeSet<&str> = [
            "secret_outbound_network_deny",
            "email_new_host_approve",
            "multi_pii_firstseen_approve",
            "secret_shell_exec_deny",
            "secret_email_body_approve",
        ]
        .into_iter()
        .collect();
        assert_eq!(ids, expected, "规则 id 集合漂移");
    }

    #[test]
    fn default_pii_rules_integrate_with_engine() {
        // 端到端:放进 PolicyEngine 能 evaluate;空上下文无命中 → 兜底 Deny
        let engine = PolicyEngine::new(default_pii_rules());
        let effects = EffectVector::default();
        let ctx = PolicyContext::default();
        let decision = engine.evaluate(&effects, &ctx).unwrap();
        assert_eq!(decision.action, PolicyAction::Deny);
        assert_eq!(
            decision.policy_ids,
            vec!["default-deny".to_string()],
            "空输入不应命中任何 PII 规则"
        );
    }

    // R2 MUST-FIX 4 — 5 条默认 PII 规则逐条行为测(命中 / 动作 / 优先级)
    // 每条独立构造 effects + ctx,直接 engine.evaluate,断言 action + policy_ids。

    fn pii_ctx_with(label: &str, count: u32) -> PolicyContext {
        use std::collections::HashMap;
        // engine.evaluate 会跑**所有**规则,其中 email_new_host_approve 引用
        // allowed_hosts 键;未配置时会 UnknownContextKey Err。给所有 per-rule
        // 测试 ctx 都补一个空 allowed_hosts,避免跑其他无关规则时报错。
        let mut allowlists: HashMap<String, Vec<String>> = HashMap::new();
        allowlists.insert("allowed_hosts".into(), Vec::new());
        PolicyContext {
            allowlists,
            pii_findings: vec![crate::engine::PiiFindingSummary {
                label: label.into(),
                count,
            }],
            ..PolicyContext::default()
        }
    }

    #[test]
    fn rule_secret_outbound_network_deny_hits() {
        let engine = PolicyEngine::new(default_pii_rules());
        let effects = EffectVector {
            effects: vec![EffectKind::NetOutbound],
            ..EffectVector::default()
        };
        let ctx = pii_ctx_with("secret", 1);
        let d = engine.evaluate(&effects, &ctx).unwrap();
        assert_eq!(d.action, PolicyAction::Deny, "secret+outbound 必 Deny");
        assert!(d
            .policy_ids
            .iter()
            .any(|id| id == "secret_outbound_network_deny"));
    }

    #[test]
    fn rule_email_new_host_approve_hits_when_host_outside_allowlist() {
        use std::collections::HashMap;
        let engine = PolicyEngine::new(default_pii_rules());
        let effects = EffectVector {
            network_hosts: vec!["evil.example".into()],
            ..EffectVector::default()
        };
        // allowlist 不含 evil.example → HostNotInAllowList 真,email PII 命中 → Approve
        let mut allowlists: HashMap<String, Vec<String>> = HashMap::new();
        allowlists.insert("allowed_hosts".into(), vec!["trusted.example".into()]);
        let ctx = PolicyContext {
            allowlists,
            pii_findings: vec![crate::engine::PiiFindingSummary {
                label: "email".into(),
                count: 1,
            }],
            ..PolicyContext::default()
        };
        let d = engine.evaluate(&effects, &ctx).unwrap();
        // 可能并行命中 secret 类规则 effects 集合,这里 effects 无 NetOutbound/ExecNative/CommSend,
        // 仅此规则命中 → Approve 是 fail-closed 合并后的最终动作
        assert_eq!(
            d.action,
            PolicyAction::Approve,
            "email + new host 应 Approve;实际 ids={:?}",
            d.policy_ids
        );
        assert!(d.policy_ids.iter().any(|id| id == "email_new_host_approve"));
    }

    #[test]
    fn rule_multi_pii_firstseen_approve_hits() {
        use std::collections::HashMap;
        let engine = PolicyEngine::new(default_pii_rules());
        let effects = EffectVector::default();
        let mut allowlists: HashMap<String, Vec<String>> = HashMap::new();
        allowlists.insert("allowed_hosts".into(), Vec::new());
        let ctx = PolicyContext {
            allowlists,
            descriptor: DescriptorState::FirstSeen,
            pii_findings: vec![
                crate::engine::PiiFindingSummary {
                    label: "email".into(),
                    count: 1,
                },
                crate::engine::PiiFindingSummary {
                    label: "phone".into(),
                    count: 1,
                },
            ],
            ..PolicyContext::default()
        };
        let d = engine.evaluate(&effects, &ctx).unwrap();
        assert_eq!(d.action, PolicyAction::Approve);
        assert!(d
            .policy_ids
            .iter()
            .any(|id| id == "multi_pii_firstseen_approve"));
    }

    #[test]
    fn rule_secret_shell_exec_deny_hits() {
        let engine = PolicyEngine::new(default_pii_rules());
        let effects = EffectVector {
            effects: vec![EffectKind::ExecNative],
            ..EffectVector::default()
        };
        let ctx = pii_ctx_with("secret", 1);
        let d = engine.evaluate(&effects, &ctx).unwrap();
        assert_eq!(d.action, PolicyAction::Deny);
        assert!(d.policy_ids.iter().any(|id| id == "secret_shell_exec_deny"));
    }

    #[test]
    fn rule_secret_email_body_approve_hits() {
        let engine = PolicyEngine::new(default_pii_rules());
        let effects = EffectVector {
            effects: vec![EffectKind::CommSend],
            ..EffectVector::default()
        };
        let ctx = pii_ctx_with("secret", 1);
        let d = engine.evaluate(&effects, &ctx).unwrap();
        assert_eq!(d.action, PolicyAction::Approve);
        assert!(d
            .policy_ids
            .iter()
            .any(|id| id == "secret_email_body_approve"));
    }

    /// R2 NICE 2 守门:default_pii_rules 里任何 PiiContains 的 min_count 都必须 ≥ 1。
    /// `min_count = 0` 是平凡条件(永真),默认规则用它就是"误 allow"陷阱。
    #[test]
    fn default_pii_rules_no_min_count_zero() {
        let rules = default_pii_rules();
        for r in &rules {
            for c in &r.conditions {
                if let Condition::PiiContains { label, min_count } = c {
                    assert!(
                        *min_count >= 1,
                        "rule `{}` 含 PiiContains label=`{}` min_count=0 (trivially true);\
                         默认规则禁用 min_count=0,caller 显式 ≥ 1",
                        r.id,
                        label
                    );
                }
            }
        }
    }
}
