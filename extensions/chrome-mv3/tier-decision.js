// ISS-20260423-007 —— 3 档策略决策纯函数(SW + Node 单测共用)。
//
// 设计:
//   - 纯函数 / 无副作用 / 不读全局状态 —— 便于 node --test 覆盖矩阵
//   - 常量 + 函数 ES module 导出;`background.js` import 后装配到 message handler
//   - 维护纪律:Rust 端 `crates/vigil-redaction` HARD_RULES 新增 name 时必须同步 SECRET_KINDS
//     / PII_KINDS;Node 单测 `scripts/test-local/ext-tier-decision.test.mjs` 守门

export const TIER_VALUES = Object.freeze(["strict", "balanced", "recall-first"]);
export const TIER_DEFAULT = "balanced";

/**
 * Secret 类 finding(凭证 / 密钥 / 私钥)—— strict 和 recall-first 均 block。
 * 与 `crates/vigil-redaction/src/lib.rs` HARD_RULES `name` 字面量对齐。
 * `vigil-browser` wire 短名由 FINDING_KIND_ALIASES 归一化后再查本集合。
 */
export const SECRET_KINDS = Object.freeze(
    new Set([
        "aws_access_key_id",
        "github_token",
        "anthropic_api_key",
        "openai_api_key",
        "pem_private_key",
        "jwt",
        "env_assignment",
        "slack_webhook",
        "stripe_secret_key",
        "google_api_key",
        "gitlab_pat",
        "database_url",
    ]),
);

/**
 * vigil-browser wire protocol uses stable short names for a few secret kinds,
 * while vigil-redaction hard rules use long names. Tier logic accepts both and
 * evaluates the canonical long name so strict/recall-first cannot miss aliases.
 */
export const FINDING_KIND_ALIASES = Object.freeze({
    aws_access_key: "aws_access_key_id",
    anthropic_key: "anthropic_api_key",
    openai_key: "openai_api_key",
});

/**
 * PII 类 finding(非凭证)—— recall-first 的"多类命中"阈值参与者。
 * v0.4 Stage 2+ 接入 Privacy Filter 模型层时必须扩展此集合(private_person /
 * private_phone / private_address / private_date)并同步更新单测。
 */
export const PII_KINDS = Object.freeze(
    new Set([
        "email",
    ]),
);

/** `internal_ipv4` 等不在 SECRET / PII,仅记数不影响决策 —— tier 逻辑按 "distinct count" */

export function canonicalFindingKind(kind) {
    return FINDING_KIND_ALIASES[kind] || kind;
}

/**
 * 应用 3 档决策层。
 *
 * **不变量**(纵深防御必保):
 *   - tier 只能 **收紧**,不能放宽
 *   - NH 返 allow → 任何档仍 allow
 *   - NH 返 block → 任何档仍 block
 *   - NH 返 redact → tier 可 override 为 block;不可 override 为 allow
 *
 * @param {{action:string, findings:string[], redacted_text?:string}} resp NH 原响应
 * @param {string} tier TIER_VALUES 之一;非法值按 balanced(fail-safe)
 * @returns {object} 决策后响应;override 场景加 `_tier_override` 标签便于审计
 */
export function applyTierDecision(resp, tier) {
    if (!resp || typeof resp.action !== "string") {
        return { action: "block", findings: [], _error: "invalid_resp_in_tier" };
    }
    const { action } = resp;
    const findings = Array.isArray(resp.findings) ? resp.findings : [];

    // allow / block 路径:tier 不参与(纵深防御不变量)
    if (action === "allow" || action === "block") {
        return resp;
    }

    // redact 路径:按 tier 决策
    const canonicalFindings = findings.map(canonicalFindingKind);
    const hasSecret = canonicalFindings.some((f) => SECRET_KINDS.has(f));
    const distinctKinds = new Set(canonicalFindings).size;

    if (tier === "strict") {
        if (hasSecret) {
            return {
                ...resp,
                action: "block",
                _tier_override: "strict_secret_block",
            };
        }
        return resp;
    }

    if (tier === "recall-first") {
        if (hasSecret) {
            return {
                ...resp,
                action: "block",
                _tier_override: "recall_first_secret_block",
            };
        }
        if (distinctKinds >= 2) {
            return {
                ...resp,
                action: "block",
                _tier_override: "recall_first_multi_kind_block",
            };
        }
        return resp;
    }

    // balanced(默认)+ 未知 tier 值:fail-safe 按 balanced,NH redact 直接通过
    return resp;
}
