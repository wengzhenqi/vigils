import test from "node:test";
import assert from "node:assert/strict";
import { applyTierDecision } from "../tier-decision.js";

test("strict blocks object-shaped consumer secret findings", () => {
    const result = applyTierDecision(
        {
            action: "confirm_redact",
            findings: [{ kind: "openai_api_key", severity: "medium", redactable: true }],
            redacted_text: "OPENAI_API_KEY=[REDACTED openai_api_key]",
        },
        "strict",
    );

    assert.equal(result.action, "block");
    assert.equal(result._tier_override, "strict_secret_block");
});

test("recall-first blocks object-shaped consumer secret findings", () => {
    const result = applyTierDecision(
        {
            action: "confirm_redact",
            findings: [{ kind: "github_token", severity: "medium", redactable: true }],
            redacted_text: "[REDACTED github_token]",
        },
        "recall-first",
    );

    assert.equal(result.action, "block");
    assert.equal(result._tier_override, "recall_first_secret_block");
});

test("recall-first multi-kind logic handles mixed finding shapes", () => {
    const result = applyTierDecision(
        {
            action: "confirm_redact",
            findings: ["email", { kind: "internal_ipv4", severity: "low", redactable: true }],
            redacted_text: "mail [REDACTED email] ip [REDACTED internal_ipv4]",
        },
        "recall-first",
    );

    assert.equal(result.action, "block");
    assert.equal(result._tier_override, "recall_first_multi_kind_block");
});
