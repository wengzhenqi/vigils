import test from "node:test";
import assert from "node:assert/strict";
import {
    scanText,
    redactText,
    hasFindings,
} from "../redaction-rules.js";
import { decideRisk } from "../risk-decision.js";

const REQUEST_ID = "11111111-1111-4111-8111-111111111111";

test("scanText detects and redacts common consumer secrets", () => {
    const text = [
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDE1234567890",
        "DATABASE_URL=postgres://user:p%40ssword@example.com/db",
        "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ].join("\n");

    const findings = scanText(text);
    assert.deepEqual(
        findings.map((f) => f.kind).sort(),
        ["database_url", "env_assignment", "jwt", "openai_api_key"].sort(),
    );
    assert.equal(findings.every((f) => f.redactable), true);

    const redacted = redactText(text, findings);
    assert.match(redacted, /\[REDACTED openai_api_key\]/);
    assert.match(redacted, /\[REDACTED database_url\]/);
    assert.match(redacted, /\[REDACTED jwt\]/);
    assert.equal(redacted.includes("sk-proj-abcdefghijklmnopqrstuvwxyz"), false);
    assert.equal(redacted.includes("p%40ssword"), false);
    assert.equal(hasFindings(redacted), false);
});

test("decideRisk returns confirm_redact for redactable findings", () => {
    const text = "token ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD";
    const findings = scanText(text);

    const result = decideRisk({ request_id: REQUEST_ID, text }, findings);

    assert.equal(result.request_id, REQUEST_ID);
    assert.equal(result.action, "confirm_redact");
    assert.deepEqual(result.findings.map((f) => f.kind), ["github_token"]);
    assert.match(result.redacted_text, /\[REDACTED github_token\]/);
});

test("PEM private key is block-only", () => {
    const text = [
        "-----BEGIN PRIVATE KEY-----",
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
        "-----END PRIVATE KEY-----",
    ].join("\n");

    const findings = scanText(text);
    const result = decideRisk({ request_id: REQUEST_ID, text }, findings);

    assert.equal(findings[0].kind, "pem_private_key");
    assert.equal(findings[0].severity, "high");
    assert.equal(findings[0].redactable, false);
    assert.equal(result.action, "block");
    assert.equal(result.redacted_text, undefined);
});

test("safe text is allowed", () => {
    const text = "Please summarize this public README section.";
    const findings = scanText(text);
    const result = decideRisk({ request_id: REQUEST_ID, text }, findings);

    assert.deepEqual(findings, []);
    assert.deepEqual(result, {
        request_id: REQUEST_ID,
        action: "allow",
        findings: [],
        source: "consumer_js",
    });
});
