const RULES = Object.freeze([
    {
        kind: "pem_private_key",
        severity: "high",
        redactable: false,
        pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    },
    {
        kind: "openai_api_key",
        severity: "medium",
        redactable: true,
        pattern: /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b/g,
    },
    {
        kind: "anthropic_api_key",
        severity: "medium",
        redactable: true,
        pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    },
    {
        kind: "google_api_key",
        severity: "medium",
        redactable: true,
        pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    },
    {
        kind: "github_token",
        severity: "medium",
        redactable: true,
        pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/g,
    },
    {
        kind: "gitlab_pat",
        severity: "medium",
        redactable: true,
        pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    },
    {
        kind: "slack_webhook",
        severity: "medium",
        redactable: true,
        pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/+_-]+\/[A-Za-z0-9/+_-]+\/[A-Za-z0-9/+_-]+/g,
    },
    {
        kind: "stripe_secret_key",
        severity: "medium",
        redactable: true,
        pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    },
    {
        kind: "aws_access_key_id",
        severity: "medium",
        redactable: true,
        pattern: /\bA[KS]IA[0-9A-Z]{16}\b/g,
    },
    {
        kind: "jwt",
        severity: "medium",
        redactable: true,
        pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    },
    {
        kind: "database_url",
        severity: "medium",
        redactable: true,
        pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^:\s/@]+:[^@\s]+@[^\s]+/gi,
    },
    {
        kind: "env_assignment",
        severity: "medium",
        redactable: true,
        pattern: /\b[A-Z][A-Z0-9_]{2,}=(?!(?:true|false|null)\b)[^\s"'`]{6,}/g,
    },
]);

function findRule(kind) {
    return RULES.find((rule) => rule.kind === kind) || null;
}

function replaceAll(text, pattern, replacer) {
    pattern.lastIndex = 0;
    return text.replace(pattern, replacer);
}

function selectedKindsFor(text, findings) {
    if (Array.isArray(findings) && findings.length > 0) {
        return new Set(
            findings
                .map((finding) => finding && finding.kind)
                .filter((kind) => typeof kind === "string" && kind.length > 0),
        );
    }

    return new Set(scanText(text).map((finding) => finding.kind));
}

function patternMatches(pattern, text) {
    pattern.lastIndex = 0;
    const matched = pattern.test(text);
    pattern.lastIndex = 0;
    return matched;
}

function redactAssignment(match) {
    const equalIndex = match.indexOf("=");
    if (equalIndex < 0) return "[REDACTED env_assignment]";

    const key = match.slice(0, equalIndex);
    const value = match.slice(equalIndex + 1);
    const nestedRule = RULES.find(
        (rule) => rule.redactable && rule.kind !== "env_assignment" && patternMatches(rule.pattern, value),
    );
    if (nestedRule) {
        return `${key}=\n[REDACTED ${nestedRule.kind}]`;
    }

    return `${key}=\n[REDACTED env_assignment]`;
}

export function scanText(text) {
    if (typeof text !== "string" || text.length === 0) return [];

    const seen = new Set();
    const findings = [];

    for (const rule of RULES) {
        if (!patternMatches(rule.pattern, text)) continue;
        if (seen.has(rule.kind)) continue;
        seen.add(rule.kind);
        findings.push({
            kind: rule.kind,
            severity: rule.severity,
            redactable: rule.redactable,
        });
    }

    return findings;
}

export function redactText(text, findings) {
    if (typeof text !== "string" || text.length === 0) return "";

    let redacted = text;
    const kinds = selectedKindsFor(text, findings);

    const envRule = findRule("env_assignment");
    if (envRule && kinds.has(envRule.kind)) {
        redacted = replaceAll(redacted, envRule.pattern, redactAssignment);
    }

    for (const rule of RULES) {
        if (!rule.redactable || rule.kind === "env_assignment" || !kinds.has(rule.kind)) continue;
        redacted = replaceAll(redacted, rule.pattern, `[REDACTED ${rule.kind}]`);
    }

    return redacted;
}

export function hasFindings(text) {
    return scanText(text).length > 0;
}
