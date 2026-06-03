# Vigils Security Audit — 2026-06-03

**Type**: Comprehensive baseline (supply-chain + OWASP Top 10 2021 + STRIDE + Vigils-invariant verification)
**Target**: Vigils workspace — 15 crates + 3 apps (~50k Rust LOC) + Tauri 2 desktop + Chrome MV3 extension + published `vigil-sdk`
**Method**: `cargo audit` / `cargo deny` / secrets+CI grep (supply chain); 4 independent code-audit passes demanding `file:line` evidence (OWASP + the 8 core security invariants); STRIDE threat model mapped to trust boundaries.

## Result

| | |
|---|---|
| **Score** | **9.9 / 10 — Excellent** (0 Critical, 0 High, 3 Medium, 5 Low, 1 Info) |
| **Gate** | PASS (baseline ≥ 2.0; production-readiness target ≥ 7.0 — exceeded) |
| **Verdict** | Strong posture. The product's core security claims are proven-safe with code + test evidence. |

### Proven-safe (with code + test evidence)

- **Fail-closed decisions** — default-deny; unknown/error → Deny; PII scan error → whole-decision Deny (no decision/approval persisted); fresh tool descriptor → FirstSeen (approval-required), never auto-allow; OAuth scope allowlist deny-by-default.
- **No-plaintext audit** — schema stores only metadata (length buckets, sha256 fingerprints, label/offset/placeholder, action); `append_event` runs a hard-secret gate on payload + summary; strict 32-hex fingerprint validation; OAuth token *values* and secret-lease values never persisted (Zeroizing). Tests bypass the API to attack the disk directly.
- **No OAuth token passthrough** — the gateway strips inbound auth headers and injects only its own token; RFC 8707 resource binding; `HttpUpstream` always passes `incoming_headers = []`.
- **JWKS** — real signature verification, RS256/ES256 allowlist, `none`/HS rejected, issuer + audience + exp bound via a sealed `TokenStore` (compile-fail doctests prove no-unverified-path).
- **Sandbox** — Landlock applied in the child *before* `execvp`, no degrade-to-unsandboxed; wasmtime 44.0.2 (RUSTSEC-2026-0149 cleared).
- **MCP gate-before-spawn** — attach serialized; dup → resolve → argv-drift → resolved-program-drift checks run before spawn; raw spawn is `pub(crate)`.
- **Injection** — SQL fully parameterized; process spawn never uses a shell; paths canonicalized with component-wise containment.
- **Tauri / extension least-privilege** — strict CSP (`script-src 'self'`, no `unsafe-eval`), 21-command allowlist with a bidirectional set-diff test; extension uses only `nativeMessaging` + `activeTab`, no `externally_connectable`, tab+origin-bound 10-min exemptions.

## Findings

| ID | Sev | Title | Status |
|----|-----|-------|--------|
| **VIGIL-SEC-001** | Medium | Audit hash-chain digest omitted `session_id` / `event_type` / `redacted_text` (A08) | **Fixed** — hash-chain v2 (versioned, Codex-reviewed R1→fix); see ADR 0002 Revised 2026-06-03 |
| VIGIL-SEC-002/003 | Medium | Wasm runner preopen path-collision + write-grant granularity | Open — **latent** (the `wasm` feature is off in all shipped binaries) |
| VIGIL-SEC-004 | Low | `pin_tool_descriptor` accepts empty `descriptor_hash` (production-unreachable) | **Fixed** — oracle fail-closes malformed incoming hashes to FirstSeen + pin rejects empty |
| VIGIL-SEC-005 | Low | Reserved-key guard only blocks literal `allowed_hosts` | **Fixed** — reserved-key *set* guard (extensible) |
| VIGIL-SEC-006 | Low | Extension `background.js` `onMessage` doesn't validate `sender.id` (safe — no `externally_connectable`) | **Fixed** — `sender.id === runtime.id` guard |
| VIGIL-SEC-007 | Low | Site-initiated `form.submit()` bypasses the redaction listener | Documented DOM-interception limitation |
| VIGIL-SEC-008 | Low | `rand 0.7.3` + 19 unmaintained — transitive / build-time, not in production runtime | **Addressed** — `deny.toml [advisories] ignore` (per-entry reason) + ADR 0019 |
| VIGIL-SEC-009 | Info | Dead `invocations.args_redacted_json` schema column | Open (P2) |

### VIGIL-SEC-001 — fixed

The audit hash chain (a tamper-evident SHA-256 chain) digested only `prev_hash`, `payload_jcs`, and `created_at`. The `session_id`, `event_type`, and `redacted_text` columns sat *outside* the digest, so a local actor with database write access could rewrite them (move an event out of a session replay, rewrite the searchable/displayed summary, flip an event type) without `verify_chain()` detecting it — partially defeating the audit-tamper mitigation.

**Fix** (versioned, backward-compatible): a per-event `chain_version` column + a v2 digest (`vigil.ledger.event.v2`) that additionally binds `session_id`, `event_type`, and `redacted_text`. Historical v1 events stay verifiable under v1 (no chain break); new events use v2; `verify_chain` dispatches per the stored version, fails closed on unknown versions, and (per Codex R1) enforces version **monotonicity** so a v2→v1 downgrade is rejected. Guarded by tests `tamper_v2_bound_fields_detected`, `legacy_v1_event_and_mixed_chain_verify`, and `v2_then_v1_rejected_as_downgrade`.

**Inherent limitation** (out of scope, tracked): a hash chain without an external anchor cannot stop a full-chain rewrite by an actor with complete DB write access; it raises the bar and makes *partial* tampering evident. Periodic external checkpointing is the follow-up to fully close threat #7.

## Remediation roadmap

- **Done**: VIGIL-SEC-001 (hash-chain v2, Codex R1→R2 ACCEPT); SEC-004 (descriptor-hash guards), SEC-005 (reserved-key set), SEC-006 (extension sender guard), SEC-008 (deny.toml advisories + ADR 0019).
- **P2** (latent / low, remaining): SEC-002/003 (Wasm preopen — fix before enabling the off-by-default backend), SEC-009 (drop dead `invocations.args_redacted_json` column).
- **Documented limitation**: SEC-007 (DOM `form.submit()`).
- **Follow-up enhancement**: external hash-chain checkpoint/anchor (fully closes threat #7 against full-chain rewrite).

*This advisory summarizes a comprehensive internal security audit. To report a vulnerability, see [SECURITY.md](../../SECURITY.md).*
