# Privacy Filter

`vigil-redaction` provides two layers of defense in depth.

## Layer 1 — Hard fingerprints

Fixed-prefix and structured-credential rules with 100% precision, zero ML dependency, and
instant startup:

| Kind | Pattern |
|---|---|
| github_token | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` + 36 |
| slack_webhook | `hooks.slack.com/services/T...` |
| stripe_secret | `sk_live_` / `sk_test_` |
| google_api_key | `AIza` + 35 |
| gitlab_pat | `glpat-` + 20 |
| aws_access_key | `AKIA` + 16 uppercase |
| database_url | `<scheme>://user:password@host/db` |
| private_key | PEM block |
| ... | 13 kinds total |

## Layer 2 — ONNX ensemble (opt-in, `--features ort`)

A 3-engine ensemble (OpenAI Privacy Filter + `xlmr-pii-v1` for multilingual text +
`yonigo-pii-v1`) for natural-language PII. Typical latency: cold ~11 s, warm p95 ~419 ms.

A per-`(language, label)` threshold profile calibrates recall vs. false positives — for
example tightening `zh.account_number` cut a noisy false-positive cluster while improving F1.

The two layers merge fail-closed (hard fingerprints win on overlap). See ADR 0013.
