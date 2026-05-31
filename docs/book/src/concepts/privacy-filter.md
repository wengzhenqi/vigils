# Privacy Filter

`vigil-redaction` — 两层 defense in depth:

## Layer 1:Hard fingerprint(13 kinds)

| Kind | Pattern |
|---|---|
| github_token | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` + 36 |
| slack_webhook | `hooks.slack.com/services/T...` |
| stripe_secret | `sk_live_` / `sk_test_` |
| google_api_key | `AIza` + 35 |
| gitlab_pat | `glpat-` + 20 |
| aws_access_key | `AKIA` + 16 uppercase |
| database_url | `<scheme>://user:password@host/db` |
| private_key | PEM |
| ... | 13 total |

100% precision,zero ML dep,即时启动。

## Layer 2:ONNX ensemble(opt-in `--features ort`)

3-engine:OpenAI Privacy Filter + xlmr-pii-v1(multilang)+ yonigo-pii-v1。
Production:cold ~11s,warm p95 419ms。

## v0.10 Calibration

xlmr `LangConditionalThresholdProfile`:per-(lang,label)override。zh.account_number 1.1 → FP 150→6,F1 +4.30pp。

详见 ADR 0013 + v0.10 Sprint 5+6 spike trajectory。
