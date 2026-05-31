# multilang_baseline_v1 — Vigil v0.10 Sprint 5 Phase 4 Pre-Spike Fixture

**Created**: 2026-05-10 (Day 1 schema 冻结,目录骨架)
**Status**: 🚧 Day 1 占位 — Day 2 800-sample 数据填充待启
**Schema doc**: `docs/operations/v0.10-sprint5-spike/fixture-schema.md`

---

## 目录结构

```
multilang_baseline_v1/
├── README.md                  # 本文件
├── zh/                        # 200 sample(中文 PII)
├── ja/                        # 200 sample(日文 PII)
├── ru/                        # 200 sample(俄文 PII)
├── mixed_script/              # 100 sample(多脚本混合)
└── negative_control/          # 100 sample(无 PII,含敏感词 lookalike)
```

每文件:`{bucket}/ml-{lang}-{NNN}.json`,符合 `fixture-schema.md` § 2 schema。

---

## 合规 Top-3 提醒(Day 2 标注前必读)

1. **0 Live PII** — 一律 synthetic / public NER / 内部撰写;**不收**用户真实数据
   - 中国身份证:18 位 synthetic,通用前 6 位(110101 / 310000 / 440100),禁真地区+生日组合
   - 日本 my-number:12 位随机,**避**符合官方校验算法的号(防误中真用户)
   - 俄罗斯护照:`SSSS NNNNNN`,SSSS 用 1000-1099 测试段
   - 姓名:仅 王小明 / 田中太郎 / Иван Иванов 等通用化名,或 WikiNeural 公开 NER 派生
   - 手机号:中国 13800138xxx 测试段 / 日本 020-050 测试号段 / 俄罗斯 +7 9000 000 0000

2. **Human-curated lang authoritative** — `lang` 字段必须人工核对作权威源
   - heuristic 启发式只作 draft,**永不**作最终 lang(`feedback_lang_review_authoritative`)
   - `lang_review_status` 字段必填 `human_curated`(标准)或 `pending_review`(临时,Day 2 必清零)

3. **8 canonical label 硬约束** — `expected_findings[].label` 必在
   `[secret, account_number, email, phone, person, address, date, url]`
   - 中国身份证 / 日本 my-number / 俄护照号 → 全部 mapping 到 `account_number`(non-extensible enum)
   - 不可新加 label;若数据需要新 label 类,先扩 `PrivacyLabel::ALL`(SDK ABI 硬变更,需独立 ADR)

---

## Day 2 标注流程

```
1. spike-team 出 synthetic 模板(scripts/spike-phase4/synth_zh.py / synth_ja.py / synth_ru.py)
2. 生成 200/lang × 3 lang + 100 mixed + 100 negative = 800 raw samples
3. spike-team 内部 lang review(每 sample ≥ 1 人确认 lang_review_status='human_curated')
4. spike-team 内部抽样 10/lang spot-check 0-live-PII(随机 sample)
5. Codex preliminary review:本 README + fixture-schema.md + 10-sample/lang random spot-check
6. Codex ACCEPT → 进入 Day 3 baseline 跑(crates/vigil-redaction/examples/multilang_baseline_spike.rs)
```

---

## 守门(static gates)

- `crates/vigil-redaction/tests/fixture_invariants.rs` 已扩 `'ru'` + `ASIA_LANGS` const + `asia_langs_subset_of_allowed_lang_enum` 测试
- Day 2 加 fixture loader test(独立 `tests/multilang_baseline_v1_loader.rs` 或类似),按 200/lang 守门

---

## 引用

- Schema: `docs/operations/v0.10-sprint5-spike/fixture-schema.md`(权威 schema)
- Brainstorm: `.workflow/.brainstorm/BS-v0.10-sprint5-phase4-multilang-2026-05-10/`
- Plan: `.workflow/.lite-plan/v0.10-sprint5-phase4-spike-2026-05-10/`
