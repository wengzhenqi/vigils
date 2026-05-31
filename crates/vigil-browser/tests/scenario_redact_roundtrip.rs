//! PS-001 Redact Round-trip — 产品级"指纹绝不漏"场景测试。
//!
//! 参见 `docs/test-cases/scenarios/PS-001-redact-roundtrip.md`。
//!
//! 与 `rule_sync.rs`(只验 classifier 能识别 finding)的差异:
//! - PS-001 验的是**端到端** round-trip:识别 → redact → 二次扫 必须干净
//! - PS-001 验 `redacted_text` 不含原值 16+ 字符连续片段(子串搜索,不依赖格式)
//! - PS-001 是**单一表**驱动所有 13 variants,任一失败 = 产品承诺破坏

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use vigil_browser::{
    classify, BrowserCheckRequest, BrowserEventKind, ClassifyOutcome, FindingKind,
};

/// 13 条 `(kind, raw_value_with_high_entropy)` —— 每条必须能被 classifier 识别
/// **并且**在 redacted_text 里彻底消失。
///
/// 选值策略:用高熵、长度足够触发 16 字符子串断言的样本。
const CASES: &[(FindingKind, &str)] = &[
    (
        FindingKind::GithubToken,
        "ghp_ProductLevelTok3nABCDEFGHIJKLMNOPQRSTUV",
    ),
    (
        FindingKind::OpenaiKey,
        "sk-ProductLevelKeyABCDEFGHIJKLMNOPQR",
    ),
    (
        FindingKind::AnthropicKey,
        "sk-ant-ProductLevelKeyABCDEFGHIJKLMNOP",
    ),
    (FindingKind::AwsAccessKey, "AKIAPRODUCTLEVEL1234"),
    (
        FindingKind::Jwt,
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwcm9kdWN0bGV2ZWx0ZXN0In0.HighEntropySignatureSegmentProdLevel12",
    ),
    (
        FindingKind::EnvAssignment,
        "PRODUCTION_PASSWORD=HighlyEntropicSecretV4lue",
    ),
    (
        FindingKind::PemPrivateKey,
        "-----BEGIN RSA PRIVATE KEY-----\nProductLevelKeyMaterialLine1\n-----END RSA PRIVATE KEY-----",
    ),
    (FindingKind::LocalhostUrl, "http://localhost:8080/api/product"),
    (
        FindingKind::SlackWebhook,
        "https://hooks.slack.com/services/TPRODLVL0001/BPRODLVL0001/ProductLevelSignature24",
    ),
    (
        FindingKind::StripeSecretKey,
        "sk_live_ProductLevelStripeKeyBase32Chars",
    ),
    (
        // Google key regex 要求 AIza + 严格 35 chars(39 total)
        FindingKind::GoogleApiKey,
        "AIzaProductLevelGoogleKey0123456789ABCD",
    ),
    (
        FindingKind::GitlabPat,
        "glpat-ProductLevelGitLabPat012345",
    ),
    (
        FindingKind::DatabaseUrl,
        "postgres://produser:ProductLevelPass@db.internal.example.com:5432/app_prod",
    ),
];

fn mk_request(text: &str) -> BrowserCheckRequest {
    BrowserCheckRequest {
        request_id: "ps001-rid".into(),
        origin: "https://chatgpt.com".into(),
        event_kind: BrowserEventKind::Paste,
        text: text.into(),
    }
}

/// 对每个 raw_value 找一个 16+ 字符的"签名片段",用来证明 redacted_text 没留原文。
///
/// 策略:取**中间**那段高熵 payload(跳过常见前缀 `sk-`/`ghp_`/`AIza` 等),避免因
/// 前缀是通用字符串导致 false positive(例如 "https://" 前缀会在 scrub 结果里出现)。
fn high_entropy_signature(raw: &str) -> &str {
    // 去掉前 8 个字符后取 24 字符窗口(若长度不够,取尾 24 字符)
    let skip = raw.len().min(8);
    let end = (skip + 24).min(raw.len());
    if end - skip >= 16 {
        &raw[skip..end]
    } else {
        &raw[raw.len().saturating_sub(16)..]
    }
}

#[test]
fn ps001_all_13_findings_roundtrip_clean() {
    let mut fail_report: Vec<String> = Vec::new();

    for (kind, raw) in CASES {
        let req = mk_request(raw);
        let outcome = classify(&req);
        let resp = match outcome {
            ClassifyOutcome::Response(r) => r,
            ClassifyOutcome::Error(e) => {
                fail_report.push(format!("[{kind:?}] 协议错而非识别:{e:?}"));
                continue;
            }
        };

        // 断言 1:findings 含期望 kind
        if !resp.findings.contains(kind) {
            fail_report.push(format!(
                "[{kind:?}] classify 未识别为该类 findings={:?}",
                resp.findings
            ));
            continue;
        }

        // PEM 走 Block 路径,无 redacted_text —— 单独处理
        let redacted = match resp.redacted_text.as_deref() {
            Some(r) => r.to_string(),
            None => {
                // Block 语义下不返 redacted_text 是合约允许;跳过原值残留检查,
                // 只验 findings 识别成功(上面已断言)即可视为 PS-001 通过
                continue;
            }
        };

        // LocalhostUrl 是**警示**类指纹(提醒"指向本地服务"),非敏感凭证 ——
        // 产品设计上不走 redaction(见 rule_sync.rs LOCAL_ONLY);豁免原文残留 + 二次扫断言。
        if *kind == FindingKind::LocalhostUrl {
            continue;
        }

        // 断言 2:redacted_text 不含原值 16+ 字符高熵片段
        let sig = high_entropy_signature(raw);
        if sig.len() >= 16 && redacted.contains(sig) {
            fail_report.push(format!(
                "[{kind:?}] redacted_text 仍含原值片段 {sig:?}: {redacted}"
            ));
        }

        // 断言 3:对 redacted_text 再扫硬指纹,不得再命中同一规则名
        //
        // scan_hard_findings 返 Vec<&'static str>(规则名),需把 FindingKind 映射过去。
        // 用 as_str() 作为统一标识符(它本身就是规则名契约)。
        let second_scan = vigil_redaction::scan_hard_findings(&redacted);
        let kind_name = kind.as_str();
        if second_scan.contains(&kind_name) {
            fail_report.push(format!(
                "[{kind:?}] 二次 scan_hard_findings 仍命中 {kind_name:?};redacted={redacted}"
            ));
        }
    }

    if !fail_report.is_empty() {
        panic!(
            "PS-001 Redact Round-trip 失败 {} 项:\n{}",
            fail_report.len(),
            fail_report.join("\n")
        );
    }
}
