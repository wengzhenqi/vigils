//! ISS-011 Stage 2 —— T0 redaction scan 审计两表 + CRUD 验收测试。
//!
//! 覆盖:
//!  1. test_redaction_schema_initializes_idempotent       —— open_in_memory 幂等
//!  2. test_insert_redaction_scan_and_list                —— scan 回放字段完整
//!  3. test_insert_redaction_finding_and_list             —— findings 3 条按 id 升序 + derived placeholder 回放
//!  4. test_redaction_source_allowlist                    —— 4 合法 + 1 非法
//!  5. test_redaction_label_allowlist_exact_set           —— 8 合法 + 非法(SSOT diff)
//!  6. test_redaction_fingerprint_length_strict           —— ≠32 char 在 scan/finding 两路径都 Err
//!  7. test_redaction_fingerprint_hex_lower_strict        —— R2 新增:非 hex / uppercase Err(BLOCKER 1 守门)
//!  8. test_redaction_placeholder_is_derived_and_safe     —— R2 新增:NewRedactionFinding 无 placeholder 字段,
//!     DB 落地形态严格 `[{verb} {label}]`(BLOCKER 2 守门)
//!  9. test_schema_forbids_plaintext_columns              —— grep 守门禁字段 + 正向新表
//! 10. test_bit_width_bucket_math                         —— 位宽 bucket 边界(原 log2_bucket,R1 NICE 改名)
//! 11. contract_audit_labels_match_redaction_privacy_label —— R2 新增:跨 crate SSOT 守门(MUST-FIX 2)
//!
//! 不变量纪律见 schema.sql 顶注 + ALLOWED_REDACTION_LABELS doc。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]

use vigil_audit::{
    AuditError, Ledger, NewRedactionFinding, NewRedactionScan, ALLOWED_REDACTION_LABELS,
};

// 32 字符 hex-lower(= sha256 前 16 字节)。测试里复用。
const FP_A: &str = "0123456789abcdef0123456789abcdef";
const FP_B: &str = "fedcba9876543210fedcba9876543210";
const FP_C: &str = "aaaabbbbccccddddeeeeffff00001111";
const FP_D: &str = "1111222233334444555566667777aaaa";

fn start_session(l: &Ledger) -> String {
    l.start_session("test", Some("redaction_schema")).unwrap()
}

/// (ISS-014 wave-4 Stage 3)`aggregate_redaction_labels_by_session` 行为矩阵:
///
/// 1. 空 session(无 scans / findings)→ 空 Vec
/// 2. 仅非 `tool_arg` source(paste / tool_output)→ 空 Vec(scope 严格按 firewall preflight 写入路径)
/// 3. 单 `tool_arg` scan 多 finding → 按 label 聚合 + count 正确 + DESC count / ASC label 排序
/// 4. 跨 session 隔离 → 仅返本 session 的命中
///
/// 关键不变量:**绝不展原文**,仅 (label, count) 元数据返回(由调用方 UI 层呈现)。
#[test]
fn test_aggregate_redaction_labels_by_session() {
    let l = Ledger::open_in_memory().unwrap();
    let sid_a = start_session(&l);
    let sid_b = l.start_session("test", Some("other")).unwrap();

    // sid_a:1 paste(应忽略)+ 1 tool_arg(2 secret + 1 email)
    let _scan_paste = l
        .insert_redaction_scan(NewRedactionScan {
            session_id: &sid_a,
            source: "paste", // 非 tool_arg,不进聚合
            text_length: 32,
            fingerprint: FP_A,
        })
        .unwrap();

    let scan_arg = l
        .insert_redaction_scan(NewRedactionScan {
            session_id: &sid_a,
            source: "tool_arg",
            text_length: 200,
            fingerprint: FP_B,
        })
        .unwrap();
    for (label, fp) in [("secret", FP_A), ("secret", FP_B), ("email", FP_C)] {
        l.insert_redaction_finding(NewRedactionFinding {
            scan_id: &scan_arg,
            label,
            offset: 0,
            fingerprint: fp,
            action_taken: "redacted",
        })
        .unwrap();
    }

    // sid_b:独立 tool_arg 1 phone — 不应漏到 sid_a
    let scan_b = l
        .insert_redaction_scan(NewRedactionScan {
            session_id: &sid_b,
            source: "tool_arg",
            text_length: 50,
            fingerprint: FP_D,
        })
        .unwrap();
    l.insert_redaction_finding(NewRedactionFinding {
        scan_id: &scan_b,
        label: "phone",
        offset: 0,
        fingerprint: FP_A,
        action_taken: "redacted",
    })
    .unwrap();

    // sid_a 聚合:secret×2 + email×1(paste 来源不算入)
    let agg_a = l.aggregate_redaction_labels_by_session(&sid_a).unwrap();
    assert_eq!(agg_a.len(), 2, "sid_a 聚合 2 个 label,paste 源不进");
    // 排序:count DESC → secret(2) 先,email(1) 后
    assert_eq!(agg_a[0], ("secret".to_string(), 2));
    assert_eq!(agg_a[1], ("email".to_string(), 1));

    // sid_b 聚合:仅 phone × 1,不漏 sid_a
    let agg_b = l.aggregate_redaction_labels_by_session(&sid_b).unwrap();
    assert_eq!(agg_b, vec![("phone".to_string(), 1)]);

    // 空 session 聚合 → 空(start_session 不创建 scans)
    let sid_empty = l.start_session("test", Some("empty")).unwrap();
    let agg_empty = l.aggregate_redaction_labels_by_session(&sid_empty).unwrap();
    assert!(agg_empty.is_empty());
}

/// (ISS-017)`aggregate_redaction_labels_global` + `list_recent_redaction_scans_with_counts`
/// 行为矩阵:
/// 1. 全空 → 两 helper 均返空
/// 2. global 聚合不限 source(paste / tool_arg 都计入,与 by-session 版区别)
/// 3. recent_scans 按 ts DESC 排;limit=0 用 50 默认;finding_count 来自子查询
#[test]
fn test_aggregate_global_and_recent_scans() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = start_session(&l);

    // 全空
    assert!(l.aggregate_redaction_labels_global().unwrap().is_empty());
    assert!(l
        .list_recent_redaction_scans_with_counts(10)
        .unwrap()
        .is_empty());

    // 1 paste(secret×1)+ 1 tool_arg(secret×1, email×2)
    let paste_scan = l
        .insert_redaction_scan(NewRedactionScan {
            session_id: &sid,
            source: "paste",
            text_length: 64,
            fingerprint: FP_A,
        })
        .unwrap();
    l.insert_redaction_finding(NewRedactionFinding {
        scan_id: &paste_scan,
        label: "secret",
        offset: 0,
        fingerprint: FP_A,
        action_taken: "blocked",
    })
    .unwrap();

    let arg_scan = l
        .insert_redaction_scan(NewRedactionScan {
            session_id: &sid,
            source: "tool_arg",
            text_length: 256,
            fingerprint: FP_B,
        })
        .unwrap();
    for (label, fp) in [("secret", FP_B), ("email", FP_C), ("email", FP_D)] {
        l.insert_redaction_finding(NewRedactionFinding {
            scan_id: &arg_scan,
            label,
            offset: 0,
            fingerprint: fp,
            action_taken: "redacted",
        })
        .unwrap();
    }

    // 全局聚合:secret×2(paste+arg 都计)+ email×2;按 count DESC, label ASC 排
    let global = l.aggregate_redaction_labels_global().unwrap();
    assert_eq!(
        global,
        vec![
            ("email".to_string(), 2), // count 同 → 字母序 email 先
            ("secret".to_string(), 2),
        ]
    );

    // recent_scans:2 条 + finding_count 子查询正确。
    // **不**断言 scan 顺序 —— 同秒入库时 ts 相同,scan_id 是 UUID 字典序不稳;
    // 改用 by-id 索引断言 finding_count 正确(子查询是 ISS-017 的核心契约)。
    let scans = l.list_recent_redaction_scans_with_counts(10).unwrap();
    assert_eq!(scans.len(), 2);
    let by_id: std::collections::HashMap<String, i64> = scans
        .iter()
        .map(|(row, c)| (row.scan_id.clone(), *c))
        .collect();
    assert_eq!(by_id.get(&arg_scan), Some(&3), "arg_scan 含 3 finding");
    assert_eq!(by_id.get(&paste_scan), Some(&1), "paste_scan 含 1 finding");

    // limit=0 → ledger 用 50 默认(防御 caller 传 0 时全量;此处 2 条都返)
    let scans_default = l.list_recent_redaction_scans_with_counts(0).unwrap();
    assert_eq!(scans_default.len(), 2);
}

/// (1) Schema 幂等:连续 open 两次内存库不 panic。
///
/// 注:单 `Ledger::open_in_memory` 已经 `execute_batch(SCHEMA_SQL)`,若 CREATE
/// 语法有漂移(非 IF NOT EXISTS 之类)第二次就会失败。此处再额外建一个独立实例,
/// 保证"重复 open 路径"的守门。
#[test]
fn test_redaction_schema_initializes_idempotent() {
    let _l1 = Ledger::open_in_memory().unwrap();
    let _l2 = Ledger::open_in_memory().unwrap();
    // 多个独立 Ledger 生命周期结束也不 panic。
}

/// (2) insert_redaction_scan → list_redaction_scans_by_session 字段回放正确。
#[test]
fn test_insert_redaction_scan_and_list() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = start_session(&l);

    let scan_id = l
        .insert_redaction_scan(NewRedactionScan {
            session_id: &sid,
            source: "paste",
            text_length: 1024, // bucket = 11
            fingerprint: FP_A,
        })
        .unwrap();

    let rows = l.list_redaction_scans_by_session(&sid).unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.scan_id, scan_id);
    assert_eq!(row.session_id, sid);
    assert_eq!(row.source, "paste");
    assert_eq!(row.text_length_bucket, 11, "bit_width_bucket(1024) 应为 11");
    assert_eq!(row.fingerprint, FP_A);
    assert!(row.ts > 0);
}

/// (3) insert_redaction_finding × 3(不同 label)→ list_redaction_findings_by_scan
/// 返回 3 条,按 finding_id 升序,字段完整。
#[test]
fn test_insert_redaction_finding_and_list() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = start_session(&l);

    let scan_id = l
        .insert_redaction_scan(NewRedactionScan {
            session_id: &sid,
            source: "tool_arg",
            text_length: 512,
            fingerprint: FP_A,
        })
        .unwrap();

    let f1 = l
        .insert_redaction_finding(NewRedactionFinding {
            scan_id: &scan_id,
            label: "email",
            offset: 0,
            fingerprint: FP_B,
            action_taken: "redacted",
        })
        .unwrap();
    let f2 = l
        .insert_redaction_finding(NewRedactionFinding {
            scan_id: &scan_id,
            label: "phone",
            offset: 64,
            fingerprint: FP_C,
            action_taken: "blocked",
        })
        .unwrap();
    let f3 = l
        .insert_redaction_finding(NewRedactionFinding {
            scan_id: &scan_id,
            label: "secret",
            offset: 1000,
            fingerprint: FP_D,
            action_taken: "allowed_once",
        })
        .unwrap();

    assert!(f1 < f2 && f2 < f3, "finding_id 单调自增");

    let rows = l.list_redaction_findings_by_scan(&scan_id).unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].finding_id, f1);
    assert_eq!(rows[0].label, "email");
    assert_eq!(rows[0].offset_bucket, 0); // bit_width_bucket(0) = 0
                                          // R2:placeholder 由 audit 派生(redacted → REDACTED verb)
    assert_eq!(rows[0].placeholder, "[REDACTED email]");
    assert_eq!(rows[0].fingerprint, FP_B);
    assert_eq!(rows[0].action_taken, "redacted");

    assert_eq!(rows[1].label, "phone");
    assert_eq!(rows[1].offset_bucket, 7); // bit_width_bucket(64) = 7
                                          // R2:blocked → BLOCKED verb
    assert_eq!(rows[1].placeholder, "[BLOCKED phone]");
    assert_eq!(rows[1].action_taken, "blocked");

    assert_eq!(rows[2].label, "secret");
    assert_eq!(rows[2].offset_bucket, 10); // bit_width_bucket(1000) = 10
                                           // R2:allowed_once → ALLOWED_ONCE verb
    assert_eq!(rows[2].placeholder, "[ALLOWED_ONCE secret]");
    assert_eq!(rows[2].action_taken, "allowed_once");
}

/// (4) source allowlist —— 4 合法全 Ok;非法返回 InvalidInput 且 reason 精确。
#[test]
fn test_redaction_source_allowlist() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = start_session(&l);

    for src in ["paste", "tool_arg", "tool_output", "export"] {
        let r = l.insert_redaction_scan(NewRedactionScan {
            session_id: &sid,
            source: src,
            text_length: 10,
            fingerprint: FP_A,
        });
        assert!(r.is_ok(), "合法 source '{src}' 应插入成功:{r:?}");
    }

    let bad = l.insert_redaction_scan(NewRedactionScan {
        session_id: &sid,
        source: "unknown",
        text_length: 10,
        fingerprint: FP_A,
    });
    match bad {
        Err(AuditError::InvalidInput { reason }) => {
            assert_eq!(reason, "redaction_scan_source_not_allowed");
        }
        other => panic!("非法 source 应返回 InvalidInput,得到 {other:?}"),
    }
}

/// (5) label allowlist —— 精确集合守门(feedback_ssot_drift_guard):
///   - 断言 ALLOWED_REDACTION_LABELS 与本地字面量集合双向完全相等
///   - 逐个插入 8 合法 label 均成功
///   - 非法 "unknown" / "raw" 返回 InvalidInput
#[test]
fn test_redaction_label_allowlist_exact_set() {
    // 本地 SSOT —— 必须与 ledger.rs ALLOWED_REDACTION_LABELS 完全一致。
    let expected: std::collections::BTreeSet<&str> = [
        "secret",
        "account_number",
        "email",
        "phone",
        "person",
        "address",
        "date",
        "url",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<&str> =
        ALLOWED_REDACTION_LABELS.iter().copied().collect();
    assert_eq!(
        actual, expected,
        "ALLOWED_REDACTION_LABELS 与测试期望集合漂移;\
         若有意增删 label,请同时更新 ISS-005 PrivacyLabel::as_str()、\
         schema.sql 注释和本测试"
    );

    let l = Ledger::open_in_memory().unwrap();
    let sid = start_session(&l);
    let scan_id = l
        .insert_redaction_scan(NewRedactionScan {
            session_id: &sid,
            source: "paste",
            text_length: 1,
            fingerprint: FP_A,
        })
        .unwrap();

    for label in &expected {
        let r = l.insert_redaction_finding(NewRedactionFinding {
            scan_id: &scan_id,
            label,
            offset: 1,
            fingerprint: FP_B,
            action_taken: "redacted",
        });
        assert!(r.is_ok(), "合法 label '{label}' 应插入成功:{r:?}");
    }

    for bad in ["unknown", "raw", "", "Secret" /* 大小写敏感 */] {
        let r = l.insert_redaction_finding(NewRedactionFinding {
            scan_id: &scan_id,
            label: bad,
            offset: 1,
            fingerprint: FP_B,
            action_taken: "redacted",
        });
        match r {
            Err(AuditError::InvalidInput { reason }) => {
                assert_eq!(reason, "redaction_finding_label_not_allowed");
            }
            other => panic!("非法 label '{bad}' 应 Err,得到 {other:?}"),
        }
    }
}

/// (6) fingerprint 长度必须恰好 32 —— scan / finding 两个路径都守门。
#[test]
fn test_redaction_fingerprint_length_strict() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = start_session(&l);

    // scan 路径:短(31)与长(33)都应拒绝。
    for bad_fp in [
        "0123456789abcdef0123456789abcde",
        "0123456789abcdef0123456789abcdef0",
    ] {
        let r = l.insert_redaction_scan(NewRedactionScan {
            session_id: &sid,
            source: "paste",
            text_length: 1,
            fingerprint: bad_fp,
        });
        match r {
            Err(AuditError::InvalidInput { reason }) => {
                assert_eq!(reason, "fingerprint_must_be_sha256_16byte_hex");
            }
            other => panic!(
                "长度 {} 的 scan fingerprint 应 Err,得到 {other:?}",
                bad_fp.len()
            ),
        }
    }

    // 先建一个合法 scan 供 finding 挂载。
    let scan_id = l
        .insert_redaction_scan(NewRedactionScan {
            session_id: &sid,
            source: "paste",
            text_length: 1,
            fingerprint: FP_A,
        })
        .unwrap();

    // finding 路径:同样双边长度异常。
    for bad_fp in ["aaaa", &format!("{FP_A}extra")[..]] {
        let r = l.insert_redaction_finding(NewRedactionFinding {
            scan_id: &scan_id,
            label: "secret",
            offset: 0,
            fingerprint: bad_fp,
            action_taken: "redacted",
        });
        match r {
            Err(AuditError::InvalidInput { reason }) => {
                assert_eq!(reason, "fingerprint_must_be_sha256_16byte_hex");
            }
            other => panic!(
                "长度 {} 的 finding fingerprint 应 Err,得到 {other:?}",
                bad_fp.len()
            ),
        }
    }
}

/// (7) **R2 新增(BLOCKER 1 守门)**:fingerprint 必须是 **ASCII lowercase hex**,
/// 不仅长度。旧实装只检查 `len == 32`,32 字符原文 secret / uppercase hex / 非 hex
/// 都能直写 SQLite,违背"绝不存原文"+fail-closed 不变量。
///
/// 覆盖:
/// - 32 字符但含非 hex 字符(含空格 / 标点 / Unicode 变种)→ Err
/// - 32 字符但 uppercase hex → Err(contracted lowercase-only)
/// - 混合大小写 → Err
/// - 合法 lowercase hex → Ok(回归基线)
#[test]
fn test_redaction_fingerprint_hex_lower_strict() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = start_session(&l);

    // 32 字符但内容非 hex-lower 的攻击样本(长度正好通过旧守门)
    let bad_fps: &[&str] = &[
        // 全 uppercase hex(32 字符):必须 Err(lowercase-only 契约)
        "0123456789ABCDEF0123456789ABCDEF",
        // 混合大小写
        "0123456789aBcDeF0123456789abcdef",
        // 含非 hex 字符:`g`(合法但超 f)
        "0123456789abcdef0123456789abcdeg",
        // 含空格(32 字符)
        "0123456789abcdef0123456789abcde ",
        // 含标点
        "0123456789abcdef0123456789abcde.",
        // 伪造 32 字符的 "看似 secret" 形态(32 字符明文)
        "ghp_abcdefghijklmnopqrstuvwxyz01",
    ];

    // scan 路径守门
    for bad in bad_fps {
        let r = l.insert_redaction_scan(NewRedactionScan {
            session_id: &sid,
            source: "paste",
            text_length: 1,
            fingerprint: bad,
        });
        match r {
            Err(AuditError::InvalidInput { reason }) => {
                assert_eq!(
                    reason, "fingerprint_must_be_lowercase_hex",
                    "非 hex-lower fingerprint '{bad}' 应被拒(scan 路径)"
                );
            }
            other => panic!("非 hex-lower scan fingerprint '{bad}' 应 Err,得到 {other:?}"),
        }
    }

    // finding 路径守门
    let scan_id = l
        .insert_redaction_scan(NewRedactionScan {
            session_id: &sid,
            source: "paste",
            text_length: 1,
            fingerprint: FP_A,
        })
        .unwrap();
    for bad in bad_fps {
        let r = l.insert_redaction_finding(NewRedactionFinding {
            scan_id: &scan_id,
            label: "secret",
            offset: 0,
            fingerprint: bad,
            action_taken: "redacted",
        });
        match r {
            Err(AuditError::InvalidInput { reason }) => {
                assert_eq!(
                    reason, "fingerprint_must_be_lowercase_hex",
                    "非 hex-lower fingerprint '{bad}' 应被拒(finding 路径)"
                );
            }
            other => panic!("非 hex-lower finding fingerprint '{bad}' 应 Err,得到 {other:?}"),
        }
    }
}

/// (8) **R2 新增(BLOCKER 2 守门)**:placeholder 由 audit 内部派生,caller **无法**
/// 传入自己的 placeholder。这把"caller 传真 secret 或 伪占位符"的攻击面直接消灭。
///
/// 覆盖:
/// - NewRedactionFinding 的字段上**不存在** `placeholder` 字段(编译期守门,见本测试
///   的构造字面量)
/// - 落库后的 placeholder 严格遵循 `[{verb} {label}]` 形态,verb 由 action_taken 映射
/// - 三种 action_taken 的 verb 全部覆盖
#[test]
fn test_redaction_placeholder_is_derived_and_safe() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = start_session(&l);
    let scan_id = l
        .insert_redaction_scan(NewRedactionScan {
            session_id: &sid,
            source: "tool_arg",
            text_length: 1,
            fingerprint: FP_A,
        })
        .unwrap();

    let cases: &[(&str, &str, &str)] = &[
        // (label, action_taken, expected_placeholder)
        ("email", "redacted", "[REDACTED email]"),
        ("secret", "blocked", "[BLOCKED secret]"),
        ("phone", "allowed_once", "[ALLOWED_ONCE phone]"),
        ("person", "redacted", "[REDACTED person]"),
        ("account_number", "blocked", "[BLOCKED account_number]"),
    ];

    for (label, action, _expected) in cases {
        l.insert_redaction_finding(NewRedactionFinding {
            scan_id: &scan_id,
            label,
            offset: 0,
            fingerprint: FP_B,
            action_taken: action,
        })
        .unwrap();
    }

    let rows = l.list_redaction_findings_by_scan(&scan_id).unwrap();
    assert_eq!(rows.len(), cases.len());
    for (row, (_, _, expected)) in rows.iter().zip(cases.iter()) {
        assert_eq!(
            row.placeholder, *expected,
            "placeholder 派生形态不符合 `[{{verb}} {{label}}]` 契约"
        );
        // 正向不变量:placeholder 永远不含原始 secret 字面量。
        assert!(
            !row.placeholder.contains("ghp_")
                && !row.placeholder.contains("sk-")
                && !row.placeholder.contains("AKIA"),
            "placeholder '{}' 泄漏了疑似 secret 字面量",
            row.placeholder
        );
    }
}

/// (7) grep 守门 —— schema.sql 绝不含原文字段;正向断言新表名已落地。
///
/// 失败信息必带违规字段名/表名,便于回归 triage(feedback_ssot_drift_guard)。
#[test]
fn test_schema_forbids_plaintext_columns() {
    let sql = include_str!("../src/schema.sql");

    let forbidden = [
        "raw_text",
        "raw_secret",
        "full_input",
        "plain_text",
        "original_text",
    ];
    for forbid in forbidden {
        assert!(
            !sql.contains(forbid),
            "schema.sql 包含禁字段 '{forbid}';\
             ISS-011 '绝不存原文' 不变量被破坏"
        );
    }

    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS redaction_scans"),
        "schema.sql 未包含 redaction_scans 表定义"
    );
    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS redaction_findings"),
        "schema.sql 未包含 redaction_findings 表定义"
    );
}

/// (10) bit_width_bucket 边界 —— 通过 insert → list 端到端验证位宽粗化。
///
/// **R1 NICE 改名**:原名(R1 版)让读者误以为 `floor(log2(n))`。
/// 实际语义是"位宽 bucket"(MSB 位号 1-based,0 特判 0)。
///
/// 内部 `bit_width_bucket` 是 private fn,此处通过公开 API 观测其行为,覆盖
/// 0 / 1 / 2 / 3(边界)/ 1024 等典型。
#[test]
fn test_bit_width_bucket_math() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = start_session(&l);

    // (len, expected_bucket):0→0, 1→1, 2→2, 3→2, 4→3, 1023→10, 1024→11。
    let cases: &[(usize, i64)] = &[
        (0, 0),
        (1, 1),
        (2, 2),
        (3, 2),
        (4, 3),
        (1023, 10),
        (1024, 11),
    ];

    for (len, expected) in cases {
        let scan_id = l
            .insert_redaction_scan(NewRedactionScan {
                session_id: &sid,
                source: "paste",
                text_length: *len,
                fingerprint: FP_A,
            })
            .unwrap();
        let rows = l.list_redaction_scans_by_session(&sid).unwrap();
        let row = rows
            .iter()
            .find(|r| r.scan_id == scan_id)
            .expect("scan_id round-trip");
        assert_eq!(
            row.text_length_bucket, *expected,
            "bit_width_bucket({len}) 期望 {expected},实际 {}",
            row.text_length_bucket
        );
    }
}

/// (11) **R2 新增(MUST-FIX 2 守门)**:跨 crate label SSOT 契约测试。
///
/// `vigil-audit` 本就 runtime-deps `vigil-redaction`(ledger.rs 用 detect_hard_secret
/// 做 fail-closed 自检,ADR 0002 §D1),T4→T0 方向正确;此处直接 `use vigil_redaction::`
/// 不增加任何新依赖;
/// 此测试把两侧 SSOT 集合精确双向 diff,任一侧漂移立即红。
///
/// 修改 `PrivacyLabel::as_str()` 或 `ALLOWED_REDACTION_LABELS` 时,另一侧必须同步,
/// 否则此测试会指出具体漂移字面量。
#[test]
fn contract_audit_labels_match_redaction_privacy_label() {
    use std::collections::BTreeSet;

    let audit_side: BTreeSet<&str> = ALLOWED_REDACTION_LABELS.iter().copied().collect();
    let redaction_side: BTreeSet<&str> = vigil_redaction::PrivacyLabel::ALL
        .iter()
        .map(|l| l.as_str())
        .collect();

    assert_eq!(
        audit_side, redaction_side,
        "跨 crate SSOT 漂移:\n  audit(ALLOWED_REDACTION_LABELS) = {audit_side:?}\n  \
         redaction(PrivacyLabel::as_str ALL) = {redaction_side:?}\n  \
         修法:同步改 crates/vigil-audit/src/ledger.rs::ALLOWED_REDACTION_LABELS 或 \
         crates/vigil-redaction/src/label.rs::PrivacyLabel"
    );
}
