//! ADR 0020 audit checkpoint anchor 测试矩阵(Codex MF#7)。
//!
//! 核心 killer:整链重写后 `verify_chain` PASS 但 `verify_anchored` = CheckpointMismatch
//! —— 证明锚点确实检出哈希链单独检不出的整链重写(threat #7 本地部分)。
//! 另含 fail-closed 全覆盖 + checkpoint-only 绕过(MF#1)+ Unanchored(MF#2)+ 身份字段(MF#3)。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rusqlite::Connection;
use serde_json::json;
use tempfile::tempdir;
use vigil_audit::{Anchored, AuditError, CheckpointLog, Ledger};

/// 建一个磁盘账本 + 追加 `n` 条事件(session 来源 `source`,payload 含序号)。返回 db 路径。
fn ledger_with_events(dir: &std::path::Path, source: &str, n: usize) -> std::path::PathBuf {
    let path = dir.join("ledger.db");
    let l = Ledger::open(&path).unwrap();
    let sid = l.start_session(source, None).unwrap();
    for i in 0..n {
        l.append_event(&sid, "test.event", &json!({ "i": i, "src": source }), None)
            .unwrap();
    }
    l.verify_chain().unwrap();
    path
}

#[test]
fn happy_path_emit_then_verify_anchored() {
    let dir = tempdir().unwrap();
    let path = ledger_with_events(dir.path(), "s1", 3);
    let l = Ledger::open(&path).unwrap();
    let log = CheckpointLog::sidecar_for(&path);

    let cp = log.emit(&l).unwrap().expect("非空链应产出 checkpoint");
    assert_eq!(cp.event_id, 3, "应锚定链头 event_id=3");

    match log.verify_anchored(&l).unwrap() {
        Anchored::Verified {
            checkpoints,
            through_event_id,
        } => {
            assert_eq!(checkpoints, 1);
            assert_eq!(through_event_id, 3);
        }
        other => panic!("期望 Verified,得 {other:?}"),
    }
}

#[test]
fn empty_chain_emit_is_none() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let l = Ledger::open(&path).unwrap();
    let log = CheckpointLog::sidecar_for(&path);
    assert!(log.emit(&l).unwrap().is_none(), "空链 emit 应 None");
}

#[test]
fn no_sidecar_is_unanchored_not_verified() {
    // MF#2:无 checkpoint / sidecar 不存在 → Unanchored,绝不冒充 verified。
    let dir = tempdir().unwrap();
    let path = ledger_with_events(dir.path(), "s1", 2);
    let l = Ledger::open(&path).unwrap();
    let log = CheckpointLog::sidecar_for(&path);
    assert!(!log.path().exists(), "尚未 emit,sidecar 不应存在");
    assert_eq!(log.verify_anchored(&l).unwrap(), Anchored::Unanchored);
}

#[test]
fn monotonic_emit_noop_when_head_unchanged() {
    let dir = tempdir().unwrap();
    let path = ledger_with_events(dir.path(), "s1", 2);
    let l = Ledger::open(&path).unwrap();
    let log = CheckpointLog::sidecar_for(&path);
    assert!(log.emit(&l).unwrap().is_some(), "首次 emit 应产出");
    assert!(
        log.emit(&l).unwrap().is_none(),
        "链头未前进,二次 emit 应 None(不破坏严格递增)"
    );
}

#[test]
fn killer_full_chain_rewrite_passes_verify_chain_but_anchor_detects() {
    // ★ 核心 killer(threat #7 本地部分):整链重写(wipe + 重建一条合法新链于同 event_id)
    // → verify_chain 仍 PASS(新链内部自洽)→ 但锚点检出(锚定的历史链头绑定字段已变)。
    let dir = tempdir().unwrap();
    let path = ledger_with_events(dir.path(), "s1", 3);
    let log = CheckpointLog::sidecar_for(&path);
    {
        let l = Ledger::open(&path).unwrap();
        log.emit(&l).unwrap().expect("emit 锚定 event 3");
    }

    // 攻击者:清空 events 表 + 重置自增 + 重建一条**不同内容**但内部自洽的新链(同 event_id 1..3)。
    // (sidecar 文件未被触及 —— 这正是本层的检出前提:攻击作用域限于 DB。)
    {
        let c = Connection::open(&path).unwrap();
        c.execute("DELETE FROM events", []).unwrap();
        c.execute("DELETE FROM event_fts", []).unwrap();
        // 重置 AUTOINCREMENT,让重建的事件复用 event_id 1..3(模拟"原地重写"而非"截断")。
        let _ = c.execute(
            "UPDATE sqlite_sequence SET seq = 0 WHERE name = 'events'",
            [],
        );
    }
    let l2 = Ledger::open(&path).unwrap();
    let sid2 = l2.start_session("s2-forged", None).unwrap();
    for i in 0..3 {
        l2.append_event(
            &sid2,
            "test.event",
            &json!({ "i": i, "src": "forged" }),
            None,
        )
        .unwrap();
    }

    // 整链重写后:链内自洽 → verify_chain 仍通过(这正是哈希链单独检不出的攻击)。
    l2.verify_chain()
        .expect("重写后的新链内部自洽,verify_chain 应通过(证明 hash-chain 单独无法检出)");

    // 但锚点检出:event 3 的绑定字段(hash/session/...)已变。
    let err = log.verify_anchored(&l2).expect_err("锚点必须检出整链重写");
    assert!(
        matches!(err, AuditError::CheckpointMismatch { .. }),
        "期望 CheckpointMismatch,得 {err:?}"
    );
}

#[test]
fn checkpoint_only_bypass_is_blocked_by_chain_check_first() {
    // MF#1 证明:攻击者把 events[3] 内容改了但**保留** event_hash = 锚定值(企图骗过仅比对 hash 的
    // 检查)。因 verify_anchored **先**跑 verify_chain,会因 recompute != 存储 hash 而 ChainBroken,
    // 绝不返回 Verified。
    let dir = tempdir().unwrap();
    let path = ledger_with_events(dir.path(), "s1", 3);
    let log = CheckpointLog::sidecar_for(&path);
    {
        let l = Ledger::open(&path).unwrap();
        log.emit(&l).unwrap().expect("emit 锚定 event 3");
    }
    // 改 payload 但**不**动 event_hash(= 锚定值):制造"锚点 hash 匹配但行内不自洽"。
    {
        let c = Connection::open(&path).unwrap();
        c.execute(
            "UPDATE events SET payload_json = ?1 WHERE event_id = 3",
            rusqlite::params![r#"{"x":"evil"}"#],
        )
        .unwrap();
    }
    let l = Ledger::open(&path).unwrap();
    let err = log
        .verify_anchored(&l)
        .expect_err("checkpoint-only 绕过必须被前置链校验挡住");
    assert!(
        matches!(err, AuditError::ChainBroken { .. }),
        "期望 ChainBroken(verify_chain 先行),得 {err:?}"
    );
}

#[test]
fn deleted_anchored_event_is_mismatch() {
    let dir = tempdir().unwrap();
    let path = ledger_with_events(dir.path(), "s1", 3);
    let log = CheckpointLog::sidecar_for(&path);
    {
        let l = Ledger::open(&path).unwrap();
        log.emit(&l).unwrap().expect("emit 锚定 event 3");
    }
    // 删掉锚定的 event 3(截断):剩余 1,2 链仍自洽。
    {
        let c = Connection::open(&path).unwrap();
        c.execute("DELETE FROM events WHERE event_id = 3", [])
            .unwrap();
        c.execute("DELETE FROM event_fts WHERE rowid = 3", [])
            .unwrap();
    }
    let l = Ledger::open(&path).unwrap();
    l.verify_chain().expect("剩余 1,2 链内自洽");
    let err = log.verify_anchored(&l).expect_err("锚定事件被删应检出");
    assert!(
        matches!(err, AuditError::CheckpointMismatch { event_id: 3 }),
        "期望 CheckpointMismatch{{event_id:3}},得 {err:?}"
    );
}

#[test]
fn corrupt_sidecar_malformed_line_fails_closed() {
    let dir = tempdir().unwrap();
    let sidecar = dir.path().join("x.checkpoints");
    std::fs::write(&sidecar, "this is not json\n").unwrap();
    let log = CheckpointLog::at(&sidecar);
    let err = log.load().expect_err("坏行必须 fail-closed");
    assert!(matches!(err, AuditError::CheckpointStoreCorrupt { .. }));
}

#[test]
fn corrupt_sidecar_non_monotonic_fails_closed() {
    // 两条合法 JSON 但 event_id 5 → 3(非严格递增)→ 拒绝。
    let dir = tempdir().unwrap();
    let sidecar = dir.path().join("x.checkpoints");
    let h = "a".repeat(64);
    let line = |id: i64| {
        format!(
            r#"{{"event_id":{id},"event_hash":"{h}","prev_hash":"","session_id":"s","event_type":"t","created_at":1,"anchored_at":1}}"#
        )
    };
    std::fs::write(&sidecar, format!("{}\n{}\n", line(5), line(3))).unwrap();
    let err = CheckpointLog::at(&sidecar)
        .load()
        .expect_err("非单调必须 fail-closed");
    assert!(matches!(err, AuditError::CheckpointStoreCorrupt { .. }));
}

#[test]
fn corrupt_sidecar_bad_hash_fails_closed() {
    let dir = tempdir().unwrap();
    let sidecar = dir.path().join("x.checkpoints");
    // event_hash 非 64-hex。
    std::fs::write(
        &sidecar,
        r#"{"event_id":1,"event_hash":"XYZ","prev_hash":"","session_id":"s","event_type":"t","created_at":1,"anchored_at":1}"#.to_string() + "\n",
    )
    .unwrap();
    let err = CheckpointLog::at(&sidecar)
        .load()
        .expect_err("非法 hash 必须 fail-closed");
    assert!(matches!(err, AuditError::CheckpointStoreCorrupt { .. }));
}

#[test]
fn corrupt_sidecar_unterminated_final_line_fails_closed() {
    // Codex BLOCKER 回归:完整 JSON 但**缺末尾换行**(撕裂/部分写)→ fail-closed
    // (BufRead::lines() 会误纳;末字节守门拒之)。
    let dir = tempdir().unwrap();
    let sidecar = dir.path().join("x.checkpoints");
    let h = "a".repeat(64);
    std::fs::write(
        &sidecar,
        // 注意:**无**结尾 '\n'。
        format!(
            r#"{{"event_id":1,"event_hash":"{h}","prev_hash":"","session_id":"s","event_type":"t","created_at":1,"anchored_at":1}}"#
        ),
    )
    .unwrap();
    let err = CheckpointLog::at(&sidecar)
        .load()
        .expect_err("未结束的末行必须 fail-closed");
    assert!(matches!(err, AuditError::CheckpointStoreCorrupt { .. }));
}

#[test]
fn empty_sidecar_file_loads_as_no_checkpoints() {
    // 0 字节 sidecar(被创建但从未写入)= 未锚定(非错误、非 verified)。
    let dir = tempdir().unwrap();
    let sidecar = dir.path().join("x.checkpoints");
    std::fs::write(&sidecar, "").unwrap();
    assert!(
        CheckpointLog::at(&sidecar).load().unwrap().is_empty(),
        "0 字节 sidecar 应 load 成空(未锚定)"
    );
}

#[test]
fn corrupt_sidecar_non_positive_id_fails_closed() {
    let dir = tempdir().unwrap();
    let sidecar = dir.path().join("x.checkpoints");
    let h = "a".repeat(64);
    std::fs::write(
        &sidecar,
        format!(
            r#"{{"event_id":0,"event_hash":"{h}","prev_hash":"","session_id":"s","event_type":"t","created_at":1,"anchored_at":1}}"#
        ) + "\n",
    )
    .unwrap();
    let err = CheckpointLog::at(&sidecar)
        .load()
        .expect_err("非正 event_id 必须 fail-closed");
    assert!(matches!(err, AuditError::CheckpointStoreCorrupt { .. }));
}

#[test]
fn corrupt_sidecar_duplicate_id_fails_closed() {
    // 同 event_id 两次(非严格递增)→ 拒绝。
    let dir = tempdir().unwrap();
    let sidecar = dir.path().join("x.checkpoints");
    let h = "a".repeat(64);
    let l = format!(
        r#"{{"event_id":2,"event_hash":"{h}","prev_hash":"","session_id":"s","event_type":"t","created_at":1,"anchored_at":1}}"#
    );
    std::fs::write(&sidecar, format!("{l}\n{l}\n")).unwrap();
    let err = CheckpointLog::at(&sidecar)
        .load()
        .expect_err("重复 event_id 必须 fail-closed");
    assert!(matches!(err, AuditError::CheckpointStoreCorrupt { .. }));
}
