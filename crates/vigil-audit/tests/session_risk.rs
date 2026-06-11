//! P0 注入防护 Slice 2a — `bump_session_risk` session risk 写 API 守门。
//!
//! 反馈环基础设施:元指令命中 → 累加 `sessions.risk_score` → 后续 hook 读分升档。
//! `risk_score` 列自 I01 起就在 schema(DEFAULT 0)但一直无写入口,本测试守门首个写 API。
//!
//! 重点验:
//!   - 累加正确 / 多次累加叠加;
//!   - session 行不存在时先兜底建行再 bump(hook 可能先于 start_session);
//!   - **IMMEDIATE 写安全**:两个独立 `Ledger` 连接(模拟 hook 多进程)并发 bump
//!     同一 session,无 `SQLITE_BUSY_SNAPSHOT(517)`,最终累加值精确等于各 delta 之和
//!     (无丢更新)。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::thread;

use tempfile::tempdir;
use vigil_audit::Ledger;

#[test]
fn bump_on_existing_session_accumulates_and_returns_new_score() {
    let ledger = Ledger::open_in_memory().unwrap();
    let sid = ledger.start_session("test", None).unwrap();

    // 单次 bump:0 + 8 = 8。
    assert_eq!(ledger.bump_session_risk(&sid, 8).unwrap(), 8);
    // 再次 bump:8 + 8 = 16(多次累加叠加)。
    assert_eq!(ledger.bump_session_risk(&sid, 8).unwrap(), 16);
    // 第三次:16 + 8 = 24。
    assert_eq!(ledger.bump_session_risk(&sid, 8).unwrap(), 24);

    // 读路径(list_sessions)看到的 risk_score 与返回值一致。
    let sessions = ledger.list_sessions(None, 10).unwrap();
    let row = sessions.iter().find(|s| s.session_id == sid).unwrap();
    assert_eq!(row.risk_score, 24);
}

#[test]
fn bump_on_missing_session_creates_row_then_bumps() {
    let ledger = Ledger::open_in_memory().unwrap();
    // 该 session 从未经 start_session 建立(模拟 hook 先于会话建立)。
    let sid = "hook-session-never-started";

    // 行不存在 → 先 INSERT OR IGNORE 兜底建行(risk_score 0)再 +8 = 8。
    assert_eq!(ledger.bump_session_risk(sid, 8).unwrap(), 8);

    // 行已被建出,list_sessions 能查到,risk_score 正确。
    let sessions = ledger.list_sessions(None, 10).unwrap();
    let row = sessions.iter().find(|s| s.session_id == sid).unwrap();
    assert_eq!(row.risk_score, 8);
    // 占位 source 为 "unknown"(满足 NOT NULL)。
    assert_eq!(row.source, "unknown");

    // 后续再 bump 在已建行上叠加,不重复建行。
    assert_eq!(ledger.bump_session_risk(sid, 16).unwrap(), 24);
}

#[test]
fn idempotent_start_session_after_bump_keeps_risk() {
    // bump 兜底建行后,start_session 用相同 session_id 不会发生(start_session 生成
    // 自己的 UUID),但验证 bump 建出的行不被后续读路径误判:再 bump 仍叠加在累计值上。
    let ledger = Ledger::open_in_memory().unwrap();
    let sid = "pre-session-bumped";
    assert_eq!(ledger.bump_session_risk(sid, 8).unwrap(), 8);
    assert_eq!(ledger.bump_session_risk(sid, 8).unwrap(), 16);
    assert_eq!(ledger.bump_session_risk(sid, 8).unwrap(), 24);
}

#[test]
fn get_session_risk_reads_current_score_and_zero_for_missing() {
    // P0 注入防护 Slice 2b 读入口:PreToolUse 升档前读当前累计 risk。
    let ledger = Ledger::open_in_memory().unwrap();

    // session 不存在 → 返回 0(零风险,不报错),用 base 档不升档。
    assert_eq!(ledger.get_session_risk("never-seen").unwrap(), 0);

    // bump 后读到的值与 bump 返回的累加值一致。
    let sid = ledger.start_session("test", None).unwrap();
    assert_eq!(ledger.get_session_risk(&sid).unwrap(), 0);
    ledger.bump_session_risk(&sid, 8).unwrap();
    assert_eq!(ledger.get_session_risk(&sid).unwrap(), 8);
    ledger.bump_session_risk(&sid, 16).unwrap();
    assert_eq!(ledger.get_session_risk(&sid).unwrap(), 24);
}

/// IMMEDIATE 写安全:两个独立 `Ledger`(各持自己的连接,模拟 hook 多进程并发)
/// 各对同一 session bump N 次,最终累加值必须精确 = 两侧 delta 之和。
///
/// 若 bump 用 DEFERRED 事务(先 SELECT snapshot 再 UPDATE),WAL 下并发会撞
/// `SQLITE_BUSY_SNAPSHOT(517)` 或丢更新;IMMEDIATE 串行化写锁保证无冲突、无丢更新。
#[test]
fn concurrent_bumps_from_two_connections_no_lost_update() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("ledger.sqlite3");

    // 先用一个连接建好 session 行(避免两侧同时 INSERT OR IGNORE 的无关噪声;
    // 兜底建行已由 missing-session 测试覆盖,本测试聚焦并发累加无丢失)。
    let sid = {
        let l = Ledger::open(&db_path).unwrap();
        l.start_session("concurrent", None).unwrap()
    };

    let ledger_a = Arc::new(Ledger::open(&db_path).unwrap());
    let ledger_b = Arc::new(Ledger::open(&db_path).unwrap());

    const ROUNDS: i64 = 50;
    const DELTA: i64 = 8;

    let sid_a = sid.clone();
    let a = {
        let ledger_a = Arc::clone(&ledger_a);
        thread::spawn(move || {
            for _ in 0..ROUNDS {
                ledger_a.bump_session_risk(&sid_a, DELTA).unwrap();
            }
        })
    };
    let sid_b = sid.clone();
    let b = {
        let ledger_b = Arc::clone(&ledger_b);
        thread::spawn(move || {
            for _ in 0..ROUNDS {
                ledger_b.bump_session_risk(&sid_b, DELTA).unwrap();
            }
        })
    };
    a.join().unwrap();
    b.join().unwrap();

    // 两侧各 ROUNDS 次 × DELTA,总计 2*ROUNDS*DELTA,无丢更新。
    let expected = 2 * ROUNDS * DELTA;
    let sessions = ledger_a.list_sessions(None, 10).unwrap();
    let row = sessions.iter().find(|s| s.session_id == sid).unwrap();
    assert_eq!(
        row.risk_score, expected,
        "concurrent bumps lost updates (got {}, want {expected})",
        row.risk_score
    );
}
