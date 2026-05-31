//! BM-02 + BM-05:Ledger append 延迟基准(S1 — 只建基线,不定硬 SLO)。
//!
//! 产品角度:每次 tool call 都会向 ledger 追加至少一条事件;append 延迟直接影响
//! agent 的 tool call RTT。BM-02 测冷启动状态,BM-05 测 10 万条已存在事件后是否退化
//! (SQLite FTS5 + B-tree 长表的真实表现)。

// bench 代码允许 unwrap/expect/panic —— 环境异常应 fail-fast 暴露
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json::json;
use vigil_audit::Ledger;

fn setup_ledger_with_session() -> (Ledger, String) {
    // 用内存库避免磁盘 IO 噪声,聚焦 append_event 自身的 CPU + SQLite cost
    let ledger = Ledger::open_in_memory().expect("open in-memory ledger");
    let session = ledger
        .start_session("bench", Some("bench-app"))
        .expect("start_session");
    (ledger, session)
}

/// BM-02:冷启动 ledger,测 append 单次耗时
fn bench_append_cold(c: &mut Criterion) {
    c.bench_function("ledger_append_cold", |b| {
        b.iter_batched(
            setup_ledger_with_session,
            |(ledger, session)| {
                let payload = json!({"note": "cold benchmark event"});
                ledger
                    .append_event(&session, "bench.cold", &payload, None)
                    .expect("append");
                black_box(())
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

/// BM-05:预填 10 万条后,测 append 是否退化
///
/// SQLite FTS5 + 长表在数据量大时 B-tree 深度 + FTS rowid 分配可能拖慢。
/// 产品角度:长跑 session 末期 audit 不应突然变慢。
fn bench_append_hot(c: &mut Criterion) {
    // 预热代价不入采样(setup 在 iter_batched 外部);criterion 的 bench_function 语义下,
    // 手动准备一个长期复用的 ledger
    let (ledger, session) = setup_ledger_with_session();
    let payload = json!({"note": "preload"});
    // 预填 100k(内存库;每次写 events + event_fts 双表)
    // 注:此处用 expect 是 bench 专用,fail-fast 暴露环境问题
    for i in 0..100_000u32 {
        ledger
            .append_event(
                &session,
                &format!("bench.preload.{}", i % 8), // 少量 event_type variety,模拟真实
                &payload,
                None,
            )
            .expect("preload append");
    }

    let mut counter = 100_000u32;
    c.bench_function("ledger_append_after_100k", |b| {
        b.iter(|| {
            let p = json!({"note": "hot event"});
            counter += 1;
            ledger
                .append_event(&session, "bench.hot", &p, None)
                .expect("append");
            black_box(())
        })
    });
}

criterion_group!(benches, bench_append_cold, bench_append_hot);
criterion_main!(benches);
