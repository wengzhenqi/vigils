//! v0.7-α2 Phase 2A — `scan_text` Hard-only 路径性能基线(invariant #13 默认关键路径)。
//!
//! # 用途
//!
//! ADR 0016 锁 invariant #13 默认关键路径 SLO:**warm p95 < 10ms / cold p95 < 100ms**。
//! 本 bench 给 `scan_text`(默认走 NoopEngine,等价 Hard-only)产 1KB / 10KB / 100KB
//! 三档基线,与 [`scrub.rs`](scrub.rs) 互补:
//! - `scrub.rs`:`scrub_text`(结果替换为占位符的字符串)
//! - 本 bench:`scan_text`(结构化 RedactionResult,SDK 默认入口)
//!
//! # 与 invariant #13 关系
//!
//! - 默认路径 `scan_text` 内部走 `scan_text_with_engine(text, &NoopEngine)` →
//!   `merge_findings(hard_findings, vec![])` 退化为 hard-only 全保留
//! - 实测 v0.6.1 multilang 32-sample fixture hard_only 总耗 2.78ms = ~87μs/sample
//!   远低于 10ms 阈值;本 bench 给 1KB / 10KB / 100KB 三档量化跨输入大小的退化曲线
//!
//! # CI gate
//!
//! 走 workspace `cargo bench --bench scan_hardonly`(0 ORT,默认 feature)。
//! 阈值由 CI 设(criterion 自动 baseline diff,regression > 20% 即 fail)。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use vigil_redaction::scan_text;

fn bench_scan_sizes(c: &mut Criterion) {
    // 三档代表性大小,与 scrub.rs 同步
    // 1 KB = 短对话(typical chat prompt)
    // 10 KB = 中型 prompt(含上下文)
    // 100 KB = 贴文档(代码/配置粘贴)
    let sizes: &[(usize, &str)] = &[(1024, "1KB"), (10 * 1024, "10KB"), (100 * 1024, "100KB")];

    let mut group = c.benchmark_group("scan_text_hardonly");
    for (size, label) in sizes {
        // 语料构造:80% 普通英文 + 20% 含硬指纹(token / email / url)迫使规则真扫
        // 每 5 KB 插 1 条 hard finding,确保不同 size 都至少命中
        let mut corpus = String::with_capacity(*size);
        while corpus.len() < *size {
            corpus.push_str("The quick brown fox jumps over the lazy dog. ");
            if corpus.len() % 5120 < 50 {
                corpus.push_str(" token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ ");
                corpus.push_str(" mail user@example.com visit https://example.com/path ");
            }
        }
        corpus.truncate(*size);

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &corpus, |b, c| {
            b.iter(|| {
                // scan_text 默认走 NoopEngine,等价 hard-only;Result 不解包避免分支干扰
                let _ = black_box(scan_text(black_box(c)));
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_scan_sizes);
criterion_main!(benches);
