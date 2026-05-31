//! BM-01:`scrub_text` 对不同大小文本的吞吐基准(S1 — 只建基线,不定硬 SLO)。
//!
//! 产品角度:Chrome 扩展 + Desktop UI 会对用户粘贴文本调 scrub。100 KB 在 1 ms 级
//! 说明"粘贴 → 脱敏"对用户感知是无延迟的。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use vigil_redaction::scrub_text;

fn bench_scrub_sizes(c: &mut Criterion) {
    // 三档代表性大小:1 KB(短对话)/ 10 KB(中型 prompt)/ 100 KB(贴文档)
    let sizes: &[(usize, &str)] = &[(1024, "1KB"), (10 * 1024, "10KB"), (100 * 1024, "100KB")];

    let mut group = c.benchmark_group("scrub_text");
    for (size, label) in sizes {
        // 语料:80% 普通英文 + 20% 命中硬指纹的片段,迫使规则都实际 scrub
        // 每 5 KB 插 1 条 hard finding 确保不同 size 都至少命中一次
        let mut corpus = String::with_capacity(*size);
        while corpus.len() < *size {
            corpus.push_str("The quick brown fox jumps over the lazy dog. ");
            if corpus.len() % 5120 < 50 {
                corpus.push_str(" token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ ");
            }
        }
        corpus.truncate(*size);

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &corpus, |b, c| {
            b.iter(|| black_box(scrub_text(black_box(c))))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_scrub_sizes);
criterion_main!(benches);
