//! Criterion benchmarks for `ogentic-redact-core`.
//!
//! Measures per-chunk latency of `redact_one_way` against the same 512-char
//! chunk used by the Python `bench_stream.py` reference benchmark (OGE-1282).
//!
//! Run with:
//!   cargo bench -p ogentic-redact-core

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ogentic_redact_core::redact_one_way;

// Mirrors the sample text in python/tests/bench_stream.py so the two
// benchmarks measure comparable workloads.
const SAMPLE_TEXT: &str = "\
Alice Johnson called the office at +1-800-555-0199 and left her email \
alice.johnson@example.com for the follow-up. She mentioned that Robert \
De Niro would join the call next Tuesday. The meeting link was sent to \
hr@ogenticai.com and the invoice was addressed to billing@corp.example. \
Please confirm with John Smith (john.smith@finance.org) by end of day. \
The IP 192.168.1.42 showed suspicious activity; SSN 123-45-6789 was \
flagged in the audit log. IBAN GB29NWBK60161331926819 appeared twice.";

/// Return a 512-char slice cycling through SAMPLE_TEXT.
fn make_chunk(offset: usize) -> String {
    let target = 512_usize;
    let src = SAMPLE_TEXT.repeat(4); // > 512 chars
    let start = offset % src.len();
    let end = (start + target).min(src.len());
    let mut chunk = src[start..end].to_owned();
    if chunk.len() < target {
        chunk.push_str(&src[..target - chunk.len()]);
    }
    chunk
}

fn bench_redact_one_way(c: &mut Criterion) {
    let chunk = make_chunk(0);

    let mut group = c.benchmark_group("redact_one_way_throughput");
    group.bench_with_input(
        BenchmarkId::new("512-char chunk", chunk.len()),
        &chunk,
        |b, input| {
            b.iter(|| redact_one_way(black_box(input)));
        },
    );
    group.finish();
}

criterion_group!(benches, bench_redact_one_way);
criterion_main!(benches);
