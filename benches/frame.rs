//! Criterion benchmarks for the frame hot path.
//!
//! Production path per frame: read buffer -> `to_vec()` -> `seal()` (AEAD) ->
//! channel. These benches isolate each stage so the allocation/copy overhead
//! can be compared against the raw AEAD cost.

use std::hint::black_box;
use std::sync::Arc;

use bytes::BytesMut;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use newppp::proto::crypto::{CounterGen, FrameCipher};
use newppp::proto::frame::{FrameDecoder, FrameEncoder, FrameType, HEADER_LEN, TAG_LEN};

const KEY: [u8; 32] = [0x42; 32];
const SIZES: [usize; 3] = [64, 1024, 16 * 1024];

fn bench_aead(c: &mut Criterion) {
    let cipher = FrameCipher::new(&KEY);
    let mut group = c.benchmark_group("aead");
    for size in SIZES {
        let pt = vec![0xabu8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("seal", size), &pt, |b, pt| {
            b.iter(|| black_box(cipher.seal(1, b"aad", black_box(pt)).unwrap()));
        });

        let ct = cipher.seal(1, b"aad", &pt).unwrap();
        group.bench_with_input(BenchmarkId::new("open", size), &ct, |b, ct| {
            b.iter(|| black_box(cipher.open(1, b"aad", black_box(ct)).unwrap()));
        });
    }
    group.finish();
}

fn bench_frame(c: &mut Criterion) {
    let cipher = Arc::new(FrameCipher::new(&KEY));
    let mut group = c.benchmark_group("frame");
    for size in SIZES {
        let payload = vec![0xabu8; size];
        let enc = FrameEncoder::new(cipher.clone(), CounterGen::stream());
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("encode", size), &payload, |b, p| {
            b.iter(|| black_box(enc.encode(FrameType::Data, 0, 1, black_box(p)).unwrap()));
        });

        let mut reuse_buf = BytesMut::with_capacity(HEADER_LEN + size + TAG_LEN);
        group.bench_with_input(BenchmarkId::new("encode_reuse", size), &payload, |b, p| {
            b.iter(|| {
                reuse_buf.clear();
                enc.encode_into(FrameType::Data, 0, 1, black_box(p), &mut reuse_buf)
                    .unwrap();
                black_box(&reuse_buf);
            });
        });

        let wire = enc.encode(FrameType::Data, 0, 1, &payload).unwrap();
        group.bench_with_input(BenchmarkId::new("decode", size), &wire, |b, wire| {
            let mut dec = FrameDecoder::new(Some(cipher.clone()), None);
            b.iter(|| {
                dec.feed(black_box(wire));
                black_box(dec.next_frame().unwrap().unwrap())
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_aead, bench_frame);
criterion_main!(benches);
