#![allow(clippy::unwrap_used)]

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

use sacp_cbor::{validate_canonical, CborError, DecodeLimits, Encoder};

fn sample_small() -> Vec<u8> {
    vec![0xa1, 0x61, 0x61, 0x01] // {"a":1}
}

fn encode_map(len: usize, width: usize) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.map(len, |m| {
        for i in 0..len {
            let key = format!("k{i:0width$}", width = width);
            m.entry(key.as_str(), |e| e.int(i as i64))?;
        }
        Ok(())
    })
    .unwrap();
    enc.into_vec()
}

fn sample_medium() -> Vec<u8> {
    encode_map(64, 5)
}

fn sample_large_map(len: usize) -> Vec<u8> {
    encode_map(len, 5)
}

fn encode_depth_encoder(enc: &mut Encoder, depth: usize) -> Result<(), CborError> {
    if depth == 0 {
        return enc.null();
    }
    enc.array(1, |a| encode_depth_array(a, depth - 1))
}

fn encode_depth_array(
    arr: &mut sacp_cbor::ArrayEncoder<'_>,
    depth: usize,
) -> Result<(), CborError> {
    if depth == 0 {
        return arr.null();
    }
    arr.array(1, |a| encode_depth_array(a, depth - 1))
}

fn sample_deep(depth: usize) -> Vec<u8> {
    let mut enc = Encoder::new();
    encode_depth_encoder(&mut enc, depth).unwrap();
    enc.into_vec()
}

fn bench_validate(c: &mut Criterion) {
    let small = sample_small();
    let small_limits = DecodeLimits::for_bytes(small.len());

    c.bench_function("validate_canonical_small", |b| {
        b.iter(|| {
            validate_canonical(black_box(&small), small_limits).unwrap();
        })
    });

    let medium = sample_medium();
    let medium_limits = DecodeLimits::for_bytes(medium.len());

    c.bench_function("validate_canonical_medium", |b| {
        b.iter(|| {
            validate_canonical(black_box(&medium), medium_limits).unwrap();
        })
    });

    let large = sample_large_map(1024);
    let large_limits = DecodeLimits::for_bytes(large.len());
    c.bench_function("validate_canonical_large_map", |b| {
        b.iter(|| {
            validate_canonical(black_box(&large), large_limits).unwrap();
        })
    });

    let deep = sample_deep(32);
    let deep_limits = DecodeLimits::for_bytes(deep.len());
    c.bench_function("validate_canonical_deep", |b| {
        b.iter(|| {
            validate_canonical(black_box(&deep), deep_limits).unwrap();
        })
    });

    c.bench_function("encode_stream_medium", |b| {
        b.iter(|| {
            let bytes = sample_medium();
            black_box(bytes);
        })
    });
}

criterion_group!(benches, bench_validate);
criterion_main!(benches);
