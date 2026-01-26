#![allow(clippy::unwrap_used)]

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

use sacp_cbor::{decode_value, validate_canonical, CborMap, CborValue, DecodeLimits};

fn sample_small() -> Vec<u8> {
    vec![0xa1, 0x61, 0x61, 0x01] // {"a":1}
}

fn sample_medium() -> Vec<u8> {
    let mut entries = Vec::new();
    for i in 0..64_i64 {
        entries.push((format!("k{i:03}"), CborValue::Int(i)));
    }
    let map = CborMap::new(entries).unwrap();
    CborValue::Map(map).encode_canonical().unwrap()
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

    c.bench_function("decode_value_medium", |b| {
        b.iter(|| {
            let v = decode_value(black_box(&medium), medium_limits).unwrap();
            black_box(v);
        })
    });

    let decoded = decode_value(&medium, medium_limits).unwrap();
    c.bench_function("encode_canonical_medium", |b| {
        b.iter(|| {
            let bytes = decoded.encode_canonical().unwrap();
            black_box(bytes);
        })
    });
}

criterion_group!(benches, bench_validate);
criterion_main!(benches);
