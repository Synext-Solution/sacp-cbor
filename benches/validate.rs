#![allow(clippy::unwrap_used)]

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

use sacp_cbor::{validate_canonical, CborMap, CborValue, DecodeLimits};

#[cfg(feature = "serde")]
use sacp_cbor::from_slice;

fn sample_small() -> Vec<u8> {
    vec![0xa1, 0x61, 0x61, 0x01] // {"a":1}
}

fn sample_medium_value() -> CborValue {
    let mut entries = Vec::new();
    for i in 0..64_i64 {
        entries.push((
            format!("k{i:03}").into_boxed_str(),
            CborValue::int(i).unwrap(),
        ));
    }
    let map = CborMap::new(entries).unwrap();
    CborValue::map(map)
}

fn sample_medium() -> Vec<u8> {
    sample_medium_value().encode_canonical().unwrap()
}

fn sample_large_map(len: usize) -> Vec<u8> {
    let mut entries = Vec::new();
    for i in 0..len {
        entries.push((
            format!("k{i:05}").into_boxed_str(),
            CborValue::int(i as i64).unwrap(),
        ));
    }
    let map = CborMap::new(entries).unwrap();
    CborValue::map(map).encode_canonical().unwrap()
}

fn sample_deep(depth: usize) -> Vec<u8> {
    let mut v = CborValue::null();
    for _ in 0..depth {
        v = CborValue::array(vec![v]);
    }
    v.encode_canonical().unwrap()
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

    #[cfg(feature = "serde")]
    c.bench_function("from_slice_medium", |b| {
        b.iter(|| {
            let v: CborValue = from_slice(black_box(&medium), medium_limits).unwrap();
            black_box(v);
        })
    });

    #[cfg(feature = "serde")]
    c.bench_function("from_slice_deep", |b| {
        b.iter(|| {
            let v: CborValue = from_slice(black_box(&deep), deep_limits).unwrap();
            black_box(v);
        })
    });

    let decoded = sample_medium_value();
    c.bench_function("encode_canonical_medium", |b| {
        b.iter(|| {
            let bytes = decoded.encode_canonical().unwrap();
            black_box(bytes);
        })
    });

    #[cfg(feature = "sha2")]
    c.bench_function("encode_sha256_medium", |b| {
        b.iter(|| {
            let digest = decoded.sha256_canonical().unwrap();
            black_box(digest);
        })
    });
}

criterion_group!(benches, bench_validate);
criterion_main!(benches);
