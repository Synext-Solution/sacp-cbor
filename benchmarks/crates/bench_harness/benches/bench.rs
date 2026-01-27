use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use bench_harness::adapters::{Adapter, SacpCbor};
use bench_harness::datasets::{dataset_root, load_appendix_a, synthetic_datasets};
use bench_harness::value::BenchValue;

#[cfg(feature = "adapter-serde_cbor")]
use bench_harness::adapters::SerdeCbor;
#[cfg(feature = "adapter-ciborium")]
use bench_harness::adapters::Ciborium;
#[cfg(feature = "adapter-minicbor")]
use bench_harness::adapters::Minicbor;
#[cfg(feature = "adapter-cbor4ii")]
use bench_harness::adapters::Cbor4ii;

fn adapters() -> Vec<Box<dyn Adapter>> {
    let mut out: Vec<Box<dyn Adapter>> = Vec::new();
    out.push(Box::new(SacpCbor));
    #[cfg(feature = "adapter-serde_cbor")]
    out.push(Box::new(SerdeCbor));
    #[cfg(feature = "adapter-ciborium")]
    out.push(Box::new(Ciborium));
    #[cfg(feature = "adapter-minicbor")]
    out.push(Box::new(Minicbor));
    #[cfg(feature = "adapter-cbor4ii")]
    out.push(Box::new(Cbor4ii));
    out
}

fn load_appendix_canonical() -> Vec<Vec<u8>> {
    let path = dataset_root().join("appendix_a.json");
    let dataset = load_appendix_a(&path).expect("appendix_a.json must load");
    let mut out = Vec::new();
    for bytes in dataset.items {
        if sacp_cbor::validate(&bytes, sacp_cbor::DecodeLimits::for_bytes(bytes.len())).is_ok() {
            out.push(bytes);
        }
    }
    out
}

fn synthetic_values() -> Vec<(String, BenchValue)> {
    synthetic_datasets()
}

fn synthetic_bytes(values: &[(String, BenchValue)]) -> Vec<(String, Vec<u8>)> {
    values
        .iter()
        .map(|(name, v)| {
            let bytes = SacpCbor.encode(v).expect("encode synthetic value");
            (name.clone(), bytes)
        })
        .collect()
}

fn bench_validate(c: &mut Criterion) {
    let appendix = load_appendix_canonical();
    for adapter in adapters() {
        let mut group = c.benchmark_group(format!("validate/{}", adapter.name()));
        group.bench_function("appendix_a_canonical", |b| {
            b.iter(|| {
                for item in &appendix {
                    adapter.validate(black_box(item)).unwrap();
                }
            })
        });
        group.finish();
    }
}

fn bench_decode(c: &mut Criterion) {
    let appendix = load_appendix_canonical();
    for adapter in adapters() {
        let mut group = c.benchmark_group(format!("decode/{}", adapter.name()));
        group.bench_function("appendix_a_canonical", |b| {
            b.iter(|| {
                for item in &appendix {
                    adapter.decode_discard(black_box(item)).unwrap();
                }
            })
        });
        group.finish();
    }
}

fn bench_encode(c: &mut Criterion) {
    let values = synthetic_values();
    for adapter in adapters() {
        let mut group = c.benchmark_group(format!("encode/{}", adapter.name()));
        for (name, value) in &values {
            group.bench_with_input(BenchmarkId::new("synthetic", name), value, |b, v| {
                b.iter(|| {
                    let _ = adapter.encode(black_box(v)).unwrap();
                })
            });
        }
        group.finish();
    }
}

fn bench_serde_roundtrip(c: &mut Criterion) {
    let values = synthetic_values();
    for adapter in adapters() {
        let mut group = c.benchmark_group(format!("serde_roundtrip/{}", adapter.name()));
        for (name, value) in &values {
            group.bench_with_input(BenchmarkId::new("synthetic", name), value, |b, v| {
                b.iter(|| {
                    adapter.serde_roundtrip(black_box(v)).unwrap();
                })
            });
        }
        group.finish();
    }
}

fn bench_synthetic_decode(c: &mut Criterion) {
    let values = synthetic_values();
    let bytes = synthetic_bytes(&values);
    for adapter in adapters() {
        let mut group = c.benchmark_group(format!("decode_synth/{}", adapter.name()));
        for (name, item) in &bytes {
            group.bench_with_input(BenchmarkId::new("synthetic", name), item, |b, v| {
                b.iter(|| {
                    adapter.decode_discard(black_box(v)).unwrap();
                })
            });
        }
        group.finish();
    }
}

criterion_group!(
    benches,
    bench_validate,
    bench_decode,
    bench_encode,
    bench_serde_roundtrip,
    bench_synthetic_decode
);
criterion_main!(benches);
