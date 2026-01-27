use std::sync::OnceLock;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use bench_harness::adapters::{encode_sacp_stream, Adapter, SacpCbor};
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
#[cfg(feature = "pprof")]
use pprof::criterion::{Output, PProfProfiler};

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

static APPENDIX_CANONICAL: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
static SYNTHETIC_VALUES: OnceLock<Vec<(String, BenchValue)>> = OnceLock::new();
static SYNTHETIC_VALUES_FAST: OnceLock<Vec<(String, BenchValue)>> = OnceLock::new();
static SYNTHETIC_BYTES: OnceLock<Vec<(String, Vec<u8>)>> = OnceLock::new();
static SYNTHETIC_BYTES_FAST: OnceLock<Vec<(String, Vec<u8>)>> = OnceLock::new();

fn fast_mode_enabled() -> bool {
    std::env::var_os("BENCH_FAST").is_some()
}

fn load_appendix_canonical() -> &'static Vec<Vec<u8>> {
    APPENDIX_CANONICAL.get_or_init(|| {
        let path = dataset_root().join("appendix_a.json");
        let dataset = load_appendix_a(&path).expect("appendix_a.json must load");
        let mut out = Vec::new();
        for bytes in dataset.items {
            if sacp_cbor::validate(&bytes, sacp_cbor::DecodeLimits::for_bytes(bytes.len())).is_ok()
            {
                out.push(bytes);
            }
        }
        out
    })
}

fn synthetic_values() -> &'static Vec<(String, BenchValue)> {
    SYNTHETIC_VALUES.get_or_init(synthetic_datasets)
}

fn synthetic_values_fast() -> &'static Vec<(String, BenchValue)> {
    SYNTHETIC_VALUES_FAST.get_or_init(|| {
        synthetic_values()
            .iter()
            .filter(|(name, _)| {
                matches!(
                    name.as_str(),
                    "map_k16_i64" | "array_len256_bool"
                )
            })
            .cloned()
            .collect()
    })
}

fn synthetic_values_for_run() -> &'static Vec<(String, BenchValue)> {
    if fast_mode_enabled() {
        synthetic_values_fast()
    } else {
        synthetic_values()
    }
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

fn synthetic_bytes_for_run() -> &'static Vec<(String, Vec<u8>)> {
    if fast_mode_enabled() {
        SYNTHETIC_BYTES_FAST.get_or_init(|| synthetic_bytes(synthetic_values_fast()))
    } else {
        SYNTHETIC_BYTES.get_or_init(|| synthetic_bytes(synthetic_values()))
    }
}

fn bench_validate(c: &mut Criterion) {
    let appendix = load_appendix_canonical();
    for adapter in adapters() {
        let mut group = c.benchmark_group(format!("validate/{}", adapter.name()));
        group.bench_function("appendix_a_canonical", |b| {
            b.iter(|| {
                for item in appendix {
                    adapter.validate(black_box(item)).unwrap();
                }
            })
        });
        group.finish();
    }
}

fn bench_decode_validated(c: &mut Criterion) {
    let appendix = load_appendix_canonical();
    for adapter in adapters() {
        let mut group = c.benchmark_group(format!("decode_validated/{}", adapter.name()));
        group.bench_function("appendix_a_canonical", |b| {
            b.iter(|| {
                for item in appendix {
                    adapter.decode_discard(black_box(item)).unwrap();
                }
            })
        });
        group.finish();
    }
}

fn bench_decode_trusted(c: &mut Criterion) {
    let appendix = load_appendix_canonical();
    for adapter in adapters() {
        let mut group = c.benchmark_group(format!("decode_trusted/{}", adapter.name()));
        group.bench_function("appendix_a_canonical", |b| {
            b.iter(|| {
                for item in appendix {
                    adapter.decode_discard_trusted(black_box(item)).unwrap();
                }
            })
        });
        group.finish();
    }
}

fn bench_encode(c: &mut Criterion) {
    let values = synthetic_values_for_run();
    for adapter in adapters() {
        let mut group = c.benchmark_group(format!("encode/{}", adapter.name()));
        for (name, value) in values {
            group.bench_with_input(BenchmarkId::new("synthetic", name), value, |b, v| {
                b.iter(|| {
                    let _ = adapter.encode(black_box(v)).unwrap();
                })
            });
        }
        group.finish();
    }
}

fn bench_encode_stream(c: &mut Criterion) {
    let values = synthetic_values_for_run();
    let mut group = c.benchmark_group("encode_stream/sacp-cbor");
    for (name, value) in values {
        group.bench_with_input(BenchmarkId::new("synthetic", name), value, |b, v| {
            b.iter(|| {
                let _ = encode_sacp_stream(black_box(v)).unwrap();
            })
        });
    }
    group.finish();
}

fn bench_serde_roundtrip(c: &mut Criterion) {
    let values = synthetic_values_for_run();
    for adapter in adapters() {
        let mut group = c.benchmark_group(format!("serde_roundtrip/{}", adapter.name()));
        for (name, value) in values {
            group.bench_with_input(BenchmarkId::new("synthetic", name), value, |b, v| {
                b.iter(|| {
                    adapter.serde_roundtrip(black_box(v)).unwrap();
                })
            });
        }
        group.finish();
    }
}

fn bench_synthetic_decode_validated(c: &mut Criterion) {
    let bytes = synthetic_bytes_for_run();
    for adapter in adapters() {
        let mut group = c.benchmark_group(format!("decode_synth_validated/{}", adapter.name()));
        for (name, item) in bytes {
            group.bench_with_input(BenchmarkId::new("synthetic", name), item, |b, v| {
                b.iter(|| {
                    adapter.decode_discard(black_box(v)).unwrap();
                })
            });
        }
        group.finish();
    }
}

fn bench_synthetic_decode_trusted(c: &mut Criterion) {
    let bytes = synthetic_bytes_for_run();
    for adapter in adapters() {
        let mut group = c.benchmark_group(format!("decode_synth_trusted/{}", adapter.name()));
        for (name, item) in bytes {
            group.bench_with_input(BenchmarkId::new("synthetic", name), item, |b, v| {
                b.iter(|| {
                    adapter.decode_discard_trusted(black_box(v)).unwrap();
                })
            });
        }
        group.finish();
    }
}

fn criterion_config() -> Criterion {
    let mut criterion = Criterion::default();
    if fast_mode_enabled() {
        criterion = criterion
            .sample_size(10)
            .warm_up_time(Duration::from_millis(500))
            .measurement_time(Duration::from_secs(1))
            .without_plots();
    }
    #[cfg(feature = "pprof")]
    {
        criterion = criterion.with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    }
    criterion.configure_from_args()
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets =
        bench_validate,
        bench_decode_validated,
        bench_decode_trusted,
        bench_encode,
        bench_encode_stream,
        bench_serde_roundtrip,
        bench_synthetic_decode_validated,
        bench_synthetic_decode_trusted
}
criterion_main!(benches);
