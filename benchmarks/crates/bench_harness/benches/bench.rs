use std::sync::OnceLock;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use bench_harness::adapters::{encode_sacp_stream, Adapter, BenchInput, SacpCbor};
use bench_harness::datasets::{dataset_root, load_appendix_a, synthetic_datasets};
use bench_harness::query_edit::sort_map_entries;
use bench_harness::value::{BenchValue, BenchValueBorrowed, BenchValueNative};
use serde::de::IgnoredAny;
use sacp_cbor::{decode, encode_to_vec, ArrayPos, DecodeLimits, PathElem};

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

fn serde_adapters() -> Vec<Box<dyn Adapter>> {
    let mut out: Vec<Box<dyn Adapter>> = Vec::new();
    out.push(Box::new(SacpCbor));
    #[cfg(feature = "adapter-serde_cbor")]
    out.push(Box::new(SerdeCbor));
    #[cfg(feature = "adapter-ciborium")]
    out.push(Box::new(Ciborium));
    #[cfg(feature = "adapter-cbor4ii")]
    out.push(Box::new(Cbor4ii));
    out
}

static APPENDIX_CANONICAL: OnceLock<Vec<sacp_cbor::CborBytes>> = OnceLock::new();
static SYNTHETIC_VALUES: OnceLock<Vec<(String, BenchValue)>> = OnceLock::new();
static SYNTHETIC_VALUES_FAST: OnceLock<Vec<(String, BenchValue)>> = OnceLock::new();
static SYNTHETIC_BYTES: OnceLock<Vec<(String, sacp_cbor::CborBytes)>> = OnceLock::new();
static SYNTHETIC_BYTES_FAST: OnceLock<Vec<(String, sacp_cbor::CborBytes)>> = OnceLock::new();
static QUERY_EDIT_DOCS: OnceLock<Vec<(String, BenchValue)>> = OnceLock::new();
static QUERY_EDIT_DOCS_FAST: OnceLock<Vec<(String, BenchValue)>> = OnceLock::new();
static QUERY_EDIT_BYTES: OnceLock<Vec<(String, sacp_cbor::CborBytes)>> = OnceLock::new();
static QUERY_EDIT_BYTES_FAST: OnceLock<Vec<(String, sacp_cbor::CborBytes)>> = OnceLock::new();

fn fast_mode_enabled() -> bool {
    std::env::var_os("BENCH_FAST").is_some()
}

fn load_appendix_canonical() -> &'static Vec<sacp_cbor::CborBytes> {
    APPENDIX_CANONICAL.get_or_init(|| {
        let path = dataset_root().join("appendix_a.json");
        let dataset = load_appendix_a(&path).expect("appendix_a.json must load");
        let mut out = Vec::new();
        for bytes in dataset.items {
            let limits = sacp_cbor::DecodeLimits::for_bytes(bytes.len());
            if let Ok(canon) = sacp_cbor::CborBytes::from_vec(bytes, limits) {
                out.push(canon);
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

fn synthetic_bytes(values: &[(String, BenchValue)]) -> Vec<(String, sacp_cbor::CborBytes)> {
    values
        .iter()
        .map(|(name, v)| {
            let bytes = SacpCbor.encode(v).expect("encode synthetic value");
            let canon = sacp_cbor::CborBytes::from_vec_default_limits(bytes)
                .expect("synthetic bytes must be canonical");
            (name.clone(), canon)
        })
        .collect()
}

fn synthetic_bytes_for_run() -> &'static Vec<(String, sacp_cbor::CborBytes)> {
    if fast_mode_enabled() {
        SYNTHETIC_BYTES_FAST.get_or_init(|| synthetic_bytes(synthetic_values_fast()))
    } else {
        SYNTHETIC_BYTES.get_or_init(|| synthetic_bytes(synthetic_values()))
    }
}

fn build_nested_doc(items_len: usize, values_len: usize) -> BenchValue {
    let mut meta = vec![
        ("flags".to_string(), BenchValue::Array(vec![BenchValue::Bool(true), BenchValue::Bool(false)])),
        ("owner".to_string(), BenchValue::Text("alice".to_string())),
        ("version".to_string(), BenchValue::Int(1)),
    ];
    sort_map_entries(&mut meta);

    let mut items = Vec::with_capacity(items_len);
    for i in 0..items_len {
        let mut entry = vec![
            ("active".to_string(), BenchValue::Bool(i % 2 == 0)),
            ("id".to_string(), BenchValue::Int(i as i64)),
            ("score".to_string(), BenchValue::Int((i as i64) * 10)),
        ];
        sort_map_entries(&mut entry);
        items.push(BenchValue::Map(entry));
    }

    let values = BenchValue::Array((0..values_len).map(|i| BenchValue::Int(i as i64)).collect());

    let mut root = vec![
        ("items".to_string(), BenchValue::Array(items)),
        ("meta".to_string(), BenchValue::Map(meta)),
        ("values".to_string(), values),
    ];
    sort_map_entries(&mut root);
    BenchValue::Map(root)
}

fn build_array_doc(len: usize) -> BenchValue {
    let values = BenchValue::Array((0..len).map(|i| BenchValue::Int(i as i64)).collect());
    let mut root = vec![("items".to_string(), values)];
    sort_map_entries(&mut root);
    BenchValue::Map(root)
}

fn query_edit_docs() -> &'static Vec<(String, BenchValue)> {
    QUERY_EDIT_DOCS.get_or_init(|| {
        vec![
            ("map_k64".to_string(), BenchValue::synthetic_map(64, BenchValue::Int(7))),
            ("nested_items128".to_string(), build_nested_doc(128, 256)),
            ("array_len256".to_string(), build_array_doc(256)),
        ]
    })
}

fn query_edit_docs_fast() -> &'static Vec<(String, BenchValue)> {
    QUERY_EDIT_DOCS_FAST.get_or_init(|| {
        vec![
            ("map_k16".to_string(), BenchValue::synthetic_map(16, BenchValue::Int(7))),
            ("nested_items32".to_string(), build_nested_doc(32, 64)),
            ("array_len64".to_string(), build_array_doc(64)),
        ]
    })
}

fn query_edit_bytes(values: &[(String, BenchValue)]) -> Vec<(String, sacp_cbor::CborBytes)> {
    values
        .iter()
        .map(|(name, v)| {
            let bytes = SacpCbor.encode(v).expect("encode query/edit value");
            let canon =
                sacp_cbor::CborBytes::from_vec_default_limits(bytes)
                    .expect("query/edit bytes must be canonical");
            (name.clone(), canon)
        })
        .collect()
}

fn query_edit_bytes_for_run() -> &'static Vec<(String, sacp_cbor::CborBytes)> {
    if fast_mode_enabled() {
        QUERY_EDIT_BYTES_FAST.get_or_init(|| query_edit_bytes(query_edit_docs_fast()))
    } else {
        QUERY_EDIT_BYTES.get_or_init(|| query_edit_bytes(query_edit_docs()))
    }
}

fn bench_validate(c: &mut Criterion) {
    let appendix = load_appendix_canonical();
    for adapter in adapters() {
        let mut group = c.benchmark_group(format!("validate/{}", adapter.name()));
        group.bench_function("appendix_a_canonical", |b| {
            b.iter(|| {
                for item in appendix {
                    adapter.validate(black_box(item.as_bytes())).unwrap();
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
                    adapter.decode_discard(black_box(item.as_bytes())).unwrap();
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
                    let input = BenchInput {
                        bytes: item.as_bytes(),
                        sacp_canon: Some(item.as_ref()),
                    };
                    adapter.decode_discard_trusted(black_box(&input)).unwrap();
                }
            })
        });
        group.finish();
    }
}

fn bench_decode_canonical_trusted(c: &mut Criterion) {
    let appendix = load_appendix_canonical();
    let mut group = c.benchmark_group("decode_canonical_trusted/sacp-cbor");
    group.bench_function("appendix_a_canonical", |b| {
        b.iter(|| {
            for item in appendix {
                let out: IgnoredAny = sacp_cbor::from_canonical_bytes_ref(item.as_ref()).unwrap();
                black_box(out);
            }
        })
    });
    group.finish();
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
    for adapter in serde_adapters() {
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

fn bench_native_roundtrip(c: &mut Criterion) {
    let values = synthetic_values_for_run();
    let mut group = c.benchmark_group("native_roundtrip/sacp-cbor");
    for (name, value) in values {
        let native = BenchValueNative::from_bench(value);
        group.bench_with_input(BenchmarkId::new("synthetic", name), &native, |b, v| {
            b.iter(|| {
                let bytes = encode_to_vec(black_box(v)).unwrap();
                let _out: BenchValueNative =
                    decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
            })
        });
    }
    group.finish();
}

fn bench_native_decode_borrowed(c: &mut Criterion) {
    let values = synthetic_values_for_run();
    let mut group = c.benchmark_group("native_decode_borrowed/sacp-cbor");
    for (name, value) in values {
        let native = BenchValueNative::from_bench(value);
        let bytes = encode_to_vec(&native).unwrap();
        group.bench_with_input(BenchmarkId::new("synthetic", name), &bytes, |b, bytes| {
            b.iter(|| {
                let _out: BenchValueBorrowed<'_> =
                    decode(black_box(bytes), DecodeLimits::for_bytes(bytes.len())).unwrap();
            })
        });
    }
    group.finish();
}

fn bench_synthetic_decode_validated(c: &mut Criterion) {
    let bytes = synthetic_bytes_for_run();
    for adapter in adapters() {
        let mut group = c.benchmark_group(format!("decode_synth_validated/{}", adapter.name()));
        for (name, item) in bytes {
            group.bench_with_input(BenchmarkId::new("synthetic", name), item, |b, v| {
                b.iter(|| {
                    adapter.decode_discard(black_box(v.as_bytes())).unwrap();
                })
            });
        }
        group.finish();
    }
}

fn bench_synthetic_query_trusted(c: &mut Criterion) {
    let bytes = synthetic_bytes_for_run();
    for adapter in adapters() {
        let mut group = c.benchmark_group(format!("query_synth_trusted/{}", adapter.name()));
        for (name, item) in bytes {
            group.bench_with_input(BenchmarkId::new("synthetic", name), item, |b, v| {
                b.iter(|| {
                    let input = BenchInput {
                        bytes: v.as_bytes(),
                        sacp_canon: Some(v.as_ref()),
                    };
                    adapter.decode_discard_trusted(black_box(&input)).unwrap();
                })
            });
        }
        group.finish();
    }
}

fn bench_synthetic_decode_canonical_trusted(c: &mut Criterion) {
    let bytes = synthetic_bytes_for_run();
    let mut group = c.benchmark_group("decode_synth_canonical_trusted/sacp-cbor");
    for (name, item) in bytes {
        group.bench_with_input(BenchmarkId::new("synthetic", name), item, |b, v| {
            b.iter(|| {
                let out: IgnoredAny = sacp_cbor::from_canonical_bytes_ref(v.as_ref()).unwrap();
                black_box(out);
            })
        });
    }
    group.finish();
}


fn bench_query_path_zero_copy(c: &mut Criterion) {
    const ITEMS_INDEX: usize = 24;
    let bytes = query_edit_bytes_for_run();
    let path_meta = [PathElem::Key("meta"), PathElem::Key("owner")];
    let path_items = [
        PathElem::Key("items"),
        PathElem::Index(ITEMS_INDEX),
        PathElem::Key("score"),
    ];
    let path_miss = [
        PathElem::Key("items"),
        PathElem::Index(999),
        PathElem::Key("score"),
    ];

    let mut group = c.benchmark_group("query_path_zero_copy/sacp-cbor");
    for (name, item) in bytes {
        let root = item.root();

        if name.starts_with("nested_") {
            group.bench_function(BenchmarkId::new("path_meta", name), |b| {
                b.iter(|| {
                    let out = root.at(&path_meta).unwrap();
                    black_box(out);
                })
            });
            group.bench_function(BenchmarkId::new("path_items", name), |b| {
                b.iter(|| {
                    let out = root.at(&path_items).unwrap();
                    black_box(out);
                })
            });
            group.bench_function(BenchmarkId::new("path_miss", name), |b| {
                b.iter(|| {
                    let out = root.at(&path_miss).unwrap();
                    black_box(out);
                })
            });
        }
    }
    group.finish();
}

fn bench_query_map_get_many_zero_copy(c: &mut Criterion) {
    let bytes = query_edit_bytes_for_run();
    let keys_hit = ["k0001", "k0004", "k0008", "k0012"];
    let keys_miss = ["k9999", "k7777", "k0500", "k0128"];

    let mut group = c.benchmark_group("query_map_get_many_zero_copy/sacp-cbor");
    for (name, item) in bytes {
        if !name.starts_with("map_") {
            continue;
        }
        let map = item.root().map().expect("map root");
        group.bench_function(BenchmarkId::new("hits4", name), |b| {
            b.iter(|| {
                let out = map.get_many_sorted(keys_hit).unwrap();
                black_box(out);
            })
        });
        group.bench_function(BenchmarkId::new("miss4", name), |b| {
            b.iter(|| {
                let out = map.get_many_sorted(keys_miss).unwrap();
                black_box(out);
            })
        });
    }
    group.finish();
}


fn bench_edit_patch(c: &mut Criterion) {
    const MAP_SET_KEY: &str = "k0008";
    const MAP_INSERT_KEY: &str = "k9999";
    const MAP_DELETE_KEY: &str = "k0001";
    const ARRAY_REPLACE_INDEX: usize = 32;
    const ARRAY_SPLICE_INDEX: usize = 16;

    let bytes = query_edit_bytes_for_run();
    let map_set_path = [PathElem::Key(MAP_SET_KEY)];
    let map_insert_path = [PathElem::Key(MAP_INSERT_KEY)];
    let map_delete_path = [PathElem::Key(MAP_DELETE_KEY)];
    let array_replace_path = [PathElem::Key("items"), PathElem::Index(ARRAY_REPLACE_INDEX)];
    let array_path = [PathElem::Key("items")];

    let mut group = c.benchmark_group("edit_patch/sacp-cbor");
    for (name, item) in bytes {

        if name.starts_with("map_") {
            group.bench_function(BenchmarkId::new("map_set", name), |b| {
                b.iter(|| {
                    let out = item.edit(|ed| ed.set(&map_set_path, 123i64)).unwrap();
                    black_box(out);
                })
            });
            group.bench_function(BenchmarkId::new("map_insert", name), |b| {
                b.iter(|| {
                    let out = item
                        .edit(|ed| ed.insert(&map_insert_path, 999i64))
                        .unwrap();
                    black_box(out);
                })
            });
            group.bench_function(BenchmarkId::new("map_delete", name), |b| {
                b.iter(|| {
                    let out = item.edit(|ed| ed.delete(&map_delete_path)).unwrap();
                    black_box(out);
                })
            });
        }

        if name.starts_with("array_") {
            group.bench_function(BenchmarkId::new("array_replace", name), |b| {
                b.iter(|| {
                    let out = item
                        .edit(|ed| ed.set(&array_replace_path, 777i64))
                        .unwrap();
                    black_box(out);
                })
            });
            group.bench_function(BenchmarkId::new("array_splice", name), |b| {
                b.iter(|| {
                    let out = item
                        .edit(|ed| {
                            ed.splice(&array_path, ArrayPos::At(ARRAY_SPLICE_INDEX), 4)?
                                .insert(111i64)?
                                .insert(222i64)?
                                .finish()
                        })
                        .unwrap();
                    black_box(out);
                })
            });
        }
    }
    group.finish();
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
    bench_decode_canonical_trusted,
    bench_encode,
    bench_encode_stream,
    bench_serde_roundtrip,
    bench_native_roundtrip,
    bench_native_decode_borrowed,
    bench_synthetic_decode_validated,
    bench_synthetic_query_trusted,
    bench_synthetic_decode_canonical_trusted,
    bench_query_path_zero_copy,
    bench_query_map_get_many_zero_copy,
        bench_edit_patch
}
criterion_main!(benches);
