//! Scenario-driven CBOR benchmarks.
//!
//! The suite is organized around what real SACP endpoints do with messages,
//! not around isolated parser micro-ops:
//!
//! - `validate`      — accept/reject an untrusted message (sacp-cbor
//!   `validate_canonical` vs the closest competitor equivalent, a full parse).
//! - `ingest`        — receive-side hot path: check an untrusted message and
//!   read its routing fields (zero-copy validate+query vs decode-everything).
//! - `decode_typed`  — full decode to an owned value tree.
//! - `encode`        — typed value tree to wire bytes.
//! - `roundtrip`     — encode + decode.
//! - `patch`         — gateway rewrite: change one field and re-emit canonical
//!   bytes (structural `Editor` vs decode→mutate→encode).
//! - `appendix_a`    — RFC 8949 test vectors (small-item soup).
//! - `micro_query` / `micro_edit` — optimization-target micro benches for the
//!   query and edit hot paths.
//!
//! Criterion IDs are uniformly `scenario/implementation/workload`, which the
//! report binary pivots into per-scenario comparison tables.

use std::sync::OnceLock;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use bench_harness::adapters::{encode_sacp_stream, Adapter, SacpCbor};
use bench_harness::datasets::{dataset_root, load_appendix_a, workloads, Workload, FAST_WORKLOADS};
use bench_harness::query_edit::{bench_value_at, bench_value_set, sort_map_entries};
use bench_harness::value::{BenchValue, BenchValueBorrowed, BenchValueNative};
use sacp_cbor::edit::{ArrayPos, DeleteMode, PatchValue, SetMode, Splice};
use sacp_cbor::query::PathElem;
use sacp_cbor::{decode_canonical, encode_to_canonical, DecodeLimits};
use serde::de::IgnoredAny;

#[cfg(feature = "adapter-cbor4ii")]
use bench_harness::adapters::Cbor4ii;
#[cfg(feature = "adapter-ciborium")]
use bench_harness::adapters::Ciborium;
#[cfg(feature = "adapter-minicbor")]
use bench_harness::adapters::Minicbor;
#[cfg(feature = "adapter-serde_cbor")]
use bench_harness::adapters::SerdeCbor;
#[cfg(all(feature = "pprof", unix))]
use pprof::criterion::{Output, PProfProfiler};

#[allow(clippy::vec_init_then_push)]
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

fn fast_mode_enabled() -> bool {
    std::env::var_os("BENCH_FAST").is_some()
}

/* =========================
 * Workload fixtures
 * ========================= */

struct WorkloadData {
    workload: Workload,
    canon: sacp_cbor::CanonicalCbor,
    native: BenchValueNative,
}

static WORKLOAD_DATA: OnceLock<Vec<WorkloadData>> = OnceLock::new();

fn workload_data() -> &'static [WorkloadData] {
    WORKLOAD_DATA.get_or_init(|| {
        let fast = fast_mode_enabled();
        workloads()
            .into_iter()
            .filter(|w| !fast || FAST_WORKLOADS.contains(&w.name))
            .map(|workload| {
                let bytes = encode_sacp_stream(&workload.value).expect("encode workload");
                let limits = DecodeLimits::for_bytes(bytes.len());
                let canon = sacp_cbor::CanonicalCbor::from_vec(bytes, limits)
                    .expect("workload bytes must be canonical");
                let native = BenchValueNative::from_bench(&workload.value);
                WorkloadData {
                    workload,
                    canon,
                    native,
                }
            })
            .collect()
    })
}

static APPENDIX_CANONICAL: OnceLock<Vec<sacp_cbor::CanonicalCbor>> = OnceLock::new();

fn load_appendix_canonical() -> &'static Vec<sacp_cbor::CanonicalCbor> {
    APPENDIX_CANONICAL.get_or_init(|| {
        let path = dataset_root().join("appendix_a.json");
        let dataset = load_appendix_a(&path).expect("appendix_a.json must load");
        let mut out = Vec::new();
        for bytes in dataset.items {
            let limits = sacp_cbor::DecodeLimits::for_bytes(bytes.len());
            if let Ok(canon) = sacp_cbor::CanonicalCbor::from_vec(bytes, limits) {
                out.push(canon);
            }
        }
        out
    })
}

/* =========================
 * Pipeline scenarios
 * ========================= */

/// Accept/reject an untrusted message. sacp-cbor validates without building
/// anything; the closest competitor operation is a full ignored parse.
fn bench_validate(c: &mut Criterion) {
    let mut group = c.benchmark_group("validate");
    for data in workload_data() {
        let name = data.workload.name;
        let bytes = data.canon.as_bytes();
        group.throughput(Throughput::Bytes(bytes.len() as u64));

        group.bench_function(BenchmarkId::new("sacp-cbor", name), |b| {
            b.iter(|| {
                let canon = sacp_cbor::validate_canonical(
                    black_box(bytes),
                    DecodeLimits::for_bytes(bytes.len()),
                )
                .unwrap();
                black_box(canon);
            })
        });

        for adapter in adapters() {
            if adapter.name() == "sacp-cbor" {
                continue;
            }
            group.bench_function(BenchmarkId::new(adapter.name(), name), |b| {
                b.iter(|| adapter.decode_ignored(black_box(bytes)).unwrap())
            });
        }
    }
    group.finish();
}

/// Receive-side hot path: check an untrusted message, then read its routing
/// fields. This is the operation sacp-cbor's zero-copy query exists for; the
/// competitor flow has to decode the whole message first.
fn bench_ingest(c: &mut Criterion) {
    let mut group = c.benchmark_group("ingest");
    for data in workload_data() {
        let name = data.workload.name;
        let bytes = data.canon.as_bytes();
        let paths = data.workload.inspect_paths;
        group.throughput(Throughput::Bytes(bytes.len() as u64));

        group.bench_function(BenchmarkId::new("sacp-zerocopy", name), |b| {
            b.iter(|| {
                let canon = sacp_cbor::validate_canonical(
                    black_box(bytes),
                    DecodeLimits::for_bytes(bytes.len()),
                )
                .unwrap();
                for path in paths {
                    let v = canon.at(path).unwrap().expect("inspect path must hit");
                    black_box(v);
                }
            })
        });

        for adapter in adapters() {
            group.bench_function(BenchmarkId::new(adapter.name(), name), |b| {
                b.iter(|| {
                    let value = adapter.decode_bench_value(black_box(bytes)).unwrap();
                    for path in paths {
                        let v = bench_value_at(&value, path).expect("inspect path must hit");
                        black_box(v);
                    }
                })
            });
        }
    }
    group.finish();
}

/// Full decode to an owned value tree. `sacp-trusted`/`sacp-borrowed` decode
/// from an existing canonical witness (the cost after `validate` already ran).
fn bench_decode_typed(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_typed");
    for data in workload_data() {
        let name = data.workload.name;
        let bytes = data.canon.as_bytes();
        group.throughput(Throughput::Bytes(bytes.len() as u64));

        for adapter in adapters() {
            group.bench_function(BenchmarkId::new(adapter.name(), name), |b| {
                b.iter(|| {
                    let out = adapter.decode_bench_value(black_box(bytes)).unwrap();
                    black_box(out);
                })
            });
        }

        group.bench_function(BenchmarkId::new("sacp-trusted", name), |b| {
            b.iter(|| {
                let out: BenchValueNative = decode_canonical(
                    black_box(data.canon.as_canonical_ref()),
                    DecodeLimits::for_bytes(bytes.len()),
                )
                .unwrap();
                black_box(out);
            })
        });

        group.bench_function(BenchmarkId::new("sacp-borrowed", name), |b| {
            b.iter(|| {
                let out: BenchValueBorrowed<'_> = decode_canonical(
                    black_box(data.canon.as_canonical_ref()),
                    DecodeLimits::for_bytes(bytes.len()),
                )
                .unwrap();
                black_box(out);
            })
        });
    }
    group.finish();
}

/// Typed value tree to wire bytes.
fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");
    for data in workload_data() {
        let name = data.workload.name;
        group.throughput(Throughput::Bytes(data.canon.as_bytes().len() as u64));

        for adapter in adapters() {
            group.bench_function(BenchmarkId::new(adapter.name(), name), |b| {
                b.iter(|| {
                    let bytes = adapter
                        .encode_bench_value(black_box(&data.workload.value))
                        .unwrap();
                    black_box(bytes);
                })
            });
        }

        group.bench_function(BenchmarkId::new("sacp-stream", name), |b| {
            b.iter(|| {
                let bytes = encode_sacp_stream(black_box(&data.workload.value)).unwrap();
                black_box(bytes);
            })
        });
    }
    group.finish();
}

/// Encode + decode round-trip.
fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");
    for data in workload_data() {
        let name = data.workload.name;
        group.throughput(Throughput::Bytes(data.canon.as_bytes().len() as u64));

        for adapter in adapters() {
            group.bench_function(BenchmarkId::new(adapter.name(), name), |b| {
                b.iter(|| {
                    let bytes = adapter
                        .encode_bench_value(black_box(&data.workload.value))
                        .unwrap();
                    let out = adapter.decode_bench_value(bytes.as_slice()).unwrap();
                    black_box(out);
                })
            });
        }

        group.bench_function(BenchmarkId::new("sacp-native", name), |b| {
            b.iter(|| {
                let bytes = encode_to_canonical(black_box(&data.native)).unwrap();
                let out: BenchValueNative = decode_canonical(
                    bytes.as_canonical_ref(),
                    DecodeLimits::for_bytes(bytes.as_bytes().len()),
                )
                .unwrap();
                black_box(out);
            })
        });
    }
    group.finish();
}

/// Gateway rewrite: bump the root `"seq"` field and re-emit canonical bytes.
/// `sacp-editor` patches structurally; every other implementation must
/// decode the whole message, mutate, and re-encode.
fn bench_patch(c: &mut Criterion) {
    let seq_path = [PathElem::Key("seq")];

    let mut group = c.benchmark_group("patch");
    for data in workload_data() {
        let name = data.workload.name;
        let bytes = data.canon.as_bytes();
        group.throughput(Throughput::Bytes(bytes.len() as u64));

        group.bench_function(BenchmarkId::new("sacp-editor", name), |b| {
            b.iter(|| {
                let out = data
                    .canon
                    .edit(|ed| {
                        ed.set(
                            &seq_path,
                            SetMode::ReplaceOnly,
                            PatchValue::Encoded(encode_to_canonical(&4242i64).unwrap()),
                        )
                    })
                    .unwrap();
                black_box(out);
            })
        });

        for adapter in adapters() {
            group.bench_function(BenchmarkId::new(adapter.name(), name), |b| {
                b.iter(|| {
                    let mut value = adapter.decode_bench_value(black_box(bytes)).unwrap();
                    bench_value_set(&mut value, &seq_path, BenchValue::Int(4242)).unwrap();
                    let out = adapter.encode_bench_value(&value).unwrap();
                    black_box(out);
                })
            });
        }
    }
    group.finish();
}

/* =========================
 * RFC test vectors
 * ========================= */

fn bench_appendix_a(c: &mut Criterion) {
    let appendix = load_appendix_canonical();
    let total: u64 = appendix.iter().map(|b| b.as_bytes().len() as u64).sum();

    let mut group = c.benchmark_group("appendix_a");
    group.throughput(Throughput::Bytes(total));

    for adapter in adapters() {
        group.bench_function(BenchmarkId::new(adapter.name(), "decode_ignored"), |b| {
            b.iter(|| {
                for item in appendix {
                    adapter.decode_ignored(black_box(item.as_bytes())).unwrap();
                }
            })
        });
    }

    group.bench_function(BenchmarkId::new("sacp-validate", "validate_only"), |b| {
        b.iter(|| {
            for item in appendix {
                sacp_cbor::validate_canonical(
                    black_box(item.as_bytes()),
                    sacp_cbor::DecodeLimits::for_bytes(item.as_bytes().len()),
                )
                .unwrap();
            }
        })
    });

    group.bench_function(BenchmarkId::new("sacp-trusted", "decode_ignored"), |b| {
        b.iter(|| {
            for item in appendix {
                let out: IgnoredAny =
                    sacp_cbor::serde::from_canonical_bytes_ref(item.as_canonical_ref()).unwrap();
                black_box(out);
            }
        })
    });

    group.finish();
}

/* =========================
 * Micro benches (optimization targets)
 * ========================= */

fn build_nested_doc(items_len: usize, values_len: usize) -> BenchValue {
    let mut meta = vec![
        (
            "flags".to_string(),
            BenchValue::Array(vec![BenchValue::Bool(true), BenchValue::Bool(false)]),
        ),
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

fn build_map_doc(len: usize) -> BenchValue {
    BenchValue::synthetic_map(len, BenchValue::Int(7))
}

static MICRO_DOCS: OnceLock<Vec<(String, sacp_cbor::CanonicalCbor)>> = OnceLock::new();

fn micro_docs() -> &'static Vec<(String, sacp_cbor::CanonicalCbor)> {
    MICRO_DOCS.get_or_init(|| {
        let docs: Vec<(String, BenchValue)> = if fast_mode_enabled() {
            vec![
                ("map_k16".to_string(), build_map_doc(16)),
                ("nested_items32".to_string(), build_nested_doc(32, 64)),
                ("array_len64".to_string(), build_array_doc(64)),
            ]
        } else {
            vec![
                ("map_k64".to_string(), build_map_doc(64)),
                ("nested_items128".to_string(), build_nested_doc(128, 256)),
                ("array_len256".to_string(), build_array_doc(256)),
            ]
        };
        docs.into_iter()
            .map(|(name, v)| {
                let bytes = encode_sacp_stream(&v).expect("encode micro doc");
                let limits = DecodeLimits::for_bytes(bytes.len());
                let canon = sacp_cbor::CanonicalCbor::from_vec(bytes, limits)
                    .expect("micro doc bytes must be canonical");
                (name, canon)
            })
            .collect()
    })
}

fn bench_micro_query(c: &mut Criterion) {
    const ITEMS_INDEX: usize = 24;
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
    let keys_hit = ["k0001", "k0004", "k0008", "k0012"];
    let keys_miss = ["k0128", "k0500", "k7777", "k9999"];

    let mut group = c.benchmark_group("micro_query");
    for (name, item) in micro_docs() {
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

        if name.starts_with("map_") {
            let map = item.root().map().expect("map root");
            group.bench_function(BenchmarkId::new("get_hit", name), |b| {
                b.iter(|| {
                    let out = map.get("k0008").unwrap();
                    black_box(out);
                })
            });
            group.bench_function(BenchmarkId::new("get_miss", name), |b| {
                b.iter(|| {
                    let out = map.get("k9999").unwrap();
                    black_box(out);
                })
            });
            group.bench_function(BenchmarkId::new("get_many4_hit", name), |b| {
                b.iter(|| {
                    let out = map.get_many_sorted(keys_hit).unwrap();
                    black_box(out);
                })
            });
            group.bench_function(BenchmarkId::new("get_many4_miss", name), |b| {
                b.iter(|| {
                    let out = map.get_many_sorted(keys_miss).unwrap();
                    black_box(out);
                })
            });
        }
    }
    group.finish();
}

fn bench_micro_edit(c: &mut Criterion) {
    const ARRAY_REPLACE_INDEX: usize = 32;
    const ARRAY_SPLICE_INDEX: usize = 16;
    let array_path = [PathElem::Key("items")];

    fn encoded<'a, T: sacp_cbor::CborEncode>(value: &T) -> PatchValue<'a> {
        PatchValue::Encoded(encode_to_canonical(value).unwrap())
    }

    let mut group = c.benchmark_group("micro_edit");
    for (name, item) in micro_docs() {
        group.bench_function(BenchmarkId::new("noop", name), |b| {
            b.iter(|| {
                let out = item.edit(|_ed| Ok(())).unwrap();
                black_box(out);
            })
        });

        if name.starts_with("map_") {
            group.bench_function(BenchmarkId::new("map_set", name), |b| {
                b.iter(|| {
                    let out = item
                        .edit(|ed| {
                            ed.set(&[PathElem::Key("k0008")], SetMode::Upsert, encoded(&123i64))
                        })
                        .unwrap();
                    black_box(out);
                })
            });
            group.bench_function(BenchmarkId::new("map_insert", name), |b| {
                b.iter(|| {
                    let out = item
                        .edit(|ed| {
                            ed.set(
                                &[PathElem::Key("k9999")],
                                SetMode::InsertOnly,
                                encoded(&999i64),
                            )
                        })
                        .unwrap();
                    black_box(out);
                })
            });
            group.bench_function(BenchmarkId::new("map_delete", name), |b| {
                b.iter(|| {
                    let out = item
                        .edit(|ed| ed.delete(&[PathElem::Key("k0001")], DeleteMode::Require))
                        .unwrap();
                    black_box(out);
                })
            });
        }

        if name.starts_with("array_") {
            group.bench_function(BenchmarkId::new("array_set", name), |b| {
                b.iter(|| {
                    let out = item
                        .edit(|ed| {
                            ed.set(
                                &[PathElem::Key("items"), PathElem::Index(ARRAY_REPLACE_INDEX)],
                                SetMode::ReplaceOnly,
                                encoded(&777i64),
                            )
                        })
                        .unwrap();
                    black_box(out);
                })
            });
            group.bench_function(BenchmarkId::new("array_splice", name), |b| {
                b.iter(|| {
                    let out = item
                        .edit(|ed| {
                            ed.splice(
                                &array_path,
                                Splice {
                                    pos: ArrayPos::At(ARRAY_SPLICE_INDEX),
                                    delete: 4,
                                    insert: vec![encoded(&111i64), encoded(&222i64)],
                                },
                            )
                        })
                        .unwrap();
                    black_box(out);
                })
            });
        }
    }
    group.finish();
}

/* =========================
 * Harness setup
 * ========================= */

fn criterion_config() -> Criterion {
    let mut criterion = Criterion::default();
    if fast_mode_enabled() {
        criterion = criterion
            .sample_size(10)
            .warm_up_time(Duration::from_millis(500))
            .measurement_time(Duration::from_secs(1))
            .without_plots();
    }
    #[cfg(all(feature = "pprof", unix))]
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
        bench_ingest,
        bench_decode_typed,
        bench_encode,
        bench_roundtrip,
        bench_patch,
        bench_appendix_a,
        bench_micro_query,
        bench_micro_edit
}
criterion_main!(benches);
