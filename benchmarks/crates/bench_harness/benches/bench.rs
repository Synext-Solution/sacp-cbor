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
 * ABI fixtures
 * ========================= */

#[derive(Debug, Clone, PartialEq, Eq, sacp_cbor_abi::CborAbi)]
#[abi(type_id = "bench.AbiMessage", version = 1, unknown_fields = "preserve")]
struct AbiBenchMessage {
    #[abi(id = 1)]
    id: String,
    #[abi(id = 2)]
    kind: String,
    #[abi(id = 3)]
    seq: u64,
    #[abi(id = 4)]
    route: String,
    #[abi(id = 5, optional)]
    note: Option<String>,
    #[abi(id = 6)]
    payload: sacp_cbor::bytes::Bytes,
    #[abi(id = 7)]
    values: Vec<u64>,
    #[abi(unknown_fields)]
    unknown: sacp_cbor_abi::UnknownFields,
}

#[derive(Debug, Clone, PartialEq, Eq, sacp_cbor_abi::CborAbi)]
#[abi(type_id = "bench.AbiFlat16", version = 1)]
struct AbiFlat16 {
    #[abi(id = 1)]
    f01: u64,
    #[abi(id = 2)]
    f02: u64,
    #[abi(id = 3)]
    f03: u64,
    #[abi(id = 4)]
    f04: u64,
    #[abi(id = 5)]
    f05: String,
    #[abi(id = 6)]
    f06: String,
    #[abi(id = 7)]
    f07: String,
    #[abi(id = 8)]
    f08: String,
    #[abi(id = 9, optional)]
    f09: Option<String>,
    #[abi(id = 10, optional)]
    f10: Option<String>,
    #[abi(id = 11)]
    f11: u64,
    #[abi(id = 12)]
    f12: u64,
    #[abi(id = 13)]
    f13: u64,
    #[abi(id = 14)]
    f14: u64,
    #[abi(id = 15)]
    f15: u64,
    #[abi(id = 16)]
    f16: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, sacp_cbor_abi::CborAbi)]
#[abi(
    type_id = "bench.AbiUnknownIgnore",
    version = 1,
    unknown_fields = "ignore"
)]
struct AbiUnknownIgnore {
    #[abi(id = 1)]
    value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, sacp_cbor_abi::CborAbi)]
#[abi(
    type_id = "bench.AbiUnknownPreserve",
    version = 1,
    unknown_fields = "preserve"
)]
struct AbiUnknownPreserve {
    #[abi(id = 1)]
    value: u64,
    #[abi(unknown_fields)]
    unknown: sacp_cbor_abi::UnknownFields,
}

#[derive(Debug, Clone, PartialEq, Eq, sacp_cbor_abi::CborAbi)]
#[abi(type_id = "bench.AbiCommand", version = 1)]
enum AbiBenchCommand {
    #[abi(id = 1)]
    Route {
        #[abi(id = 1)]
        id: String,
        #[abi(id = 2)]
        seq: u64,
        #[abi(id = 3)]
        payload: sacp_cbor::bytes::Bytes,
    },
    #[abi(id = 2)]
    Ack,
    #[abi(unknown)]
    Unknown(sacp_cbor_abi::UnknownVariant),
}

struct AbiWorkload {
    name: &'static str,
    canon: sacp_cbor::CanonicalCbor,
}

static ABI_MESSAGE_WORKLOADS: OnceLock<Vec<AbiWorkload>> = OnceLock::new();
static ABI_FLAT16_WORKLOAD: OnceLock<AbiWorkload> = OnceLock::new();
static ABI_UNKNOWN_WORKLOADS: OnceLock<Vec<AbiWorkload>> = OnceLock::new();
static ABI_COMMAND_WORKLOADS: OnceLock<Vec<AbiWorkload>> = OnceLock::new();
static ABI_MESSAGE_SCHEMA: OnceLock<&'static sacp_cbor_abi::Schema> = OnceLock::new();
static ABI_MESSAGE_RUNTIME: OnceLock<sacp_cbor_abi::RuntimeFieldSetSchema<'static>> =
    OnceLock::new();
static ABI_UNKNOWN_SCHEMA: OnceLock<&'static sacp_cbor_abi::Schema> = OnceLock::new();
static ABI_UNKNOWN_RUNTIME: OnceLock<sacp_cbor_abi::RuntimeFieldSetSchema<'static>> =
    OnceLock::new();
static ABI_NAMED_CHILD_SCHEMA: OnceLock<&'static sacp_cbor_abi::Schema> = OnceLock::new();
static ABI_NAMED_CHILD_RUNTIME: OnceLock<sacp_cbor_abi::RuntimeSchema<'static>> = OnceLock::new();
static ABI_NAMED_ROOT_RUNTIME: OnceLock<sacp_cbor_abi::RuntimeFieldSetSchema<'static>> =
    OnceLock::new();
static ABI_NAMED_WORKLOAD: OnceLock<AbiWorkload> = OnceLock::new();

fn runtime_inline_mode() -> sacp_cbor_abi::RuntimeInline {
    sacp_cbor_abi::RuntimeInline
}

fn runtime_config() -> sacp_cbor_abi::RuntimeValidationConfig {
    sacp_cbor_abi::RuntimeValidationConfig::default()
}

struct AbiRoutingFieldHook;

impl sacp_cbor_abi::RuntimeValidationHooks for AbiRoutingFieldHook {
    fn exit_field(
        &mut self,
        _ctx: sacp_cbor_abi::RuntimeFieldContext<'_>,
        field: &sacp_cbor_abi::FieldDef,
        value: sacp_cbor::query::CborValueRef<'_>,
        outcome: sacp_cbor_abi::RuntimeHookOutcome,
    ) -> Result<(), sacp_cbor_abi::RuntimeAbiError> {
        if outcome != sacp_cbor_abi::RuntimeHookOutcome::Success {
            return Ok(());
        }
        match field.id {
            1 | 2 | 4 => {
                black_box(!value.text()?.is_empty());
            }
            3 => {
                black_box(value.integer()?.as_u128().is_some());
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Default)]
struct AbiVecSortedUniqueHook {
    prev: Option<u128>,
}

impl sacp_cbor_abi::RuntimeValidationHooks for AbiVecSortedUniqueHook {
    fn enter_vec(
        &mut self,
        ctx: sacp_cbor_abi::RuntimeTypeContext<'_>,
        _item: &sacp_cbor_abi::TypeRef,
        _value: sacp_cbor::query::CborValueRef<'_>,
        _len: usize,
    ) -> Result<(), sacp_cbor_abi::RuntimeAbiError> {
        if ctx.field.is_some_and(|field| field.id == 7) {
            self.prev = None;
        }
        Ok(())
    }

    fn exit_vec_item(
        &mut self,
        ctx: sacp_cbor_abi::RuntimeVecItemContext<'_>,
        _item: &sacp_cbor_abi::TypeRef,
        value: sacp_cbor::query::CborValueRef<'_>,
        outcome: sacp_cbor_abi::RuntimeHookOutcome,
    ) -> Result<(), sacp_cbor_abi::RuntimeAbiError> {
        if outcome != sacp_cbor_abi::RuntimeHookOutcome::Success
            || ctx.field.is_none_or(|field| field.id != 7)
        {
            return Ok(());
        }
        let item = value.integer()?.as_u128().ok_or_else(|| {
            sacp_cbor::CborError::new(sacp_cbor::ErrorCode::ExpectedInteger, value.offset())
        })?;
        if self.prev.is_some_and(|prev| item <= prev) {
            return Err(sacp_cbor_abi::RuntimeAbiError::HookRejected {
                reason: "values not sorted unique",
                offset: value.offset(),
            });
        }
        self.prev = Some(item);
        Ok(())
    }
}

struct AbiAcceptNamedHook;

impl sacp_cbor_abi::RuntimeValidationHooks for AbiAcceptNamedHook {
    fn validate_named(
        &mut self,
        _ctx: sacp_cbor_abi::RuntimeTypeContext<'_>,
        _type_id: &str,
        _version: Option<u32>,
        _value: sacp_cbor::query::CborValueRef<'_>,
    ) -> Result<sacp_cbor_abi::RuntimeNamedDecision, sacp_cbor_abi::RuntimeAbiError> {
        Ok(sacp_cbor_abi::RuntimeNamedDecision::Accepted)
    }
}

struct AbiBenchRegistry {
    schema: &'static sacp_cbor_abi::RuntimeSchema<'static>,
}

impl sacp_cbor_abi::AbiSchemaRegistry for AbiBenchRegistry {
    fn resolve<'r>(
        &'r self,
        type_id: &str,
        version: Option<u32>,
    ) -> Option<&'r sacp_cbor_abi::RuntimeSchema<'r>> {
        if type_id == "bench.NamedChild" && version == Some(1) {
            Some(self.schema)
        } else {
            None
        }
    }
}

fn abi_message_schema() -> &'static sacp_cbor_abi::Schema {
    ABI_MESSAGE_SCHEMA.get_or_init(|| {
        Box::leak(Box::new(
            <AbiBenchMessage as sacp_cbor_abi::AbiType>::schema(),
        ))
    })
}

fn abi_message_runtime_schema() -> &'static sacp_cbor_abi::RuntimeFieldSetSchema<'static> {
    ABI_MESSAGE_RUNTIME.get_or_init(|| {
        match sacp_cbor_abi::compile_runtime_schema(abi_message_schema())
            .expect("compile runtime ABI message schema")
        {
            sacp_cbor_abi::RuntimeSchema::Struct(schema) => schema,
            _ => unreachable!("AbiBenchMessage schema is a struct"),
        }
    })
}

fn abi_unknown_schema() -> &'static sacp_cbor_abi::Schema {
    ABI_UNKNOWN_SCHEMA.get_or_init(|| {
        Box::leak(Box::new(
            <AbiUnknownPreserve as sacp_cbor_abi::AbiType>::schema(),
        ))
    })
}

fn abi_unknown_runtime_schema() -> &'static sacp_cbor_abi::RuntimeFieldSetSchema<'static> {
    ABI_UNKNOWN_RUNTIME.get_or_init(|| {
        match sacp_cbor_abi::compile_runtime_schema(abi_unknown_schema())
            .expect("compile runtime ABI unknown schema")
        {
            sacp_cbor_abi::RuntimeSchema::Struct(schema) => schema,
            _ => unreachable!("AbiUnknownPreserve schema is a struct"),
        }
    })
}

fn abi_named_child_schema() -> &'static sacp_cbor_abi::Schema {
    ABI_NAMED_CHILD_SCHEMA.get_or_init(|| {
        Box::leak(Box::new(sacp_cbor_abi::Schema::new(
            "bench.NamedChild",
            1,
            sacp_cbor_abi::TypeDef::Primitive {
                ty: sacp_cbor_abi::TypeRef::U64,
            },
        )))
    })
}

fn abi_named_child_runtime_schema() -> &'static sacp_cbor_abi::RuntimeSchema<'static> {
    ABI_NAMED_CHILD_RUNTIME.get_or_init(|| {
        sacp_cbor_abi::compile_runtime_schema(abi_named_child_schema())
            .expect("compile named child runtime schema")
    })
}

fn abi_named_root_runtime_schema() -> &'static sacp_cbor_abi::RuntimeFieldSetSchema<'static> {
    ABI_NAMED_ROOT_RUNTIME.get_or_init(|| {
        let def = Box::leak(Box::new(sacp_cbor_abi::FieldSetDef {
            fields: vec![sacp_cbor_abi::FieldDef {
                id: 1,
                name: "child".to_string(),
                ty: sacp_cbor_abi::TypeRef::Named {
                    type_id: "bench.NamedChild".to_string(),
                    version: Some(1),
                },
                presence: sacp_cbor_abi::FieldPresence::Required,
            }],
            unknown_fields: sacp_cbor_abi::UnknownFieldPolicy::Reject,
        }));
        sacp_cbor_abi::RuntimeFieldSetSchema::compile(def)
            .expect("compile named root runtime schema")
    })
}

fn abi_named_workload() -> &'static AbiWorkload {
    ABI_NAMED_WORKLOAD.get_or_init(|| AbiWorkload {
        name: "named_u64",
        canon: sacp_cbor::CanonicalCbor::from_slice(
            &[0x82, 0x01, 0x18, 0x2a],
            DecodeLimits::for_bytes(4),
        )
        .expect("named workload is canonical"),
    })
}

fn abi_payload(len: usize) -> sacp_cbor::bytes::Bytes {
    let bytes = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
    sacp_cbor::bytes::Bytes::new(bytes)
}

fn abi_canon<T: sacp_cbor_abi::AbiEncode>(value: &T) -> sacp_cbor::CanonicalCbor {
    sacp_cbor_abi::encode_to_canonical(value).expect("encode ABI workload")
}

fn abi_message_workloads() -> &'static [AbiWorkload] {
    ABI_MESSAGE_WORKLOADS.get_or_init(|| {
        let fast = fast_mode_enabled();
        let specs: &[(&str, usize, usize, Option<usize>)] = if fast {
            &[
                ("abi_flat4", 0, 4, None),
                ("abi_blob64k", 64 * 1024, 8, Some(16)),
            ]
        } else {
            &[
                ("abi_flat4", 0, 4, None),
                ("abi_text4k", 0, 16, Some(4096)),
                ("abi_blob64k", 64 * 1024, 32, Some(64)),
            ]
        };
        specs
            .iter()
            .map(|(name, payload_len, values_len, note_len)| {
                let note = note_len.map(|len| "x".repeat(len));
                let value = AbiBenchMessage {
                    id: "msg-0000000000000001".to_string(),
                    kind: "tool_result".to_string(),
                    seq: 42,
                    route: "worker.dispatch".to_string(),
                    note,
                    payload: abi_payload(*payload_len),
                    values: (0..*values_len as u64).collect(),
                    unknown: sacp_cbor_abi::UnknownFields::empty(),
                };
                AbiWorkload {
                    name,
                    canon: abi_canon(&value),
                }
            })
            .collect()
    })
}

fn abi_flat16_workload() -> &'static AbiWorkload {
    ABI_FLAT16_WORKLOAD.get_or_init(|| AbiWorkload {
        name: "abi_flat16",
        canon: abi_canon(&AbiFlat16 {
            f01: 1,
            f02: 2,
            f03: 3,
            f04: 4,
            f05: "alpha".to_string(),
            f06: "beta".to_string(),
            f07: "gamma".to_string(),
            f08: "delta".to_string(),
            f09: Some("epsilon".to_string()),
            f10: Some("zeta".to_string()),
            f11: 11,
            f12: 12,
            f13: 13,
            f14: 14,
            f15: 15,
            f16: 16,
        }),
    })
}

fn abi_unknown_workloads() -> &'static [AbiWorkload] {
    ABI_UNKNOWN_WORKLOADS.get_or_init(|| {
        let specs: &[(&str, usize, usize)] = if fast_mode_enabled() {
            &[("unknown4_small", 4, 16), ("unknown16_4k", 16, 4096)]
        } else {
            &[
                ("unknown4_small", 4, 16),
                ("unknown16_256b", 16, 256),
                ("unknown64_4k", 64, 4096),
            ]
        };
        specs
            .iter()
            .map(|(name, count, payload_len)| {
                let mut fields = Vec::with_capacity(*count);
                for i in 0..*count {
                    let payload = sacp_cbor::encode_to_canonical(&abi_payload(*payload_len))
                        .expect("encode unknown payload");
                    fields.push(sacp_cbor_abi::UnknownField {
                        id: 10 + i as u32,
                        value: payload,
                    });
                }
                let value = AbiUnknownPreserve {
                    value: 7,
                    unknown: sacp_cbor_abi::UnknownFields::try_from_vec(fields)
                        .expect("unknown fields sorted"),
                };
                AbiWorkload {
                    name,
                    canon: abi_canon(&value),
                }
            })
            .collect()
    })
}

fn abi_command_workloads() -> &'static [AbiWorkload] {
    ABI_COMMAND_WORKLOADS.get_or_init(|| {
        let known = AbiBenchCommand::Route {
            id: "msg-0000000000000001".to_string(),
            seq: 42,
            payload: abi_payload(if fast_mode_enabled() { 1024 } else { 16 * 1024 }),
        };
        let unknown = AbiBenchCommand::Unknown(sacp_cbor_abi::UnknownVariant {
            id: 9,
            payload: sacp_cbor::encode_to_canonical(&abi_payload(4096))
                .expect("encode unknown variant payload"),
        });
        vec![
            AbiWorkload {
                name: "known_payload",
                canon: abi_canon(&known),
            },
            AbiWorkload {
                name: "unknown_payload",
                canon: abi_canon(&unknown),
            },
        ]
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

fn bench_abi_decode_owned(c: &mut Criterion) {
    let mut group = c.benchmark_group("abi_decode_owned");
    for data in abi_message_workloads() {
        let bytes = data.canon.as_bytes();
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_function(BenchmarkId::new("abi-owned", data.name), |b| {
            b.iter(|| {
                let out: AbiBenchMessage =
                    sacp_cbor_abi::decode(black_box(bytes), DecodeLimits::for_bytes(bytes.len()))
                        .unwrap();
                black_box(out);
            })
        });
    }

    let flat16 = abi_flat16_workload();
    let bytes = flat16.canon.as_bytes();
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_function(BenchmarkId::new("abi-owned", flat16.name), |b| {
        b.iter(|| {
            let out: AbiFlat16 =
                sacp_cbor_abi::decode(black_box(bytes), DecodeLimits::for_bytes(bytes.len()))
                    .unwrap();
            black_box(out);
        })
    });
    group.finish();
}

fn bench_abi_view_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("abi_view_access");
    let runtime_schema = abi_message_runtime_schema();
    let runtime_mode = runtime_inline_mode();
    let runtime_config = runtime_config();
    const ROUTING_IDS: &[u32] = &[1, 2, 3, 4];

    for data in abi_message_workloads() {
        let bytes = data.canon.as_bytes();
        group.throughput(Throughput::Bytes(bytes.len() as u64));

        group.bench_function(BenchmarkId::new("abi-view", data.name), |b| {
            b.iter(|| {
                let view =
                    AbiBenchMessageView::from_canonical(black_box(data.canon.as_canonical_ref()))
                        .unwrap();
                black_box(view.id().unwrap());
                black_box(view.kind().unwrap());
                black_box(view.seq().unwrap());
                black_box(view.route().unwrap());
            })
        });

        group.bench_function(BenchmarkId::new("abi-runtime-view", data.name), |b| {
            b.iter(|| {
                let view = runtime_schema
                    .view_value(black_box(data.canon.as_canonical_ref()).root())
                    .unwrap();
                let mut out = [None; 4];
                view.get_many_raw_sorted_into(ROUTING_IDS, &mut out)
                    .unwrap();
                black_box(out[0].unwrap().text().unwrap());
                black_box(out[1].unwrap().text().unwrap());
                black_box(out[2].unwrap().integer().unwrap().as_u128().unwrap());
                black_box(out[3].unwrap().text().unwrap());
            })
        });

        group.bench_function(
            BenchmarkId::new("abi-runtime-validate-inline", data.name),
            |b| {
                b.iter(|| {
                    let view = runtime_schema
                        .validate_value(
                            black_box(data.canon.as_canonical_ref()).root(),
                            runtime_mode,
                        )
                        .unwrap();
                    let mut out = [None; 4];
                    view.get_many_raw_sorted_into(ROUTING_IDS, &mut out)
                        .unwrap();
                    black_box(out[0].unwrap().text().unwrap());
                    black_box(out[1].unwrap().text().unwrap());
                    black_box(out[2].unwrap().integer().unwrap().as_u128().unwrap());
                    black_box(out[3].unwrap().text().unwrap());
                })
            },
        );

        group.bench_function(
            BenchmarkId::new("abi-runtime-validate-inline-noop-hook-concrete", data.name),
            |b| {
                b.iter(|| {
                    let mut hook = sacp_cbor_abi::NoRuntimeValidationHooks;
                    let view = runtime_schema
                        .validate_value_with_hooks(
                            black_box(data.canon.as_canonical_ref()).root(),
                            runtime_mode,
                            runtime_config,
                            &mut hook,
                        )
                        .unwrap();
                    let mut out = [None; 4];
                    view.get_many_raw_sorted_into(ROUTING_IDS, &mut out)
                        .unwrap();
                    black_box(out[0].unwrap().text().unwrap());
                    black_box(out[1].unwrap().text().unwrap());
                    black_box(out[2].unwrap().integer().unwrap().as_u128().unwrap());
                    black_box(out[3].unwrap().text().unwrap());
                })
            },
        );

        group.bench_function(
            BenchmarkId::new("abi-runtime-validate-inline-field-hook-concrete", data.name),
            |b| {
                b.iter(|| {
                    let mut hook = AbiRoutingFieldHook;
                    let view = runtime_schema
                        .validate_value_with_hooks(
                            black_box(data.canon.as_canonical_ref()).root(),
                            runtime_mode,
                            runtime_config,
                            &mut hook,
                        )
                        .unwrap();
                    let mut out = [None; 4];
                    view.get_many_raw_sorted_into(ROUTING_IDS, &mut out)
                        .unwrap();
                    black_box(out[0].unwrap().text().unwrap());
                    black_box(out[1].unwrap().text().unwrap());
                    black_box(out[2].unwrap().integer().unwrap().as_u128().unwrap());
                    black_box(out[3].unwrap().text().unwrap());
                })
            },
        );

        group.bench_function(
            BenchmarkId::new("abi-runtime-vec-sorted-unique-hook", data.name),
            |b| {
                b.iter(|| {
                    let mut hook = AbiVecSortedUniqueHook::default();
                    let view = runtime_schema
                        .validate_value_with_hooks(
                            black_box(data.canon.as_canonical_ref()).root(),
                            runtime_mode,
                            runtime_config,
                            &mut hook,
                        )
                        .unwrap();
                    let mut out = [None; 4];
                    view.get_many_raw_sorted_into(ROUTING_IDS, &mut out)
                        .unwrap();
                    black_box(out[0].unwrap().text().unwrap());
                    black_box(out[1].unwrap().text().unwrap());
                    black_box(out[2].unwrap().integer().unwrap().as_u128().unwrap());
                    black_box(out[3].unwrap().text().unwrap());
                })
            },
        );

        group.bench_function(BenchmarkId::new("abi-view-checked", data.name), |b| {
            b.iter(|| {
                let canon = sacp_cbor::validate_canonical(
                    black_box(bytes),
                    DecodeLimits::for_bytes(bytes.len()),
                )
                .unwrap();
                let view = AbiBenchMessageView::from_canonical(canon).unwrap();
                black_box(view.id().unwrap());
                black_box(view.kind().unwrap());
                black_box(view.seq().unwrap());
                black_box(view.route().unwrap());
            })
        });

        group.bench_function(
            BenchmarkId::new("abi-runtime-view-checked", data.name),
            |b| {
                b.iter(|| {
                    let canon = sacp_cbor::validate_canonical(
                        black_box(bytes),
                        DecodeLimits::for_bytes(bytes.len()),
                    )
                    .unwrap();
                    let view = runtime_schema.view_value(canon.root()).unwrap();
                    let mut out = [None; 4];
                    view.get_many_raw_sorted_into(ROUTING_IDS, &mut out)
                        .unwrap();
                    black_box(out[0].unwrap().text().unwrap());
                    black_box(out[1].unwrap().text().unwrap());
                    black_box(out[2].unwrap().integer().unwrap().as_u128().unwrap());
                    black_box(out[3].unwrap().text().unwrap());
                })
            },
        );

        group.bench_function(
            BenchmarkId::new("abi-runtime-validate-inline-checked", data.name),
            |b| {
                b.iter(|| {
                    let canon = sacp_cbor::validate_canonical(
                        black_box(bytes),
                        DecodeLimits::for_bytes(bytes.len()),
                    )
                    .unwrap();
                    let view = runtime_schema
                        .validate_value(canon.root(), runtime_mode)
                        .unwrap();
                    let mut out = [None; 4];
                    view.get_many_raw_sorted_into(ROUTING_IDS, &mut out)
                        .unwrap();
                    black_box(out[0].unwrap().text().unwrap());
                    black_box(out[1].unwrap().text().unwrap());
                    black_box(out[2].unwrap().integer().unwrap().as_u128().unwrap());
                    black_box(out[3].unwrap().text().unwrap());
                })
            },
        );

        group.bench_function(
            BenchmarkId::new("abi-view-array-get-last", data.name),
            |b| {
                b.iter(|| {
                    let view = AbiBenchMessageView::from_canonical(black_box(
                        data.canon.as_canonical_ref(),
                    ))
                    .unwrap();
                    let values = view.values().unwrap();
                    let len = values.len().unwrap();
                    black_box(values.get(len - 1).unwrap());
                })
            },
        );

        group.bench_function(BenchmarkId::new("abi-owned-trusted", data.name), |b| {
            b.iter(|| {
                let out: AbiBenchMessage =
                    sacp_cbor_abi::decode_canonical(black_box(data.canon.as_canonical_ref()))
                        .unwrap();
                black_box((&out.id, &out.kind, out.seq, &out.route));
            })
        });

        group.bench_function(BenchmarkId::new("abi-owned", data.name), |b| {
            b.iter(|| {
                let out: AbiBenchMessage =
                    sacp_cbor_abi::decode(black_box(bytes), DecodeLimits::for_bytes(bytes.len()))
                        .unwrap();
                black_box((&out.id, &out.kind, out.seq, &out.route));
            })
        });
    }
    group.finish();
}

fn bench_abi_unknown_preserve(c: &mut Criterion) {
    let mut group = c.benchmark_group("abi_unknown_preserve");
    let runtime_schema = abi_unknown_runtime_schema();
    for data in abi_unknown_workloads() {
        let bytes = data.canon.as_bytes();
        group.throughput(Throughput::Bytes(bytes.len() as u64));

        group.bench_function(BenchmarkId::new("ignore", data.name), |b| {
            b.iter(|| {
                let out: AbiUnknownIgnore =
                    sacp_cbor_abi::decode(black_box(bytes), DecodeLimits::for_bytes(bytes.len()))
                        .unwrap();
                black_box(out.value);
            })
        });

        group.bench_function(BenchmarkId::new("preserve-owned", data.name), |b| {
            b.iter(|| {
                let out: AbiUnknownPreserve =
                    sacp_cbor_abi::decode(black_box(bytes), DecodeLimits::for_bytes(bytes.len()))
                        .unwrap();
                black_box(out.unknown.len());
            })
        });

        group.bench_function(BenchmarkId::new("preserve-owned-trusted", data.name), |b| {
            b.iter(|| {
                let out: AbiUnknownPreserve =
                    sacp_cbor_abi::decode_canonical(black_box(data.canon.as_canonical_ref()))
                        .unwrap();
                black_box(out.unknown.len());
            })
        });

        group.bench_function(BenchmarkId::new("preserve-view", data.name), |b| {
            b.iter(|| {
                let view = AbiUnknownPreserveView::from_canonical(black_box(
                    data.canon.as_canonical_ref(),
                ))
                .unwrap();
                let count = view
                    .unknown_fields()
                    .unwrap()
                    .map(|field| field.unwrap().value.byte_len())
                    .sum::<usize>();
                black_box(count);
            })
        });

        group.bench_function(BenchmarkId::new("preserve-view-checked", data.name), |b| {
            b.iter(|| {
                let canon = sacp_cbor::validate_canonical(
                    black_box(bytes),
                    DecodeLimits::for_bytes(bytes.len()),
                )
                .unwrap();
                let view = AbiUnknownPreserveView::from_canonical(canon).unwrap();
                let count = view
                    .unknown_fields()
                    .unwrap()
                    .map(|field| field.unwrap().value.byte_len())
                    .sum::<usize>();
                black_box(count);
            })
        });

        group.bench_function(BenchmarkId::new("runtime-preserve-view", data.name), |b| {
            b.iter(|| {
                let view = runtime_schema
                    .view_value(black_box(data.canon.as_canonical_ref()).root())
                    .unwrap();
                let count = view
                    .unknown_fields()
                    .unwrap()
                    .map(|field| field.unwrap().value.byte_len())
                    .sum::<usize>();
                black_box(count);
            })
        });

        group.bench_function(
            BenchmarkId::new("runtime-preserve-view-checked", data.name),
            |b| {
                b.iter(|| {
                    let canon = sacp_cbor::validate_canonical(
                        black_box(bytes),
                        DecodeLimits::for_bytes(bytes.len()),
                    )
                    .unwrap();
                    let view = runtime_schema.view_value(canon.root()).unwrap();
                    let count = view
                        .unknown_fields()
                        .unwrap()
                        .map(|field| field.unwrap().value.byte_len())
                        .sum::<usize>();
                    black_box(count);
                })
            },
        );
    }
    group.finish();
}

fn bench_abi_runtime_compile(c: &mut Criterion) {
    let mut group = c.benchmark_group("abi_runtime_compile");

    if let sacp_cbor_abi::TypeDef::Struct(def) = &abi_message_schema().root {
        group.bench_function(BenchmarkId::new("runtime-compile", "abi_message"), |b| {
            b.iter(|| {
                let schema = sacp_cbor_abi::RuntimeFieldSetSchema::compile(black_box(def)).unwrap();
                black_box(schema);
            })
        });
    }

    if let sacp_cbor_abi::TypeDef::Struct(def) = &abi_unknown_schema().root {
        group.bench_function(
            BenchmarkId::new("runtime-compile", "unknown_preserve"),
            |b| {
                b.iter(|| {
                    let schema =
                        sacp_cbor_abi::RuntimeFieldSetSchema::compile(black_box(def)).unwrap();
                    black_box(schema);
                })
            },
        );
    }

    group.finish();
}

fn bench_abi_runtime_named(c: &mut Criterion) {
    let mut group = c.benchmark_group("abi_runtime_named");
    let runtime_schema = abi_named_root_runtime_schema();
    let data = abi_named_workload();
    let bytes = data.canon.as_bytes();
    let registry = AbiBenchRegistry {
        schema: abi_named_child_runtime_schema(),
    };
    let resolve_mode = sacp_cbor_abi::RuntimeResolveNamed::new(&registry);
    let runtime_config = runtime_config();
    group.throughput(Throughput::Bytes(bytes.len() as u64));

    group.bench_function(
        BenchmarkId::new("abi-runtime-named-registry-compiled", data.name),
        |b| {
            b.iter(|| {
                let view = runtime_schema
                    .validate_value(
                        black_box(data.canon.as_canonical_ref()).root(),
                        resolve_mode,
                    )
                    .unwrap();
                black_box(view.raw_fields());
            })
        },
    );

    group.bench_function(
        BenchmarkId::new("abi-runtime-named-hook-accepted", data.name),
        |b| {
            b.iter(|| {
                let mut hook = AbiAcceptNamedHook;
                let view = runtime_schema
                    .validate_value_with_hooks(
                        black_box(data.canon.as_canonical_ref()).root(),
                        sacp_cbor_abi::RuntimeRejectNamed,
                        runtime_config,
                        &mut hook,
                    )
                    .unwrap();
                black_box(view.raw_fields());
            })
        },
    );

    group.finish();
}

fn bench_abi_enum_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("abi_enum_access");
    for data in abi_command_workloads() {
        let bytes = data.canon.as_bytes();
        group.throughput(Throughput::Bytes(bytes.len() as u64));

        group.bench_function(BenchmarkId::new("view", data.name), |b| {
            b.iter(|| {
                let view =
                    AbiBenchCommandView::from_canonical(black_box(data.canon.as_canonical_ref()))
                        .unwrap();
                black_box(view.variant_id());
                if let Some(route) = view.as_route().unwrap() {
                    black_box(route.id().unwrap());
                    black_box(route.seq().unwrap());
                }
                if let Some(unknown) = view.unknown_variant() {
                    black_box(unknown.payload.byte_len());
                }
            })
        });

        group.bench_function(BenchmarkId::new("view-checked", data.name), |b| {
            b.iter(|| {
                let canon = sacp_cbor::validate_canonical(
                    black_box(bytes),
                    DecodeLimits::for_bytes(bytes.len()),
                )
                .unwrap();
                let view = AbiBenchCommandView::from_canonical(canon).unwrap();
                black_box(view.variant_id());
                if let Some(route) = view.as_route().unwrap() {
                    black_box(route.id().unwrap());
                    black_box(route.seq().unwrap());
                }
                if let Some(unknown) = view.unknown_variant() {
                    black_box(unknown.payload.byte_len());
                }
            })
        });

        group.bench_function(BenchmarkId::new("view-repeat", data.name), |b| {
            b.iter(|| {
                let view =
                    AbiBenchCommandView::from_canonical(black_box(data.canon.as_canonical_ref()))
                        .unwrap();
                if let Some(route) = view.as_route().unwrap() {
                    black_box(route.id().unwrap());
                }
                if let Some(route) = view.as_route().unwrap() {
                    black_box(route.seq().unwrap());
                }
                if let Some(unknown) = view.unknown_variant() {
                    black_box(unknown.payload.byte_len());
                }
            })
        });

        group.bench_function(BenchmarkId::new("owned-trusted", data.name), |b| {
            b.iter(|| {
                let out: AbiBenchCommand =
                    sacp_cbor_abi::decode_canonical(black_box(data.canon.as_canonical_ref()))
                        .unwrap();
                match &out {
                    AbiBenchCommand::Route { id, seq, .. } => {
                        black_box(id);
                        black_box(seq);
                    }
                    AbiBenchCommand::Ack => {
                        black_box(0u8);
                    }
                    AbiBenchCommand::Unknown(unknown) => {
                        black_box(unknown.payload.as_bytes().len());
                    }
                }
            })
        });

        group.bench_function(BenchmarkId::new("owned", data.name), |b| {
            b.iter(|| {
                let out: AbiBenchCommand =
                    sacp_cbor_abi::decode(black_box(bytes), DecodeLimits::for_bytes(bytes.len()))
                        .unwrap();
                match &out {
                    AbiBenchCommand::Route { id, seq, .. } => {
                        black_box(id);
                        black_box(seq);
                    }
                    AbiBenchCommand::Ack => {
                        black_box(0u8);
                    }
                    AbiBenchCommand::Unknown(unknown) => {
                        black_box(unknown.id);
                        black_box(unknown.payload.as_bytes().len());
                    }
                };
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
        bench_abi_decode_owned,
        bench_abi_view_access,
        bench_abi_unknown_preserve,
        bench_abi_enum_access,
        bench_abi_runtime_compile,
        bench_abi_runtime_named,
        bench_patch,
        bench_appendix_a,
        bench_micro_query,
        bench_micro_edit
}
criterion_main!(benches);
