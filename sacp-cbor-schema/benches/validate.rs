//! Validation throughput benchmarks.
//!
//! For each dataset, four measurements bracket the cost structure:
//!
//! - `core`: `validate_canonical_with` alone — the grammar floor; no schema
//!   check can be cheaper than this.
//! - `fused`: `RecordSchema::validate` — grammar + schema in one traversal.
//! - `two-pass`: `validate_canonical_with` then `RecordSchema::check` — the
//!   composition the fused pass replaces.
//! - `check`: `RecordSchema::check` alone over a pre-validated witness — the
//!   trusted re-check cost (read-side usage).
//!
//! The `fused/core` ratio is the schema tax on the write path; `fused` versus
//! `two-pass` is the fusion win. Run with:
//! `cargo bench -p sacp-cbor-schema`

use std::hint::black_box;
use std::time::Instant;

use sacp_cbor::{validate_canonical_with, DecodeLimits, Encoder, ValidationOptions};
use sacp_cbor_schema::{
    Constraint, CountUnit, Coupling, EnumMember, FieldDef, FieldType, Int, RecordDef, RecordSchema,
    UnionAlt,
};

fn field(key: &str, ty: FieldType, required: bool, constraints: Vec<Constraint>) -> FieldDef {
    FieldDef {
        key: key.to_owned(),
        ty,
        required,
        constraints,
    }
}

struct Dataset {
    name: &'static str,
    schema: RecordSchema,
    bytes: Vec<u8>,
}

impl Dataset {
    fn new(name: &'static str, def: &RecordDef, bytes: Vec<u8>) -> Self {
        let schema = RecordSchema::compile(def).expect("compile");
        // Every dataset must be valid under its schema.
        schema
            .validate(
                &bytes,
                DecodeLimits::for_bytes(bytes.len()),
                ValidationOptions::new(),
            )
            .expect("dataset validates");
        Self {
            name,
            schema,
            bytes,
        }
    }
}

/// Twelve mixed scalar fields, the shape of a typical row record.
fn flat_scalars(constrained: bool) -> Dataset {
    let c_range = || {
        if constrained {
            vec![Constraint::Range {
                min: Some(Int::from(0_i64)),
                max: Some(Int::from(1_000_000_i64)),
            }]
        } else {
            vec![]
        }
    };
    let c_text = || {
        if constrained {
            vec![Constraint::Count {
                unit: CountUnit::Octets,
                min: Some(1),
                max: Some(64),
            }]
        } else {
            vec![]
        }
    };
    let c_enum = || {
        if constrained {
            vec![Constraint::Enum(vec![
                EnumMember::Text("active".to_owned()),
                EnumMember::Text("closed".to_owned()),
                EnumMember::Text("open".to_owned()),
            ])]
        } else {
            vec![]
        }
    };
    let def = RecordDef {
        fields: vec![
            field("amount", FieldType::Int, true, c_range()),
            field("category", FieldType::Text, true, c_text()),
            field("count", FieldType::Int, true, c_range()),
            field("digest", FieldType::Bytes, true, vec![]),
            field("flag", FieldType::Bool, true, vec![]),
            field("id", FieldType::Int, true, c_range()),
            field("label", FieldType::Text, false, c_text()),
            field("name", FieldType::Text, true, c_text()),
            field("note", FieldType::Text, false, vec![]),
            field("seq", FieldType::Int, true, c_range()),
            field("state", FieldType::Text, true, c_enum()),
            field("total", FieldType::Int, true, c_range()),
        ],
        couplings: vec![],
    };
    let mut enc = Encoder::new();
    // Canonical map order: shorter key first, then bytes.
    enc.map(12, |m| {
        m.entry("id", |e| e.int(902_213))?;
        m.entry("seq", |e| e.int(88))?;
        m.entry("flag", |e| e.bool(true))?;
        m.entry("name", |e| e.text("settlement batch"))?;
        m.entry("note", |e| e.text("carried forward from prior period"))?;
        m.entry("count", |e| e.int(17))?;
        m.entry("label", |e| e.text("west-2"))?;
        m.entry("state", |e| e.text("open"))?;
        m.entry("total", |e| e.int(998_001))?;
        m.entry("amount", |e| e.int(431_557))?;
        m.entry("digest", |e| e.bytes(&[0xAB; 32]))?;
        m.entry("category", |e| e.text("payments"))
    })
    .expect("encode");
    Dataset::new(
        if constrained {
            "flat_scalars_constrained"
        } else {
            "flat_scalars_plain"
        },
        &def,
        enc.finish().expect("finish").into_bytes(),
    )
}

/// One large text field: UTF-8 validation bound.
fn text_heavy(name: &'static str, len: usize) -> Dataset {
    let def = RecordDef {
        fields: vec![
            field("body", FieldType::Text, true, vec![]),
            field("id", FieldType::Int, true, vec![]),
        ],
        couplings: vec![],
    };
    let body = "the quick brown fox jumps over the lazy dog — ωφθ. "
        .repeat(len / 52 + 1)
        .chars()
        .take(len)
        .collect::<String>();
    let mut enc = Encoder::new();
    enc.map(2, |m| {
        m.entry("id", |e| e.int(7))?;
        m.entry("body", |e| e.text(&body))
    })
    .expect("encode");
    Dataset::new(name, &def, enc.finish().expect("finish").into_bytes())
}

/// A long homogeneous integer array.
fn array_int_1000() -> Dataset {
    let def = RecordDef {
        fields: vec![field(
            "values",
            FieldType::Array(Box::new(FieldType::Int)),
            true,
            vec![],
        )],
        couplings: vec![],
    };
    let mut enc = Encoder::new();
    enc.map(1, |m| {
        m.entry("values", |e| {
            e.array(1000, |a| {
                for i in 0..1000_i64 {
                    a.int(i * 37)?;
                }
                Ok(())
            })
        })
    })
    .expect("encode");
    Dataset::new(
        "array_int_1000",
        &def,
        enc.finish().expect("finish").into_bytes(),
    )
}

/// A sorted set of 32-byte references (content-address shape).
fn set_ref32_100() -> Dataset {
    let def = RecordDef {
        fields: vec![field(
            "refs",
            FieldType::Set(Box::new(FieldType::Bytes)),
            true,
            vec![Constraint::Count {
                unit: CountUnit::Elements,
                min: None,
                max: Some(128),
            }],
        )],
        couplings: vec![],
    };
    let mut refs: Vec<[u8; 32]> = (0..100_u32)
        .map(|i| {
            let mut r = [0u8; 32];
            r[..4].copy_from_slice(&i.to_be_bytes());
            r[4..8].copy_from_slice(&(i.wrapping_mul(0x9E37_79B9)).to_be_bytes());
            r
        })
        .collect();
    refs.sort_unstable();
    let mut enc = Encoder::new();
    enc.map(1, |m| {
        m.entry("refs", |e| {
            e.array(100, |a| {
                for r in &refs {
                    a.bytes(r)?;
                }
                Ok(())
            })
        })
    })
    .expect("encode");
    Dataset::new(
        "set_ref32_100",
        &def,
        enc.finish().expect("finish").into_bytes(),
    )
}

/// A list of coded unions with mixed alternatives.
fn union_list_200() -> Dataset {
    let def = RecordDef {
        fields: vec![field(
            "events",
            FieldType::Array(Box::new(FieldType::Union(vec![
                UnionAlt {
                    code: 0,
                    payload: None,
                },
                UnionAlt {
                    code: 1,
                    payload: Some(FieldType::Int),
                },
                UnionAlt {
                    code: 2,
                    payload: Some(FieldType::Text),
                },
            ]))),
            true,
            vec![],
        )],
        couplings: vec![],
    };
    let mut enc = Encoder::new();
    enc.map(1, |m| {
        m.entry("events", |e| {
            e.array(200, |a| {
                for i in 0..200_i64 {
                    match i % 3 {
                        0 => a.array(1, |u| u.int(0))?,
                        1 => a.array(2, |u| {
                            u.int(1)?;
                            u.int(i)
                        })?,
                        _ => a.array(2, |u| {
                            u.int(2)?;
                            u.text("event payload")
                        })?,
                    }
                }
                Ok(())
            })
        })
    })
    .expect("encode");
    Dataset::new(
        "union_list_200",
        &def,
        enc.finish().expect("finish").into_bytes(),
    )
}

/// Nested records four levels deep, eight leaves per level.
fn nested_depth4() -> Dataset {
    fn level(depth: usize) -> RecordDef {
        let mut fields = vec![
            field("k0", FieldType::Int, true, vec![]),
            field("k1", FieldType::Text, true, vec![]),
        ];
        if depth > 0 {
            fields.push(field(
                "next",
                FieldType::Record(Box::new(level(depth - 1))),
                true,
                vec![],
            ));
        }
        RecordDef {
            fields,
            couplings: vec![],
        }
    }
    fn encode_level(e: &mut Encoder, depth: usize) -> Result<(), sacp_cbor::CborError> {
        let n = if depth > 0 { 3 } else { 2 };
        e.map(n, |m| {
            m.entry("k0", |e| e.int(depth as i64))?;
            m.entry("k1", |e| e.text("layer value"))?;
            if depth > 0 {
                m.entry("next", |e| encode_level(e, depth - 1))?;
            }
            Ok(())
        })
    }
    let def = level(4);
    let mut enc = Encoder::new();
    encode_level(&mut enc, 4).expect("encode");
    Dataset::new(
        "nested_depth4",
        &def,
        enc.finish().expect("finish").into_bytes(),
    )
}

/// Sixteen optional fields under eight couplings, all present.
fn couplings_16() -> Dataset {
    let keys: Vec<String> = (0..16).map(|i| format!("f{i:02}")).collect();
    let def = RecordDef {
        fields: keys
            .iter()
            .map(|k| field(k, FieldType::Int, false, vec![]))
            .collect(),
        couplings: (0..8)
            .map(|i| Coupling::Together(vec![keys[2 * i].clone(), keys[2 * i + 1].clone()]))
            .collect(),
    };
    let mut enc = Encoder::new();
    enc.map(16, |m| {
        for (i, k) in keys.iter().enumerate() {
            m.entry(k, |e| e.int(i as i64))?;
        }
        Ok(())
    })
    .expect("encode");
    Dataset::new(
        "couplings_16",
        &def,
        enc.finish().expect("finish").into_bytes(),
    )
}

/// Minimum ns/op over `SAMPLES` batches, each batch sized to ~`BATCH_MS`.
///
/// The minimum is the robust statistic for a CPU-bound microbenchmark on a
/// noisy host: interference only ever inflates a sample.
fn measure<F: FnMut()>(mut f: F) -> f64 {
    const BATCH_MS: u128 = 12;
    const SAMPLES: usize = 15;

    // Warm up and size the batch.
    let mut iters: u64 = 8;
    loop {
        let start = Instant::now();
        for _ in 0..iters {
            f();
        }
        let elapsed = start.elapsed().as_millis();
        if elapsed >= BATCH_MS {
            break;
        }
        iters = iters.saturating_mul(4).max(8);
    }

    let mut samples: Vec<f64> = (0..SAMPLES)
        .map(|_| {
            let start = Instant::now();
            for _ in 0..iters {
                f();
            }
            start.elapsed().as_nanos() as f64 / iters as f64
        })
        .collect();
    samples.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    samples[0]
}

fn mib_per_s(bytes: usize, ns_per_op: f64) -> f64 {
    (bytes as f64) / ns_per_op * 1e9 / (1024.0 * 1024.0)
}

fn main() {
    let datasets = vec![
        flat_scalars(false),
        flat_scalars(true),
        text_heavy("text_1k", 1024),
        text_heavy("text_8k", 8192),
        array_int_1000(),
        set_ref32_100(),
        union_list_200(),
        nested_depth4(),
        couplings_16(),
    ];

    println!(
        "{:<26} {:>7} {:>10} {:>10} {:>10} {:>10} {:>7} {:>9}",
        "dataset", "bytes", "core", "fused", "two-pass", "check", "tax", "fused"
    );
    println!(
        "{:<26} {:>7} {:>10} {:>10} {:>10} {:>10} {:>7} {:>9}",
        "", "", "ns/op", "ns/op", "ns/op", "ns/op", "x core", "MiB/s"
    );

    for d in &datasets {
        let bytes = &d.bytes;
        let limits = DecodeLimits::for_bytes(bytes.len());
        let options = ValidationOptions::new();
        let witness = validate_canonical_with(bytes, limits, options).expect("canonical");

        let core = measure(|| {
            black_box(validate_canonical_with(black_box(bytes), limits, options)).expect("core");
        });
        let fused = measure(|| {
            black_box(d.schema.validate(black_box(bytes), limits, options)).expect("fused");
        });
        let two_pass = measure(|| {
            let w =
                validate_canonical_with(black_box(bytes), limits, options).expect("two-pass core");
            black_box(d.schema.check(w)).expect("two-pass check");
        });
        let check = measure(|| {
            black_box(d.schema.check(black_box(witness))).expect("check");
        });

        println!(
            "{:<26} {:>7} {:>10.0} {:>10.0} {:>10.0} {:>10.0} {:>6.2}x {:>9.1}",
            d.name,
            bytes.len(),
            core,
            fused,
            two_pass,
            check,
            fused / core,
            mib_per_s(bytes.len(), fused)
        );
    }
}
