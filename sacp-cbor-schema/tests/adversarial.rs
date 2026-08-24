//! Hand-constructed edge vectors targeting boundary conditions.

use sacp_cbor::{DecodeLimits, Encoder, ValidationOptions};
use sacp_cbor_schema::{
    Constraint, ConstraintFault, Coupling, EnumMember, Fault, FieldType, Int, RecordDef,
    RecordSchema, ShapeFault, UnionAlt,
};

mod common;
use common::{field, limits, one_field};

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct TrackingAllocator;
thread_local! { static TRACK: Cell<bool> = const { Cell::new(false) }; static ALLOCS: Cell<usize> = const { Cell::new(0) }; }
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        TRACK.with(|on| {
            if on.get() {
                ALLOCS.with(|count| count.set(count.get() + 1));
            }
        });
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn one_int_field(constraints: Vec<Constraint>) -> RecordSchema {
    RecordSchema::compile(
        &RecordDef {
            fields: vec![field("v", FieldType::Int, true, constraints)],
            couplings: vec![],
        },
        limits(),
    )
    .expect("compile")
}

fn validate(schema: &RecordSchema, bytes: &[u8]) -> Result<(), Fault> {
    schema
        .validate(
            bytes,
            DecodeLimits::for_bytes(bytes.len()),
            ValidationOptions::new(),
        )
        .map(|_| ())
        .map_err(|err| err.fault)
}

#[test]
fn dynamic_workspace_supports_more_than_64_fields_and_reuses_without_allocation() {
    let fields = (0..130)
        .map(|index| field(&format!("k{index:03}"), FieldType::Int, true, vec![]))
        .collect();
    let schema = RecordSchema::compile(
        &RecordDef {
            fields,
            couplings: vec![],
        },
        sacp_cbor_schema::SchemaCompileLimits {
            max_fields_per_record: 130,
            ..limits()
        },
    )
    .expect("dynamic field limit permits 130 fields");
    let mut encoder = Encoder::new();
    encoder
        .map(130, |map| {
            for index in 0..130 {
                map.entry(&format!("k{index:03}"), |value| {
                    value.int_u128(index as u128)
                })?;
            }
            Ok(())
        })
        .unwrap();
    let bytes = encoder.finish().unwrap();
    let mut workspace = sacp_cbor_schema::ValidationWorkspace::new();
    workspace.prepare(&schema).unwrap();
    schema
        .validate_with_workspace(
            &bytes,
            DecodeLimits::for_bytes(bytes.len()),
            ValidationOptions::new(),
            &mut workspace,
        )
        .unwrap();
    ALLOCS.with(|count| count.set(0));
    TRACK.with(|on| on.set(true));
    let result = schema.validate_with_workspace(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        ValidationOptions::new(),
        &mut workspace,
    );
    TRACK.with(|on| on.set(false));
    result.unwrap();
    assert_eq!(
        ALLOCS.with(Cell::get),
        0,
        "prepared validation workspace performs no allocation on success"
    );
}

#[test]
fn validation_rejects_each_workspace_capacity_minus_one_before_decoding() {
    let schema = RecordSchema::compile(
        &RecordDef {
            fields: (0..65)
                .map(|index| field(&format!("k{index:03}"), FieldType::Int, false, vec![]))
                .collect(),
            couplings: vec![],
        },
        sacp_cbor_schema::SchemaCompileLimits {
            max_fields_per_record: 65,
            ..limits()
        },
    )
    .unwrap();
    let (presence_words, path_depth, frame_capacity) = schema.workspace_requirements();
    let container_capacity = schema.workspace_container_capacity();
    for capacities in [
        (
            presence_words - 1,
            path_depth,
            frame_capacity,
            container_capacity,
        ),
        (
            presence_words,
            path_depth - 1,
            frame_capacity,
            container_capacity,
        ),
        (
            presence_words,
            path_depth,
            frame_capacity - 1,
            container_capacity,
        ),
        (
            presence_words,
            path_depth,
            frame_capacity,
            container_capacity - 1,
        ),
    ] {
        let mut workspace = sacp_cbor_schema::ValidationWorkspace::new();
        workspace
            .prepare_capacity(capacities.0, capacities.1, capacities.2, capacities.3)
            .unwrap();
        let error = schema
            .validate_with_workspace(
                &[0xa0],
                DecodeLimits::for_bytes(1),
                ValidationOptions::new(),
                &mut workspace,
            )
            .unwrap_err();
        assert_eq!(
            error.fault,
            Fault::WorkspaceTooSmall,
            "workspace capacity rejection rule"
        );
        assert_eq!(error.offset, 0);
        assert!(error.path.is_empty());
        assert!(error.path_complete);
    }
}

#[test]
fn validation_frame_and_container_requirements_are_exact_for_scalar_payload_union() {
    let schema = RecordSchema::compile(
        &RecordDef {
            fields: vec![field(
                "u",
                FieldType::Union(vec![UnionAlt {
                    code: 1,
                    payload: Some(FieldType::Int),
                }]),
                false,
                vec![],
            )],
            couplings: vec![],
        },
        limits(),
    )
    .unwrap();
    let (_, _, frames) = schema.workspace_requirements();
    assert_eq!(frames, 3, "exact validation frame requirement rule");
    assert_eq!(
        schema.workspace_container_capacity(),
        2,
        "exact open-container requirement rule"
    );

    let bytes = [0xa1, 0x61, b'u', 0x82, 0x01, 0x00];
    let mut workspace = sacp_cbor_schema::ValidationWorkspace::new();
    workspace.prepare(&schema).unwrap();
    schema
        .validate_with_workspace(
            &bytes,
            DecodeLimits::for_bytes(bytes.len()),
            ValidationOptions::new(),
            &mut workspace,
        )
        .expect("the exact frame capacity admits the worst scalar-union value");
}

#[test]
fn any_uses_only_caller_prepared_depth_storage_beyond_inline_skip_depth() {
    let schema = RecordSchema::compile(
        &RecordDef {
            fields: vec![field("z", FieldType::Any, true, vec![])],
            couplings: vec![],
        },
        limits(),
    )
    .unwrap();
    let mut bytes = vec![0xa1, 0x61, b'z'];
    bytes.extend(core::iter::repeat_n(0x81, 64));
    bytes.push(0xf6);
    let decode_limits = DecodeLimits::for_bytes(bytes.len());

    let mut underprepared = sacp_cbor_schema::ValidationWorkspace::new();
    underprepared.prepare(&schema).unwrap();
    assert_eq!(
        schema
            .validate_with_workspace(
                &bytes,
                decode_limits,
                ValidationOptions::new(),
                &mut underprepared,
            )
            .unwrap_err()
            .fault,
        Fault::WorkspaceTooSmall,
        "Any explicit traversal-depth workspace rule"
    );

    let mut workspace = sacp_cbor_schema::ValidationWorkspace::new();
    workspace
        .prepare_for_limits(&schema, decode_limits)
        .unwrap();
    ALLOCS.with(|count| count.set(0));
    TRACK.with(|on| on.set(true));
    let result = schema.validate_with_workspace(
        &bytes,
        decode_limits,
        ValidationOptions::new(),
        &mut workspace,
    );
    TRACK.with(|on| on.set(false));
    result.unwrap();
    assert_eq!(
        ALLOCS.with(Cell::get),
        0,
        "prepared Any traversal performs no hidden depth-spill allocation"
    );
}

#[test]
fn validation_workspace_presence_is_exact_max_live_not_all_records_sum() {
    let nested = || RecordDef {
        fields: (0..65)
            .map(|index| field(&format!("k{index:03}"), FieldType::Int, false, vec![]))
            .collect(),
        couplings: vec![],
    };
    let schema = RecordSchema::compile(
        &RecordDef {
            fields: vec![
                field("a", FieldType::Record(Box::new(nested())), false, vec![]),
                field("b", FieldType::Record(Box::new(nested())), false, vec![]),
            ],
            couplings: vec![],
        },
        sacp_cbor_schema::SchemaCompileLimits {
            max_fields_per_record: 65,
            ..limits()
        },
    )
    .unwrap();
    let (presence_words, path_depth, frame_capacity) = schema.workspace_requirements();
    assert_eq!(
        presence_words, 3,
        "max-live presence arena requirement rule"
    );
    assert_eq!(path_depth, 2, "exact diagnostic path requirement rule");
    assert_eq!(frame_capacity, 5, "exact validation frame requirement rule");
}

#[test]
fn compile_owned_byte_limit_rejects_huge_key_and_enum_before_clone_or_reserve() {
    let huge = "x".repeat(1_000_000);
    let key_def = RecordDef {
        fields: vec![field(&huge, FieldType::Int, false, vec![])],
        couplings: vec![],
    };
    let enum_def = RecordDef {
        fields: vec![field(
            "a",
            FieldType::Text,
            false,
            vec![Constraint::Enum(vec![EnumMember::Text(huge)])],
        )],
        couplings: vec![],
    };
    let bounded = sacp_cbor_schema::SchemaCompileLimits {
        max_total_owned_bytes: 64,
        ..limits()
    };
    for def in [&key_def, &enum_def] {
        ALLOCS.with(|count| count.set(0));
        TRACK.with(|on| on.set(true));
        let result = RecordSchema::compile(def, bounded);
        TRACK.with(|on| on.set(false));
        assert!(
            matches!(
                result,
                Err(sacp_cbor_schema::SchemaError::OwnedByteLimitExceeded { .. })
            ),
            "compiled-owned-byte limit rejection rule"
        );
        assert_eq!(
            ALLOCS.with(Cell::get),
            0,
            "owned-byte preflight rejects before compiled allocation"
        );
    }
}

#[test]
fn total_node_limit_rejects_record_fanout_before_enqueuing_children() {
    let definition = RecordDef {
        fields: (0..10_000)
            .map(|index| field(&format!("k{index:05}"), FieldType::Int, false, vec![]))
            .collect(),
        couplings: vec![],
    };
    let compile_limits = sacp_cbor_schema::SchemaCompileLimits {
        max_fields_per_record: 10_000,
        max_total_nodes: 1,
        max_total_owned_bytes: 100_000,
        ..limits()
    };
    ALLOCS.with(|count| count.set(0));
    TRACK.with(|on| on.set(true));
    let result = RecordSchema::compile(&definition, compile_limits);
    TRACK.with(|on| on.set(false));
    assert!(matches!(
        result,
        Err(sacp_cbor_schema::SchemaError::TotalNodeLimitExceeded { .. })
    ));
    assert!(
        ALLOCS.with(Cell::get) <= 1,
        "node gate runs before record child-task fanout allocation"
    );
}

#[test]
fn invalid_decode_limits_are_rejected_before_any_workspace_reserve() {
    let schema = RecordSchema::compile(
        &RecordDef {
            fields: vec![field("z", FieldType::Any, true, vec![])],
            couplings: vec![],
        },
        limits(),
    )
    .unwrap();
    let invalid = DecodeLimits {
        max_depth: usize::MAX,
        max_map_len: usize::MAX,
        ..DecodeLimits::for_bytes(4)
    };
    let mut workspace = sacp_cbor_schema::ValidationWorkspace::new();
    ALLOCS.with(|count| count.set(0));
    TRACK.with(|on| on.set(true));
    let prepare_error = workspace
        .prepare_for_limits(&schema, invalid)
        .expect_err("invalid limits must be refused before prepare");
    TRACK.with(|on| on.set(false));
    assert!(
        matches!(prepare_error.fault, Fault::Grammar(error) if error.code == sacp_cbor::ErrorCode::InvalidLimits),
        "invalid prepare-limit precedence rule: {prepare_error:?}"
    );
    assert_eq!(
        ALLOCS.with(Cell::get),
        0,
        "invalid prepare limits allocate no workspace storage"
    );

    ALLOCS.with(|count| count.set(0));
    TRACK.with(|on| on.set(true));
    let validate_error = schema
        .validate(&[0xa1, 0x61, b'z', 0xf6], invalid, ValidationOptions::new())
        .expect_err("invalid limits must be refused before validation prepare");
    TRACK.with(|on| on.set(false));
    assert!(
        matches!(validate_error.fault, Fault::Grammar(error) if error.code == sacp_cbor::ErrorCode::InvalidLimits),
        "invalid validate-limit precedence rule: {validate_error:?}"
    );
    assert_eq!(
        ALLOCS.with(Cell::get),
        0,
        "invalid validation limits allocate no workspace storage"
    );
}

#[test]
fn deep_schema_compile_uses_explicit_frames_and_names_depth_limit() {
    const WRAPPERS: usize = 20_000;
    let mut ty = FieldType::Int;
    for _ in 0..WRAPPERS {
        ty = FieldType::Array(Box::new(ty));
    }
    let def = RecordDef {
        fields: vec![field("v", ty, true, vec![])],
        couplings: vec![],
    };
    let exact_depth = WRAPPERS + 1;
    let generous = sacp_cbor_schema::SchemaCompileLimits {
        max_schema_depth: exact_depth,
        max_total_nodes: WRAPPERS + 16,
        ..limits()
    };
    let schema =
        RecordSchema::compile(&def, generous).expect("explicit frames compile a deep legal schema");
    let rejected = RecordSchema::compile(
        &def,
        sacp_cbor_schema::SchemaCompileLimits {
            max_schema_depth: exact_depth - 1,
            ..generous
        },
    );
    assert!(
        matches!(
            rejected,
            Err(sacp_cbor_schema::SchemaError::NestingDepthExceeded { depth })
                if depth == exact_depth
        ),
        "schema nesting depth limit rejection rule"
    );
    let mut bytes = Vec::with_capacity(4 + WRAPPERS);
    bytes.extend_from_slice(&[0xa1, 0x61, b'v']);
    bytes.resize(bytes.len() + WRAPPERS, 0x81);
    bytes.push(0x00);
    let decode_limits = DecodeLimits {
        max_input_bytes: bytes.len(),
        max_depth: WRAPPERS + 1,
        max_total_items: WRAPPERS + 2,
        max_array_len: 1,
        max_map_len: 1,
        max_bytes_len: 0,
        max_text_len: 1,
    };
    let mut workspace = sacp_cbor_schema::ValidationWorkspace::new();
    workspace.prepare(&schema).unwrap();
    schema
        .validate_with_workspace(
            &bytes,
            decode_limits,
            ValidationOptions::new(),
            &mut workspace,
        )
        .expect("explicit validation frames accept a deep legal value");
    core::mem::forget(def);
}

const TWO_POW_53: u128 = 1 << 53;

/// Big-endian magnitude with leading zeros stripped.
fn mag(value: u128) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

#[test]
fn range_bounds_hold_exactly_at_the_safe_bignum_seam() {
    // Bound -(2^53); values -(2^53) (equal, in range) and -(2^53+1) (below).
    let schema = one_int_field(vec![Constraint::Range {
        min: Some(Int::from(-(TWO_POW_53 as i128))),
        max: Some(Int::from(0_i64)),
    }]);

    // Tag-3 magnitude m encodes -(1 + m).
    let at_min = one_field("v", |e| e.bignum(true, &mag(TWO_POW_53 - 1)));
    assert!(validate(&schema, &at_min).is_ok(), "-(2^53) is in range");

    let below_min = one_field("v", |e| e.bignum(true, &mag(TWO_POW_53)));
    assert!(matches!(
        validate(&schema, &below_min),
        Err(Fault::Constraint(ConstraintFault::RangeBelow))
    ));

    let zero = one_field("v", |e| e.int(0));
    assert!(validate(&schema, &zero).is_ok());

    let above_max = one_field("v", |e| e.int(1));
    assert!(matches!(
        validate(&schema, &above_max),
        Err(Fault::Constraint(ConstraintFault::RangeAbove))
    ));
}

#[test]
fn positive_bignum_compares_against_positive_bignum_bound() {
    let bound = Int::from(TWO_POW_53 + 10);
    let schema = one_int_field(vec![Constraint::Range {
        min: None,
        max: Some(bound),
    }]);

    let at_max = one_field("v", |e| e.bignum(false, &mag(TWO_POW_53 + 10)));
    assert!(validate(&schema, &at_max).is_ok());

    let above = one_field("v", |e| e.bignum(false, &mag(TWO_POW_53 + 11)));
    assert!(matches!(
        validate(&schema, &above),
        Err(Fault::Constraint(ConstraintFault::RangeAbove))
    ));
}

#[test]
fn enum_with_bignum_member_matches_by_canonical_bytes() {
    let schema = one_int_field(vec![Constraint::Enum(vec![
        EnumMember::Int(Int::from(7_i64)),
        EnumMember::Int(Int::from(TWO_POW_53 + 1)),
    ])]);

    let small = one_field("v", |e| e.int(7));
    assert!(validate(&schema, &small).is_ok());

    let big = one_field("v", |e| e.bignum(false, &mag(TWO_POW_53 + 1)));
    assert!(validate(&schema, &big).is_ok());

    let miss = one_field("v", |e| e.int(8));
    assert!(matches!(
        validate(&schema, &miss),
        Err(Fault::Constraint(ConstraintFault::EnumMismatch))
    ));
}

#[test]
fn restriction_modes_apply_inside_the_fused_pass() {
    let schema = RecordSchema::compile(
        &RecordDef {
            fields: vec![field("v", FieldType::Bool, true, vec![])],
            couplings: vec![],
        },
        limits(),
    )
    .expect("compile");

    let bytes = one_field("v", |e| e.bool(true));
    // Plain options admit the boolean.
    assert!(validate(&schema, &bytes).is_ok());
    // no-simple mode rejects it as a grammar fault before the schema sees it.
    let err = schema
        .validate(
            &bytes,
            DecodeLimits::for_bytes(bytes.len()),
            ValidationOptions::new().no_simple(),
        )
        .expect_err("simple forbidden");
    assert!(matches!(err.fault, Fault::Grammar(_)));
}

#[test]
fn unknown_keys_before_and_after_all_declared_fields_are_rejected() {
    let schema = RecordSchema::compile(
        &RecordDef {
            fields: vec![field("m", FieldType::Int, false, vec![])],
            couplings: vec![],
        },
        limits(),
    )
    .expect("compile");

    // "a" sorts before "m", "z" after; both are unknown.
    for key in ["a", "z"] {
        let mut enc = Encoder::new();
        enc.map(1, |m| m.entry(key, |e| e.int(1))).expect("encode");
        let bytes = enc.finish().expect("finish");
        assert!(matches!(
            validate(&schema, &bytes),
            Err(Fault::Shape(ShapeFault::UnknownKey))
        ));
    }
}

#[test]
fn empty_record_satisfies_all_optional_but_violates_exactly_one() {
    let fields = vec![
        field("a", FieldType::Int, false, vec![]),
        field("b", FieldType::Int, false, vec![]),
    ];
    let plain = RecordSchema::compile(
        &RecordDef {
            fields: fields.clone(),
            couplings: vec![],
        },
        limits(),
    )
    .expect("compile");
    let coupled = RecordSchema::compile(
        &RecordDef {
            fields,
            couplings: vec![Coupling::ExactlyOne(vec!["a".to_owned(), "b".to_owned()])],
        },
        limits(),
    )
    .expect("compile");

    let mut enc = Encoder::new();
    enc.map(0, |_| Ok(())).expect("encode");
    let empty = enc.finish().expect("finish");

    assert!(validate(&plain, &empty).is_ok());
    assert!(matches!(
        validate(&coupled, &empty),
        Err(Fault::Constraint(ConstraintFault::CouplingExactlyOne))
    ));
}

#[test]
fn set_of_unions_orders_by_encoded_bytes() {
    // Alternative 0 is payload-free ([0], arity 1); alternative 1 carries an
    // Int ([1, n], arity 2). Order is by canonical encoded bytes: [0] = 81 00,
    // [1, 5] = 82 01 05, so [0] sorts first.
    let schema = RecordSchema::compile(
        &RecordDef {
            fields: vec![field(
                "v",
                FieldType::Set(Box::new(FieldType::Union(vec![
                    UnionAlt {
                        code: 0,
                        payload: None,
                    },
                    UnionAlt {
                        code: 1,
                        payload: Some(FieldType::Int),
                    },
                ]))),
                true,
                vec![],
            )],
            couplings: vec![],
        },
        limits(),
    )
    .expect("compile");

    let ascending = one_field("v", |e| {
        e.array(2, |a| {
            a.array(1, |u| u.int(0))?;
            a.array(2, |u| {
                u.int(1)?;
                u.int(5)
            })
        })
    });
    assert!(validate(&schema, &ascending).is_ok());

    let descending = one_field("v", |e| {
        e.array(2, |a| {
            a.array(2, |u| {
                u.int(1)?;
                u.int(5)
            })?;
            a.array(1, |u| u.int(0))
        })
    });
    assert!(matches!(
        validate(&schema, &descending),
        Err(Fault::Shape(ShapeFault::SetOrder))
    ));
}

#[test]
fn union_code_must_be_a_non_negative_safe_integer() {
    let schema = RecordSchema::compile(
        &RecordDef {
            fields: vec![field(
                "v",
                FieldType::Union(vec![UnionAlt {
                    code: 1,
                    payload: None,
                }]),
                true,
                vec![],
            )],
            couplings: vec![],
        },
        limits(),
    )
    .expect("compile");

    let negative = one_field("v", |e| e.array(1, |a| a.int(-1)));
    let negative_result = validate(&schema, &negative);
    assert!(
        matches!(&negative_result, Err(Fault::Shape(ShapeFault::WrongKind))),
        "union negative-code rejection rule: {negative_result:?}"
    );

    let huge = one_field("v", |e| e.array(1, |a| a.bignum(false, &[1; 16])));
    let huge_result = validate(&schema, &huge);
    assert!(
        matches!(&huge_result, Err(Fault::Shape(ShapeFault::WrongKind))),
        "union oversized-code rejection rule: {huge_result:?}"
    );
}

#[test]
fn record_inside_union_payload_is_fully_checked() {
    let schema = RecordSchema::compile(
        &RecordDef {
            fields: vec![field(
                "v",
                FieldType::Union(vec![UnionAlt {
                    code: 2,
                    payload: Some(FieldType::Record(Box::new(RecordDef {
                        fields: vec![field("x", FieldType::Int, true, vec![])],
                        couplings: vec![],
                    }))),
                }]),
                true,
                vec![],
            )],
            couplings: vec![],
        },
        limits(),
    )
    .expect("compile");

    let good = one_field("v", |e| {
        e.array(2, |a| {
            a.int(2)?;
            a.map(1, |m| m.entry("x", |e| e.int(9)))
        })
    });
    assert!(validate(&schema, &good).is_ok());

    let missing_inner = one_field("v", |e| {
        e.array(2, |a| {
            a.int(2)?;
            a.map(0, |_| Ok(()))
        })
    });
    assert!(matches!(
        validate(&schema, &missing_inner),
        Err(Fault::Shape(ShapeFault::MissingField))
    ));
}

#[test]
fn trailing_bytes_and_non_map_roots_are_grammar_or_shape_faults() {
    let schema = one_int_field(vec![]);

    let mut bytes = one_field("v", |e| e.int(1));
    bytes.push(0x00);
    assert!(matches!(validate(&schema, &bytes), Err(Fault::Grammar(_))));

    let mut enc = Encoder::new();
    enc.int(5).expect("encode");
    let non_map = enc.finish().expect("finish");
    assert!(matches!(
        validate(&schema, &non_map),
        Err(Fault::Shape(ShapeFault::WrongKind))
    ));
}
