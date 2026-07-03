//! Hand-constructed edge vectors targeting boundary conditions.

use sacp_cbor::{DecodeLimits, Encoder, ValidationOptions};
use sacp_cbor_schema::{
    Constraint, ConstraintFault, Coupling, EnumMember, Fault, FieldType, Int, RecordDef,
    RecordSchema, ShapeFault, UnionAlt,
};

mod common;
use common::{field, one_field};

fn one_int_field(constraints: Vec<Constraint>) -> RecordSchema {
    RecordSchema::compile(&RecordDef {
        fields: vec![field("v", FieldType::Int, true, constraints)],
        couplings: vec![],
    })
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
    let schema = RecordSchema::compile(&RecordDef {
        fields: vec![field("v", FieldType::Bool, true, vec![])],
        couplings: vec![],
    })
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
    let schema = RecordSchema::compile(&RecordDef {
        fields: vec![field("m", FieldType::Int, false, vec![])],
        couplings: vec![],
    })
    .expect("compile");

    // "a" sorts before "m", "z" after; both are unknown.
    for key in ["a", "z"] {
        let mut enc = Encoder::new();
        enc.map(1, |m| m.entry(key, |e| e.int(1))).expect("encode");
        let bytes = enc.finish().expect("finish").into_bytes();
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
    let plain = RecordSchema::compile(&RecordDef {
        fields: fields.clone(),
        couplings: vec![],
    })
    .expect("compile");
    let coupled = RecordSchema::compile(&RecordDef {
        fields,
        couplings: vec![Coupling::ExactlyOne(vec!["a".to_owned(), "b".to_owned()])],
    })
    .expect("compile");

    let mut enc = Encoder::new();
    enc.map(0, |_| Ok(())).expect("encode");
    let empty = enc.finish().expect("finish").into_bytes();

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
    let schema = RecordSchema::compile(&RecordDef {
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
    })
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
    let schema = RecordSchema::compile(&RecordDef {
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
    })
    .expect("compile");

    let negative = one_field("v", |e| e.array(1, |a| a.int(-1)));
    assert!(matches!(
        validate(&schema, &negative),
        Err(Fault::Shape(ShapeFault::WrongKind))
    ));

    let huge = one_field("v", |e| e.array(1, |a| a.bignum(false, &[1; 16])));
    assert!(matches!(
        validate(&schema, &huge),
        Err(Fault::Shape(ShapeFault::WrongKind))
    ));
}

#[test]
fn record_inside_union_payload_is_fully_checked() {
    let schema = RecordSchema::compile(&RecordDef {
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
    })
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
    let non_map = enc.finish().expect("finish").into_bytes();
    assert!(matches!(
        validate(&schema, &non_map),
        Err(Fault::Shape(ShapeFault::WrongKind))
    ));
}
