#![allow(clippy::needless_pass_by_value)]

use sacp_cbor::scalar::F64Bits;
use sacp_cbor::{DecodeLimits, Encoder, ValidationOptions};
use sacp_cbor_schema::{Fault, FieldType, RecordDef, ShapeFault, UnionAlt};

mod common;
use common::{field, one_field, schema, validate};

#[test]
fn scalar_types_accept_and_reject_wrong_kind() {
    let s = schema(
        vec![
            field("a", FieldType::Int, true, vec![]),
            field("b", FieldType::Bool, true, vec![]),
            field("c", FieldType::Float64, true, vec![]),
            field("d", FieldType::Bytes, true, vec![]),
            field("e", FieldType::Text, true, vec![]),
        ],
        vec![],
    );
    let mut enc = Encoder::new();
    enc.map(5, |m| {
        m.entry("a", |e| e.int(1))?;
        m.entry("b", |e| e.bool(true))?;
        m.entry("c", |e| e.float(F64Bits::try_from_f64(1.5)?))?;
        m.entry("d", |e| e.bytes(b"xx"))?;
        m.entry("e", |e| e.text("ok"))
    })
    .expect("encode");
    let bytes = enc.finish().expect("finish").into_bytes();
    validate(&s, &bytes).expect("valid scalars");

    let bad = one_field("a", |e| e.text("not int"));
    let err = schema(vec![field("a", FieldType::Int, true, vec![])], vec![])
        .validate(
            &bad,
            DecodeLimits::for_bytes(bad.len()),
            ValidationOptions::new(),
        )
        .expect_err("wrong kind");
    assert!(matches!(err.fault, Fault::Shape(ShapeFault::WrongKind)));
}

#[test]
fn closed_record_rejects_unknown_and_missing_keys() {
    let s = schema(vec![field("a", FieldType::Int, true, vec![])], vec![]);
    let empty = {
        let mut enc = Encoder::new();
        enc.map(0, |_| Ok(())).expect("encode");
        enc.finish().expect("finish").into_bytes()
    };
    let missing = s
        .validate(
            &empty,
            DecodeLimits::for_bytes(empty.len()),
            ValidationOptions::new(),
        )
        .expect_err("missing required");
    assert!(matches!(
        missing.fault,
        Fault::Shape(ShapeFault::MissingField)
    ));

    let mut enc = Encoder::new();
    enc.map(2, |m| {
        m.entry("a", |e| e.int(1))?;
        m.entry("z", |e| e.int(2))
    })
    .expect("encode");
    let bytes = enc.finish().expect("finish").into_bytes();
    let unknown = s
        .validate(
            &bytes,
            DecodeLimits::for_bytes(bytes.len()),
            ValidationOptions::new(),
        )
        .expect_err("unknown key");
    assert!(matches!(
        unknown.fault,
        Fault::Shape(ShapeFault::UnknownKey)
    ));
}

#[test]
fn arrays_maps_nested_records_and_any_validate() {
    let s = schema(
        vec![
            field(
                "a",
                FieldType::Array(Box::new(FieldType::Int)),
                true,
                vec![],
            ),
            field("m", FieldType::Map(Box::new(FieldType::Text)), true, vec![]),
            field(
                "r",
                FieldType::Record(Box::new(RecordDef {
                    fields: vec![field("x", FieldType::Bool, true, vec![])],
                    couplings: vec![],
                })),
                true,
                vec![],
            ),
            field("z", FieldType::Any, true, vec![]),
        ],
        vec![],
    );
    let mut enc = Encoder::new();
    enc.map(4, |m| {
        m.entry("a", |e| {
            e.array(2, |a| {
                a.int(1)?;
                a.int(2)
            })
        })?;
        m.entry("m", |e| e.map(1, |m| m.entry("k", |e| e.text("v"))))?;
        m.entry("r", |e| e.map(1, |m| m.entry("x", |e| e.bool(false))))?;
        m.entry("z", |e| e.array(1, |a| a.null()))
    })
    .expect("encode");
    let bytes = enc.finish().expect("finish").into_bytes();
    validate(&s, &bytes).expect("valid compound value");
}

#[test]
fn set_order_and_duplicates_are_rejected() {
    let s = schema(
        vec![field(
            "s",
            FieldType::Set(Box::new(FieldType::Text)),
            true,
            vec![],
        )],
        vec![],
    );
    let ok = one_field("s", |e| {
        e.array(2, |a| {
            a.text("a")?;
            a.text("b")
        })
    });
    validate(&s, &ok).expect("sorted set");

    let dup = one_field("s", |e| {
        e.array(2, |a| {
            a.text("a")?;
            a.text("a")
        })
    });
    let err = s
        .validate(
            &dup,
            DecodeLimits::for_bytes(dup.len()),
            ValidationOptions::new(),
        )
        .expect_err("duplicate");
    assert!(matches!(err.fault, Fault::Shape(ShapeFault::SetDuplicate)));

    let unsorted = one_field("s", |e| {
        e.array(2, |a| {
            a.text("b")?;
            a.text("a")
        })
    });
    let err = s
        .validate(
            &unsorted,
            DecodeLimits::for_bytes(unsorted.len()),
            ValidationOptions::new(),
        )
        .expect_err("order");
    assert!(matches!(err.fault, Fault::Shape(ShapeFault::SetOrder)));
}

#[test]
fn union_arity_code_and_payload_are_checked() {
    let s = schema(
        vec![field(
            "u",
            FieldType::Union(vec![
                UnionAlt {
                    code: 1,
                    payload: None,
                },
                UnionAlt {
                    code: 2,
                    payload: Some(FieldType::Text),
                },
            ]),
            true,
            vec![],
        )],
        vec![],
    );
    let no_payload = one_field("u", |e| e.array(1, |a| a.int(1)));
    validate(&s, &no_payload).expect("payload-free alt");
    let payload = one_field("u", |e| {
        e.array(2, |a| {
            a.int(2)?;
            a.text("ok")
        })
    });
    validate(&s, &payload).expect("payload alt");

    let unknown = one_field("u", |e| e.array(1, |a| a.int(9)));
    let err = s
        .validate(
            &unknown,
            DecodeLimits::for_bytes(unknown.len()),
            ValidationOptions::new(),
        )
        .expect_err("unknown code");
    assert!(matches!(
        err.fault,
        Fault::Shape(ShapeFault::UnionCodeUnknown)
    ));

    let wrong_arity = one_field("u", |e| {
        e.array(2, |a| {
            a.int(1)?;
            a.text("extra")
        })
    });
    let err = s
        .validate(
            &wrong_arity,
            DecodeLimits::for_bytes(wrong_arity.len()),
            ValidationOptions::new(),
        )
        .expect_err("wrong arity");
    assert!(matches!(err.fault, Fault::Shape(ShapeFault::UnionArity)));
}
