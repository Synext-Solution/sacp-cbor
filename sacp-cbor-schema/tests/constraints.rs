use sacp_cbor::{DecodeLimits, Encoder, ValidationOptions};
use sacp_cbor_schema::{
    Constraint, ConstraintFault, CountUnit, Coupling, EnumMember, Fault, FieldDef, FieldType, Int,
    RecordDef, RecordSchema, SchemaError,
};

mod common;
use common::{field, one_field, schema, validate};

#[test]
fn range_supports_safe_and_bignum_bounds() {
    let big = Int::from_sign_magnitude(false, &[0x20, 0, 0, 0, 0, 0, 0]).expect("big int");
    let s = schema(
        vec![field(
            "i",
            FieldType::Int,
            true,
            vec![Constraint::Range {
                min: Some(Int::from(-5_i64)),
                max: Some(big.clone()),
            }],
        )],
        vec![],
    );
    let safe = one_field("i", |e| e.int(0));
    validate(&s, &safe).expect("safe in range");
    let big_ok = one_field("i", |e| e.bignum(false, big.magnitude()));
    validate(&s, &big_ok).expect("big boundary in range");

    let low = one_field("i", |e| e.int(-6));
    let err = s
        .validate(
            &low,
            DecodeLimits::for_bytes(low.len()),
            ValidationOptions::new(),
        )
        .expect_err("below range");
    assert!(matches!(
        err.fault,
        Fault::Constraint(ConstraintFault::RangeBelow)
    ));
}

#[test]
fn count_constraints_check_elements_and_octets() {
    let s = schema(
        vec![
            field(
                "a",
                FieldType::Array(Box::new(FieldType::Bool)),
                true,
                vec![Constraint::Count {
                    unit: CountUnit::Elements,
                    min: Some(2),
                    max: Some(2),
                }],
            ),
            field(
                "t",
                FieldType::Text,
                true,
                vec![Constraint::Count {
                    unit: CountUnit::Octets,
                    min: Some(2),
                    max: Some(4),
                }],
            ),
        ],
        vec![],
    );
    let mut enc = Encoder::new();
    enc.map(2, |m| {
        m.entry("a", |e| {
            e.array(2, |a| {
                a.bool(true)?;
                a.bool(false)
            })
        })?;
        m.entry("t", |e| e.text("é"))
    })
    .expect("encode");
    let bytes = enc.finish().expect("finish").into_bytes();
    validate(&s, &bytes).expect("counts on boundaries");

    let short = one_field("t", |e| e.text("a"));
    let text_schema = schema(
        vec![field(
            "t",
            FieldType::Text,
            true,
            vec![Constraint::Count {
                unit: CountUnit::Octets,
                min: Some(2),
                max: None,
            }],
        )],
        vec![],
    );
    let err = text_schema
        .validate(
            &short,
            DecodeLimits::for_bytes(short.len()),
            ValidationOptions::new(),
        )
        .expect_err("too short");
    assert!(matches!(
        err.fault,
        Fault::Constraint(ConstraintFault::CountBelow)
    ));
}

#[test]
fn enum_constraints_use_canonical_encoding_equality() {
    let big = Int::from_sign_magnitude(false, &[0x20, 0, 0, 0, 0, 0, 1]).expect("big int");
    let int_schema = schema(
        vec![field(
            "i",
            FieldType::Int,
            true,
            vec![Constraint::Enum(vec![
                EnumMember::Int(Int::from(1_u64)),
                EnumMember::Int(big.clone()),
            ])],
        )],
        vec![],
    );
    let ok = one_field("i", |e| e.bignum(false, big.magnitude()));
    validate(&int_schema, &ok).expect("big enum hit");
    let miss = one_field("i", |e| e.int(2));
    assert!(matches!(
        int_schema
            .validate(
                &miss,
                DecodeLimits::for_bytes(miss.len()),
                ValidationOptions::new(),
            )
            .expect_err("enum miss")
            .fault,
        Fault::Constraint(ConstraintFault::EnumMismatch)
    ));

    let text_schema = schema(
        vec![field(
            "t",
            FieldType::Text,
            true,
            vec![Constraint::Enum(vec![EnumMember::Text("ok".to_owned())])],
        )],
        vec![],
    );
    validate(&text_schema, &one_field("t", |e| e.text("ok"))).expect("text enum hit");
}

#[test]
fn couplings_are_checked_from_optional_presence_bits() {
    let s = schema(
        vec![
            field("a", FieldType::Int, false, vec![]),
            field("b", FieldType::Int, false, vec![]),
            field("c", FieldType::Int, false, vec![]),
            field("d", FieldType::Int, false, vec![]),
        ],
        vec![
            Coupling::Requires {
                if_present: "a".to_owned(),
                then_present: "b".to_owned(),
            },
            Coupling::ExactlyOne(vec!["c".to_owned(), "d".to_owned()]),
        ],
    );
    let mut ok = Encoder::new();
    ok.map(3, |m| {
        m.entry("a", |e| e.int(1))?;
        m.entry("b", |e| e.int(1))?;
        m.entry("c", |e| e.int(1))
    })
    .expect("encode");
    validate(&s, &ok.finish().expect("finish").into_bytes()).expect("couplings satisfied");

    let bad = one_field("a", |e| e.int(1));
    let err = s
        .validate(
            &bad,
            DecodeLimits::for_bytes(bad.len()),
            ValidationOptions::new(),
        )
        .expect_err("requires violated");
    assert!(matches!(
        err.fault,
        Fault::Constraint(ConstraintFault::CouplingRequires)
    ));

    let together = schema(
        vec![
            field("a", FieldType::Int, false, vec![]),
            field("b", FieldType::Int, false, vec![]),
        ],
        vec![Coupling::Together(vec!["a".to_owned(), "b".to_owned()])],
    );
    let err = together
        .validate(
            &bad,
            DecodeLimits::for_bytes(bad.len()),
            ValidationOptions::new(),
        )
        .expect_err("together violated");
    assert!(matches!(
        err.fault,
        Fault::Constraint(ConstraintFault::CouplingTogether)
    ));
}

#[test]
fn compile_errors_cover_model_rejections() {
    let too_many_fields: Vec<FieldDef> = (0..65)
        .map(|i| field(&format!("k{i:02}"), FieldType::Int, false, vec![]))
        .collect();
    assert!(matches!(
        RecordSchema::compile(&RecordDef {
            fields: too_many_fields,
            couplings: vec![],
        }),
        Err(SchemaError::FieldCapExceeded { .. })
    ));

    assert!(matches!(
        RecordSchema::compile(&RecordDef {
            fields: vec![
                field("a", FieldType::Int, false, vec![]),
                field("a", FieldType::Text, false, vec![]),
            ],
            couplings: vec![],
        }),
        Err(SchemaError::DuplicateFieldKey { .. })
    ));

    assert!(matches!(
        RecordSchema::compile(&RecordDef {
            fields: vec![field(
                "a",
                FieldType::Text,
                false,
                vec![Constraint::Range {
                    min: None,
                    max: None,
                }],
            )],
            couplings: vec![],
        }),
        Err(SchemaError::ConstraintWrongKind { .. })
    ));

    assert!(matches!(
        RecordSchema::compile(&RecordDef {
            fields: vec![field("a", FieldType::Union(vec![]), false, vec![],)],
            couplings: vec![],
        }),
        Err(SchemaError::EmptyUnion { .. })
    ));

    assert!(matches!(
        RecordSchema::compile(&RecordDef {
            fields: vec![field(
                "a",
                FieldType::Union(vec![
                    sacp_cbor_schema::UnionAlt {
                        code: 1,
                        payload: None
                    },
                    sacp_cbor_schema::UnionAlt {
                        code: 1,
                        payload: None
                    },
                ]),
                false,
                vec![],
            )],
            couplings: vec![],
        }),
        Err(SchemaError::DuplicateUnionCode { .. })
    ));

    assert!(matches!(
        RecordSchema::compile(&RecordDef {
            fields: vec![field("a", FieldType::Int, true, vec![])],
            couplings: vec![Coupling::Requires {
                if_present: "a".to_owned(),
                then_present: "missing".to_owned(),
            }],
        }),
        Err(SchemaError::CouplingNonOptionalField { .. })
            | Err(SchemaError::CouplingUnknownField { .. })
    ));

    assert!(matches!(
        RecordSchema::compile(&RecordDef {
            fields: vec![field("a", FieldType::Int, false, vec![])],
            couplings: vec![Coupling::Together(vec!["a".to_owned(), "a".to_owned()])],
        }),
        Err(SchemaError::CouplingDuplicateKey { .. })
    ));

    assert!(matches!(
        Int::from_sign_magnitude(true, &[]),
        Err(SchemaError::NonNormalizedInt)
    ));
}
