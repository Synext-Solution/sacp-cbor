use sacp_cbor::{DecodeLimits, Encoder, ValidationOptions};
use sacp_cbor_schema::{
    Constraint, ConstraintFault, CountUnit, Coupling, EnumMember, Fault, FieldDef, FieldType, Int,
    RecordDef, RecordSchema, SchemaError,
};

mod common;
use common::{field, limits, one_field, schema, validate};

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
    let bytes = enc.finish().expect("finish");
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
    validate(&s, &ok.finish().expect("finish")).expect("couplings satisfied");

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
        RecordSchema::compile(
            &RecordDef {
                fields: too_many_fields,
                couplings: vec![],
            },
            sacp_cbor_schema::SchemaCompileLimits {
                max_fields_per_record: 64,
                ..limits()
            }
        ),
        Err(SchemaError::FieldCapExceeded { .. })
    ));

    assert!(matches!(
        RecordSchema::compile(
            &RecordDef {
                fields: vec![
                    field("a", FieldType::Int, false, vec![]),
                    field("a", FieldType::Text, false, vec![]),
                ],
                couplings: vec![],
            },
            limits()
        ),
        Err(SchemaError::DuplicateFieldKey { .. })
    ));

    assert!(matches!(
        RecordSchema::compile(
            &RecordDef {
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
            },
            limits()
        ),
        Err(SchemaError::ConstraintWrongKind { .. })
    ));

    assert!(matches!(
        RecordSchema::compile(
            &RecordDef {
                fields: vec![field("a", FieldType::Union(vec![]), false, vec![],)],
                couplings: vec![],
            },
            limits()
        ),
        Err(SchemaError::EmptyUnion { .. })
    ));

    assert!(matches!(
        RecordSchema::compile(
            &RecordDef {
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
            },
            limits()
        ),
        Err(SchemaError::DuplicateUnionCode { .. })
    ));

    assert!(matches!(
        RecordSchema::compile(
            &RecordDef {
                fields: vec![field("a", FieldType::Int, true, vec![])],
                couplings: vec![Coupling::Requires {
                    if_present: "a".to_owned(),
                    then_present: "missing".to_owned(),
                }],
            },
            limits()
        ),
        Err(SchemaError::CouplingNonOptionalField { .. })
            | Err(SchemaError::CouplingUnknownField { .. })
    ));

    assert!(matches!(
        RecordSchema::compile(
            &RecordDef {
                fields: vec![field("a", FieldType::Int, false, vec![])],
                couplings: vec![Coupling::Together(vec!["a".to_owned(), "a".to_owned()])],
            },
            limits()
        ),
        Err(SchemaError::CouplingDuplicateKey { .. })
    ));

    assert!(matches!(
        Int::from_sign_magnitude(true, &[]),
        Err(SchemaError::NonNormalizedInt)
    ));
}

#[test]
fn nested_preflight_caps_report_the_full_named_path_and_rule() {
    let nested_record = |leaf: FieldType, couplings: Vec<Coupling>| RecordDef {
        fields: vec![field("inner", leaf, false, vec![])],
        couplings,
    };

    let field_cap = RecordDef {
        fields: vec![field(
            "outer",
            FieldType::Array(Box::new(FieldType::Record(Box::new(RecordDef {
                fields: vec![
                    field("a", FieldType::Int, false, vec![]),
                    field("b", FieldType::Int, false, vec![]),
                ],
                couplings: vec![],
            })))),
            false,
            vec![],
        )],
        couplings: vec![],
    };
    let mut cap = limits();
    cap.max_fields_per_record = 1;
    assert_eq!(
        RecordSchema::compile(&field_cap, cap).unwrap_err(),
        SchemaError::FieldCapExceeded {
            path: "outer".into(),
            count: 2,
        },
        "nested field-cap path rule"
    );

    let constraint_cap = RecordDef {
        fields: vec![field(
            "outer",
            FieldType::Record(Box::new(RecordDef {
                fields: vec![FieldDef {
                    key: "inner".into(),
                    ty: FieldType::Int,
                    required: false,
                    constraints: vec![
                        Constraint::Count {
                            unit: CountUnit::Octets,
                            min: None,
                            max: None,
                        },
                        Constraint::Count {
                            unit: CountUnit::Elements,
                            min: None,
                            max: None,
                        },
                    ],
                }],
                couplings: vec![],
            })),
            false,
            vec![],
        )],
        couplings: vec![],
    };
    let mut cap = limits();
    cap.max_constraints_per_field = 1;
    assert_eq!(
        RecordSchema::compile(&constraint_cap, cap).unwrap_err(),
        SchemaError::ConstraintCapExceeded {
            field: "outer.inner".into(),
            count: 2,
        },
        "nested constraint-cap path rule"
    );

    let union_cap = RecordDef {
        fields: vec![field(
            "outer",
            FieldType::Record(Box::new(nested_record(
                FieldType::Union(vec![
                    sacp_cbor_schema::UnionAlt {
                        code: 1,
                        payload: None,
                    },
                    sacp_cbor_schema::UnionAlt {
                        code: 2,
                        payload: None,
                    },
                ]),
                vec![],
            ))),
            false,
            vec![],
        )],
        couplings: vec![],
    };
    let mut cap = limits();
    cap.max_union_alternatives = 1;
    assert_eq!(
        RecordSchema::compile(&union_cap, cap).unwrap_err(),
        SchemaError::UnionAltCapExceeded {
            path: "outer.inner".into(),
            count: 2,
        },
        "nested union-cap path rule"
    );

    let coupling_cap = RecordDef {
        fields: vec![field(
            "outer",
            FieldType::Record(Box::new(nested_record(
                FieldType::Int,
                vec![
                    Coupling::Together(vec!["inner".into(), "missing".into()]),
                    Coupling::ExactlyOne(vec!["inner".into(), "missing".into()]),
                ],
            ))),
            false,
            vec![],
        )],
        couplings: vec![],
    };
    let mut cap = limits();
    cap.max_couplings_per_record = 1;
    assert_eq!(
        RecordSchema::compile(&coupling_cap, cap).unwrap_err(),
        SchemaError::CouplingCapExceeded {
            path: "outer".into(),
            count: 2,
        },
        "nested coupling-cap path rule"
    );
}

#[test]
fn permissive_depth_limit_does_not_allocate_to_the_limit() {
    let mut compile_limits = limits();
    compile_limits.max_schema_depth = usize::MAX;
    RecordSchema::compile(
        &RecordDef {
            fields: vec![field("a", FieldType::Int, true, vec![])],
            couplings: vec![],
        },
        compile_limits,
    )
    .expect("tiny schema uses actual path depth, not the caller's permissive limit");
}

#[test]
fn duplicate_constraints_use_canonical_semantics_without_pairwise_scans() {
    let definition = RecordDef {
        fields: vec![field(
            "a",
            FieldType::Text,
            true,
            vec![
                Constraint::Enum(vec![
                    EnumMember::Text("a".into()),
                    EnumMember::Text("b".into()),
                ]),
                Constraint::Enum(vec![
                    EnumMember::Text("b".into()),
                    EnumMember::Text("a".into()),
                ]),
            ],
        )],
        couplings: vec![],
    };
    assert_eq!(
        RecordSchema::compile(&definition, limits()).unwrap_err(),
        SchemaError::DuplicateConstraint { field: "a".into() },
        "constraint canonical-set duplicate rule"
    );
}
