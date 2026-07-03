use sacp_cbor_schema::{
    Constraint, CountUnit, Coupling, Direction, EnumMember, FieldType, Int, RecordDef, UnionAlt,
};

mod common;
use common::{field, schema};

fn holds(direction: &Direction) -> bool {
    matches!(direction, Direction::Holds)
}

#[test]
fn adding_optional_field_is_forward_only() {
    let old = schema(vec![field("a", FieldType::Int, true, vec![])], vec![]);
    let new = schema(
        vec![
            field("a", FieldType::Int, true, vec![]),
            field("b", FieldType::Text, false, vec![]),
        ],
        vec![],
    );
    let c = old.containment(&new);
    assert!(holds(&c.forward));
    assert!(!holds(&c.backward));
}

#[test]
fn adding_required_field_is_neither_direction() {
    let old = schema(vec![field("a", FieldType::Int, true, vec![])], vec![]);
    let new = schema(
        vec![
            field("a", FieldType::Int, true, vec![]),
            field("b", FieldType::Text, true, vec![]),
        ],
        vec![],
    );
    let c = old.containment(&new);
    assert!(!holds(&c.forward));
    assert!(!holds(&c.backward));
}

#[test]
fn required_optional_transitions_have_expected_directions() {
    let required = schema(vec![field("a", FieldType::Int, true, vec![])], vec![]);
    let optional = schema(vec![field("a", FieldType::Int, false, vec![])], vec![]);

    let required_to_optional = required.containment(&optional);
    assert!(holds(&required_to_optional.forward));
    assert!(!holds(&required_to_optional.backward));

    let optional_to_required = optional.containment(&required);
    assert!(!holds(&optional_to_required.forward));
    assert!(holds(&optional_to_required.backward));
}

#[test]
fn type_changes_and_any_rules_are_detected() {
    let int_schema = schema(vec![field("a", FieldType::Int, true, vec![])], vec![]);
    let text_schema = schema(vec![field("a", FieldType::Text, true, vec![])], vec![]);
    let changed = int_schema.containment(&text_schema);
    assert!(!holds(&changed.forward));
    assert!(!holds(&changed.backward));

    let any_schema = schema(vec![field("a", FieldType::Any, true, vec![])], vec![]);
    assert!(holds(&int_schema.containment(&any_schema).forward));
    assert!(!holds(&any_schema.containment(&int_schema).forward));
}

#[test]
fn ranges_counts_and_enums_widen_or_narrow() {
    let narrow_range = schema(
        vec![field(
            "a",
            FieldType::Int,
            true,
            vec![Constraint::Range {
                min: Some(Int::from(0_u64)),
                max: Some(Int::from(10_u64)),
            }],
        )],
        vec![],
    );
    let wide_range = schema(
        vec![field(
            "a",
            FieldType::Int,
            true,
            vec![Constraint::Range {
                min: Some(Int::from(0_u64)),
                max: Some(Int::from(100_u64)),
            }],
        )],
        vec![],
    );
    assert!(holds(&narrow_range.containment(&wide_range).forward));
    assert!(!holds(&wide_range.containment(&narrow_range).forward));

    let short = schema(
        vec![field(
            "a",
            FieldType::Text,
            true,
            vec![Constraint::Count {
                unit: CountUnit::Octets,
                min: None,
                max: Some(4),
            }],
        )],
        vec![],
    );
    let long = schema(
        vec![field(
            "a",
            FieldType::Text,
            true,
            vec![Constraint::Count {
                unit: CountUnit::Octets,
                min: None,
                max: Some(8),
            }],
        )],
        vec![],
    );
    assert!(holds(&short.containment(&long).forward));
    assert!(!holds(&long.containment(&short).forward));

    let one = schema(
        vec![field(
            "a",
            FieldType::Text,
            true,
            vec![Constraint::Enum(vec![EnumMember::Text("a".to_owned())])],
        )],
        vec![],
    );
    let two = schema(
        vec![field(
            "a",
            FieldType::Text,
            true,
            vec![Constraint::Enum(vec![
                EnumMember::Text("a".to_owned()),
                EnumMember::Text("b".to_owned()),
            ])],
        )],
        vec![],
    );
    assert!(holds(&one.containment(&two).forward));
    assert!(!holds(&two.containment(&one).forward));
}

#[test]
fn union_codes_payloads_couplings_and_nested_records() {
    let old_union = schema(
        vec![field(
            "u",
            FieldType::Union(vec![UnionAlt {
                code: 1,
                payload: Some(FieldType::Int),
            }]),
            true,
            vec![],
        )],
        vec![],
    );
    let new_union = schema(
        vec![field(
            "u",
            FieldType::Union(vec![
                UnionAlt {
                    code: 1,
                    payload: Some(FieldType::Int),
                },
                UnionAlt {
                    code: 2,
                    payload: None,
                },
            ]),
            true,
            vec![],
        )],
        vec![],
    );
    assert!(holds(&old_union.containment(&new_union).forward));
    assert!(!holds(&old_union.containment(&new_union).backward));

    let payload_changed = schema(
        vec![field(
            "u",
            FieldType::Union(vec![UnionAlt {
                code: 1,
                payload: Some(FieldType::Text),
            }]),
            true,
            vec![],
        )],
        vec![],
    );
    assert!(!holds(&old_union.containment(&payload_changed).forward));

    let no_coupling = schema(
        vec![
            field("a", FieldType::Int, false, vec![]),
            field("b", FieldType::Int, false, vec![]),
        ],
        vec![],
    );
    let with_coupling = schema(
        vec![
            field("a", FieldType::Int, false, vec![]),
            field("b", FieldType::Int, false, vec![]),
        ],
        vec![Coupling::Together(vec!["a".to_owned(), "b".to_owned()])],
    );
    assert!(!holds(&no_coupling.containment(&with_coupling).forward));
    assert!(holds(&with_coupling.containment(&no_coupling).forward));

    let nested_old = schema(
        vec![field(
            "r",
            FieldType::Record(Box::new(RecordDef {
                fields: vec![field("x", FieldType::Int, true, vec![])],
                couplings: vec![],
            })),
            true,
            vec![],
        )],
        vec![],
    );
    let nested_new = schema(
        vec![field(
            "r",
            FieldType::Record(Box::new(RecordDef {
                fields: vec![
                    field("x", FieldType::Int, true, vec![]),
                    field("y", FieldType::Text, false, vec![]),
                ],
                couplings: vec![],
            })),
            true,
            vec![],
        )],
        vec![],
    );
    let nested = nested_old.containment(&nested_new);
    assert!(holds(&nested.forward), "{nested:?}");
    assert!(!holds(&nested.backward), "{nested:?}");
}

#[test]
fn unchanged_coupling_survives_presence_bit_shift() {
    // "A" sorts before "a" and "b" in canonical key order, so adding it
    // shifts the coupled fields' presence bits in the successor schema.
    // The coupling itself is unchanged and must compare by keys, not masks.
    let coupled = Coupling::Together(vec!["a".to_owned(), "b".to_owned()]);
    let old = schema(
        vec![
            field("a", FieldType::Int, false, vec![]),
            field("b", FieldType::Text, false, vec![]),
        ],
        vec![coupled.clone()],
    );
    let new = schema(
        vec![
            field("A", FieldType::Int, false, vec![]),
            field("a", FieldType::Int, false, vec![]),
            field("b", FieldType::Text, false, vec![]),
        ],
        vec![coupled],
    );
    let c = old.containment(&new);
    assert!(holds(&c.forward));
    assert!(!holds(&c.backward));
}

#[test]
fn nested_record_reasons_follow_the_direction_perspective() {
    // Adding an optional field INSIDE a nested record: forward holds;
    // backward fails and the reason must read from the evolution
    // perspective — the field was ADDED in the successor.
    let nested = |extra: bool| {
        let mut fields = vec![field("x", FieldType::Int, true, vec![])];
        if extra {
            fields.push(field("y", FieldType::Int, false, vec![]));
        }
        FieldType::Record(Box::new(RecordDef {
            fields,
            couplings: vec![],
        }))
    };
    let old = schema(vec![field("r", nested(false), true, vec![])], vec![]);
    let new = schema(vec![field("r", nested(true), true, vec![])], vec![]);

    let c = old.containment(&new);
    assert!(holds(&c.forward));
    let Direction::NotDerivable(non_derivation) = c.backward else {
        panic!("backward must not derive");
    };
    assert_eq!(
        non_derivation.reason,
        sacp_cbor_schema::NonDerivationReason::FieldAdded
    );
    assert_eq!(non_derivation.path, vec!["r".to_owned(), "y".to_owned()]);
}
