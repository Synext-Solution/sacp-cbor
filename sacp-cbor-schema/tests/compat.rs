use sacp_cbor_schema::{
    Constraint, CountUnit, Coupling, DecodeLimits, EnumMember, FieldType, InclusionProof, Int,
    RecordDef, RecordSchema, SchemaCompileLimits, UnionAlt,
};

mod common;
use common::{field, inclusion_limits, limits, schema};

fn holds(direction: &InclusionProof) -> bool {
    matches!(direction, InclusionProof::Proven)
}

fn replay_limits(bytes: &[u8]) -> DecodeLimits {
    DecodeLimits {
        max_depth: bytes.len(),
        max_array_len: bytes.len(),
        max_map_len: bytes.len(),
        ..DecodeLimits::for_bytes(bytes.len())
    }
}

fn assert_refuted(
    source: &sacp_cbor_schema::RecordSchema,
    target: &sacp_cbor_schema::RecordSchema,
    proof: &InclusionProof,
    rule: &str,
) {
    let InclusionProof::Refuted(counterexample) = proof else {
        panic!("{rule} must have a verified wire counterexample: {proof:?}")
    };
    let limits = replay_limits(counterexample.canonical().as_bytes());
    source
        .check(counterexample.canonical().as_canonical_ref(), limits)
        .expect("counterexample source acceptance");
    let rejection = target
        .check(counterexample.canonical().as_canonical_ref(), limits)
        .expect_err("counterexample target rejection");
    assert_eq!(
        &rejection,
        counterexample.target_rejection(),
        "{rule} replayed target rejection"
    );
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
    let c = old.inclusion(&new, inclusion_limits());
    assert!(holds(&c.forward));
    assert_refuted(
        &new,
        &old,
        &c.backward,
        "optional field addition closed-record rule",
    );
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
    let c = old.inclusion(&new, inclusion_limits());
    assert_refuted(&old, &new, &c.forward, "required field addition rule");
    assert_refuted(&new, &old, &c.backward, "closed-record field removal rule");
}

#[test]
fn required_optional_transitions_have_expected_directions() {
    let required = schema(vec![field("a", FieldType::Int, true, vec![])], vec![]);
    let optional = schema(vec![field("a", FieldType::Int, false, vec![])], vec![]);

    let required_to_optional = required.inclusion(&optional, inclusion_limits());
    assert!(holds(&required_to_optional.forward));
    assert_refuted(
        &optional,
        &required,
        &required_to_optional.backward,
        "optional-to-required presence rule",
    );

    let optional_to_required = optional.inclusion(&required, inclusion_limits());
    assert_refuted(
        &optional,
        &required,
        &optional_to_required.forward,
        "optional-to-required forward rule",
    );
    assert!(holds(&optional_to_required.backward));
}

#[test]
fn type_changes_and_any_rules_are_detected() {
    let int_schema = schema(vec![field("a", FieldType::Int, true, vec![])], vec![]);
    let text_schema = schema(vec![field("a", FieldType::Text, true, vec![])], vec![]);
    let changed = int_schema.inclusion(&text_schema, inclusion_limits());
    assert_refuted(
        &int_schema,
        &text_schema,
        &changed.forward,
        "integer-to-text type rule",
    );
    assert_refuted(
        &text_schema,
        &int_schema,
        &changed.backward,
        "text-to-integer type rule",
    );

    let any_schema = schema(vec![field("a", FieldType::Any, true, vec![])], vec![]);
    assert!(holds(
        &int_schema
            .inclusion(&any_schema, inclusion_limits())
            .forward
    ));
    let any_to_int = any_schema.inclusion(&int_schema, inclusion_limits());
    assert_refuted(
        &any_schema,
        &int_schema,
        &any_to_int.forward,
        "Any narrowing rule",
    );
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
    assert!(holds(
        &narrow_range
            .inclusion(&wide_range, inclusion_limits())
            .forward
    ));
    let range_narrowed = wide_range.inclusion(&narrow_range, inclusion_limits());
    assert_refuted(
        &wide_range,
        &narrow_range,
        &range_narrowed.forward,
        "range narrowing rule",
    );

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
    assert!(holds(&short.inclusion(&long, inclusion_limits()).forward));
    let count_narrowed = long.inclusion(&short, inclusion_limits());
    assert_refuted(
        &long,
        &short,
        &count_narrowed.forward,
        "count narrowing rule",
    );

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
    assert!(holds(&one.inclusion(&two, inclusion_limits()).forward));
    let enum_narrowed = two.inclusion(&one, inclusion_limits());
    assert_refuted(&two, &one, &enum_narrowed.forward, "enum narrowing rule");
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
    assert!(holds(
        &old_union.inclusion(&new_union, inclusion_limits()).forward
    ));
    let union_added = old_union.inclusion(&new_union, inclusion_limits());
    assert_refuted(
        &new_union,
        &old_union,
        &union_added.backward,
        "union alternative removal rule",
    );

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
    let payload_change = old_union.inclusion(&payload_changed, inclusion_limits());
    assert_refuted(
        &old_union,
        &payload_changed,
        &payload_change.forward,
        "union payload type rule",
    );

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
    let coupling_added = no_coupling.inclusion(&with_coupling, inclusion_limits());
    assert_refuted(
        &no_coupling,
        &with_coupling,
        &coupling_added.forward,
        "presence coupling rule",
    );
    assert!(holds(
        &with_coupling
            .inclusion(&no_coupling, inclusion_limits())
            .forward
    ));

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
    let nested = nested_old.inclusion(&nested_new, inclusion_limits());
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
    let c = old.inclusion(&new, inclusion_limits());
    assert!(holds(&c.forward));
    assert!(!holds(&c.backward));
}

#[test]
fn coupling_sets_and_declaration_lists_have_canonical_semantics() {
    let fields = || {
        vec![
            field("a", FieldType::Int, false, vec![]),
            field("b", FieldType::Int, false, vec![]),
            field("c", FieldType::Int, false, vec![]),
        ]
    };
    let left = schema(
        fields(),
        vec![
            Coupling::Together(vec!["a".into(), "b".into(), "c".into()]),
            Coupling::ExactlyOne(vec!["a".into(), "b".into()]),
        ],
    );
    let right = schema(
        fields(),
        vec![
            Coupling::ExactlyOne(vec!["b".into(), "a".into()]),
            Coupling::Together(vec!["c".into(), "a".into(), "b".into()]),
            Coupling::Together(vec!["b".into(), "c".into(), "a".into()]),
        ],
    );
    let inclusion = left.inclusion(&right, inclusion_limits());
    assert!(holds(&inclusion.forward), "coupling set permutation rule");
    assert!(
        holds(&inclusion.backward),
        "coupling declaration normalization rule"
    );
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

    let c = old.inclusion(&new, inclusion_limits());
    assert!(holds(&c.forward));
    let InclusionProof::Refuted(counterexample) = c.backward else {
        panic!("backward must carry a replayable wire counterexample");
    };
    let limits = replay_limits(counterexample.canonical().as_bytes());
    new.check(counterexample.canonical().as_canonical_ref(), limits)
        .expect("counterexample is admitted by source");
    let rejection = old
        .check(counterexample.canonical().as_canonical_ref(), limits)
        .unwrap_err();
    assert_eq!(&rejection, counterexample.target_rejection());
    assert_eq!(rejection.path, vec!["r".to_owned()]);
}

#[test]
fn inclusion_resource_exhaustion_is_unknown_and_workspace_capacity_is_explicit() {
    let source = schema(vec![field("a", FieldType::Int, true, vec![])], vec![]);
    let target = schema(vec![field("a", FieldType::Text, true, vec![])], vec![]);
    let tiny = sacp_cbor_schema::InclusionLimits::new(0, 8, 8, 64, 128, 64, 8);
    let proof = source.inclusion(&target, tiny).forward;
    assert!(
        matches!(proof, InclusionProof::Unknown(ref unknown) if unknown.reason == sacp_cbor_schema::NonDerivationReason::ResourceLimit),
        "work budget exhaustion rule"
    );

    let limits = inclusion_limits();
    let mut workspace = sacp_cbor_schema::InclusionWorkspace::new();
    workspace
        .prepare(
            &source,
            &target,
            sacp_cbor_schema::InclusionLimits::new(
                limits.max_steps,
                limits.max_frames,
                0,
                limits.max_path_bytes,
                limits.max_witness_bytes,
                limits.max_witness_items,
                limits.max_value_depth,
            ),
        )
        .unwrap();
    let proof = source
        .inclusion_with_workspace(&target, limits, &mut workspace)
        .forward;
    assert!(
        matches!(proof, InclusionProof::Unknown(ref unknown) if unknown.reason == sacp_cbor_schema::NonDerivationReason::ResourceLimit),
        "workspace capacity-minus-required rule"
    );
}

#[test]
fn backward_replay_uses_direction_independent_validation_capacity() {
    let shallow = schema(vec![field("a", FieldType::Int, true, vec![])], vec![]);
    let deep = schema(
        vec![field(
            "a",
            FieldType::Array(Box::new(FieldType::Array(Box::new(FieldType::Int)))),
            true,
            vec![],
        )],
        vec![],
    );
    let inclusion = shallow.inclusion(&deep, inclusion_limits());
    assert_refuted(
        &shallow,
        &deep,
        &inclusion.forward,
        "forward asymmetric validation-workspace rule",
    );
    assert_refuted(
        &deep,
        &shallow,
        &inclusion.backward,
        "backward asymmetric validation-workspace rule",
    );
}

#[test]
fn set_counterexample_synthesis_emits_distinct_canonically_sorted_elements() {
    let source = schema(
        vec![field(
            "s",
            FieldType::Set(Box::new(FieldType::Int)),
            true,
            vec![Constraint::Count {
                unit: CountUnit::Elements,
                min: Some(2),
                max: Some(2),
            }],
        )],
        vec![],
    );
    let target = schema(
        vec![field(
            "s",
            FieldType::Set(Box::new(FieldType::Int)),
            true,
            vec![Constraint::Count {
                unit: CountUnit::Elements,
                min: None,
                max: Some(1),
            }],
        )],
        vec![],
    );
    let proof = source.inclusion(&target, inclusion_limits()).forward;
    assert_refuted(
        &source,
        &target,
        &proof,
        "set length counterexample distinct-order rule",
    );
    let InclusionProof::Refuted(counterexample) = proof else {
        unreachable!();
    };
    assert_eq!(
        counterexample.canonical().as_bytes(),
        [0xa1, 0x61, b's', 0x82, 0x00, 0x01],
        "set witness canonical element order rule"
    );
}

#[test]
fn enum_counterexample_searches_the_full_constraint_intersection() {
    let exact_one = Constraint::Range {
        min: Some(Int::from(1_i64)),
        max: Some(Int::from(1_i64)),
    };
    let source = schema(
        vec![field(
            "i",
            FieldType::Int,
            true,
            vec![
                Constraint::Enum(vec![
                    EnumMember::Int(Int::from(0_i64)),
                    EnumMember::Int(Int::from(1_i64)),
                    EnumMember::Int(Int::from(2_i64)),
                ]),
                Constraint::Enum(vec![EnumMember::Int(Int::from(1_i64))]),
                exact_one.clone(),
            ],
        )],
        vec![],
    );
    let target = schema(
        vec![field(
            "i",
            FieldType::Int,
            true,
            vec![
                Constraint::Enum(vec![EnumMember::Int(Int::from(0_i64))]),
                exact_one,
            ],
        )],
        vec![],
    );
    let proof = source.inclusion(&target, inclusion_limits()).forward;
    assert_refuted(
        &source,
        &target,
        &proof,
        "enum intersection candidate-search rule",
    );
}

#[test]
fn deep_inclusion_uses_caller_prepared_frames_without_call_stack_recursion() {
    const DEPTH: usize = 20_000;
    let mut ty = FieldType::Int;
    for _ in 0..DEPTH {
        ty = FieldType::Array(Box::new(ty));
    }
    let model = RecordDef {
        fields: vec![field("a", ty, true, vec![])],
        couplings: vec![],
    };
    let compile_limits = SchemaCompileLimits {
        max_schema_depth: DEPTH + 2,
        max_total_nodes: DEPTH * 4,
        max_total_owned_bytes: 1024,
        ..limits()
    };
    let source = RecordSchema::compile(&model, compile_limits).unwrap();
    let target = RecordSchema::compile(&model, compile_limits).unwrap();
    core::mem::forget(model);
    let limits = sacp_cbor_schema::InclusionLimits::new(
        DEPTH * 16,
        DEPTH + 8,
        DEPTH + 8,
        DEPTH * 4,
        1024,
        1024,
        DEPTH + 8,
    );
    let inclusion = source.inclusion(&target, limits);
    assert!(holds(&inclusion.forward), "deep forward frame-machine rule");
    assert!(
        holds(&inclusion.backward),
        "deep backward frame-machine rule"
    );
}

#[test]
fn deep_counterexample_synthesis_and_replay_are_stack_safe() {
    const DEPTH: usize = 10_000;
    let nested = |leaf| {
        let mut ty = leaf;
        for _ in 0..DEPTH {
            ty = FieldType::Array(Box::new(ty));
        }
        RecordDef {
            fields: vec![field("a", ty, true, vec![])],
            couplings: vec![],
        }
    };
    let source_model = nested(FieldType::Int);
    let target_model = nested(FieldType::Text);
    let compile_limits = SchemaCompileLimits {
        max_schema_depth: DEPTH + 2,
        max_total_nodes: DEPTH * 4,
        max_total_owned_bytes: 1024,
        ..limits()
    };
    let source = RecordSchema::compile(&source_model, compile_limits).unwrap();
    let target = RecordSchema::compile(&target_model, compile_limits).unwrap();
    core::mem::forget(source_model);
    core::mem::forget(target_model);
    let proof = source
        .inclusion(
            &target,
            sacp_cbor_schema::InclusionLimits::new(
                DEPTH * 100,
                DEPTH * 3,
                DEPTH + 16,
                DEPTH * 4,
                DEPTH * 4,
                DEPTH * 2,
                DEPTH * 2,
            ),
        )
        .forward;
    assert_refuted(
        &source,
        &target,
        &proof,
        "deep iterative counterexample synthesis rule",
    );
}

#[test]
fn lower_candidate_can_fail_to_refute_while_upper_candidate_proves_range_narrowing() {
    let source = schema(
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
    let target = schema(
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
    let proof = source.inclusion(&target, inclusion_limits()).forward;
    assert_refuted(
        &source,
        &target,
        &proof,
        "upper range witness after lower is accepted",
    );
}

#[test]
fn uninhabited_source_mismatch_is_unknown_not_refuted() {
    let source = schema(
        vec![field(
            "a",
            FieldType::Int,
            true,
            vec![
                Constraint::Range {
                    min: Some(Int::from(0_u64)),
                    max: Some(Int::from(0_u64)),
                },
                Constraint::Range {
                    min: Some(Int::from(1_u64)),
                    max: Some(Int::from(1_u64)),
                },
            ],
        )],
        vec![],
    );
    let target = schema(vec![field("a", FieldType::Text, true, vec![])], vec![]);
    assert!(
        matches!(
            source.inclusion(&target, inclusion_limits()).forward,
            InclusionProof::Unknown(_)
        ),
        "uninhabited source cannot produce a wire counterexample"
    );
}
