use sacp_cbor_abi::{
    diff, CompatibilityClass, EnumDef, FieldDef, FieldPresence, FieldSetDef, Schema, TypeDef,
    TypeRef, UnknownFieldPolicy, UnknownVariantPolicy, VariantDef,
};

fn field(id: u32, ty: TypeRef, presence: FieldPresence) -> FieldDef {
    FieldDef {
        id,
        name: format!("f{id}"),
        ty,
        presence,
    }
}

fn renamed_field(id: u32, name: &str, ty: TypeRef, presence: FieldPresence) -> FieldDef {
    FieldDef {
        id,
        name: name.to_string(),
        ty,
        presence,
    }
}

fn struct_schema(fields: Vec<FieldDef>, unknown_fields: UnknownFieldPolicy) -> Schema {
    Schema::new(
        "example.Type",
        1,
        TypeDef::Struct(FieldSetDef {
            fields,
            unknown_fields,
        }),
    )
}

fn enum_schema(variants: Vec<VariantDef>, unknown_variants: UnknownVariantPolicy) -> Schema {
    Schema::new(
        "example.Enum",
        1,
        TypeDef::Enum(EnumDef {
            variants,
            unknown_fields: UnknownFieldPolicy::Reject,
            unknown_variants,
        }),
    )
}

#[test]
fn optional_field_addition_is_directional() {
    let new = struct_schema(
        vec![
            field(1, TypeRef::U64, FieldPresence::Required),
            field(2, TypeRef::Text, FieldPresence::Optional),
        ],
        UnknownFieldPolicy::Reject,
    );

    let old_reject = struct_schema(
        vec![field(1, TypeRef::U64, FieldPresence::Required)],
        UnknownFieldPolicy::Reject,
    );
    let report = diff(&old_reject, &new);
    assert_eq!(report.new_reads_old, CompatibilityClass::Compatible);
    assert_eq!(report.old_reads_new, CompatibilityClass::Incompatible);
    assert_eq!(report.old_preserves_new, CompatibilityClass::Incompatible);

    let old_ignore = struct_schema(
        vec![field(1, TypeRef::U64, FieldPresence::Required)],
        UnknownFieldPolicy::Ignore,
    );
    let report = diff(&old_ignore, &new);
    assert_eq!(report.old_reads_new, CompatibilityClass::Compatible);
    assert_eq!(report.old_preserves_new, CompatibilityClass::Incompatible);

    let old_preserve = struct_schema(
        vec![field(1, TypeRef::U64, FieldPresence::Required)],
        UnknownFieldPolicy::Preserve,
    );
    let report = diff(&old_preserve, &new);
    assert_eq!(report.old_reads_new, CompatibilityClass::Compatible);
    assert_eq!(report.old_preserves_new, CompatibilityClass::Compatible);
}

#[test]
fn required_field_addition_blocks_new_reads_old() {
    let old = struct_schema(
        vec![field(1, TypeRef::U64, FieldPresence::Required)],
        UnknownFieldPolicy::Ignore,
    );
    let new = struct_schema(
        vec![
            field(1, TypeRef::U64, FieldPresence::Required),
            field(2, TypeRef::Text, FieldPresence::Required),
        ],
        UnknownFieldPolicy::Reject,
    );

    let report = diff(&old, &new);
    assert_eq!(report.new_reads_old, CompatibilityClass::Incompatible);
    assert_eq!(report.old_reads_new, CompatibilityClass::Compatible);
}

#[test]
fn type_change_is_incompatible_in_every_direction() {
    let old = struct_schema(
        vec![field(1, TypeRef::U64, FieldPresence::Required)],
        UnknownFieldPolicy::Preserve,
    );
    let new = struct_schema(
        vec![field(1, TypeRef::Text, FieldPresence::Required)],
        UnknownFieldPolicy::Preserve,
    );

    let report = diff(&old, &new);
    assert_eq!(report.new_reads_old, CompatibilityClass::Incompatible);
    assert_eq!(report.old_reads_new, CompatibilityClass::Incompatible);
    assert_eq!(report.old_preserves_new, CompatibilityClass::Incompatible);
}

#[test]
fn metadata_rename_keeps_wire_hash_and_read_compatibility() {
    let old = struct_schema(
        vec![renamed_field(
            1,
            "amount",
            TypeRef::U64,
            FieldPresence::Required,
        )],
        UnknownFieldPolicy::Reject,
    );
    let new = struct_schema(
        vec![renamed_field(
            1,
            "units",
            TypeRef::U64,
            FieldPresence::Required,
        )],
        UnknownFieldPolicy::Reject,
    );

    assert_eq!(old.wire_hash().unwrap(), new.wire_hash().unwrap());
    assert_ne!(old.full_hash().unwrap(), new.full_hash().unwrap());

    let report = diff(&old, &new);
    assert_eq!(report.bidirectional, CompatibilityClass::Compatible);
    assert!(report
        .changes
        .iter()
        .any(|change| change.message == "field name changed"));
}

#[test]
fn enum_variant_addition_requires_unknown_variant_preservation() {
    let old_reject = enum_schema(
        vec![VariantDef {
            id: 1,
            name: "A".to_string(),
            fields: Vec::new(),
        }],
        UnknownVariantPolicy::Reject,
    );
    let old_preserve = enum_schema(
        vec![VariantDef {
            id: 1,
            name: "A".to_string(),
            fields: Vec::new(),
        }],
        UnknownVariantPolicy::Preserve,
    );
    let new = enum_schema(
        vec![
            VariantDef {
                id: 1,
                name: "A".to_string(),
                fields: Vec::new(),
            },
            VariantDef {
                id: 2,
                name: "B".to_string(),
                fields: Vec::new(),
            },
        ],
        UnknownVariantPolicy::Reject,
    );

    let report = diff(&old_reject, &new);
    assert_eq!(report.new_reads_old, CompatibilityClass::Compatible);
    assert_eq!(report.old_reads_new, CompatibilityClass::Incompatible);

    let report = diff(&old_preserve, &new);
    assert_eq!(report.old_reads_new, CompatibilityClass::Compatible);
    assert_eq!(report.old_preserves_new, CompatibilityClass::Compatible);
}
