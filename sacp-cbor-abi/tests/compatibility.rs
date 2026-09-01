use sacp_cbor::EncodeLimits;
use sacp_cbor_abi::{
    diff, CompatibilityClass, EnumDef, FieldDef, FieldPresence, FieldSetDef, Schema, TypeDef,
    TypeRef, UnknownFieldPolicy, UnknownVariantPolicy, VariantDef,
};

fn limits() -> EncodeLimits {
    EncodeLimits::for_bytes(4096)
}

#[test]
fn optional_field_addition_is_directional() {
    static NEW: Schema = Schema::new(
        "example.Type",
        1,
        TypeDef::Struct(FieldSetDef::new(
            &[
                FieldDef::new(1, "f1", TypeRef::U64, FieldPresence::Required),
                FieldDef::new(2, "f2", TypeRef::TEXT, FieldPresence::Optional),
            ],
            UnknownFieldPolicy::Reject,
        )),
    );
    static OLD_REJECT: Schema = Schema::new(
        "example.Type",
        1,
        TypeDef::Struct(FieldSetDef::new(
            &[FieldDef::new(
                1,
                "f1",
                TypeRef::U64,
                FieldPresence::Required,
            )],
            UnknownFieldPolicy::Reject,
        )),
    );
    static OLD_IGNORE: Schema = Schema::new(
        "example.Type",
        1,
        TypeDef::Struct(FieldSetDef::new(
            &[FieldDef::new(
                1,
                "f1",
                TypeRef::U64,
                FieldPresence::Required,
            )],
            UnknownFieldPolicy::Ignore,
        )),
    );
    static OLD_PRESERVE: Schema = Schema::new(
        "example.Type",
        1,
        TypeDef::Struct(FieldSetDef::new(
            &[FieldDef::new(
                1,
                "f1",
                TypeRef::U64,
                FieldPresence::Required,
            )],
            UnknownFieldPolicy::Preserve,
        )),
    );

    let report = diff(&OLD_REJECT, &NEW);
    assert_eq!(report.new_reads_old, CompatibilityClass::Compatible);
    assert_eq!(report.old_reads_new, CompatibilityClass::Incompatible);
    assert_eq!(report.old_preserves_new, CompatibilityClass::Incompatible);

    let report = diff(&OLD_IGNORE, &NEW);
    assert_eq!(report.old_reads_new, CompatibilityClass::Compatible);
    assert_eq!(report.old_preserves_new, CompatibilityClass::Incompatible);

    let report = diff(&OLD_PRESERVE, &NEW);
    assert_eq!(report.old_reads_new, CompatibilityClass::Compatible);
    assert_eq!(report.old_preserves_new, CompatibilityClass::Compatible);
}

#[test]
fn required_field_addition_blocks_new_reads_old() {
    static OLD: Schema = Schema::new(
        "example.Type",
        1,
        TypeDef::Struct(FieldSetDef::new(
            &[FieldDef::new(
                1,
                "f1",
                TypeRef::U64,
                FieldPresence::Required,
            )],
            UnknownFieldPolicy::Ignore,
        )),
    );
    static NEW: Schema = Schema::new(
        "example.Type",
        1,
        TypeDef::Struct(FieldSetDef::new(
            &[
                FieldDef::new(1, "f1", TypeRef::U64, FieldPresence::Required),
                FieldDef::new(2, "f2", TypeRef::TEXT, FieldPresence::Required),
            ],
            UnknownFieldPolicy::Reject,
        )),
    );

    let report = diff(&OLD, &NEW);
    assert_eq!(report.new_reads_old, CompatibilityClass::Incompatible);
    assert_eq!(report.old_reads_new, CompatibilityClass::Compatible);
}

#[test]
fn type_change_is_incompatible_in_every_direction() {
    static OLD: Schema = Schema::new(
        "example.Type",
        1,
        TypeDef::Struct(FieldSetDef::new(
            &[FieldDef::new(
                1,
                "f1",
                TypeRef::U64,
                FieldPresence::Required,
            )],
            UnknownFieldPolicy::Preserve,
        )),
    );
    static NEW: Schema = Schema::new(
        "example.Type",
        1,
        TypeDef::Struct(FieldSetDef::new(
            &[FieldDef::new(
                1,
                "f1",
                TypeRef::TEXT,
                FieldPresence::Required,
            )],
            UnknownFieldPolicy::Preserve,
        )),
    );

    let report = diff(&OLD, &NEW);
    assert_eq!(report.new_reads_old, CompatibilityClass::Incompatible);
    assert_eq!(report.old_reads_new, CompatibilityClass::Incompatible);
    assert_eq!(report.old_preserves_new, CompatibilityClass::Incompatible);
}

#[test]
fn metadata_rename_keeps_wire_hash_and_read_compatibility() {
    static OLD: Schema = Schema::new(
        "example.Type",
        1,
        TypeDef::Struct(FieldSetDef::new(
            &[FieldDef::new(
                1,
                "amount",
                TypeRef::U64,
                FieldPresence::Required,
            )],
            UnknownFieldPolicy::Reject,
        )),
    );
    static NEW: Schema = Schema::new(
        "example.Type",
        1,
        TypeDef::Struct(FieldSetDef::new(
            &[FieldDef::new(
                1,
                "units",
                TypeRef::U64,
                FieldPresence::Required,
            )],
            UnknownFieldPolicy::Reject,
        )),
    );

    assert_eq!(
        OLD.wire_hash(limits()).unwrap(),
        NEW.wire_hash(limits()).unwrap()
    );
    assert_ne!(
        OLD.full_hash(limits()).unwrap(),
        NEW.full_hash(limits()).unwrap()
    );

    let report = diff(&OLD, &NEW);
    assert_eq!(report.bidirectional, CompatibilityClass::Compatible);
    assert!(report
        .changes
        .iter()
        .any(|change| change.message == "field name changed"));
}

#[test]
fn enum_variant_addition_requires_unknown_variant_preservation() {
    static OLD_REJECT: Schema = Schema::new(
        "example.Enum",
        1,
        TypeDef::Enum(EnumDef::new(
            &[VariantDef::unit(1, "A")],
            UnknownVariantPolicy::Reject,
        )),
    );
    static OLD_PRESERVE: Schema = Schema::new(
        "example.Enum",
        1,
        TypeDef::Enum(EnumDef::new(
            &[VariantDef::unit(1, "A")],
            UnknownVariantPolicy::Preserve,
        )),
    );
    static NEW: Schema = Schema::new(
        "example.Enum",
        1,
        TypeDef::Enum(EnumDef::new(
            &[VariantDef::unit(1, "A"), VariantDef::unit(2, "B")],
            UnknownVariantPolicy::Reject,
        )),
    );

    let report = diff(&OLD_REJECT, &NEW);
    assert_eq!(report.new_reads_old, CompatibilityClass::Compatible);
    assert_eq!(report.old_reads_new, CompatibilityClass::Incompatible);

    let report = diff(&OLD_PRESERVE, &NEW);
    assert_eq!(report.old_reads_new, CompatibilityClass::Compatible);
    assert_eq!(report.old_preserves_new, CompatibilityClass::Compatible);
}
