use sacp_cbor_abi::{
    diff, diff_with_policy, CompatibilityClass, CompatibilityPolicy, FieldDef, Schema, TypeDef,
    UnknownFieldPolicy, VariantDef,
};

fn field(id: u32, ty: &str, optional: bool) -> FieldDef {
    FieldDef {
        id,
        name: format!("f{id}"),
        ty: ty.to_string(),
        optional,
    }
}

fn schema(fields: Vec<FieldDef>) -> Schema {
    Schema::new(
        "example.Type",
        1,
        TypeDef::Struct {
            fields,
            unknown_fields: UnknownFieldPolicy::Reject,
        },
    )
}

#[test]
fn optional_field_addition_is_compatible_by_default() {
    let old = schema(vec![field(1, "u64", false)]);
    let new = schema(vec![field(1, "u64", false), field(2, "String", true)]);
    let report = diff(&old, &new);
    assert_eq!(report.class, CompatibilityClass::Compatible);
}

#[test]
fn required_field_addition_and_type_changes_are_incompatible() {
    let old = schema(vec![field(1, "u64", false)]);
    let new_required = schema(vec![field(1, "u64", false), field(2, "String", false)]);
    assert_eq!(
        diff(&old, &new_required).class,
        CompatibilityClass::Incompatible
    );

    let changed_type = schema(vec![field(1, "String", false)]);
    assert_eq!(
        diff(&old, &changed_type).class,
        CompatibilityClass::Incompatible
    );

    let changed_optionality = schema(vec![field(1, "u64", true)]);
    assert_eq!(
        diff(&old, &changed_optionality).class,
        CompatibilityClass::Incompatible
    );
}

#[test]
fn profile_and_unknown_policy_changes_are_incompatible() {
    let old = schema(vec![field(1, "u64", false)]);
    let mut changed_profile = old.clone();
    changed_profile.profile = "other".to_string();
    assert_eq!(
        diff(&old, &changed_profile).class,
        CompatibilityClass::Incompatible
    );

    let changed_policy = Schema::new(
        "example.Type",
        1,
        TypeDef::Struct {
            fields: vec![field(1, "u64", false)],
            unknown_fields: UnknownFieldPolicy::Ignore,
        },
    );
    assert_eq!(
        diff(&old, &changed_policy).class,
        CompatibilityClass::Incompatible
    );
}

#[test]
fn enum_variant_addition_is_policy_controlled() {
    let old = Schema::new(
        "example.Enum",
        1,
        TypeDef::Enum {
            variants: vec![VariantDef {
                id: 1,
                name: "A".to_string(),
                fields: Vec::new(),
            }],
            unknown_fields: UnknownFieldPolicy::Reject,
        },
    );
    let new = Schema::new(
        "example.Enum",
        2,
        TypeDef::Enum {
            variants: vec![
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
            unknown_fields: UnknownFieldPolicy::Reject,
        },
    );

    assert_eq!(diff(&old, &new).class, CompatibilityClass::Incompatible);
    assert_eq!(
        diff_with_policy(
            &old,
            &new,
            CompatibilityPolicy {
                allow_optional_field_additions: true,
                allow_variant_additions: true,
            },
        )
        .class,
        CompatibilityClass::Compatible
    );
}
