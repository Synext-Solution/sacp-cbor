#![cfg(feature = "derive")]

#[test]
fn internal_tagged_tuple_variants_fail_to_derive() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/internal_tagged_tuple_variant.rs");
}

#[test]
fn empty_enums_fail_to_derive() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/empty_enum.rs");
}

#[test]
fn duplicate_renamed_fields_fail_to_derive() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/duplicate_field_keys.rs");
}

#[test]
fn default_fields_fail_to_derive() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/default_field.rs");
    t.compile_fail("tests/ui/skipped_field_rename.rs");
}

#[test]
fn duplicate_renamed_variants_fail_to_derive() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/duplicate_variant_names.rs");
}

#[test]
fn untagged_enums_fail_to_derive() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/ambiguous_untagged_enum.rs");
}

#[test]
fn external_tagged_enums_without_unit_variants_compile() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/external_tagged_data_variants.rs");
}

#[test]
fn internal_tagged_field_conflicts_fail_to_derive() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/internal_tagged_field_conflict.rs");
}
