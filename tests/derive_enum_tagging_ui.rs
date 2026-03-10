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
fn external_tagged_enums_without_unit_variants_compile() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/external_tagged_data_variants.rs");
}
