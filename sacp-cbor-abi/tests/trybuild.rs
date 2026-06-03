#[test]
fn abi_schema_errors_fail_to_compile() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/missing_field_id.rs");
    t.compile_fail("tests/ui/duplicate_field_id.rs");
    t.compile_fail("tests/ui/required_option.rs");
    t.compile_fail("tests/ui/tuple_struct.rs");
    t.compile_fail("tests/ui/duplicate_variant_id.rs");
    t.compile_fail("tests/ui/unknown_fields_without_storage.rs");
    t.compile_fail("tests/ui/invalid_unknown_variant.rs");
    t.compile_fail("tests/ui/ty_version_without_ty.rs");
}
