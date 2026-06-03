#[test]
fn abi_schema_errors_fail_to_compile() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/missing_field_id.rs");
    t.compile_fail("tests/ui/duplicate_field_id.rs");
    t.compile_fail("tests/ui/required_option.rs");
    t.compile_fail("tests/ui/tuple_struct.rs");
    t.compile_fail("tests/ui/duplicate_variant_id.rs");
}
