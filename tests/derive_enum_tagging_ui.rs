#[test]
fn internal_tagged_tuple_variants_fail_to_derive() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/internal_tagged_tuple_variant.rs");
}
