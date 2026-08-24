#[test]
fn traversal_brands_reject_cross_decoder_tokens() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/traversal_cross_decoder_outer_to_inner.rs");
    t.compile_fail("tests/ui/traversal_cross_decoder_inner_to_outer.rs");
    t.compile_fail("tests/ui/traversal_session_escape.rs");
}
