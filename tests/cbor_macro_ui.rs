#![cfg(feature = "derive")]

#[test]
fn cbor_bytes_unsupported_keys_fail_to_compile() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/cbor_bytes_unsupported_key.rs");
}

#[test]
fn cbor_bytes_duplicate_keys_fail_to_compile() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/cbor_bytes_duplicate_key.rs");
}
