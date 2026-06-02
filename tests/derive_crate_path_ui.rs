#![cfg(feature = "derive")]

#[test]
fn invalid_crate_paths_fail_to_derive() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/invalid_crate_path.rs");
    t.compile_fail("tests/ui/duplicate_crate_path.rs");
}

#[test]
fn unsupported_struct_container_attrs_fail_to_derive() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/struct_container_enum_attr.rs");
}
