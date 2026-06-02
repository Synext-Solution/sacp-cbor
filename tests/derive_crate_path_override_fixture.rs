#![cfg(feature = "derive")]

use std::path::PathBuf;
use std::process::Command;

#[test]
fn renamed_dependency_facade_fixture_compiles_and_tests() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = root
        .join("tests")
        .join("fixtures")
        .join("derive_crate_path_override")
        .join("Cargo.toml");
    let target_dir = root
        .join("target")
        .join("derive-crate-path-override-fixture");

    let status = Command::new(env!("CARGO"))
        .arg("test")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(manifest)
        .arg("--target-dir")
        .arg(target_dir)
        .status()
        .expect("fixture cargo test should start");

    assert!(status.success(), "fixture cargo test failed");
}
