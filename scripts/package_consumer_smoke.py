#!/usr/bin/env python3
"""Build and run a consumer using only cargo-package output."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]
PACKAGES = {
    "sacp-cbor": ROOT / "Cargo.toml",
    "sacp-cbor-derive": ROOT / "sacp-cbor-derive" / "Cargo.toml",
    "sacp-cbor-schema": ROOT / "sacp-cbor-schema" / "Cargo.toml",
    "sacp-cbor-abi": ROOT / "sacp-cbor-abi" / "Cargo.toml",
    "sacp-cbor-abi-derive": ROOT / "sacp-cbor-abi-derive" / "Cargo.toml",
}


def version(manifest: Path) -> str:
    return tomllib.loads(manifest.read_text(encoding="utf-8"))["package"]["version"]


def toml_string(value: str) -> str:
    return json.dumps(value)


def main() -> None:
    versions = {name: version(manifest) for name, manifest in PACKAGES.items()}
    extracted = {
        name: ROOT / "target" / "package" / f"{name}-{versions[name]}"
        for name in PACKAGES
    }
    for name, package_dir in extracted.items():
        archive = package_dir.parent / f"{name}-{versions[name]}.crate"
        if not archive.is_file() or not package_dir.is_dir():
            raise SystemExit(
                f"missing cargo package output for {name}: {archive} and {package_dir}"
            )

    patch_lines = ["[patch.crates-io]"]
    for name in sorted(extracted):
        patch_lines.append(
            f'{name} = {{ path = {toml_string(extracted[name].as_posix())} }}'
        )

    manifest = f'''[workspace]

[package]
name = "packaged-tarball-consumer"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
sacp-cbor = {{ version = "={versions["sacp-cbor"]}", features = ["derive"] }}
sacp-cbor-schema = "={versions["sacp-cbor-schema"]}"
sacp-cbor-abi = {{ version = "={versions["sacp-cbor-abi"]}", features = ["derive"] }}

{chr(10).join(patch_lines)}
'''
    source = r'''use sacp_cbor::{CborDecode, CborEncode, DecodeLimits};
use sacp_cbor_abi::CborAbi;
use sacp_cbor_schema::{FieldDef, FieldType, RecordDef, RecordSchema};

#[derive(Debug, PartialEq, Eq, CborEncode, CborDecode)]
struct NativeMessage {
    id: u64,
    body: String,
}

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(type_id = "smoke.PublicMessage", version = 1)]
struct PublicMessage {
    #[abi(id = 1)]
    id: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let native = NativeMessage { id: 7, body: "ready".to_owned() };
    let bytes = sacp_cbor::encode_to_vec(&native)?;
    let decoded: NativeMessage = sacp_cbor::decode(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
    )?;
    assert_eq!(decoded, native);

    let public = PublicMessage { id: 9 };
    let abi_bytes = sacp_cbor_abi::encode_to_vec(&public)?;
    let abi_decoded: PublicMessage = sacp_cbor_abi::decode(
        &abi_bytes,
        DecodeLimits::for_bytes(abi_bytes.len()),
    )?;
    assert_eq!(abi_decoded, public);

    let schema = RecordSchema::compile(&RecordDef {
        fields: vec![FieldDef {
            key: "id".to_owned(),
            ty: FieldType::Int,
            required: true,
            constraints: vec![],
        }],
        couplings: vec![],
    })?;
    let witness = schema.validate(
        &[0xa1, 0x62, b'i', b'd', 0x09],
        DecodeLimits::for_bytes(5),
        sacp_cbor::ValidationOptions::new(),
    )?;
    schema.check(witness)?;
    Ok(())
}
'''

    with tempfile.TemporaryDirectory(prefix="sacp-cbor-package-consumer-") as temp:
        consumer = Path(temp)
        (consumer / "src").mkdir()
        (consumer / "Cargo.toml").write_text(manifest, encoding="utf-8")
        (consumer / "src" / "main.rs").write_text(source, encoding="utf-8")
        subprocess.run(
            ["cargo", "run", "--quiet", "--manifest-path", str(consumer / "Cargo.toml")],
            cwd=consumer,
            check=True,
        )

        minimal_consumers = {
            "core-no-default": (
                f'sacp-cbor = {{ version = "={versions["sacp-cbor"]}", default-features = false }}'
            ),
            "abi-no-default": (
                f'sacp-cbor-abi = {{ version = "={versions["sacp-cbor-abi"]}", default-features = false }}'
            ),
            "schema-no-default": (
                f'sacp-cbor-schema = {{ version = "={versions["sacp-cbor-schema"]}", default-features = false }}'
            ),
        }
        for name, dependency in minimal_consumers.items():
            minimal = consumer / name
            (minimal / "src").mkdir(parents=True)
            minimal_manifest = f'''[workspace]

[package]
name = "{name}"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
{dependency}

{chr(10).join(patch_lines)}
'''
            (minimal / "Cargo.toml").write_text(minimal_manifest, encoding="utf-8")
            (minimal / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
            subprocess.run(
                ["cargo", "check", "--quiet", "--manifest-path", str(minimal / "Cargo.toml")],
                cwd=minimal,
                check=True,
            )

    print("packaged tarball consumer and no-default-feature smokes passed")


if __name__ == "__main__":
    main()
