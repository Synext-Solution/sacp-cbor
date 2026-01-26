# sacp-cbor

`sacp-cbor` is a **strict, deterministic CBOR** implementation of the **SACP-CBOR/1** profile from the
**Synext Agent Control Protocol (SACP)**.

It is designed for **hot-path** validation (WebSocket frames, API request bodies) with:

- allocation-free validation on success (`validate_canonical`)
- deterministic map ordering enforcement (canonical CBOR key ordering, by encoded key bytes)
- strict canonical integer/length encoding checks (shortest form)
- strict numeric rules (safe integers, bignums via tags 2/3, float64-only, canonical NaN, forbid `-0.0`)
- strict tag rules (only bignum tags 2 and 3)
- `no_std` support (with optional `alloc` for owned types)

This crate intentionally keeps the core small and uncompromising. If bytes validate under SACP-CBOR/1,
they are already canonical; therefore, for opaque payloads, **semantic equality reduces to byte equality**.

## Status

- Version: `0.1.0`
- License: MIT
- MSRV: Rust `1.75`

## Features

| Feature | Default | Meaning                                                                                   |
|---------|---------|-------------------------------------------------------------------------------------------|
| `std`   | yes     | Implements `std::error::Error` for `CborError`.                                           |
| `alloc` | yes     | Enables owned AST types (`CborValue`, `CborMap`, `CanonicalCbor`) and canonical encoding. |
| `sha2`  | yes     | Enables SHA-256 helpers for canonical CBOR bytes (`sha256()`).                            |

### `no_std` usage

- **Validation-only** (no allocation): disable default features:

```toml
sacp-cbor = { version = "0.1", default-features = false }
```

- **`no_std` + `alloc`** (owned values + encoding): enable `alloc`:

```toml
sacp-cbor = { version = "0.1", default-features = false, features = ["alloc"] }
```

- **`no_std` + `alloc` + `sha2`**:

```toml
sacp-cbor = { version = "0.1", default-features = false, features = ["alloc", "sha2"] }
```

Note: `alloc` requires an allocator provided by your environment.

## Quick start

### Validate SACP-CBOR/1 bytes (hot path)

```rust
use sacp_cbor::{validate_canonical, DecodeLimits};

fn handle_frame(bytes: &[u8]) -> Result<(), sacp_cbor::CborError> {
    let limits = DecodeLimits::for_bytes(bytes.len());
    let canonical = validate_canonical(bytes, limits)?;
    // At this point: SACP-CBOR/1 is satisfied, and `bytes` are canonical.
    let _stable_bytes = canonical.as_bytes();
    Ok(())
}
```

### Decode into an owned AST (requires `alloc`)

```rust
use sacp_cbor::{decode_value, DecodeLimits};

let bytes = [0xa1, 0x61, 0x61, 0x01]; // {"a":1}
let v = decode_value(&bytes, DecodeLimits::for_bytes(bytes.len()))?;
assert_eq!(v.encode_canonical()?, bytes);
# Ok::<(), sacp_cbor::CborError>(())
```

### Hash canonical bytes (requires `sha2`)

```rust
use sacp_cbor::{validate_canonical, DecodeLimits};

let bytes = [0xa1, 0x61, 0x61, 0x01];
let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len()))?;
let digest = canon.sha256();
```

## API overview

- `validate_canonical(bytes, limits) -> CanonicalCborRef`
- `validate(bytes, limits) -> ()`
- `decode_value(bytes, limits) -> CborValue` *(feature `alloc`)*
- `CborValue::encode_canonical() -> Vec<u8>` *(feature `alloc`)*
- `cbor_equal(a, b) -> bool` *(feature `alloc`)*

## Fuzzing

This repository includes `cargo-fuzz` targets under `./fuzz`.

Prerequisites:

```bash
cargo install cargo-fuzz
rustup toolchain install nightly
```

Run:

```bash
cd fuzz
cargo +nightly fuzz run validate_roundtrip
cargo +nightly fuzz run validate_only
```

The fuzz targets:

- validate arbitrary bytes under strict limits
- when validation succeeds, decode and re-encode and assert roundtrip identity

## Benchmarks

Criterion benchmarks are under `./benches`.

Run:

```bash
cargo bench
```

## License

MIT. See [`LICENSE`](LICENSE).
