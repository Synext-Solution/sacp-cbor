# sacp-cbor

`sacp-cbor` is a **strict, deterministic CBOR** implementation of the **SACP-CBOR/1** profile from the
**Synext Agent Control Protocol (SACP)**.

It is designed for **hot-path** validation (WebSocket frames, API request bodies) with:

- allocation-free validation on success (`validate_canonical`)
- allocation-free queries on validated bytes (borrowed views, no decoding)
- deterministic map ordering enforcement (canonical CBOR key ordering, by encoded key bytes)
- strict canonical integer/length encoding checks (shortest form)
- strict numeric rules (safe integers, bignums via tags 2/3, float64-only, canonical NaN, forbid `-0.0`)
- strict tag rules (only bignum tags 2 and 3)
- `no_std` support (with optional `alloc` for owned types)

This crate intentionally keeps the core small and uncompromising. If bytes validate under SACP-CBOR/1,
they are already canonical; therefore, for opaque payloads, **semantic equality reduces to byte equality**.

## SACP-CBOR/1 profile (explicit)

**Allowed data model**

- Single CBOR item only (no trailing bytes).
- Definite-length items only (no indefinite-length encodings).
- Map keys must be text strings (major 3) and valid UTF-8.
- Only tags 2 and 3 are allowed (bignums), and bignums must be canonical and outside the safe-int range.
- Integers (major 0/1) must be in the safe range `[-(2^53-1), +(2^53-1)]`.
- Floats must be encoded as float64 (major 7, ai=27), forbid `-0.0`, and require the canonical NaN bit pattern.
- Only simple values `false`, `true`, and `null` are allowed.

**Canonical encoding constraints**

- Minimal integer/length encoding (no overlong forms).
- Map keys are strictly increasing by canonical CBOR key ordering:
  `(encoded length, then lexicographic encoded bytes)`.

## Status

- Version: `0.3.0`
- License: MIT
- MSRV: Rust `1.75`

## Features

| Feature | Default | Meaning                                                                                   |
|---------|---------|-------------------------------------------------------------------------------------------|
| `std`   | yes     | Implements `std::error::Error` for `CborError`.                                           |
| `alloc` | yes     | Enables owned AST types (`CborValue`, `CborMap`, `CanonicalCbor`) and canonical encoding. |
| `sha2`  | yes     | Enables SHA-256 helpers for canonical CBOR bytes (`sha256()`).                            |
| `serde` | no      | Enables serde-based conversions to/from canonical CBOR (`to_vec`, `from_slice`).          |

Note: `serde` currently requires `std` + `alloc`.

### `no_std` usage

- **Validation-only** (no allocation): disable default features:

```toml
sacp-cbor = { version = "0.3", default-features = false }
```

- **`no_std` + `alloc`** (owned values + encoding): enable `alloc`:

```toml
sacp-cbor = { version = "0.3", default-features = false, features = ["alloc"] }
```

- **`no_std` + `alloc` + `sha2`**:

```toml
sacp-cbor = { version = "0.3", default-features = false, features = ["alloc", "sha2"] }
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

### Build an owned AST with `cbor!` (requires `alloc`)

```rust
use sacp_cbor::cbor;

let user_key = "dynamic";
let v = cbor!({
    a: 1,
    (user_key): [true, null, 1.5],
})?;

assert_eq!(v.encode_canonical()?, vec![
    0xa2, 0x61, 0x61, 0x01,
    0x67, 0x64, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63,
    0x83, 0xf5, 0xf6, 0xfb, 0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);
# Ok::<(), sacp_cbor::CborError>(())
```

### Query canonical bytes without decoding

```rust
use sacp_cbor::{validate_canonical, DecodeLimits, PathElem};

// { "user": { "id": 42, "active": true } }
let bytes = [0xa1, 0x64, 0x75, 0x73, 0x65, 0x72, 0xa2, 0x62, 0x69, 0x64, 0x18, 0x2a, 0x66, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0xf5];
let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len()))?;

let path = [PathElem::Key("user"), PathElem::Key("id")];
let v = canon.at(&path)?.unwrap();
assert_eq!(v.integer()?.as_i64(), Some(42));
# Ok::<(), sacp_cbor::CborError>(())
```

```rust
use sacp_cbor::{validate_canonical, DecodeLimits};

// { "a": 1, "b": 2, "c": 3 }
let bytes = [0xa3, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02, 0x61, 0x63, 0x03];
let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len()))?;
let map = canon.root().map()?;

let out = map.get_many_sorted(["a", "b", "c"])?;
assert_eq!(out[1].unwrap().integer()?.as_i64(), Some(2));
# Ok::<(), sacp_cbor::QueryError>(())
```

### Serde encode/decode (requires `serde` + `alloc`)

```rust
use serde::{Deserialize, Serialize};
use sacp_cbor::{from_slice, to_vec, DecodeLimits};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Msg {
    op: String,
    n: u64,
}

let msg = Msg {
    op: "ping".to_string(),
    n: 42,
};

let bytes = to_vec(&msg)?;
let decoded: Msg = from_slice(&bytes, DecodeLimits::for_bytes(bytes.len()))?;
assert_eq!(msg, decoded);
# Ok::<(), sacp_cbor::CborError>(())
```

### Serde helper for `CborValue` fields (requires `serde` + `alloc`)

```rust
use serde::{Deserialize, Serialize};
use sacp_cbor::{cbor, from_slice, to_vec, DecodeLimits, CborValue};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Envelope {
    #[serde(with = "sacp_cbor::serde_value")]
    details: CborValue,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct OptionalEnvelope {
    #[serde(with = "sacp_cbor::serde_value::option")]
    details: Option<CborValue>,
}

let msg = Envelope {
    details: cbor!({"a": 1, "b": [true, null]})?,
};

let bytes = to_vec(&msg)?;
let decoded: Envelope = from_slice(&bytes, DecodeLimits::for_bytes(bytes.len()))?;
assert_eq!(msg, decoded);
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
- `cbor!(...) -> Result<CborValue, CborError>` *(feature `alloc`)*
- `cbor_equal(a, b) -> bool` *(feature `alloc`)*
- `CanonicalCborRef::root() -> CborValueRef`
- `CanonicalCborRef::at(path) -> Option<CborValueRef>`
- `CborValueRef::{kind, integer, map, array, get_key, get_index, at}`
- `MapRef::{get, get_many_sorted, iter}`
- `MapRef::get_many(keys) -> Vec<Option<CborValueRef>>` *(feature `alloc`)*
- `to_vec<T: Serialize>(&T) -> Vec<u8>` *(feature `serde` + `alloc`)*
- `from_slice<T: DeserializeOwned>(bytes, limits) -> T` *(feature `serde` + `alloc`)*
- `serde_value::{serialize, deserialize}` *(feature `serde`)*

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

## Coverage (llvm-cov + grcov)

Prerequisites:

```bash
rustup component add llvm-tools-preview
cargo install grcov
```

Run the coverage script:

```bash
./scripts/coverage.sh
```

The HTML report is generated at `./coverage/index.html`.

## License

MIT. See [`LICENSE`](LICENSE).
