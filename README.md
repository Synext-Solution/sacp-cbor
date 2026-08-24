# sacp-cbor

Strict canonical CBOR bytes validation + **zero-copy querying** + **canonical encoding** + **structural patching** (map/array edits) + optional **serde** + optional **SHA-256**.

This crate is intentionally **not** a general-purpose CBOR implementation. It enforces a **small, deterministic CBOR profile** designed for stable hashing, signatures, and safe interop.

---

## What you get

### Core capabilities

- **Validate** that an input is a *single, canonical* CBOR item under a strict profile (`validate_canonical`).
- Wrap validated bytes as `CanonicalCborRef<'a>` for **zero-copy querying** (`at`, `root`, `MapRef`, `ArrayRef`, `CborValueRef`).
- **Stream-decode with validation** in one pass: the checked `Decoder` applies the full canonical grammar while decoding, and `finish()` returns the canonical witness — no second traversal.
- Optionally **decode** into Rust types via `sacp_cbor::serde::from_slice` (`serde`).
- **Encode canonical CBOR** directly (`Encoder`, `encode::MapEncoder`, `encode::ArrayEncoder`) (`alloc`).
- Build canonical bytes with the **fallible** `cbor_bytes!` macro (`derive`).
- **Patch/edit** canonical bytes without decoding the whole structure (`edit::Editor`) (`edit`).
- **Bridge to RFC 8949 CDE**: total `cde::to_cde` and validating `cde::from_cde`, mutually inverse on the shared subset (`cde`).
- Optional:
  - **serde** conversion utilities (`serde`).
  - **SHA-256** helpers for canonical bytes / canonical-encoded values (`sha2`).

### Published crates

This repository publishes five crates with different responsibilities:

| Crate | Current line | Responsibility |
|---|---:|---|
| `sacp-cbor` | `0.18` | Canonical CBOR validation, zero-copy query, encoding, editing, and optional serde integration. |
| `sacp-cbor-derive` | `0.18` | Companion derive macros for the Rust-shape codec; normally enabled through `sacp-cbor`'s `derive` feature. |
| `sacp-cbor-schema` | `0.2` | Closed-record schema validation over canonical values, with explicit compile/validation limits and replayable inclusion results. |
| `sacp-cbor-abi` | `0.7` | Stable public ABI schemas, numeric field/variant IDs, structural runtime admission, compatibility reports, and zero-copy ABI views. |
| `sacp-cbor-abi-derive` | `0.4` | Companion `#[derive(CborAbi)]` macro; normally enabled through `sacp-cbor-abi`'s default `derive` feature. |

Use `sacp-cbor` for canonical CBOR infrastructure and internal Rust-shape codecs. Use
`sacp-cbor-abi` for public protocols that must remain stable across Rust refactors. Use
`sacp-cbor-schema` to admit data against a declared closed-record schema (field types, value
constraints, presence couplings) in the same traversal that validates the canonical grammar.

### Design constraints (important)

This crate enforces a strict “canonical profile”:

- **Single item** only (no trailing bytes).
- **Definite-length** only (indefinite lengths forbidden).
- **Map keys must be UTF-8 text strings**, and maps must be in **canonical order** (see below).
- **Integers**
  - “Safe” integers only: `[-(2^53-1), +(2^53-1)]`.
  - Larger magnitude integers must use **CBOR bignum tags**:
    - tag `2` (positive bignum)
    - tag `3` (negative bignum)
  - Bignum magnitudes must be canonical (non-empty, no leading zero) and must be **outside** the safe integer range.
- **Floats**
  - Only **float64** encoding is accepted/emitted.
  - **Negative zero** is forbidden.
  - **NaN** must use a single canonical NaN bit pattern.
- **Simple values**
  - Only `false`, `true`, and `null` are supported (plus float64, encoded under major type 7).
  - Other simple values are rejected.

Two profile semantics are fixed and documented in [`SPEC.md`](SPEC.md):

- **Text identity:** no Unicode normalization; text equality is UTF-8 byte equality. Producers
  that require a normal form (such as NFC) must normalize before encoding.
- **Validation modes:** `ValidationOptions` selects optional restriction modes that only reject
  more inputs. The **no-float mode** (`no_float()`) rejects float64 anywhere in the item; the
  **no-simple mode** (`no_simple()`) rejects `false`, `true`, and `null` — for deployments whose
  durable data model excludes floating point or has no boolean/null values.

If you need tags beyond bignums, indefinite lengths, non-text map keys, half/float32 encodings, etc., this crate is the wrong tool.

The maintained wire/profile contract lives in [`SPEC.md`](SPEC.md).

---

## Feature flags

This crate supports `no_std` when default features are disabled. Default features enable `std` and `derive`; `std` enables `alloc`.

| Feature | Enables | Notes |
|---|---|---|
| `std` | `std::error::Error` for `CborError` + `alloc` APIs | Otherwise `no_std` |
| `alloc` | Owned types + encoding | Required for `CanonicalCbor` and `Encoder` |
| `derive` | `#[derive(CborEncode, CborDecode)]` + `cbor_bytes!` | Requires `alloc`; enabled by default |
| `collections` | Native collection impls + `collections::MapEntries` | Requires `alloc` |
| `edit` | Structural patching under `sacp_cbor::edit` | Requires `alloc` |
| `cde` | RFC 8949 CDE bridge under `sacp_cbor::cde` | Requires `alloc` |
| `serde` | serde integration under `sacp_cbor::serde` | Requires `alloc` |
| `sha2` | SHA-256 helpers | Uses `sha2` crate |
| `simdutf8` | Faster UTF-8 validation | Optional SIMD validation, same semantics |
| `unsafe` | Unchecked UTF-8 for canonical-trusted reads | Uses `unsafe` only for canonical-validated inputs |

### Recommended dependency configs

**Default Rust (std + alloc):**
```toml
[dependencies]
sacp-cbor = "0.18"
```

**`no_std` + `alloc`:**
```toml
[dependencies]
sacp-cbor = { version = "0.18", default-features = false, features = ["alloc"] }
```

**`std` + serde + sha2:**
```toml
[dependencies]
sacp-cbor = { version = "0.18", default-features = false, features = ["std", "serde", "sha2"] }
```

> In Rust code the crate name is typically `sacp_cbor` (hyphen becomes underscore).

### Minimum supported Rust versions

- `sacp-cbor`, `sacp-cbor-abi`, and `sacp-cbor-schema`: Rust 1.85. The core and ABI
  lines expose SHA-2 0.11, whose supported compiler floor is Rust 1.85; schema's normal
  dependency closure includes the core crate.
- `sacp-cbor-derive` and `sacp-cbor-abi-derive`: Rust 1.75. These proc-macro crates do
  not depend on the runtime or SHA-2.

---

## Canonical profile rules

### Canonical map ordering (text keys only)

Maps must be sorted by the **encoded CBOR bytes of the key**, using:

1. **Encoded length** ascending (shorter encoded key bytes come first)
2. If equal length, **lexicographic** order of the encoded bytes

Because keys are text strings, the encoded key is:

- a text header (1/2/3/5/9 bytes depending on string length), followed by
- UTF-8 bytes of the key

For most “small keys” (< 24 bytes), the header is 1 byte, so the order is effectively:

- shorter key first, then
- lexicographic order of UTF-8 bytes

But note: at lengths 24, 256, 65536, … the header grows, which affects the encoded length ordering.

### Safe integer range

The safe integer range is:

- `MIN_SAFE_INTEGER = -(2^53 - 1)`
- `MAX_SAFE_INTEGER = +(2^53 - 1)`

Constants are exported from `sacp_cbor::profile`:

- `MAX_SAFE_INTEGER: u64`
- `MAX_SAFE_INTEGER_I64: i64`
- `MIN_SAFE_INTEGER: i64`

Integers outside that range must be encoded as bignum (tag 2 or 3), and bignums are *required* to be outside safe range (i.e., you cannot represent a safe integer using a bignum).

### Float64 rules

- Only float64 encoding is allowed.
- `-0.0` is rejected.
- NaN must be canonicalized.

---

## Complexity model used in this README

- `n` = input byte length
- `d` = nesting depth
- `m` = number of entries in a map
- `a` = number of items in an array
- `k` = number of query keys in a multi-key operation
- “bytes scanned” means the implementation may need to walk CBOR structure boundaries using a value-end walker; this is proportional to the size of the traversed portion.

Where relevant, time complexity is **worst-case** unless noted.

---

## Quick start

### 1) Validate canonical bytes (no allocation required)

```rust
use sacp_cbor::{validate_canonical, DecodeLimits};

fn main() -> Result<(), sacp_cbor::CborError> {
  let input: &[u8] = /* ... */;

  // Choose limits (protects you from deep nesting / huge containers / etc.)
  let limits = DecodeLimits::for_bytes(input.len());

  // Validates: canonical, single item, strict profile
  let canon = validate_canonical(input, limits)?;

  // From here on you can do zero-copy queries:
  println!("validated {} bytes", canon.as_bytes().len());
  Ok(())
}
```

For float-free deployments, validate under the no-float restriction mode:

```rust
use sacp_cbor::{validate_canonical_with, DecodeLimits, ValidationOptions};

let input: &[u8] = /* ... */;
let limits = DecodeLimits::for_bytes(input.len());
let canon = validate_canonical_with(input, limits, ValidationOptions::new().no_float())?;
// Any float64 in the item is rejected with ErrorCode::FloatForbidden.
```

**Complexity**

- Time: `O(n)`
- Space: `O(d)` stack

  - **Without `alloc`**, validation uses a fixed inline stack sized for the default depth; extremely deep inputs can fail even if you raise `max_depth`.

### 2) Zero-copy query into a validated document

```rust
use sacp_cbor::{query::PathElem, validate_canonical, DecodeLimits};

fn main() -> Result<(), sacp_cbor::CborError> {
  let bytes: &[u8] = /* canonical bytes */;

  let canon = validate_canonical(bytes, DecodeLimits::for_bytes(bytes.len()))?;

  let path = [PathElem::Key("user"), PathElem::Key("id")];
  if let Some(id_ref) = canon.at(&path)? {
    let id = id_ref.integer()?.as_i64(); // Option<i64>, None if big integer
    println!("user.id: {id:?}");
  }

  Ok(())
}
```

**Complexity**

- `at(path)` time is proportional to what must be scanned in maps/arrays along the path:

  - Worst-case: `O(bytes scanned)`, often close to `O(n)` for pathological paths
  - Typical: shallow maps with early exits are much smaller
- Space: `O(1)`

---

## Limits and safety

### `DecodeLimits`

`DecodeLimits` is a public struct you pass to validation and decoding:

```rust
pub struct DecodeLimits {
  pub max_input_bytes: usize,
  pub max_depth: usize,
  pub max_total_items: usize,
  pub max_array_len: usize,
  pub max_map_len: usize,
  pub max_bytes_len: usize,
  pub max_text_len: usize,
}
```

Use `DecodeLimits::for_bytes(max_message_bytes)` for a reasonable baseline:

- `max_depth = 256`
- `max_total_items = max_message_bytes`
- `max_array_len/max_map_len = min(max_message_bytes, 1<<16)`
- `max_bytes_len/max_text_len = max_message_bytes`

**Why limits matter**

- Prevents “CBOR bombs” (huge containers, deeply nested data).
- Controls worst-case time and memory for validation and decoding.

Use separate `DecodeLimits` and `EncodeLimits` values for distinct budgets. The core exposes only
the primitive limit types; protocol-specific pairings belong at the protocol layer.

---

## Zero-copy query API

All query APIs operate on **validated canonical bytes** (via `CanonicalCborRef` / `CanonicalCbor`) and return lightweight views from `sacp_cbor::query` into the underlying buffer.

### `CanonicalCborRef<'a>`

How you obtain it:

- returned by `validate_canonical(&[u8], DecodeLimits)`

Key methods:

- `as_bytes() -> &'a [u8]` (`O(1)`)
- `root() -> CborValueRef<'a>` (`O(1)`)
- `at(path: &[PathElem]) -> Result<Option<CborValueRef>, CborError>`

  - Time: `O(bytes scanned)`
  - Space: `O(1)`

Optional:

- `sha256() -> [u8; 32]` (`sha2`) — `O(n)`
- `to_owned() -> Result<CanonicalCbor, CborError>` (`alloc`) — `O(n)` copy + alloc
- `editor()/edit(...)` (`alloc`) — see “Editing”

### `CanonicalCbor` (owned, `alloc`)

How you obtain it:

- `CanonicalCbor::from_slice(bytes, limits)` validates + copies
- or from an `Encoder` (`finish()`)
- or from an `edit::Editor::apply()`

Key methods:

- `as_bytes() -> &[u8]` (`O(1)`)
- `into_bytes() -> Vec<u8>` (`O(1)` move)
- `root()/at(...)` same as `CanonicalCborRef`
- `sha256()` (`sha2`) — `O(n)`
- `edit(...)` (`alloc`) — see “Editing”

### `PathElem`

```rust
use sacp_cbor::query::PathElem;

let p1 = [
  PathElem::Key("a"),
  PathElem::Key("b"),
  PathElem::Index(0),
  PathElem::Key("c"),
];
let p2 = [PathElem::Key("a"), PathElem::Index(0)];
```

- `PathElem::Key(&str)`
- `PathElem::Index(usize)`

**Complexity**

- Path construction is ordinary slice/array construction; traversal cost dominates.
- Query traversal cost depends on containers traversed.

### `CborValueRef<'a>`

`CborValueRef` is a view into a contiguous CBOR value within a canonical buffer.

Key methods (behavior + complexity):

- `as_bytes() -> &'a [u8]` — `O(1)`
- `offset() -> usize` — `O(1)` (byte offset in the original buffer)
- `byte_len() -> usize` — `O(1)`

Type/category inspection:

- `kind() -> Result<CborKind, CborError>`

  - Time: `O(1)` for header; may read small tag headers
- `is_null() -> bool` — `O(1)`

Container access:

- `map() -> Result<MapRef<'a>, CborError>`

  - Errors: `ExpectedMap` if not a map, or `MalformedCanonical` if corrupt
- `array() -> Result<ArrayRef<'a>, CborError>`

  - Errors: `ExpectedArray`, `MalformedCanonical`
- `get_key(&str) -> Result<Option<CborValueRef>, CborError>` (map lookup)
- `get_index(usize) -> Result<Option<CborValueRef>, CborError>` (array lookup)
- `at(path) -> Result<Option<CborValueRef>, CborError>` (path traversal)

Scalar decoding (zero-copy where possible):

- `integer() -> Result<IntegerRef<'a>, CborError>`

  - Returns `Safe(i64)` or `Big(BigIntRef)`
  - Time: `O(1)` + reads magnitude bytes for bigints
  - Errors: `ExpectedInteger`, `MalformedCanonical`
- `text() -> Result<&'a str, CborError>`

  - Time: `O(len)` due to UTF-8 validation
- `bytes() -> Result<&'a [u8], CborError>`

  - Time: `O(1)`
- `bool() -> Result<bool, CborError>` — `O(1)`
- `float64() -> Result<f64, CborError>` — `O(1)`

### `MapRef<'a>`

Obtain via `CborValueRef::map()?`.

Map APIs assume:

- keys are **text**, and
- map is **canonical key-sorted**

Key methods:

- `len()`, `is_empty()` — `O(1)`

Single key lookup:

- `get(key: &str) -> Result<Option<CborValueRef>, CborError>`

  - Time: `O(bytes scanned in map until match or early-exit)`
  - Early-exit: once map key > query key (canonical order), returns `None`
  - Errors: `MalformedCanonical`, or `LengthOverflow` if query key is absurdly large

- `require(key) -> Result<CborValueRef, CborError>`

  - Same as `get`, but returns `MissingKey` if not found

Multi-key lookup:

- `get_many_sorted<const N: usize>(keys: [&str; N]) -> Result<[Option<CborValueRef>; N], CborError>`
- `require_many_sorted<const N: usize>(keys: [&str; N]) -> Result<[CborValueRef; N], CborError>`

These functions:

- validate key sizes
- require keys to be strictly increasing by canonical key encoding
- scan the map once (merge-like scan)

**Complexity**

- Time: `O(k * L + bytes scanned in map)`
  where `k = N`, `L` = average key length used in comparisons.
- Space: `O(k)` for the fixed output array; `get_many_sorted_into` is allocation-free

Dynamic multi-key lookup (`alloc`):

- `get_many(keys: &[&str]) -> Result<Vec<Option<CborValueRef>>, CborError>`
- `require_many(keys: &[&str]) -> Result<Vec<CborValueRef>>, CborError>`
- `get_many_into(keys, out)` (writes into caller-provided slice)

These accept keys in any order, allocate an index vector, sort by canonical key order, and preserve
the input key order in the result.

**Complexity**

- Time: `O(k log k * L + bytes scanned in map)`
- Space: `O(k)` for sorting indices

Iteration:

- `iter() -> impl Iterator<Item = Result<(&str, CborValueRef), CborError>>`

  - Full iteration: `O(bytes in map)`

Extras (fields not in a set of “used keys”):

- `extras_sorted(used_keys: &[&str]) -> Result<impl Iterator<...>, CborError>`

  - Requires `used_keys` to be **strictly increasing** in canonical key order (validated)
  - Time: `O(bytes in map + k)`
  - Space: `O(1)`

`alloc` helpers:

- `extras_sorted_vec(used_keys) -> Result<Vec<(&str, CborValueRef)>, CborError>`
- `extras_vec(used_keys) -> Result<Vec<(&str, CborValueRef)>, CborError>`

  - `extras_vec` sorts your keys internally (allocates)
  - Time: `O(k log k * L + bytes in map)`
  - Space: `O(k)` + output vec

### `ArrayRef<'a>`

Obtain via `CborValueRef::array()?`.

- `len()`, `is_empty()` — `O(1)`
- `get(index) -> Result<Option<CborValueRef>, CborError>`

  - Time: `O(bytes scanned up to index)` (because it walks item boundaries)
  - Space: `O(1)`
- `iter() -> impl Iterator<Item = Result<CborValueRef>, CborError>`

  - Full iteration: `O(bytes in array)`

---

### `Integer` / `BigInt` / `F64Bits`

These wrappers live under `sacp_cbor::value` and `sacp_cbor::scalar`.

- `Integer::safe(i64) -> Result<Integer, CborError>`
- `Integer::big(negative, magnitude: Vec<u8>) -> Result<Integer, CborError>`
- `BigInt::new(negative, magnitude: Vec<u8>) -> Result<BigInt, CborError>`

  - magnitude must be canonical and outside safe range
- `F64Bits::new(bits: u64) -> Result<F64Bits, CborError>`
- `F64Bits::try_from_f64(f64) -> Result<F64Bits, CborError>`

  - canonicalizes NaN and rejects -0.0

---

## Canonical encoding API (`alloc`)

`Encoder<S>` writes one canonical root value directly into any `ByteSink`.
There is one state machine for vector, counting, digest, I/O, serde, derive,
and custom-sink encoding. Native encoding and strict serde stream payloads
without staging them in a temporary `Vec`; the explicitly selected serde
`sorted_maps` mode buffers entries within the encoder's configured limits.

### `Encoder`

Create:

- `Encoder::new()`
- `Encoder::with_sink(sink)`
- `Encoder::with_sink_and_limits(sink, EncodeLimits)`
- `Encoder::try_with_capacity(usize) -> Result<Encoder, CborError>`
- `Encoder::with_limits(EncodeLimits) -> Result<Encoder, CborError>`
- `Encoder::try_with_capacity_and_limits(usize, EncodeLimits) -> Result<Encoder, CborError>`

Extract:

- `finish() -> Result<S::Output, EncodeError<S::Error>>` (only succeeds for exactly one complete root value)
- `as_bytes() -> &[u8]` on the vector-backed encoder (current buffer)
- `encode_to_canonical(&value)` when an owned canonical witness is required

Built-in sinks:

- `VecSink` returns `Vec<u8>`
- `CountingSink` returns the encoded byte count without retaining payload bytes
- `DigestSink<D>` hashes bytes incrementally (`sha2` feature)
- `IoSink<W>` writes with `std::io::Write` and returns the writer (`std` feature)

Write scalars:

- `null()`, `bool(bool)`
- `int(i64) -> Result<(), CborError>` (safe range enforced)
- `bignum(negative, magnitude: &[u8]) -> Result<(), CborError>` (canonical + outside safe range enforced)
- `bytes(&[u8])`, `text(&str)`
- `float(F64Bits)`

Write composites:

- `array(len, |arr| ...)`
- `map(len, |map| ...)`

Raw splice:

- `raw_cbor(CanonicalCborRef)` (copies bytes as-is into output)
- `raw_value_ref(CborValueRef)` (copies bytes as-is into output)

Limited encoders enforce output bytes, depth, item count, array/map length, and bytes/text length
before accepting writes. Raw splices are scanned against those limits before copying.

Every failure is sticky. The fallible encoding call that first fails returns
the precise `EncodeError::Cbor` or owned `EncodeError::Sink`; every later
fallible encoding or finish operation returns `EncodeError::Poisoned`.
Read-only observations remain available. `len()` counts only whole chunks whose
sink writes returned `Ok`, and `is_empty()` means that no such chunk was
confirmed; neither claims that a failing sink accepted no partial bytes. A sink
may accept part of a write before returning an error, so the generic encoder
never promises rollback.

**Key rule:** When emitting maps via `Encoder::map`, you must insert entries in **canonical key order** using `map.entry`. The encoder enforces this and will error if you violate it.

**Complexity**

- Encoding operations are proportional to the bytes written:

  - Time: `O(output_bytes)`
  - Space: sink storage + `O(depth + active_previous_key_bytes)` encoder state;
    each active map level retains one reusable previous-key string
- `map` ordering checks compare source text keys by canonical encoded length
  and UTF-8 bytes before emitting the next key:

  - Additional time: `O(total key bytes)` across all entries

### `encode::MapEncoder::entry`

Signature:

```rust
fn entry<F>(&mut self, key: &str, f: F) -> EncodeResult<(), S>
where
    F: FnOnce(&mut Encoder<S>) -> EncodeResult<(), S>;
```

Properties:

- Key must be text (`&str`), always.
- Enforces:

  - **no duplicate keys**
  - **strict canonical order**
- A duplicate or descending key is rejected before any byte of that offending
  key reaches the sink.
- Errors poison the encoder; bytes already accepted by the sink are not rolled back.

Errors you may see:

- `DuplicateMapKey`
- `NonCanonicalMapOrder`
- `MapLenMismatch` (if you write too many/few entries overall)
- plus anything your closure emits

**Complexity**

- Per entry: `O(key_len + value_bytes)` + ordering compare `O(key_len)`

### `encode::ArrayEncoder`

You must write exactly `len` items; otherwise:

- `ArrayLenMismatch`

**Complexity**

- `O(total written bytes)`

---

## Macros (`derive`)

### `#[cbor(crate = path::to::runtime)]`

`CborEncode` and `CborDecode` derive accept a container-level runtime path:

```rust
#[derive(CborEncode, CborDecode)]
#[cbor(crate = my_crate::codec::cbor)]
struct Msg {
    id: u64,
}
```

The path must name a module that exposes the derive runtime API:

```rust
pub mod cbor {
    pub use sacp_cbor::{
        ByteSink, CanonicalCbor, CborDecode, CborEncode, CborError, DecodeLimits, Decoder,
        EncodeResult, Encoder, ErrorCode, ValueEncoder, encode_with_to_canonical,
    };

    pub mod query {
        pub use sacp_cbor::query::{CborKind, CborValueRef};
    }
}
```

### `cbor_bytes!` — build canonical bytes directly (fallible)

- Produces `Result<CanonicalCbor, CborError>`
- Uses `Encoder` internally
- Sorts map keys at compile time (no runtime buffering)
- Map keys must be identifiers or string literals
- Rust repeat byte-array expressions such as `[0u8; 32]` are encoded via
  `CborEncode` as CBOR byte strings. Comma arrays such as `[1, 2, 3]` remain
  CBOR array literals. Use parentheses to force an ordinary Rust expression,
  e.g. `cbor_bytes!(([1u8, 2, 3]))`.

Example (keys can be written in any order):

```rust
use sacp_cbor::cbor_bytes;

let bytes = cbor_bytes!({
    "z": 3,
    "a": 1,
    "b": 2,
})?;
```

Facade crates can select the macro runtime path explicitly:

```rust
let bytes = cbor_bytes!(crate = my_crate::codec::cbor; { id: 7 })?;
```

Splicing existing canonical fragments (still copied into output, but no decoding/re-encoding):

```rust
use sacp_cbor::{cbor_bytes, validate_canonical, DecodeLimits};

let existing: &[u8] = /* canonical CBOR */;
let canon = validate_canonical(existing, DecodeLimits::for_bytes(existing.len()))?;

let out = cbor_bytes!([canon, 1, 2, 3])?; // array whose first element is the existing item
```

**Complexity**

- Time: `O(output_bytes)`
- Space: output buffer
- Map order enforcement: same as `Encoder`/`encode::MapEncoder`

---

## Stable public ABI (`sacp-cbor-abi`)

`#[derive(CborEncode, CborDecode)]` is intentionally a Rust-shape codec: it follows the Rust
container shape and is best for internal data. Public protocols should use the separate
`sacp-cbor-abi` crate, where field and variant identity is explicit, numeric, and stable across
renames, module moves, and private Rust refactors.

The ABI layer is opt-in:

```rust
use sacp_cbor::{DecodeLimits, CanonicalCbor};
use sacp_cbor_abi::{decode, encode_to_vec, AbiType, CborAbi};

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(type_id = "ledger.Transfer", version = 1)]
struct Transfer {
    #[abi(id = 1)]
    from: u64,
    #[abi(id = 2)]
    to: u64,
    #[abi(id = 3)]
    amount: u64,
    #[abi(id = 4, optional)]
    memo: Option<String>,
}

let value = Transfer {
    from: 1001,
    to: 2002,
    amount: 5000,
    memo: None,
};

let bytes = encode_to_vec(&value)?;
let decoded: Transfer = decode(&bytes, DecodeLimits::for_bytes(bytes.len()))?;
assert_eq!(decoded, value);

let wire_hash = Transfer::schema().wire_hash()?;
let full_hash = Transfer::schema().full_hash()?;
assert_ne!(wire_hash, full_hash);
```

### Wire contract

ABI structs encode as canonical field-set arrays:

```text
[field_id, value, field_id, value, ...]
```

For the `Transfer` above, `memo: None` is omitted and the logical wire shape is:

```text
[1, 1001, 2, 2002, 3, 5000]
```

Field IDs and variant IDs must be nonzero `u32` values. On the wire, ABI field-set IDs must be
strictly increasing; duplicate, decreasing, zero, and odd-length field-set arrays are rejected.
Required `Option<T>` fields are rejected at derive time; optional fields must be declared with
`#[abi(optional)]` and are omitted when `None`.

Enums encode as `[variant_id, payload]`. Unit variants use `null`; named variants use the same
field-set encoding as structs:

```rust
use sacp_cbor_abi::{CborAbi, UnknownVariant};

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(type_id = "ledger.Command", version = 1)]
enum Command {
    #[abi(id = 1)]
    Route {
        #[abi(id = 1)]
        transfer_id: String,
        #[abi(id = 2)]
        priority: u64,
    },
    #[abi(id = 2)]
    Ping,
    #[abi(unknown)]
    Unknown(UnknownVariant),
}
```

Unknown enum variants are rejected unless the enum has one `#[abi(unknown)]` variant. Preserved
unknown variants retain the numeric variant ID and the borrowed/owned canonical payload.

### Zero-copy views

`#[derive(CborAbi)]` also generates a borrowed `TypeView<'a>` for read-heavy hot paths. A view is
a validated ABI witness over canonical bytes: construction validates the ABI shell, required fields,
ID order, and unknown-field policy, while accessors decode only the selected field payload.

```rust
let canon = CanonicalCbor::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len()))?;
let view = TransferView::from_canonical(canon.as_canonical_ref())?;

assert_eq!(view.amount()?, 5000);
assert_eq!(view.memo()?, None);

let raw_amount = view.amount_raw()?;
assert_eq!(raw_amount.as_bytes(), &[0x19, 0x13, 0x88]); // 5000

let owned_again = view.to_owned()?;
assert_eq!(owned_again, value);
```

View accessor mapping is chosen for borrowing:

- `String` and `&str` fields return `&'a str`.
- `Bytes` and `BytesRef` fields return `BytesRef<'a>`.
- `CanonicalCbor` and `CanonicalCborRef` fields return `CanonicalCborRef<'a>`.
- `Vec<T>` fields return `AbiArrayView<'a, T>`; array elements are decoded when accessed.
- Nested ABI types return their generated nested views.
- `Option<T>` is represented by field presence and returns `Option<T::View>`.

Named enum payload views are validated and cached during enum view construction, so repeated
`as_route()` calls do not rescan the payload field-set. Transparent newtypes encode exactly like
their inner type while keeping a named ABI identity; if `#[abi(try_from = "...")]` is present, the
view constructor enforces the same invariant as owned decode.

### Unknown fields

Unknown fields can be rejected, ignored, or preserved. Preserve mode is the right choice when a
service must forward fields introduced by a newer peer:

```rust
use sacp_cbor_abi::{CborAbi, UnknownFields};

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(
    type_id = "ledger.TransferEnvelope",
    version = 1,
    unknown_fields = "preserve"
)]
struct TransferEnvelope {
    #[abi(id = 1)]
    transfer: Transfer,
    #[abi(unknown_fields)]
    unknown: UnknownFields,
}
```

Owned decode stores preserved unknown fields as owned `CanonicalCbor`. The generated view exposes
`unknown_fields()` as borrowed `UnknownFieldRef<'a>`, so forwarding or patching can inspect unknowns
without copying their payloads.

### Schema compatibility

Rust names are diagnostic metadata; schema identity comes from `type_id`, numeric IDs, and stable
field `TypeRef` values. Use `wire_hash` for wire compatibility and `full_hash` when diagnostics and
version should be part of the identity:

```rust
use sacp_cbor_abi::{AbiType, CborAbi, CompatibilityClass, UnknownFields};

#[derive(CborAbi)]
#[abi(type_id = "ledger.Transfer", version = 1, unknown_fields = "preserve")]
struct TransferV1 {
    #[abi(id = 1)]
    from: u64,
    #[abi(id = 2)]
    to: u64,
    #[abi(id = 3)]
    amount: u64,
    #[abi(unknown_fields)]
    unknown: UnknownFields,
}

#[derive(CborAbi)]
#[abi(type_id = "ledger.Transfer", version = 2, unknown_fields = "preserve")]
struct TransferV2 {
    #[abi(id = 1)]
    from: u64,
    #[abi(id = 2)]
    to: u64,
    #[abi(id = 3)]
    amount: u64,
    #[abi(id = 4, optional)]
    memo: Option<String>,
    #[abi(unknown_fields)]
    unknown: UnknownFields,
}

let report = sacp_cbor_abi::diff(&TransferV1::schema(), &TransferV2::schema());
assert_eq!(report.new_reads_old, CompatibilityClass::Compatible);
assert_eq!(report.old_reads_new, CompatibilityClass::Compatible);
assert_eq!(report.old_preserves_new, CompatibilityClass::Compatible);
```

### Facade crates

Facade crates can route generated code through their own public module layout. The facade must
re-export the ABI runtime items used by generated code:

```rust
pub mod wire {
    pub mod abi {
        pub use sacp_cbor_abi::*;
    }
    pub mod cbor {
        pub use sacp_cbor::{
            CanonicalCbor, CborDecode, CborError, Decoder, Encoder, ErrorCode,
        };
    }
}

use crate::wire::abi::CborAbi;

#[derive(CborAbi)]
#[abi(
    crate = crate::wire::abi,
    cbor = crate::wire::cbor,
    type_id = "facade.Transfer",
    version = 1
)]
struct FacadeTransfer {
    #[abi(id = 1)]
    amount: u64,
}
```

Use the owned path (`encode_to_vec`, `decode`, `decode_canonical`) for business logic and re-encode.
Use the generated view path for routing, filtering, forwarding, and patching where only a subset of
fields is needed.

---

## Editing / patching canonical bytes (`alloc`)

The editor applies a set of mutations to an existing canonical document and emits new canonical bytes.

### High-level semantics

- The input must be canonical (you start from `CanonicalCborRef` or `CanonicalCbor`).
- Map edits use a path whose terminal element is `PathElem::Key`.
- Array replacements/deletes use a path whose terminal element is `PathElem::Index`.
- Array insertions and range edits use `Editor::splice` against an array path; `&[]` targets the root array.
- Root replacement is not an editor operation.
- `PatchValue::Encoded` inserts owned canonical bytes; `PatchValue::Raw` reuses a value reference from the source document.
- Array indices in edit paths are interpreted against the **original** array (before edits).

### Getting an editor

```rust
use sacp_cbor::edit::{DeleteMode, PatchValue, SetMode};
use sacp_cbor::query::PathElem;
use sacp_cbor::{encode_to_canonical, validate_canonical, DecodeLimits};

let bytes: &[u8] = /* canonical */;
let canon = validate_canonical(bytes, DecodeLimits::for_bytes(bytes.len()))?;

let edited = canon.edit(|ed| {
    ed.set(
        &[PathElem::Key("user"), PathElem::Key("name")],
        SetMode::Upsert,
        PatchValue::Encoded(encode_to_canonical(&"alice")?),
    )?;
    ed.delete(&[PathElem::Key("temporary")], DeleteMode::IfPresent)?;
    Ok(())
})?;
```

Or with owned bytes:

```rust
use sacp_cbor::edit::{PatchValue, SetMode};
use sacp_cbor::query::PathElem;
use sacp_cbor::{encode_to_canonical, CanonicalCbor, DecodeLimits};

let owned = CanonicalCbor::from_slice(/*...*/, DecodeLimits::for_bytes(/*...*/))?;
let updated = owned.edit(|ed| {
    ed.set(
        &[PathElem::Key("counter")],
        SetMode::ReplaceOnly,
        PatchValue::Encoded(encode_to_canonical(&42i64)?),
    )?;
    Ok(())
})?;
```

### `Editor` operations

All mutating operations return `Result<(), CborError>`.

- `set(path, SetMode, PatchValue)` inserts or replaces a map key, or replaces an existing array item.
- `delete(path, DeleteMode)` deletes a map key or array item.
- `splice(array_path, Splice)` inserts and/or deletes a contiguous array range.

Finalize:

- `apply(self) -> Result<CanonicalCbor, CborError>`

### Supported value types for edits

The editor accepts `PatchValue`:

- `PatchValue::Encoded(CanonicalCbor)` for newly encoded values.
- `PatchValue::Raw(CborValueRef)` for reusing an existing canonical sub-value from the source.

Use `encode_to_canonical(&value)` to turn any `T: CborEncode` into `PatchValue::Encoded`.

**Complexity**

- Building `PatchValue::Encoded` means encoding a single CBOR item:

  - Time: `O(encoded_bytes_of_value)`
  - Space: may allocate a `Vec<u8>` for the encoded item; use raw insertion when you already have a canonical value reference.

### Editor limitations (must-read)

- **No root replacement**: map and array edits target containers inside the root; use encoding APIs to build a new root value.
- **Array indices are relative to the original array** (before edits).
- **Splice constraints**:

  - Splice delete ranges must be in bounds.
  - Splices must not overlap; overlapping splices or edits inside deleted ranges yield `PatchConflict`.
- **Patch conflicts**:

  - Two operations that overlap (e.g., replacing map key `a` and also editing inside `a`) yield `PatchConflict`.
- **Missing key semantics in maps**:

  - `set(..., SetMode::ReplaceOnly, ...)` on a missing key returns `MissingKey`
  - `delete(..., DeleteMode::Require)` on a missing key returns `MissingKey`
  - `delete(..., DeleteMode::IfPresent)` on a missing key succeeds
  - nested edits on missing keys → `MissingKey`

### Editor performance / complexity

Let:

- `n` = input size in bytes
- `p` = number of patch operations (terminals)
- `u` = number of distinct modified keys within a specific map node

Applying an editor:

- Worst-case time: `O(n + Σ(u log u))`

  - It walks/rewrites the whole document once (`O(n)`)
  - For each patched map, it sorts the modified keys (`O(u log u)`)
- Space:

  - Output buffer: `O(output_bytes)`
  - Patch tree: `O(p)` nodes + key storage
- No full decode of the input is performed; values are copied forward unchanged unless touched.

---

## Serde integration (`serde` + `alloc`)

### Convert Rust types ↔ canonical CBOR bytes

- `serde::to_vec<T: Serialize>(&T) -> Result<Vec<u8>, CborError>`
- `serde::from_slice<T: DeserializeOwned>(bytes, limits) -> Result<T, CborError>`

```rust
use serde::{Serialize, Deserialize};
use sacp_cbor::{serde::{from_slice, to_vec}, DecodeLimits};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Msg {
  n: i64,
  typ: String,
}

let msg = Msg { typ: "hi".into(), n: 5 };
let bytes = to_vec(&msg)?;

let decoded: Msg = from_slice(&bytes, DecodeLimits::for_bytes(bytes.len()))?;
assert_eq!(decoded, msg);
```

Strict serde streams maps and structs exactly in the order supplied by `Serialize` and rejects
duplicate or descending text keys before writing the offending key. Struct declarations must
therefore place serialized field names in canonical key order. For map types or struct declarations
whose order is not already canonical, explicitly opt into bounded sorted-map encoding:

```rust
use sacp_cbor::serde::SerdeOptions;

let bytes = SerdeOptions::sorted_maps().to_vec(&msg)?;
```

### Serde limitations (important)

- Map keys must serialize as **text** (`&str`/`String`/`char` etc). Non-string keys fail with `MapKeyMustBeText`.
- `SerdeOptions::strict()` does not buffer payload values. `SerdeOptions::sorted_maps()` explicitly
  buffers keys and encoded values, but preflights map length/items/depth/output and applies the
  remaining cumulative encoder budgets to every buffered entry.
- Serde `Option<T>` uses the same injective `{ "none": null }` / `{ "some": value }` shape as native `Option<T>`.
- Integer support via serde is limited to what serde exposes:

  - Very large bignums (more than 128 bits) cannot be losslessly represented through serde numeric primitives.
- Custom serde mismatches return `ErrorCode::SerdeError`; encoder profile errors
  report the current output offset and structural parse errors preserve input offsets.

---

## Hashing (`sha2`)

- `CanonicalCborRef::sha256() -> [u8; 32]`
- `CanonicalCbor::sha256() -> [u8; 32]`

**Complexity**

- Time: `O(n)` for bytes
- Space: `O(1)`

---

## Errors

### `CborError`

```rust
pub struct CborError {
  pub code: ErrorCode,
  pub offset: usize,
}
```

- `code`: machine-readable category
- `offset`: byte position in the input (or 0 for some logical/query errors)

### `ErrorCode` (high-level grouping)

- Limits / structure:

  - `InvalidLimits`, `MessageLenLimitExceeded`, `DepthLimitExceeded`, `TotalItemsLimitExceeded`,
    `ArrayLenLimitExceeded`, `MapLenLimitExceeded`, `BytesLenLimitExceeded`, `TextLenLimitExceeded`
- Canonical encoding violations:

  - `NonCanonicalEncoding`, `IndefiniteLengthForbidden`, `ReservedAdditionalInfo`, `TrailingBytes`
- Map rules:

  - `MapKeyMustBeText`, `DuplicateMapKey`, `NonCanonicalMapOrder`
- Integers / tags:

  - `IntegerOutsideSafeRange`, `ForbiddenOrMalformedTag`, `BignumNotCanonical`, `BignumMustBeOutsideSafeRange`
- Floats:

  - `NegativeZeroForbidden`, `NonCanonicalNaN`, `FloatForbidden` (no-float mode),
    `SimpleForbidden` (no-simple mode)
- Type expectation errors (query/edit):

  - `ExpectedMap`, `ExpectedArray`, `ExpectedInteger`, `ExpectedText`, `ExpectedBytes`,
    `ExpectedBool`, `ExpectedNull`, `ExpectedFloat`
- Sorted-sequence consumption (`ArrayDecoder::skip_sorted_scalars`):

  - `DuplicateElement`, `NonAscendingElement`
- Editing:

  - `PatchConflict`, `IndexOutOfBounds`, `InvalidQuery`, `MissingKey`
- serde:

  - `SerdeError`
- Catch-alls:

  - `MalformedCanonical`, `UnexpectedEof`, `LengthOverflow`, `AllocationFailed`

---

## Public API index (with properties and complexity)

This section is intentionally exhaustive for day-to-day use. For full signatures, rely on rustdoc.

### Validation & limits

- `validate_canonical(bytes, limits) -> Result<CanonicalCborRef, CborError>`

  - Validates canonical + single item and returns a typed wrapper.
  - Time: `O(n)`, Space: `O(d)`

- `validate_canonical_with(bytes, limits, options) -> Result<CanonicalCborRef, CborError>`

  - Same, under explicit `ValidationOptions` restriction modes.
  - No-float mode adds no cost to float-free inputs (the check sits on the float header path).

- `ValidationOptions`

  - Grammar-restriction modes; `ValidationOptions::new().no_float()` rejects float64 anywhere.
  - Restriction modes only reject more inputs; they never change the wire grammar.
  - Modes are a property of the validation call, not of the bytes: trusted re-traversal
    (queries, editing, trusted decode) ignores them, so re-validate edited output under the
    same options if you need the restriction to hold across a round trip.

- `DecodeLimits::for_bytes(max_message_bytes) -> DecodeLimits`

  - Convenience baseline limits.

- `EncodeLimits::for_bytes(max_output_bytes) -> EncodeLimits`

  - Convenience baseline limits for `Encoder::with_limits`.

### Typed decode/encode

- `decode(bytes, limits) -> Result<T, CborError>`
- `decode_canonical(canon_ref, limits) -> Result<T, CborError>`
- `encode_to_vec(&value) -> Result<Vec<u8>, CborError>` (`alloc`)
- `encode_to_canonical(&value) -> Result<CanonicalCbor, CborError>` (`alloc`)
- `CborEncode::encode` receives a `ValueEncoder`, not the underlying encoder;
  `Encoder::encode` owns slot accounting and makes every trait failure sticky.

Common trait coverage for derive-driven models includes:

- byte strings: `bytes::Bytes` / `bytes::BytesRef`
- explicit optional values: `Option<T>` using `{ "none": null }` or `{ "some": value }`
- arrays: `Vec<T>` (`collections`)
- maps: `MapEntries<K, V>` for encode/decode; `BTreeMap` and `HashMap` are encode-only conveniences
- fixed byte arrays: `[u8; N]` (CBOR byte strings with exact-length decode checks)
- canonical wrappers: `CanonicalCborRef<'a>` and `CanonicalCbor` (`alloc`)

### Bytes wrappers

- `CanonicalCborRef<'a>` (borrowed)

  - `as_bytes/root` — `O(1)`
- `at(path)` — `O(bytes scanned)`
  - `sha256` (`sha2`) — `O(n)`
  - `to_owned` (`alloc`) — `O(n)` alloc+copy
  - `editor/edit` (`alloc`) — see editing

- `CanonicalCbor` (`alloc`, owned)

  - `from_slice(bytes, limits)` — validates then copies (`O(n)`)
  - `from_slice_with(bytes, limits, options)` / `from_vec_with(bytes, limits, options)` —
    same, under explicit `ValidationOptions`
  - `as_bytes/into_bytes` — `O(1)`
  - query/edit methods same as `CanonicalCborRef`

### Query types

- `query::PathElem`: `Key(&str)` / `Index(usize)`

- `query::CborValueRef<'a>`

  - scalar reads: mostly `O(1)` (text is `O(len)`)
  - container queries: `O(bytes scanned)`

- `query::MapRef<'a>`

  - `get/require`: `O(bytes scanned until match/early-exit)`
  - sorted multi-key lookups: `O(k + bytes scanned)`; unsorted `alloc` lookups sort first
  - iter/extras: `O(bytes in map)` (+ optional key sorting costs)

- `query::ArrayRef<'a>`

  - `get`: `O(bytes scanned up to index)`
  - `iter`: `O(bytes in array)`

### Encoding (`alloc`)

- `Encoder<S: ByteSink>`

  - sink-generic streaming canonical CBOR output
  - maps require canonical key order; enforced
  - first failure is returned precisely; later fallible encode/finish calls return `Poisoned`

- `encode::ArrayEncoder`, `encode::MapEncoder`

  - enforce arity + map canonical ordering

### Editing (`edit`)

- `edit::Editor`

  - `set`, `delete`, `splice`, and `apply` with conflict detection
  - array indices refer to the original array
  - Time: `O(n + Σ(u log u))` worst-case

### Macros (`derive`)

- `cbor_bytes!` → `Result<CanonicalCbor, CborError>`

  - literal map entries are sorted into canonical order at macro expansion

- `#[cbor(crate = path::to::runtime)]` on `CborEncode` / `CborDecode` derive containers selects the generated runtime API path

### Serde (`serde` + `alloc`)

- `serde::to_vec`, `serde::from_slice`
- `serde::from_canonical_bytes_ref`, `serde::from_canonical_bytes` (for already-validated canonical bytes)
- `serde::SerdeOptions` for sorted-map encoding
- numeric bignums are limited to `i128/u128` roundtrips through serde

---

## When to use what

- **You already have CBOR bytes and need fast reads:**
  `validate_canonical` → `CanonicalCborRef` → `at/get/iter`

- **You need to *emit* canonical CBOR efficiently:**
  `Encoder` / `cbor_bytes!`
  (ensure canonical map key order)

- **You need to patch existing canonical bytes without decoding everything:**
  `CanonicalCborRef::edit` / `CanonicalCbor::edit`

- **You need to admit records against a declared schema (types, constraints, couplings):**
  `sacp-cbor-schema` — one fused pass validates grammar and schema and returns the witness

- **You need serde:**
  `serde::to_vec` / `serde::from_slice`
- **You already validated canonical bytes and want struct decode:**
  `serde::from_canonical_bytes_ref` / `serde::from_canonical_bytes`

---

## Notes for maintainers / auditors

- `unsafe` is forbidden unless the `unsafe` feature is enabled for canonical-trusted UTF-8 reads.
- The validator is intentionally strict and rejects many CBOR features by design.
- All offset-bearing errors aim to point at the byte position where the violation is detected (serde conversions generally return offset 0).
- Bounded Kani proof harnesses for integer minimality, checked primitive decoding, profile
  classifiers, canonical key comparators, and sticky encoder slot accounting are compiled under `cfg(kani)`.
  Run `scripts/proof.sh` on a Kani-supported host after installing and setting up `cargo-kani`.

---

## Benchmarks

A separate benchmark workspace lives under `benchmarks/` and runs scenario-driven cross-crate
CBOR benchmarks (validate / ingest / decode / encode / patch pipelines) on realistic SACP
message workloads, with pivot-table reports and a baseline-comparison mode for regression
tracking. See `benchmarks/README.md` for setup and usage.
