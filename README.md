# sacp-cbor

Strict canonical CBOR bytes validation + **zero-copy querying** + **canonical encoding** + **structural patching** (map/array edits) + optional **serde** + optional **SHA-256**.

This crate is intentionally **not** a general-purpose CBOR implementation. It enforces a **small, deterministic CBOR profile** designed for stable hashing, signatures, and safe interop.

---

## What you get

### Core capabilities

- **Validate** that an input is a *single, canonical* CBOR item under a strict profile (`validate_canonical`).
- Wrap validated bytes as `CborBytesRef<'a>` for **zero-copy querying** (`at`, `root`, `MapRef`, `ArrayRef`, `CborValueRef`).
- Optionally **decode** into an owned DOM (`CborValue`) with `decode_value` (`alloc`).
- **Encode canonical CBOR** directly (`Encoder`, `MapEncoder`, `ArrayEncoder`) (`alloc`).
- Build values with the **fallible** `cbor!` macro (`alloc`) and build canonical bytes with `cbor_bytes!` (`alloc`).
- **Patch/edit** canonical bytes without decoding the whole structure (`Editor`) (`alloc`).
- Optional:
  - **serde** conversion utilities (`serde`).
  - **SHA-256** helpers for canonical bytes / canonical-encoded values (`sha2`).

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

If you need tags beyond bignums, indefinite lengths, non-text map keys, half/float32 encodings, etc., this crate is the wrong tool.

---

## Feature flags

This crate is `no_std` by default unless `std` is enabled.

| Feature | Enables | Notes |
|---|---|---|
| `std` | `std::error::Error` for `CborError` | Otherwise `no_std` |
| `alloc` | Owned types + encoding/decoding + editor + macros | Required for `CborBytes`, `CborValue`, `Encoder`, `Editor`, `cbor!`, `cbor_bytes!` |
| `serde` | serde integration (`to_vec`, `from_slice`, etc.) | Requires `alloc` in practice |
| `sha2` | SHA-256 helpers | Uses `sha2` crate |

### Recommended dependency configs

**Default Rust (std + alloc):**
```toml
[dependencies]
sacp-cbor = "0.5"
````

**`no_std` + `alloc`:**

```toml
[dependencies]
sacp-cbor = { version = "0.5", default-features = false, features = ["alloc"] }
```

**`no_std` + `alloc` + serde + sha2:**

```toml
[dependencies]
sacp-cbor = { version = "0.5", default-features = false, features = ["alloc", "serde", "sha2"] }
```

> In Rust code the crate name is typically `sacp_cbor` (hyphen becomes underscore).

---

## Canonical profile rules

### Canonical map ordering (text keys only)

Maps must be sorted by the **encoded CBOR bytes of the key**, using:

1. **Encoded length** ascending (shorter encoded key bytes come first)
2. If equal length, **lexicographic** order of the encoded bytes

Because keys are text strings, the encoded key is:

* a text header (1/2/3/5/9 bytes depending on string length), followed by
* UTF-8 bytes of the key

For most “small keys” (< 24 bytes), the header is 1 byte, so the order is effectively:

* shorter key first, then
* lexicographic order of UTF-8 bytes

But note: at lengths 24, 256, 65536, … the header grows, which affects the encoded length ordering.

### Safe integer range

The safe integer range is:

* `MIN_SAFE_INTEGER = -(2^53 - 1)`
* `MAX_SAFE_INTEGER = +(2^53 - 1)`

Constants are exported:

* `MAX_SAFE_INTEGER: u64`
* `MAX_SAFE_INTEGER_I64: i64`
* `MIN_SAFE_INTEGER: i64`

Integers outside that range must be encoded as bignum (tag 2 or 3), and bignums are *required* to be outside safe range (i.e., you cannot represent a safe integer using a bignum).

### Float64 rules

* Only float64 encoding is allowed.
* `-0.0` is rejected.
* NaN must be canonicalized.

---

## Complexity model used in this README

* `n` = input byte length
* `d` = nesting depth
* `m` = number of entries in a map
* `a` = number of items in an array
* `k` = number of query keys in a multi-key operation
* “bytes scanned” means the implementation may need to walk CBOR structure boundaries using a value-end walker; this is proportional to the size of the traversed portion.

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
    println!("validated {} bytes", canon.len());
    Ok(())
}
```

**Complexity**

* Time: **O(n)**
* Space: **O(d)** stack

  * **Without `alloc`**, validation uses a fixed inline stack sized for the default depth; extremely deep inputs can fail even if you raise `max_depth`.

### 2) Zero-copy query into a validated document

```rust
use sacp_cbor::{path, validate_canonical, DecodeLimits};

fn main() -> Result<(), sacp_cbor::CborError> {
    let bytes: &[u8] = /* canonical bytes */;

    let canon = validate_canonical(bytes, DecodeLimits::for_bytes(bytes.len()))?;

    // Navigate: root -> ["user"] -> ["id"]
    if let Some(id_ref) = canon.at(path!("user", "id"))? {
        let id = id_ref.integer()?.as_i64(); // Option<i64>, None if big integer
        println!("user.id: {id:?}");
    }

    Ok(())
}
```

**Complexity**

* `at(path)` time is proportional to what must be scanned in maps/arrays along the path:

  * Worst-case: **O(bytes scanned)**, often close to **O(n)** for pathological paths
  * Typical: shallow maps with early exits are much smaller
* Space: O(1)

### 3) Decode into an owned `CborValue` (requires `alloc`)

```rust
use sacp_cbor::{decode_value, DecodeLimits};

fn main() -> Result<(), sacp_cbor::CborError> {
    let bytes: &[u8] = /* canonical bytes */;
    let limits = DecodeLimits::for_bytes(bytes.len());

    let v = decode_value(bytes, limits)?;

    if let Some(user) = v.at(sacp_cbor::path!("user"))? {
        println!("user is null? {}", user.is_null());
    }

    Ok(())
}
```

**Complexity**

* Time: **O(n)**
* Allocations: proportional to the decoded structure (arrays/maps/strings/bytes)
* Space: **O(size of decoded content)**

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

* `max_depth = 256`
* `max_total_items = max_message_bytes`
* `max_array_len/max_map_len = min(max_message_bytes, 1<<16)`
* `max_bytes_len/max_text_len = max_message_bytes`

**Why limits matter**

* Prevents “CBOR bombs” (huge containers, deeply nested data).
* Controls worst-case time and memory for validation and decoding.

### `CborLimits`

If you need two distinct policies (e.g., “message” vs “state”):

```rust
use sacp_cbor::CborLimits;

let limits = CborLimits::new(1_000_000, 16_384)?;
let msg = limits.message_limits();
let state = limits.state_limits();
```

---

## Zero-copy query API

All query APIs operate on **validated canonical bytes** (via `CborBytesRef` / `CborBytes`) and return lightweight views (`CborValueRef`) into the underlying buffer.

### `CborBytesRef<'a>`

How you obtain it:

* returned by `validate_canonical(&[u8], DecodeLimits)`

Key methods:

* `as_bytes() -> &'a [u8]` (O(1))
* `len() -> usize` (O(1))
* `is_empty() -> bool` (O(1))
* `bytes_eq(other) -> bool` (O(n) compare)
* `root() -> CborValueRef<'a>` (O(1))
* `at(path: &[PathElem]) -> Result<Option<CborValueRef>, CborError>`

  * **Time:** O(bytes scanned)
  * **Space:** O(1)

Optional:

* `sha256() -> [u8; 32]` (`sha2`) — **O(n)**
* `to_owned() -> Result<CborBytes, CborError>` (`alloc`) — **O(n)** copy + alloc
* `editor()/edit(...)` (`alloc`) — see “Editing”

### `CborBytes` (owned, `alloc`)

How you obtain it:

* `CborBytes::from_slice(bytes, limits)` validates + copies
* or from an `Encoder` (`into_canonical()`)
* or from an `Editor::apply()`

Key methods:

* `as_bytes() -> &[u8]` (O(1))
* `into_bytes() -> Vec<u8>` (O(1) move)
* `bytes_eq(&other) -> bool` (O(n))
* `root()/at(...)` same as `CborBytesRef`
* `sha256()` (`sha2`) — **O(n)**
* `edit(...)` (`alloc`) — see “Editing”

### `PathElem` and `path!`

```rust
use sacp_cbor::{PathElem, path};

let p1: &[PathElem] = path!("a", "b", 0, "c"); // keys and indices
let p2: &[PathElem] = &[PathElem::Key("a"), PathElem::Index(0)];
```

* `PathElem::Key(&str)`
* `PathElem::Index(usize)`

**Complexity**

* Path construction is compile-time for literals; runtime cost is trivial.
* Query traversal cost depends on containers traversed.

### `CborValueRef<'a>`

`CborValueRef` is a view into a contiguous CBOR value within a canonical buffer.

Key methods (behavior + complexity):

* `as_bytes() -> &'a [u8]` — O(1)
* `offset() -> usize` — O(1) (byte offset in the original buffer)
* `len() -> usize` — O(1)
* `is_empty() -> bool` — O(1)

Type/category inspection:

* `kind() -> Result<CborKind, CborError>`

  * **Time:** O(1) for header; may read small tag headers
* `is_null() -> bool` — O(1)

Container access:

* `map() -> Result<MapRef<'a>, CborError>`

  * Errors: `ExpectedMap` if not a map, or `MalformedCanonical` if corrupt
* `array() -> Result<ArrayRef<'a>, CborError>`

  * Errors: `ExpectedArray`, `MalformedCanonical`
* `get_key(&str) -> Result<Option<CborValueRef>, CborError>` (map lookup)
* `get_index(usize) -> Result<Option<CborValueRef>, CborError>` (array lookup)
* `at(path) -> Result<Option<CborValueRef>, CborError>` (path traversal)

Scalar decoding (zero-copy where possible):

* `integer() -> Result<CborIntegerRef<'a>, CborError>`

  * Returns `Safe(i64)` or `Big(BigIntRef)`
  * **Time:** O(1) + reads magnitude bytes for bigints
  * Errors: `ExpectedInteger`, `MalformedCanonical`
* `text() -> Result<&'a str, CborError>`

  * **Time:** O(len) due to UTF-8 validation
* `bytes() -> Result<&'a [u8], CborError>`

  * **Time:** O(1)
* `bool() -> Result<bool, CborError>` — O(1)
* `float64() -> Result<f64, CborError>` — O(1)

Owned conversion (`alloc`):

* `to_owned() -> Result<CborValue, CborError>`

  * **Time:** O(len of this value)**
  * **Allocations:** proportional to decoded subtree

### `MapRef<'a>`

Obtain via `CborValueRef::map()?`.

Map APIs assume:

* keys are **text**, and
* map is **canonical key-sorted**

Key methods:

* `len()`, `is_empty()` — O(1)

Single key lookup:

* `get(key: &str) -> Result<Option<CborValueRef>, CborError>`

  * **Time:** O(bytes scanned in map until match or early-exit)**
  * Early-exit: once map key > query key (canonical order), returns `None`
  * Errors: `MalformedCanonical`, or `LengthOverflow` if query key is absurdly large

* `require(key) -> Result<CborValueRef, CborError>`

  * Same as `get`, but returns `MissingKey` if not found

Multi-key lookup:

* `get_many_sorted<const N: usize>(keys: [&str; N]) -> Result<[Option<CborValueRef>; N], CborError>`
* `require_many_sorted<const N: usize>(keys: [&str; N]) -> Result<[CborValueRef; N], CborError>`

These functions:

* validate key sizes
* internally sort an index array by canonical key encoding
* scan the map once (merge-like scan)

**Complexity**

* Time: **O(k log k * L + bytes scanned in map)**
  where `k = N`, `L` = average key length used in comparisons.
* Space: O(k) (small fixed arrays)

Dynamic multi-key lookup (`alloc`):

* `get_many(keys: &[&str]) -> Result<Vec<Option<CborValueRef>>, CborError>`
* `require_many(keys: &[&str]) -> Result<Vec<CborValueRef>, CborError>`
* `get_many_into(keys, out)` (writes into caller-provided slice)

**Complexity**

* Time: **O(k log k * L + bytes scanned in map)**
* Space: `get_many/get_many_into` allocate O(k) for sorting indices (unless you provide your own pre-sorted list and use `extras_sorted` patterns)

Iteration:

* `iter() -> impl Iterator<Item = Result<(&str, CborValueRef), CborError>>`

  * **Time:** full iteration is **O(bytes in map)**

Extras (fields not in a set of “used keys”):

* `extras_sorted(used_keys: &[&str]) -> Result<impl Iterator<...>, CborError>`

  * Requires `used_keys` to be **strictly increasing** in canonical key order (validated)
  * **Time:** O(bytes in map + k)
  * **Space:** O(1)

`alloc` helpers:

* `extras_sorted_vec(used_keys) -> Result<Vec<(&str, CborValueRef)>, CborError>`
* `extras_vec(used_keys) -> Result<Vec<(&str, CborValueRef)>, CborError>`

  * `extras_vec` sorts your keys internally (allocates)
  * **Time:** O(k log k * L + bytes in map)**
  * **Space:** O(k) + output vec

### `ArrayRef<'a>`

Obtain via `CborValueRef::array()?`.

* `len()`, `is_empty()` — O(1)
* `get(index) -> Result<Option<CborValueRef>, CborError>`

  * **Time:** O(bytes scanned up to index)** (because it walks item boundaries)
  * Space: O(1)
* `iter() -> impl Iterator<Item = Result<CborValueRef, CborError>>`

  * Full iteration: O(bytes in array)

---

## Owned value API (`alloc`)

If you want an owned DOM tree (and canonical encoding from it), use `CborValue` + friends.

### `CborValue`

Construction (all fallible where appropriate):

* `CborValue::null()`
* `CborValue::bool(bool)`
* `CborValue::float(F64Bits)`
* `CborValue::float64(f64) -> Result<Self, CborError>` (rejects -0.0, canonicalizes NaN)
* `CborValue::bytes(Vec<u8>)`
* `CborValue::text(S: Into<Box<str>>)`
* `CborValue::array(items: impl Into<Box<[CborValue]>>)`
* `CborValue::map(CborMap)`

Integers:

* `CborValue::int(i64) -> Result<Self, CborError>` (safe range enforced)
* `CborValue::bigint(negative, magnitude: Vec<u8>) -> Result<Self, CborError>`
* `CborValue::integer(CborInteger)` (already validated by constructors)

Accessors:

* `as_i64() -> Option<i64>`
* `as_bigint() -> Option<&BigInt>`
* `as_bytes() -> Option<&[u8]>`
* `as_text() -> Option<&str>`
* `as_array() -> Option<&[CborValue]>`
* `as_map() -> Option<&CborMap>`
* `as_bool() -> Option<bool>`
* `is_null() -> bool`
* `as_float() -> Option<F64Bits>`

Path traversal (owned):

* `CborValue::at(path) -> Result<Option<&CborValue>, CborError>`

  * **Time:** depends on map/array lookups; maps use binary search on sorted keys
  * For maps: O(log m * compare_cost)
  * For arrays: O(1) index
  * Space: O(1)

Encoding:

* `encode_canonical() -> Result<Vec<u8>, CborError>`

  * **Time:** O(size of value)**
  * **Space:** O(depth) stack (small inline + possible overflow)

Hashing (optional):

* `sha256_canonical() -> Result<[u8; 32], CborError>` (`sha2`)

  * **Time:** O(size of canonical encoding)**

### `CborMap`

Create canonical maps:

* `CborMap::new(Vec<(Box<str>, CborValue)>) -> Result<CborMap, CborError>`

  * Validates key size
  * Sorts keys into canonical order
  * Rejects duplicates

**Complexity**

* Time: **O(m log m * L)** (sort + comparisons)
* Space: O(m)

Lookup:

* `get(&str) -> Option<&CborValue>`

  * **Time:** O(log m * L)**
  * Uses binary search by canonical key encoding

Multi-key lookups:

* `get_many_sorted<const N: usize>(keys: [&str; N]) -> Result<[Option<&CborValue>; N], CborError>`
* `get_many_sorted_into(keys: &[&str], out: &mut [Option<&CborValue>]) -> Result<(), CborError>`

**Complexity**

* Time: O(k log k * L + m * merge_scan_cost) in worst-case (it uses a merge scan over the already-sorted map iterator)
* Space: O(k)

### `CborInteger` / `BigInt` / `F64Bits`

* `CborInteger::safe(i64) -> Result<CborInteger, CborError>`
* `CborInteger::big(negative, magnitude: Vec<u8>) -> Result<CborInteger, CborError>`
* `BigInt::new(negative, magnitude: Vec<u8>) -> Result<BigInt, CborError>`

  * magnitude must be canonical and outside safe range
* `F64Bits::new(bits: u64) -> Result<F64Bits, CborError>`
* `F64Bits::try_from_f64(f64) -> Result<F64Bits, CborError>`

  * canonicalizes NaN and rejects -0.0

---

## Canonical encoding API (`alloc`)

If you want to produce canonical CBOR bytes directly, use `Encoder`.

### `Encoder`

Create:

* `Encoder::new()`
* `Encoder::with_capacity(usize)`

Extract:

* `into_vec() -> Vec<u8>` (not wrapped/validated)
* `into_canonical() -> CborBytes` (assumes you used encoder correctly)
* `as_bytes() -> &[u8]` (current buffer)

Write scalars:

* `null()`, `bool(bool)`
* `int(i64) -> Result<(), CborError>` (safe range enforced)
* `bignum(negative, magnitude: &[u8]) -> Result<(), CborError>` (canonical + outside safe range enforced)
* `bytes(&[u8])`, `text(&str)`
* `float(F64Bits)`

Write composites:

* `array(len, |&mut ArrayEncoder| ...)`
* `map(len, |&mut MapEncoder| ...)`

Raw splice:

* `raw_cbor(CborBytesRef)` (copies bytes as-is into output)
* `raw_value_ref(CborValueRef)` (copies bytes as-is into output)

**Key rule:** When emitting maps via `Encoder::map`, you must insert entries in **canonical key order** using `MapEncoder::entry`. The encoder enforces this and will error if you violate it.

**Complexity**

* Encoding operations are proportional to the bytes written:

  * Time: **O(output_bytes)**
  * Space: output buffer + small stack
* `map` ordering checks compare encoded key bytes:

  * Additional time: O(total key bytes) across all entries

### `MapEncoder::entry`

Signature:

```rust
fn entry<F>(&mut self, key: &str, f: F) -> Result<(), CborError>
where
    F: FnOnce(&mut Encoder) -> Result<(), CborError>;
```

Properties:

* Key must be text (`&str`), always.
* Enforces:

  * **no duplicate keys**
  * **strict canonical order**
* On any error inside the closure `f`, the partially-written entry is rolled back (buffer truncated).

Errors you may see:

* `DuplicateMapKey`
* `NonCanonicalMapOrder`
* `MapLenMismatch` (if you write too many/few entries overall)
* plus anything your closure emits

**Complexity**

* Per entry: O(key_len + value_bytes) + ordering compare O(key_len)

### `ArrayEncoder`

You must write exactly `len` items; otherwise:

* `ArrayLenMismatch`

**Complexity**

* O(total written bytes)

---

## Macros (`alloc`)

### `cbor!` — build an owned `CborValue` (fallible)

* Produces `Result<CborValue, CborError>`
* Sorts map keys for you (because it builds a `CborMap::new(...)`)

Example:

```rust
use sacp_cbor::cbor;

let v = cbor!({
    "a": 1,
    "b": [true, null, 1.5],
})?;
```

Map keys can be:

* identifiers: `{ foo: 1 }` (becomes `"foo"`)
* string literals: `{ "foo": 1 }`
* dynamic expressions: `{ ((some_string)): 1 }`

**Complexity**

* Arrays: O(#elements)
* Maps: O(m log m * L) due to sorting + duplicate check

### `cbor_bytes!` — build canonical bytes directly (fallible)

* Produces `Result<CborBytes, CborError>`
* Uses `Encoder` internally
* **Does NOT sort map keys**. Your literal/entry order must already be canonical.

Example (canonical key order required):

```rust
use sacp_cbor::cbor_bytes;

let bytes = cbor_bytes!({
    "a": 1,
    "b": 2,
    "z": 3,
})?;
```

Splicing existing canonical fragments (still copied into output, but no decoding/re-encoding):

```rust
use sacp_cbor::{cbor_bytes, validate_canonical, DecodeLimits};

let existing: &[u8] = /* canonical CBOR */;
let canon = validate_canonical(existing, DecodeLimits::for_bytes(existing.len()))?;

let out = cbor_bytes!([canon, 1, 2, 3])?; // array whose first element is the existing item
```

**Complexity**

* Time: O(output_bytes)
* Space: output buffer
* Map order enforcement: same as `Encoder`/`MapEncoder`

---

## Editing / patching canonical bytes (`alloc`)

The editor applies a set of mutations to an existing canonical document and emits new canonical bytes.

### High-level semantics

* The input must be canonical (you start from `CborBytesRef` or `CborBytes`).
* Operations are specified by a **non-empty path** (`&[PathElem]`).

  * You cannot “replace the root value” via an empty path.
* Map edits can insert/delete keys; arrays support structural edits via splices.
* Array indices in edit paths are interpreted against the **original** array (before edits).

### Getting an editor

```rust
use sacp_cbor::{validate_canonical, DecodeLimits, path};

let bytes: &[u8] = /* canonical */;
let canon = validate_canonical(bytes, DecodeLimits::for_bytes(bytes.len()))?;

let edited = canon.edit(|ed| {
    ed.set(path!("user", "name"), "alice")?;
    ed.delete_if_present(path!("legacy"))?;
    Ok(())
})?;
```

Or with owned bytes:

```rust
use sacp_cbor::{CborBytes, DecodeLimits, path};

let owned = CborBytes::from_slice(/*...*/, DecodeLimits::for_bytes(/*...*/))?;
let updated = owned.edit(|ed| {
    ed.replace(path!("counter"), 42i64)?;
    Ok(())
})?;
```

### `EditOptions`

```rust
use sacp_cbor::EditOptions;

ed.options_mut().create_missing_maps = true;
```

* `create_missing_maps: bool`

  * If `true`, missing **map** keys along the path may be created as new (empty or partially filled) maps.
  * This only creates **maps**, not arrays, and only when the editor can prove the needed structure.

### `Editor` operations

All return `Result<(), CborError>`.

Set operations:

* `set(path, value)` → Upsert semantics (arrays: replace element)
* `insert(path, value)` → InsertOnly (maps: error if key exists; arrays: insert before index)
* `replace(path, value)` → ReplaceOnly (maps: error if missing; arrays: replace element)
* `set_raw(path, CborValueRef)` → splice a raw value reference from the source document
* `set_encoded(path, |enc| { ... })` → compute the new value by encoding exactly one CBOR item

Delete operations:

* `delete(path)` → must exist (arrays: index must be in bounds)
* `delete_if_present(path)` → no error if missing (arrays: ignore out-of-bounds)

Array splices:

* `splice(array_path, pos, delete)` → returns a builder to insert values at `pos`
* `push(array_path, value)` / `push_encoded(array_path, |enc| ...)` → append to end

Finalize:

* `apply(self) -> Result<CborBytes, CborError>`

### Supported value types for edits (`EditEncode`)

The editor accepts any `T: EditEncode` for `set/insert/replace`.

Implemented out of the box:

* `bool`, `()`
* `&str`, `String`
* `&[u8]`, `Vec<u8>`
* `f32`, `f64`, `F64Bits`
* `i64`, `u64`, `i128`, `u128` (bignum encoding when outside safe range)
* `CborValue`, `&CborValue`
* `CborBytesRef`, `CborBytes`, `&CborBytes`

**Complexity**

* Converting `T` into an edit value usually means encoding a single CBOR item:

  * Time: O(encoded_bytes_of_value)
  * Space: may allocate a `Vec<u8>` for the encoded item unless you pass a `CborBytesRef`/`&CborBytes`.

### Editor limitations (must-read)

* **No empty path**: attempting to edit the root directly yields `InvalidQuery`.
* **Array indices are relative to the original array** (before edits).
* **Splice constraints**:

  * Splice delete ranges must be in bounds.
  * Splices must not overlap; overlapping splices or edits inside deleted ranges yield `PatchConflict`.
* **Patch conflicts**:

  * Two operations that overlap (e.g., set `["a"]` and also set `["a","b"]`) yield `PatchConflict`.
* **Missing key semantics in maps**:

  * `replace` on a missing key → `MissingKey`
  * `delete` on a missing key → `MissingKey`
  * `delete_if_present` on missing key → OK
  * nested edits on missing keys:

    * if `create_missing_maps = true`, the editor may create missing maps
    * otherwise → `MissingKey`

### Editor performance / complexity

Let:

* `n` = input size in bytes
* `p` = number of patch operations (terminals)
* `u` = number of distinct modified keys within a specific map node

Applying an editor:

* Worst-case time: **O(n + Σ(u log u))**

  * It walks/rewrites the whole document once (O(n))
  * For each patched map, it sorts the modified keys (O(u log u))
* Space:

  * Output buffer: O(output_bytes)
  * Patch tree: O(p) nodes + key storage
* No full decode of the input is performed; values are copied forward unchanged unless touched.

---

## Serde integration (`serde` + `alloc`)

### Convert Rust types ↔ canonical CBOR bytes

* `to_vec<T: Serialize>(&T) -> Result<Vec<u8>, CborError>`
* `from_slice<T: DeserializeOwned>(bytes, limits) -> Result<T, CborError>`

```rust
use serde::{Serialize, Deserialize};
use sacp_cbor::{to_vec, from_slice, DecodeLimits};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Msg {
    typ: String,
    n: i64,
}

let msg = Msg { typ: "hi".into(), n: 5 };
let bytes = to_vec(&msg)?;

let decoded: Msg = from_slice(&bytes, DecodeLimits::for_bytes(bytes.len()))?;
assert_eq!(decoded, msg);
```

### Convert Rust types ↔ `CborValue`

* `to_value<T: Serialize>(&T) -> Result<CborValue, CborError>`
* `from_value_ref<T: Deserialize>(&CborValue) -> Result<T, CborError>`

### `serde_value` helper module

Use when you want a struct field to be encoded/decoded as a `CborValue` itself:

```rust
use serde::{Serialize, Deserialize};
use sacp_cbor::CborValue;

#[derive(Serialize, Deserialize)]
struct Wrapper {
    #[serde(with = "sacp_cbor::serde_value")]
    inner: CborValue,
}
```

Optional variant:

```rust
#[derive(Serialize, Deserialize)]
struct Wrapper2 {
    #[serde(with = "sacp_cbor::serde_value::option")]
    inner: Option<CborValue>,
}
```

### Serde limitations (important)

* Map keys must serialize as **text** (`&str`/`String`/`char` etc). Non-string keys fail with `MapKeyMustBeText`.
* Integer support via serde is limited to what serde exposes:

  * Serialization of `CborValue` bignums only succeeds if they fit into `i128` or `u128`.
  * Very large bignums (more than 128 bits) cannot be losslessly represented through serde numeric primitives.
* Serde errors are returned as `ErrorCode::SerdeError` (offset 0), so you don’t get byte offsets for schema mismatches.

---

## Hashing (`sha2`)

* `CborBytesRef::sha256() -> [u8; 32]`
* `CborBytes::sha256() -> [u8; 32]`
* `CborValue::sha256_canonical() -> Result<[u8; 32], CborError>`

**Complexity**

* Time: O(n) for bytes, O(size of canonical encoding) for values
* Space: O(1)

---

## Errors

### `CborError`

```rust
pub struct CborError {
    pub code: ErrorCode,
    pub offset: usize,
}
```

* `code`: machine-readable category
* `offset`: byte position in the input (or 0 for some logical/query errors)

### `ErrorCode` (high-level grouping)

* Limits / structure:

  * `InvalidLimits`, `MessageLenLimitExceeded`, `DepthLimitExceeded`, `TotalItemsLimitExceeded`,
    `ArrayLenLimitExceeded`, `MapLenLimitExceeded`, `BytesLenLimitExceeded`, `TextLenLimitExceeded`
* Canonical encoding violations:

  * `NonCanonicalEncoding`, `IndefiniteLengthForbidden`, `ReservedAdditionalInfo`, `TrailingBytes`
* Map rules:

  * `MapKeyMustBeText`, `DuplicateMapKey`, `NonCanonicalMapOrder`
* Integers / tags:

  * `IntegerOutsideSafeRange`, `ForbiddenOrMalformedTag`, `BignumNotCanonical`, `BignumMustBeOutsideSafeRange`
* Floats:

  * `NegativeZeroForbidden`, `NonCanonicalNaN`
* Type expectation errors (query/edit):

  * `ExpectedMap`, `ExpectedArray`, `ExpectedInteger`, `ExpectedText`, `ExpectedBytes`,
    `ExpectedBool`, `ExpectedFloat`
* Editing:

  * `PatchConflict`, `IndexOutOfBounds`, `InvalidQuery`, `MissingKey`
* serde:

  * `SerdeError`
* Catch-alls:

  * `MalformedCanonical`, `UnexpectedEof`, `LengthOverflow`, `AllocationFailed`

---

## Public API index (with properties and complexity)

This section is intentionally exhaustive for day-to-day use. For full signatures, rely on rustdoc.

### Validation & limits

* `validate(bytes, limits) -> Result<(), CborError>`

  * Validates canonical + single item.
  * **Time:** O(n), **Space:** O(d)

* `validate_canonical(bytes, limits) -> Result<CborBytesRef, CborError>`

  * Same as `validate`, but returns a typed wrapper.
  * **Time:** O(n), **Space:** O(d)

* `DecodeLimits::for_bytes(max_message_bytes) -> DecodeLimits`

  * Convenience baseline limits.

* `CborLimits::new(max_message_bytes, max_state_bytes) -> Result<CborLimits, CborError>`

  * Enforces `max_state_bytes <= max_message_bytes`.

* `CborLimits::{message_limits,state_limits}() -> DecodeLimits`

  * Derives `DecodeLimits` for each budget.

### Bytes wrappers

* `CborBytesRef<'a>` (borrowed)

  * `as_bytes/len/is_empty/root` — O(1)
  * `bytes_eq` — O(n)
  * `at(path)` — O(bytes scanned)
  * `sha256` (`sha2`) — O(n)
  * `to_owned` (`alloc`) — O(n) alloc+copy
  * `editor/edit` (`alloc`) — see editing

* `CborBytes` (`alloc`, owned)

  * `from_slice(bytes, limits)` — validates then copies (**O(n)**)
  * `as_bytes/into_bytes` — O(1)
  * query/edit methods same as `CborBytesRef`

### Query types

* `PathElem`: `Key(&str)` / `Index(usize)`

* `path!()` macro: builds `&[PathElem]` slice

* `CborValueRef<'a>`

  * scalar reads: mostly O(1) (text is O(len))
  * container queries: O(bytes scanned)
  * `to_owned` (`alloc`): O(value_len)

* `MapRef<'a>`

  * `get/require`: O(bytes scanned until match/early-exit)
  * multi-key lookups: O(k log k + bytes scanned)
  * iter/extras: O(bytes in map) (+ optional key sorting costs)

* `ArrayRef<'a>`

  * `get`: O(bytes scanned up to index)
  * `iter`: O(bytes in array)

### Decoding (`alloc`)

* `decode_value(bytes, limits) -> Result<CborValue, CborError>`

  * Validates canonical then decodes.
  * **Time:** O(n)
  * **Space:** O(decoded_size)

### Encoding (`alloc`)

* `Encoder`

  * streaming canonical CBOR output
  * maps require canonical key order; enforced

* `ArrayEncoder`, `MapEncoder`

  * enforce arity + map canonical ordering

### Editing (`alloc`)

* `Editor`

  * set/insert/replace/delete semantics with conflict detection
  * array indices refer to the original array; cannot edit root via empty path
  * **Time:** O(n + Σ(u log u)) worst-case

### Macros (`alloc`)

* `cbor!` → `Result<CborValue, CborError>`

  * maps sorted for you (**O(m log m)**)
* `cbor_bytes!` → `Result<CborBytes, CborError>`

  * no sorting; order must already be canonical

### Serde (`serde` + `alloc`)

* `to_vec`, `from_slice`, `to_value`, `from_value_ref`
* `serde_value` helpers for struct fields
* numeric bignums are limited to `i128/u128` roundtrips through serde

---

## When to use what

* **You already have CBOR bytes and need fast reads:**
  `validate_canonical` → `CborBytesRef` → `at/get/iter`

* **You need an owned representation or want to manipulate values in memory:**
  `decode_value` → `CborValue` (+ `CborMap`, `CborInteger`)

* **You need to *emit* canonical CBOR efficiently:**
  `Encoder` / `cbor_bytes!`
  (ensure canonical map key order)

* **You need to patch existing canonical bytes without decoding everything:**
  `CborBytesRef::edit` / `CborBytes::edit`

* **You need serde:**
  `to_vec/from_slice` or `to_value/from_value_ref`

---

## Notes for maintainers / auditors

* `unsafe` is forbidden (`#![forbid(unsafe_code)]`).
* The validator is intentionally strict and rejects many CBOR features by design.
* All offset-bearing errors aim to point at the byte position where the violation is detected (serde conversions generally return offset 0).
