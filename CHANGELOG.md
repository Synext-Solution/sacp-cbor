# Changelog

## 0.7.0

- **Breaking:** removed serde `to_value` / `from_value` conversion helpers; serde now streams directly to `Encoder` and decodes via borrowed `CborValueRef`.
- Added zero-copy serde deserialization helpers (`from_slice_borrowed`, `from_bytes_ref_borrowed`, `from_value_ref_borrowed`) and `CborRefDeserializer`.

## 0.6.0

- **Breaking:** `Encoder::into_canonical()` now returns `Result<CborBytes, CborError>` and errors if the buffer does not contain exactly one CBOR item.
- **Breaking:** `EditEncode` is now sealed; only the built-in edit value types are supported.
- **Breaking:** `EditValue` is now an opaque type (no public constructors), preventing invariant-violating edits.
- Added `MapEncoder::entry_raw_key` and optimized editor map splicing to reuse encoded key bytes.
- Centralized fallible allocation and tightened error reporting (length overflow vs allocation failure) across alloc paths.
- Editor now maintains ordered children/splices on insertion, removing per-emit sorting and duplicate scans.

## 0.5.0

- **Breaking:** renamed canonical owned/borrowed bytes to `CborBytes`/`CborBytesRef` and encoder/editor to `Encoder`/`Editor`.
- **Breaking:** `CborBytesRef::to_owned()` now returns `Result<CborBytes, CborError>` to surface allocation failures.
- **Breaking:** array edits are now splice-based; `insert/delete/replace` on array indices are supported and indices are interpreted against the original array.
- Added array splice API (`Editor::splice`, `ArrayPos`, `ArraySpliceBuilder`) and `push`/`push_encoded` helpers.
- Made `Encoder::array` and `Encoder::map` transactional on errors.
- Added `CborBytes::from_vec` / `from_vec_default_limits` for zero-copy owned validation.
- Added `Encoder::int_i128` / `int_u128` and centralized bignum magnitude handling.
- Tightened trusted decode to range-checked API and removed redundant trailing-byte validation.
- Improved allocation-failure handling across fallible APIs.

## 0.4.1

- Patch release: no-alloc query sorting fix and build hygiene updates.

## 0.4.0

- Re-architected validation around a single canonical walker; query traversal now shares the same value-end logic.
- Added direct decode path (`decode_value`) layered on canonical validation.
- Added `CborIntegerRef` and unified query integer handling (`CborKind::Integer`).
- Reworked query helpers for multi-key lookup, extras, and required keys; fixed view equality semantics.
- Added direct canonical encoder (`CanonicalEncoder`) and `cbor_bytes!` macro for zero-copy splicing.
- Added serde support for `CborValue` and `serde_value` helper module (feature `serde`).
- Updated fuzz targets and tests for the new APIs.

## 0.3.0

- Added the `cbor!` macro for fallible, JSON-like construction of `CborValue` (alloc feature).
- Added integration tests for the macro (canonical encoding, bignum boundaries, float rules, key ergonomics).
