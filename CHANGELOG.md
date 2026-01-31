# Changelog

## 0.10.0

- **Breaking:** `Decoder` is now const-generic over `CHECKED`, and `CborDecode::decode` now accepts `Decoder<'_, CHECKED>` (use `CheckedDecoder`/`TrustedDecoder` aliases as needed).
- **Breaking:** Dropping `ArrayDecoder`/`MapDecoder` before consuming all items now poisons the decoder; subsequent reads return an error instead of silently continuing.
- Fallible allocation is enforced for `String`, `Vec<u8>`, `MapEntries<String, V>`, and query extras (OOM now maps to `AllocationFailed` instead of panicking).
- Allocation errors now distinguish capacity overflow vs allocation failure more consistently across alloc paths.
- `Encoder::into_canonical` now relies on internal invariants (single-item tracking) without a second-pass validation.

## 0.9.0

- **Breaking:** `cbor_bytes!` is now a procedural macro that sorts map keys at compile time; dynamic keys are no longer supported in the macro (use `Encoder` for dynamic keys).
- **Breaking:** `Decoder::new` was removed; use `Decoder::new_checked` or `Decoder::new_trusted` (canonical bytes only).
- **Breaking:** trusted decoding no longer applies canonical float-bit validation (consistent with other trusted paths).
- Derived encoders sort named map fields by canonical key order at compile time.
- Tests updated to cover map ordering for derives and `cbor_bytes!`.

## 0.8.0

- **Breaking:** renamed feature `unsafe-utf8` to `unsafe`.
- Added unsafe canonical constructors behind the `unsafe` feature (`CborBytesRef::from_canonical`, `CborValueRef::from_canonical_range`).
- Refactored `sacp-cbor-derive` internals to reduce boilerplate and shared decode/encode helpers.
- Enabled `clippy::all` deny in both crates; added missing crate-level docs for the derive crate.

## 0.7.1

- Added `sacp-cbor-derive` workspace crate and `#[derive(CborEncode, CborDecode)]`.
- Optimized skip/query hot paths (inline stack reuse, primitive fast paths, less UTF-8 work in trusted queries).
- Reduced map-key order check overhead by consolidating comparisons.
- CI/release fixes: publish derive crate first, robust crates.io version check, and publish metadata cleanup.

## 0.7.0

- **Breaking:** removed owned value tree APIs and the `cbor!` macro; encoding is streaming-only via `Encoder`/`cbor_bytes!`.
- **Breaking:** removed serde `to_value` / `from_value` conversion helpers; serde now streams directly to `Encoder` and validates+deserializes in a single pass from bytes (`from_slice` / `from_slice_borrowed`).
- **Breaking:** removed `from_value_ref`, `from_bytes_ref_borrowed`, `from_value_ref_borrowed`, and `CborRefDeserializer` in favor of the direct single-pass deserializer.
- **Breaking:** removed `decode_value`, `decode_value_trusted`, and `decode_value_canonical`; owned decoding now goes through serde `from_slice` / `from_slice_borrowed` (single-pass, inline validation).
- Added canonical-trusted serde decode helpers (`from_canonical_bytes_ref`, `from_canonical_bytes`) for validated canonical bytes.

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
- Updated fuzz targets and tests for the new APIs.

## 0.3.0

- Added integration tests for the macro (canonical encoding, bignum boundaries, float rules, key ergonomics).
