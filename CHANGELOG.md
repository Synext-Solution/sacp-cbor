# Changelog

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
