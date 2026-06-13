# Changelog

## Unreleased

## 0.6.0 `sacp-cbor-abi` release

Published crates:

- `sacp-cbor-abi` 0.6.0

### `sacp-cbor-abi`

- Fixed a serious runtime validation performance regression introduced in 0.5.0: no-hook
  `RuntimeFieldSetSchema::validate_value` and `RuntimeFieldSetView::get_checked` now use a
  dedicated no-hook validation engine instead of the hook-aware enter/exit callback engine.
- Reduced runtime error layout pressure by compacting `RuntimeAbiError::HookRejected.offset` to
  `u32` and adding `RuntimeAbiError::hook_rejected(reason, offset)` for ergonomic saturated
  construction from `usize` offsets.
- Restored the no-hook runtime validation hot path to zero hook callback work while keeping the
  explicit hook APIs and their balanced enter/exit semantics unchanged.
- This release is source-breaking relative to 0.5.0 for code that directly constructs or matches
  `RuntimeAbiError::HookRejected { offset }` as a `usize`; use
  `RuntimeAbiError::hook_rejected(...)` or match the compact `u32` field.

## 0.5.0 `sacp-cbor-abi` release

Published crates:

- `sacp-cbor-abi` 0.5.0

### `sacp-cbor-abi`

- Added runtime validation hooks with field, type, named-type, vector, vector-item,
  and balanced exit callbacks for semantic refinements on top of ABI validation.
- Added `RuntimeNamedDecision::Accepted` as the only hook-controlled validation
  replacement path, limited to `TypeRef::Named`; primitive and container ABI
  validation cannot be bypassed by hooks.
- Added hook-aware `validate_value_with_hooks` and `get_checked_with_hooks` on
  top of generic/static-dispatch runtime modes; no-hook validation uses
  monomorphized `NoRuntimeValidationHooks`.
- Replaced runtime validation options with the lean static mode API:
  `RuntimeInline`, `RuntimeRejectNamed`, `RuntimeResolveNamed<R>`,
  `RuntimeTypeMode`, and `RuntimeValidationConfig`.
- Changed `AbiSchemaRegistry` to return compiled `RuntimeSchema` values so named
  recursion avoids schema compilation and allocation on the validation hot path.
- Extended `RuntimeSchema` to cover struct, transparent, and primitive roots;
  runtime enum views remain unsupported.
- Added Criterion rows for concrete no-op hooks, concrete field hooks, named
  compiled-registry validation, named hook acceptance, and vector sorted/unique
  hook validation.
- Added a required Kani CI job for the ABI proof harnesses before release.
- **Breaking:** Removed `RuntimeAbiOptions` and `RuntimeTypeValidation`; callers
  now pass a static runtime type mode directly and pass recursion limits through
  `RuntimeValidationConfig` only where needed.
- **Breaking:** `RuntimeFieldSetSchema::validate_value` and
  `RuntimeFieldSetView::get_checked` now take generic `RuntimeTypeMode`
  values.
- **Breaking:** `RuntimeFieldSetSchema::validate_value_with_hooks` and
  `RuntimeFieldSetView::get_checked_with_hooks` now take
  `(mode, RuntimeValidationConfig, hooks)` and require concrete hook types for
  the normal public hot path.
- **Breaking:** `AbiSchemaRegistry::resolve` now returns a compiled
  `RuntimeSchema` instead of a raw `Schema`.
- **Breaking:** `RuntimeAbiError` is now `#[non_exhaustive]` and includes
  `HookRejected`.

## 0.4.1 `sacp-cbor-abi` release

Published crates:

- `sacp-cbor-abi` 0.4.1

### `sacp-cbor-abi`

- Added runtime schema-guided field-set validation and zero-copy views via
  `RuntimeFieldSetSchema`, `RuntimeFieldSetView`, `RuntimeAbiOptions`,
  `RuntimeTypeValidation`, `AbiSchemaRegistry`, and `compile_runtime_schema`.
- Added shell-only and deep `TypeRef` validation modes for runtime field-sets,
  including primitive bounds, fixed bytes, vectors, named-type reject/opaque
  policy, registry-backed named-type resolution, and recursion limits.
- Added sorted multi-field raw lookup for runtime views with
  `RuntimeFieldSetView::get_many_raw_sorted_into`, so callers can retrieve
  selected fields in one scan after validation.
- Optimized runtime validation and iteration hot paths by exploiting sorted
  field IDs with monotonic schema cursors instead of per-field binary search.
- Added runtime ABI Criterion rows for trusted/checked runtime views,
  inline deep validation, unknown-field preservation, and one-time schema
  compilation cost.
- Added Kani proof targets for runtime schema ID validation and required-field
  bitset tracking.

## 0.17.3 workspace release

Published crates:

- `sacp-cbor` 0.17.3
- `sacp-cbor-derive` 0.17.3
- `sacp-cbor-abi` 0.4.0
- `sacp-cbor-abi-derive` 0.3.0

### `sacp-cbor`

- Added borrowed canonical sub-value access via
  `CborValueRef::as_canonical_ref()`.
- Added integer widening helpers on borrowed integer views.
- Added hot-path inline annotations for zero-copy query wrappers.

### `sacp-cbor-derive`

- Version-only release to keep the companion derive crate aligned with
  `sacp-cbor` 0.17.3.

### `sacp-cbor-abi`

- Added ABI field-set view/editor runtime APIs, `decode_canonical`, borrowed
  unknown field/variant refs, and `AbiArrayView` for lazy array-element access.
- Added Kani proofs for ABI ID validation and sorted query-ID validation.
- Added ABI-specific Criterion scenarios for owned decode, view access,
  unknown preserve, enum access, and checked-vs-trusted view comparisons.
- Expanded the README's stable ABI section with concrete struct, enum,
  zero-copy view, unknown-field preservation, schema-diff, and facade examples.
- Added a crate-specific README for the published ABI package.
- **Breaking:** ABI field and variant IDs equal to `0` are now rejected at
  derive time or at runtime with `InvalidAbiValue`, including unknown
  ignore/preserve paths.
- **Breaking:** generated ABI views validate named enum payload field-sets and
  transparent `try_from` invariants during view construction, matching the
  owned decode contract before any accessor is called.

### `sacp-cbor-abi-derive`

- Added zero-copy ABI views generated by the existing `#[derive(CborAbi)]`
  entrypoint. The derive now emits `TypeView<'a>` types with borrowed typed
  accessors, raw field accessors, borrowed unknown-field/variant refs, and
  explicit `to_owned()` for the existing full decode path.
- **Breaking:** ABI field and variant IDs equal to `0` are now rejected at
  macro expansion time for known fields and variants.
- **Breaking:** generated ABI views validate named enum payload field-sets and
  transparent `try_from` invariants during view construction, matching the
  owned decode contract before any accessor is called.

## 0.17.2

- Re-exported `ArrayDecoder`, `MapDecoder`, and `MapKey` at the crate root:
  the container guards are part of the streaming decoder's public API and
  must be nameable for downstream helper functions.
- Added `ArrayDecoder::position` and `MapDecoder::position`: the current
  byte offset of the underlying decoder, for error reporting and span
  capture inside guard traversals.

## 0.17.1

- Added `Decoder::<true>::new_checked_with`: a checked streaming decoder that
  enforces `ValidationOptions` restriction modes (e.g. no-float) on every
  consumed value, skipped subtrees included.
- Added `Decoder::<true>::finish`, completing a checked pass into a
  `CanonicalCborRef` witness. A full typed traversal now validates in a
  single pass — no separate `validate_canonical` traversal needed. `finish`
  succeeds only when the pass consumed the input as exactly one canonical
  item (no poison, no trailing bytes, exactly one root value); acceptance
  equivalence with `validate_canonical[_with]` is property-tested
  (`tests/decode_witness.rs`).
- Added `MapDecoder::decode_value_with` and `ArrayDecoder::decode_next_with`:
  closure decoding with caller-defined error types (`E: From<CborError>`);
  caller errors poison the pass.
- Decode errors that consume input are now sticky: the decoder is poisoned
  and every later operation (including `finish`) fails with the first
  error. Non-consuming state-machine misuse (e.g. `next_value` before
  `next_key_ref`) remains recoverable. Stickiness is what makes the
  `finish` witness sound against callers that swallow errors.
- Fixed `Decoder::skip_value` ignoring restriction modes: skipped subtrees
  are now validated under the decoder's `ValidationOptions` (reachable only
  through the new `new_checked_with` constructor, so no released behavior
  changes).
- Root-value accounting and the options field are const-folded away on the
  trusted path; the decode hot loops are A/B-verified neutral within noise.
- README install snippets now track the current release line, enforced by a
  release-job check.

## 0.17.0

- Added an opt-in **no-float validation mode**: `ValidationOptions` (builder
  `ValidationOptions::new().no_float()`), `validate_canonical_with`,
  `CanonicalCbor::from_slice_with`, and `CanonicalCbor::from_vec_with` reject float64 values
  anywhere in an item with the new `ErrorCode::FloatForbidden` at the float header offset.
  Restriction modes only reject more inputs — every item accepted under a restriction mode is
  also a valid SACP-CBOR/1 item — and default validation is unchanged. The check sits on the
  float header path, so float-free inputs validate at the same cost as before.
- `SPEC.md` now defines **text identity** (no Unicode normalization; text equality is UTF-8 byte
  equality — codifying existing behavior as a normative commitment) and the **validation modes**
  contract (modes are a property of a validation call, not of the canonical witness; trusted
  re-traversal ignores them).
- `sacp-cbor-abi` 0.3.0 tracks the sacp-cbor 0.17 dependency; no ABI schema or wire changes.

## 0.16.1

- Optimized the shared validate/skip hot loop: the innermost open container is
  held in a register and the frame stack is touched only at container
  boundaries, removing per-item stack peeks. Speeds up `validate_canonical`,
  zero-copy queries, and editing (measured ~25% faster small-message
  validation, ~17% faster validate+query ingest, up to ~45% faster deep query
  paths). No API or wire-format changes.
- Optimized canonical encoding: item headers are built in a fixed buffer and
  written with a single reservation, and text/bytes payloads share one
  reservation with their header (~20% faster typical message encoding).
- Redesigned the benchmark suite around real SACP pipeline scenarios
  (validate / ingest / patch / encode / decode) on realistic message workloads,
  with pivot-table reports, competitor ratios, and a baseline regression mode
  (see `benchmarks/README.md`).

## 0.16.0

- **Breaking:** defined ABI profile `SACP_CBOR_ABI/1` with structured `TypeRef` schema identity, separate wire/full schema hashes, directional compatibility reports, unknown field and variant preservation, transparent newtypes, ABI facade paths, and golden-vector helpers.
- Added `ErrorCode::InvalidAbiValue` for ABI-level validation failures over otherwise canonical bytes.

## 0.15.0

- **Breaking:** crate-path attributes use token paths: `#[cbor(crate = my_crate::codec::cbor)]`.
- Made derives and `cbor_bytes!` facade-safe for wrapper traits by routing generated encode/decode calls through the configured runtime path.
- Added `ArrayEncoder::value_with` for facade and codegen integrations that need closure-based array element encoding.
- Added `sacp-cbor-abi` and `sacp-cbor-abi-derive` for stable public ABI schemas, numeric field/variant IDs, schema hashes, compatibility checks, and golden-vector tests.

## 0.14.0

- **Breaking:** derive container attributes are now validated on structs as well as enums; unsupported struct-level `#[cbor(...)]` attributes fail at compile time.
- Added a derive crate-path override so framework facades can provide the runtime API path used by generated impls.
- Tightened derive bounds for borrowed fields so lifetime-only field types do not receive unnecessary trait bounds.

## 0.13.0

- **Breaking:** derive decoding is exact by default: unknown fields and missing fields are rejected, explicit optional fields use injective `Option<T>`, `#[cbor(default)]` is rejected, and untagged enums are no longer part of the derive grammar.
- **Breaking:** removed the thin `validate` and `encode_into` public helpers; use `validate_canonical`, `encode_to_vec`, `encode_to_canonical`, or `Encoder` directly.
- **Breaking:** renamed the owned canonical witness accessor from `CanonicalCbor::as_ref()` to `as_canonical_ref()` to avoid conflicting semantics with `AsRef<[u8]>`.
- **Breaking:** collapsed editing to `set`, `delete`, `splice`, and `apply`, with explicit `PatchValue`, `SetMode`, and `DeleteMode`.
- **Breaking:** native and serde optional values use the same explicit injective `Option<T>` representation.
- **Breaking:** narrowed root exports; bytes, scalar, value, profile, query, and streaming container types are reached through their modules.
- **Breaking:** removed robust-core decoders for standard map/set collections; use `MapEntries` for fallible vector-backed map decoding. `BTreeMap` and `HashMap` remain encode conveniences.
- **Breaking:** reorganized feature topology: defaults are now `std` plus `derive`, `sha2` is opt-in, and `collections`, `edit`, `serde`, and `derive` explicitly require `alloc`.
- Added explicit `derive` and `EncodeLimits` APIs, with encoder enforcement for output bytes, depth, item counts, container lengths, and bytes/text lengths.
- Added `SPEC.md` for the maintained SACP-CBOR/1 wire/profile contract.
- Made sorted multi-key query APIs validate strictly sorted input and scan without allocation or sorting.
- Added `CborEncode::encode_array_item` so native encoders can use direct `ArrayEncoder` paths for array elements while retaining the guarded fallback.
- Simplified encoder/serde internals by removing the unused sink abstraction, serde root plumbing, and duplicated integer write paths.
- Refactored derive internals around a normalized schema model and removed duplicated attribute/type-bound paths.

## 0.12.0

- **Breaking:** externally tagged derive newtype variants now encode and decode as direct payloads (`{ "variant": value }`) instead of single-element arrays.
- **Breaking:** externally tagged derive enums without unit variants now reject text-form inputs with `ErrorCode::ExpectedEnum`; those enums are map-only on the wire.
- Fixed `CborDecode` derive for externally tagged enums with no unit variants so it no longer emits invalid Rust and now compiles against the map-only contract.
- Derive validation now rejects empty enums at compile time with a targeted error instead of generating invalid code.
- Added derive/serde parity coverage for externally tagged data-only enums, legacy-shape rejection coverage for external newtypes, and compile-fail coverage for empty enums.

## 0.11.0

- **Breaking:** external unit enum variants now encode and decode as CBOR text strings only (Serde-style) instead of one-entry maps.
- Added Serde-compatible enum tagging to `#[derive(CborEncode, CborDecode)]`:
  - `#[cbor(tag = "...")]` for internally tagged enums
  - `#[cbor(tag = "...", content = "...")]` for adjacently tagged enums
  - `#[cbor(rename_all = "...")]` for enum-level variant renaming, with variant `#[cbor(rename = "...")]` still taking precedence
- Derive validation now rejects unsupported internally tagged tuple variants at compile time with a targeted error.
- Updated serde streaming encode/decode to align with the new enum contract:
  - unit variants serialize as text
  - struct-like enum maps are canonically sorted before emission, so internally/adjacently tagged Serde enums no longer fail on field order
- Added derive/serde parity tests covering internal tagging, adjacent tagging, enum `rename_all`, per-variant rename overrides, unit/newtype/tuple/struct variants, and compile-fail coverage for invalid internal-tag tuple variants.
- Build hygiene: normalized `scripts/coverage.sh` to LF line endings and added `.gitattributes` enforcement for `*.sh` so Linux shell-based CI steps parse consistently.

## 0.10.2

- Fixed derive macro hygiene: generated `#[derive(CborEncode, CborDecode)]` impls now use fully-qualified `::core::result::Result`.
- Added native `CborEncode` / `CborDecode` support for fixed byte arrays (`[u8; N]`) with exact-length decode checks.
- Added native `CborEncode` / `CborDecode` support for `BTreeSet<T>` (`alloc`) with strict canonical set-order validation on decode (`ErrorCode::NonCanonicalSetOrder`).
- Added native decode/encode support for canonical wrappers in typed models:
  - `CborDecode` for `CanonicalCborRef<'a>`
  - `CborEncode` and `CborDecode` for `CanonicalCbor` (`alloc`)

## 0.10.1

- Added native `CborEncode` / `CborDecode` support for `BTreeMap<String, V>` and `HashMap<String, V>` (keys are sorted into canonical order on encode).
- Added serde helper `to_vec_sorted_maps` to encode maps with non-canonical iteration order by buffering and sorting text keys (existing `to_vec` remains strict).

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
