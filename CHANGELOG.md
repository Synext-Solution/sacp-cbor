# Changelog

## Unreleased stability work

No crate or workspace package version is changed by this work.

### `sacp-cbor`

- **Breaking:** encoding and decoding traits, encoder/decoder state machines, and their guarded
  adapters now carry one statically dispatched `WorkObserver`. The observation plumbing itself is
  allocation-free, with no trait objects or per-byte observer callbacks; ordinary entry points use
  the zero-sized `NoopWorkObserver`.
- Added deterministic observed entry points for canonical validation, typed decode, canonical-trusted
  decode, vector/canonical encoding, and sink-generic encoding. Enabled transactions issue an
  initial zero checkpoint, report completed engine work in deltas of at most
  `WORK_CHECKPOINT_INTERVAL`, and flush a final non-zero remainder before success.
- Added caller-owned `WorkSession<O>` with consuming `finish(self)`, plus session-aware borrowed
  array-query traversal, so multiple lazy operations can preserve one initial checkpoint, cadence,
  and final remainder. The cadence covers engine-owned metered work and bounds completed-work
  deltas, not wall-clock time inside a caller callback or one `ByteSink::write` call; those remain
  cooperative opaque boundaries.
- Observer cancellation is normalized to `ErrorCode::WorkCancelled`. Decoder cancellation preserves
  the first sticky error and cannot be resumed. Encoder cancellation poisons the encoder, does not
  call sink `finish`, and does not roll back already confirmed sink output; a sink may also retain
  unconfirmed physical side effects under its existing failure contract.
- Canonical walks, raw canonical accounting, typed and prepared decode traversal, array/map batch
  traversal, derived tagged-enum sub-value decoding, structural encode steps, and observer-enabled
  sink writes now use the same work model. Targeted canonical, byte-loop, decode, derive, encode,
  ABI-projection, and borrowed-view tests reject only after one full interval, demonstrating
  cancellation after loop entry rather than only at admission.

### `sacp-cbor-abi`

- **Breaking:** ABI encode/decode and projection traits propagate the core static observer through
  owned values, derived codecs, exact-indexed sequences, source-driven sequence emitters, and
  `CountingSink` sizing. Encode cancellation remains a core encode error rather than being
  collapsed into projection, sequence-contract, or sink failure; ABI decode cancellation
  originates as `CborError(ErrorCode::WorkCancelled)` before conversion through
  `AbiDecodeContext::Error::from`.
- Added the observed ABI entry points `encode_to_sink_with_observer`,
  `encode_to_vec_with_observer`, `decode_with_observer`, and
  `decode_canonical_with_observer`.
- Source-driven projections are observed at engine-owned `SequenceEmitter::emit` boundaries. Code
  executing inside caller callbacks or between emitter calls remains cooperative caller work and
  cannot be preempted by the CBOR engine.
- For a generated record view's sequence field, the observed manifest path is
  `*View::from_canonical_with_session` to a generated field `*_with_session` and then
  `AbiArrayView::cursor` / `AbiArrayViewCursor::next_with_session`. The cursor stores no session and
  borrows it only for one step, so the same caller-owned cadence can enter an outer sequence record,
  traverse that record's nested `*_with_session` field and cursor, then return to the outer cursor.
  Record scans, value-boundary traversal, and lazy zero-copy sequence walks share that state;
  ordinary view and `iter` methods remain the `NoopWorkObserver` path.

## 0.18.2 workspace release

Published crates:

- `sacp-cbor` 0.18.2
- `sacp-cbor-derive` 0.18.2
- `sacp-cbor-schema` 0.2.2
- `sacp-cbor-abi` 0.9.0
- `sacp-cbor-abi-derive` 0.6.0

The ABI protocol profile remains `SACP_CBOR_ABI/1`.

### `sacp-cbor`

- Added guarded value and definite-array adapters that preserve a caller-defined typed error domain.
  Callback failure, sink failure, underfill, overfill, and swallowed inner failures all poison the
  encoder, while impossible declared lengths and limit failures are rejected before projection or
  output.
- Added `FanoutSink`, which drives two sinks in one encoding pass and reports which branch failed.
- The encoder now keeps its first 32 container frames inline and migrates fallibly only for unusually
  deep values. Ordinary encoding and bignum magnitude emission no longer allocate intermediate
  storage.
- These core changes are additive; existing core encoding and decoding entry points retain their
  signatures and wire behavior.

### `sacp-cbor-derive`

- Version-only release required by the root crate's exact companion dependency.

### `sacp-cbor-schema`

- Dependency-only patch release tracking the exact `sacp-cbor` 0.18.2 runtime.

### `sacp-cbor-abi`

- **Breaking:** schema ownership is separated from Rust storage. Derived types expose one static,
  allocation-free `Schema`; protocol sequences are represented by `wire::Sequence<W>` instead of a
  Rust `Vec<T>` schema node. Existing sequence data bytes remain unchanged, while sequence-bearing
  schema hashes intentionally change from the old carrier-named normal form.
- **Breaking:** ABI encoding entry points are sink-generic and require explicit `EncodeLimits`.
  `AbiEncodeError` preserves projection, exact-sequence contract, core profile, and owned sink
  failures without collapsing them into a generic CBOR error.
- The same derived schema owner can encode its owned `Vec<T>` fields, borrowed slices, exact indexed
  projections, or source-driven projections without materializing a wire DTO. Generated projection
  traits expose semantic field and variant methods; business adapters never provide numeric wire
  IDs.
- Exact sequence sources declare their length independently of iteration. Underfill and overfill are
  checked transactionally, including when a source swallows an inner error; ordinary `Iterator` and
  `ExactSizeIterator` types are deliberately not admitted by blanket implementation.
- Static schema canonicalization and hashing stream directly to caller sinks and SHA-256. The static
  hot path contains no schema-side `String`, `Vec`, or `Box` construction.
- **Breaking:** runtime validation now borrows static descriptors through `RuntimeSchema::new`; the
  allocation-backed `compile_runtime_schema` layer is removed. Caller-prepared workspaces remain
  reusable and stack-safe.
- **Breaking:** string-based `#[abi(ty = "...")]` schema overrides are removed because they could
  declare an identity that the codec did not prove. Derived schema, codec, view, and projection code
  now share one parsed owner model.
- The runtime is now genuinely `no_std` with allocation-backed owned values when default features are
  disabled; the default `std` feature adds standard error integration.

### `sacp-cbor-abi-derive`

- **Breaking:** generated code targets the static schema and storage-independent projection APIs in
  `sacp-cbor-abi` 0.9. Struct fields and enum variants are selected through generated semantic
  interfaces, and owned encoding delegates to the same generated projection driver.
- Generated schemas use only static descriptors, and protocol IDs, presence rules, unknown policies,
  codec paths, views, and projection adapters are emitted from one validated derive model.
- Removed string type-identity override parsing and added compile-time rejection for legacy override
  syntax and iterator-based sequence misuse.

## 0.18.1 workspace release

Published crates:

- `sacp-cbor` 0.18.1
- `sacp-cbor-derive` 0.18.1
- `sacp-cbor-schema` 0.2.1
- `sacp-cbor-abi` 0.8.0
- `sacp-cbor-abi-derive` 0.5.0

### `sacp-cbor`

- Added guarded text and byte payload decode funnels. The caller observes the canonical, core-limited
  declared length after its header is consumed and before payload read, UTF-8 validation, or owned
  copy. Caller errors remain typed and poison the single-pass decoder.
- Added consuming array admission after canonical length and structural limits but before caller
  allocation. Empty-array refusal is sticky as well.
- Added guarded canonical-value traversal so callers can admit the validated encoded length before
  copying the complete value into owned storage.
- `CanonicalCborRef::to_owned_with_offset` preserves a caller-known absolute input offset in the
  allocation failure diagnostic for nested canonical values.
- `Decoder::finish` now closes both checked and canonical-trusted passes with the same poison,
  trailing-input, and traversal-protocol checks.
- This is additive: no published core API was removed or changed.

### `sacp-cbor-derive`

- Version-only release required by the root crate's exact companion dependency.

### `sacp-cbor-schema`

- Dependency-only patch release tracking the exact `sacp-cbor` 0.18.1 runtime.

### `sacp-cbor-abi`

- **Breaking:** owned decode has one context-carrying API. `AbiDecode` is parameterized by
  `AbiDecodeContext`; `decode`, `decode_canonical`, and generated view `to_owned` require the same
  explicit mutable context. The old context-free trait method and entry-point signatures are removed.
- `Vec`, `String`, `Bytes`, owned canonical values, and preserved unknowns invoke typed admission
  after core grammar/length limits and before their first reservation or payload copy. Location
  metadata identifies the stable type, variant, and field without counting ABI framing arrays as
  semantic sequences. Borrowed values remain zero-copy and emit no owned-admission event.
- Preserved unknown fields are admitted and fallibly reserved by actual observed count instead of
  reserving the enclosing field-set's upper bound.
- Nested owned canonical values report allocation failure at their actual payload header instead of
  losing the location at offset zero.

### `sacp-cbor-abi-derive`

- **Breaking:** generated struct, enum, transparent, nested-field, unknown-preservation, and
  `to_owned` decoders recursively thread one caller context and its typed error domain.
- Borrowed transparent views no longer allocate an owned value to enforce `try_from`; that semantic
  invariant is checked by explicit owned decode while view construction validates wire structure.

Release publication now waits for both the authenticated registry artifact and Cargo index
resolution, including recovery of an identical artifact published by an interrupted prior run.

## 0.18.0 workspace release

Published crates:

- `sacp-cbor` 0.18.0
- `sacp-cbor-derive` 0.18.0
- `sacp-cbor-schema` 0.2.0
- `sacp-cbor-abi` 0.7.0
- `sacp-cbor-abi-derive` 0.4.0

### `sacp-cbor`

- **Breaking:** canonical encoding now has one sink-generic path through
  `Encoder<S: ByteSink>`; vector, byte-count, digest, standard I/O, serde,
  derives, and custom sinks share the same state machine and limits.
- Sink and profile failures are sticky. The first call returns its owned
  `EncodeError`; every later fallible encoding or finish operation is rejected
  as `Poisoned` because a generic sink cannot promise rollback after partial
  side effects. Read-only state observation remains available.
- Map keys are checked from their source text before any offending key byte is
  written. The encoder rejects duplicate or descending keys and never sorts or
  repairs input.
- Added `VecSink`, `CountingSink`, optional `DigestSink<D>`, and `IoSink<W>`;
  upgraded the optional SHA-2 integration to 0.11.
- The published runtime crates now require Rust 1.85, matching SHA-2 0.11's
  compiler floor; the two proc-macro-only crates retain Rust 1.75.

### `sacp-cbor-derive`

- **Breaking:** generated `CborEncode` implementations target the controlled,
  sink-generic value adapter so custom errors cannot bypass sticky encoder
  state.

### `sacp-cbor-schema`

- **Breaking:** schema compilation and validation use explicit caller-selected
  limits and fallibly prepared reusable workspaces instead of fixed field and
  recursion caps.
- **Breaking:** structural containment is replaced by bounded inclusion with
  distinct `Proven`, replayable `Refuted`, and operational `Unknown` outcomes.
  Deep validation and inclusion use explicit machines rather than the native
  call stack.

### `sacp-cbor-abi`

- **Breaking:** runtime semantic hooks and named-value acceptance bypasses are
  removed. Runtime admission is structural, covers struct, enum, transparent,
  primitive, vector, fixed-byte, and named schemas, and resolves named schemas
  only through the caller's registry.
- Runtime admission uses explicit work limits and caller-prepared reusable
  frame storage, so deep validation is stack-safe and allocation-free after
  preparation.
- Owned vector decoding and generated unknown-field preservation reserve their
  complete bounded capacity before the first element is stored and report
  allocation refusal as `AllocationFailed` at the enclosing array offset.

### `sacp-cbor-abi-derive`

- **Breaking:** generated ABI encoders target the sink-generic 0.7 runtime
  facade and preserve the encoder's sticky-failure contract.

## 0.17.6 workspace release

Published crates:

- `sacp-cbor` 0.17.6
- `sacp-cbor-derive` 0.17.6 (dependency-only)
- `sacp-cbor-schema` 0.1.1 (dependency-only)
- `sacp-cbor-abi` 0.6.3 (dependency-only)

### `sacp-cbor`

- New `cde` feature: RFC 8949 Core Deterministic Encoding (CDE) bridge under
  `sacp_cbor::cde`. `to_cde` converts a canonical SACP-CBOR/1 item to its CDE
  image (total; rewrites only integer and float spellings, never grows the
  item). `from_cde` validates untrusted CDE bytes, converts the two deviating
  normal forms, and re-validates the image under the full SACP-CBOR/1 grammar
  and the caller's limits, with typed rejections for CDE shapes outside the
  profile. The two directions are mutually inverse on the shared subset.
  Frozen cross-profile vectors live in `tests/fixtures/cde_vectors.txt`.

## 0.17.5 workspace release

Published crates:

- `sacp-cbor` 0.17.5
- `sacp-cbor-schema` 0.1.0 (new)
- `sacp-cbor-derive` 0.17.5
- `sacp-cbor-abi` 0.6.2

### `sacp-cbor-schema` (new crate)

- Closed-record schema validation for canonical SACP-CBOR/1 values, `no_std` + `alloc`.
  A compiled `RecordSchema` validates untrusted bytes in one checked-decoder traversal
  (grammar, shape, and value constraints, returning the canonical witness), checks trusted
  witnesses, and derives structural containment (compatibility directions) between schema
  versions. Closed-key records with presence couplings; `Int`/`Bool`/`Float64`/`Bytes`/`Text`/
  `Array`/`Set`/`Map`/`Union`/`Record`/`Any` types; `range`/`count`/`enum` constraints;
  `Grammar`/`Shape`/`Constraint` fault taxonomy with offsets and field paths. Includes a
  normative SPEC.md, differential and property tests, adversarial edge vectors, a fuzz
  target, and a throughput benchmark suite.

### `sacp-cbor`

- Added a zero-copy streaming integer decode: `query::IntegerRef` now implements `CborDecode`,
  consuming one integer-kind value (safe int or bignum) through the direct scalar funnel with
  no subtree walk and no allocation.
- Added kind-checked scalar consumption funnels: `ScalarKind`, `Decoder::skip_scalar`,
  `ArrayDecoder::skip_scalars` (batch homogeneous consume), and `ArrayDecoder::next_scalar_span`
  (per-element canonical byte range). One header read per value, direct funnels, no subtree
  walk; wrong kinds report the kind's `Expected*` code at the header offset.
- Added `ArrayDecoder::skip_sorted_scalars`: the sorted-set batch form with the strictly-ascending
  memcmp order comparison inlined, reporting `DuplicateElement` / `NonAscendingElement` (new
  `ErrorCode` variants) at the violating element's header offset.

### `sacp-cbor-derive`

- Dependency-only patch release to track `sacp-cbor` 0.17.5.

### `sacp-cbor-abi`

- Dependency-only patch release to track `sacp-cbor` 0.17.5.

## 0.17.4 workspace release

Published crates:

- `sacp-cbor` 0.17.4
- `sacp-cbor-derive` 0.17.4
- `sacp-cbor-abi` 0.6.1

### `sacp-cbor`

- Added the no-simple restriction mode (`ValidationOptions::no_simple` /
  `forbid_simple`): rejects the simple values `false`, `true`, and `null`
  anywhere in the item with the new `ErrorCode::SimpleForbidden` at the
  simple-value header offset, in both the batch validator and the checked
  decoder (typed, skip, and owned-constructor paths). Restriction-mode
  semantics are unchanged: modes only reject more inputs, and trusted
  re-traversal ignores them.
- Added `cbor_bytes!` support for Rust repeat byte-array expressions such as
  `[0u8; 32]`, encoded through the existing `[u8; N]` `CborEncode` fast path as
  CBOR byte strings. Comma arrays such as `[1, 2, 3]` keep their existing CBOR
  array-literal meaning.
- Documented the `cbor_bytes!` bracket-expression boundary, including the
  parenthesized Rust-expression escape for ordinary array literals.

### `sacp-cbor-derive`

- Updated `cbor_bytes!` parsing to treat only Rust repeat array expressions as
  expression values, preserving the existing CBOR array-literal grammar for
  comma arrays.
- Reused the shared encoded-text-key helper for compile-time map key sorting in
  `cbor_bytes!`, keeping derive and macro ordering logic aligned.

### `sacp-cbor-abi`

- Dependency-only patch release to track `sacp-cbor` 0.17.4.

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
