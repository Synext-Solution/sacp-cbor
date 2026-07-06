# SACP-CBOR/1 Specification

This document defines the canonical CBOR profile implemented by this crate.

## Wire Grammar

```text
Value ::=
    SafeInt
  | BigInt
  | Bytes
  | Text
  | Array
  | Map
  | Bool
  | Null
  | Float64

SafeInt ::= CBOR major 0 or 1 integer in [-(2^53 - 1), +(2^53 - 1)]
BigInt  ::= tag 2 or tag 3 followed by a canonical byte-string magnitude
Bytes   ::= definite-length CBOR byte string
Text    ::= definite-length UTF-8 CBOR text string
Array   ::= definite-length array of Value
Map     ::= definite-length map of Text key to Value
Bool    ::= false or true
Null    ::= null
Float64 ::= CBOR float64
```

One encoded item is one complete `Value` with no trailing bytes. Indefinite lengths, unsupported
tags, non-text map keys, unsupported simple values, float16, float32, break bytes, and reserved
additional-info values are outside this grammar.

## Canonical Encoding

All integer and length arguments use the shortest CBOR form. Maps are sorted by canonical text-key
order: compare the encoded CBOR text keys by encoded length first, then lexicographically by the
encoded bytes. Duplicate map keys are rejected.

For text keys with equal CBOR header length, this is equivalent to comparing UTF-8 payload bytes.
At length-boundary header changes such as 24, 256, and 65536 bytes, the header contributes to the
encoded length and therefore to the ordering.

## Numeric Rules

The safe integer range is exactly `[-(2^53 - 1), +(2^53 - 1)]`.

Positive bignums use tag 2 and negative bignums use tag 3. Bignum magnitudes are non-empty
big-endian byte strings with no leading zero byte, and bignums must represent values outside the
safe integer range.

Floats are encoded only as CBOR float64. Negative zero is rejected. NaN is accepted only as the
canonical bit pattern `0x7ff8_0000_0000_0000`. Positive and negative infinity are allowed.

## Text Identity

Text strings are validated as UTF-8 and compared as encoded bytes. The profile applies **no
Unicode normalization**: two text strings are equal exactly when their UTF-8 bytes are equal.
Visually identical strings with different code point sequences are different values, different map
keys, and produce different canonical bytes and hashes. Producers that require a normal form (such
as NFC) must normalize before encoding; the profile neither performs nor verifies normalization,
so any normal-form requirement is a schema-layer contract, not a wire rule.

## Validation Modes

Validation accepts an optional set of restriction modes (`ValidationOptions`). Restriction modes
only reject more inputs: every item accepted under a restriction mode is also a valid SACP-CBOR/1
item, so restricted and unrestricted consumers interoperate in one direction by construction.
Modes do not define new wire profiles; the wire grammar above is the only grammar.

The **no-float mode** (`ValidationOptions::no_float`) rejects float64 values (major type 7,
additional info 27) anywhere in the item with `FloatForbidden` at the float header offset. It
exists for deployments whose durable data model excludes floating point and which want that rule
enforced at the validation boundary rather than by schema convention.

The **no-simple mode** (`ValidationOptions::no_simple`) rejects the simple values `false`, `true`,
and `null` (major type 7, additional info 20..=22) anywhere in the item with `SimpleForbidden` at
the simple-value header offset. It exists for deployments whose durable data model has no boolean
or null term — expressing optionality by key omission and booleans as schema-constrained
integers — and which want that rule enforced at the validation boundary rather than by schema
convention. Modes compose: an item accepted under both no-float and no-simple contains no
major-type-7 item.

Modes are a property of a validation call, not of the validated bytes: the canonical witness types
attest SACP-CBOR/1 canonicality only. Trusted re-traversal of already-validated bytes (queries,
editing, trusted decode) ignores restriction modes; callers that require a restriction across an
editing or re-encoding round trip re-validate the output under the same options.

## Resource Limits

`DecodeLimits` applies to input validation and decoding:

- `max_input_bytes` bounds the full input slice length.
- `max_depth` counts arrays and maps; a root container has depth 1.
- `max_total_items` counts contained array values and both keys and values in maps.
- `max_array_len`, `max_map_len`, `max_bytes_len`, and `max_text_len` bound the corresponding
  declared lengths.

`EncodeLimits` applies to `Encoder`:

- `max_output_bytes` bounds the emitted byte buffer.
- `max_depth`, `max_total_items`, `max_array_len`, `max_map_len`, `max_bytes_len`, and
  `max_text_len` use the same semantics as decode limits.

Raw canonical splicing through the encoder is scanned against the active encode limits before it is
copied to output.

## Trusted References

`CanonicalCborRef<'a>` is a witness that `&'a [u8]` is one complete SACP-CBOR/1 value. `CanonicalCbor`
is the owned form of that witness. `CborValueRef<'a>` is a subrange of a canonical root and must span
exactly one complete value.

Unchecked constructors are available only behind the `unsafe` feature. Their safety precondition is
that the caller has already established the same invariants that validation would establish for the
provided bytes and ranges.

## Derived Schema Normal Form

Derived structs decode exact canonical maps:

- unknown fields are rejected;
- missing non-skipped fields are rejected;
- native optional values use `Option<T>` and encode injectively as `{ "none": null }` or
  `{ "some": value }`;
- `#[cbor(default)]` is not part of the derive grammar;
- skipped fields are local Rust state and are filled with `Default::default()`;
- generated decoders expect fields in canonical key order.

Derived enums support external, internal, and adjacent tagging. Untagged enums are not part of the
derive grammar. External unit variants use the same one-entry map shape as data variants, with a
`null` payload. Adjacent variants always include both tag and content; unit content is `null`.
Internal variants reject fields not belonging to the selected variant.

## Stable ABI Schema Layer

The optional `sacp-cbor-abi` crate defines public ABI codecs above this canonical profile.
ABI structs encode as field-set arrays of `[field_id, value, ...]` sorted by nonzero numeric field
ID. ABI enums encode as `[variant_id, payload]`, where unit payloads are `null` and named variant
payloads are field-set arrays. Optional fields are `Option<T>` and are omitted when absent; required
`Option<T>` is rejected by the derive macro. ABI schemas include a stable type ID, version, profile,
structured type references, numeric field and variant IDs, unknown-field policy, and unknown-variant
policy. The schema layer defines separate SHA-256 hashes for wire-significant data and full
diagnostic metadata. Unknown fields may be rejected, ignored, or preserved; unknown enum variants
may be rejected or preserved. Lifetime-only derived ABI types may borrow decoded field values from
the input.

## Collection Policy

`Vec<T>` represents a CBOR array. Byte strings use `Bytes`, `BytesRef`, byte slices, or fixed byte
arrays. `MapEntries<K, V>` is the fallible vector-backed map representation. Standard collection map
types are encode conveniences; robust decode paths use vector-backed representations.

## Editing Semantics

The editor operates on validated canonical input and emits a new `CanonicalCbor` through `Encoder`.
`set`, `delete`, and `splice` are the complete patch surface. Map operations use paths ending in
`PathElem::Key`; array replacements and deletes use paths ending in `PathElem::Index`; structural
array edits use `splice`. Missing nested maps are not created implicitly. Conflicting edits,
overlapping array splices, edits inside deleted array ranges, and map/array path kind mismatches are
rejected.

## CDE Interoperability Bridge

The optional `cde` feature bridges SACP-CBOR/1 and RFC 8949 Core Deterministic
Encoding (CDE). The two profiles encode the same data model and differ in
exactly two normal forms: CDE head-encodes every integer whose argument fits an
unsigned 64-bit head and uses tags 2/3 only beyond that, where SACP-CBOR/1
head-encodes only the safe range; and CDE uses the shortest of
float16/float32/float64 with `0xf97e00` as the preferred NaN, where SACP-CBOR/1
uses float64 only. Everything else, including the text-key map order, coincides
byte for byte.

`cde::to_cde` maps a canonical item to its CDE image and is total: only integer
and float spellings are rewritten, every other octet is copied verbatim, and the
image is never longer than the input. `cde::from_cde` validates untrusted CDE
bytes, converts the two deviating normal forms, and re-validates the converted
image under the full SACP-CBOR/1 grammar and the caller's limits; CDE shapes the
profile excludes (non-text map keys, foreign tags, extra simple values, negative
zero, non-preferred NaNs) are rejected with their typed codes. On the shared
subset the two functions are mutually inverse. Array order is preserved
verbatim; a schema-level sorted-set convention over encoded element bytes is
re-canonicalized by the schema layer, not by the bridge.

## Allocation and Safety

Validation and borrowed query traversal are allocation-free. Owned decode paths use fallible
reservation before vector/string construction where Rust exposes that boundary. Standard collection
decoding is not part of the robust core because standard map/set insertion does not provide a fully
fallible allocation contract.

The default build forbids unsafe code. The `unsafe` feature is limited to trusted-boundary
constructors and unchecked UTF-8 conversion for already canonical data.

## Verification Status

The crate verifies this profile with validation vectors (including no-float and no-simple restriction-mode
vectors), derive compile-fail tests, feature-matrix builds, benchmark/fuzz target compilation, and
a Miri smoke test for the unsafe feature. The CDE bridge is verified with frozen cross-profile vectors, an exhaustive float16 sweep against an arithmetic widening oracle, property-based round-trip and acceptance-law tests, and a dedicated fuzz target.

Bounded Kani proof harnesses, compiled only under `cfg(kani)`, cover these core obligations:

- shortest unsigned-integer additional-info classification;
- checked unsigned-integer argument roundtrip and non-minimal rejection for additional-info
  `24..=27`;
- checked length decoding rejection for indefinite lengths without cursor advance;
- float bit-pattern classification for negative zero and non-canonical NaNs;
- bignum safe-range boundary classification;
- text-key payload ordering equivalence to encoded-key ordering for payload lengths `0..=3`;
- duplicate text-key detection for payload lengths `0..=3`;
- encoder rollback after failed/underfilled array callbacks;
- encoder root-slot and one-element array slot conservation.

Run the harnesses with `scripts/proof.sh` on a Kani-supported host. Full recursive value skipping,
edit-map merging, and generated-schema roundtrips are covered by tests and fuzz target compilation,
not claimed as Kani-proven properties. These checks are assurance evidence for this implementation;
they are not an independent safety certification.
