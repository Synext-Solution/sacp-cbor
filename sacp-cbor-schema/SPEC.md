# sacp-cbor-schema Specification

This document defines the closed-record schema model for canonical SACP-CBOR/1 values.

## Scope

A `RecordSchema` admits a set of canonical SACP-CBOR/1 values. The root value is a record. A record is a CBOR map with text keys and a closed field table: every present key is declared, and every required field is present.

The schema layer never weakens SACP-CBOR/1 canonical grammar. A value admitted by a schema is a valid canonical SACP-CBOR/1 item.

## Fixed Caps

The model has fixed caps:

- 64 fields per record node.
- 16 constraints per field.
- 64 enum members per enum constraint.
- 64 union alternatives per union type.
- 16 couplings per record node.
- 2 to 16 keys per multi-key coupling.
- 32 schema type nesting levels.

These caps are model constants and are not schema-configurable.

## Records

A record is encoded as a CBOR map. Keys are text strings. The SACP-CBOR/1 base grammar enforces canonical map key order and uniqueness. The schema compiler sorts declared fields by the same canonical text-key order: payload length first, then payload bytes.

During validation, the encoded map entries and the compiled field table are merge-joined. An undeclared key is rejected. A missing required key is rejected. Optional keys may be omitted.

Nested records use the same rules as the root record and have independent field tables, constraints, couplings, and presence bitsets.

## Types

The field type grammar is closed:

- `Int`: a safe SACP-CBOR/1 integer or a tag 2/3 bignum.
- `Bool`: `false` or `true`.
- `Float64`: canonical SACP-CBOR/1 float64.
- `Bytes`: byte string.
- `Text`: UTF-8 text string.
- `Array(T)`: CBOR array, every element checked as `T`.
- `Set(T)`: CBOR array, every element checked as `T`, with set ordering rules below.
- `Map(T)`: CBOR map with text keys and homogeneous values checked as `T`. The key set is not closed by the schema.
- `Union(alts)`: coded union with a closed code table.
- `Record(node)`: nested closed record.
- `Any`: any canonical SACP-CBOR/1 value.

There is no `Null` schema type. Absence is represented by omitting an optional key. An explicit no-value case is represented by a payload-free union alternative.

## Sets

A set is encoded as a CBOR array. Each element is checked against the element type. Element encodings must be strictly ascending by unsigned lexicographic byte order over the canonical encoded bytes. Equal adjacent encodings are duplicates and are rejected.

This order is deliberately bytewise memcmp order. It is not the canonical map-key order, which compares encoded length first and then bytes. Canonical CBOR items are self-delimiting, so no element encoding is a proper prefix of a different complete element encoding.

## Homogeneous Maps

`Map(T)` is a CBOR map with text keys. The SACP-CBOR/1 base grammar enforces key order and uniqueness. The schema does not close the key set. Every map value is checked against `T`.

## Unions

A union is encoded as either `[code]` or `[code, payload]`.

The `code` is a non-negative safe integer representable as `u64`. It must appear in the union's closed code table. A payload-free alternative has arity 1. A payload alternative has arity 2 and the payload is checked against the alternative type. The code table has at most 64 alternatives and codes are unique.

## Constraints

Constraints apply to a field's decoded value as a whole. They do not attach to structural children beneath that field unless those children are fields of nested records. Multiple constraints on one field are combined by logical AND. Exact duplicate constraints are a compile-time error.

`Range { min, max }` applies only to `Int`. Bounds are inclusive. Missing bounds are unbounded. Comparison is integer order over safe integers and bignums.

`Count { unit: Elements, min, max }` applies only to `Array`, `Set`, and `Map`; it counts array elements, set elements, or map entries. `Count { unit: Octets, min, max }` applies only to `Bytes` and `Text`; it counts payload bytes. For `Text`, this is UTF-8 byte length, never code points or grapheme clusters.

`Enum(members)` applies only to `Int` and `Text`. It has at most 64 members. Each member must have the field kind. The compiled table stores canonical member encodings sorted by byte order. Runtime checking is byte equality against that table; canonical encoding is unique, so byte equality is value equality.

## Presence Couplings

Couplings are evaluated after a record's keys are scanned. They read only presence bits of declared optional fields in the same record. Couplings never inspect values.

`Requires { if_present, then_present }` has exactly two distinct keys. If `if_present` is present, `then_present` must be present.

`ExactlyOne(keys)` has 2 to 16 distinct keys. Exactly one listed key must be present.

`Together(keys)` has 2 to 16 distinct keys. The listed keys must be all present or all absent.

Referencing an undeclared field, a required field, or the same field twice is a compile-time error.

## Validation

`RecordSchema::validate` constructs a checked SACP-CBOR/1 decoder with caller-supplied limits and validation options. It walks the value once, validating canonical grammar and schema rules together. On success, decoder finish returns the canonical witness.

`RecordSchema::check` constructs a trusted decoder from an existing `CanonicalCborRef`. It performs one schema walk and does not repeat canonical grammar checks beyond trusted traversal invariants.

The success path after compilation performs no schema-side allocation. Error paths may allocate to build diagnostic paths.

## Containment

For `old.containment(new)`, forward means every value admitted by `old` is admitted by `new`. Backward means every value admitted by `new` is admitted by `old`. Each direction is derived independently and conservatively.

Records are closed-key. A key only in `new` preserves forward containment only when the new field is optional; backward containment fails because old records reject that key. A key only in `old` breaks forward containment; backward containment holds only when the old field is optional.

For a shared key, forward containment rejects `old optional -> new required`. Backward containment rejects `new optional -> old required`.

Type containment is structural. Identical scalar kinds proceed to constraints. `Any` as the target admits every source type; `Any` as the source does not fit a narrower non-`Any` target. Arrays, sets, and maps are covariant in their element or value type and must have the same wrapper. Records recurse. Unions require the source code set to be a subset of the target code set, and shared codes must have equal payload arity with contained payload types.

Range containment compares effective intervals: the target interval must contain the source interval. Count containment uses the same rule per count unit. Enum containment is active only when the target has an enum: the source must also have an enum, and the source effective member set must be a subset of the target set. A source enum with no target enum preserves containment because the target admits more values.

Couplings are compared by form and field key names, never by compiled presence-bit masks: bit assignment depends on a record's own sorted field table, so an unrelated field addition must not change how a coupling compares. A direction holds only when every target coupling is already present in the source coupling set.
