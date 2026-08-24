# sacp-cbor-schema

`sacp-cbor-schema` validates canonical SACP-CBOR/1 values against closed record schemas.

The crate compiles a plain Rust data description into a `RecordSchema`. The compiled form performs:

- canonical grammar validation and schema validation in one pass for untrusted bytes;
- allocation-free successful validation with a caller-prepared reusable workspace;
- trusted schema checks over existing `CanonicalCborRef` witnesses;
- bounded structural inclusion with distinct proven, refuted, and unknown outcomes.

## Installation

```toml
[dependencies]
sacp-cbor-schema = "0.2"
```

For `no_std` targets:

```toml
[dependencies]
sacp-cbor-schema = { version = "0.2", default-features = false }
```

## Quick Example

```rust
use sacp_cbor::{DecodeLimits, Encoder, ValidationOptions};
use sacp_cbor_schema::{
    Constraint, CountUnit, FieldDef, FieldType, Int, RecordDef, RecordSchema,
    SchemaCompileLimits,
};

let def = RecordDef {
    fields: vec![
        FieldDef {
            key: "id".to_owned(),
            ty: FieldType::Int,
            required: true,
            constraints: vec![Constraint::Range {
                min: Some(Int::from(1_u64)),
                max: None,
            }],
        },
        FieldDef {
            key: "name".to_owned(),
            ty: FieldType::Text,
            required: false,
            constraints: vec![Constraint::Count {
                unit: CountUnit::Octets,
                min: Some(1),
                max: Some(64),
            }],
        },
    ],
    couplings: vec![],
};

let schema = RecordSchema::compile(
    &def,
    SchemaCompileLimits::new(64, 16, 64, 16, 32, 4096, 64 * 1024),
)?;
let mut enc = Encoder::new();
enc.map(2, |m| {
    m.entry("id", |e| e.int(7))?;
    m.entry("name", |e| e.text("alpha"))
})?;
let bytes = enc.finish()?.into_bytes();

let witness = schema.validate(
    &bytes,
    DecodeLimits::for_bytes(bytes.len()),
    ValidationOptions::new(),
)?;
schema.check(witness, DecodeLimits::for_bytes(bytes.len()))?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Feature Table

| Area | Support |
| --- | --- |
| Records | Closed text-keyed CBOR maps within caller-selected compile limits |
| Types | Int, Bool, Float64, Bytes, Text, Array, Set, Map, Union, Record, Any |
| Constraints | Integer ranges, element/octet counts, int/text enums |
| Couplings | Requires, ExactlyOne, Together over optional fields |
| Compatibility | Bounded forward/backward inclusion with replayable counterexamples |
| `no_std` | Supported with `alloc`; `std` is the default feature |

See `SPEC.md` for the normative model.
