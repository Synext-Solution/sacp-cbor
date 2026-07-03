# sacp-cbor-schema

`sacp-cbor-schema` validates canonical SACP-CBOR/1 values against closed record schemas.

The crate compiles a plain Rust data description into a `RecordSchema`. The compiled form performs:

- canonical grammar validation and schema validation in one pass for untrusted bytes;
- allocation-free validation after compilation on the success path;
- trusted schema checks over existing `CanonicalCborRef` witnesses;
- structural containment derivation between old and successor schemas.

## Installation

```toml
[dependencies]
sacp-cbor-schema = "0.1"
```

For `no_std` targets:

```toml
[dependencies]
sacp-cbor-schema = { version = "0.1", default-features = false }
```

## Quick Example

```rust
use sacp_cbor::{DecodeLimits, Encoder, ValidationOptions};
use sacp_cbor_schema::{
    Constraint, CountUnit, FieldDef, FieldType, Int, RecordDef, RecordSchema,
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

let schema = RecordSchema::compile(&def)?;
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
schema.check(witness)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Feature Table

| Area | Support |
| --- | --- |
| Records | Closed text-keyed CBOR maps, up to 64 fields per record node |
| Types | Int, Bool, Float64, Bytes, Text, Array, Set, Map, Union, Record, Any |
| Constraints | Integer ranges, element/octet counts, int/text enums |
| Couplings | Requires, ExactlyOne, Together over optional fields |
| Compatibility | Forward and backward structural containment derivation |
| `no_std` | Supported with `alloc`; `std` is the default feature |

See `SPEC.md` for the normative model.
