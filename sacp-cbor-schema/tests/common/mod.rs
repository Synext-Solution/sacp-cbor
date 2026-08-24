//! Shared helpers for the integration test suites.
#![allow(dead_code)]

use sacp_cbor::{DecodeLimits, EncodeResult, Encoder, ValidationOptions, VecSink};
use sacp_cbor_schema::{
    Constraint, Coupling, FieldDef, FieldType, InclusionLimits, RecordDef, RecordError,
    RecordSchema, SchemaCompileLimits,
};

pub fn field(key: &str, ty: FieldType, required: bool, constraints: Vec<Constraint>) -> FieldDef {
    FieldDef {
        key: key.to_owned(),
        ty,
        required,
        constraints,
    }
}

pub fn schema(fields: Vec<FieldDef>, couplings: Vec<Coupling>) -> RecordSchema {
    RecordSchema::compile(&RecordDef { fields, couplings }, limits()).expect("schema compiles")
}

pub const fn limits() -> SchemaCompileLimits {
    SchemaCompileLimits::new(4096, 4096, 4096, 4096, 4096, 1_000_000, 16_000_000)
}

pub const fn inclusion_limits() -> InclusionLimits {
    InclusionLimits::new(
        1_000_000, 4096, 4096, 1_000_000, 16_000_000, 1_000_000, 4096,
    )
}

pub fn validate(schema: &RecordSchema, bytes: &[u8]) -> Result<(), RecordError> {
    schema
        .validate(
            bytes,
            DecodeLimits::for_bytes(bytes.len()),
            ValidationOptions::new(),
        )
        .map(|_| ())
}

/// Encode a single-field record `{key: <f>}`.
pub fn one_field<F>(key: &str, f: F) -> Vec<u8>
where
    F: FnOnce(&mut Encoder) -> EncodeResult<(), VecSink>,
{
    let mut enc = Encoder::new();
    enc.map(1, |m| m.entry(key, f)).expect("encode");
    enc.finish().expect("finish")
}
