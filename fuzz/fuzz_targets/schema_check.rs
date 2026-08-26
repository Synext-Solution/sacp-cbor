#![no_main]

use libfuzzer_sys::fuzz_target;
use sacp_cbor::{validate_canonical, DecodeLimits, ValidationOptions};
use sacp_cbor_schema::{
    Constraint, CountUnit, Coupling, FieldDef, FieldType, Int, RecordDef, RecordSchema,
    SchemaCompileLimits, UnionAlt,
};

const SCHEMA_COMPILE_LIMITS: SchemaCompileLimits =
    SchemaCompileLimits::new(64, 16, 64, 16, 32, 4096, 64 * 1024);

fn schemas() -> Vec<RecordSchema> {
    let basic = RecordDef {
        fields: vec![
            FieldDef {
                key: "a".to_owned(),
                ty: FieldType::Int,
                required: true,
                constraints: vec![Constraint::Range {
                    min: Some(Int::from(-10_i64)),
                    max: Some(Int::from(10_i64)),
                }],
            },
            FieldDef {
                key: "b".to_owned(),
                ty: FieldType::Array(Box::new(FieldType::Text)),
                required: false,
                constraints: vec![Constraint::Count {
                    unit: CountUnit::Elements,
                    min: Some(0),
                    max: Some(4),
                }],
            },
        ],
        couplings: vec![],
    };

    let complex = RecordDef {
        fields: vec![
            FieldDef {
                key: "m".to_owned(),
                ty: FieldType::Map(Box::new(FieldType::Bytes)),
                required: false,
                constraints: vec![],
            },
            FieldDef {
                key: "s".to_owned(),
                ty: FieldType::Set(Box::new(FieldType::Int)),
                required: false,
                constraints: vec![],
            },
            FieldDef {
                key: "u".to_owned(),
                ty: FieldType::Union(vec![
                    UnionAlt {
                        code: 0,
                        payload: None,
                    },
                    UnionAlt {
                        code: 1,
                        payload: Some(FieldType::Record(Box::new(RecordDef {
                            fields: vec![FieldDef {
                                key: "ok".to_owned(),
                                ty: FieldType::Bool,
                                required: true,
                                constraints: vec![],
                            }],
                            couplings: vec![],
                        }))),
                    },
                ]),
                required: false,
                constraints: vec![],
            },
            FieldDef {
                key: "x".to_owned(),
                ty: FieldType::Any,
                required: false,
                constraints: vec![],
            },
        ],
        couplings: vec![Coupling::Together(vec!["m".to_owned(), "s".to_owned()])],
    };

    [basic, complex]
        .iter()
        .map(|def| {
            RecordSchema::compile(def, SCHEMA_COMPILE_LIMITS)
                .expect("fixed fuzz schema must remain within its declared compile limits")
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let limits = DecodeLimits::for_bytes(data.len());
    for schema in schemas() {
        if let Ok(witness) = schema.validate(data, limits, ValidationOptions::new()) {
            assert!(validate_canonical(data, limits).is_ok());
            assert!(schema.check(witness, limits).is_ok());
        }
    }
});
