#![allow(clippy::too_many_lines)]

use core::cmp::Ordering;
use std::time::Instant;

use proptest::prelude::*;
use sacp_cbor::query::{CborKind, CborValueRef};
use sacp_cbor::{validate_canonical_with, DecodeLimits, Encoder, ValidationOptions};
use sacp_cbor_schema::{
    Constraint, CountUnit, Coupling, Direction, EnumMember, FieldType, Int, RecordDef,
    RecordSchema, UnionAlt,
};

mod common;
use common::field;

#[derive(Clone, Copy, Debug)]
enum Class {
    Grammar,
    Shape,
    Constraint,
}

#[derive(Clone, Copy, Debug)]
enum SimpleTy {
    Int,
    Text,
    Bool,
}

fn ref_check(def: &RecordDef, bytes: &[u8]) -> Result<(), Class> {
    let limits = DecodeLimits::for_bytes(bytes.len());
    let witness = validate_canonical_with(bytes, limits, ValidationOptions::new())
        .map_err(|_| Class::Grammar)?;
    ref_record(def, witness.root())
}

fn ref_record(def: &RecordDef, value: CborValueRef<'_>) -> Result<(), Class> {
    let map = value.map().map_err(|_| Class::Shape)?;
    let mut present = vec![false; def.fields.len()];
    for entry in map.iter() {
        let (key, child) = entry.map_err(|_| Class::Grammar)?;
        let Some(idx) = def.fields.iter().position(|field| field.key == key) else {
            return Err(Class::Shape);
        };
        present[idx] = true;
        ref_value(&def.fields[idx].ty, &def.fields[idx].constraints, child)?;
    }
    for (idx, field) in def.fields.iter().enumerate() {
        if field.required && !present[idx] {
            return Err(Class::Shape);
        }
    }
    for coupling in &def.couplings {
        match coupling {
            Coupling::Requires {
                if_present,
                then_present,
            } => {
                let if_idx = def.fields.iter().position(|field| field.key == *if_present);
                let then_idx = def
                    .fields
                    .iter()
                    .position(|field| field.key == *then_present);
                if let (Some(a), Some(b)) = (if_idx, then_idx) {
                    if present[a] && !present[b] {
                        return Err(Class::Constraint);
                    }
                }
            }
            Coupling::ExactlyOne(keys) => {
                let count = keys
                    .iter()
                    .filter_map(|key| def.fields.iter().position(|field| field.key == **key))
                    .filter(|&idx| present[idx])
                    .count();
                if count != 1 {
                    return Err(Class::Constraint);
                }
            }
            Coupling::Together(keys) => {
                let count = keys
                    .iter()
                    .filter_map(|key| def.fields.iter().position(|field| field.key == **key))
                    .filter(|&idx| present[idx])
                    .count();
                if count != 0 && count != keys.len() {
                    return Err(Class::Constraint);
                }
            }
        }
    }
    Ok(())
}

fn ref_value(
    ty: &FieldType,
    constraints: &[Constraint],
    value: CborValueRef<'_>,
) -> Result<(), Class> {
    match ty {
        FieldType::Int => {
            if value.kind().map_err(|_| Class::Grammar)? != CborKind::Integer {
                return Err(Class::Shape);
            }
            let integer = value.integer().map_err(|_| Class::Grammar)?;
            for constraint in constraints {
                match constraint {
                    Constraint::Range { min, max } => {
                        let Some(v) = integer.as_i128() else {
                            continue;
                        };
                        if min.as_ref().and_then(int_to_i128).is_some_and(|lo| v < lo) {
                            return Err(Class::Constraint);
                        }
                        if max.as_ref().and_then(int_to_i128).is_some_and(|hi| v > hi) {
                            return Err(Class::Constraint);
                        }
                    }
                    Constraint::Enum(members) => {
                        if !members
                            .iter()
                            .any(|member| enum_bytes(member) == value.as_bytes())
                        {
                            return Err(Class::Constraint);
                        }
                    }
                    Constraint::Count { .. } => {}
                }
            }
        }
        FieldType::Bool => {
            if value.kind().map_err(|_| Class::Grammar)? != CborKind::Bool {
                return Err(Class::Shape);
            }
        }
        FieldType::Float64 => {
            if value.kind().map_err(|_| Class::Grammar)? != CborKind::Float {
                return Err(Class::Shape);
            }
        }
        FieldType::Bytes => {
            let bytes = value.bytes().map_err(|_| Class::Shape)?;
            ref_count(CountUnit::Octets, bytes.len(), constraints)?;
        }
        FieldType::Text => {
            let text = value.text().map_err(|_| Class::Shape)?;
            ref_count(CountUnit::Octets, text.len(), constraints)?;
            for constraint in constraints {
                if let Constraint::Enum(members) = constraint {
                    if !members
                        .iter()
                        .any(|member| enum_bytes(member) == value.as_bytes())
                    {
                        return Err(Class::Constraint);
                    }
                }
            }
        }
        FieldType::Array(inner) => {
            let array = value.array().map_err(|_| Class::Shape)?;
            ref_count(CountUnit::Elements, array.len(), constraints)?;
            for item in array.iter() {
                ref_value(inner, &[], item.map_err(|_| Class::Grammar)?)?;
            }
        }
        FieldType::Set(inner) => {
            let array = value.array().map_err(|_| Class::Shape)?;
            ref_count(CountUnit::Elements, array.len(), constraints)?;
            let mut prev: Option<Vec<u8>> = None;
            for item in array.iter() {
                let item = item.map_err(|_| Class::Grammar)?;
                ref_value(inner, &[], item)?;
                if let Some(prev_bytes) = &prev {
                    match prev_bytes.as_slice().cmp(item.as_bytes()) {
                        Ordering::Less => {}
                        Ordering::Equal | Ordering::Greater => return Err(Class::Shape),
                    }
                }
                prev = Some(item.as_bytes().to_vec());
            }
        }
        FieldType::Map(inner) => {
            let map = value.map().map_err(|_| Class::Shape)?;
            ref_count(CountUnit::Elements, map.len(), constraints)?;
            for entry in map.iter() {
                let (_, child) = entry.map_err(|_| Class::Grammar)?;
                ref_value(inner, &[], child)?;
            }
        }
        FieldType::Union(alts) => {
            let array = value.array().map_err(|_| Class::Shape)?;
            if array.len() != 1 && array.len() != 2 {
                return Err(Class::Shape);
            }
            let code_value = array
                .get(0)
                .map_err(|_| Class::Grammar)?
                .ok_or(Class::Shape)?;
            let code = code_value
                .integer()
                .map_err(|_| Class::Shape)?
                .as_u128()
                .and_then(|v| u64::try_from(v).ok())
                .ok_or(Class::Shape)?;
            let alt = alts
                .iter()
                .find(|alt| alt.code == code)
                .ok_or(Class::Shape)?;
            match (&alt.payload, array.len()) {
                (None, 1) => {}
                (Some(payload), 2) => {
                    let payload_value = array
                        .get(1)
                        .map_err(|_| Class::Grammar)?
                        .ok_or(Class::Shape)?;
                    ref_value(payload, &[], payload_value)?;
                }
                _ => return Err(Class::Shape),
            }
        }
        FieldType::Record(record) => ref_record(record, value)?,
        FieldType::Any => {}
    }
    Ok(())
}

fn ref_count(unit: CountUnit, count: usize, constraints: &[Constraint]) -> Result<(), Class> {
    let count = u64::try_from(count).map_err(|_| Class::Constraint)?;
    for constraint in constraints {
        if let Constraint::Count {
            unit: c_unit,
            min,
            max,
        } = constraint
        {
            if *c_unit == unit
                && (min.is_some_and(|lo| count < lo) || max.is_some_and(|hi| count > hi))
            {
                return Err(Class::Constraint);
            }
        }
    }
    Ok(())
}

fn enum_bytes(member: &EnumMember) -> Vec<u8> {
    let mut enc = Encoder::new();
    match member {
        EnumMember::Int(value) => {
            if value.is_negative() {
                let signed = int_to_i128(value).expect("test int fits i128");
                enc.int_i128(signed).expect("encode int");
            } else {
                let unsigned = int_to_i128(value).expect("test int fits i128") as u128;
                enc.int_u128(unsigned).expect("encode int");
            }
        }
        EnumMember::Text(value) => enc.text(value).expect("encode text"),
    }
    enc.finish().expect("finish").into_bytes()
}

fn int_to_i128(value: &Int) -> Option<i128> {
    let mut out = 0i128;
    for &byte in value.magnitude() {
        out = out.checked_mul(256)?;
        out = out.checked_add(i128::from(byte))?;
    }
    Some(if value.is_negative() { -out } else { out })
}

fn simple_def(kinds: &[(SimpleTy, bool)]) -> RecordDef {
    let keys = ["a", "b", "c"];
    RecordDef {
        fields: kinds
            .iter()
            .enumerate()
            .map(|(idx, (ty, required))| {
                let field_ty = match ty {
                    SimpleTy::Int => FieldType::Int,
                    SimpleTy::Text => FieldType::Text,
                    SimpleTy::Bool => FieldType::Bool,
                };
                field(keys[idx], field_ty, *required, vec![])
            })
            .collect(),
        couplings: vec![],
    }
}

fn encode_simple(
    def: &RecordDef,
    present: &[bool],
    ints: &[i64],
    texts: &[String],
    bools: &[bool],
) -> Vec<u8> {
    let count = def
        .fields
        .iter()
        .enumerate()
        .filter(|(idx, field)| field.required || present.get(*idx).copied().unwrap_or(false))
        .count();
    let mut enc = Encoder::new();
    enc.map(count, |m| {
        for (idx, field) in def.fields.iter().enumerate() {
            if !field.required && !present.get(idx).copied().unwrap_or(false) {
                continue;
            }
            m.entry(&field.key, |e| match &field.ty {
                FieldType::Int => e.int(ints[idx]),
                FieldType::Text => e.text(&texts[idx]),
                FieldType::Bool => e.bool(bools[idx]),
                _ => unreachable!("simple def only"),
            })?;
        }
        Ok(())
    })
    .expect("encode");
    enc.finish().expect("finish").into_bytes()
}

prop_compose! {
    fn simple_kinds()(len in 1usize..=3)(
        pairs in prop::collection::vec(
            (prop_oneof![Just(SimpleTy::Int), Just(SimpleTy::Text), Just(SimpleTy::Bool)], any::<bool>()),
            len
        )
    ) -> Vec<(SimpleTy, bool)> {
        pairs
    }
}

proptest! {
    #[test]
    fn generated_conforming_values_match_reference(
        kinds in simple_kinds(),
        present in prop::collection::vec(any::<bool>(), 3),
        ints in prop::collection::vec(-100_i64..100, 3),
        texts in prop::collection::vec("[a-z]{0,4}", 3),
        bools in prop::collection::vec(any::<bool>(), 3),
    ) {
        let def = simple_def(&kinds);
        let schema = RecordSchema::compile(&def).expect("compile");
        let bytes = encode_simple(&def, &present, &ints, &texts, &bools);
        let schema_ok = schema.validate(
            &bytes,
            DecodeLimits::for_bytes(bytes.len()),
            ValidationOptions::new(),
        ).is_ok();
        let ref_ok = ref_check(&def, &bytes).is_ok();
        prop_assert_eq!(schema_ok, ref_ok);
    }

    #[test]
    fn random_bytes_match_reference_on_ok_err(
        bytes in prop::collection::vec(any::<u8>(), 0..64)
    ) {
        let def = RecordDef {
            fields: vec![
                field("a", FieldType::Int, true, vec![]),
                field("b", FieldType::Text, false, vec![]),
            ],
            couplings: vec![],
        };
        let schema = RecordSchema::compile(&def).expect("compile");
        let schema_ok = schema.validate(
            &bytes,
            DecodeLimits::for_bytes(bytes.len()),
            ValidationOptions::new(),
        ).is_ok();
        let ref_ok = ref_check(&def, &bytes).is_ok();
        prop_assert_eq!(schema_ok, ref_ok);
    }

    #[test]
    fn validate_ok_implies_core_ok_and_trusted_check(
        v in -50_i64..50
    ) {
        let def = RecordDef {
            fields: vec![field("a", FieldType::Int, true, vec![])],
            couplings: vec![],
        };
        let schema = RecordSchema::compile(&def).expect("compile");
        let bytes = encode_simple(&def, &[true], &[v, 0, 0], &["".to_owned(), "".to_owned(), "".to_owned()], &[false; 3]);
        let limits = DecodeLimits::for_bytes(bytes.len());
        let witness = schema.validate(&bytes, limits, ValidationOptions::new()).expect("validate");
        prop_assert!(validate_canonical_with(&bytes, limits, ValidationOptions::new()).is_ok());
        prop_assert!(schema.check(witness).is_ok());
    }

    #[test]
    fn sampled_forward_containment_accepts_old_values(v in 0_i64..=10) {
        let old = RecordSchema::compile(&RecordDef {
            fields: vec![field("a", FieldType::Int, true, vec![Constraint::Range {
                min: Some(Int::from(0_i64)),
                max: Some(Int::from(10_i64)),
            }])],
            couplings: vec![],
        }).expect("compile old");
        let new = RecordSchema::compile(&RecordDef {
            fields: vec![field("a", FieldType::Int, true, vec![Constraint::Range {
                min: Some(Int::from(0_i64)),
                max: Some(Int::from(20_i64)),
            }])],
            couplings: vec![],
        }).expect("compile new");
        prop_assert!(matches!(old.containment(&new).forward, Direction::Holds));
        let def = RecordDef {
            fields: vec![field("a", FieldType::Int, true, vec![])],
            couplings: vec![],
        };
        let bytes = encode_simple(&def, &[true], &[v, 0, 0], &["".to_owned(), "".to_owned(), "".to_owned()], &[false; 3]);
        prop_assert!(new.validate(
            &bytes,
            DecodeLimits::for_bytes(bytes.len()),
            ValidationOptions::new(),
        ).is_ok());
    }
}

#[test]
fn reference_checker_covers_union_set_map_and_record() {
    let def = RecordDef {
        fields: vec![
            field("m", FieldType::Map(Box::new(FieldType::Text)), true, vec![]),
            field(
                "r",
                FieldType::Record(Box::new(RecordDef {
                    fields: vec![field("x", FieldType::Bool, true, vec![])],
                    couplings: vec![],
                })),
                true,
                vec![],
            ),
            field("s", FieldType::Set(Box::new(FieldType::Text)), true, vec![]),
            field(
                "u",
                FieldType::Union(vec![UnionAlt {
                    code: 1,
                    payload: Some(FieldType::Int),
                }]),
                true,
                vec![],
            ),
        ],
        couplings: vec![],
    };
    let schema = RecordSchema::compile(&def).expect("compile");
    let mut enc = Encoder::new();
    enc.map(4, |m| {
        m.entry("m", |e| e.map(1, |m| m.entry("k", |e| e.text("v"))))?;
        m.entry("r", |e| e.map(1, |m| m.entry("x", |e| e.bool(true))))?;
        m.entry("s", |e| {
            e.array(2, |a| {
                a.text("a")?;
                a.text("b")
            })
        })?;
        m.entry("u", |e| {
            e.array(2, |a| {
                a.int(1)?;
                a.int(7)
            })
        })
    })
    .expect("encode");
    let bytes = enc.finish().expect("finish").into_bytes();
    assert!(schema
        .validate(
            &bytes,
            DecodeLimits::for_bytes(bytes.len()),
            ValidationOptions::new()
        )
        .is_ok());
    assert!(ref_check(&def, &bytes).is_ok());
}

#[test]
#[ignore]
fn throughput_smoke_fused_vs_two_pass() {
    let def = RecordDef {
        fields: vec![
            field(
                "a",
                FieldType::Array(Box::new(FieldType::Int)),
                true,
                vec![],
            ),
            field("b", FieldType::Text, true, vec![]),
        ],
        couplings: vec![],
    };
    let schema = RecordSchema::compile(&def).expect("compile");
    let mut enc = Encoder::new();
    enc.map(2, |m| {
        m.entry("a", |e| {
            e.array(200, |a| {
                for i in 0..200 {
                    a.int(i)?;
                }
                Ok(())
            })
        })?;
        m.entry("b", |e| e.text(&"x".repeat(800)))
    })
    .expect("encode");
    let bytes = enc.finish().expect("finish").into_bytes();
    let limits = DecodeLimits::for_bytes(bytes.len());
    let rounds = 1_000u32;

    let start = Instant::now();
    for _ in 0..rounds {
        let _ = schema
            .validate(&bytes, limits, ValidationOptions::new())
            .expect("validate");
    }
    let fused = start.elapsed() / rounds;

    let start = Instant::now();
    for _ in 0..rounds {
        let witness =
            validate_canonical_with(&bytes, limits, ValidationOptions::new()).expect("core");
        schema.check(witness).expect("check");
    }
    let two_pass = start.elapsed() / rounds;

    println!("fused ns/op: {}", fused.as_nanos());
    println!("two-pass ns/op: {}", two_pass.as_nanos());
}
