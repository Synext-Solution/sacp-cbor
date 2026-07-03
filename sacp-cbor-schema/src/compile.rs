//! Schema compilation into validation arenas.

use alloc::{borrow::ToOwned, boxed::Box, string::String, vec::Vec};
use core::cmp::Ordering;
use core::ops::Range;

use sacp_cbor::profile::cmp_text_keys_canonical;
use sacp_cbor::{Encoder, ScalarKind};

use crate::error::SchemaError;
use crate::ir::{Constraint, CountUnit, Coupling, EnumMember, FieldDef, FieldType, RecordDef};
use crate::{
    Int, MAX_CONSTRAINTS_PER_FIELD, MAX_COUPLINGS_PER_RECORD, MAX_COUPLING_KEYS, MAX_ENUM_MEMBERS,
    MAX_FIELDS_PER_RECORD, MAX_NESTING_DEPTH, MAX_UNION_ALTERNATIVES, MIN_COUPLING_KEYS,
};

pub(crate) type TypeIdx = usize;
pub(crate) type RecordIdx = usize;

/// Compiled closed-record schema.
#[derive(Clone, Debug)]
pub struct RecordSchema {
    pub(crate) types: Vec<TypeNode>,
    pub(crate) records: Vec<CompiledRecord>,
    pub(crate) fields: Vec<CompiledField>,
    pub(crate) constraints: Vec<CompiledConstraint>,
    pub(crate) enum_members: Vec<Box<[u8]>>,
    pub(crate) union_alts: Vec<CompiledUnionAlt>,
    pub(crate) couplings: Vec<CompiledCoupling>,
    pub(crate) root_record: RecordIdx,
}

#[derive(Clone, Debug)]
pub(crate) enum TypeNode {
    Int,
    Bool,
    Float64,
    Bytes,
    Text,
    Array(TypeIdx),
    Set(TypeIdx),
    Map(TypeIdx),
    Union(Range<usize>),
    Record(RecordIdx),
    Any,
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledRecord {
    pub(crate) fields: Range<usize>,
    pub(crate) required_mask: u64,
    pub(crate) couplings: Range<usize>,
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledField {
    pub(crate) key: Box<str>,
    pub(crate) type_idx: TypeIdx,
    pub(crate) required: bool,
    pub(crate) bit: u64,
    pub(crate) constraints: Range<usize>,
}

#[derive(Clone, Debug)]
pub(crate) enum CompiledConstraint {
    Range {
        min: Option<Int>,
        max: Option<Int>,
    },
    Count {
        unit: CountUnit,
        min: Option<u64>,
        max: Option<u64>,
    },
    Enum {
        members: Range<usize>,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledUnionAlt {
    pub(crate) code: u64,
    pub(crate) payload: Option<TypeIdx>,
    /// The payload's scalar kind when the payload is a leaf scalar,
    /// resolved at compile time so validation consumes it through the
    /// direct scalar funnel without a per-value dispatch.
    pub(crate) payload_scalar: Option<ScalarKind>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompiledCoupling {
    Requires { if_mask: u64, then_mask: u64 },
    ExactlyOne { mask: u64 },
    Together { mask: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValueKind {
    Int,
    Bool,
    Float64,
    Bytes,
    Text,
    Array,
    Set,
    Map,
    Union,
    Record,
    Any,
}

impl RecordSchema {
    /// Compile a source-form record schema.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaError`] when the source schema exceeds a fixed cap, contains duplicate
    /// declarations, applies a constraint to the wrong kind, or otherwise violates the model.
    pub fn compile(def: &RecordDef) -> Result<Self, SchemaError> {
        let mut compiler = Compiler::default();
        let root_record = compiler.compile_record(def, 0)?;
        Ok(Self {
            types: compiler.types,
            records: compiler.records,
            fields: compiler.fields,
            constraints: compiler.constraints,
            enum_members: compiler.enum_members,
            union_alts: compiler.union_alts,
            couplings: compiler.couplings,
            root_record,
        })
    }

    pub(crate) fn record(&self, idx: RecordIdx) -> &CompiledRecord {
        &self.records[idx]
    }

    pub(crate) fn type_node(&self, idx: TypeIdx) -> &TypeNode {
        &self.types[idx]
    }

    pub(crate) fn fields_for(&self, record: &CompiledRecord) -> &[CompiledField] {
        &self.fields[record.fields.clone()]
    }

    pub(crate) fn constraints_for(&self, range: Range<usize>) -> &[CompiledConstraint] {
        &self.constraints[range]
    }

    pub(crate) fn union_alts_for(&self, range: Range<usize>) -> &[CompiledUnionAlt] {
        &self.union_alts[range]
    }

    pub(crate) fn couplings_for(&self, record: &CompiledRecord) -> &[CompiledCoupling] {
        &self.couplings[record.couplings.clone()]
    }
}

#[derive(Default)]
struct Compiler {
    types: Vec<TypeNode>,
    records: Vec<CompiledRecord>,
    fields: Vec<CompiledField>,
    constraints: Vec<CompiledConstraint>,
    enum_members: Vec<Box<[u8]>>,
    union_alts: Vec<CompiledUnionAlt>,
    couplings: Vec<CompiledCoupling>,
    path: Vec<String>,
}

impl Compiler {
    fn compile_record(&mut self, def: &RecordDef, depth: usize) -> Result<RecordIdx, SchemaError> {
        Self::check_depth(depth)?;
        if def.fields.len() > MAX_FIELDS_PER_RECORD {
            return Err(SchemaError::FieldCapExceeded {
                path: self.path_name(),
                count: def.fields.len(),
            });
        }
        if def.couplings.len() > MAX_COUPLINGS_PER_RECORD {
            return Err(SchemaError::CouplingCapExceeded {
                path: self.path_name(),
                count: def.couplings.len(),
            });
        }

        let mut field_refs: Vec<&FieldDef> = def.fields.iter().collect();
        field_refs.sort_by(|a, b| cmp_text_keys_canonical(&a.key, &b.key));
        for pair in field_refs.windows(2) {
            if pair[0].key == pair[1].key {
                return Err(SchemaError::DuplicateFieldKey {
                    key: pair[0].key.clone(),
                });
            }
        }

        let mut required_mask = 0u64;
        let mut compiled_fields = Vec::with_capacity(field_refs.len());
        for (idx, field) in field_refs.iter().enumerate() {
            self.path.push(field.key.clone());
            let type_idx = self.compile_type(&field.ty, depth.saturating_add(1))?;
            let constraints = self.compile_constraints(field, &field.ty)?;
            let bit = 1u64 << idx;
            if field.required {
                required_mask |= bit;
            }
            compiled_fields.push(CompiledField {
                key: field.key.clone().into_boxed_str(),
                type_idx,
                required: field.required,
                bit,
                constraints,
            });
            let _ = self.path.pop();
        }

        let fields_start = self.fields.len();
        self.fields.extend(compiled_fields);
        let fields_end = self.fields.len();

        let couplings_start = self.couplings.len();
        self.compile_couplings(&def.couplings, fields_start..fields_end)?;
        let couplings_end = self.couplings.len();

        let record_idx = self.records.len();
        self.records.push(CompiledRecord {
            fields: fields_start..fields_end,
            required_mask,
            couplings: couplings_start..couplings_end,
        });
        Ok(record_idx)
    }

    fn compile_type(&mut self, ty: &FieldType, depth: usize) -> Result<TypeIdx, SchemaError> {
        Self::check_depth(depth)?;
        let node = match ty {
            FieldType::Int => TypeNode::Int,
            FieldType::Bool => TypeNode::Bool,
            FieldType::Float64 => TypeNode::Float64,
            FieldType::Bytes => TypeNode::Bytes,
            FieldType::Text => TypeNode::Text,
            FieldType::Array(inner) => {
                let idx = self.compile_type(inner, depth.saturating_add(1))?;
                TypeNode::Array(idx)
            }
            FieldType::Set(inner) => {
                let idx = self.compile_type(inner, depth.saturating_add(1))?;
                TypeNode::Set(idx)
            }
            FieldType::Map(inner) => {
                let idx = self.compile_type(inner, depth.saturating_add(1))?;
                TypeNode::Map(idx)
            }
            FieldType::Union(alts) => self.compile_union(alts, depth)?,
            FieldType::Record(def) => {
                let idx = self.compile_record(def, depth.saturating_add(1))?;
                TypeNode::Record(idx)
            }
            FieldType::Any => TypeNode::Any,
        };
        let idx = self.types.len();
        self.types.push(node);
        Ok(idx)
    }

    fn compile_union(
        &mut self,
        alts: &[crate::ir::UnionAlt],
        depth: usize,
    ) -> Result<TypeNode, SchemaError> {
        if alts.is_empty() {
            return Err(SchemaError::EmptyUnion {
                path: self.path_name(),
            });
        }
        if alts.len() > MAX_UNION_ALTERNATIVES {
            return Err(SchemaError::UnionAltCapExceeded {
                path: self.path_name(),
                count: alts.len(),
            });
        }
        let mut refs: Vec<&crate::ir::UnionAlt> = alts.iter().collect();
        refs.sort_by_key(|alt| alt.code);
        for pair in refs.windows(2) {
            if pair[0].code == pair[1].code {
                return Err(SchemaError::DuplicateUnionCode {
                    path: self.path_name(),
                    code: pair[0].code,
                });
            }
        }

        let start = self.union_alts.len();
        for alt in refs {
            let payload = match &alt.payload {
                Some(payload) => Some(self.compile_type(payload, depth.saturating_add(1))?),
                None => None,
            };
            let payload_scalar = alt.payload.as_ref().and_then(scalar_kind_of);
            self.union_alts.push(CompiledUnionAlt {
                code: alt.code,
                payload,
                payload_scalar,
            });
        }
        let end = self.union_alts.len();
        Ok(TypeNode::Union(start..end))
    }

    fn compile_constraints(
        &mut self,
        field: &FieldDef,
        ty: &FieldType,
    ) -> Result<Range<usize>, SchemaError> {
        if field.constraints.len() > MAX_CONSTRAINTS_PER_FIELD {
            return Err(SchemaError::ConstraintCapExceeded {
                field: self.path_name(),
                count: field.constraints.len(),
            });
        }
        for (idx, left) in field.constraints.iter().enumerate() {
            if field
                .constraints
                .iter()
                .skip(idx + 1)
                .any(|right| right == left)
            {
                return Err(SchemaError::DuplicateConstraint {
                    field: self.path_name(),
                });
            }
        }

        let kind = kind_of_type(ty);
        let start = self.constraints.len();
        for constraint in &field.constraints {
            match constraint {
                Constraint::Range { min, max } => {
                    if kind != ValueKind::Int {
                        return Err(SchemaError::ConstraintWrongKind {
                            field: self.path_name(),
                        });
                    }
                    if matches!((min, max), (Some(lo), Some(hi)) if lo > hi) {
                        return Err(SchemaError::ConstraintBounds {
                            field: self.path_name(),
                        });
                    }
                    self.constraints.push(CompiledConstraint::Range {
                        min: min.clone(),
                        max: max.clone(),
                    });
                }
                Constraint::Count { unit, min, max } => {
                    self.check_count_kind(kind, *unit)?;
                    if matches!((min, max), (Some(lo), Some(hi)) if lo > hi) {
                        return Err(SchemaError::ConstraintBounds {
                            field: self.path_name(),
                        });
                    }
                    self.constraints.push(CompiledConstraint::Count {
                        unit: *unit,
                        min: *min,
                        max: *max,
                    });
                }
                Constraint::Enum(members) => {
                    let members = self.compile_enum_members(kind, members)?;
                    self.constraints.push(CompiledConstraint::Enum { members });
                }
            }
        }
        Ok(start..self.constraints.len())
    }

    fn compile_enum_members(
        &mut self,
        kind: ValueKind,
        members: &[EnumMember],
    ) -> Result<Range<usize>, SchemaError> {
        if kind != ValueKind::Int && kind != ValueKind::Text {
            return Err(SchemaError::ConstraintWrongKind {
                field: self.path_name(),
            });
        }
        if members.len() > MAX_ENUM_MEMBERS {
            return Err(SchemaError::EnumMemberCapExceeded {
                field: self.path_name(),
                count: members.len(),
            });
        }

        let mut encoded = Vec::with_capacity(members.len());
        for member in members {
            match (kind, member) {
                (ValueKind::Int, EnumMember::Int(value)) => {
                    encoded.push(value.encode_canonical()?);
                }
                (ValueKind::Text, EnumMember::Text(value)) => {
                    encoded.push(encode_text_member(value)?);
                }
                _ => {
                    return Err(SchemaError::EnumMemberWrongKind {
                        field: self.path_name(),
                    });
                }
            }
        }
        encoded.sort();
        for pair in encoded.windows(2) {
            if pair[0] == pair[1] {
                return Err(SchemaError::DuplicateEnumMember {
                    field: self.path_name(),
                });
            }
        }

        let start = self.enum_members.len();
        for bytes in encoded {
            self.enum_members.push(bytes.into_boxed_slice());
        }
        Ok(start..self.enum_members.len())
    }

    fn compile_couplings(
        &mut self,
        couplings: &[Coupling],
        fields: Range<usize>,
    ) -> Result<(), SchemaError> {
        for coupling in couplings {
            match coupling {
                Coupling::Requires {
                    if_present,
                    then_present,
                } => {
                    if if_present == then_present {
                        return Err(SchemaError::CouplingDuplicateKey {
                            path: self.path_name(),
                            key: if_present.clone(),
                        });
                    }
                    let if_mask = self.coupling_key_mask(if_present, fields.clone())?;
                    let then_mask = self.coupling_key_mask(then_present, fields.clone())?;
                    self.couplings
                        .push(CompiledCoupling::Requires { if_mask, then_mask });
                }
                Coupling::ExactlyOne(keys) => {
                    let mask = self.coupling_keys_mask("ExactlyOne", keys, fields.clone())?;
                    self.couplings.push(CompiledCoupling::ExactlyOne { mask });
                }
                Coupling::Together(keys) => {
                    let mask = self.coupling_keys_mask("Together", keys, fields.clone())?;
                    self.couplings.push(CompiledCoupling::Together { mask });
                }
            }
        }
        Ok(())
    }

    fn coupling_keys_mask(
        &self,
        kind: &'static str,
        keys: &[String],
        fields: Range<usize>,
    ) -> Result<u64, SchemaError> {
        if !(MIN_COUPLING_KEYS..=MAX_COUPLING_KEYS).contains(&keys.len()) {
            return Err(SchemaError::CouplingKeyCount {
                path: self.path_name(),
                kind,
                count: keys.len(),
            });
        }

        let mut mask = 0u64;
        for key in keys {
            let bit = self.coupling_key_mask(key, fields.clone())?;
            if mask & bit != 0 {
                return Err(SchemaError::CouplingDuplicateKey {
                    path: self.path_name(),
                    key: key.clone(),
                });
            }
            mask |= bit;
        }
        Ok(mask)
    }

    fn coupling_key_mask(&self, key: &str, fields: Range<usize>) -> Result<u64, SchemaError> {
        for field in &self.fields[fields] {
            if field.key.as_ref() == key {
                if field.required {
                    return Err(SchemaError::CouplingNonOptionalField {
                        path: self.path_name(),
                        key: key.to_owned(),
                    });
                }
                return Ok(field.bit);
            }
        }
        Err(SchemaError::CouplingUnknownField {
            path: self.path_name(),
            key: key.to_owned(),
        })
    }

    fn check_count_kind(&self, kind: ValueKind, unit: CountUnit) -> Result<(), SchemaError> {
        let ok = match unit {
            CountUnit::Elements => {
                matches!(kind, ValueKind::Array | ValueKind::Set | ValueKind::Map)
            }
            CountUnit::Octets => matches!(kind, ValueKind::Bytes | ValueKind::Text),
        };
        if ok {
            Ok(())
        } else {
            Err(SchemaError::ConstraintWrongKind {
                field: self.path_name(),
            })
        }
    }

    const fn check_depth(depth: usize) -> Result<(), SchemaError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(SchemaError::NestingDepthExceeded { depth });
        }
        Ok(())
    }

    fn path_name(&self) -> String {
        if self.path.is_empty() {
            "$".to_owned()
        } else {
            self.path.join(".")
        }
    }
}

const fn kind_of_type(ty: &FieldType) -> ValueKind {
    match ty {
        FieldType::Int => ValueKind::Int,
        FieldType::Bool => ValueKind::Bool,
        FieldType::Float64 => ValueKind::Float64,
        FieldType::Bytes => ValueKind::Bytes,
        FieldType::Text => ValueKind::Text,
        FieldType::Array(_) => ValueKind::Array,
        FieldType::Set(_) => ValueKind::Set,
        FieldType::Map(_) => ValueKind::Map,
        FieldType::Union(_) => ValueKind::Union,
        FieldType::Record(_) => ValueKind::Record,
        FieldType::Any => ValueKind::Any,
    }
}

fn encode_text_member(value: &str) -> Result<Vec<u8>, SchemaError> {
    let mut enc = Encoder::new();
    enc.text(value)
        .map_err(SchemaError::CanonicalEncodingFailed)?;
    let canon = enc.finish().map_err(SchemaError::CanonicalEncodingFailed)?;
    Ok(canon.into_bytes())
}

pub(crate) fn cmp_field_key(a: &str, b: &str) -> Ordering {
    cmp_text_keys_canonical(a, b)
}

const fn scalar_kind_of(ty: &FieldType) -> Option<ScalarKind> {
    match ty {
        FieldType::Int => Some(ScalarKind::Integer),
        FieldType::Bool => Some(ScalarKind::Bool),
        FieldType::Float64 => Some(ScalarKind::Float),
        FieldType::Bytes => Some(ScalarKind::Bytes),
        FieldType::Text => Some(ScalarKind::Text),
        _ => None,
    }
}
