//! Source-form schema descriptions.

use alloc::{boxed::Box, string::String, vec::Vec};

use crate::Int;

/// A closed record schema node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordDef {
    /// Declared fields. Compilation sorts these by canonical text-key order.
    pub fields: Vec<FieldDef>,
    /// Presence couplings evaluated after all fields in this record are seen.
    pub couplings: Vec<Coupling>,
}

/// A field declaration inside a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDef {
    /// Text key used in the CBOR map.
    pub key: String,
    /// Field value type.
    pub ty: FieldType,
    /// Whether the key must be present.
    pub required: bool,
    /// Value constraints applied to this field as a whole.
    pub constraints: Vec<Constraint>,
}

/// Closed grammar of schema field types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldType {
    /// Integer: safe integer or tag 2/3 bignum.
    Int,
    /// Boolean simple value.
    Bool,
    /// Float64 value.
    Float64,
    /// Byte string.
    Bytes,
    /// UTF-8 text string.
    Text,
    /// Homogeneous array.
    Array(Box<Self>),
    /// Homogeneous set encoded as a sorted array.
    Set(Box<Self>),
    /// Homogeneous text-keyed map.
    Map(Box<Self>),
    /// Closed coded union.
    Union(Vec<UnionAlt>),
    /// Nested closed record.
    Record(Box<RecordDef>),
    /// Any canonical SACP-CBOR/1 value.
    Any,
}

/// One coded union alternative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnionAlt {
    /// Non-negative safe integer code.
    pub code: u64,
    /// Optional payload type.
    pub payload: Option<FieldType>,
}

/// Field-level value constraint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Constraint {
    /// Integer range constraint.
    Range {
        /// Inclusive lower bound.
        min: Option<Int>,
        /// Inclusive upper bound.
        max: Option<Int>,
    },
    /// Count constraint for elements or octets.
    Count {
        /// Counted unit.
        unit: CountUnit,
        /// Inclusive lower bound.
        min: Option<u64>,
        /// Inclusive upper bound.
        max: Option<u64>,
    },
    /// Closed enum membership constraint.
    Enum(Vec<EnumMember>),
}

/// Unit used by a count constraint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CountUnit {
    /// Array, set, or map element count.
    Elements,
    /// Byte-string or text payload byte count.
    Octets,
}

/// Source-form enum member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnumMember {
    /// Integer enum member.
    Int(Int),
    /// Text enum member.
    Text(String),
}

/// Presence coupling over optional fields in one record node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Coupling {
    /// If one optional field is present, another must also be present.
    Requires {
        /// Antecedent key.
        if_present: String,
        /// Consequent key.
        then_present: String,
    },
    /// Exactly one listed optional field must be present.
    ExactlyOne(Vec<String>),
    /// Listed optional fields must be all present or all absent.
    Together(Vec<String>),
}
