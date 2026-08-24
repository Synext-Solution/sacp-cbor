//! Error types for schema compilation, validation, and containment.

use alloc::{string::String, vec::Vec};
use core::fmt;

use sacp_cbor::CborError;

/// Compile-time schema error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaError {
    /// A schema allocation failed.
    AllocationFailed,
    /// The caller's total compiled-node limit was exceeded.
    TotalNodeLimitExceeded {
        /// Nodes requested by the source schema.
        count: usize,
    },
    /// The caller's compiled owned-byte limit was exceeded.
    OwnedByteLimitExceeded {
        /// Owned bytes requested by the source schema.
        count: usize,
    },
    /// A record declares more than the allowed number of fields.
    FieldCapExceeded {
        /// Record path.
        path: String,
        /// Observed count.
        count: usize,
    },
    /// A field declares more than the allowed number of constraints.
    ConstraintCapExceeded {
        /// Field path.
        field: String,
        /// Observed count.
        count: usize,
    },
    /// An enum constraint declares too many members.
    EnumMemberCapExceeded {
        /// Field path.
        field: String,
        /// Observed count.
        count: usize,
    },
    /// A union declares too many alternatives.
    UnionAltCapExceeded {
        /// Type path.
        path: String,
        /// Observed count.
        count: usize,
    },
    /// A record declares too many couplings.
    CouplingCapExceeded {
        /// Record path.
        path: String,
        /// Observed count.
        count: usize,
    },
    /// A coupling has an invalid number of keys.
    CouplingKeyCount {
        /// Record path.
        path: String,
        /// Coupling kind.
        kind: &'static str,
        /// Observed count.
        count: usize,
    },
    /// A record contains duplicate field keys.
    DuplicateFieldKey {
        /// Duplicate key.
        key: String,
    },
    /// A union has no alternatives.
    EmptyUnion {
        /// Type path.
        path: String,
    },
    /// A union contains duplicate alternative codes.
    DuplicateUnionCode {
        /// Type path.
        path: String,
        /// Duplicate code.
        code: u64,
    },
    /// A constraint is not valid for the field kind.
    ConstraintWrongKind {
        /// Field path.
        field: String,
    },
    /// A constraint has inconsistent bounds.
    ConstraintBounds {
        /// Field path.
        field: String,
    },
    /// An enum member does not match the field kind.
    EnumMemberWrongKind {
        /// Field path.
        field: String,
    },
    /// An enum constraint contains duplicate canonical members.
    DuplicateEnumMember {
        /// Field path.
        field: String,
    },
    /// A field contains the same constraint more than once.
    DuplicateConstraint {
        /// Field path.
        field: String,
    },
    /// A coupling references an undeclared field.
    CouplingUnknownField {
        /// Record path.
        path: String,
        /// Referenced key.
        key: String,
    },
    /// A coupling references a required field.
    CouplingNonOptionalField {
        /// Record path.
        path: String,
        /// Referenced key.
        key: String,
    },
    /// A coupling repeats a key.
    CouplingDuplicateKey {
        /// Record path.
        path: String,
        /// Repeated key.
        key: String,
    },
    /// An integer is not in normalized sign/magnitude form.
    NonNormalizedInt,
    /// Schema type nesting exceeds the fixed limit.
    NestingDepthExceeded {
        /// Observed depth.
        depth: usize,
    },
    /// Canonical enum member encoding failed.
    CanonicalEncodingFailed(CborError),
}

/// Runtime validation error for one record value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordError {
    /// Byte offset where the failure was detected.
    pub offset: usize,
    /// Path from the root to the failing value.
    pub path: Vec<String>,
    /// Whether `path` is the complete diagnostic path. Allocation failure may leave a safe prefix.
    pub path_complete: bool,
    /// Failure class.
    pub fault: Fault,
}

/// Validation failure taxonomy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Caller-provided validation workspace is not prepared for this schema.
    WorkspaceTooSmall,
    /// Base canonical grammar or limits failure.
    Grammar(CborError),
    /// Schema shape failure.
    Shape(ShapeFault),
    /// Field or record constraint failure.
    Constraint(ConstraintFault),
}

/// Schema shape failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapeFault {
    /// A map key was not declared by a closed record.
    UnknownKey,
    /// A required field was absent.
    MissingField,
    /// A value had the wrong CBOR kind.
    WrongKind,
    /// A union code is not declared.
    UnionCodeUnknown,
    /// A union array has the wrong arity for its alternative.
    UnionArity,
    /// Set elements are not in strict bytewise order.
    SetOrder,
    /// Set elements contain a duplicate canonical encoding.
    SetDuplicate,
}

/// Constraint failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConstraintFault {
    /// Integer is below the lower bound.
    RangeBelow,
    /// Integer is above the upper bound.
    RangeAbove,
    /// Count is below the lower bound.
    CountBelow,
    /// Count is above the upper bound.
    CountAbove,
    /// Value is not in an enum table.
    EnumMismatch,
    /// A `Requires` coupling is violated.
    CouplingRequires,
    /// An `ExactlyOne` coupling is violated.
    CouplingExactlyOne,
    /// A `Together` coupling is violated.
    CouplingTogether,
}

impl From<CborError> for RecordError {
    fn from(value: CborError) -> Self {
        Self {
            offset: value.offset,
            path: Vec::new(),
            path_complete: true,
            fault: Fault::Grammar(value),
        }
    }
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllocationFailed => write!(f, "schema allocation failed"),
            Self::TotalNodeLimitExceeded { count } => {
                write!(f, "schema exceeds total node limit: {count}")
            }
            Self::OwnedByteLimitExceeded { count } => {
                write!(f, "schema exceeds owned byte limit: {count}")
            }
            Self::FieldCapExceeded { path, count } => {
                write!(f, "record {path} declares too many fields: {count}")
            }
            Self::ConstraintCapExceeded { field, count } => {
                write!(f, "field {field} declares too many constraints: {count}")
            }
            Self::EnumMemberCapExceeded { field, count } => {
                write!(f, "field {field} declares too many enum members: {count}")
            }
            Self::UnionAltCapExceeded { path, count } => {
                write!(f, "union {path} declares too many alternatives: {count}")
            }
            Self::CouplingCapExceeded { path, count } => {
                write!(f, "record {path} declares too many couplings: {count}")
            }
            Self::CouplingKeyCount { path, kind, count } => {
                write!(
                    f,
                    "{kind} coupling in {path} has invalid key count: {count}"
                )
            }
            Self::DuplicateFieldKey { key } => write!(f, "duplicate field key {key}"),
            Self::EmptyUnion { path } => write!(f, "union {path} has no alternatives"),
            Self::DuplicateUnionCode { path, code } => {
                write!(f, "union {path} has duplicate code {code}")
            }
            Self::ConstraintWrongKind { field } => {
                write!(f, "constraint is not valid for field {field}")
            }
            Self::ConstraintBounds { field } => {
                write!(f, "constraint bounds are inconsistent for field {field}")
            }
            Self::EnumMemberWrongKind { field } => {
                write!(f, "enum member kind does not match field {field}")
            }
            Self::DuplicateEnumMember { field } => {
                write!(f, "duplicate enum member for field {field}")
            }
            Self::DuplicateConstraint { field } => {
                write!(f, "duplicate constraint on field {field}")
            }
            Self::CouplingUnknownField { path, key } => {
                write!(f, "coupling in {path} references unknown field {key}")
            }
            Self::CouplingNonOptionalField { path, key } => {
                write!(f, "coupling in {path} references required field {key}")
            }
            Self::CouplingDuplicateKey { path, key } => {
                write!(f, "coupling in {path} repeats key {key}")
            }
            Self::NonNormalizedInt => write!(f, "integer is not normalized"),
            Self::NestingDepthExceeded { depth } => {
                write!(f, "schema nesting depth exceeds limit: {depth}")
            }
            Self::CanonicalEncodingFailed(err) => write!(f, "canonical encoding failed: {err}"),
        }
    }
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "record error at {}", self.offset)?;
        if !self.path.is_empty() {
            write!(f, " at {}", self.path.join("."))?;
        }
        write!(f, ": {:?}", self.fault)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SchemaError {}

#[cfg(feature = "std")]
impl std::error::Error for RecordError {}
