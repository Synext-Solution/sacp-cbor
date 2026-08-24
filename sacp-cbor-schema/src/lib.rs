//! Closed-record schema validation for canonical SACP-CBOR/1 values.
//!
//! This crate compiles a plain source-form schema into a closed-record validator. Validation uses
//! the public `sacp-cbor` checked decoder for untrusted bytes, so canonical grammar validation and
//! schema checking happen in one traversal. A trusted checker is also available for values already
//! witnessed as canonical.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

extern crate alloc;

/// Minimum keys allowed in a multi-key coupling.
pub const MIN_COUPLING_KEYS: usize = 2;

/// Caller-owned limits for schema compilation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemaCompileLimits {
    /// Maximum fields in one record.
    pub max_fields_per_record: usize,
    /// Maximum constraints on one field.
    pub max_constraints_per_field: usize,
    /// Maximum alternatives in one union.
    pub max_union_alternatives: usize,
    /// Maximum couplings in one record.
    pub max_couplings_per_record: usize,
    /// Maximum nested schema depth.
    pub max_schema_depth: usize,
    /// Maximum total compiled nodes, including enum members and coupling keys.
    pub max_total_nodes: usize,
    /// Maximum total owned source bytes copied into the compiled schema.
    pub max_total_owned_bytes: usize,
}

impl SchemaCompileLimits {
    /// Construct explicit compile limits.
    #[must_use]
    pub const fn new(
        max_fields_per_record: usize,
        max_constraints_per_field: usize,
        max_union_alternatives: usize,
        max_couplings_per_record: usize,
        max_schema_depth: usize,
        max_total_nodes: usize,
        max_total_owned_bytes: usize,
    ) -> Self {
        Self {
            max_fields_per_record,
            max_constraints_per_field,
            max_union_alternatives,
            max_couplings_per_record,
            max_schema_depth,
            max_total_nodes,
            max_total_owned_bytes,
        }
    }
}

pub mod compat;
pub mod compile;
pub mod error;
pub mod int;
pub mod ir;

mod check;

pub use crate::check::ValidationWorkspace;
pub use crate::compat::{
    Inclusion, InclusionLimits, InclusionProof, InclusionWorkspace, NonDerivation,
    NonDerivationReason, WireCounterexample,
};
pub use crate::compile::RecordSchema;
pub use crate::error::{ConstraintFault, Fault, RecordError, SchemaError, ShapeFault};
pub use crate::int::Int;
pub use crate::ir::{
    Constraint, CountUnit, Coupling, EnumMember, FieldDef, FieldType, RecordDef, UnionAlt,
};
pub use sacp_cbor::{CanonicalCborRef, CborError, DecodeLimits, ValidationOptions};

#[cfg(kani)]
mod proofs {
    use super::int::Int;

    #[kani::proof]
    fn int_order_is_reflexive_for_small_values() {
        let v: i64 = kani::any();
        let a = Int::from(v);
        assert!(a == a);
    }
}
