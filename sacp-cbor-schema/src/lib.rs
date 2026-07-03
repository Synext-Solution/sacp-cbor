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

/// Maximum fields allowed in one record node.
pub const MAX_FIELDS_PER_RECORD: usize = 64;
/// Maximum value constraints allowed on one field.
pub const MAX_CONSTRAINTS_PER_FIELD: usize = 16;
/// Maximum enum members allowed in one enum constraint.
pub const MAX_ENUM_MEMBERS: usize = 64;
/// Maximum union alternatives allowed in one union type.
pub const MAX_UNION_ALTERNATIVES: usize = 64;
/// Maximum presence couplings allowed in one record node.
pub const MAX_COUPLINGS_PER_RECORD: usize = 16;
/// Minimum keys allowed in a multi-key coupling.
pub const MIN_COUPLING_KEYS: usize = 2;
/// Maximum keys allowed in a multi-key coupling.
pub const MAX_COUPLING_KEYS: usize = 16;
/// Maximum schema type nesting depth.
pub const MAX_NESTING_DEPTH: usize = 32;

pub mod compat;
pub mod compile;
pub mod error;
pub mod int;
pub mod ir;

mod check;

pub use crate::compat::{Containment, Direction, NonDerivation, NonDerivationReason};
pub use crate::compile::RecordSchema;
pub use crate::error::{ConstraintFault, Fault, RecordError, SchemaError, ShapeFault};
pub use crate::int::Int;
pub use crate::ir::{
    Constraint, CountUnit, Coupling, EnumMember, FieldDef, FieldType, RecordDef, UnionAlt,
};
pub use sacp_cbor::{CanonicalCborRef, CborError, DecodeLimits, ValidationOptions};

#[cfg(kani)]
mod proofs {
    use super::{compat, int::Int};

    #[kani::proof]
    fn int_order_is_reflexive_for_small_values() {
        let v: i64 = kani::any();
        let a = Int::from(v);
        assert!(a == a);
    }

    #[kani::proof]
    fn coupling_masks_classify_together() {
        let mask: u64 = kani::any();
        let present: u64 = kani::any();
        let narrowed = mask & 0xffff;
        let bits = present & narrowed;
        assert_eq!(
            compat::together_holds_for_mask(bits, narrowed),
            bits == 0 || bits == narrowed
        );
    }
}
