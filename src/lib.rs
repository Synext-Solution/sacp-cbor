//! # sacp-cbor
//!
//! Strict deterministic CBOR validation and canonical encoding for the **SACP-CBOR/1** profile used by
//! the **Synext Agent Control Protocol (SACP)**.
//!
//! ## Design principles
//!
//! - **Canonical bytes are the value.**
//!   Under SACP-CBOR/1, any valid encoding is canonical; therefore, semantic equality for opaque
//!   payloads reduces to **byte equality**.
//! - **Hot-path validation is allocation-free.**
//!   Use [`validate_canonical`] to validate a single CBOR data item with strict SACP-CBOR/1 rules.
//! - **Owned AST is optional.**
//!   Enable the `alloc` feature to decode into [`CborValue`] and to construct and encode canonical CBOR.
//!
//! ## Feature flags
//!
//! - `std` *(default)*: implements `std::error::Error` for [`CborError`].
//! - `alloc` *(default)*: enables owned types (`CborValue`, `CborMap`, `CanonicalCbor`) and encoding.
//! - `sha2` *(default)*: enables SHA-256 hashing helpers for canonical bytes.
//!
//! ## Safety
//!
//! This crate forbids `unsafe` code.
//!
//! ## `no_std`
//!
//! The crate is `no_std` compatible.
//! - Validation-only usage works without `alloc`.
//! - Owned APIs require `alloc` and therefore an allocator provided by your environment.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod canonical;
mod error;
mod float;
mod limits;
mod order;
mod query;
mod scanner;
#[cfg(feature = "serde")]
mod serde_impl;

pub use crate::canonical::CanonicalCborRef;
pub use crate::error::{CborError, CborErrorCode, CborErrorKind};
pub use crate::limits::{CborLimits, DecodeLimits};
pub use crate::limits::{MAX_SAFE_INTEGER, MAX_SAFE_INTEGER_I64, MIN_SAFE_INTEGER};
pub use crate::query::{
    ArrayRef, BigIntRef, CborKind, CborValueRef, MapRef, PathElem, QueryError, QueryErrorCode,
};
pub use crate::scanner::{validate, validate_canonical};

#[cfg(feature = "alloc")]
mod encode;
#[cfg(feature = "alloc")]
mod value;

#[cfg(feature = "alloc")]
pub use crate::canonical::CanonicalCbor;
#[cfg(feature = "alloc")]
pub use crate::scanner::decode_value;
#[cfg(feature = "alloc")]
pub use crate::value::{cbor_equal, BigInt, CborMap, CborValue, F64Bits};

#[cfg(feature = "serde")]
pub use crate::serde_impl::{from_slice, from_value_ref, to_value, to_vec};
