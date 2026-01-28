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
//! - **Encoding is streaming-first.**
//!   Use [`Encoder`] or [`cbor_bytes!`] to emit canonical bytes without building an owned tree.
//!
//! ## SACP-CBOR/1 profile (explicit)
//!
//! **Terminology note:** “canonical” in this crate means **canonical under the strict SACP-CBOR/1
//! profile** defined here, not RFC 8949 canonical CBOR.
//!
//! **Allowed data model**
//!
//! - Single CBOR item only (no trailing bytes).
//! - Definite-length items only (no indefinite-length encodings).
//! - Map keys must be text strings (major 3) and valid UTF-8.
//! - Only tags 2 and 3 are allowed (bignums), and bignums must be canonical and outside the safe-int range.
//! - Integers (major 0/1) must be in the safe range `[-(2^53-1), +(2^53-1)]`.
//! - Floats must be encoded as float64 (major 7, ai=27), forbid `-0.0`, and require the canonical NaN bit pattern.
//! - Only simple values `false`, `true`, and `null` are allowed.
//!
//! **Canonical encoding constraints**
//!
//! - Minimal integer/length encoding (no overlong forms).
//! - Map keys are strictly increasing by canonical CBOR key ordering:
//!   `(encoded length, then lexicographic encoded bytes)`.
//!
//! ## Feature flags
//!
//! - `std` *(default)*: implements `std::error::Error` for [`CborError`].
//! - `alloc` *(default)*: enables owned canonical bytes (`CborBytes`), editing, and encoding helpers.
//! - `sha2` *(default)*: enables SHA-256 hashing helpers for canonical bytes.
//! - `simdutf8`: enables SIMD-accelerated UTF-8 validation where supported.
//! - `unsafe-utf8`: allows unchecked UTF-8 for canonical-trusted inputs.
//!
//! ## Safety
//!
//! This crate forbids `unsafe` code by default. Enabling the `unsafe-utf8` feature allows
//! unchecked UTF-8 conversion on canonical-trusted inputs.
//!
//! ## `no_std`
//!
//! The crate is `no_std` compatible.
//! - Validation-only usage works without `alloc`.
//! - Owned APIs (canonical bytes + editor) require `alloc` and therefore an allocator provided by your environment.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "unsafe-utf8"), forbid(unsafe_code))]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod alloc_util;
mod canonical;
mod codec;
mod error;
mod limits;
mod parse;
mod profile;
mod query;
mod scalar;
#[cfg(feature = "serde")]
mod serde_impl;
pub(crate) mod utf8;
mod wire;

#[cfg(feature = "alloc")]
mod edit;
#[cfg(feature = "alloc")]
mod int;

pub use crate::canonical::{CborBytesRef, EncodedTextKey};
pub use crate::codec::{decode, decode_canonical, CborDecode, Decoder};
pub use crate::error::{CborError, ErrorCode};
pub use crate::limits::{CborLimits, DecodeLimits};
pub use crate::parse::{validate, validate_canonical};
pub use crate::profile::{MAX_SAFE_INTEGER, MAX_SAFE_INTEGER_I64, MIN_SAFE_INTEGER};
pub use crate::query::{
    ArrayRef, BigIntRef, CborIntegerRef, CborKind, CborValueRef, MapRef, PathElem,
};
pub use crate::scalar::F64Bits;

#[cfg(feature = "alloc")]
mod encode;
#[cfg(feature = "alloc")]
mod macros;
#[cfg(feature = "alloc")]
mod value;
#[cfg(feature = "alloc")]
pub use crate::canonical::CborBytes;
#[cfg(feature = "alloc")]
pub use crate::codec::{
    decode_canonical_owned, encode_into, encode_to_canonical, encode_to_vec, CborArrayElem,
    CborEncode, MapEntries,
};
#[cfg(feature = "alloc")]
pub use crate::edit::{
    ArrayPos, ArraySpliceBuilder, DeleteMode, EditEncode, EditOptions, EditValue, Editor, SetMode,
};
#[cfg(feature = "alloc")]
pub use crate::encode::{ArrayEncoder, Encoder, MapEncoder};
#[cfg(feature = "alloc")]
#[doc(hidden)]
pub use crate::macros::__cbor_macro;
#[cfg(feature = "alloc")]
pub use crate::value::{BigInt, CborInteger};

#[cfg(feature = "serde")]
pub use crate::serde_impl::{
    from_canonical_bytes, from_canonical_bytes_ref, from_slice, from_slice_borrowed, to_vec,
    DeError,
};

pub use sacp_cbor_derive::{CborDecode, CborEncode};

/// Construct a path slice for query/edit operations.
#[macro_export]
macro_rules! path {
    ($($seg:expr),* $(,)?) => {
        &[$($crate::__path_elem!($seg)),*]
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __path_elem {
    ($seg:expr) => {
        $crate::PathElem::from($seg)
    };
}
