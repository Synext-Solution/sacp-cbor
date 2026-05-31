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
//!   Use `Encoder` or `cbor_bytes!` to emit canonical bytes without building an owned tree.
//!
//! ## SACP-CBOR/1 profile (explicit)
//!
//! **Terminology note:** "canonical" in this crate means **canonical under the strict SACP-CBOR/1
//! profile** defined here, not RFC 8949 canonical CBOR.
//!
//! **Allowed data model**
//!
//! - Single CBOR item only (no trailing bytes).
//! - Definite-length items only (no indefinite-length encodings).
//! - Map keys must be text strings (major 3) and valid UTF-8.
//! - Duplicate map keys are rejected.
//! - Only tags 2 and 3 are allowed (bignums), and bignums must be canonical and outside the safe-int range.
//! - Integers (major 0/1) must be in the safe range `[-(2^53-1), +(2^53-1)]`.
//! - Floats must be encoded as float64 (major 7, ai=27), forbid `-0.0`, and require NaN to be encoded as `0x7ff8_0000_0000_0000`.
//! - Only simple values `false`, `true`, and `null` are allowed.
//! - All other tags, simple values, float16/float32 encodings, break bytes, and reserved additional-info values are rejected.
//!
//! **Canonical encoding constraints**
//!
//! - Minimal integer/length encoding (no overlong forms).
//! - Map keys are strictly increasing by canonical CBOR key ordering:
//!   `(encoded length, then lexicographic encoded bytes)`.
//! - Exactly one root value must be emitted or decoded.
//!
//! **Witness invariants**
//!
//! - [`CanonicalCborRef`] is a borrowed witness that its byte slice is one complete canonical item.
//! - `CanonicalCbor` is the owned form of the same invariant.
//! - [`query::CborValueRef`] is a borrowed sub-value view containing the original root bytes plus a byte
//!   range for one complete canonical item inside that root.
//! - [`Decoder::<true>`] validates canonical constraints while decoding.
//! - [`Decoder::<false>`] is constructed only from [`CanonicalCborRef`] and relies on that witness.
//! - `Encoder::finish` succeeds only after exactly one complete root value has been emitted and
//!   every declared container has been closed with its exact element count.
//! - With the `edit` feature, `edit::Editor::apply` emits through `Encoder::finish`, so successful
//!   patch output is a new `CanonicalCbor`.
//!
//! **Decode limits**
//!
//! [`DecodeLimits`] contains deterministic resource limits:
//! `max_input_bytes`, `max_depth`, `max_total_items`, `max_array_len`, `max_map_len`,
//! `max_bytes_len`, and `max_text_len`. Maps count as two items per pair for
//! `max_total_items` because both keys and values are scanned. [`DecodeLimits::validate`] rejects
//! configurations this build cannot enforce, such as no-alloc depth values above the fixed stack.
//!
//! **Allocation policy**
//!
//! Validation and borrowed query traversal are allocation-free. Owned APIs use fallible reservation
//! helpers for `Vec`, `String`, and `Box<str>` construction and report [`ErrorCode::AllocationFailed`]
//! where Rust exposes allocation failure. Standard-library collections may still abort on process
//! OOM inside their own insertion routines.
//!
//! ## Feature flags
//!
//! - `std` *(default)*: implements `std::error::Error` for [`CborError`] and enables `alloc`.
//! - `alloc`: enables owned canonical bytes (`CanonicalCbor`) and encoding helpers.
//! - `derive` *(default)*: enables derive macros and `cbor_bytes!`.
//! - `collections`: enables native collection impls and `collections::MapEntries`.
//! - `edit`: enables canonical CBOR editing under `edit`.
//! - `sha2`: enables SHA-256 hashing helpers for canonical bytes.
//! - `serde`: enables serde integration under `serde`.
//! - `simdutf8`: enables SIMD-accelerated UTF-8 validation where supported.
//! - `unsafe`: allows unchecked UTF-8 for canonical-trusted inputs.
//!
//! ## Safety
//!
//! This crate forbids `unsafe` code by default. Enabling the `unsafe` feature allows
//! unchecked UTF-8 conversion on canonical-trusted inputs.
//!
//! ## `no_std`
//!
//! The crate supports `no_std`.
//! - Validation-only usage works without `alloc`.
//! - Owned APIs (canonical bytes, encoding, collections, and editor) require `alloc` and therefore an allocator provided by your environment.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "unsafe"), forbid(unsafe_code))]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic, clippy::nursery)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod alloc_util;
pub mod bytes;
mod canonical;
mod codec;
#[cfg(feature = "alloc")]
mod codec_impls;
pub mod decode;
pub mod error;
pub mod limits;
mod parse;
pub mod profile;
#[cfg(all(kani, feature = "alloc"))]
#[path = "../proofs/kani.rs"]
mod proofs;
pub mod query;
pub mod scalar;
#[cfg(feature = "serde")]
mod serde_impl;
pub(crate) mod utf8;
mod wire;

#[cfg(feature = "edit")]
#[cfg_attr(docsrs, doc(cfg(feature = "edit")))]
pub mod edit;
mod int;

pub use crate::canonical::CanonicalCborRef;
pub use crate::codec::CborDecode;
pub use crate::decode::{decode, decode_canonical, Decoder};
pub use crate::error::{CborError, ErrorCode};
pub use crate::limits::{DecodeLimits, EncodeLimits};
pub use crate::parse::validate_canonical;

#[cfg(feature = "alloc")]
pub mod encode;
#[cfg(feature = "alloc")]
pub mod value;
#[cfg(feature = "alloc")]
pub use crate::canonical::CanonicalCbor;
#[cfg(feature = "alloc")]
pub use crate::codec::CborEncode;
#[cfg(feature = "alloc")]
pub use crate::codec_impls::{encode_to_canonical, encode_to_vec};
#[cfg(feature = "alloc")]
pub use crate::encode::Encoder;
#[cfg(feature = "derive")]
#[cfg_attr(docsrs, doc(cfg(feature = "derive")))]
pub use sacp_cbor_derive::cbor_bytes;

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub mod serde {
    //! Serde encode/decode integration for SACP-CBOR/1.

    pub use crate::serde_impl::{
        from_canonical_bytes, from_canonical_bytes_ref, from_slice, to_vec, DeError, SerdeOptions,
    };
}

#[cfg(feature = "collections")]
#[cfg_attr(docsrs, doc(cfg(feature = "collections")))]
pub mod collections {
    //! Native collection implementations and map-entry helper types.

    pub use crate::decode::MapEntries;
}

#[cfg(feature = "derive")]
#[cfg_attr(docsrs, doc(cfg(feature = "derive")))]
pub use sacp_cbor_derive::{CborDecode, CborEncode};
