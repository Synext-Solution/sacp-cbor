//! Static, storage-independent ABI schemas and allocation-free projected codecs for SACP-CBOR.

#![no_std]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use core::fmt::Debug;

use sacp_cbor::{ByteSink, CborError, ErrorCode};

mod decode_abi;
mod edit;
mod encode_abi;
mod runtime;
mod schema;
mod view;

#[cfg(kani)]
#[path = "../../proofs/abi_kani.rs"]
mod proofs;

pub use decode_abi::{
    decode, decode_canonical, AbiDecode, AbiDecodeContext, AbiDecodeLocation, AbiDecodeValue,
    UnknownField, UnknownFields, UnknownVariant,
};
pub use edit::{AbiDeleteMode, AbiFieldSetEditor, AbiPatchValue, AbiSetMode};
pub use encode_abi::{
    encode_to_canonical, encode_to_sink, encode_to_vec, exact_indexed_sequence, indexed_sequence,
    projected_sequence, wire, AbiEncode, AbiEncodeAs, AbiEncodeError, AbiRepresentation,
    AbiWireType, ExactIndexProjection, ExactIndexedSequence, IndexedSequence, ProjectedSequence,
    SequenceContractError, SequenceEmitter, SequenceProjection,
};
pub use runtime::{
    AbiSchemaRegistry, NoNamedSchemas, RuntimeAbiError, RuntimeEnumSchema, RuntimeEnumView,
    RuntimeFieldRef, RuntimeFieldSetSchema, RuntimeFieldSetView, RuntimeSchema,
    RuntimeValidationLimits, RuntimeValidationWorkspace,
};
pub use sacp_cbor::EncodeLimits;
#[cfg(feature = "derive")]
pub use sacp_cbor_abi_derive::CborAbi;
pub use schema::{
    diff, encode_schema_to_sink, schema_hash, CompatibilityClass, CompatibilityReport, EnumDef,
    FieldDef, FieldPresence, FieldSetDef, Schema, SchemaChange, SchemaChangeClass, SchemaHash,
    SchemaHashKind, TypeAtom, TypeDef, TypeRef, UnknownFieldPolicy, UnknownVariantPolicy,
    VariantDef, VariantPayloadDef, ABI_PROFILE,
};
pub use view::{
    AbiArrayView, AbiFieldEntryRef, AbiFieldSetRef, AbiView, AbiViewField, UnknownFieldRef,
    UnknownVariantRef,
};

/// The one static schema owner for a public ABI declaration.
pub trait AbiType: AbiWireType {
    /// Allocation-free schema descriptor generated from the declaration's single ID/policy owner.
    const SCHEMA: &'static Schema;

    /// Return the unique static schema descriptor.
    #[must_use]
    fn schema() -> &'static Schema {
        Self::SCHEMA
    }
}

/// Support items used by generated code.
#[doc(hidden)]
pub mod __private {
    pub use alloc::{boxed::Box, string::String, vec, vec::Vec};
    pub use sacp_cbor;

    use super::{AbiDecodeContext, AbiEncodeError, UnknownFields, UnknownVariant};

    /// Convert one core decode failure into the active ABI context's error domain.
    pub fn decode_error<C: AbiDecodeContext + ?Sized>(
        code: sacp_cbor::ErrorCode,
        offset: usize,
    ) -> C::Error {
        C::Error::from(sacp_cbor::CborError::new(code, offset))
    }

    /// Decode and validate a nonzero ABI field or variant ID.
    pub fn decode_abi_id(
        value: sacp_cbor::query::CborValueRef<'_>,
    ) -> Result<u32, sacp_cbor::CborError> {
        super::view::abi_field_id(value)
    }

    /// Encode one schema-owned numeric ID.
    pub fn encode_field_id<S: sacp_cbor::ByteSink, E>(
        array: &mut sacp_cbor::encode::ArrayEncoder<'_, S>,
        id: u32,
    ) -> Result<(), AbiEncodeError<S::Error, E>> {
        array.value(&id).map_err(AbiEncodeError::Encode)
    }

    /// Encode preserved unknown fields whose IDs are lower than `before_id`.
    pub fn encode_unknown_fields_before<S: sacp_cbor::ByteSink, E>(
        array: &mut sacp_cbor::encode::ArrayEncoder<'_, S>,
        unknown: &UnknownFields,
        cursor: &mut usize,
        before_id: u32,
    ) -> Result<(), AbiEncodeError<S::Error, E>> {
        super::encode_abi::encode_unknown_fields_before(array, unknown, cursor, before_id)
    }

    /// Encode all remaining preserved unknown fields.
    pub fn encode_remaining_unknown_fields<S: sacp_cbor::ByteSink, E>(
        array: &mut sacp_cbor::encode::ArrayEncoder<'_, S>,
        unknown: &UnknownFields,
        cursor: &mut usize,
    ) -> Result<(), AbiEncodeError<S::Error, E>> {
        super::encode_abi::encode_remaining_unknown_fields(array, unknown, cursor)
    }

    /// Reject an unknown variant whose ID collides with a known semantic variant.
    pub fn validate_unknown_variant<SinkError, E>(
        variant: &UnknownVariant,
        reserved: &[u32],
    ) -> Result<(), AbiEncodeError<SinkError, E>> {
        super::encode_abi::validate_unknown_variant(variant, reserved)
    }

    /// Widen an impossible owned-projection error into an arbitrary surrounding error domain.
    pub fn widen_infallible<SinkError, E>(
        error: AbiEncodeError<SinkError, core::convert::Infallible>,
    ) -> AbiEncodeError<SinkError, E> {
        match error {
            AbiEncodeError::Encode(error) => AbiEncodeError::Encode(error),
            AbiEncodeError::Projection(never) => match never {},
            AbiEncodeError::Sequence(error) => AbiEncodeError::Sequence(error),
        }
    }

    /// Construct the typed ABI wrapper for checked-length arithmetic overflow.
    pub fn length_overflow<SinkError, E>() -> AbiEncodeError<SinkError, E> {
        AbiEncodeError::Encode(sacp_cbor::EncodeError::Cbor(sacp_cbor::CborError::new(
            sacp_cbor::ErrorCode::LengthOverflow,
            0,
        )))
    }
}

/// Assert a type's wire schema hash under explicit encoding limits.
pub fn assert_wire_schema_hash<T: AbiType>(expected_hex: &str, limits: EncodeLimits) {
    let actual = T::SCHEMA.wire_hash(limits).expect("schema wire hash");
    assert_eq!(actual.to_string(), expected_hex);
}

/// Assert a type's full schema hash under explicit encoding limits.
pub fn assert_full_schema_hash<T: AbiType>(expected_hex: &str, limits: EncodeLimits) {
    let actual = T::SCHEMA.full_hash(limits).expect("schema full hash");
    assert_eq!(actual.to_string(), expected_hex);
}

/// Assert an ABI encoding golden vector under explicit limits.
pub fn assert_abi_vector<T>(name: &str, value: &T, expected_hex: &str, limits: EncodeLimits)
where
    T: AbiEncode + ?Sized,
    T::Error: Debug,
{
    let bytes = encode_to_vec(value, limits)
        .unwrap_or_else(|error| panic!("{name}: encode failed: {error:?}"));
    let mut actual = String::new();
    for byte in bytes {
        actual.push_str(&format!("{byte:02x}"));
    }
    assert_eq!(actual, expected_hex, "{name}");
}

/// Assert that ABI decoding rejects bytes with the expected core error code.
pub fn assert_abi_rejects<'de, T, C>(bytes: &'de [u8], expected: ErrorCode, context: &mut C)
where
    C: AbiDecodeContext<Error = CborError> + ?Sized,
    T: AbiDecode<'de, C>,
{
    match decode::<T, C>(
        bytes,
        sacp_cbor::DecodeLimits::for_bytes(bytes.len()),
        context,
    ) {
        Ok(_) => panic!("decode unexpectedly succeeded"),
        Err(error) => assert_eq!(error.code, expected),
    }
}

// Keep the public signature honest: all encoding entry points accept a generic sink.
const _: fn() = || {
    fn assert_sink<S: ByteSink>() {}
    let _ = assert_sink::<sacp_cbor::encode::VecSink>;
};
