//! Context-aware ABI decoding and owned unknown-value preservation.

use alloc::string::String;
use alloc::vec::Vec;

use sacp_cbor::bytes::{Bytes, BytesRef};
use sacp_cbor::{
    CanonicalCbor, CanonicalCborRef, CborDecode, CborError, DecodeLimits, Decoder, ErrorCode,
};

/// Identifies the semantic owner of an admitted ABI value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiDecodeLocation {
    /// A value decoded directly at the root entry point.
    Root,
    /// A declared struct field or named enum-variant field.
    Field {
        /// Stable ABI type ID of the containing declaration.
        type_id: &'static str,
        /// Variant ID for a named enum payload, or `None` for a struct field.
        variant_id: Option<u32>,
        /// Stable numeric field ID.
        field_id: u32,
    },
    /// An unknown field retained by a preserve-policy declaration.
    UnknownField {
        /// Stable ABI type ID of the containing declaration.
        type_id: &'static str,
        /// Variant ID for a named enum payload, or `None` for a struct field.
        variant_id: Option<u32>,
        /// Unknown numeric field ID observed on the wire.
        field_id: u32,
    },
    /// An unknown enum variant retained by a preserve-policy declaration.
    UnknownVariant {
        /// Stable ABI type ID of the enum declaration.
        type_id: &'static str,
        /// Unknown numeric variant ID observed on the wire.
        variant_id: u32,
    },
}

/// A length-bearing semantic value observed before its first owned allocation or payload copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiDecodeValue {
    /// A homogeneous protocol sequence.
    Sequence {
        /// Header byte offset.
        offset: usize,
        /// Declared element count.
        items: usize,
    },
    /// A UTF-8 text value.
    Text {
        /// Header byte offset.
        offset: usize,
        /// Declared UTF-8 byte length.
        bytes: usize,
    },
    /// A byte-string value.
    Bytes {
        /// Header byte offset.
        offset: usize,
        /// Declared byte length.
        bytes: usize,
    },
    /// A complete canonical value that will be copied into an owned witness.
    Canonical {
        /// Header byte offset.
        offset: usize,
        /// Complete encoded byte length.
        bytes: usize,
    },
    /// One retained unknown field, before storage reservation and payload ownership.
    UnknownField {
        /// Field-ID byte offset.
        offset: usize,
    },
    /// One retained unknown variant, before payload ownership.
    UnknownVariant {
        /// Variant-ID byte offset.
        offset: usize,
    },
}

/// Caller-owned admission context threaded through an entire recursive ABI decode.
pub trait AbiDecodeContext {
    /// Error returned by the complete decode transaction.
    type Error: From<CborError>;

    /// Admit one semantic value before ownership is allocated or copied.
    fn admit(
        &mut self,
        location: AbiDecodeLocation,
        value: AbiDecodeValue,
    ) -> Result<(), Self::Error>;
}

impl AbiDecodeContext for () {
    type Error = CborError;

    fn admit(
        &mut self,
        _location: AbiDecodeLocation,
        _value: AbiDecodeValue,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Decode a public ABI value through one caller-owned admission context.
pub trait AbiDecode<'de, C: AbiDecodeContext + ?Sized>: Sized {
    /// Decode `Self` from a streaming decoder.
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        context: &mut C,
        location: AbiDecodeLocation,
    ) -> Result<Self, C::Error>;
}

/// Preserved unknown field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownField {
    /// Stable numeric field ID.
    pub id: u32,
    /// Canonical field value bytes.
    pub value: CanonicalCbor,
}

impl UnknownField {
    /// Construct a preserved unknown field.
    pub fn new(id: u32, value: CanonicalCbor) -> Result<Self, CborError> {
        if id == 0 {
            return Err(CborError::new(ErrorCode::InvalidAbiValue, 0));
        }
        Ok(Self { id, value })
    }
}

/// Preserved unknown fields in strict field-ID order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnknownFields(Vec<UnknownField>);

impl UnknownFields {
    /// Construct an empty unknown-field set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Construct an unknown-field set after validating ID order and uniqueness.
    pub fn try_from_vec(fields: Vec<UnknownField>) -> Result<Self, CborError> {
        let mut previous = None;
        for field in &fields {
            if field.id == 0 || previous.is_some_and(|id| field.id <= id) {
                return Err(CborError::new(ErrorCode::InvalidAbiValue, 0));
            }
            previous = Some(field.id);
        }
        Ok(Self(fields))
    }

    /// Return the preserved fields.
    #[must_use]
    pub fn as_slice(&self) -> &[UnknownField] {
        &self.0
    }

    /// Return the number of preserved fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return `true` when no unknown fields are preserved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume and return the preserved fields.
    #[must_use]
    pub fn into_vec(self) -> Vec<UnknownField> {
        self.0
    }
}

/// Preserved unknown enum variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownVariant {
    /// Stable numeric variant ID.
    pub id: u32,
    /// Canonical payload bytes.
    pub payload: CanonicalCbor,
}

impl UnknownVariant {
    /// Construct a preserved unknown variant.
    pub fn new(id: u32, payload: CanonicalCbor) -> Result<Self, CborError> {
        if id == 0 {
            return Err(CborError::new(ErrorCode::InvalidAbiValue, 0));
        }
        Ok(Self { id, payload })
    }
}

/// Validate and decode an ABI value through one caller-owned context.
pub fn decode<'de, T, C>(
    bytes: &'de [u8],
    limits: DecodeLimits,
    context: &mut C,
) -> Result<T, C::Error>
where
    C: AbiDecodeContext + ?Sized,
    T: AbiDecode<'de, C>,
{
    let mut decoder = Decoder::<true>::new_checked(bytes, limits)?;
    let value = T::abi_decode(&mut decoder, context, AbiDecodeLocation::Root)?;
    let _ = decoder.finish()?;
    Ok(value)
}

/// Decode an ABI value from an already validated canonical witness.
pub fn decode_canonical<'de, T, C>(
    cbor: CanonicalCborRef<'de>,
    context: &mut C,
) -> Result<T, C::Error>
where
    C: AbiDecodeContext + ?Sized,
    T: AbiDecode<'de, C>,
{
    let mut decoder =
        Decoder::<false>::new_trusted(cbor, DecodeLimits::for_bytes(cbor.as_bytes().len()))?;
    let value = T::abi_decode(&mut decoder, context, AbiDecodeLocation::Root)?;
    let _ = decoder.finish()?;
    Ok(value)
}

macro_rules! passthrough_decode {
    ($($ty:ty),* $(,)?) => {
        $(
            impl<'de, C: AbiDecodeContext + ?Sized> AbiDecode<'de, C> for $ty {
                fn abi_decode<const CHECKED: bool>(
                    decoder: &mut Decoder<'de, CHECKED>,
                    _context: &mut C,
                    _location: AbiDecodeLocation,
                ) -> Result<Self, C::Error> {
                    CborDecode::decode(decoder).map_err(C::Error::from)
                }
            }
        )*
    };
}

passthrough_decode!((), bool, u8, u16, u32, u64, i8, i16, i32, i64);

impl<'de, C: AbiDecodeContext + ?Sized> AbiDecode<'de, C> for &'de str {
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        _context: &mut C,
        _location: AbiDecodeLocation,
    ) -> Result<Self, C::Error> {
        CborDecode::decode(decoder).map_err(C::Error::from)
    }
}

impl<'de, C: AbiDecodeContext + ?Sized> AbiDecode<'de, C> for String {
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        context: &mut C,
        location: AbiDecodeLocation,
    ) -> Result<Self, C::Error> {
        let offset = decoder.position();
        let value = decoder.decode_text_with_guard(|header| {
            context.admit(
                location,
                AbiDecodeValue::Text {
                    offset: header.header_offset(),
                    bytes: header.declared_len(),
                },
            )
        })?;
        let mut owned = String::new();
        owned
            .try_reserve_exact(value.len())
            .map_err(|_| C::Error::from(CborError::new(ErrorCode::AllocationFailed, offset)))?;
        owned.push_str(value);
        Ok(owned)
    }
}

impl<'de, C: AbiDecodeContext + ?Sized> AbiDecode<'de, C> for BytesRef<'de> {
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        _context: &mut C,
        _location: AbiDecodeLocation,
    ) -> Result<Self, C::Error> {
        CborDecode::decode(decoder).map_err(C::Error::from)
    }
}

impl<'de, C: AbiDecodeContext + ?Sized> AbiDecode<'de, C> for Bytes {
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        context: &mut C,
        location: AbiDecodeLocation,
    ) -> Result<Self, C::Error> {
        let offset = decoder.position();
        let value = decoder.decode_bytes_with_guard(|header| {
            context.admit(
                location,
                AbiDecodeValue::Bytes {
                    offset: header.header_offset(),
                    bytes: header.declared_len(),
                },
            )
        })?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(value.len())
            .map_err(|_| C::Error::from(CborError::new(ErrorCode::AllocationFailed, offset)))?;
        owned.extend_from_slice(value);
        Ok(Self::new(owned))
    }
}

impl<'de, C: AbiDecodeContext + ?Sized> AbiDecode<'de, C> for CanonicalCborRef<'de> {
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        _context: &mut C,
        _location: AbiDecodeLocation,
    ) -> Result<Self, C::Error> {
        CborDecode::decode(decoder).map_err(C::Error::from)
    }
}

impl<'de, C: AbiDecodeContext + ?Sized> AbiDecode<'de, C> for CanonicalCbor {
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        context: &mut C,
        location: AbiDecodeLocation,
    ) -> Result<Self, C::Error> {
        let value_offset = core::cell::Cell::new(0);
        let value = decoder.decode_canonical_with_guard(|header| {
            value_offset.set(header.header_offset());
            context.admit(
                location,
                AbiDecodeValue::Canonical {
                    offset: header.header_offset(),
                    bytes: header.encoded_len(),
                },
            )
        })?;
        value
            .to_owned_with_offset(value_offset.get())
            .map_err(C::Error::from)
    }
}

impl<'de, C: AbiDecodeContext + ?Sized, const N: usize> AbiDecode<'de, C> for [u8; N] {
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        _context: &mut C,
        _location: AbiDecodeLocation,
    ) -> Result<Self, C::Error> {
        CborDecode::decode(decoder).map_err(C::Error::from)
    }
}

impl<'de, T, C> AbiDecode<'de, C> for Vec<T>
where
    C: AbiDecodeContext + ?Sized,
    T: AbiDecode<'de, C>,
{
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        context: &mut C,
        location: AbiDecodeLocation,
    ) -> Result<Self, C::Error> {
        let array_offset = decoder.position();
        let array = decoder.array()?;
        let mut array = array.admit_with(|header| {
            context.admit(
                location,
                AbiDecodeValue::Sequence {
                    offset: header.header_offset(),
                    items: header.declared_len(),
                },
            )
        })?;
        let mut out = Vec::new();
        out.try_reserve_exact(array.remaining()).map_err(|_| {
            C::Error::from(CborError::new(ErrorCode::AllocationFailed, array_offset))
        })?;
        while let Some(value) =
            array.decode_next_with(|decoder| T::abi_decode(decoder, context, location))?
        {
            out.push(value);
        }
        Ok(out)
    }
}
