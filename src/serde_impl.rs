use alloc::string::String;
use core::fmt;
use serde::de::{
    self, Deserialize, DeserializeSeed, EnumAccess, IntoDeserializer, MapAccess, SeqAccess,
    VariantAccess, Visitor,
};
use serde::Deserializer;

use crate::canonical::{CanonicalCbor, CanonicalCborRef};
use crate::codec::CborDecode;
use crate::decode::{ArrayDecoder, Decoder, MapDecoder};
use crate::query::{CborKind, CborValueRef};
use crate::{CborError, DecodeLimits, ErrorCode, WorkObserver};

const RAW_VALUE_MARKER: &str = "$__sacp_cbor_raw_value";

/// Deserialize a Rust value from canonical SACP-CBOR/1 bytes.
///
/// This validates and deserializes in a single pass over the input.
///
/// # Errors
///
/// Returns a canonical-profile, structural, or serde type error.
pub fn from_slice<'de, T: Deserialize<'de>>(
    bytes: &'de [u8],
    limits: DecodeLimits,
) -> Result<T, CborError> {
    let mut decoder = Decoder::<true>::new_checked(bytes, limits)?;
    let value = T::deserialize(&mut decoder).map_err(DeError::into_cbor_error)?;
    if decoder.position() != bytes.len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, decoder.position()));
    }
    Ok(value)
}

/// A serde decoding error that preserves an [`ErrorCode`] plus an input offset.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeError {
    /// Error category.
    pub code: ErrorCode,
    /// Byte offset within the input where the error was detected.
    pub offset: usize,
}

impl DeError {
    #[inline]
    #[must_use]
    /// Construct a new serde error with a code and offset.
    pub const fn new(code: ErrorCode, offset: usize) -> Self {
        Self { code, offset }
    }

    #[inline]
    #[must_use]
    /// Convert into the crate's [`CborError`].
    pub const fn into_cbor_error(self) -> CborError {
        CborError::new(self.code, self.offset)
    }
}

impl fmt::Display for DeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let e = CborError::new(self.code, self.offset);
        fmt::Display::fmt(&e, f)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DeError {}

impl serde::de::Error for DeError {
    fn custom<T: fmt::Display>(_msg: T) -> Self {
        Self::new(ErrorCode::SerdeError, 0)
    }
}

impl From<CborError> for DeError {
    fn from(e: CborError) -> Self {
        Self::new(e.code, e.offset)
    }
}

struct ArrayAccess<'a, 'de, const CHECKED: bool, O: WorkObserver> {
    array: ArrayDecoder<'a, 'de, CHECKED, O>,
}

impl<'de, const CHECKED: bool, O: WorkObserver> SeqAccess<'de>
    for ArrayAccess<'_, 'de, CHECKED, O>
{
    type Error = DeError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, DeError>
    where
        T: DeserializeSeed<'de>,
    {
        self.array
            .decode_next(|decoder| seed.deserialize(decoder).map_err(DeError::into_cbor_error))
            .map_err(DeError::from)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.array.remaining())
    }
}

struct MapAccessImpl<'a, 'de, const CHECKED: bool, O: WorkObserver> {
    map: MapDecoder<'a, 'de, CHECKED, O>,
}

impl<'de, const CHECKED: bool, O: WorkObserver> MapAccess<'de>
    for MapAccessImpl<'_, 'de, CHECKED, O>
{
    type Error = DeError;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, DeError>
    where
        K: DeserializeSeed<'de>,
    {
        let Some(key) = self.map.next_key_ref().map_err(DeError::from)? else {
            return Ok(None);
        };
        seed.deserialize(<&'de str as IntoDeserializer<'de, DeError>>::into_deserializer(key.text))
            .map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, DeError>
    where
        V: DeserializeSeed<'de>,
    {
        self.map
            .decode_value(|decoder| seed.deserialize(decoder).map_err(DeError::into_cbor_error))
            .map_err(DeError::from)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.map.remaining())
    }
}

enum EnumPayload<'a, 'de, const CHECKED: bool, O: WorkObserver> {
    Unit,
    Map(MapDecoder<'a, 'de, CHECKED, O>),
}

struct EnumAccessImpl<'a, 'de, const CHECKED: bool, O: WorkObserver> {
    key: &'de str,
    payload: EnumPayload<'a, 'de, CHECKED, O>,
    offset: usize,
}

#[allow(clippy::elidable_lifetime_names)]
impl<'a, 'de, const CHECKED: bool, O: WorkObserver> EnumAccess<'de>
    for EnumAccessImpl<'a, 'de, CHECKED, O>
{
    type Error = DeError;
    type Variant = VariantAccessImpl<'a, 'de, CHECKED, O>;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), DeError>
    where
        V: DeserializeSeed<'de>,
    {
        let variant = seed.deserialize(
            <&'de str as IntoDeserializer<'de, DeError>>::into_deserializer(self.key),
        )?;
        Ok((
            variant,
            VariantAccessImpl {
                payload: self.payload,
                offset: self.offset,
            },
        ))
    }
}

struct VariantAccessImpl<'a, 'de, const CHECKED: bool, O: WorkObserver> {
    payload: EnumPayload<'a, 'de, CHECKED, O>,
    offset: usize,
}

impl<'de, const CHECKED: bool, O: WorkObserver> VariantAccess<'de>
    for VariantAccessImpl<'_, 'de, CHECKED, O>
{
    type Error = DeError;

    fn unit_variant(self) -> Result<(), DeError> {
        match self.payload {
            EnumPayload::Unit => Ok(()),
            EnumPayload::Map(mut map) => map
                .decode_value(|decoder| {
                    let _: () = CborDecode::decode(decoder)?;
                    Ok(())
                })
                .map_err(DeError::from),
        }
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, DeError>
    where
        T: DeserializeSeed<'de>,
    {
        match self.payload {
            EnumPayload::Unit => Err(DeError::new(ErrorCode::ExpectedEnum, self.offset)),
            EnumPayload::Map(mut map) => map
                .decode_value(|decoder| seed.deserialize(decoder).map_err(DeError::into_cbor_error))
                .map_err(DeError::from),
        }
    }

    fn tuple_variant<V>(self, len: usize, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        match self.payload {
            EnumPayload::Unit => Err(DeError::new(ErrorCode::ExpectedEnum, self.offset)),
            EnumPayload::Map(mut map) => map
                .decode_value(|decoder| {
                    decoder
                        .deserialize_tuple(len, visitor)
                        .map_err(DeError::into_cbor_error)
                })
                .map_err(DeError::from),
        }
    }

    fn struct_variant<V>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        match self.payload {
            EnumPayload::Unit => Err(DeError::new(ErrorCode::ExpectedEnum, self.offset)),
            EnumPayload::Map(mut map) => map
                .decode_value(|decoder| {
                    decoder
                        .deserialize_struct("", fields, visitor)
                        .map_err(DeError::into_cbor_error)
                })
                .map_err(DeError::from),
        }
    }
}

impl<'de, const CHECKED: bool, O: WorkObserver> de::Deserializer<'de>
    for &mut Decoder<'de, CHECKED, O>
{
    type Error = DeError;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        match self.peek_kind().map_err(DeError::from)? {
            CborKind::Null => self.deserialize_unit(visitor),
            CborKind::Bool => self.deserialize_bool(visitor),
            CborKind::Integer => {
                let value: i128 = CborDecode::decode(self).map_err(DeError::from)?;
                visitor.visit_i128(value)
            }
            CborKind::Float => self.deserialize_f64(visitor),
            CborKind::Bytes => {
                let value: &'de [u8] = CborDecode::decode(self).map_err(DeError::from)?;
                visitor.visit_borrowed_bytes(value)
            }
            CborKind::Text => {
                let value: &'de str = CborDecode::decode(self).map_err(DeError::from)?;
                visitor.visit_borrowed_str(value)
            }
            CborKind::Array => self.deserialize_seq(visitor),
            CborKind::Map => self.deserialize_map(visitor),
        }
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: bool = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_bool(value)
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: i8 = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_i8(value)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: i16 = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_i16(value)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: i32 = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_i32(value)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: i64 = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_i64(value)
    }

    fn deserialize_i128<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: i128 = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_i128(value)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: u8 = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_u8(value)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: u16 = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_u16(value)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: u32 = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_u32(value)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: u64 = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_u64(value)
    }

    fn deserialize_u128<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: u128 = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_u128(value)
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: f32 = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_f32(value)
    }

    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: f64 = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_f64(value)
    }

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: &'de str = CborDecode::decode(self).map_err(DeError::from)?;
        let mut chars = value.chars();
        let ch = chars
            .next()
            .ok_or_else(|| DeError::new(ErrorCode::ExpectedText, self.position()))?;
        if chars.next().is_some() {
            return Err(DeError::new(ErrorCode::ExpectedText, self.position()));
        }
        visitor.visit_char(ch)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: &'de str = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_borrowed_str(value)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: String = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_string(value)
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: &'de [u8] = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_borrowed_bytes(value)
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let value: crate::bytes::Bytes = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_byte_buf(value.into_vec())
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.position();
        let mut map = self.map().map_err(DeError::from)?;
        if map.remaining() != 1 {
            return Err(DeError::new(ErrorCode::MapLenMismatch, off));
        }
        let Some(key) = map.next_key_ref().map_err(DeError::from)? else {
            return Err(DeError::new(ErrorCode::MapLenMismatch, off));
        };
        match key.text {
            "none" => {
                map.decode_value(|decoder| {
                    let _: () = CborDecode::decode(decoder)?;
                    Ok(())
                })
                .map_err(DeError::from)?;
                visitor.visit_none()
            }
            "some" => map
                .decode_value(|decoder| {
                    visitor
                        .visit_some(decoder)
                        .map_err(DeError::into_cbor_error)
                })
                .map_err(DeError::from),
            _ => Err(DeError::new(ErrorCode::UnknownEnumVariant, key.offset)),
        }
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let _: () = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        if name == RAW_VALUE_MARKER {
            let start = self.position();
            self.skip_value().map_err(DeError::from)?;
            let end = self.position();
            let raw = &self.data()[start..end];
            return visitor.visit_borrowed_bytes(raw);
        }
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let array = self.array().map_err(DeError::from)?;
        visitor.visit_seq(ArrayAccess { array })
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.position();
        let array = self.array().map_err(DeError::from)?;
        if array.remaining() != len {
            return Err(DeError::new(ErrorCode::ArrayLenMismatch, off));
        }
        visitor.visit_seq(ArrayAccess { array })
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        self.deserialize_tuple(len, visitor)
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let map = self.map().map_err(DeError::from)?;
        visitor.visit_map(MapAccessImpl { map })
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.position();
        if matches!(self.peek_kind().map_err(DeError::from)?, CborKind::Text) {
            let key: &'de str = CborDecode::decode(self).map_err(DeError::from)?;
            return visitor.visit_enum(EnumAccessImpl {
                key,
                payload: EnumPayload::<CHECKED, O>::Unit,
                offset: off,
            });
        }
        if !matches!(self.peek_kind().map_err(DeError::from)?, CborKind::Map) {
            return Err(DeError::new(ErrorCode::ExpectedEnum, off));
        }
        let mut map = self.map().map_err(DeError::from)?;
        if map.remaining() != 1 {
            return Err(DeError::new(ErrorCode::MapLenMismatch, off));
        }
        let Some(key) = map.next_key_ref().map_err(DeError::from)? else {
            return Err(DeError::new(ErrorCode::MapLenMismatch, off));
        };
        visitor.visit_enum(EnumAccessImpl {
            key: key.text,
            payload: EnumPayload::Map(map),
            offset: key.offset,
        })
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        self.skip_value().map_err(DeError::from)?;
        visitor.visit_unit()
    }
}

/// Deserialize `T` from validated canonical bytes without re-checking canonical encodings.
///
/// This assumes `canon` was produced by `validate_canonical`.
///
/// # Errors
///
/// Returns an error if deserialization fails or if trailing bytes are found.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub fn from_canonical_bytes_ref<'de, T>(canon: CanonicalCborRef<'de>) -> Result<T, CborError>
where
    T: Deserialize<'de>,
{
    let limits = DecodeLimits::for_bytes(canon.as_bytes().len());
    let mut decoder = Decoder::<false>::new_trusted(canon, limits)?;
    let value = T::deserialize(&mut decoder).map_err(DeError::into_cbor_error)?;
    if decoder.position() != canon.as_bytes().len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, decoder.position()));
    }
    Ok(value)
}

/// Deserialize `T` from owned canonical bytes without re-checking canonical encodings.
///
/// This assumes `canon` was produced by `CanonicalCbor::from_slice` or `CanonicalCbor::from_vec`.
///
/// # Errors
///
/// Returns an error if deserialization fails or if trailing bytes are found.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub fn from_canonical_bytes<'de, T>(canon: &'de CanonicalCbor) -> Result<T, CborError>
where
    T: Deserialize<'de>,
{
    from_canonical_bytes_ref(canon.as_canonical_ref())
}

impl<'de> Deserialize<'de> for CborValueRef<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct RawCborValueVisitor;

        impl<'de> Visitor<'de> for RawCborValueVisitor {
            type Value = CborValueRef<'de>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a raw CBOR value")
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CborValueRef::new(v, 0, v.len()))
            }
        }

        deserializer.deserialize_newtype_struct(RAW_VALUE_MARKER, RawCborValueVisitor)
    }
}
