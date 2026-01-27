use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::de::{
    self, Deserialize, DeserializeSeed, EnumAccess, IntoDeserializer, MapAccess, SeqAccess,
    VariantAccess, Visitor,
};
use serde::ser::{self, SerializeMap, SerializeSeq, SerializeStruct};
use serde::{Deserialize as SerdeDeserialize, Serialize, Serializer};

use crate::canonical::{CborBytes, CborBytesRef};
use crate::encode::Encoder;
use crate::int::{integer_from_i128, integer_from_u128};
use crate::profile::{
    is_strictly_increasing_encoded, validate_bignum_bytes, validate_f64_bits, MAX_SAFE_INTEGER,
};
use crate::scalar::F64Bits;
use crate::value::{CborMap, CborValue, ValueRepr};
use crate::{CborError, DecodeLimits, ErrorCode};

fn check_map_key_order(
    enc: &mut Encoder,
    prev_key_range: Option<(usize, usize)>,
    key_start: usize,
    key_end: usize,
    entry_start: usize,
) -> Result<(), SerdeError> {
    if let Some((ps, pe)) = prev_key_range {
        let buf = enc.as_bytes();
        let prev = &buf[ps..pe];
        let curr = &buf[key_start..key_end];
        if prev == curr {
            enc.truncate(entry_start);
            return Err(SerdeError::with_code(ErrorCode::DuplicateMapKey));
        }
        if !is_strictly_increasing_encoded(prev, curr) {
            enc.truncate(entry_start);
            return Err(SerdeError::with_code(ErrorCode::NonCanonicalMapOrder));
        }
    }
    Ok(())
}

fn mag_to_u128(mag: &[u8]) -> Option<u128> {
    if mag.len() > 16 {
        return None;
    }
    let mut buf = [0u8; 16];
    let start = 16 - mag.len();
    buf[start..].copy_from_slice(mag);
    Some(u128::from_be_bytes(buf))
}

fn bigint_to_u128(negative: bool, mag: &[u8]) -> Option<u128> {
    if negative {
        return None;
    }
    mag_to_u128(mag)
}

fn bigint_to_i128(negative: bool, mag: &[u8]) -> Option<i128> {
    let n = mag_to_u128(mag)?;
    if n > i128::MAX as u128 {
        return None;
    }
    let n_i = i128::try_from(n).ok()?;
    if negative {
        Some(-1 - n_i)
    } else {
        Some(n_i)
    }
}

impl Serialize for CborValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.repr() {
            ValueRepr::Null => serializer.serialize_unit(),
            ValueRepr::Bool(b) => serializer.serialize_bool(*b),
            ValueRepr::Integer(i) => {
                if let Some(v) = i.as_i64() {
                    serializer.serialize_i64(v)
                } else if let Some(b) = i.as_bigint() {
                    if let Some(v) = bigint_to_i128(b.is_negative(), b.magnitude()) {
                        serializer.serialize_i128(v)
                    } else if let Some(v) = bigint_to_u128(b.is_negative(), b.magnitude()) {
                        serializer.serialize_u128(v)
                    } else {
                        Err(serde::ser::Error::custom("bignum out of range"))
                    }
                } else {
                    Err(serde::ser::Error::custom("invalid integer"))
                }
            }
            ValueRepr::Float(bits) => serializer.serialize_f64(bits.to_f64()),
            ValueRepr::Bytes(b) => serializer.serialize_bytes(b),
            ValueRepr::Text(s) => serializer.serialize_str(s),
            ValueRepr::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            ValueRepr::Map(map) => {
                let mut m = serializer.serialize_map(Some(map.len()))?;
                for (k, v) in map.iter() {
                    m.serialize_entry(k, v)?;
                }
                m.end()
            }
        }
    }
}

impl<'de> SerdeDeserialize<'de> for CborValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(CborValueVisitor)
    }
}

struct CborValueVisitor;

impl<'de> Visitor<'de> for CborValueVisitor {
    type Value = CborValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a valid SACP-CBOR/1 value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
        Ok(CborValue::bool(v))
    }

    fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        int_to_value(i128::from(v)).map_err(|_| E::custom("invalid integer"))
    }

    fn visit_i16<E>(self, v: i16) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        int_to_value(i128::from(v)).map_err(|_| E::custom("invalid integer"))
    }

    fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        int_to_value(i128::from(v)).map_err(|_| E::custom("invalid integer"))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        int_to_value(i128::from(v)).map_err(|_| E::custom("invalid integer"))
    }

    fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        int_to_value(v).map_err(|_| E::custom("invalid integer"))
    }

    fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        uint_to_value(u128::from(v)).map_err(|_| E::custom("invalid integer"))
    }

    fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        uint_to_value(u128::from(v)).map_err(|_| E::custom("invalid integer"))
    }

    fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        uint_to_value(u128::from(v)).map_err(|_| E::custom("invalid integer"))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        uint_to_value(u128::from(v)).map_err(|_| E::custom("invalid integer"))
    }

    fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        uint_to_value(v).map_err(|_| E::custom("invalid integer"))
    }

    fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_f64(f64::from(v))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let bits = F64Bits::try_from_f64(v).map_err(|_| E::custom("invalid float"))?;
        Ok(CborValue::float(bits))
    }

    fn visit_char<E: serde::de::Error>(self, v: char) -> Result<Self::Value, E> {
        let mut buf = [0u8; 4];
        let s = v.encode_utf8(&mut buf);
        let boxed = crate::alloc_util::try_box_str_from_str(s, 0)
            .map_err(|_| E::custom("allocation failed"))?;
        Ok(CborValue::text(boxed))
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        let boxed = crate::alloc_util::try_box_str_from_str(v, 0)
            .map_err(|_| E::custom("allocation failed"))?;
        Ok(CborValue::text(boxed))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
        Ok(CborValue::text(v))
    }

    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        let out = crate::alloc_util::try_vec_from_slice(v, 0)
            .map_err(|_| E::custom("allocation failed"))?;
        Ok(CborValue::bytes(out))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E> {
        Ok(CborValue::bytes(v))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(CborValue::null())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(CborValue::null())
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut items: Vec<CborValue> = match seq.size_hint() {
            Some(len) => crate::alloc_util::try_vec_with_capacity(len, 0)
                .map_err(|_| <A::Error as serde::de::Error>::custom("allocation failed"))?,
            None => crate::alloc_util::try_vec_with_capacity(8, 0)
                .map_err(|_| <A::Error as serde::de::Error>::custom("allocation failed"))?,
        };
        while let Some(v) = seq.next_element::<CborValue>()? {
            crate::alloc_util::try_reserve(&mut items, 1, 0).map_err(|err| {
                let msg = match err.code {
                    ErrorCode::LengthOverflow => "length overflow",
                    _ => "allocation failed",
                };
                <A::Error as serde::de::Error>::custom(msg)
            })?;
            items.push(v);
        }
        Ok(CborValue::array(items))
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: serde::de::MapAccess<'de>,
    {
        let mut entries: Vec<(Box<str>, CborValue)> = match map.size_hint() {
            Some(len) => crate::alloc_util::try_vec_with_capacity(len, 0)
                .map_err(|_| <M::Error as serde::de::Error>::custom("allocation failed"))?,
            None => crate::alloc_util::try_vec_with_capacity(8, 0)
                .map_err(|_| <M::Error as serde::de::Error>::custom("allocation failed"))?,
        };
        while let Some((k, v)) = map.next_entry::<Box<str>, CborValue>()? {
            crate::alloc_util::try_reserve(&mut entries, 1, 0).map_err(|err| {
                let msg = match err.code {
                    ErrorCode::LengthOverflow => "length overflow",
                    _ => "allocation failed",
                };
                <M::Error as serde::de::Error>::custom(msg)
            })?;
            entries.push((k, v));
        }
        let map = CborMap::new(entries)
            .map_err(|_| <M::Error as serde::de::Error>::custom("invalid map"))?;
        Ok(CborValue::map(map))
    }
}

/// Serialize a Rust value into canonical SACP-CBOR/1 bytes.
///
/// # Errors
///
/// Returns an error if the value cannot be represented under SACP-CBOR/1 constraints.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, CborError> {
    let mut enc = Encoder::new();
    value
        .serialize(EncoderSerializer::new(&mut enc))
        .map_err(|err| CborError::new(err.code, 0))?;
    Ok(enc.into_vec())
}

/// Deserialize a Rust value from canonical SACP-CBOR/1 bytes.
///
/// This validates and deserializes in a single pass over the input.
///
/// # Errors
///
/// Returns an error if bytes are invalid or if the decoded value doesn't match the target type.
pub fn from_slice<'de, T: Deserialize<'de>>(
    bytes: &'de [u8],
    limits: DecodeLimits,
) -> Result<T, CborError> {
    let mut de = DirectDeserializer::new_checked(bytes, limits)?;
    let value = T::deserialize(&mut de).map_err(DeError::into_cbor_error)?;
    if de.offset() != bytes.len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, de.offset()));
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy)]
struct SerdeError {
    code: ErrorCode,
}

impl SerdeError {
    const fn with_code(code: ErrorCode) -> Self {
        Self { code }
    }
}

impl fmt::Display for SerdeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let err = CborError::new(self.code, 0);
        fmt::Display::fmt(&err, f)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SerdeError {}

impl serde::ser::Error for SerdeError {
    fn custom<T: fmt::Display>(_msg: T) -> Self {
        Self::with_code(ErrorCode::SerdeError)
    }
}

impl From<CborError> for SerdeError {
    fn from(err: CborError) -> Self {
        Self::with_code(err.code)
    }
}

struct EncoderSerializer<'a> {
    enc: &'a mut Encoder,
}

impl<'a> EncoderSerializer<'a> {
    fn new(enc: &'a mut Encoder) -> Self {
        Self { enc }
    }
}

impl<'a> ser::Serializer for EncoderSerializer<'a> {
    type Ok = ();
    type Error = SerdeError;

    type SerializeSeq = SeqSerializer<'a>;
    type SerializeTuple = SeqSerializer<'a>;
    type SerializeTupleStruct = SeqSerializer<'a>;
    type SerializeTupleVariant = TupleVariantSerializer<'a>;
    type SerializeMap = MapSerializer<'a>;
    type SerializeStruct = StructSerializer<'a>;
    type SerializeStructVariant = StructVariantSerializer<'a>;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        self.enc.bool(v).map_err(SerdeError::from)
    }

    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        self.enc.int_i128(i128::from(v)).map_err(SerdeError::from)
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        self.enc.int_i128(i128::from(v)).map_err(SerdeError::from)
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        self.enc.int_i128(i128::from(v)).map_err(SerdeError::from)
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        self.enc.int_i128(i128::from(v)).map_err(SerdeError::from)
    }

    fn serialize_i128(self, v: i128) -> Result<Self::Ok, Self::Error> {
        self.enc.int_i128(v).map_err(SerdeError::from)
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.enc.int_u128(u128::from(v)).map_err(SerdeError::from)
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.enc.int_u128(u128::from(v)).map_err(SerdeError::from)
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.enc.int_u128(u128::from(v)).map_err(SerdeError::from)
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        self.enc.int_u128(u128::from(v)).map_err(SerdeError::from)
    }

    fn serialize_u128(self, v: u128) -> Result<Self::Ok, Self::Error> {
        self.enc.int_u128(v).map_err(SerdeError::from)
    }

    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        self.serialize_f64(f64::from(v))
    }

    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        let bits = F64Bits::try_from_f64(v).map_err(SerdeError::from)?;
        self.enc.float(bits).map_err(SerdeError::from)
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        let mut buf = [0u8; 4];
        let s = v.encode_utf8(&mut buf);
        self.enc.text(s).map_err(SerdeError::from)
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        self.enc.text(v).map_err(SerdeError::from)
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.enc.bytes(v).map_err(SerdeError::from)
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.enc.null().map_err(SerdeError::from)
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        self.enc.null().map_err(SerdeError::from)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.enc.null().map_err(SerdeError::from)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        let start = start_enum_map(self.enc, variant)?;
        let res = self.enc.null();
        if let Err(err) = res {
            self.enc.truncate(start);
            return Err(SerdeError::from(err));
        }
        Ok(())
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        let start = start_enum_map(self.enc, variant)?;
        if let Err(err) = value.serialize(EncoderSerializer::new(self.enc)) {
            self.enc.truncate(start);
            return Err(err);
        }
        Ok(())
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        let len = len.ok_or_else(|| SerdeError::with_code(ErrorCode::IndefiniteLengthForbidden))?;
        self.enc.array_header(len).map_err(SerdeError::from)?;
        Ok(SeqSerializer::new(self.enc, len))
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.enc.array_header(len).map_err(SerdeError::from)?;
        Ok(SeqSerializer::new(self.enc, len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.enc.array_header(len).map_err(SerdeError::from)?;
        Ok(SeqSerializer::new(self.enc, len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        let start = start_enum_map(self.enc, variant)?;
        if let Err(err) = self.enc.array_header(len) {
            self.enc.truncate(start);
            return Err(SerdeError::from(err));
        }
        Ok(TupleVariantSerializer::new(self.enc, len))
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        let len = len.ok_or_else(|| SerdeError::with_code(ErrorCode::IndefiniteLengthForbidden))?;
        self.enc.map_header(len).map_err(SerdeError::from)?;
        Ok(MapSerializer::new(self.enc, len))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        self.enc.map_header(len).map_err(SerdeError::from)?;
        Ok(StructSerializer::new(self.enc, len))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        let start = start_enum_map(self.enc, variant)?;
        if let Err(err) = self.enc.map_header(len) {
            self.enc.truncate(start);
            return Err(SerdeError::from(err));
        }
        Ok(StructVariantSerializer::new(self.enc, len))
    }
}

fn start_enum_map(enc: &mut Encoder, variant: &str) -> Result<usize, SerdeError> {
    let start = enc.buf_len();
    if let Err(err) = enc.map_header(1) {
        enc.truncate(start);
        return Err(SerdeError::from(err));
    }
    if let Err(err) = enc.text(variant) {
        enc.truncate(start);
        return Err(SerdeError::from(err));
    }
    Ok(start)
}

struct SeqSerializer<'a> {
    enc: &'a mut Encoder,
    remaining: usize,
}

impl<'a> SeqSerializer<'a> {
    fn new(enc: &'a mut Encoder, remaining: usize) -> Self {
        Self { enc, remaining }
    }
}

impl SerializeSeq for SeqSerializer<'_> {
    type Ok = ();
    type Error = SerdeError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SerdeError> {
        if self.remaining == 0 {
            return Err(SerdeError::with_code(ErrorCode::ArrayLenMismatch));
        }
        value.serialize(EncoderSerializer::new(self.enc))?;
        self.remaining -= 1;
        Ok(())
    }

    fn end(self) -> Result<(), SerdeError> {
        if self.remaining != 0 {
            return Err(SerdeError::with_code(ErrorCode::ArrayLenMismatch));
        }
        Ok(())
    }
}

impl ser::SerializeTuple for SeqSerializer<'_> {
    type Ok = ();
    type Error = SerdeError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SerdeError> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<(), SerdeError> {
        SerializeSeq::end(self)
    }
}

impl ser::SerializeTupleStruct for SeqSerializer<'_> {
    type Ok = ();
    type Error = SerdeError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SerdeError> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<(), SerdeError> {
        SerializeSeq::end(self)
    }
}

struct TupleVariantSerializer<'a> {
    seq: SeqSerializer<'a>,
}

impl<'a> TupleVariantSerializer<'a> {
    fn new(enc: &'a mut Encoder, remaining: usize) -> Self {
        Self {
            seq: SeqSerializer::new(enc, remaining),
        }
    }
}

impl ser::SerializeTupleVariant for TupleVariantSerializer<'_> {
    type Ok = ();
    type Error = SerdeError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SerdeError> {
        self.seq.serialize_element(value)
    }

    fn end(self) -> Result<(), SerdeError> {
        self.seq.end()
    }
}

struct PendingKey {
    entry_start: usize,
    key_start: usize,
    key_end: usize,
}

struct MapSerializer<'a> {
    enc: &'a mut Encoder,
    remaining: usize,
    prev_key_range: Option<(usize, usize)>,
    pending: Option<PendingKey>,
}

impl<'a> MapSerializer<'a> {
    fn new(enc: &'a mut Encoder, remaining: usize) -> Self {
        Self {
            enc,
            remaining,
            prev_key_range: None,
            pending: None,
        }
    }

    fn write_pending_key<T: ?Sized + Serialize>(
        &mut self,
        key: &T,
    ) -> Result<PendingKey, SerdeError> {
        let entry_start = self.enc.buf_len();
        let (key_start, key_end) = key.serialize(MapKeySerializer::new(self.enc, entry_start))?;

        check_map_key_order(
            self.enc,
            self.prev_key_range,
            key_start,
            key_end,
            entry_start,
        )?;

        Ok(PendingKey {
            entry_start,
            key_start,
            key_end,
        })
    }
}

impl SerializeMap for MapSerializer<'_> {
    type Ok = ();
    type Error = SerdeError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), SerdeError> {
        if self.pending.is_some() {
            return Err(SerdeError::with_code(ErrorCode::SerdeError));
        }
        if self.remaining == 0 {
            return Err(SerdeError::with_code(ErrorCode::MapLenMismatch));
        }
        let pending = self.write_pending_key(key)?;
        self.pending = Some(pending);
        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SerdeError> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| SerdeError::with_code(ErrorCode::SerdeError))?;

        if let Err(err) = value.serialize(EncoderSerializer::new(self.enc)) {
            self.enc.truncate(pending.entry_start);
            return Err(err);
        }

        self.prev_key_range = Some((pending.key_start, pending.key_end));
        self.remaining -= 1;
        Ok(())
    }

    fn serialize_entry<K: ?Sized + Serialize, V: ?Sized + Serialize>(
        &mut self,
        key: &K,
        value: &V,
    ) -> Result<(), SerdeError> {
        if self.remaining == 0 {
            return Err(SerdeError::with_code(ErrorCode::MapLenMismatch));
        }
        let pending = self.write_pending_key(key)?;
        if let Err(err) = value.serialize(EncoderSerializer::new(self.enc)) {
            self.enc.truncate(pending.entry_start);
            return Err(err);
        }
        self.prev_key_range = Some((pending.key_start, pending.key_end));
        self.remaining -= 1;
        Ok(())
    }

    fn end(self) -> Result<(), SerdeError> {
        if self.pending.is_some() {
            return Err(SerdeError::with_code(ErrorCode::SerdeError));
        }
        if self.remaining != 0 {
            return Err(SerdeError::with_code(ErrorCode::MapLenMismatch));
        }
        Ok(())
    }
}

struct StructSerializer<'a> {
    enc: &'a mut Encoder,
    remaining: usize,
    prev_key_range: Option<(usize, usize)>,
}

impl<'a> StructSerializer<'a> {
    fn new(enc: &'a mut Encoder, remaining: usize) -> Self {
        Self {
            enc,
            remaining,
            prev_key_range: None,
        }
    }
}

impl ser::SerializeStruct for StructSerializer<'_> {
    type Ok = ();
    type Error = SerdeError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), SerdeError> {
        if self.remaining == 0 {
            return Err(SerdeError::with_code(ErrorCode::MapLenMismatch));
        }

        let entry_start = self.enc.buf_len();
        if let Err(err) = self.enc.text(key) {
            self.enc.truncate(entry_start);
            return Err(SerdeError::from(err));
        }
        let key_start = entry_start;
        let key_end = self.enc.buf_len();

        check_map_key_order(
            self.enc,
            self.prev_key_range,
            key_start,
            key_end,
            entry_start,
        )?;

        if let Err(err) = value.serialize(EncoderSerializer::new(self.enc)) {
            self.enc.truncate(entry_start);
            return Err(err);
        }

        self.prev_key_range = Some((key_start, key_end));
        self.remaining -= 1;
        Ok(())
    }

    fn end(self) -> Result<(), SerdeError> {
        if self.remaining != 0 {
            return Err(SerdeError::with_code(ErrorCode::MapLenMismatch));
        }
        Ok(())
    }
}

struct StructVariantSerializer<'a> {
    inner: StructSerializer<'a>,
}

impl<'a> StructVariantSerializer<'a> {
    fn new(enc: &'a mut Encoder, remaining: usize) -> Self {
        Self {
            inner: StructSerializer::new(enc, remaining),
        }
    }
}

impl ser::SerializeStructVariant for StructVariantSerializer<'_> {
    type Ok = ();
    type Error = SerdeError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), SerdeError> {
        self.inner.serialize_field(key, value)
    }

    fn end(self) -> Result<(), SerdeError> {
        self.inner.end()
    }
}

struct MapKeySerializer<'a> {
    enc: &'a mut Encoder,
    entry_start: usize,
}

impl<'a> MapKeySerializer<'a> {
    fn new(enc: &'a mut Encoder, entry_start: usize) -> Self {
        Self { enc, entry_start }
    }
}

impl ser::Serializer for MapKeySerializer<'_> {
    type Ok = (usize, usize);
    type Error = SerdeError;

    type SerializeSeq = ser::Impossible<(usize, usize), SerdeError>;
    type SerializeTuple = ser::Impossible<(usize, usize), SerdeError>;
    type SerializeTupleStruct = ser::Impossible<(usize, usize), SerdeError>;
    type SerializeTupleVariant = ser::Impossible<(usize, usize), SerdeError>;
    type SerializeMap = ser::Impossible<(usize, usize), SerdeError>;
    type SerializeStruct = ser::Impossible<(usize, usize), SerdeError>;
    type SerializeStructVariant = ser::Impossible<(usize, usize), SerdeError>;

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        let key_start = self.entry_start;
        if let Err(err) = self.enc.text(v) {
            self.enc.truncate(self.entry_start);
            return Err(SerdeError::from(err));
        }
        let key_end = self.enc.buf_len();
        Ok((key_start, key_end))
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        let mut buf = [0u8; 4];
        let s = v.encode_utf8(&mut buf);
        self.serialize_str(s)
    }

    fn serialize_bool(self, _v: bool) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_i8(self, _v: i8) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_i16(self, _v: i16) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_i32(self, _v: i32) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_i64(self, _v: i64) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_i128(self, _v: i128) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_u8(self, _v: u8) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_u16(self, _v: u16) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_u32(self, _v: u32) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_u64(self, _v: u64) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_u128(self, _v: u128) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_f32(self, _v: f32) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_f64(self, _v: f64) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_bytes(self, _v: &[u8]) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_some<T: ?Sized + Serialize>(self, _value: &T) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(SerdeError::with_code(ErrorCode::MapKeyMustBeText))
    }
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

#[inline]
const fn ser_err(off: usize) -> DeError {
    DeError::new(ErrorCode::SerdeError, off)
}

struct DirectDeserializer<'de> {
    input: &'de [u8],
    pos: usize,
    limits: DecodeLimits,
    items_seen: usize,
    depth: usize,
    mode: Mode,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Checked,
    CanonicalTrusted,
}

impl<'de> DirectDeserializer<'de> {
    const fn new_checked(input: &'de [u8], limits: DecodeLimits) -> Result<Self, CborError> {
        Self::new(input, limits, Mode::Checked)
    }

    const fn new_trusted(input: &'de [u8], limits: DecodeLimits) -> Result<Self, CborError> {
        Self::new(input, limits, Mode::CanonicalTrusted)
    }

    const fn new(input: &'de [u8], limits: DecodeLimits, mode: Mode) -> Result<Self, CborError> {
        if input.len() > limits.max_input_bytes {
            return Err(CborError::new(ErrorCode::MessageLenLimitExceeded, 0));
        }
        Ok(Self {
            input,
            pos: 0,
            limits,
            items_seen: 0,
            depth: 0,
            mode,
        })
    }

    #[inline]
    const fn offset(&self) -> usize {
        self.pos
    }

    fn peek_u8(&self) -> Result<u8, DeError> {
        let off = self.pos;
        self.input
            .get(self.pos)
            .copied()
            .ok_or_else(|| DeError::new(ErrorCode::UnexpectedEof, off))
    }

    fn read_u8(&mut self) -> Result<u8, DeError> {
        let off = self.pos;
        let b = *self
            .input
            .get(self.pos)
            .ok_or_else(|| DeError::new(ErrorCode::UnexpectedEof, off))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_exact(&mut self, n: usize) -> Result<&'de [u8], DeError> {
        let off = self.pos;
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| DeError::new(ErrorCode::LengthOverflow, off))?;
        if end > self.input.len() {
            return Err(DeError::new(ErrorCode::UnexpectedEof, off));
        }
        let out = &self.input[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn read_be_u16(&mut self) -> Result<u16, DeError> {
        let s = self.read_exact(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn read_be_u32(&mut self) -> Result<u32, DeError> {
        let s = self.read_exact(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_be_u64(&mut self) -> Result<u64, DeError> {
        let s = self.read_exact(8)?;
        Ok(u64::from_be_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn read_uint_arg_checked(&mut self, ai: u8, off: usize) -> Result<u64, DeError> {
        match ai {
            0..=23 => Ok(u64::from(ai)),
            24 => {
                let v = u64::from(self.read_u8()?);
                if v < 24 {
                    return Err(DeError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Ok(v)
            }
            25 => {
                let v = u64::from(self.read_be_u16()?);
                if u8::try_from(v).is_ok() {
                    return Err(DeError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Ok(v)
            }
            26 => {
                let v = u64::from(self.read_be_u32()?);
                if u16::try_from(v).is_ok() {
                    return Err(DeError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Ok(v)
            }
            27 => {
                let v = self.read_be_u64()?;
                if u32::try_from(v).is_ok() {
                    return Err(DeError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Ok(v)
            }
            _ => Err(DeError::new(ErrorCode::ReservedAdditionalInfo, off)),
        }
    }

    fn read_uint_arg_trusted(&mut self, ai: u8, off: usize) -> Result<u64, DeError> {
        match ai {
            0..=23 => Ok(u64::from(ai)),
            24 => Ok(u64::from(self.read_u8()?)),
            25 => Ok(u64::from(self.read_be_u16()?)),
            26 => Ok(u64::from(self.read_be_u32()?)),
            27 => Ok(self.read_be_u64()?),
            _ => Err(DeError::new(ErrorCode::ReservedAdditionalInfo, off)),
        }
    }

    fn read_uint_arg(&mut self, ai: u8, off: usize) -> Result<u64, DeError> {
        match self.mode {
            Mode::Checked => self.read_uint_arg_checked(ai, off),
            Mode::CanonicalTrusted => self.read_uint_arg_trusted(ai, off),
        }
    }

    fn read_len_checked(&mut self, ai: u8, off: usize) -> Result<usize, DeError> {
        if ai == 31 {
            return Err(DeError::new(ErrorCode::IndefiniteLengthForbidden, off));
        }
        let len = self.read_uint_arg_checked(ai, off)?;
        usize::try_from(len).map_err(|_| DeError::new(ErrorCode::LengthOverflow, off))
    }

    fn read_len_trusted(&mut self, ai: u8, off: usize) -> Result<usize, DeError> {
        if ai == 31 {
            return Err(DeError::new(ErrorCode::IndefiniteLengthForbidden, off));
        }
        let len = self.read_uint_arg_trusted(ai, off)?;
        usize::try_from(len).map_err(|_| DeError::new(ErrorCode::LengthOverflow, off))
    }

    fn read_len(&mut self, ai: u8, off: usize) -> Result<usize, DeError> {
        match self.mode {
            Mode::Checked => self.read_len_checked(ai, off),
            Mode::CanonicalTrusted => self.read_len_trusted(ai, off),
        }
    }

    const fn enforce_len(
        len: usize,
        max_len: usize,
        code: ErrorCode,
        off: usize,
    ) -> Result<(), DeError> {
        if len > max_len {
            return Err(DeError::new(code, off));
        }
        Ok(())
    }

    fn bump_items(&mut self, add: usize, off: usize) -> Result<(), DeError> {
        self.items_seen = self
            .items_seen
            .checked_add(add)
            .ok_or_else(|| DeError::new(ErrorCode::LengthOverflow, off))?;
        if self.items_seen > self.limits.max_total_items {
            return Err(DeError::new(ErrorCode::TotalItemsLimitExceeded, off));
        }
        Ok(())
    }

    const fn ensure_depth(&self, next_depth: usize, off: usize) -> Result<(), DeError> {
        if next_depth > self.limits.max_depth {
            return Err(DeError::new(ErrorCode::DepthLimitExceeded, off));
        }
        Ok(())
    }

    fn parse_text_from_header(&mut self, off: usize, ai: u8) -> Result<&'de str, DeError> {
        let len = self.read_len(ai, off)?;
        Self::enforce_len(
            len,
            self.limits.max_text_len,
            ErrorCode::TextLenLimitExceeded,
            off,
        )?;
        let bytes = self.read_exact(len)?;
        let s =
            core::str::from_utf8(bytes).map_err(|_| DeError::new(ErrorCode::Utf8Invalid, off))?;
        Ok(s)
    }

    fn parse_bytes_from_header(&mut self, off: usize, ai: u8) -> Result<&'de [u8], DeError> {
        let len = self.read_len(ai, off)?;
        Self::enforce_len(
            len,
            self.limits.max_bytes_len,
            ErrorCode::BytesLenLimitExceeded,
            off,
        )?;
        self.read_exact(len)
    }

    fn parse_text_key(
        &mut self,
        prev_key_range: &mut Option<(usize, usize)>,
    ) -> Result<&'de str, DeError> {
        let key_start = self.pos;
        let ib = self.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if major != 3 {
            return Err(DeError::new(ErrorCode::MapKeyMustBeText, key_start));
        }
        let s = self.parse_text_from_header(key_start, ai)?;
        let key_end = self.pos;
        if self.mode == Mode::Checked {
            if let Some((ps, pe)) = *prev_key_range {
                let prev = &self.input[ps..pe];
                let curr = &self.input[key_start..key_end];
                if prev == curr {
                    return Err(DeError::new(ErrorCode::DuplicateMapKey, key_start));
                }
                if !is_strictly_increasing_encoded(prev, curr) {
                    return Err(DeError::new(ErrorCode::NonCanonicalMapOrder, key_start));
                }
            }
            *prev_key_range = Some((key_start, key_end));
        }
        Ok(s)
    }

    fn parse_bignum(&mut self, off: usize, ai: u8) -> Result<(bool, &'de [u8]), DeError> {
        let tag = self.read_uint_arg(ai, off)?;
        let negative = match tag {
            2 => false,
            3 => true,
            _ => return Err(DeError::new(ErrorCode::ForbiddenOrMalformedTag, off)),
        };
        let m_off = self.pos;
        let first = self.read_u8()?;
        let m_major = first >> 5;
        let m_ai = first & 0x1f;
        if m_major != 2 {
            return Err(DeError::new(ErrorCode::ForbiddenOrMalformedTag, m_off));
        }
        let m_len = self.read_len(m_ai, m_off)?;
        Self::enforce_len(
            m_len,
            self.limits.max_bytes_len,
            ErrorCode::BytesLenLimitExceeded,
            m_off,
        )?;
        let mag = self.read_exact(m_len)?;
        if self.mode == Mode::Checked {
            validate_bignum_bytes(negative, mag).map_err(|code| DeError::new(code, m_off))?;
        }
        Ok((negative, mag))
    }

    fn parse_i128(&mut self) -> Result<i128, DeError> {
        let off = self.pos;
        let ib = self.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        match major {
            0 => {
                let v = self.read_uint_arg(ai, off)?;
                if self.mode == Mode::Checked && v > MAX_SAFE_INTEGER {
                    return Err(DeError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                Ok(i128::from(v))
            }
            1 => {
                let n = self.read_uint_arg(ai, off)?;
                if self.mode == Mode::Checked && n >= MAX_SAFE_INTEGER {
                    return Err(DeError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                Ok(-1 - i128::from(n))
            }
            6 => {
                let (negative, mag) = self.parse_bignum(off, ai)?;
                bigint_to_i128(negative, mag).ok_or_else(|| ser_err(off))
            }
            _ => Err(DeError::new(ErrorCode::ExpectedInteger, off)),
        }
    }

    fn parse_u128(&mut self) -> Result<u128, DeError> {
        let off = self.pos;
        let ib = self.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        match major {
            0 => {
                let v = self.read_uint_arg(ai, off)?;
                if self.mode == Mode::Checked && v > MAX_SAFE_INTEGER {
                    return Err(DeError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                Ok(u128::from(v))
            }
            1 => Err(ser_err(off)),
            6 => {
                let (negative, mag) = self.parse_bignum(off, ai)?;
                if negative {
                    return Err(ser_err(off));
                }
                bigint_to_u128(false, mag).ok_or_else(|| ser_err(off))
            }
            _ => Err(DeError::new(ErrorCode::ExpectedInteger, off)),
        }
    }

    fn parse_i64(&mut self) -> Result<i64, DeError> {
        let off = self.pos;
        let n = self.parse_i128()?;
        i64::try_from(n).map_err(|_| ser_err(off))
    }

    fn parse_u64(&mut self) -> Result<u64, DeError> {
        let off = self.pos;
        let n = self.parse_u128()?;
        u64::try_from(n).map_err(|_| ser_err(off))
    }

    fn parse_float64(&mut self) -> Result<f64, DeError> {
        let off = self.pos;
        let ib = self.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if major != 7 {
            return Err(DeError::new(ErrorCode::ExpectedFloat, off));
        }
        match ai {
            27 => {
                let bits = self.read_be_u64()?;
                validate_f64_bits(bits).map_err(|code| DeError::new(code, off))?;
                Ok(f64::from_bits(bits))
            }
            20..=22 => Err(DeError::new(ErrorCode::ExpectedFloat, off)),
            24 => {
                let simple = self.read_u8()?;
                if simple < 24 {
                    return Err(DeError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Err(DeError::new(ErrorCode::UnsupportedSimpleValue, off))
            }
            28..=30 => Err(DeError::new(ErrorCode::ReservedAdditionalInfo, off)),
            _ => Err(DeError::new(ErrorCode::UnsupportedSimpleValue, off)),
        }
    }

    fn consume_null(&mut self) -> Result<bool, DeError> {
        let off = self.pos;
        let ib = self.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if major != 7 {
            return Err(ser_err(off));
        }
        match ai {
            22 => Ok(true),
            24 => {
                let simple = self.read_u8()?;
                if simple < 24 {
                    return Err(DeError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Err(DeError::new(ErrorCode::UnsupportedSimpleValue, off))
            }
            28..=30 => Err(DeError::new(ErrorCode::ReservedAdditionalInfo, off)),
            20 | 21 => Err(ser_err(off)),
            _ => Err(DeError::new(ErrorCode::UnsupportedSimpleValue, off)),
        }
    }

    fn enter_array(&mut self, len: usize, off: usize) -> Result<bool, DeError> {
        Self::enforce_len(
            len,
            self.limits.max_array_len,
            ErrorCode::ArrayLenLimitExceeded,
            off,
        )?;
        self.bump_items(len, off)?;
        self.ensure_depth(self.depth + 1, off)?;
        if len > 0 {
            self.depth += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn enter_map(&mut self, len: usize, off: usize) -> Result<bool, DeError> {
        Self::enforce_len(
            len,
            self.limits.max_map_len,
            ErrorCode::MapLenLimitExceeded,
            off,
        )?;
        let items = len
            .checked_mul(2)
            .ok_or_else(|| DeError::new(ErrorCode::LengthOverflow, off))?;
        self.bump_items(items, off)?;
        self.ensure_depth(self.depth + 1, off)?;
        if len > 0 {
            self.depth += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn exit_container(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

struct DirectSeqAccess<'a, 'de> {
    de: &'a mut DirectDeserializer<'de>,
    remaining: usize,
    depth_entered: bool,
}

impl<'a, 'de> DirectSeqAccess<'a, 'de> {
    fn new(de: &'a mut DirectDeserializer<'de>, remaining: usize, depth_entered: bool) -> Self {
        Self {
            de,
            remaining,
            depth_entered,
        }
    }
}

impl<'de> SeqAccess<'de> for DirectSeqAccess<'_, 'de> {
    type Error = DeError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, DeError>
    where
        T: DeserializeSeed<'de>,
    {
        if self.remaining == 0 {
            if self.depth_entered {
                self.de.exit_container();
            }
            return Ok(None);
        }
        let value = seed.deserialize(&mut *self.de)?;
        self.remaining = self.remaining.saturating_sub(1);
        if self.remaining == 0 && self.depth_entered {
            self.de.exit_container();
        }
        Ok(Some(value))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}

struct DirectMapAccess<'a, 'de> {
    de: &'a mut DirectDeserializer<'de>,
    remaining_pairs: usize,
    depth_entered: bool,
    pending_key: bool,
    prev_key_range: Option<(usize, usize)>,
}

impl<'a, 'de> DirectMapAccess<'a, 'de> {
    fn new(
        de: &'a mut DirectDeserializer<'de>,
        remaining_pairs: usize,
        depth_entered: bool,
    ) -> Self {
        Self {
            de,
            remaining_pairs,
            depth_entered,
            pending_key: false,
            prev_key_range: None,
        }
    }
}

impl<'de> MapAccess<'de> for DirectMapAccess<'_, 'de> {
    type Error = DeError;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, DeError>
    where
        K: DeserializeSeed<'de>,
    {
        if self.pending_key {
            return Err(ser_err(self.de.offset()));
        }
        if self.remaining_pairs == 0 {
            if self.depth_entered {
                self.de.exit_container();
            }
            return Ok(None);
        }

        let key = self.de.parse_text_key(&mut self.prev_key_range)?;
        self.pending_key = true;
        let val =
            seed.deserialize(<&'de str as IntoDeserializer<'de, DeError>>::into_deserializer(key))?;
        Ok(Some(val))
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, DeError>
    where
        V: DeserializeSeed<'de>,
    {
        if !self.pending_key {
            return Err(ser_err(self.de.offset()));
        }
        let value = seed.deserialize(&mut *self.de)?;
        self.pending_key = false;
        self.remaining_pairs = self.remaining_pairs.saturating_sub(1);
        if self.remaining_pairs == 0 && self.depth_entered {
            self.de.exit_container();
        }
        Ok(value)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining_pairs)
    }
}

struct DirectEnumAccess<'a, 'de> {
    de: &'a mut DirectDeserializer<'de>,
    variant: &'de str,
    has_value: bool,
    off: usize,
}

impl<'a, 'de> EnumAccess<'de> for DirectEnumAccess<'a, 'de> {
    type Error = DeError;
    type Variant = DirectVariantAccess<'a, 'de>;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), DeError>
    where
        V: DeserializeSeed<'de>,
    {
        let v = seed.deserialize(
            <&'de str as IntoDeserializer<'de, DeError>>::into_deserializer(self.variant),
        )?;
        Ok((
            v,
            DirectVariantAccess {
                de: self.de,
                has_value: self.has_value,
                off: self.off,
            },
        ))
    }
}

struct DirectVariantAccess<'a, 'de> {
    de: &'a mut DirectDeserializer<'de>,
    has_value: bool,
    off: usize,
}

impl<'de> VariantAccess<'de> for DirectVariantAccess<'_, 'de> {
    type Error = DeError;

    fn unit_variant(self) -> Result<(), DeError> {
        if !self.has_value {
            return Ok(());
        }
        let is_null = self.de.consume_null()?;
        if is_null {
            self.de.exit_container();
            Ok(())
        } else {
            Err(ser_err(self.off))
        }
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, DeError>
    where
        T: DeserializeSeed<'de>,
    {
        if !self.has_value {
            return Err(ser_err(self.off));
        }
        let value = seed.deserialize(&mut *self.de)?;
        self.de.exit_container();
        Ok(value)
    }

    fn tuple_variant<V>(self, _len: usize, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        if !self.has_value {
            return Err(ser_err(self.off));
        }
        let value = de::Deserializer::deserialize_seq(&mut *self.de, visitor)?;
        self.de.exit_container();
        Ok(value)
    }

    fn struct_variant<V>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        if !self.has_value {
            return Err(ser_err(self.off));
        }
        let value = de::Deserializer::deserialize_map(&mut *self.de, visitor)?;
        self.de.exit_container();
        Ok(value)
    }
}

impl<'de> de::Deserializer<'de> for &mut DirectDeserializer<'de> {
    type Error = DeError;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.pos;
        let ib = self.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        match major {
            0 => {
                let v = self.read_uint_arg_checked(ai, off)?;
                if v > MAX_SAFE_INTEGER {
                    return Err(DeError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                visitor.visit_u64(v)
            }
            1 => {
                let n = self.read_uint_arg_checked(ai, off)?;
                if n >= MAX_SAFE_INTEGER {
                    return Err(DeError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                let v = -1 - i128::from(n);
                let out = i64::try_from(v).map_err(|_| ser_err(off))?;
                visitor.visit_i64(out)
            }
            2 => {
                let bytes = self.parse_bytes_from_header(off, ai)?;
                visitor.visit_borrowed_bytes(bytes)
            }
            3 => {
                let s = self.parse_text_from_header(off, ai)?;
                visitor.visit_borrowed_str(s)
            }
            4 => {
                let len = self.read_len_checked(ai, off)?;
                let depth_entered = self.enter_array(len, off)?;
                visitor.visit_seq(DirectSeqAccess::new(self, len, depth_entered))
            }
            5 => {
                let len = self.read_len_checked(ai, off)?;
                let depth_entered = self.enter_map(len, off)?;
                visitor.visit_map(DirectMapAccess::new(self, len, depth_entered))
            }
            6 => {
                let (negative, mag) = self.parse_bignum(off, ai)?;
                if negative {
                    let n = bigint_to_i128(true, mag).ok_or_else(|| ser_err(off))?;
                    visitor.visit_i128(n)
                } else {
                    let n = bigint_to_u128(false, mag).ok_or_else(|| ser_err(off))?;
                    visitor.visit_u128(n)
                }
            }
            7 => match ai {
                20 => visitor.visit_bool(false),
                21 => visitor.visit_bool(true),
                22 => visitor.visit_unit(),
                27 => {
                    let bits = self.read_be_u64()?;
                    validate_f64_bits(bits).map_err(|code| DeError::new(code, off))?;
                    visitor.visit_f64(f64::from_bits(bits))
                }
                24 => {
                    let simple = self.read_u8()?;
                    if simple < 24 {
                        return Err(DeError::new(ErrorCode::NonCanonicalEncoding, off));
                    }
                    Err(DeError::new(ErrorCode::UnsupportedSimpleValue, off))
                }
                28..=30 => Err(DeError::new(ErrorCode::ReservedAdditionalInfo, off)),
                _ => Err(DeError::new(ErrorCode::UnsupportedSimpleValue, off)),
            },
            _ => Err(DeError::new(ErrorCode::MalformedCanonical, off)),
        }
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.pos;
        let ib = self.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if major != 7 {
            return Err(DeError::new(ErrorCode::ExpectedBool, off));
        }
        match ai {
            20 => visitor.visit_bool(false),
            21 => visitor.visit_bool(true),
            22 | 27 => Err(DeError::new(ErrorCode::ExpectedBool, off)),
            24 => {
                let simple = self.read_u8()?;
                if simple < 24 {
                    return Err(DeError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Err(DeError::new(ErrorCode::UnsupportedSimpleValue, off))
            }
            28..=30 => Err(DeError::new(ErrorCode::ReservedAdditionalInfo, off)),
            _ => Err(DeError::new(ErrorCode::UnsupportedSimpleValue, off)),
        }
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.pos;
        let n = self.parse_i128()?;
        let out = i8::try_from(n).map_err(|_| ser_err(off))?;
        visitor.visit_i8(out)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.pos;
        let n = self.parse_i128()?;
        let out = i16::try_from(n).map_err(|_| ser_err(off))?;
        visitor.visit_i16(out)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.pos;
        let n = self.parse_i128()?;
        let out = i32::try_from(n).map_err(|_| ser_err(off))?;
        visitor.visit_i32(out)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i64(self.parse_i64()?)
    }

    fn deserialize_i128<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i128(self.parse_i128()?)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.pos;
        let n = self.parse_u128()?;
        let out = u8::try_from(n).map_err(|_| ser_err(off))?;
        visitor.visit_u8(out)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.pos;
        let n = self.parse_u128()?;
        let out = u16::try_from(n).map_err(|_| ser_err(off))?;
        visitor.visit_u16(out)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.pos;
        let n = self.parse_u128()?;
        let out = u32::try_from(n).map_err(|_| ser_err(off))?;
        visitor.visit_u32(out)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u64(self.parse_u64()?)
    }

    fn deserialize_u128<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u128(self.parse_u128()?)
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.pos;
        let v = self.parse_float64()?;
        if v.is_nan() {
            return visitor.visit_f32(f32::NAN);
        }
        if v.is_infinite() {
            return visitor.visit_f32(if v.is_sign_negative() {
                f32::NEG_INFINITY
            } else {
                f32::INFINITY
            });
        }
        if v > f64::from(f32::MAX) || v < f64::from(f32::MIN) {
            return Err(ser_err(off));
        }
        #[allow(clippy::cast_possible_truncation)]
        {
            visitor.visit_f32(v as f32)
        }
    }

    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        visitor.visit_f64(self.parse_float64()?)
    }

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.pos;
        let ib = self.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if major != 3 {
            return Err(DeError::new(ErrorCode::ExpectedText, off));
        }
        let s = self.parse_text_from_header(off, ai)?;
        let mut it = s.chars();
        match (it.next(), it.next()) {
            (Some(c), None) => visitor.visit_char(c),
            _ => Err(ser_err(off)),
        }
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.pos;
        let ib = self.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if major != 3 {
            return Err(DeError::new(ErrorCode::ExpectedText, off));
        }
        let s = self.parse_text_from_header(off, ai)?;
        visitor.visit_borrowed_str(s)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.pos;
        let ib = self.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if major != 2 {
            return Err(DeError::new(ErrorCode::ExpectedBytes, off));
        }
        let bytes = self.parse_bytes_from_header(off, ai)?;
        visitor.visit_borrowed_bytes(bytes)
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        if self.peek_u8()? == 0xf6 {
            self.read_u8()?;
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.pos;
        let ib = self.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if major != 7 {
            return Err(ser_err(off));
        }
        match ai {
            22 => visitor.visit_unit(),
            20 | 21 | 27 => Err(ser_err(off)),
            24 => {
                let simple = self.read_u8()?;
                if simple < 24 {
                    return Err(DeError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Err(DeError::new(ErrorCode::UnsupportedSimpleValue, off))
            }
            28..=30 => Err(DeError::new(ErrorCode::ReservedAdditionalInfo, off)),
            _ => Err(DeError::new(ErrorCode::UnsupportedSimpleValue, off)),
        }
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
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.pos;
        let ib = self.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if major != 4 {
            return Err(DeError::new(ErrorCode::ExpectedArray, off));
        }
        let len = self.read_len_checked(ai, off)?;
        let depth_entered = self.enter_array(len, off)?;
        visitor.visit_seq(DirectSeqAccess::new(self, len, depth_entered))
    }

    fn deserialize_tuple<V>(self, _len: usize, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let off = self.pos;
        let ib = self.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if major != 5 {
            return Err(DeError::new(ErrorCode::ExpectedMap, off));
        }
        let len = self.read_len_checked(ai, off)?;
        let depth_entered = self.enter_map(len, off)?;
        visitor.visit_map(DirectMapAccess::new(self, len, depth_entered))
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
        let off = self.pos;
        let ib = self.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        match major {
            3 => {
                let variant = self.parse_text_from_header(off, ai)?;
                visitor.visit_enum(DirectEnumAccess {
                    de: self,
                    variant,
                    has_value: false,
                    off,
                })
            }
            5 => {
                let len = self.read_len_checked(ai, off)?;
                if len != 1 {
                    return Err(ser_err(off));
                }
                let depth_entered = self.enter_map(len, off)?;
                if !depth_entered {
                    return Err(ser_err(off));
                }
                let mut prev_key_range = None;
                let variant = self.parse_text_key(&mut prev_key_range)?;
                visitor.visit_enum(DirectEnumAccess {
                    de: self,
                    variant,
                    has_value: true,
                    off,
                })
            }
            _ => Err(ser_err(off)),
        }
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
        let _ = serde::de::IgnoredAny::deserialize(self)?;
        visitor.visit_unit()
    }
}

/// Deserialize `T` with zero-copy borrows, validating during parsing.
///
/// # Errors
///
/// Returns an error if validation fails or if deserialization fails.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub fn from_slice_borrowed<'de, T>(bytes: &'de [u8], limits: DecodeLimits) -> Result<T, CborError>
where
    T: Deserialize<'de>,
{
    let mut de = DirectDeserializer::new_checked(bytes, limits)?;
    let value = T::deserialize(&mut de).map_err(DeError::into_cbor_error)?;
    if de.offset() != bytes.len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, de.offset()));
    }
    Ok(value)
}

/// Deserialize `T` from validated canonical bytes without re-checking canonical encodings.
///
/// This assumes `canon` was produced by `validate_canonical`.
///
/// # Errors
///
/// Returns an error if deserialization fails or if trailing bytes are found.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub fn from_canonical_bytes_ref<'de, T>(canon: CborBytesRef<'de>) -> Result<T, CborError>
where
    T: Deserialize<'de>,
{
    let bytes = canon.as_bytes();
    let limits = DecodeLimits::for_bytes(bytes.len());
    let mut de = DirectDeserializer::new_trusted(bytes, limits)?;
    let value = T::deserialize(&mut de).map_err(DeError::into_cbor_error)?;
    if de.offset() != bytes.len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, de.offset()));
    }
    Ok(value)
}

/// Deserialize `T` from owned canonical bytes without re-checking canonical encodings.
///
/// This assumes `canon` was produced by `CborBytes::from_slice` or `CborBytes::from_vec`.
///
/// # Errors
///
/// Returns an error if deserialization fails or if trailing bytes are found.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub fn from_canonical_bytes<'de, T>(canon: &'de CborBytes) -> Result<T, CborError>
where
    T: Deserialize<'de>,
{
    from_canonical_bytes_ref(canon.as_ref())
}

fn int_to_value(v: i128) -> Result<CborValue, SerdeError> {
    let int = integer_from_i128(v).map_err(SerdeError::with_code)?;
    Ok(CborValue::integer(int))
}

fn uint_to_value(v: u128) -> Result<CborValue, SerdeError> {
    let int = integer_from_u128(v).map_err(SerdeError::with_code)?;
    Ok(CborValue::integer(int))
}

/// Serde helper module for `#[serde(with = "sacp_cbor::serde_value")]`.
pub mod serde_value {
    use super::CborValue;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize a `CborValue` using Serde's data model.
    ///
    /// # Errors
    ///
    /// Returns any serialization error from the underlying serializer.
    pub fn serialize<S: Serializer>(value: &CborValue, serializer: S) -> Result<S::Ok, S::Error> {
        value.serialize(serializer)
    }

    /// Deserialize a `CborValue` using Serde's data model.
    ///
    /// # Errors
    ///
    /// Returns any deserialization error from the underlying deserializer.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<CborValue, D::Error> {
        CborValue::deserialize(deserializer)
    }

    /// Serde helpers for `Option<CborValue>`.
    pub mod option {
        use super::CborValue;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        /// Serialize `Option<CborValue>` using Serde's data model.
        ///
        /// # Errors
        ///
        /// Returns any serialization error from the underlying serializer.
        pub fn serialize<S: Serializer>(
            value: &Option<CborValue>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            value.serialize(serializer)
        }

        /// Deserialize `Option<CborValue>` using Serde's data model.
        ///
        /// # Errors
        ///
        /// Returns any deserialization error from the underlying deserializer.
        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<CborValue>, D::Error> {
            Option::<CborValue>::deserialize(deserializer)
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_value_tests {
    use super::{from_slice, to_vec};
    use crate::{cbor, DecodeLimits};

    #[test]
    fn cbor_value_serde_roundtrip_via_bytes() {
        let big = 1u128 << 80;
        let v = cbor!({
            "a": 1,
            "b": [true, null, 1.5],
            "c": big,
            "d": b"bytes",
        })
        .unwrap();

        let bytes = to_vec(&v).unwrap();
        let decoded = from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
        assert_eq!(v, decoded);
    }
}
