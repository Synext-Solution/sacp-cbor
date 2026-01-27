use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use serde::de::{
    self, Deserialize, DeserializeSeed, EnumAccess, IntoDeserializer, MapAccess, SeqAccess,
    VariantAccess, Visitor,
};
use serde::ser::{self, SerializeMap, SerializeSeq, SerializeStruct};
use serde::{Deserialize as SerdeDeserialize, Serialize, Serializer};

use crate::encode::Encoder;
use crate::int::{integer_from_i128, integer_from_u128};
use crate::profile::is_strictly_increasing_encoded;
use crate::query::{CborIntegerRef, CborKind, CborValueRef};
use crate::scalar::F64Bits;
use crate::value::{CborMap, CborValue, ValueRepr};
use crate::{CborBytesRef, CborError, DecodeLimits, ErrorCode};

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
            None => Vec::new(),
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
            None => Vec::new(),
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
/// # Errors
///
/// Returns an error if bytes are invalid or if the decoded value doesn't match the target type.
pub fn from_slice<'de, T: Deserialize<'de>>(
    bytes: &'de [u8],
    limits: DecodeLimits,
) -> Result<T, CborError> {
    let canon = crate::validate_canonical(bytes, limits)?;
    from_value_ref(canon.root())
}

/// Deserialize a Rust value from a `CborValueRef`.
///
/// # Errors
///
/// Returns an error if the value doesn't match the target type.
pub fn from_value_ref<'de, T: Deserialize<'de>>(value: CborValueRef<'de>) -> Result<T, CborError> {
    let de = CborRefDeserializer::new(value);
    T::deserialize(de).map_err(DeError::into_cbor_error)
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
///
/// This is the `serde::Deserializer::Error` type used by [`CborRefDeserializer`].
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

/// Validate `bytes` as canonical under `limits`, then deserialize `T` with zero-copy borrows.
///
/// # Errors
///
/// Returns an error if validation fails or if deserialization fails.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub fn from_slice_borrowed<'de, T>(bytes: &'de [u8], limits: DecodeLimits) -> Result<T, CborError>
where
    T: Deserialize<'de>,
{
    let canon = crate::validate_canonical(bytes, limits)?;
    from_bytes_ref_borrowed(canon)
}

/// Deserialize from already-validated canonical bytes (fast path).
///
/// # Errors
///
/// Returns an error if deserialization fails.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub fn from_bytes_ref_borrowed<'de, T>(canon: CborBytesRef<'de>) -> Result<T, CborError>
where
    T: Deserialize<'de>,
{
    from_value_ref_borrowed(canon.root())
}

/// Deserialize directly from a validated [`CborValueRef`].
///
/// # Errors
///
/// Returns an error if deserialization fails.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub fn from_value_ref_borrowed<'de, T>(value: CborValueRef<'de>) -> Result<T, CborError>
where
    T: Deserialize<'de>,
{
    let de = CborRefDeserializer::new(value);
    T::deserialize(de).map_err(DeError::into_cbor_error)
}

/// A zero-copy `serde::Deserializer` for canonical CBOR, backed by [`CborValueRef<'de>`].
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[derive(Debug, Clone, Copy)]
pub struct CborRefDeserializer<'de> {
    v: CborValueRef<'de>,
}

impl<'de> CborRefDeserializer<'de> {
    #[inline]
    #[must_use]
    /// Construct a borrowed deserializer from a validated [`CborValueRef`].
    pub const fn new(v: CborValueRef<'de>) -> Self {
        Self { v }
    }

    #[inline]
    #[must_use]
    const fn off(&self) -> usize {
        self.v.offset()
    }
}

#[inline]
fn parse_i128(v: CborValueRef<'_>) -> Result<i128, DeError> {
    let off = v.offset();
    match v.integer().map_err(DeError::from)? {
        CborIntegerRef::Safe(i) => Ok(i128::from(i)),
        CborIntegerRef::Big(b) => bigint_to_i128(b.is_negative(), b.magnitude())
            .ok_or_else(|| DeError::new(ErrorCode::SerdeError, off)),
    }
}

#[inline]
fn parse_u128(v: CborValueRef<'_>) -> Result<u128, DeError> {
    let off = v.offset();
    match v.integer().map_err(DeError::from)? {
        CborIntegerRef::Safe(i) => {
            if i < 0 {
                return Err(DeError::new(ErrorCode::SerdeError, off));
            }
            u128::try_from(i).map_err(|_| DeError::new(ErrorCode::SerdeError, off))
        }
        CborIntegerRef::Big(b) => bigint_to_u128(b.is_negative(), b.magnitude())
            .ok_or_else(|| DeError::new(ErrorCode::SerdeError, off)),
    }
}

#[inline]
fn parse_u64(v: CborValueRef<'_>) -> Result<u64, DeError> {
    let n = parse_u128(v)?;
    u64::try_from(n).map_err(|_| DeError::new(ErrorCode::SerdeError, v.offset()))
}

#[inline]
fn parse_i64(v: CborValueRef<'_>) -> Result<i64, DeError> {
    let n = parse_i128(v)?;
    i64::try_from(n).map_err(|_| DeError::new(ErrorCode::SerdeError, v.offset()))
}

struct CborSeqAccess<'de, I> {
    iter: I,
    remaining: usize,
    _pd: PhantomData<&'de ()>,
}

impl<I> CborSeqAccess<'_, I> {
    const fn new(iter: I, remaining: usize) -> Self {
        Self {
            iter,
            remaining,
            _pd: PhantomData,
        }
    }
}

impl<'de, I> SeqAccess<'de> for CborSeqAccess<'de, I>
where
    I: Iterator<Item = Result<CborValueRef<'de>, CborError>>,
{
    type Error = DeError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, DeError>
    where
        T: DeserializeSeed<'de>,
    {
        match self.iter.next() {
            None => {
                self.remaining = 0;
                Ok(None)
            }
            Some(Err(e)) => Err(DeError::from(e)),
            Some(Ok(v)) => {
                self.remaining = self.remaining.saturating_sub(1);
                seed.deserialize(CborRefDeserializer::new(v)).map(Some)
            }
        }
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}

struct CborMapAccess<'de, I> {
    iter: I,
    remaining: usize,
    pending_value: Option<CborValueRef<'de>>,
    map_off: usize,
    _pd: PhantomData<&'de ()>,
}

impl<I> CborMapAccess<'_, I> {
    const fn new(iter: I, remaining: usize, map_off: usize) -> Self {
        Self {
            iter,
            remaining,
            pending_value: None,
            map_off,
            _pd: PhantomData,
        }
    }
}

impl<'de, I> MapAccess<'de> for CborMapAccess<'de, I>
where
    I: Iterator<Item = Result<(&'de str, CborValueRef<'de>), CborError>>,
{
    type Error = DeError;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, DeError>
    where
        K: DeserializeSeed<'de>,
    {
        let next = match self.iter.next() {
            None => {
                self.remaining = 0;
                return Ok(None);
            }
            Some(Err(e)) => return Err(DeError::from(e)),
            Some(Ok(kv)) => kv,
        };

        let (k, v) = next;
        self.pending_value = Some(v);
        self.remaining = self.remaining.saturating_sub(1);
        seed.deserialize(<&'de str as IntoDeserializer<'de, DeError>>::into_deserializer(k))
            .map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, DeError>
    where
        V: DeserializeSeed<'de>,
    {
        let v = self
            .pending_value
            .take()
            .ok_or_else(|| DeError::new(ErrorCode::SerdeError, self.map_off))?;
        seed.deserialize(CborRefDeserializer::new(v))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}

struct CborEnumAccess<'de> {
    variant: &'de str,
    value: Option<CborValueRef<'de>>,
    off: usize,
}

impl<'de> EnumAccess<'de> for CborEnumAccess<'de> {
    type Error = DeError;
    type Variant = CborVariantAccess<'de>;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), DeError>
    where
        V: DeserializeSeed<'de>,
    {
        let v = seed.deserialize(
            <&'de str as IntoDeserializer<'de, DeError>>::into_deserializer(self.variant),
        )?;
        Ok((
            v,
            CborVariantAccess {
                value: self.value,
                off: self.off,
            },
        ))
    }
}

struct CborVariantAccess<'de> {
    value: Option<CborValueRef<'de>>,
    off: usize,
}

impl<'de> VariantAccess<'de> for CborVariantAccess<'de> {
    type Error = DeError;

    fn unit_variant(self) -> Result<(), DeError> {
        match self.value {
            None => Ok(()),
            Some(v) if v.is_null() => Ok(()),
            Some(_) => Err(DeError::new(ErrorCode::SerdeError, self.off)),
        }
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, DeError>
    where
        T: DeserializeSeed<'de>,
    {
        let v = self
            .value
            .ok_or_else(|| DeError::new(ErrorCode::SerdeError, self.off))?;
        seed.deserialize(CborRefDeserializer::new(v))
    }

    fn tuple_variant<V>(self, _len: usize, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let v = self
            .value
            .ok_or_else(|| DeError::new(ErrorCode::SerdeError, self.off))?;
        let a = v.array().map_err(DeError::from)?;
        let len = a.len();
        visitor.visit_seq(CborSeqAccess::new(a.iter(), len))
    }

    fn struct_variant<V>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let v = self
            .value
            .ok_or_else(|| DeError::new(ErrorCode::SerdeError, self.off))?;
        let m = v.map().map_err(DeError::from)?;
        let len = m.len();
        visitor.visit_map(CborMapAccess::new(m.iter(), len, v.offset()))
    }
}

impl<'de> de::Deserializer<'de> for CborRefDeserializer<'de> {
    type Error = DeError;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let kind = self.v.kind().map_err(DeError::from)?;
        match kind {
            CborKind::Null => visitor.visit_unit(),
            CborKind::Bool => visitor.visit_bool(self.v.bool().map_err(DeError::from)?),
            CborKind::Text => visitor.visit_borrowed_str(self.v.text().map_err(DeError::from)?),
            CborKind::Bytes => visitor.visit_borrowed_bytes(self.v.bytes().map_err(DeError::from)?),
            CborKind::Float => visitor.visit_f64(self.v.float64().map_err(DeError::from)?),
            CborKind::Integer => match self.v.integer().map_err(DeError::from)? {
                CborIntegerRef::Safe(i) => {
                    if i >= 0 {
                        let n = u64::try_from(i).map_err(|_| ser_err(self.off()))?;
                        visitor.visit_u64(n)
                    } else {
                        visitor.visit_i64(i)
                    }
                }
                CborIntegerRef::Big(b) => {
                    let off = self.off();
                    if b.is_negative() {
                        let n = bigint_to_i128(true, b.magnitude()).ok_or_else(|| ser_err(off))?;
                        visitor.visit_i128(n)
                    } else {
                        let n = bigint_to_u128(false, b.magnitude()).ok_or_else(|| ser_err(off))?;
                        visitor.visit_u128(n)
                    }
                }
            },
            CborKind::Array => {
                let a = self.v.array().map_err(DeError::from)?;
                let len = a.len();
                visitor.visit_seq(CborSeqAccess::new(a.iter(), len))
            }
            CborKind::Map => {
                let m = self.v.map().map_err(DeError::from)?;
                let len = m.len();
                visitor.visit_map(CborMapAccess::new(m.iter(), len, self.off()))
            }
        }
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        visitor.visit_bool(self.v.bool().map_err(DeError::from)?)
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let n = parse_i128(self.v)?;
        let out = i8::try_from(n).map_err(|_| ser_err(self.off()))?;
        visitor.visit_i8(out)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let n = parse_i128(self.v)?;
        let out = i16::try_from(n).map_err(|_| ser_err(self.off()))?;
        visitor.visit_i16(out)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let n = parse_i128(self.v)?;
        let out = i32::try_from(n).map_err(|_| ser_err(self.off()))?;
        visitor.visit_i32(out)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i64(parse_i64(self.v)?)
    }

    fn deserialize_i128<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i128(parse_i128(self.v)?)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let n = parse_u128(self.v)?;
        let out = u8::try_from(n).map_err(|_| ser_err(self.off()))?;
        visitor.visit_u8(out)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let n = parse_u128(self.v)?;
        let out = u16::try_from(n).map_err(|_| ser_err(self.off()))?;
        visitor.visit_u16(out)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let n = parse_u128(self.v)?;
        let out = u32::try_from(n).map_err(|_| ser_err(self.off()))?;
        visitor.visit_u32(out)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u64(parse_u64(self.v)?)
    }

    fn deserialize_u128<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u128(parse_u128(self.v)?)
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let v = self.v.float64().map_err(DeError::from)?;
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
            return Err(ser_err(self.off()));
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
        visitor.visit_f64(self.v.float64().map_err(DeError::from)?)
    }

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let s = self.v.text().map_err(DeError::from)?;
        let mut it = s.chars();
        match (it.next(), it.next()) {
            (Some(c), None) => visitor.visit_char(c),
            _ => Err(ser_err(self.off())),
        }
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        visitor.visit_borrowed_str(self.v.text().map_err(DeError::from)?)
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
        visitor.visit_borrowed_bytes(self.v.bytes().map_err(DeError::from)?)
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
        if self.v.is_null() {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        if self.v.is_null() {
            visitor.visit_unit()
        } else {
            Err(ser_err(self.off()))
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
        let a = self.v.array().map_err(DeError::from)?;
        let len = a.len();
        visitor.visit_seq(CborSeqAccess::new(a.iter(), len))
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
        let m = self.v.map().map_err(DeError::from)?;
        let len = m.len();
        visitor.visit_map(CborMapAccess::new(m.iter(), len, self.off()))
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
        let off = self.off();
        match self.v.kind().map_err(DeError::from)? {
            CborKind::Text => {
                let variant = self.v.text().map_err(DeError::from)?;
                visitor.visit_enum(CborEnumAccess {
                    variant,
                    value: None,
                    off,
                })
            }
            CborKind::Map => {
                let m = self.v.map().map_err(DeError::from)?;
                if m.len() != 1 {
                    return Err(DeError::new(ErrorCode::SerdeError, off));
                }
                let (k, v) = m
                    .iter()
                    .next()
                    .ok_or_else(|| DeError::new(ErrorCode::MalformedCanonical, off))?
                    .map_err(DeError::from)?;
                visitor.visit_enum(CborEnumAccess {
                    variant: k,
                    value: Some(v),
                    off,
                })
            }
            _ => Err(DeError::new(ErrorCode::SerdeError, off)),
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
        visitor.visit_unit()
    }
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
