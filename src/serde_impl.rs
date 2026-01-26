use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::de::{DeserializeOwned, IntoDeserializer, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize, Serializer};

use crate::profile::{CANONICAL_NAN_BITS, NEGATIVE_ZERO_BITS};
use crate::scalar::F64Bits;
use crate::value::{BigInt, CborInteger, CborMap, CborValue, ValueRepr};
use crate::{CborError, DecodeLimits, ErrorCode};

impl Serialize for CborValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.repr() {
            ValueRepr::Null => serializer.serialize_unit(),
            ValueRepr::Bool(b) => serializer.serialize_bool(*b),
            ValueRepr::Integer(i) => {
                if let Some(v) = i.as_i64() {
                    serializer.serialize_i64(v)
                } else if let Some(b) = i.as_bigint() {
                    if let Some(v) = bigint_to_i128(b) {
                        serializer.serialize_i128(v)
                    } else if let Some(v) = bigint_to_u128(b) {
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

impl<'de> Deserialize<'de> for CborValue {
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

    fn visit_char<E>(self, v: char) -> Result<Self::Value, E> {
        let mut buf = [0u8; 4];
        let s = v.encode_utf8(&mut buf);
        Ok(CborValue::text(s))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
        Ok(CborValue::text(v))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
        Ok(CborValue::text(v))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> {
        Ok(CborValue::bytes(v.to_vec()))
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
        let mut items: Vec<CborValue> = Vec::new();
        while let Some(v) = seq.next_element::<CborValue>()? {
            items.push(v);
        }
        Ok(CborValue::array(items))
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: serde::de::MapAccess<'de>,
    {
        let mut entries: Vec<(Box<str>, CborValue)> = Vec::new();
        while let Some((k, v)) = map.next_entry::<Box<str>, CborValue>()? {
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
    let v = to_value(value)?;
    v.encode_canonical()
}

/// Deserialize a Rust value from canonical SACP-CBOR/1 bytes.
///
/// # Errors
///
/// Returns an error if bytes are invalid or if the decoded value doesn't match the target type.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8], limits: DecodeLimits) -> Result<T, CborError> {
    let v = crate::decode_value(bytes, limits)?;
    from_value_ref(&v)
}

/// Convert a Rust value into a `CborValue`.
///
/// # Errors
///
/// Returns an error if the value cannot be represented under SACP-CBOR/1 constraints.
pub fn to_value<T: Serialize>(value: &T) -> Result<CborValue, CborError> {
    value
        .serialize(CborSerializer)
        .map_err(|err| CborError::new(err.code, 0))
}

/// Deserialize a Rust value from a `CborValue`.
///
/// # Errors
///
/// Returns an error if the value doesn't match the target type.
pub fn from_value_ref<'de, T: Deserialize<'de>>(value: &'de CborValue) -> Result<T, CborError> {
    T::deserialize(CborDeserializer::new(value))
        .map_err(|_| CborError::new(ErrorCode::SerdeError, 0))
}

/// Deserialize a Rust value from a `CborValue`.
///
/// # Errors
///
/// Returns an error if the value doesn't match the target type.

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
        write!(f, "serde conversion error")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SerdeError {}

impl serde::ser::Error for SerdeError {
    fn custom<T: fmt::Display>(_msg: T) -> Self {
        Self::with_code(ErrorCode::SerdeError)
    }
}

impl serde::de::Error for SerdeError {
    fn custom<T: fmt::Display>(_msg: T) -> Self {
        Self::with_code(ErrorCode::SerdeError)
    }
}

struct CborSerializer;

impl Serializer for CborSerializer {
    type Ok = CborValue;
    type Error = SerdeError;

    type SerializeSeq = SeqSerializer;
    type SerializeTuple = SeqSerializer;
    type SerializeTupleStruct = SeqSerializer;
    type SerializeTupleVariant = TupleVariantSerializer;
    type SerializeMap = MapSerializer;
    type SerializeStruct = StructSerializer;
    type SerializeStructVariant = StructVariantSerializer;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        Ok(CborValue::bool(v))
    }

    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        int_to_value(i128::from(v))
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        int_to_value(i128::from(v))
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        int_to_value(i128::from(v))
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        int_to_value(i128::from(v))
    }

    fn serialize_i128(self, v: i128) -> Result<Self::Ok, Self::Error> {
        int_to_value(v)
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        uint_to_value(u128::from(v))
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        uint_to_value(u128::from(v))
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        uint_to_value(u128::from(v))
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        uint_to_value(u128::from(v))
    }

    fn serialize_u128(self, v: u128) -> Result<Self::Ok, Self::Error> {
        uint_to_value(v)
    }

    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        self.serialize_f64(f64::from(v))
    }

    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        let bits = v.to_bits();
        if bits == NEGATIVE_ZERO_BITS {
            return Err(SerdeError::with_code(ErrorCode::NegativeZeroForbidden));
        }
        if v.is_nan() {
            return Ok(CborValue::float(F64Bits::new_unchecked(CANONICAL_NAN_BITS)));
        }
        Ok(CborValue::float(F64Bits::new_unchecked(bits)))
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        let mut buf = [0u8; 4];
        let s = v.encode_utf8(&mut buf);
        Ok(CborValue::text(s))
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        Ok(CborValue::text(v))
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(CborValue::bytes(v.to_vec()))
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(CborValue::null())
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(CborValue::null())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(CborValue::null())
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        enum_map(variant, CborValue::null())
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
        let inner = value.serialize(Self)?;
        enum_map(variant, inner)
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(SeqSerializer::new(len))
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Ok(SeqSerializer::new(Some(len)))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Ok(SeqSerializer::new(Some(len)))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(TupleVariantSerializer::new(variant, Some(len)))
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(MapSerializer::new(len))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(StructSerializer::new(Some(len)))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(StructVariantSerializer::new(variant, Some(len)))
    }
}

struct SeqSerializer {
    items: Vec<CborValue>,
}

impl SeqSerializer {
    fn new(len: Option<usize>) -> Self {
        let items = len.map_or_else(Vec::new, Vec::with_capacity);
        Self { items }
    }
}

impl SerializeSeq for SeqSerializer {
    type Ok = CborValue;
    type Error = SerdeError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.items.push(value.serialize(CborSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(CborValue::array(self.items))
    }
}

impl serde::ser::SerializeTuple for SeqSerializer {
    type Ok = CborValue;
    type Error = SerdeError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeSeq::end(self)
    }
}

impl serde::ser::SerializeTupleStruct for SeqSerializer {
    type Ok = CborValue;
    type Error = SerdeError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeSeq::end(self)
    }
}

struct TupleVariantSerializer {
    variant: &'static str,
    items: Vec<CborValue>,
}

impl TupleVariantSerializer {
    fn new(variant: &'static str, len: Option<usize>) -> Self {
        let items = len.map_or_else(Vec::new, Vec::with_capacity);
        Self { variant, items }
    }
}

impl serde::ser::SerializeTupleVariant for TupleVariantSerializer {
    type Ok = CborValue;
    type Error = SerdeError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.items.push(value.serialize(CborSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        enum_map(self.variant, CborValue::array(self.items))
    }
}

struct MapSerializer {
    entries: Vec<(Box<str>, CborValue)>,
    next_key: Option<Box<str>>,
}

impl MapSerializer {
    fn new(len: Option<usize>) -> Self {
        let entries = len.map_or_else(Vec::new, Vec::with_capacity);
        Self {
            entries,
            next_key: None,
        }
    }
}

impl SerializeMap for MapSerializer {
    type Ok = CborValue;
    type Error = SerdeError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Self::Error> {
        let key = key.serialize(KeySerializer)?;
        self.next_key = Some(key);
        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        let key = self
            .next_key
            .take()
            .ok_or_else(|| SerdeError::with_code(ErrorCode::SerdeError))?;
        let val = value.serialize(CborSerializer)?;
        self.entries.push((key, val));
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        let map = CborMap::new(self.entries).map_err(|err| SerdeError::with_code(err.code))?;
        Ok(CborValue::map(map))
    }
}

impl serde::ser::SerializeStruct for StructSerializer {
    type Ok = CborValue;
    type Error = SerdeError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        let val = value.serialize(CborSerializer)?;
        self.entries.push((Box::from(key), val));
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        let map = CborMap::new(self.entries).map_err(|err| SerdeError::with_code(err.code))?;
        Ok(CborValue::map(map))
    }
}

struct StructSerializer {
    entries: Vec<(Box<str>, CborValue)>,
}

impl StructSerializer {
    fn new(len: Option<usize>) -> Self {
        let entries = len.map_or_else(Vec::new, Vec::with_capacity);
        Self { entries }
    }
}

struct StructVariantSerializer {
    variant: &'static str,
    entries: Vec<(Box<str>, CborValue)>,
}

impl StructVariantSerializer {
    fn new(variant: &'static str, len: Option<usize>) -> Self {
        let entries = len.map_or_else(Vec::new, Vec::with_capacity);
        Self { variant, entries }
    }
}

impl serde::ser::SerializeStructVariant for StructVariantSerializer {
    type Ok = CborValue;
    type Error = SerdeError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        let val = value.serialize(CborSerializer)?;
        self.entries.push((Box::from(key), val));
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        let map = CborMap::new(self.entries).map_err(|err| SerdeError::with_code(err.code))?;
        enum_map(self.variant, CborValue::map(map))
    }
}

struct KeySerializer;

impl Serializer for KeySerializer {
    type Ok = Box<str>;
    type Error = SerdeError;

    type SerializeSeq = Impossible<Box<str>, SerdeError>;
    type SerializeTuple = Impossible<Box<str>, SerdeError>;
    type SerializeTupleStruct = Impossible<Box<str>, SerdeError>;
    type SerializeTupleVariant = Impossible<Box<str>, SerdeError>;
    type SerializeMap = Impossible<Box<str>, SerdeError>;
    type SerializeStruct = Impossible<Box<str>, SerdeError>;
    type SerializeStructVariant = Impossible<Box<str>, SerdeError>;

    fn serialize_str(self, value: &str) -> Result<Self::Ok, Self::Error> {
        Ok(Box::from(value))
    }

    fn serialize_char(self, value: char) -> Result<Self::Ok, Self::Error> {
        let mut buf = [0u8; 4];
        let s = value.encode_utf8(&mut buf);
        Ok(Box::from(s))
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
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

struct CborDeserializer<'de> {
    value: &'de CborValue,
}

impl<'de> CborDeserializer<'de> {
    const fn new(value: &'de CborValue) -> Self {
        Self { value }
    }
}

impl<'de> serde::de::Deserializer<'de> for CborDeserializer<'de> {
    type Error = SerdeError;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value.repr() {
            ValueRepr::Null => visitor.visit_unit(),
            ValueRepr::Bool(b) => visitor.visit_bool(*b),
            ValueRepr::Integer(i) => {
                if let Some(v) = i.as_i64() {
                    visitor.visit_i64(v)
                } else if let Some(b) = i.as_bigint() {
                    visit_bignum_any(b, visitor)
                } else {
                    Err(SerdeError::with_code(ErrorCode::SerdeError))
                }
            }
            ValueRepr::Float(bits) => visitor.visit_f64(bits.to_f64()),
            ValueRepr::Bytes(b) => visitor.visit_borrowed_bytes(b),
            ValueRepr::Text(s) => visitor.visit_str(s),
            ValueRepr::Array(items) => visitor.visit_seq(SeqAccess { items, idx: 0 }),
            ValueRepr::Map(map) => visitor.visit_map(MapAccess::new(map.iter())),
        }
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value.repr() {
            ValueRepr::Bool(b) => visitor.visit_bool(*b),
            _ => Err(SerdeError::with_code(ErrorCode::SerdeError)),
        }
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let v = parse_i128(self.value)?;
        if v < i128::from(i8::MIN) || v > i128::from(i8::MAX) {
            return Err(SerdeError::with_code(ErrorCode::SerdeError));
        }
        let v = i8::try_from(v).map_err(|_| SerdeError::with_code(ErrorCode::SerdeError))?;
        visitor.visit_i8(v)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let v = parse_i128(self.value)?;
        if v < i128::from(i16::MIN) || v > i128::from(i16::MAX) {
            return Err(SerdeError::with_code(ErrorCode::SerdeError));
        }
        let v = i16::try_from(v).map_err(|_| SerdeError::with_code(ErrorCode::SerdeError))?;
        visitor.visit_i16(v)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let v = parse_i128(self.value)?;
        if v < i128::from(i32::MIN) || v > i128::from(i32::MAX) {
            return Err(SerdeError::with_code(ErrorCode::SerdeError));
        }
        let v = i32::try_from(v).map_err(|_| SerdeError::with_code(ErrorCode::SerdeError))?;
        visitor.visit_i32(v)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let v = parse_i128(self.value)?;
        if v < i128::from(i64::MIN) || v > i128::from(i64::MAX) {
            return Err(SerdeError::with_code(ErrorCode::SerdeError));
        }
        let v = i64::try_from(v).map_err(|_| SerdeError::with_code(ErrorCode::SerdeError))?;
        visitor.visit_i64(v)
    }

    fn deserialize_i128<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let v = parse_i128(self.value)?;
        visitor.visit_i128(v)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let v = parse_u128(self.value)?;
        if v > u128::from(u8::MAX) {
            return Err(SerdeError::with_code(ErrorCode::SerdeError));
        }
        let v = u8::try_from(v).map_err(|_| SerdeError::with_code(ErrorCode::SerdeError))?;
        visitor.visit_u8(v)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let v = parse_u128(self.value)?;
        if v > u128::from(u16::MAX) {
            return Err(SerdeError::with_code(ErrorCode::SerdeError));
        }
        let v = u16::try_from(v).map_err(|_| SerdeError::with_code(ErrorCode::SerdeError))?;
        visitor.visit_u16(v)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let v = parse_u128(self.value)?;
        if v > u128::from(u32::MAX) {
            return Err(SerdeError::with_code(ErrorCode::SerdeError));
        }
        let v = u32::try_from(v).map_err(|_| SerdeError::with_code(ErrorCode::SerdeError))?;
        visitor.visit_u32(v)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let v = parse_u128(self.value)?;
        if v > u128::from(u64::MAX) {
            return Err(SerdeError::with_code(ErrorCode::SerdeError));
        }
        let v = u64::try_from(v).map_err(|_| SerdeError::with_code(ErrorCode::SerdeError))?;
        visitor.visit_u64(v)
    }

    fn deserialize_u128<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let v = parse_u128(self.value)?;
        visitor.visit_u128(v)
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value.repr() {
            ValueRepr::Float(bits) => {
                let v = bits.to_f64();
                let v32 = f64_to_f32(v)?;
                visitor.visit_f32(v32)
            }
            _ => Err(SerdeError::with_code(ErrorCode::SerdeError)),
        }
    }

    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value.repr() {
            ValueRepr::Float(bits) => visitor.visit_f64(bits.to_f64()),
            _ => Err(SerdeError::with_code(ErrorCode::SerdeError)),
        }
    }

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value.repr() {
            ValueRepr::Text(s) => {
                let mut chars = s.chars();
                if let (Some(c), None) = (chars.next(), chars.next()) {
                    visitor.visit_char(c)
                } else {
                    Err(SerdeError::with_code(ErrorCode::SerdeError))
                }
            }
            _ => Err(SerdeError::with_code(ErrorCode::SerdeError)),
        }
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value.repr() {
            ValueRepr::Text(s) => visitor.visit_str(s),
            _ => Err(SerdeError::with_code(ErrorCode::SerdeError)),
        }
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value.repr() {
            ValueRepr::Text(s) => visitor.visit_string(String::from(s.as_ref())),
            _ => Err(SerdeError::with_code(ErrorCode::SerdeError)),
        }
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value.repr() {
            ValueRepr::Bytes(b) => visitor.visit_borrowed_bytes(b),
            _ => Err(SerdeError::with_code(ErrorCode::SerdeError)),
        }
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value.repr() {
            ValueRepr::Bytes(b) => visitor.visit_byte_buf(b.clone()),
            _ => Err(SerdeError::with_code(ErrorCode::SerdeError)),
        }
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value.repr() {
            ValueRepr::Null => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value.repr() {
            ValueRepr::Null => visitor.visit_unit(),
            _ => Err(SerdeError::with_code(ErrorCode::SerdeError)),
        }
    }

    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value.repr() {
            ValueRepr::Array(items) => visitor.visit_seq(SeqAccess { items, idx: 0 }),
            _ => Err(SerdeError::with_code(ErrorCode::SerdeError)),
        }
    }

    fn deserialize_tuple<V>(self, _len: usize, visitor: V) -> Result<V::Value, Self::Error>
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
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value.repr() {
            ValueRepr::Map(map) => visitor.visit_map(MapAccess::new(map.iter())),
            _ => Err(SerdeError::with_code(ErrorCode::SerdeError)),
        }
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
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
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value.repr() {
            ValueRepr::Text(variant) => visitor.visit_enum(EnumAccess::unit(variant)),
            ValueRepr::Map(map) => EnumAccess::from_map(map).and_then(|e| visitor.visit_enum(e)),
            _ => Err(SerdeError::with_code(ErrorCode::SerdeError)),
        }
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }
}

struct SeqAccess<'de> {
    items: &'de [CborValue],
    idx: usize,
}

impl<'de> serde::de::SeqAccess<'de> for SeqAccess<'de> {
    type Error = SerdeError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        if self.idx >= self.items.len() {
            return Ok(None);
        }
        let value = &self.items[self.idx];
        self.idx += 1;
        seed.deserialize(CborDeserializer::new(value)).map(Some)
    }
}

struct MapAccess<'de, I>
where
    I: Iterator<Item = (&'de str, &'de CborValue)>,
{
    iter: I,
    pending: Option<(&'de str, &'de CborValue)>,
}

impl<'de, I> MapAccess<'de, I>
where
    I: Iterator<Item = (&'de str, &'de CborValue)>,
{
    const fn new(iter: I) -> Self {
        Self {
            iter,
            pending: None,
        }
    }
}

impl<'de, I> serde::de::MapAccess<'de> for MapAccess<'de, I>
where
    I: Iterator<Item = (&'de str, &'de CborValue)>,
{
    type Error = SerdeError;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: serde::de::DeserializeSeed<'de>,
    {
        self.pending = self.iter.next();
        match self.pending {
            None => Ok(None),
            Some((key, _)) => seed.deserialize(key.into_deserializer()).map(Some),
        }
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        let (_, value) = self
            .pending
            .take()
            .ok_or_else(|| SerdeError::with_code(ErrorCode::SerdeError))?;
        seed.deserialize(CborDeserializer::new(value))
    }
}

struct EnumAccess<'de> {
    variant: &'de str,
    value: Option<&'de CborValue>,
}

impl<'de> EnumAccess<'de> {
    const fn unit(variant: &'de str) -> Self {
        Self {
            variant,
            value: None,
        }
    }

    fn from_map(map: &'de CborMap) -> Result<Self, SerdeError> {
        if map.len() != 1 {
            return Err(SerdeError::with_code(ErrorCode::SerdeError));
        }
        let (variant, value) = map
            .iter()
            .next()
            .ok_or_else(|| SerdeError::with_code(ErrorCode::SerdeError))?;
        Ok(Self {
            variant,
            value: Some(value),
        })
    }
}

impl<'de> serde::de::EnumAccess<'de> for EnumAccess<'de> {
    type Error = SerdeError;
    type Variant = VariantAccess<'de>;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), Self::Error>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        let val = seed.deserialize(self.variant.into_deserializer())?;
        Ok((val, VariantAccess { value: self.value }))
    }
}

struct VariantAccess<'de> {
    value: Option<&'de CborValue>,
}

impl<'de> serde::de::VariantAccess<'de> for VariantAccess<'de> {
    type Error = SerdeError;

    fn unit_variant(self) -> Result<(), Self::Error> {
        match self.value {
            None => Ok(()),
            Some(v) if v.is_null() => Ok(()),
            _ => Err(SerdeError::with_code(ErrorCode::SerdeError)),
        }
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Self::Error>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        let value = self
            .value
            .ok_or_else(|| SerdeError::with_code(ErrorCode::SerdeError))?;
        seed.deserialize(CborDeserializer::new(value))
    }

    fn tuple_variant<V>(self, _len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.value.and_then(|v| v.as_array()).map_or_else(
            || Err(SerdeError::with_code(ErrorCode::SerdeError)),
            |items| visitor.visit_seq(SeqAccess { items, idx: 0 }),
        )
    }

    fn struct_variant<V>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.value.and_then(|v| v.as_map()).map_or_else(
            || Err(SerdeError::with_code(ErrorCode::SerdeError)),
            |map| visitor.visit_map(MapAccess::new(map.iter())),
        )
    }
}

struct Impossible<Ok, Err> {
    _ok: core::marker::PhantomData<Ok>,
    _err: core::marker::PhantomData<Err>,
}

impl<Ok, Err> serde::ser::SerializeSeq for Impossible<Ok, Err>
where
    Err: serde::ser::Error,
{
    type Ok = Ok;
    type Error = Err;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, _value: &T) -> Result<(), Self::Error> {
        Err(serde::ser::Error::custom("invalid map key"))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("invalid map key"))
    }
}

impl<Ok, Err> serde::ser::SerializeTuple for Impossible<Ok, Err>
where
    Err: serde::ser::Error,
{
    type Ok = Ok;
    type Error = Err;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, _value: &T) -> Result<(), Self::Error> {
        Err(serde::ser::Error::custom("invalid map key"))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("invalid map key"))
    }
}

impl<Ok, Err> serde::ser::SerializeTupleStruct for Impossible<Ok, Err>
where
    Err: serde::ser::Error,
{
    type Ok = Ok;
    type Error = Err;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, _value: &T) -> Result<(), Self::Error> {
        Err(serde::ser::Error::custom("invalid map key"))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("invalid map key"))
    }
}

impl<Ok, Err> serde::ser::SerializeTupleVariant for Impossible<Ok, Err>
where
    Err: serde::ser::Error,
{
    type Ok = Ok;
    type Error = Err;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, _value: &T) -> Result<(), Self::Error> {
        Err(serde::ser::Error::custom("invalid map key"))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("invalid map key"))
    }
}

impl<Ok, Err> serde::ser::SerializeMap for Impossible<Ok, Err>
where
    Err: serde::ser::Error,
{
    type Ok = Ok;
    type Error = Err;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, _key: &T) -> Result<(), Self::Error> {
        Err(serde::ser::Error::custom("invalid map key"))
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, _value: &T) -> Result<(), Self::Error> {
        Err(serde::ser::Error::custom("invalid map key"))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("invalid map key"))
    }
}

impl<Ok, Err> serde::ser::SerializeStruct for Impossible<Ok, Err>
where
    Err: serde::ser::Error,
{
    type Ok = Ok;
    type Error = Err;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _key: &'static str,
        _value: &T,
    ) -> Result<(), Self::Error> {
        Err(serde::ser::Error::custom("invalid map key"))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("invalid map key"))
    }
}

impl<Ok, Err> serde::ser::SerializeStructVariant for Impossible<Ok, Err>
where
    Err: serde::ser::Error,
{
    type Ok = Ok;
    type Error = Err;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _key: &'static str,
        _value: &T,
    ) -> Result<(), Self::Error> {
        Err(serde::ser::Error::custom("invalid map key"))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("invalid map key"))
    }
}

fn enum_map(variant: &str, value: CborValue) -> Result<CborValue, SerdeError> {
    let map = CborMap::new(vec![(Box::from(variant), value)])
        .map_err(|err| SerdeError::with_code(err.code))?;
    Ok(CborValue::map(map))
}

fn int_to_value(v: i128) -> Result<CborValue, SerdeError> {
    let min = i128::from(crate::MIN_SAFE_INTEGER);
    let max = i128::from(crate::MAX_SAFE_INTEGER_I64);
    if v >= min && v <= max {
        let i = i64::try_from(v).map_err(|_| SerdeError::with_code(ErrorCode::SerdeError))?;
        return Ok(CborValue::integer(CborInteger::new_safe_unchecked(i)));
    }
    let negative = v < 0;
    let n = if negative {
        u128::try_from(-1 - v).map_err(|_| SerdeError::with_code(ErrorCode::SerdeError))?
    } else {
        u128::try_from(v).map_err(|_| SerdeError::with_code(ErrorCode::SerdeError))?
    };
    bignum_from_u128(negative, n)
}

fn uint_to_value(v: u128) -> Result<CborValue, SerdeError> {
    let max = u128::from(crate::MAX_SAFE_INTEGER);
    if v <= max {
        let i = i64::try_from(v).map_err(|_| SerdeError::with_code(ErrorCode::SerdeError))?;
        return Ok(CborValue::integer(CborInteger::new_safe_unchecked(i)));
    }
    bignum_from_u128(false, v)
}

fn bignum_from_u128(negative: bool, n: u128) -> Result<CborValue, SerdeError> {
    let magnitude = u128_to_be_bytes_nonzero(n)?;
    let bigint = BigInt::new(negative, magnitude).map_err(|err| SerdeError::with_code(err.code))?;
    Ok(CborValue::integer(CborInteger::from_bigint(bigint)))
}

fn u128_to_be_bytes_nonzero(n: u128) -> Result<Vec<u8>, SerdeError> {
    if n == 0 {
        return Err(SerdeError::with_code(ErrorCode::SerdeError));
    }
    let leading_bytes = (n.leading_zeros() / 8) as usize;
    let bytes = n.to_be_bytes();
    Ok(bytes[leading_bytes..].to_vec())
}

fn bigint_to_u128(big: &BigInt) -> Option<u128> {
    if big.is_negative() {
        return None;
    }
    magnitude_to_u128(big.magnitude())
}

fn bigint_to_i128(big: &BigInt) -> Option<i128> {
    let n = magnitude_to_u128(big.magnitude())?;
    if n > i128::MAX as u128 {
        return None;
    }
    let n_i = i128::try_from(n).ok()?;
    if big.is_negative() {
        Some(-1 - n_i)
    } else {
        Some(n_i)
    }
}

fn magnitude_to_u128(magnitude: &[u8]) -> Option<u128> {
    if magnitude.len() > 16 {
        return None;
    }
    let mut buf = [0u8; 16];
    let start = 16 - magnitude.len();
    buf[start..].copy_from_slice(magnitude);
    Some(u128::from_be_bytes(buf))
}

fn parse_i128(value: &CborValue) -> Result<i128, SerdeError> {
    match value.repr() {
        ValueRepr::Integer(i) => i.as_i64().map_or_else(
            || {
                i.as_bigint()
                    .and_then(bigint_to_i128)
                    .ok_or_else(|| SerdeError::with_code(ErrorCode::SerdeError))
            },
            |v| Ok(i128::from(v)),
        ),
        _ => Err(SerdeError::with_code(ErrorCode::SerdeError)),
    }
}

fn parse_u128(value: &CborValue) -> Result<u128, SerdeError> {
    match value.repr() {
        ValueRepr::Integer(i) => {
            if let Some(v) = i.as_i64() {
                if v < 0 {
                    return Err(SerdeError::with_code(ErrorCode::SerdeError));
                }
                u128::try_from(v).map_err(|_| SerdeError::with_code(ErrorCode::SerdeError))
            } else if let Some(b) = i.as_bigint() {
                bigint_to_u128(b).ok_or_else(|| SerdeError::with_code(ErrorCode::SerdeError))
            } else {
                Err(SerdeError::with_code(ErrorCode::SerdeError))
            }
        }
        _ => Err(SerdeError::with_code(ErrorCode::SerdeError)),
    }
}

fn visit_bignum_any<'de, V>(big: &BigInt, visitor: V) -> Result<V::Value, SerdeError>
where
    V: Visitor<'de>,
{
    if let Some(v) = bigint_to_i128(big) {
        return visitor.visit_i128(v);
    }
    if let Some(v) = bigint_to_u128(big) {
        return visitor.visit_u128(v);
    }
    Err(SerdeError::with_code(ErrorCode::SerdeError))
}

fn f64_to_f32(v: f64) -> Result<f32, SerdeError> {
    if v.is_nan() {
        return Ok(f32::NAN);
    }
    if v.is_infinite() {
        return Ok(if v.is_sign_negative() {
            f32::NEG_INFINITY
        } else {
            f32::INFINITY
        });
    }
    if v > f64::from(f32::MAX) || v < f64::from(f32::MIN) {
        return Err(SerdeError::with_code(ErrorCode::SerdeError));
    }
    #[allow(clippy::cast_possible_truncation)]
    {
        Ok(v as f32)
    }
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
    use super::{from_value_ref, to_value};
    use crate::{cbor, CborValue};

    #[test]
    fn cbor_value_serde_roundtrip_via_value() {
        let big = 1u128 << 80;
        let v = cbor!({
            "a": 1,
            "b": [true, null, 1.5],
            "c": big,
            "d": b"bytes",
        })
        .unwrap();

        let via = to_value(&v).unwrap();
        assert_eq!(v, via);

        let de: CborValue = from_value_ref(&v).unwrap();
        assert_eq!(v, de);
    }
}
