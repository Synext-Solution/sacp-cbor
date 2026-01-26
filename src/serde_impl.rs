use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::de::{DeserializeOwned, IntoDeserializer, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize, Serializer};

use crate::float::{CANONICAL_NAN_BITS, NEGATIVE_ZERO_BITS};
use crate::value::{BigInt, CborMap, CborValue, F64Bits};
use crate::{CborError, CborErrorCode, DecodeLimits};

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
        .map_err(|err| CborError::encode(err.code))
}

/// Deserialize a Rust value from a `CborValue`.
///
/// # Errors
///
/// Returns an error if the value doesn't match the target type.
pub fn from_value_ref<'de, T: Deserialize<'de>>(value: &'de CborValue) -> Result<T, CborError> {
    T::deserialize(CborDeserializer::new(value))
        .map_err(|_| CborError::encode(CborErrorCode::SerdeError))
}

/// Deserialize a Rust value from a `CborValue`.
///
/// # Errors
///
/// Returns an error if the value doesn't match the target type.

#[derive(Debug, Clone, Copy)]
struct SerdeError {
    code: CborErrorCode,
}

impl SerdeError {
    const fn with_code(code: CborErrorCode) -> Self {
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
        Self::with_code(CborErrorCode::SerdeError)
    }
}

impl serde::de::Error for SerdeError {
    fn custom<T: fmt::Display>(_msg: T) -> Self {
        Self::with_code(CborErrorCode::SerdeError)
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
        Ok(CborValue::Bool(v))
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
            return Err(SerdeError::with_code(CborErrorCode::NegativeZeroForbidden));
        }
        if v.is_nan() {
            return Ok(CborValue::Float(F64Bits::new_unchecked(CANONICAL_NAN_BITS)));
        }
        Ok(CborValue::Float(F64Bits::new_unchecked(bits)))
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        Ok(CborValue::Text(v.to_string()))
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        Ok(CborValue::Text(v.to_owned()))
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(CborValue::Bytes(v.to_vec()))
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(CborValue::Null)
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(CborValue::Null)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(CborValue::Null)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        enum_map(variant, CborValue::Null)
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
        Ok(CborValue::Array(self.items))
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
        enum_map(self.variant, CborValue::Array(self.items))
    }
}

struct MapSerializer {
    entries: Vec<(String, CborValue)>,
    next_key: Option<String>,
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
            .ok_or_else(|| SerdeError::with_code(CborErrorCode::SerdeError))?;
        let val = value.serialize(CborSerializer)?;
        self.entries.push((key, val));
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        let map = CborMap::new(self.entries).map_err(|err| SerdeError::with_code(err.code))?;
        Ok(CborValue::Map(map))
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
        self.entries.push((key.to_string(), val));
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        let map = CborMap::new(self.entries).map_err(|err| SerdeError::with_code(err.code))?;
        Ok(CborValue::Map(map))
    }
}

struct StructSerializer {
    entries: Vec<(String, CborValue)>,
}

impl StructSerializer {
    fn new(len: Option<usize>) -> Self {
        let entries = len.map_or_else(Vec::new, Vec::with_capacity);
        Self { entries }
    }
}

struct StructVariantSerializer {
    variant: &'static str,
    entries: Vec<(String, CborValue)>,
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
        self.entries.push((key.to_string(), val));
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        let map = CborMap::new(self.entries).map_err(|err| SerdeError::with_code(err.code))?;
        enum_map(self.variant, CborValue::Map(map))
    }
}

struct KeySerializer;

impl Serializer for KeySerializer {
    type Ok = String;
    type Error = SerdeError;

    type SerializeSeq = Impossible<String, SerdeError>;
    type SerializeTuple = Impossible<String, SerdeError>;
    type SerializeTupleStruct = Impossible<String, SerdeError>;
    type SerializeTupleVariant = Impossible<String, SerdeError>;
    type SerializeMap = Impossible<String, SerdeError>;
    type SerializeStruct = Impossible<String, SerdeError>;
    type SerializeStructVariant = Impossible<String, SerdeError>;

    fn serialize_str(self, value: &str) -> Result<Self::Ok, Self::Error> {
        Ok(value.to_owned())
    }

    fn serialize_char(self, value: char) -> Result<Self::Ok, Self::Error> {
        Ok(value.to_string())
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
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_i8(self, _v: i8) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_i16(self, _v: i16) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_i32(self, _v: i32) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_i64(self, _v: i64) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_i128(self, _v: i128) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_u8(self, _v: u8) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_u16(self, _v: u16) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_u32(self, _v: u32) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_u64(self, _v: u64) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_u128(self, _v: u128) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_f32(self, _v: f32) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_f64(self, _v: f64) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_bytes(self, _v: &[u8]) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(SerdeError::with_code(CborErrorCode::MapKeyMustBeText))
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
        match self.value {
            CborValue::Null => visitor.visit_unit(),
            CborValue::Bool(b) => visitor.visit_bool(*b),
            CborValue::Int(v) => visitor.visit_i64(*v),
            CborValue::Float(bits) => visitor.visit_f64(bits.to_f64()),
            CborValue::Bytes(b) => visitor.visit_bytes(b),
            CborValue::Text(s) => visitor.visit_str(s),
            CborValue::Array(items) => visitor.visit_seq(SeqAccess { items, idx: 0 }),
            CborValue::Map(map) => visitor.visit_map(MapAccess::new(map)),
            CborValue::Bignum(b) => visit_bignum_any(b, visitor),
        }
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            CborValue::Bool(b) => visitor.visit_bool(*b),
            _ => Err(SerdeError::with_code(CborErrorCode::SerdeError)),
        }
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        deserialize_i128(
            self.value,
            visitor,
            i128::from(i8::MIN),
            i128::from(i8::MAX),
        )
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        deserialize_i128(
            self.value,
            visitor,
            i128::from(i16::MIN),
            i128::from(i16::MAX),
        )
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        deserialize_i128(
            self.value,
            visitor,
            i128::from(i32::MIN),
            i128::from(i32::MAX),
        )
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        deserialize_i128(
            self.value,
            visitor,
            i128::from(i64::MIN),
            i128::from(i64::MAX),
        )
    }

    fn deserialize_i128<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let v = match self.value {
            CborValue::Int(v) => i128::from(*v),
            CborValue::Bignum(b) => {
                bigint_to_i128(b).ok_or_else(|| SerdeError::with_code(CborErrorCode::SerdeError))?
            }
            _ => return Err(SerdeError::with_code(CborErrorCode::SerdeError)),
        };
        visitor.visit_i128(v)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        deserialize_u128(self.value, visitor, u128::from(u8::MAX))
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        deserialize_u128(self.value, visitor, u128::from(u16::MAX))
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        deserialize_u128(self.value, visitor, u128::from(u32::MAX))
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        deserialize_u128(self.value, visitor, u128::from(u64::MAX))
    }

    fn deserialize_u128<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let v =
            match self.value {
                CborValue::Int(v) if *v >= 0 => u128::try_from(*v)
                    .map_err(|_| SerdeError::with_code(CborErrorCode::SerdeError))?,
                CborValue::Bignum(b) => bigint_to_u128(b)
                    .ok_or_else(|| SerdeError::with_code(CborErrorCode::SerdeError))?,
                _ => return Err(SerdeError::with_code(CborErrorCode::SerdeError)),
            };
        visitor.visit_u128(v)
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            CborValue::Float(bits) => {
                let v = bits.to_f64();
                let v32 = f64_to_f32(v)?;
                visitor.visit_f32(v32)
            }
            _ => Err(SerdeError::with_code(CborErrorCode::SerdeError)),
        }
    }

    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            CborValue::Float(bits) => visitor.visit_f64(bits.to_f64()),
            _ => Err(SerdeError::with_code(CborErrorCode::SerdeError)),
        }
    }

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            CborValue::Text(s) => {
                let mut chars = s.chars();
                if let (Some(c), None) = (chars.next(), chars.next()) {
                    visitor.visit_char(c)
                } else {
                    Err(SerdeError::with_code(CborErrorCode::SerdeError))
                }
            }
            _ => Err(SerdeError::with_code(CborErrorCode::SerdeError)),
        }
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            CborValue::Text(s) => visitor.visit_str(s),
            _ => Err(SerdeError::with_code(CborErrorCode::SerdeError)),
        }
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            CborValue::Text(s) => visitor.visit_string(s.clone()),
            _ => Err(SerdeError::with_code(CborErrorCode::SerdeError)),
        }
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            CborValue::Bytes(b) => visitor.visit_bytes(b),
            _ => Err(SerdeError::with_code(CborErrorCode::SerdeError)),
        }
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            CborValue::Bytes(b) => visitor.visit_byte_buf(b.clone()),
            _ => Err(SerdeError::with_code(CborErrorCode::SerdeError)),
        }
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            CborValue::Null => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            CborValue::Null => visitor.visit_unit(),
            _ => Err(SerdeError::with_code(CborErrorCode::SerdeError)),
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
        match self.value {
            CborValue::Array(items) => visitor.visit_seq(SeqAccess { items, idx: 0 }),
            _ => Err(SerdeError::with_code(CborErrorCode::SerdeError)),
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
        match self.value {
            CborValue::Map(map) => visitor.visit_map(MapAccess::new(map)),
            _ => Err(SerdeError::with_code(CborErrorCode::SerdeError)),
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
        match self.value {
            CborValue::Text(variant) => visitor.visit_enum(EnumAccess::unit(variant)),
            CborValue::Map(map) => EnumAccess::from_map(map).and_then(|e| visitor.visit_enum(e)),
            _ => Err(SerdeError::with_code(CborErrorCode::SerdeError)),
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

struct MapAccess<'de> {
    entries: Vec<(&'de str, &'de CborValue)>,
    idx: usize,
}

impl<'de> MapAccess<'de> {
    fn new(map: &'de CborMap) -> Self {
        let entries = map.iter().collect::<Vec<_>>();
        Self { entries, idx: 0 }
    }
}

impl<'de> serde::de::MapAccess<'de> for MapAccess<'de> {
    type Error = SerdeError;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: serde::de::DeserializeSeed<'de>,
    {
        if self.idx >= self.entries.len() {
            return Ok(None);
        }
        let key = self.entries[self.idx].0;
        seed.deserialize(key.into_deserializer()).map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        let value = self.entries[self.idx].1;
        self.idx += 1;
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
            return Err(SerdeError::with_code(CborErrorCode::SerdeError));
        }
        let (variant, value) = map
            .iter()
            .next()
            .ok_or_else(|| SerdeError::with_code(CborErrorCode::SerdeError))?;
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
            None | Some(CborValue::Null) => Ok(()),
            _ => Err(SerdeError::with_code(CborErrorCode::SerdeError)),
        }
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Self::Error>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        let value = self
            .value
            .ok_or_else(|| SerdeError::with_code(CborErrorCode::SerdeError))?;
        seed.deserialize(CborDeserializer::new(value))
    }

    fn tuple_variant<V>(self, _len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            Some(CborValue::Array(items)) => visitor.visit_seq(SeqAccess { items, idx: 0 }),
            _ => Err(SerdeError::with_code(CborErrorCode::SerdeError)),
        }
    }

    fn struct_variant<V>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            Some(CborValue::Map(map)) => visitor.visit_map(MapAccess::new(map)),
            _ => Err(SerdeError::with_code(CborErrorCode::SerdeError)),
        }
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
    let map = CborMap::new(vec![(variant.to_string(), value)])
        .map_err(|err| SerdeError::with_code(err.code))?;
    Ok(CborValue::Map(map))
}

fn int_to_value(v: i128) -> Result<CborValue, SerdeError> {
    let min = i128::from(crate::MIN_SAFE_INTEGER);
    let max = i128::from(crate::MAX_SAFE_INTEGER_I64);
    if v >= min && v <= max {
        return Ok(CborValue::Int(
            i64::try_from(v).map_err(|_| SerdeError::with_code(CborErrorCode::SerdeError))?,
        ));
    }
    let negative = v < 0;
    let n = if negative {
        u128::try_from(-1 - v).map_err(|_| SerdeError::with_code(CborErrorCode::SerdeError))?
    } else {
        u128::try_from(v).map_err(|_| SerdeError::with_code(CborErrorCode::SerdeError))?
    };
    bignum_from_u128(negative, n)
}

fn uint_to_value(v: u128) -> Result<CborValue, SerdeError> {
    let max = u128::from(crate::MAX_SAFE_INTEGER);
    if v <= max {
        return Ok(CborValue::Int(
            i64::try_from(v).map_err(|_| SerdeError::with_code(CborErrorCode::SerdeError))?,
        ));
    }
    bignum_from_u128(false, v)
}

fn bignum_from_u128(negative: bool, n: u128) -> Result<CborValue, SerdeError> {
    let magnitude = u128_to_be_bytes(n);
    let bigint = BigInt::new(negative, magnitude).map_err(|err| SerdeError::with_code(err.code))?;
    Ok(CborValue::Bignum(bigint))
}

fn u128_to_be_bytes(n: u128) -> Vec<u8> {
    if n == 0 {
        return vec![0];
    }
    let leading_bytes = (n.leading_zeros() / 8) as usize;
    let bytes = n.to_be_bytes();
    bytes[leading_bytes..].to_vec()
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

fn deserialize_i128<'de, V>(
    value: &'de CborValue,
    visitor: V,
    min: i128,
    max: i128,
) -> Result<V::Value, SerdeError>
where
    V: Visitor<'de>,
{
    let v = match value {
        CborValue::Int(v) => i128::from(*v),
        CborValue::Bignum(b) => {
            bigint_to_i128(b).ok_or_else(|| SerdeError::with_code(CborErrorCode::SerdeError))?
        }
        _ => return Err(SerdeError::with_code(CborErrorCode::SerdeError)),
    };
    if v < min || v > max {
        return Err(SerdeError::with_code(CborErrorCode::SerdeError));
    }
    visitor.visit_i128(v)
}

fn deserialize_u128<'de, V>(
    value: &'de CborValue,
    visitor: V,
    max: u128,
) -> Result<V::Value, SerdeError>
where
    V: Visitor<'de>,
{
    let v = match value {
        CborValue::Int(v) if *v >= 0 => {
            u128::try_from(*v).map_err(|_| SerdeError::with_code(CborErrorCode::SerdeError))?
        }
        CborValue::Bignum(b) => {
            bigint_to_u128(b).ok_or_else(|| SerdeError::with_code(CborErrorCode::SerdeError))?
        }
        _ => return Err(SerdeError::with_code(CborErrorCode::SerdeError)),
    };
    if v > max {
        return Err(SerdeError::with_code(CborErrorCode::SerdeError));
    }
    visitor.visit_u128(v)
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
    Err(SerdeError::with_code(CborErrorCode::SerdeError))
}

fn f64_to_f32(v: f64) -> Result<f32, SerdeError> {
    if v.is_nan() {
        return Ok(f32::NAN);
    }
    if v > f64::from(f32::MAX) || v < f64::from(f32::MIN) {
        return Err(SerdeError::with_code(CborErrorCode::SerdeError));
    }
    #[allow(clippy::cast_possible_truncation)]
    {
        Ok(v as f32)
    }
}
