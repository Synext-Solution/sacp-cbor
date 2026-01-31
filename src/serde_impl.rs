use alloc::vec::Vec;
use core::fmt;
use serde::de::{
    self, Deserialize, DeserializeSeed, EnumAccess, IntoDeserializer, MapAccess, SeqAccess,
    VariantAccess, Visitor,
};
use serde::ser::{self, SerializeMap, SerializeSeq};
use serde::Deserializer;
use serde::Serialize;

use crate::canonical::{CanonicalCbor, CanonicalCborRef};
use crate::codec::{ArrayDecoder, CborDecode, Decoder, MapDecoder};
use crate::encode::Encoder;
use crate::profile::check_encoded_key_order;
use crate::query::{CborKind, CborValueRef};
use crate::scalar::F64Bits;
use crate::{CborError, DecodeLimits, ErrorCode};

const RAW_VALUE_MARKER: &str = "$__sacp_cbor_raw_value";

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
        if let Err(code) = check_encoded_key_order(prev, curr) {
            enc.truncate(entry_start);
            return Err(SerdeError::with_code(code));
        }
    }
    Ok(())
}

fn write_text_entry<T: ?Sized + Serialize>(
    enc: &mut Encoder,
    key: &str,
    prev_key_range: Option<(usize, usize)>,
    entry_start: usize,
    value: &T,
) -> Result<(usize, usize), SerdeError> {
    if let Err(err) = enc.emit_text(key) {
        enc.truncate(entry_start);
        return Err(SerdeError::from(err));
    }
    let key_start = entry_start;
    let key_end = enc.buf_len();

    check_map_key_order(enc, prev_key_range, key_start, key_end, entry_start)?;

    if let Err(err) = value.serialize(EncoderSerializer::new(enc)) {
        enc.truncate(entry_start);
        return Err(err);
    }

    Ok((key_start, key_end))
}

fn write_struct_field<T: ?Sized + Serialize>(
    enc: &mut Encoder,
    key: &'static str,
    value: &T,
    remaining: &mut usize,
    prev_key_range: &mut Option<(usize, usize)>,
) -> Result<(), SerdeError> {
    if *remaining == 0 {
        return Err(SerdeError::with_code(ErrorCode::MapLenMismatch));
    }
    let entry_start = enc.buf_len();
    let (key_start, key_end) = write_text_entry(enc, key, *prev_key_range, entry_start, value)?;
    *prev_key_range = Some((key_start, key_end));
    *remaining -= 1;
    Ok(())
}

fn finish_struct(enc: &mut Encoder, remaining: usize, roots: &[bool]) -> Result<(), SerdeError> {
    if remaining != 0 {
        return Err(SerdeError::with_code(ErrorCode::MapLenMismatch));
    }
    for &root in roots {
        enc.finish_container(root);
    }
    Ok(())
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
    let mut decoder = Decoder::<true>::new_checked(bytes, limits)?;
    let value = T::deserialize(&mut decoder).map_err(DeError::into_cbor_error)?;
    if decoder.position() != bytes.len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, decoder.position()));
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

    #[inline]
    fn encode_with<FEmit, FRoot>(self, emit: FEmit, root: FRoot) -> Result<(), SerdeError>
    where
        FEmit: FnOnce(&mut Encoder) -> Result<(), CborError>,
        FRoot: FnOnce(&mut Encoder) -> Result<(), CborError>,
    {
        let res = if self.enc.in_container() {
            emit(self.enc)
        } else {
            root(self.enc)
        };
        res.map_err(SerdeError::from)
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
        self.encode_with(|enc| enc.emit_bool(v), |enc| enc.bool(v))
    }

    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.emit_int(i64::from(v)), |enc| enc.int(i64::from(v)))
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.emit_int(i64::from(v)), |enc| enc.int(i64::from(v)))
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.emit_int(i64::from(v)), |enc| enc.int(i64::from(v)))
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.emit_int(v), |enc| enc.int(v))
    }

    fn serialize_i128(self, v: i128) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.emit_int_i128(v), |enc| enc.int_i128(v))
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.emit_int(i64::from(v)), |enc| enc.int(i64::from(v)))
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.emit_int(i64::from(v)), |enc| enc.int(i64::from(v)))
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.emit_int(i64::from(v)), |enc| enc.int(i64::from(v)))
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.emit_int_u128(u128::from(v)), |enc| enc.int_u128(u128::from(v)))
    }

    fn serialize_u128(self, v: u128) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.emit_int_u128(v), |enc| enc.int_u128(v))
    }

    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        self.serialize_f64(f64::from(v))
    }

    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        let bits = F64Bits::try_from_f64(v).map_err(SerdeError::from)?;
        self.encode_with(|enc| enc.emit_float(bits), |enc| enc.float(bits))
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        let mut buf = [0u8; 4];
        let s = v.encode_utf8(&mut buf);
        self.encode_with(|enc| enc.emit_text(s), |enc| enc.text(s))
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.emit_text(v), |enc| enc.text(v))
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.emit_bytes(v), |enc| enc.bytes(v))
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.encode_with(Encoder::emit_null, Encoder::null)
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        self.encode_with(Encoder::emit_null, Encoder::null)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.encode_with(Encoder::emit_null, Encoder::null)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        let map = start_enum_map(self.enc, variant)?;
        if let Err(err) = self.enc.null() {
            self.enc.truncate(map.start);
            self.enc.abort_container();
            return Err(SerdeError::from(err));
        }
        self.enc.finish_container(map.root);
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
        let map = start_enum_map(self.enc, variant)?;
        if let Err(err) = value.serialize(EncoderSerializer::new(self.enc)) {
            self.enc.truncate(map.start);
            self.enc.abort_container();
            return Err(err);
        }
        self.enc.finish_container(map.root);
        Ok(())
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        let len = len.ok_or_else(|| SerdeError::with_code(ErrorCode::IndefiniteLengthForbidden))?;
        let root = self.enc.array_header(len).map_err(SerdeError::from)?;
        Ok(SeqSerializer::new(self.enc, len, root))
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        let root = self.enc.array_header(len).map_err(SerdeError::from)?;
        Ok(SeqSerializer::new(self.enc, len, root))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        let root = self.enc.array_header(len).map_err(SerdeError::from)?;
        Ok(SeqSerializer::new(self.enc, len, root))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        let map = start_enum_map(self.enc, variant)?;
        if let Err(err) = self.enc.array_header(len) {
            self.enc.truncate(map.start);
            self.enc.abort_container();
            return Err(SerdeError::from(err));
        }
        Ok(TupleVariantSerializer::new(self.enc, len, map))
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        let len = len.ok_or_else(|| SerdeError::with_code(ErrorCode::IndefiniteLengthForbidden))?;
        let root = self.enc.map_header(len).map_err(SerdeError::from)?;
        Ok(MapSerializer::new(self.enc, len, root))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        let root = self.enc.map_header(len).map_err(SerdeError::from)?;
        Ok(StructSerializer::new(self.enc, len, root))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        let map = start_enum_map(self.enc, variant)?;
        if let Err(err) = self.enc.map_header(len) {
            self.enc.truncate(map.start);
            self.enc.abort_container();
            return Err(SerdeError::from(err));
        }
        Ok(StructVariantSerializer::new(self.enc, len, map))
    }
}

#[derive(Copy, Clone)]
struct EnumMapState {
    start: usize,
    root: bool,
}

fn start_enum_map(enc: &mut Encoder, variant: &str) -> Result<EnumMapState, SerdeError> {
    let start = enc.buf_len();
    let root = match enc.map_header(1) {
        Ok(root) => root,
        Err(err) => {
            enc.truncate(start);
            return Err(SerdeError::from(err));
        }
    };
    if let Err(err) = enc.emit_text(variant) {
        enc.truncate(start);
        enc.abort_container();
        return Err(SerdeError::from(err));
    }
    Ok(EnumMapState { start, root })
}

struct SeqSerializer<'a> {
    enc: &'a mut Encoder,
    remaining: usize,
    root: bool,
    finished: bool,
}

impl<'a> SeqSerializer<'a> {
    fn new(enc: &'a mut Encoder, remaining: usize, root: bool) -> Self {
        Self {
            enc,
            remaining,
            root,
            finished: false,
        }
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
        let mut this = self;
        this.enc.finish_container(this.root);
        this.finished = true;
        Ok(())
    }
}

impl Drop for SeqSerializer<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.enc.abort_container();
        }
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
    enc: &'a mut Encoder,
    remaining: usize,
    map_start: usize,
    map_root: bool,
    finished: bool,
}

impl<'a> TupleVariantSerializer<'a> {
    fn new(enc: &'a mut Encoder, remaining: usize, map: EnumMapState) -> Self {
        Self {
            enc,
            remaining,
            map_start: map.start,
            map_root: map.root,
            finished: false,
        }
    }
}

impl ser::SerializeTupleVariant for TupleVariantSerializer<'_> {
    type Ok = ();
    type Error = SerdeError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SerdeError> {
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
        let mut this = self;
        this.enc.finish_container(false);
        this.enc.finish_container(this.map_root);
        this.finished = true;
        Ok(())
    }
}

impl Drop for TupleVariantSerializer<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.enc.truncate(self.map_start);
            self.enc.abort_container();
            self.enc.abort_container();
        }
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
    root: bool,
    finished: bool,
}

impl<'a> MapSerializer<'a> {
    fn new(enc: &'a mut Encoder, remaining: usize, root: bool) -> Self {
        Self {
            enc,
            remaining,
            prev_key_range: None,
            pending: None,
            root,
            finished: false,
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
        let mut this = self;
        this.enc.finish_container(this.root);
        this.finished = true;
        Ok(())
    }
}

impl Drop for MapSerializer<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.enc.abort_container();
        }
    }
}

struct StructSerializer<'a> {
    enc: &'a mut Encoder,
    remaining: usize,
    prev_key_range: Option<(usize, usize)>,
    root: bool,
    finished: bool,
}

impl<'a> StructSerializer<'a> {
    fn new(enc: &'a mut Encoder, remaining: usize, root: bool) -> Self {
        Self {
            enc,
            remaining,
            prev_key_range: None,
            root,
            finished: false,
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
        write_struct_field(
            self.enc,
            key,
            value,
            &mut self.remaining,
            &mut self.prev_key_range,
        )
    }

    fn end(self) -> Result<(), SerdeError> {
        let mut this = self;
        finish_struct(this.enc, this.remaining, &[this.root])?;
        this.finished = true;
        Ok(())
    }
}

impl Drop for StructSerializer<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.enc.abort_container();
        }
    }
}

struct StructVariantSerializer<'a> {
    enc: &'a mut Encoder,
    remaining: usize,
    prev_key_range: Option<(usize, usize)>,
    map_start: usize,
    map_root: bool,
    finished: bool,
}

impl<'a> StructVariantSerializer<'a> {
    fn new(enc: &'a mut Encoder, remaining: usize, map: EnumMapState) -> Self {
        Self {
            enc,
            remaining,
            prev_key_range: None,
            map_start: map.start,
            map_root: map.root,
            finished: false,
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
        write_struct_field(
            self.enc,
            key,
            value,
            &mut self.remaining,
            &mut self.prev_key_range,
        )
    }

    fn end(self) -> Result<(), SerdeError> {
        let mut this = self;
        finish_struct(this.enc, this.remaining, &[false, this.map_root])?;
        this.finished = true;
        Ok(())
    }
}

impl Drop for StructVariantSerializer<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.enc.truncate(self.map_start);
            self.enc.abort_container();
            self.enc.abort_container();
        }
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
        if let Err(err) = self.enc.emit_text(v) {
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

impl crate::wire::DecodeError for DeError {
    #[inline]
    fn new(code: ErrorCode, offset: usize) -> Self {
        Self::new(code, offset)
    }
}

struct ArrayAccess<'a, 'de, const CHECKED: bool> {
    array: ArrayDecoder<'a, 'de, CHECKED>,
}

impl<'de, const CHECKED: bool> SeqAccess<'de> for ArrayAccess<'_, 'de, CHECKED> {
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

struct MapAccessImpl<'a, 'de, const CHECKED: bool> {
    map: MapDecoder<'a, 'de, CHECKED>,
}

impl<'de, const CHECKED: bool> MapAccess<'de> for MapAccessImpl<'_, 'de, CHECKED> {
    type Error = DeError;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, DeError>
    where
        K: DeserializeSeed<'de>,
    {
        let Some(key) = self.map.next_key().map_err(DeError::from)? else {
            return Ok(None);
        };
        seed.deserialize(<&'de str as IntoDeserializer<'de, DeError>>::into_deserializer(key))
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

struct EnumAccessImpl<'a, 'de, const CHECKED: bool> {
    key: &'de str,
    map: MapDecoder<'a, 'de, CHECKED>,
}

#[allow(clippy::elidable_lifetime_names)]
impl<'a, 'de, const CHECKED: bool> EnumAccess<'de> for EnumAccessImpl<'a, 'de, CHECKED> {
    type Error = DeError;
    type Variant = VariantAccessImpl<'a, 'de, CHECKED>;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), DeError>
    where
        V: DeserializeSeed<'de>,
    {
        let variant = seed
            .deserialize(<&'de str as IntoDeserializer<'de, DeError>>::into_deserializer(
                self.key,
            ))?;
        Ok((variant, VariantAccessImpl { map: self.map }))
    }
}

struct VariantAccessImpl<'a, 'de, const CHECKED: bool> {
    map: MapDecoder<'a, 'de, CHECKED>,
}

impl<'de, const CHECKED: bool> VariantAccess<'de> for VariantAccessImpl<'_, 'de, CHECKED> {
    type Error = DeError;

    fn unit_variant(mut self) -> Result<(), DeError> {
        self.map
            .decode_value(|decoder| <()>::deserialize(decoder).map_err(DeError::into_cbor_error))
            .map_err(DeError::from)
    }

    fn newtype_variant_seed<T>(mut self, seed: T) -> Result<T::Value, DeError>
    where
        T: DeserializeSeed<'de>,
    {
        self.map
            .decode_value(|decoder| seed.deserialize(decoder).map_err(DeError::into_cbor_error))
            .map_err(DeError::from)
    }

    fn tuple_variant<V>(mut self, len: usize, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        self.map
            .decode_value(|decoder| {
                decoder
                    .deserialize_tuple(len, visitor)
                    .map_err(DeError::into_cbor_error)
            })
            .map_err(DeError::from)
    }

    fn struct_variant<V>(
        mut self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        self.map
            .decode_value(|decoder| {
                decoder
                    .deserialize_struct("", fields, visitor)
                    .map_err(DeError::into_cbor_error)
            })
            .map_err(DeError::from)
    }
}

impl<'de, const CHECKED: bool> de::Deserializer<'de> for &mut Decoder<'de, CHECKED> {
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
        let value: Vec<u8> = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_byte_buf(value)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        if matches!(self.peek_kind().map_err(DeError::from)?, CborKind::Null) {
            let _: () = CborDecode::decode(self).map_err(DeError::from)?;
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        let _: () = CborDecode::decode(self).map_err(DeError::from)?;
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value, DeError>
    where
        V: Visitor<'de>,
    {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V>(self, name: &'static str, visitor: V) -> Result<V::Value, DeError>
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
        let mut map = self.map().map_err(DeError::from)?;
        if map.remaining() != 1 {
            return Err(DeError::new(ErrorCode::MapLenMismatch, off));
        }
        let Some(key) = map.next_key().map_err(DeError::from)? else {
            return Err(DeError::new(ErrorCode::MapLenMismatch, off));
        };
        visitor.visit_enum(EnumAccessImpl { key, map })
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
    let mut decoder = Decoder::<true>::new_checked(bytes, limits)?;
    let value = T::deserialize(&mut decoder).map_err(DeError::into_cbor_error)?;
    if decoder.position() != bytes.len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, decoder.position()));
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
pub fn from_canonical_bytes_ref<'de, T>(canon: CanonicalCborRef<'de>) -> Result<T, CborError>
where
    T: Deserialize<'de>,
{
    let limits = DecodeLimits::for_bytes(canon.len());
    let mut decoder = Decoder::<false>::new_trusted(canon, limits)?;
    let value = T::deserialize(&mut decoder).map_err(DeError::into_cbor_error)?;
    if decoder.position() != canon.len() {
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
    from_canonical_bytes_ref(canon.as_ref())
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
