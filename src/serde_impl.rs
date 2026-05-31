use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::de::{
    self, Deserialize, DeserializeSeed, EnumAccess, IntoDeserializer, MapAccess, SeqAccess,
    VariantAccess, Visitor,
};
use serde::ser::{self, SerializeMap, SerializeSeq};
use serde::Deserializer;
use serde::Serialize;

use crate::alloc_util;
use crate::canonical::{CanonicalCbor, CanonicalCborRef};
use crate::codec::CborDecode;
use crate::decode::{ArrayDecoder, Decoder, MapDecoder};
use crate::encode::{Encoder, EncoderCheckpoint};
use crate::profile::cmp_text_keys_canonical;
use crate::query::{CborKind, CborValueRef};
use crate::scalar::F64Bits;
use crate::{CborError, DecodeLimits, ErrorCode};

const RAW_VALUE_MARKER: &str = "$__sacp_cbor_raw_value";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MapKeyMode {
    Strict,
    SortKeys,
}

/// Serialize a Rust value into canonical SACP-CBOR/1 bytes.
///
/// # Errors
///
/// Returns an error if the value cannot be represented under SACP-CBOR/1 constraints.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, CborError> {
    SerdeOptions::strict().to_vec(value)
}

/// Serde encoding options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub struct SerdeOptions {
    map_key_mode: MapKeyMode,
}

impl SerdeOptions {
    /// Strict encoding: maps must already iterate in canonical key order.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            map_key_mode: MapKeyMode::Strict,
        }
    }

    /// Sort map keys while encoding.
    ///
    /// This buffers map entries before writing them, then emits keys in SACP-CBOR/1 canonical order.
    #[must_use]
    pub const fn sorted_maps() -> Self {
        Self {
            map_key_mode: MapKeyMode::SortKeys,
        }
    }

    /// Serialize a Rust value into canonical SACP-CBOR/1 bytes with these options.
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be represented under SACP-CBOR/1 constraints.
    pub fn to_vec<T: Serialize>(self, value: &T) -> Result<Vec<u8>, CborError> {
        serialize_to_vec(value, self.map_key_mode)
    }
}

impl Default for SerdeOptions {
    fn default() -> Self {
        Self::strict()
    }
}

fn serialize_to_vec<T: Serialize>(value: &T, mode: MapKeyMode) -> Result<Vec<u8>, CborError> {
    let mut enc = Encoder::new();
    value
        .serialize(EncoderSerializer::with_mode(&mut enc, mode))
        .map_err(SerdeError::into_cbor_error)?;
    Ok(enc.finish()?.into_bytes())
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
    error: CborError,
}

impl SerdeError {
    const fn with_code(code: ErrorCode) -> Self {
        Self {
            error: CborError::new(code, 0),
        }
    }

    const fn into_cbor_error(self) -> CborError {
        self.error
    }
}

impl fmt::Display for SerdeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
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
        Self { error: err }
    }
}

struct EncoderSerializer<'a> {
    enc: &'a mut Encoder,
    mode: MapKeyMode,
}

impl<'a> EncoderSerializer<'a> {
    fn with_mode(enc: &'a mut Encoder, mode: MapKeyMode) -> Self {
        Self { enc, mode }
    }

    #[inline]
    fn encode_with<FEmit>(self, emit: FEmit) -> Result<(), SerdeError>
    where
        FEmit: FnOnce(&mut Encoder) -> Result<(), CborError>,
    {
        emit(self.enc).map_err(SerdeError::from)
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
        self.encode_with(|enc| enc.bool(v))
    }

    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.int(i64::from(v)))
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.int(i64::from(v)))
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.int(i64::from(v)))
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.int(v))
    }

    fn serialize_i128(self, v: i128) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.int_i128(v))
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.int(i64::from(v)))
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.int(i64::from(v)))
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.int(i64::from(v)))
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.int_u128(u128::from(v)))
    }

    fn serialize_u128(self, v: u128) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.int_u128(v))
    }

    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        self.serialize_f64(f64::from(v))
    }

    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        let bits = F64Bits::try_from_f64(v).map_err(SerdeError::from)?;
        self.encode_with(|enc| enc.float(bits))
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        let mut buf = [0u8; 4];
        let s = v.encode_utf8(&mut buf);
        self.encode_with(|enc| enc.text(s))
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.text(v))
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.bytes(v))
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.map(1, |map| map.entry("none", Encoder::null)))
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        let mode = self.mode;
        self.encode_with(|enc| {
            enc.map(1, |map| {
                map.entry("some", |enc| {
                    value
                        .serialize(EncoderSerializer::with_mode(enc, mode))
                        .map_err(SerdeError::into_cbor_error)
                })
            })
        })
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        self.encode_with(Encoder::null)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.encode_with(Encoder::null)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.encode_with(|enc| enc.text(variant))
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
        value
            .serialize(EncoderSerializer::with_mode(self.enc, self.mode))
            .and_then(|()| self.enc.finish_container().map_err(SerdeError::from))
            .map_err(|err| {
                self.enc.restore(map.checkpoint);
                err
            })
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        let len = len.ok_or_else(|| SerdeError::with_code(ErrorCode::IndefiniteLengthForbidden))?;
        let checkpoint = self.enc.checkpoint();
        self.enc.array_header(len).map_err(SerdeError::from)?;
        Ok(SeqSerializer::new(self.enc, len, checkpoint, self.mode))
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        let checkpoint = self.enc.checkpoint();
        self.enc.array_header(len).map_err(SerdeError::from)?;
        Ok(SeqSerializer::new(self.enc, len, checkpoint, self.mode))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        let checkpoint = self.enc.checkpoint();
        self.enc.array_header(len).map_err(SerdeError::from)?;
        Ok(SeqSerializer::new(self.enc, len, checkpoint, self.mode))
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
            self.enc.restore(map.checkpoint);
            return Err(SerdeError::from(err));
        }
        Ok(TupleVariantSerializer::new(self.enc, len, map, self.mode))
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        let len = len.ok_or_else(|| SerdeError::with_code(ErrorCode::IndefiniteLengthForbidden))?;
        let state = MapState::new(len, self.mode)?;
        let checkpoint = self.enc.checkpoint();
        self.enc.map_header(len).map_err(SerdeError::from)?;
        Ok(MapSerializer::new(
            self.enc, len, checkpoint, self.mode, state,
        ))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        let entries = SortedEntries::new(len)?;
        let checkpoint = self.enc.checkpoint();
        self.enc.map_header(len).map_err(SerdeError::from)?;
        Ok(StructSerializer::new(
            self.enc, entries, checkpoint, self.mode,
        ))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        let entries = SortedEntries::new(len)?;
        let map = start_enum_map(self.enc, variant)?;
        if let Err(err) = self.enc.map_header(len) {
            self.enc.restore(map.checkpoint);
            return Err(SerdeError::from(err));
        }
        Ok(StructVariantSerializer::new(
            self.enc, entries, map, self.mode,
        ))
    }
}

#[derive(Copy, Clone)]
struct EnumMapState {
    checkpoint: EncoderCheckpoint,
}

fn start_enum_map(enc: &mut Encoder, variant: &str) -> Result<EnumMapState, SerdeError> {
    let checkpoint = enc.checkpoint();
    let result = enc.map_header(1).and_then(|()| {
        let key_start = enc.begin_map_key()?;
        enc.write_text_key(variant)?;
        let key_end = enc.buf_len();
        enc.finish_map_key(key_start, key_end)
    });
    if let Err(err) = result {
        enc.restore(checkpoint);
        return Err(SerdeError::from(err));
    }
    Ok(EnumMapState { checkpoint })
}

struct SeqSerializer<'a> {
    enc: &'a mut Encoder,
    checkpoint: EncoderCheckpoint,
    remaining: usize,
    finished: bool,
    mode: MapKeyMode,
}

impl<'a> SeqSerializer<'a> {
    fn new(
        enc: &'a mut Encoder,
        remaining: usize,
        checkpoint: EncoderCheckpoint,
        mode: MapKeyMode,
    ) -> Self {
        Self {
            enc,
            checkpoint,
            remaining,
            finished: false,
            mode,
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
        value.serialize(EncoderSerializer::with_mode(self.enc, self.mode))?;
        self.remaining -= 1;
        Ok(())
    }

    fn end(self) -> Result<(), SerdeError> {
        if self.remaining != 0 {
            return Err(SerdeError::with_code(ErrorCode::ArrayLenMismatch));
        }
        let mut this = self;
        this.enc.finish_container().map_err(SerdeError::from)?;
        this.finished = true;
        Ok(())
    }
}

impl Drop for SeqSerializer<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.enc.restore(self.checkpoint);
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
    checkpoint: EncoderCheckpoint,
    remaining: usize,
    finished: bool,
    mode: MapKeyMode,
}

impl<'a> TupleVariantSerializer<'a> {
    fn new(enc: &'a mut Encoder, remaining: usize, map: EnumMapState, mode: MapKeyMode) -> Self {
        Self {
            enc,
            checkpoint: map.checkpoint,
            remaining,
            finished: false,
            mode,
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
        value.serialize(EncoderSerializer::with_mode(self.enc, self.mode))?;
        self.remaining -= 1;
        Ok(())
    }

    fn end(self) -> Result<(), SerdeError> {
        if self.remaining != 0 {
            return Err(SerdeError::with_code(ErrorCode::ArrayLenMismatch));
        }
        let mut this = self;
        this.enc.finish_container().map_err(SerdeError::from)?;
        this.enc.finish_container().map_err(SerdeError::from)?;
        this.finished = true;
        Ok(())
    }
}

impl Drop for TupleVariantSerializer<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.enc.restore(self.checkpoint);
        }
    }
}

struct PendingKey {
    checkpoint: EncoderCheckpoint,
}

struct SortedEntry {
    key: String,
    value: Vec<u8>,
}

struct SortedEntries {
    entries: Vec<SortedEntry>,
    remaining: usize,
}

impl SortedEntries {
    fn new(remaining: usize) -> Result<Self, SerdeError> {
        Ok(Self {
            entries: alloc_util::try_vec_with_capacity::<SortedEntry>(remaining, 0)
                .map_err(SerdeError::from)?,
            remaining,
        })
    }

    fn push<T: ?Sized + Serialize>(
        &mut self,
        key: String,
        value: &T,
        mode: MapKeyMode,
    ) -> Result<(), SerdeError> {
        if self.remaining == 0 {
            return Err(SerdeError::with_code(ErrorCode::MapLenMismatch));
        }
        let mut tmp = Encoder::new();
        value.serialize(EncoderSerializer::with_mode(&mut tmp, mode))?;
        let value = tmp.finish().map_err(SerdeError::from)?.into_bytes();
        self.entries.push(SortedEntry { key, value });
        self.remaining -= 1;
        Ok(())
    }

    fn push_static<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
        mode: MapKeyMode,
    ) -> Result<(), SerdeError> {
        let key = alloc_util::try_string_from_str(key, 0).map_err(SerdeError::from)?;
        self.push(key, value, mode)
    }

    fn finish_into(
        &mut self,
        enc: &mut Encoder,
        containers_to_close: usize,
    ) -> Result<(), SerdeError> {
        if self.remaining != 0 {
            return Err(SerdeError::with_code(ErrorCode::MapLenMismatch));
        }

        self.entries
            .sort_by(|a, b| cmp_text_keys_canonical(&a.key, &b.key));
        for window in self.entries.windows(2) {
            if window[0].key == window[1].key {
                return Err(SerdeError::with_code(ErrorCode::DuplicateMapKey));
            }
        }

        for entry in &self.entries {
            let key_start = enc.begin_map_key().map_err(SerdeError::from)?;
            enc.write_text_key(&entry.key).map_err(SerdeError::from)?;
            let key_end = enc.buf_len();
            enc.finish_map_key(key_start, key_end)
                .map_err(SerdeError::from)?;
            enc.raw_trusted_canonical_bytes(&entry.value)
                .map_err(SerdeError::from)?;
        }

        for _ in 0..containers_to_close {
            enc.finish_container().map_err(SerdeError::from)?;
        }
        Ok(())
    }
}

enum MapState {
    Strict {
        pending: Option<PendingKey>,
    },
    Sorted {
        entries: SortedEntries,
        pending_key: Option<String>,
    },
}

impl MapState {
    fn new(remaining: usize, mode: MapKeyMode) -> Result<Self, SerdeError> {
        Ok(match mode {
            MapKeyMode::Strict => Self::Strict { pending: None },
            MapKeyMode::SortKeys => Self::Sorted {
                entries: SortedEntries::new(remaining)?,
                pending_key: None,
            },
        })
    }
}

struct MapSerializer<'a> {
    enc: &'a mut Encoder,
    checkpoint: EncoderCheckpoint,
    remaining: usize,
    finished: bool,
    mode: MapKeyMode,
    state: MapState,
}

impl<'a> MapSerializer<'a> {
    fn new(
        enc: &'a mut Encoder,
        remaining: usize,
        checkpoint: EncoderCheckpoint,
        mode: MapKeyMode,
        state: MapState,
    ) -> Self {
        Self {
            enc,
            checkpoint,
            remaining,
            finished: false,
            mode,
            state,
        }
    }

    fn write_pending_key<T: ?Sized + Serialize>(
        &mut self,
        key: &T,
    ) -> Result<PendingKey, SerdeError> {
        let checkpoint = self.enc.checkpoint();
        let entry_start = self.enc.begin_map_key().map_err(SerdeError::from)?;
        let result = key.serialize(TextKeySerializer::new(DirectMapKey {
            enc: self.enc,
            entry_start,
        }));
        if let Err(err) = result {
            self.enc.restore(checkpoint);
            return Err(err);
        }
        Ok(PendingKey { checkpoint })
    }
}

impl SerializeMap for MapSerializer<'_> {
    type Ok = ();
    type Error = SerdeError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), SerdeError> {
        match &mut self.state {
            MapState::Strict { .. } => {
                let has_pending = if let MapState::Strict { pending } = &self.state {
                    pending.is_some()
                } else {
                    return Err(SerdeError::with_code(ErrorCode::SerdeError));
                };
                if has_pending {
                    return Err(SerdeError::with_code(ErrorCode::SerdeError));
                }
                if self.remaining == 0 {
                    return Err(SerdeError::with_code(ErrorCode::MapLenMismatch));
                }
                let p = self.write_pending_key(key)?;
                if let MapState::Strict { pending, .. } = &mut self.state {
                    *pending = Some(p);
                }
                Ok(())
            }
            MapState::Sorted { pending_key, .. } => {
                if pending_key.is_some() {
                    return Err(SerdeError::with_code(ErrorCode::SerdeError));
                }
                if self.remaining == 0 {
                    return Err(SerdeError::with_code(ErrorCode::MapLenMismatch));
                }
                let k = key.serialize(TextKeySerializer::new(OwnedMapKey))?;
                *pending_key = Some(k);
                Ok(())
            }
        }
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SerdeError> {
        match &mut self.state {
            MapState::Strict { pending } => {
                let p = pending
                    .take()
                    .ok_or_else(|| SerdeError::with_code(ErrorCode::SerdeError))?;

                if let Err(err) = value.serialize(EncoderSerializer::with_mode(self.enc, self.mode))
                {
                    self.enc.restore(p.checkpoint);
                    return Err(err);
                }

                self.remaining -= 1;
                Ok(())
            }
            MapState::Sorted {
                entries,
                pending_key,
            } => {
                let key = pending_key
                    .take()
                    .ok_or_else(|| SerdeError::with_code(ErrorCode::SerdeError))?;

                entries.push(key, value, self.mode)?;
                self.remaining -= 1;
                Ok(())
            }
        }
    }

    fn serialize_entry<K: ?Sized + Serialize, V: ?Sized + Serialize>(
        &mut self,
        key: &K,
        value: &V,
    ) -> Result<(), SerdeError> {
        match &mut self.state {
            MapState::Strict { .. } => {
                if self.remaining == 0 {
                    return Err(SerdeError::with_code(ErrorCode::MapLenMismatch));
                }
                let p = self.write_pending_key(key)?;
                if let Err(err) = value.serialize(EncoderSerializer::with_mode(self.enc, self.mode))
                {
                    self.enc.restore(p.checkpoint);
                    return Err(err);
                }
                self.remaining -= 1;
                Ok(())
            }
            MapState::Sorted { entries, .. } => {
                if self.remaining == 0 {
                    return Err(SerdeError::with_code(ErrorCode::MapLenMismatch));
                }
                let key = key.serialize(TextKeySerializer::new(OwnedMapKey))?;

                entries.push(key, value, self.mode)?;
                self.remaining -= 1;
                Ok(())
            }
        }
    }

    fn end(self) -> Result<(), SerdeError> {
        if self.remaining != 0 {
            return Err(SerdeError::with_code(ErrorCode::MapLenMismatch));
        }

        let mut this = self;
        match &mut this.state {
            MapState::Strict { pending, .. } => {
                if pending.is_some() {
                    return Err(SerdeError::with_code(ErrorCode::SerdeError));
                }
            }
            MapState::Sorted {
                entries,
                pending_key,
            } => {
                if pending_key.is_some() {
                    return Err(SerdeError::with_code(ErrorCode::SerdeError));
                }

                entries.finish_into(this.enc, 0)?;
            }
        }

        this.enc.finish_container().map_err(SerdeError::from)?;
        this.finished = true;
        Ok(())
    }
}

impl Drop for MapSerializer<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.enc.restore(self.checkpoint);
        }
    }
}

struct StructSerializer<'a> {
    enc: &'a mut Encoder,
    checkpoint: EncoderCheckpoint,
    entries: SortedEntries,
    finished: bool,
    mode: MapKeyMode,
}

impl<'a> StructSerializer<'a> {
    fn new(
        enc: &'a mut Encoder,
        entries: SortedEntries,
        checkpoint: EncoderCheckpoint,
        mode: MapKeyMode,
    ) -> Self {
        Self {
            enc,
            checkpoint,
            entries,
            finished: false,
            mode,
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
        self.entries.push_static(key, value, self.mode)
    }

    fn end(self) -> Result<(), SerdeError> {
        let mut this = self;
        this.entries.finish_into(this.enc, 1)?;
        this.finished = true;
        Ok(())
    }
}

impl Drop for StructSerializer<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.enc.restore(self.checkpoint);
        }
    }
}

struct StructVariantSerializer<'a> {
    enc: &'a mut Encoder,
    checkpoint: EncoderCheckpoint,
    entries: SortedEntries,
    finished: bool,
    mode: MapKeyMode,
}

impl<'a> StructVariantSerializer<'a> {
    fn new(
        enc: &'a mut Encoder,
        entries: SortedEntries,
        map: EnumMapState,
        mode: MapKeyMode,
    ) -> Self {
        Self {
            enc,
            checkpoint: map.checkpoint,
            entries,
            finished: false,
            mode,
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
        self.entries.push_static(key, value, self.mode)
    }

    fn end(self) -> Result<(), SerdeError> {
        let mut this = self;
        this.entries.finish_into(this.enc, 2)?;
        this.finished = true;
        Ok(())
    }
}

impl Drop for StructVariantSerializer<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.enc.restore(self.checkpoint);
        }
    }
}

macro_rules! reject_non_text_map_key_serializer_methods {
    () => {
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

        fn serialize_some<T: ?Sized + Serialize>(
            self,
            _value: &T,
        ) -> Result<Self::Ok, Self::Error> {
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
    };
}

trait TextKeySink {
    type Ok;

    fn write_str(self, value: &str) -> Result<Self::Ok, SerdeError>;
}

struct DirectMapKey<'a> {
    enc: &'a mut Encoder,
    entry_start: usize,
}

impl TextKeySink for DirectMapKey<'_> {
    type Ok = (usize, usize);

    fn write_str(self, value: &str) -> Result<Self::Ok, SerdeError> {
        let key_start = self.entry_start;
        self.enc.write_text_key(value).map_err(SerdeError::from)?;
        let key_end = self.enc.buf_len();
        self.enc
            .finish_map_key(key_start, key_end)
            .map_err(SerdeError::from)?;
        Ok((key_start, key_end))
    }
}

struct OwnedMapKey;

impl TextKeySink for OwnedMapKey {
    type Ok = String;

    fn write_str(self, value: &str) -> Result<Self::Ok, SerdeError> {
        alloc_util::try_string_from_str(value, 0).map_err(SerdeError::from)
    }
}

struct TextKeySerializer<S> {
    sink: S,
}

impl<S> TextKeySerializer<S> {
    const fn new(sink: S) -> Self {
        Self { sink }
    }
}

impl<S: TextKeySink> ser::Serializer for TextKeySerializer<S> {
    type Ok = S::Ok;
    type Error = SerdeError;

    type SerializeSeq = ser::Impossible<S::Ok, SerdeError>;
    type SerializeTuple = ser::Impossible<S::Ok, SerdeError>;
    type SerializeTupleStruct = ser::Impossible<S::Ok, SerdeError>;
    type SerializeTupleVariant = ser::Impossible<S::Ok, SerdeError>;
    type SerializeMap = ser::Impossible<S::Ok, SerdeError>;
    type SerializeStruct = ser::Impossible<S::Ok, SerdeError>;
    type SerializeStructVariant = ser::Impossible<S::Ok, SerdeError>;

    fn serialize_str(self, value: &str) -> Result<Self::Ok, Self::Error> {
        self.sink.write_str(value)
    }

    fn serialize_char(self, value: char) -> Result<Self::Ok, Self::Error> {
        let mut buf = [0u8; 4];
        self.serialize_str(value.encode_utf8(&mut buf))
    }

    reject_non_text_map_key_serializer_methods!();
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

enum EnumPayload<'a, 'de, const CHECKED: bool> {
    Unit,
    Map(MapDecoder<'a, 'de, CHECKED>),
}

struct EnumAccessImpl<'a, 'de, const CHECKED: bool> {
    key: &'de str,
    payload: EnumPayload<'a, 'de, CHECKED>,
    offset: usize,
}

#[allow(clippy::elidable_lifetime_names)]
impl<'a, 'de, const CHECKED: bool> EnumAccess<'de> for EnumAccessImpl<'a, 'de, CHECKED> {
    type Error = DeError;
    type Variant = VariantAccessImpl<'a, 'de, CHECKED>;

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

struct VariantAccessImpl<'a, 'de, const CHECKED: bool> {
    payload: EnumPayload<'a, 'de, CHECKED>,
    offset: usize,
}

impl<'de, const CHECKED: bool> VariantAccess<'de> for VariantAccessImpl<'_, 'de, CHECKED> {
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
                payload: EnumPayload::<CHECKED>::Unit,
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
