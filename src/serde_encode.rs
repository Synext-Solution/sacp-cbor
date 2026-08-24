//! Sink-generic serde serialization.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::ser::{self, SerializeMap, SerializeSeq};
use serde::Serialize;

use crate::alloc_util;
use crate::encode::{major_uint_header, ByteSink, EncodeError, Encoder, VecSink};
use crate::profile::cmp_text_keys_canonical;
use crate::scalar::F64Bits;
use crate::{CborError, EncodeLimits, ErrorCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MapKeyMode {
    Strict,
    Sort,
}

/// A serde serialization failure preserving the sink's owned error type.
#[derive(Debug)]
pub enum SerdeEncodeError<E> {
    /// Profile, poison, or sink failure from the canonical encoder.
    Encode(EncodeError<E>),
}

impl<E> From<EncodeError<E>> for SerdeEncodeError<E> {
    fn from(error: EncodeError<E>) -> Self {
        Self::Encode(error)
    }
}

impl<E> From<CborError> for SerdeEncodeError<E> {
    fn from(error: CborError) -> Self {
        Self::Encode(EncodeError::Cbor(error))
    }
}

impl<E: fmt::Display> fmt::Display for SerdeEncodeError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for SerdeEncodeError<E> where E: fmt::Debug + fmt::Display {}

impl<E: fmt::Debug + fmt::Display> ser::Error for SerdeEncodeError<E> {
    fn custom<T: fmt::Display>(_message: T) -> Self {
        CborError::new(ErrorCode::SerdeError, 0).into()
    }
}

#[allow(clippy::needless_pass_by_value)]
const fn vector_error(error: SerdeEncodeError<CborError>) -> CborError {
    match error {
        SerdeEncodeError::Encode(EncodeError::Cbor(error) | EncodeError::Sink(error)) => error,
        SerdeEncodeError::Encode(EncodeError::Poisoned) => {
            CborError::new(ErrorCode::EncoderPoisoned, 0)
        }
    }
}

/// Serialize a Rust value into canonical bytes.
///
/// # Errors
///
/// Returns the first canonical-profile, serde, allocation, or vector-sink error.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, CborError> {
    SerdeOptions::strict().to_vec(value)
}

/// Serde encoding options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerdeOptions {
    map_key_mode: MapKeyMode,
}

impl SerdeOptions {
    /// Require maps to arrive in canonical text-key order.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            map_key_mode: MapKeyMode::Strict,
        }
    }

    /// Explicitly buffer and sort serde map entries before emission.
    #[must_use]
    pub const fn sorted_maps() -> Self {
        Self {
            map_key_mode: MapKeyMode::Sort,
        }
    }

    /// Serialize one value through an existing sink-generic encoder.
    ///
    /// # Errors
    ///
    /// Returns the first canonical-profile, serde, allocation, or owned sink error.
    pub fn encode<T, S>(
        self,
        value: &T,
        encoder: &mut Encoder<S>,
    ) -> Result<(), SerdeEncodeError<S::Error>>
    where
        T: Serialize + ?Sized,
        S: ByteSink,
        S::Error: fmt::Debug + fmt::Display,
    {
        serialize_nested(value, encoder, self.map_key_mode)
    }

    /// Serialize one value into a supplied sink and return its output.
    ///
    /// # Errors
    ///
    /// Returns the first canonical-profile, serde, allocation, or owned sink error.
    pub fn to_sink<T, S>(self, value: &T, sink: S) -> Result<S::Output, SerdeEncodeError<S::Error>>
    where
        T: Serialize + ?Sized,
        S: ByteSink,
        S::Error: fmt::Debug + fmt::Display,
    {
        let mut encoder = Encoder::with_sink(sink);
        self.encode(value, &mut encoder)?;
        encoder.finish().map_err(SerdeEncodeError::from)
    }

    /// Serialize one value into a vector.
    ///
    /// # Errors
    ///
    /// Returns the first canonical-profile, serde, allocation, or vector-sink error.
    pub fn to_vec<T: Serialize + ?Sized>(self, value: &T) -> Result<Vec<u8>, CborError> {
        self.to_sink(value, VecSink::new()).map_err(vector_error)
    }
}

impl Default for SerdeOptions {
    fn default() -> Self {
        Self::strict()
    }
}

fn code_error<E>(code: ErrorCode) -> SerdeEncodeError<E> {
    CborError::new(code, 0).into()
}

fn reject<S: ByteSink, T>(
    encoder: &mut Encoder<S>,
    code: ErrorCode,
) -> Result<T, SerdeEncodeError<S::Error>> {
    let offset = encoder.len();
    encoder.poison();
    Err(CborError::new(code, offset).into())
}

fn ensure_healthy<S>(encoder: &Encoder<S>) -> Result<(), SerdeEncodeError<S::Error>>
where
    S: ByteSink,
{
    encoder.ensure_healthy().map_err(SerdeEncodeError::from)
}

fn serialize_nested<T, S>(
    value: &T,
    encoder: &mut Encoder<S>,
    mode: MapKeyMode,
) -> Result<(), SerdeEncodeError<S::Error>>
where
    T: Serialize + ?Sized,
    S: ByteSink,
    S::Error: fmt::Debug + fmt::Display,
{
    encoder.guarded_value(|encoder| value.serialize(Serializer { encoder, mode }))
}

struct Serializer<'a, S: ByteSink> {
    encoder: &'a mut Encoder<S>,
    mode: MapKeyMode,
}

impl<'a, S> ser::Serializer for Serializer<'a, S>
where
    S: ByteSink,
    S::Error: fmt::Debug + fmt::Display,
{
    type Ok = ();
    type Error = SerdeEncodeError<S::Error>;
    type SerializeSeq = Sequence<'a, S>;
    type SerializeTuple = Sequence<'a, S>;
    type SerializeTupleStruct = Sequence<'a, S>;
    type SerializeTupleVariant = Sequence<'a, S>;
    type SerializeMap = MapSerializer<'a, S>;
    type SerializeStruct = StructSerializer<'a, S>;
    type SerializeStructVariant = StructSerializer<'a, S>;

    fn serialize_bool(self, value: bool) -> Result<(), Self::Error> {
        self.encoder.bool(value).map_err(Into::into)
    }
    fn serialize_i8(self, value: i8) -> Result<(), Self::Error> {
        self.encoder.int(i64::from(value)).map_err(Into::into)
    }
    fn serialize_i16(self, value: i16) -> Result<(), Self::Error> {
        self.encoder.int(i64::from(value)).map_err(Into::into)
    }
    fn serialize_i32(self, value: i32) -> Result<(), Self::Error> {
        self.encoder.int(i64::from(value)).map_err(Into::into)
    }
    fn serialize_i64(self, value: i64) -> Result<(), Self::Error> {
        self.encoder.int(value).map_err(Into::into)
    }
    fn serialize_i128(self, value: i128) -> Result<(), Self::Error> {
        self.encoder.int_i128(value).map_err(Into::into)
    }
    fn serialize_u8(self, value: u8) -> Result<(), Self::Error> {
        self.encoder.int(i64::from(value)).map_err(Into::into)
    }
    fn serialize_u16(self, value: u16) -> Result<(), Self::Error> {
        self.encoder.int(i64::from(value)).map_err(Into::into)
    }
    fn serialize_u32(self, value: u32) -> Result<(), Self::Error> {
        self.encoder.int(i64::from(value)).map_err(Into::into)
    }
    fn serialize_u64(self, value: u64) -> Result<(), Self::Error> {
        self.encoder.int_u128(u128::from(value)).map_err(Into::into)
    }
    fn serialize_u128(self, value: u128) -> Result<(), Self::Error> {
        self.encoder.int_u128(value).map_err(Into::into)
    }
    fn serialize_f32(self, value: f32) -> Result<(), Self::Error> {
        self.serialize_f64(f64::from(value))
    }
    fn serialize_f64(self, value: f64) -> Result<(), Self::Error> {
        let bits = match F64Bits::try_from_f64(value) {
            Ok(bits) => bits,
            Err(error) => {
                let error = CborError::new(error.code, self.encoder.len());
                self.encoder.poison();
                return Err(error.into());
            }
        };
        self.encoder.float(bits).map_err(Into::into)
    }
    fn serialize_char(self, value: char) -> Result<(), Self::Error> {
        let mut buffer = [0; 4];
        self.serialize_str(value.encode_utf8(&mut buffer))
    }
    fn serialize_str(self, value: &str) -> Result<(), Self::Error> {
        self.encoder.text(value).map_err(Into::into)
    }
    fn serialize_bytes(self, value: &[u8]) -> Result<(), Self::Error> {
        self.encoder.bytes(value).map_err(Into::into)
    }
    fn serialize_none(self) -> Result<(), Self::Error> {
        self.encoder
            .map(1, |map| map.entry("none", Encoder::null))
            .map_err(Into::into)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<(), Self::Error> {
        self.encoder.map_header(1)?;
        self.encoder.write_map_key("some")?;
        serialize_nested(value, self.encoder, self.mode)?;
        self.encoder.finish_container().map_err(Into::into)
    }
    fn serialize_unit(self) -> Result<(), Self::Error> {
        self.encoder.null().map_err(Into::into)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), Self::Error> {
        self.serialize_unit()
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<(), Self::Error> {
        self.encoder.text(variant).map_err(Into::into)
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.encoder.map_header(1)?;
        self.encoder.write_map_key(variant)?;
        serialize_nested(value, self.encoder, self.mode)?;
        self.encoder.finish_container().map_err(Into::into)
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        let Some(len) = len else {
            return reject(self.encoder, ErrorCode::IndefiniteLengthForbidden);
        };
        self.encoder.array_header(len)?;
        Ok(Sequence::new(self.encoder, len, 1, self.mode))
    }
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.encoder.array_header(len)?;
        Ok(Sequence::new(self.encoder, len, 1, self.mode))
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.serialize_tuple(len)
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.encoder.map_header(1)?;
        self.encoder.write_map_key(variant)?;
        self.encoder.array_header(len)?;
        Ok(Sequence::new(self.encoder, len, 2, self.mode))
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        let Some(len) = len else {
            return reject(self.encoder, ErrorCode::IndefiniteLengthForbidden);
        };
        match self.mode {
            MapKeyMode::Strict => self.encoder.map_header(len)?,
            MapKeyMode::Sort => {}
        }
        MapSerializer::new(self.encoder, len, self.mode)
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        StructSerializer::new(self.encoder, len, 0, None, self.mode)
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        StructSerializer::new(self.encoder, len, 1, Some(variant), self.mode)
    }
}

struct Sequence<'a, S: ByteSink> {
    encoder: &'a mut Encoder<S>,
    remaining: usize,
    containers: usize,
    mode: MapKeyMode,
    finished: bool,
}

impl<'a, S: ByteSink> Sequence<'a, S> {
    const fn new(
        encoder: &'a mut Encoder<S>,
        remaining: usize,
        containers: usize,
        mode: MapKeyMode,
    ) -> Self {
        Self {
            encoder,
            remaining,
            containers,
            mode,
            finished: false,
        }
    }
}

impl<S> SerializeSeq for Sequence<'_, S>
where
    S: ByteSink,
    S::Error: fmt::Debug + fmt::Display,
{
    type Ok = ();
    type Error = SerdeEncodeError<S::Error>;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        ensure_healthy(self.encoder)?;
        if self.remaining == 0 {
            return reject(self.encoder, ErrorCode::ArrayLenMismatch);
        }
        serialize_nested(value, self.encoder, self.mode)?;
        self.remaining -= 1;
        Ok(())
    }

    fn end(mut self) -> Result<(), Self::Error> {
        ensure_healthy(self.encoder)?;
        if self.remaining != 0 {
            return reject(self.encoder, ErrorCode::ArrayLenMismatch);
        }
        for _ in 0..self.containers {
            self.encoder.finish_container()?;
        }
        self.finished = true;
        Ok(())
    }
}

impl<S> ser::SerializeTuple for Sequence<'_, S>
where
    S: ByteSink,
    S::Error: fmt::Debug + fmt::Display,
{
    type Ok = ();
    type Error = SerdeEncodeError<S::Error>;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<(), Self::Error> {
        SerializeSeq::end(self)
    }
}

impl<S> ser::SerializeTupleStruct for Sequence<'_, S>
where
    S: ByteSink,
    S::Error: fmt::Debug + fmt::Display,
{
    type Ok = ();
    type Error = SerdeEncodeError<S::Error>;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<(), Self::Error> {
        SerializeSeq::end(self)
    }
}

impl<S> ser::SerializeTupleVariant for Sequence<'_, S>
where
    S: ByteSink,
    S::Error: fmt::Debug + fmt::Display,
{
    type Ok = ();
    type Error = SerdeEncodeError<S::Error>;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<(), Self::Error> {
        SerializeSeq::end(self)
    }
}

impl<S: ByteSink> Drop for Sequence<'_, S> {
    fn drop(&mut self) {
        if !self.finished {
            self.encoder.poison();
        }
    }
}

struct Entry {
    key: String,
    value: Vec<u8>,
}

struct EntryBuffer {
    entries: Vec<Entry>,
    remaining: usize,
    budget: BufferedBudget,
}

struct BufferedBudget {
    limits: EncodeLimits,
    remaining_output: usize,
    remaining_items: usize,
    value_depth: usize,
}

fn encoded_text_len(len: usize) -> Result<usize, CborError> {
    let length = u64::try_from(len).map_err(|_| CborError::new(ErrorCode::LengthOverflow, 0))?;
    let (_, header_len) = major_uint_header(3, length);
    header_len
        .checked_add(len)
        .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, 0))
}

impl BufferedBudget {
    fn new<S: ByteSink>(
        encoder: &Encoder<S>,
        len: usize,
    ) -> Result<Self, SerdeEncodeError<S::Error>> {
        let (header_len, items_after_header) = encoder.preflight_buffered_map(len)?;
        let limits = encoder.encode_limits();
        let used_output = encoder.len().checked_add(header_len).ok_or_else(|| {
            SerdeEncodeError::from(CborError::new(ErrorCode::LengthOverflow, encoder.len()))
        })?;
        let remaining_output = limits
            .max_output_bytes
            .checked_sub(used_output)
            .ok_or_else(|| {
                SerdeEncodeError::from(CborError::new(
                    ErrorCode::MessageLenLimitExceeded,
                    encoder.len(),
                ))
            })?;
        let remaining_items = limits
            .max_total_items
            .checked_sub(items_after_header)
            .ok_or_else(|| {
                SerdeEncodeError::from(CborError::new(
                    ErrorCode::TotalItemsLimitExceeded,
                    encoder.len(),
                ))
            })?;
        let map_depth = encoder.container_depth().checked_add(1).ok_or_else(|| {
            SerdeEncodeError::from(CborError::new(ErrorCode::LengthOverflow, encoder.len()))
        })?;
        let value_depth = limits.max_depth.checked_sub(map_depth).ok_or_else(|| {
            SerdeEncodeError::from(CborError::new(ErrorCode::DepthLimitExceeded, encoder.len()))
        })?;
        Ok(Self {
            limits,
            remaining_output,
            remaining_items,
            value_depth,
        })
    }

    fn check_key(&self, key: &str) -> Result<usize, CborError> {
        if key.len() > self.limits.max_text_len {
            return Err(CborError::new(ErrorCode::TextLenLimitExceeded, 0));
        }
        let encoded = encoded_text_len(key.len())?;
        if encoded > self.remaining_output {
            return Err(CborError::new(ErrorCode::MessageLenLimitExceeded, 0));
        }
        Ok(encoded)
    }

    fn value_limits(&self, key_len: usize) -> Result<EncodeLimits, CborError> {
        let max_output_bytes = self
            .remaining_output
            .checked_sub(key_len)
            .ok_or_else(|| CborError::new(ErrorCode::MessageLenLimitExceeded, 0))?;
        Ok(EncodeLimits {
            max_output_bytes,
            max_depth: self.value_depth,
            max_total_items: self.remaining_items,
            max_array_len: self.limits.max_array_len,
            max_map_len: self.limits.max_map_len,
            max_bytes_len: self.limits.max_bytes_len,
            max_text_len: self.limits.max_text_len,
        })
    }

    const fn commit(&mut self, key_len: usize, value_len: usize, items: usize) {
        self.remaining_output -= key_len + value_len;
        self.remaining_items -= items;
    }
}

impl EntryBuffer {
    fn new<S: ByteSink>(
        encoder: &mut Encoder<S>,
        remaining: usize,
    ) -> Result<Self, SerdeEncodeError<S::Error>> {
        let budget = match BufferedBudget::new(encoder, remaining) {
            Ok(budget) => budget,
            Err(error) => {
                encoder.poison();
                return Err(error);
            }
        };
        let entries = match alloc_util::try_vec_with_capacity(remaining, encoder.len()) {
            Ok(entries) => entries,
            Err(error) => {
                encoder.poison();
                return Err(SerdeEncodeError::from(error));
            }
        };
        Ok(Self {
            entries,
            remaining,
            budget,
        })
    }

    fn push<T, S>(
        &mut self,
        outer: &mut Encoder<S>,
        key: String,
        value: &T,
        mode: MapKeyMode,
    ) -> Result<(), SerdeEncodeError<S::Error>>
    where
        T: Serialize + ?Sized,
        S: ByteSink,
        S::Error: fmt::Debug + fmt::Display,
    {
        if self.remaining == 0 {
            return reject(outer, ErrorCode::MapLenMismatch);
        }
        let outer_offset = outer.len();
        let relocate = |error: CborError| CborError::new(error.code, outer_offset);
        let key_len = self.budget.check_key(&key).map_err(relocate)?;
        let limits = self.budget.value_limits(key_len).map_err(relocate)?;
        let mut encoder = Encoder::with_limits(limits)
            .map_err(relocate)
            .map_err(SerdeEncodeError::from)?;
        serialize_nested(value, &mut encoder, mode).map_err(|error| {
            let cbor = vector_error(error);
            SerdeEncodeError::Encode(EncodeError::Cbor(relocate(cbor)))
        })?;
        let items = encoder.items_seen();
        let value = encoder.finish().map_err(|error| {
            let error = match error {
                EncodeError::Cbor(error) | EncodeError::Sink(error) => error,
                EncodeError::Poisoned => CborError::new(ErrorCode::EncoderPoisoned, 0),
            };
            SerdeEncodeError::Encode(EncodeError::Cbor(relocate(error)))
        })?;
        self.budget.commit(key_len, value.len(), items);
        self.entries.push(Entry { key, value });
        self.remaining -= 1;
        Ok(())
    }

    fn emit<S>(&mut self, encoder: &mut Encoder<S>) -> Result<(), SerdeEncodeError<S::Error>>
    where
        S: ByteSink,
        S::Error: fmt::Debug + fmt::Display,
    {
        if self.remaining != 0 {
            return reject(encoder, ErrorCode::MapLenMismatch);
        }
        self.entries
            .sort_unstable_by(|left, right| cmp_text_keys_canonical(&left.key, &right.key));
        for pair in self.entries.windows(2) {
            if pair[0].key == pair[1].key {
                return reject(encoder, ErrorCode::DuplicateMapKey);
            }
        }
        encoder.map_header(self.entries.len())?;
        for entry in self.entries.drain(..) {
            encoder.write_map_key(&entry.key)?;
            encoder.raw_trusted_canonical_bytes(&entry.value)?;
        }
        encoder.finish_container()?;
        Ok(())
    }
}

enum MapStorage {
    Strict {
        previous_key: Option<String>,
        value_pending: bool,
    },
    Sorted {
        entries: EntryBuffer,
        pending_key: Option<String>,
    },
}

struct MapSerializer<'a, S: ByteSink> {
    encoder: &'a mut Encoder<S>,
    remaining: usize,
    mode: MapKeyMode,
    storage: MapStorage,
    finished: bool,
}

impl<'a, S: ByteSink> MapSerializer<'a, S> {
    fn new(
        encoder: &'a mut Encoder<S>,
        remaining: usize,
        mode: MapKeyMode,
    ) -> Result<Self, SerdeEncodeError<S::Error>> {
        let storage = match mode {
            MapKeyMode::Strict => MapStorage::Strict {
                previous_key: None,
                value_pending: false,
            },
            MapKeyMode::Sort => MapStorage::Sorted {
                entries: EntryBuffer::new(encoder, remaining)?,
                pending_key: None,
            },
        };
        Ok(Self {
            encoder,
            remaining,
            mode,
            storage,
            finished: false,
        })
    }

    fn write_strict_key(&mut self, key: String) -> Result<(), SerdeEncodeError<S::Error>>
    where
        S::Error: fmt::Debug + fmt::Display,
    {
        ensure_healthy(self.encoder)?;
        let MapStorage::Strict {
            previous_key,
            value_pending,
        } = &mut self.storage
        else {
            return reject(self.encoder, ErrorCode::SerdeError);
        };
        if *value_pending || self.remaining == 0 {
            return reject(self.encoder, ErrorCode::MapLenMismatch);
        }
        if let Some(previous) = previous_key.as_deref() {
            match cmp_text_keys_canonical(previous, &key) {
                core::cmp::Ordering::Less => {}
                core::cmp::Ordering::Equal => {
                    return reject(self.encoder, ErrorCode::DuplicateMapKey)
                }
                core::cmp::Ordering::Greater => {
                    return reject(self.encoder, ErrorCode::NonCanonicalMapOrder)
                }
            }
        }
        self.encoder.write_map_key(&key)?;
        *previous_key = Some(key);
        *value_pending = true;
        Ok(())
    }
}

impl<S> SerializeMap for MapSerializer<'_, S>
where
    S: ByteSink,
    S::Error: fmt::Debug + fmt::Display,
{
    type Ok = ();
    type Error = SerdeEncodeError<S::Error>;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Self::Error> {
        ensure_healthy(self.encoder)?;
        if self.remaining == 0 {
            return reject(self.encoder, ErrorCode::MapLenMismatch);
        }
        let (max_text_len, max_output_bytes) = match &self.storage {
            MapStorage::Strict { value_pending, .. } => {
                if *value_pending {
                    return reject(self.encoder, ErrorCode::MapLenMismatch);
                }
                let limits = self.encoder.encode_limits();
                let remaining = limits
                    .max_output_bytes
                    .checked_sub(self.encoder.len())
                    .ok_or_else(|| code_error(ErrorCode::MessageLenLimitExceeded));
                let remaining = match remaining {
                    Ok(remaining) => remaining,
                    Err(error) => {
                        self.encoder.poison();
                        return Err(error);
                    }
                };
                (limits.max_text_len, remaining)
            }
            MapStorage::Sorted {
                entries,
                pending_key,
            } => {
                if pending_key.is_some() {
                    return reject(self.encoder, ErrorCode::MapLenMismatch);
                }
                (
                    entries.budget.limits.max_text_len,
                    entries.budget.remaining_output,
                )
            }
        };
        let key = match key.serialize(KeySerializer {
            max_text_len,
            max_output_bytes,
            offset: self.encoder.len(),
        }) {
            Ok(key) => key,
            Err(error) => {
                self.encoder.poison();
                return Err(SerdeEncodeError::from(error));
            }
        };
        match &mut self.storage {
            MapStorage::Strict { .. } => self.write_strict_key(key),
            MapStorage::Sorted { pending_key, .. } => {
                if pending_key.is_some() || self.remaining == 0 {
                    return reject(self.encoder, ErrorCode::MapLenMismatch);
                }
                *pending_key = Some(key);
                Ok(())
            }
        }
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        ensure_healthy(self.encoder)?;
        let result = match &mut self.storage {
            MapStorage::Strict { value_pending, .. } => {
                if !*value_pending {
                    return reject(self.encoder, ErrorCode::SerdeError);
                }
                serialize_nested(value, self.encoder, self.mode)?;
                *value_pending = false;
                Ok(())
            }
            MapStorage::Sorted {
                entries,
                pending_key,
            } => {
                let Some(key) = pending_key.take() else {
                    return reject(self.encoder, ErrorCode::SerdeError);
                };
                entries.push(self.encoder, key, value, self.mode)
            }
        };
        if result.is_err() {
            self.encoder.poison();
        }
        result?;
        self.remaining -= 1;
        Ok(())
    }

    fn serialize_entry<K: Serialize + ?Sized, V: Serialize + ?Sized>(
        &mut self,
        key: &K,
        value: &V,
    ) -> Result<(), Self::Error> {
        self.serialize_key(key)?;
        self.serialize_value(value)
    }

    fn end(mut self) -> Result<(), Self::Error> {
        ensure_healthy(self.encoder)?;
        if self.remaining != 0 {
            return reject(self.encoder, ErrorCode::MapLenMismatch);
        }
        match &mut self.storage {
            MapStorage::Strict { value_pending, .. } => {
                if *value_pending {
                    return reject(self.encoder, ErrorCode::SerdeError);
                }
                self.encoder.finish_container()?;
            }
            MapStorage::Sorted {
                entries,
                pending_key,
            } => {
                if pending_key.is_some() {
                    return reject(self.encoder, ErrorCode::SerdeError);
                }
                entries.emit(self.encoder)?;
            }
        }
        self.finished = true;
        Ok(())
    }
}

impl<S: ByteSink> Drop for MapSerializer<'_, S> {
    fn drop(&mut self) {
        if !self.finished {
            self.encoder.poison();
        }
    }
}

enum StructStorage {
    Strict {
        previous_key: Option<&'static str>,
        remaining: usize,
    },
    Sorted(EntryBuffer),
}

struct StructSerializer<'a, S: ByteSink> {
    encoder: &'a mut Encoder<S>,
    storage: StructStorage,
    outer_maps: usize,
    mode: MapKeyMode,
    finished: bool,
}

impl<'a, S> StructSerializer<'a, S>
where
    S: ByteSink,
    S::Error: fmt::Debug + fmt::Display,
{
    fn new(
        encoder: &'a mut Encoder<S>,
        len: usize,
        outer_maps: usize,
        variant: Option<&'static str>,
        mode: MapKeyMode,
    ) -> Result<Self, SerdeEncodeError<S::Error>> {
        if let Some(variant) = variant {
            encoder.map_header(1)?;
            encoder.write_map_key(variant)?;
        }
        let storage = match mode {
            MapKeyMode::Strict => {
                encoder.map_header(len)?;
                StructStorage::Strict {
                    previous_key: None,
                    remaining: len,
                }
            }
            MapKeyMode::Sort => StructStorage::Sorted(EntryBuffer::new(encoder, len)?),
        };
        Ok(Self {
            encoder,
            storage,
            outer_maps,
            mode,
            finished: false,
        })
    }

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), SerdeEncodeError<S::Error>> {
        ensure_healthy(self.encoder)?;
        match &mut self.storage {
            StructStorage::Strict {
                previous_key,
                remaining,
            } => {
                if *remaining == 0 {
                    return reject(self.encoder, ErrorCode::MapLenMismatch);
                }
                if let Err(error) = self.encoder.check_text_len(key.len()) {
                    self.encoder.poison();
                    return Err(SerdeEncodeError::from(error));
                }
                if let Some(previous_key) = *previous_key {
                    match cmp_text_keys_canonical(previous_key, key) {
                        core::cmp::Ordering::Less => {}
                        core::cmp::Ordering::Equal => {
                            return reject(self.encoder, ErrorCode::DuplicateMapKey)
                        }
                        core::cmp::Ordering::Greater => {
                            return reject(self.encoder, ErrorCode::NonCanonicalMapOrder)
                        }
                    }
                }
                self.encoder.write_map_key(key)?;
                *previous_key = Some(key);
                serialize_nested(value, self.encoder, self.mode)?;
                *remaining -= 1;
                Ok(())
            }
            StructStorage::Sorted(entries) => {
                if let Err(error) = entries.budget.check_key(key) {
                    let error = CborError::new(error.code, self.encoder.len());
                    self.encoder.poison();
                    return Err(SerdeEncodeError::from(error));
                }
                let key = match alloc_util::try_string_from_str(key, self.encoder.len()) {
                    Ok(key) => key,
                    Err(error) => {
                        self.encoder.poison();
                        return Err(SerdeEncodeError::from(error));
                    }
                };
                let result = entries.push(self.encoder, key, value, self.mode);
                if result.is_err() {
                    self.encoder.poison();
                }
                result
            }
        }
    }

    fn finish(mut self) -> Result<(), SerdeEncodeError<S::Error>> {
        ensure_healthy(self.encoder)?;
        match &mut self.storage {
            StructStorage::Strict { remaining, .. } => {
                if *remaining != 0 {
                    return reject(self.encoder, ErrorCode::MapLenMismatch);
                }
                self.encoder.finish_container()?;
            }
            StructStorage::Sorted(entries) => entries.emit(self.encoder)?,
        }
        for _ in 0..self.outer_maps {
            self.encoder.finish_container()?;
        }
        self.finished = true;
        Ok(())
    }
}

impl<S> ser::SerializeStruct for StructSerializer<'_, S>
where
    S: ByteSink,
    S::Error: fmt::Debug + fmt::Display,
{
    type Ok = ();
    type Error = SerdeEncodeError<S::Error>;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        StructSerializer::serialize_field(self, key, value)
    }
    fn end(self) -> Result<(), Self::Error> {
        self.finish()
    }
}

impl<S> ser::SerializeStructVariant for StructSerializer<'_, S>
where
    S: ByteSink,
    S::Error: fmt::Debug + fmt::Display,
{
    type Ok = ();
    type Error = SerdeEncodeError<S::Error>;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        ser::SerializeStruct::serialize_field(self, key, value)
    }
    fn end(self) -> Result<(), Self::Error> {
        self.finish()
    }
}

impl<S: ByteSink> Drop for StructSerializer<'_, S> {
    fn drop(&mut self) {
        if !self.finished {
            self.encoder.poison();
        }
    }
}

#[derive(Debug)]
struct KeyError(CborError);

#[cfg(feature = "std")]
impl std::error::Error for KeyError {}

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

impl ser::Error for KeyError {
    fn custom<T: fmt::Display>(_message: T) -> Self {
        Self(CborError::new(ErrorCode::MapKeyMustBeText, 0))
    }
}

impl<E> From<KeyError> for SerdeEncodeError<E> {
    fn from(error: KeyError) -> Self {
        error.0.into()
    }
}

struct KeySerializer {
    max_text_len: usize,
    max_output_bytes: usize,
    offset: usize,
}

impl KeySerializer {
    const fn reject<T>(self) -> Result<T, KeyError> {
        Err(KeyError(CborError::new(
            ErrorCode::MapKeyMustBeText,
            self.offset,
        )))
    }
}

macro_rules! reject_key {
    ($($method:ident($ty:ty)),* $(,)?) => {
        $(fn $method(self, _value: $ty) -> Result<Self::Ok, Self::Error> {
            self.reject()
        })*
    };
}

impl ser::Serializer for KeySerializer {
    type Ok = String;
    type Error = KeyError;
    type SerializeSeq = ser::Impossible<String, KeyError>;
    type SerializeTuple = ser::Impossible<String, KeyError>;
    type SerializeTupleStruct = ser::Impossible<String, KeyError>;
    type SerializeTupleVariant = ser::Impossible<String, KeyError>;
    type SerializeMap = ser::Impossible<String, KeyError>;
    type SerializeStruct = ser::Impossible<String, KeyError>;
    type SerializeStructVariant = ser::Impossible<String, KeyError>;

    fn serialize_str(self, value: &str) -> Result<String, KeyError> {
        if value.len() > self.max_text_len {
            return Err(KeyError(CborError::new(
                ErrorCode::TextLenLimitExceeded,
                self.offset,
            )));
        }
        let encoded = encoded_text_len(value.len()).map_err(KeyError)?;
        if encoded > self.max_output_bytes {
            return Err(KeyError(CborError::new(
                ErrorCode::MessageLenLimitExceeded,
                self.offset,
            )));
        }
        alloc_util::try_string_from_str(value, self.offset).map_err(KeyError)
    }
    fn serialize_char(self, value: char) -> Result<String, KeyError> {
        let mut buffer = [0; 4];
        self.serialize_str(value.encode_utf8(&mut buffer))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<String, KeyError> {
        value.serialize(self)
    }

    reject_key!(
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_i128(i128),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_u128(u128),
        serialize_f32(f32),
        serialize_f64(f64),
        serialize_bytes(&[u8])
    );

    fn serialize_none(self) -> Result<String, KeyError> {
        self.reject()
    }
    fn serialize_some<T: Serialize + ?Sized>(self, _value: &T) -> Result<String, KeyError> {
        self.reject()
    }
    fn serialize_unit(self) -> Result<String, KeyError> {
        self.reject()
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<String, KeyError> {
        self.reject()
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
    ) -> Result<String, KeyError> {
        self.reject()
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<String, KeyError> {
        self.reject()
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, KeyError> {
        self.reject()
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, KeyError> {
        self.reject()
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, KeyError> {
        self.reject()
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, KeyError> {
        self.reject()
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, KeyError> {
        self.reject()
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, KeyError> {
        self.reject()
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, KeyError> {
        self.reject()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_poisoned(encoder: &mut Encoder) {
        assert!(matches!(encoder.null(), Err(EncodeError::Poisoned)));
    }

    #[test]
    fn sorted_map_start_preflight_error_poison_is_immediate() {
        let limits = EncodeLimits {
            max_map_len: 0,
            ..EncodeLimits::unbounded()
        };
        let mut encoder = Encoder::with_limits(limits).unwrap();
        let result = ser::Serializer::serialize_map(
            Serializer {
                encoder: &mut encoder,
                mode: MapKeyMode::Sort,
            },
            Some(1),
        );
        assert!(result.is_err());
        drop(result);
        assert_poisoned(&mut encoder);
    }

    #[test]
    fn sorted_struct_start_preflight_error_poison_is_immediate() {
        let limits = EncodeLimits {
            max_map_len: 0,
            ..EncodeLimits::unbounded()
        };
        let mut encoder = Encoder::with_limits(limits).unwrap();
        let result = ser::Serializer::serialize_struct(
            Serializer {
                encoder: &mut encoder,
                mode: MapKeyMode::Sort,
            },
            "TooLarge",
            1,
        );
        assert!(result.is_err());
        drop(result);
        assert_poisoned(&mut encoder);
    }

    #[test]
    fn float_conversion_error_poison_is_immediate() {
        let mut encoder = Encoder::new();
        let result = ser::Serializer::serialize_f64(
            Serializer {
                encoder: &mut encoder,
                mode: MapKeyMode::Strict,
            },
            -0.0,
        );
        assert!(matches!(
            result,
            Err(SerdeEncodeError::Encode(EncodeError::Cbor(error)))
                if error.code == ErrorCode::NegativeZeroForbidden
        ));
        assert_poisoned(&mut encoder);
    }
}
