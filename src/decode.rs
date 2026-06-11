//! Streaming decoder and exact core type implementations.

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "collections")]
use alloc::vec::Vec;
use core::ops::Range;

#[cfg(feature = "alloc")]
use crate::alloc_util;
use crate::bytes::BytesRef;
use crate::canonical::CanonicalCborRef;
use crate::codec::CborDecode;
use crate::profile::{validate_f64_bits, MAX_SAFE_INTEGER};
use crate::query::{peek_kind_at, CborKind, CborValueRef};
use crate::wire::{self, Cursor};
use crate::{CborError, DecodeLimits, ErrorCode};

#[cfg(feature = "alloc")]
use crate::bytes::Bytes;
#[cfg(feature = "alloc")]
use crate::value::{BigInt, Integer};
#[cfg(feature = "alloc")]
use crate::CanonicalCbor;

/// A CBOR map represented as ordered key/value entries.
#[cfg(feature = "collections")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapEntries<K, V>(pub Vec<(K, V)>);

#[cfg(feature = "collections")]
impl<K, V> MapEntries<K, V> {
    /// Wrap an existing vector of entries.
    #[must_use]
    pub const fn new(entries: Vec<(K, V)>) -> Self {
        Self(entries)
    }
}

/// Streaming decoder over canonical CBOR bytes.
pub struct Decoder<'de, const CHECKED: bool> {
    cursor: Cursor<'de>,
    limits: DecodeLimits,
    depth: usize,
    items_seen: usize,
    poison: Option<CborError>,
    scratch: wire::SkipScratch,
}

/// Array decoder guard that manages depth and length.
///
/// Dropping the guard before all declared elements are consumed poisons the parent decoder. Later
/// operations on that decoder return the stored malformed-canonical error.
pub struct ArrayDecoder<'a, 'de, const CHECKED: bool> {
    decoder: &'a mut Decoder<'de, CHECKED>,
    remaining: usize,
    entered: bool,
}

/// Map decoder guard that manages depth, length, and key ordering.
///
/// Dropping the guard before all declared entries are consumed, or while a key is waiting for its
/// value, poisons the parent decoder. Later operations on that decoder return the stored
/// malformed-canonical error.
pub struct MapDecoder<'a, 'de, const CHECKED: bool> {
    decoder: &'a mut Decoder<'de, CHECKED>,
    remaining: usize,
    entered: bool,
    pending_value: bool,
    prev_key_range: Option<(usize, usize)>,
}

/// Text key metadata returned by [`MapDecoder::next_key_ref`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapKey<'de> {
    /// Decoded text key.
    pub text: &'de str,
    /// Offset of the encoded text key inside the input.
    pub offset: usize,
    /// Byte range occupied by the encoded text key.
    pub encoded_range: Range<usize>,
}

impl<const CHECKED: bool> Drop for ArrayDecoder<'_, '_, CHECKED> {
    fn drop(&mut self) {
        if self.entered {
            if self.remaining != 0 {
                let off = self.decoder.position();
                self.decoder.poison(ErrorCode::MalformedCanonical, off);
            }
            self.decoder.exit_container();
        }
    }
}

impl<const CHECKED: bool> Drop for MapDecoder<'_, '_, CHECKED> {
    fn drop(&mut self) {
        if self.entered {
            if self.remaining != 0 || self.pending_value {
                let off = self.decoder.position();
                self.decoder.poison(ErrorCode::MalformedCanonical, off);
            }
            self.decoder.exit_container();
        }
    }
}

impl<'de> Decoder<'de, true> {
    /// Construct a decoder that enforces canonical constraints while decoding.
    ///
    /// # Errors
    ///
    /// Returns `MessageLenLimitExceeded` if `bytes` exceeds the input limit.
    pub const fn new_checked(bytes: &'de [u8], limits: DecodeLimits) -> Result<Self, CborError> {
        Self::new_with(bytes, limits)
    }
}

impl<'de> Decoder<'de, false> {
    /// Construct a decoder over canonical bytes with the provided limits.
    ///
    /// This assumes the input is already canonical.
    ///
    /// # Errors
    ///
    /// Returns `MessageLenLimitExceeded` if `bytes` exceeds the input limit.
    pub const fn new_trusted(
        canon: CanonicalCborRef<'de>,
        limits: DecodeLimits,
    ) -> Result<Self, CborError> {
        Self::new_with(canon.as_bytes(), limits)
    }
}

impl<'de, const CHECKED: bool> Decoder<'de, CHECKED> {
    const fn new_with(bytes: &'de [u8], limits: DecodeLimits) -> Result<Self, CborError> {
        if let Err(err) = limits.validate() {
            return Err(err);
        }
        if bytes.len() > limits.max_input_bytes {
            return Err(CborError::new(ErrorCode::MessageLenLimitExceeded, 0));
        }
        Ok(Self {
            cursor: Cursor::with_pos(bytes, 0),
            limits,
            depth: 0,
            items_seen: 0,
            poison: None,
            scratch: wire::SkipScratch::new(),
        })
    }

    /// Return the current byte offset in the input.
    #[must_use]
    #[inline]
    pub const fn position(&self) -> usize {
        self.cursor.position()
    }

    #[inline]
    pub(crate) const fn data(&self) -> &'de [u8] {
        self.cursor.data()
    }

    #[inline]
    fn read_header(&mut self) -> Result<(u8, u8, usize), CborError> {
        self.check_poison()?;
        let off = self.cursor.position();
        let ib = self.cursor.read_u8()?;
        Ok((ib >> 5, ib & 0x1f, off))
    }

    #[inline]
    fn read_uint_arg(&mut self, ai: u8, off: usize) -> Result<u64, CborError> {
        wire::read_uint_arg::<CHECKED>(&mut self.cursor, ai, off)
    }

    #[inline]
    fn read_len(&mut self, ai: u8, off: usize) -> Result<usize, CborError> {
        wire::read_len::<CHECKED>(&mut self.cursor, ai, off)
    }

    #[inline]
    fn bump_items(&mut self, add: usize, off: usize) -> Result<(), CborError> {
        self.items_seen = self
            .items_seen
            .checked_add(add)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
        if self.items_seen > self.limits.max_total_items {
            return Err(CborError::new(ErrorCode::TotalItemsLimitExceeded, off));
        }
        Ok(())
    }

    #[inline]
    fn enter_container(&mut self, len: usize, off: usize) -> Result<bool, CborError> {
        let next_depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
        if next_depth > self.limits.max_depth {
            return Err(CborError::new(ErrorCode::DepthLimitExceeded, off));
        }
        if len == 0 {
            return Ok(false);
        }
        self.depth = next_depth;
        Ok(true)
    }

    #[inline]
    fn exit_container(&mut self) {
        debug_assert!(self.depth > 0);
        self.depth = self.depth.saturating_sub(1);
    }

    #[inline]
    const fn check_poison(&self) -> Result<(), CborError> {
        if let Some(err) = self.poison {
            return Err(err);
        }
        Ok(())
    }

    #[inline]
    fn poison(&mut self, code: ErrorCode, offset: usize) {
        if self.poison.is_none() {
            self.poison = Some(CborError::new(code, offset));
        }
    }

    #[inline]
    fn parse_text_from_header(&mut self, off: usize, ai: u8) -> Result<&'de str, CborError> {
        wire::parse_text_from_header::<CHECKED>(&mut self.cursor, Some(&self.limits), off, ai)
    }

    #[inline]
    fn parse_bytes_from_header(&mut self, off: usize, ai: u8) -> Result<&'de [u8], CborError> {
        let len = self.read_len(ai, off)?;
        if len > self.limits.max_bytes_len {
            return Err(CborError::new(ErrorCode::BytesLenLimitExceeded, off));
        }
        self.cursor.read_exact(len)
    }

    #[inline]
    fn parse_bignum(&mut self, off: usize, ai: u8) -> Result<(bool, &'de [u8]), CborError> {
        wire::parse_bignum::<CHECKED>(&mut self.cursor, Some(&self.limits), off, ai)
    }

    fn parse_integer_i128(&mut self) -> Result<i128, CborError> {
        let (major, ai, off) = self.read_header()?;
        match major {
            0 => {
                let v = self.read_uint_arg(ai, off)?;
                if CHECKED && v > MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                Ok(i128::from(v))
            }
            1 => {
                let n = self.read_uint_arg(ai, off)?;
                if CHECKED && n >= MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                Ok(-1 - i128::from(n))
            }
            6 => {
                let (negative, mag) = self.parse_bignum(off, ai)?;
                let n = crate::int::magnitude_to_u128(mag)
                    .ok_or_else(|| CborError::new(ErrorCode::ExpectedInteger, off))?;
                let n = i128::try_from(n)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))?;
                Ok(if negative { -1 - n } else { n })
            }
            _ => Err(CborError::new(ErrorCode::ExpectedInteger, off)),
        }
    }

    fn parse_integer_u128(&mut self) -> Result<u128, CborError> {
        let (major, ai, off) = self.read_header()?;
        match major {
            0 => {
                let v = self.read_uint_arg(ai, off)?;
                if CHECKED && v > MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                Ok(u128::from(v))
            }
            6 => {
                let (negative, mag) = self.parse_bignum(off, ai)?;
                if negative {
                    return Err(CborError::new(ErrorCode::ExpectedInteger, off));
                }
                crate::int::magnitude_to_u128(mag)
                    .ok_or_else(|| CborError::new(ErrorCode::ExpectedInteger, off))
            }
            _ => Err(CborError::new(ErrorCode::ExpectedInteger, off)),
        }
    }

    fn parse_float64(&mut self) -> Result<f64, CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 7 {
            return Err(CborError::new(ErrorCode::ExpectedFloat, off));
        }
        if ai != 27 {
            if !CHECKED {
                return Err(CborError::new(ErrorCode::ExpectedFloat, off));
            }
            return match ai {
                24 => {
                    let simple = self.cursor.read_u8()?;
                    if simple < 24 {
                        return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                    }
                    Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off))
                }
                28..=30 => Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
                25 | 26 => Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off)),
                _ => Err(CborError::new(ErrorCode::ExpectedFloat, off)),
            };
        }
        let bits = self.cursor.read_be_u64()?;
        if CHECKED {
            validate_f64_bits(bits).map_err(|code| CborError::new(code, off))?;
        }
        Ok(f64::from_bits(bits))
    }

    fn parse_bool(&mut self) -> Result<bool, CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 7 {
            return Err(CborError::new(ErrorCode::ExpectedBool, off));
        }
        match ai {
            20 => Ok(false),
            21 => Ok(true),
            22 | 27 => Err(CborError::new(ErrorCode::ExpectedBool, off)),
            _ => self.reject_unexpected_simple(ai, off, ErrorCode::ExpectedBool),
        }
    }

    fn parse_null(&mut self) -> Result<(), CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 7 {
            return Err(CborError::new(ErrorCode::ExpectedNull, off));
        }
        match ai {
            22 => Ok(()),
            20 | 21 | 27 => Err(CborError::new(ErrorCode::ExpectedNull, off)),
            _ => self.reject_unexpected_simple(ai, off, ErrorCode::ExpectedNull),
        }
    }

    fn reject_unexpected_simple<T>(
        &mut self,
        ai: u8,
        off: usize,
        expected: ErrorCode,
    ) -> Result<T, CborError> {
        match ai {
            24 => {
                if !CHECKED {
                    return Err(CborError::new(expected, off));
                }
                let simple = self.cursor.read_u8()?;
                if simple < 24 {
                    return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off))
            }
            28..=30 if CHECKED => Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
            _ if CHECKED => Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off)),
            _ => Err(CborError::new(expected, off)),
        }
    }

    fn parse_bytes(&mut self) -> Result<&'de [u8], CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 2 {
            return Err(CborError::new(ErrorCode::ExpectedBytes, off));
        }
        self.parse_bytes_from_header(off, ai)
    }

    fn parse_text(&mut self) -> Result<&'de str, CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 3 {
            return Err(CborError::new(ErrorCode::ExpectedText, off));
        }
        self.parse_text_from_header(off, ai)
    }

    /// Decode an array header and return a guard for its elements.
    ///
    /// # Errors
    ///
    /// Returns `ExpectedArray` if the next value is not an array, or a limit error.
    pub fn array(&mut self) -> Result<ArrayDecoder<'_, 'de, CHECKED>, CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 4 {
            return Err(CborError::new(ErrorCode::ExpectedArray, off));
        }
        let len = self.read_len(ai, off)?;
        if len > self.limits.max_array_len {
            return Err(CborError::new(ErrorCode::ArrayLenLimitExceeded, off));
        }
        self.bump_items(len, off)?;
        let entered = self.enter_container(len, off)?;
        Ok(ArrayDecoder {
            decoder: self,
            remaining: len,
            entered,
        })
    }

    /// Decode a map header and return a guard for its entries.
    ///
    /// # Errors
    ///
    /// Returns `ExpectedMap` if the next value is not a map, or a limit error.
    pub fn map(&mut self) -> Result<MapDecoder<'_, 'de, CHECKED>, CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 5 {
            return Err(CborError::new(ErrorCode::ExpectedMap, off));
        }
        let len = self.read_len(ai, off)?;
        if len > self.limits.max_map_len {
            return Err(CborError::new(ErrorCode::MapLenLimitExceeded, off));
        }
        let items = len
            .checked_mul(2)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
        self.bump_items(items, off)?;
        let entered = self.enter_container(len, off)?;
        Ok(MapDecoder {
            decoder: self,
            remaining: len,
            entered,
            pending_value: false,
            prev_key_range: None,
        })
    }

    /// Skip exactly one CBOR value while enforcing decode limits.
    ///
    /// # Errors
    ///
    /// Returns a decode error if the value is malformed or violates limits.
    pub fn skip_value(&mut self) -> Result<(), CborError> {
        self.check_poison()?;
        wire::skip_one_value_with_scratch::<CHECKED>(
            &mut self.cursor,
            wire::WalkPolicy::new(Some(&self.limits), crate::ValidationOptions::new()),
            &mut self.items_seen,
            self.depth,
            &mut self.scratch,
        )
    }

    /// Peek at the kind of the next CBOR value without consuming it.
    ///
    /// # Errors
    ///
    /// Returns a decode error if the header is malformed.
    pub fn peek_kind(&self) -> Result<CborKind, CborError> {
        self.check_poison()?;
        let mut pos = self.cursor.position();
        peek_kind_at::<CHECKED>(self.data(), &mut pos)
    }
}

impl<'de, const CHECKED: bool> ArrayDecoder<'_, 'de, CHECKED> {
    /// Remaining elements in the array.
    #[inline]
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.remaining
    }

    /// Decode the next array element.
    ///
    /// Returns `Ok(None)` when the array is exhausted.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails.
    pub fn next_value<T: CborDecode<'de>>(&mut self) -> Result<Option<T>, CborError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let value = T::decode(self.decoder)?;
        self.remaining -= 1;
        Ok(Some(value))
    }

    /// Decode the next array element using a custom decoder.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails.
    pub fn decode_next<F, T>(&mut self, f: F) -> Result<Option<T>, CborError>
    where
        F: FnOnce(&mut Decoder<'de, CHECKED>) -> Result<T, CborError>,
    {
        if self.remaining == 0 {
            return Ok(None);
        }
        let value = f(self.decoder)?;
        self.remaining -= 1;
        Ok(Some(value))
    }

    /// Skip all remaining elements in the array.
    ///
    /// # Errors
    ///
    /// Returns an error if skipping fails.
    pub fn skip_remaining(&mut self) -> Result<(), CborError> {
        while self.remaining > 0 {
            self.decoder.skip_value()?;
            self.remaining -= 1;
        }
        Ok(())
    }
}

impl<'de, const CHECKED: bool> MapDecoder<'_, 'de, CHECKED> {
    /// Remaining entries in the map.
    #[inline]
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.remaining
    }

    /// Decode the next map key as text with source offsets.
    ///
    /// Returns `Ok(None)` when the map is exhausted.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails or the map is malformed.
    pub fn next_key_ref(&mut self) -> Result<Option<MapKey<'de>>, CborError> {
        if self.pending_value {
            return Err(CborError::new(
                ErrorCode::MalformedCanonical,
                self.decoder.position(),
            ));
        }
        if self.remaining == 0 {
            return Ok(None);
        }
        let key_start = self.decoder.position();
        let (major, ai, off) = self.decoder.read_header()?;
        if major != 3 {
            return Err(CborError::new(ErrorCode::MapKeyMustBeText, off));
        }
        let key = self.decoder.parse_text_from_header(off, ai)?;
        let key_end = self.decoder.position();
        if CHECKED {
            wire::check_map_key_order(
                self.decoder.data(),
                &mut self.prev_key_range,
                key_start,
                key_end,
            )?;
        }
        self.pending_value = true;
        Ok(Some(MapKey {
            text: key,
            offset: key_start,
            encoded_range: key_start..key_end,
        }))
    }

    /// Decode the value corresponding to the last returned key.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails or the map is malformed.
    pub fn next_value<T: CborDecode<'de>>(&mut self) -> Result<T, CborError> {
        self.decode_value(T::decode)
    }

    /// Decode the value corresponding to the last returned key using a custom decoder.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails or the map is malformed.
    pub fn decode_value<F, T>(&mut self, f: F) -> Result<T, CborError>
    where
        F: FnOnce(&mut Decoder<'de, CHECKED>) -> Result<T, CborError>,
    {
        if !self.pending_value {
            return Err(CborError::new(
                ErrorCode::MalformedCanonical,
                self.decoder.position(),
            ));
        }
        let value = f(self.decoder)?;
        self.pending_value = false;
        self.remaining -= 1;
        Ok(value)
    }

    /// Skip the value corresponding to the last returned key.
    ///
    /// # Errors
    ///
    /// Returns an error if no key is pending or if skipping fails.
    pub fn skip_value(&mut self) -> Result<(), CborError> {
        if !self.pending_value {
            return Err(CborError::new(
                ErrorCode::MalformedCanonical,
                self.decoder.position(),
            ));
        }
        self.decoder.skip_value()?;
        self.pending_value = false;
        self.remaining -= 1;
        Ok(())
    }

    /// Decode the next key/value entry in the map.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails or the map is malformed.
    pub fn next_entry<V: CborDecode<'de>>(&mut self) -> Result<Option<(&'de str, V)>, CborError> {
        let Some(key) = self.next_key_ref()? else {
            return Ok(None);
        };
        let value = self.next_value()?;
        Ok(Some((key.text, value)))
    }

    /// Skip all remaining map entries.
    ///
    /// # Errors
    ///
    /// Returns an error if skipping fails or the map is malformed.
    pub fn skip_remaining(&mut self) -> Result<(), CborError> {
        while self.remaining > 0 {
            if !self.pending_value {
                let _ = self.next_key_ref()?;
            }
            self.skip_value()?;
        }
        Ok(())
    }
}

/// Validate canonical CBOR and decode a value using `CborDecode`.
///
/// # Errors
///
/// Returns an error if the input is not canonical CBOR or if decoding fails.
pub fn decode<'de, T: CborDecode<'de>>(
    bytes: &'de [u8],
    limits: DecodeLimits,
) -> Result<T, CborError> {
    let mut decoder = Decoder::<true>::new_checked(bytes, limits)?;
    let value = T::decode(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, decoder.position()));
    }
    Ok(value)
}

/// Decode a value from validated canonical bytes.
///
/// # Errors
///
/// Returns an error if decoding fails.
pub fn decode_canonical<'de, T: CborDecode<'de>>(
    canon: CanonicalCborRef<'de>,
    limits: DecodeLimits,
) -> Result<T, CborError> {
    let mut decoder = Decoder::<false>::new_trusted(canon, limits)?;
    let value = T::decode(&mut decoder)?;
    if decoder.position() != canon.as_bytes().len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, decoder.position()));
    }
    Ok(value)
}

impl<'de> CborDecode<'de> for () {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        decoder.parse_null()
    }
}

#[allow(clippy::use_self)]
impl<'de> CborDecode<'de> for bool {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        decoder.parse_bool()
    }
}

impl<'de> CborDecode<'de> for i64 {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_i128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for i32 {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_i128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for i16 {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_i128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for i8 {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_i128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for isize {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_i128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for i128 {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        decoder.parse_integer_i128()
    }
}

impl<'de> CborDecode<'de> for u64 {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_u128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for u32 {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_u128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for u16 {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_u128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for u8 {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_u128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for usize {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_u128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for u128 {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        decoder.parse_integer_u128()
    }
}

#[cfg(feature = "alloc")]
impl<'de> CborDecode<'de> for BigInt {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let (major, ai, off) = decoder.read_header()?;
        if major != 6 {
            return Err(CborError::new(ErrorCode::ExpectedInteger, off));
        }
        let (negative, mag) = decoder.parse_bignum(off, ai)?;
        let magnitude = alloc_util::try_vec_from_slice(mag, off)?;
        Self::new(negative, magnitude).map_err(|err| CborError::new(err.code, off))
    }
}

#[cfg(feature = "alloc")]
impl<'de> CborDecode<'de> for Integer {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let (major, ai, off) = decoder.read_header()?;
        match major {
            0 => {
                let v = decoder.read_uint_arg(ai, off)?;
                if CHECKED && v > MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                let v_i = i64::try_from(v)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))?;
                Self::safe(v_i).map_err(|err| CborError::new(err.code, off))
            }
            1 => {
                let n = decoder.read_uint_arg(ai, off)?;
                if CHECKED && n >= MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                let n_i = i64::try_from(n)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))?;
                Self::safe(-1 - n_i).map_err(|err| CborError::new(err.code, off))
            }
            6 => {
                let (negative, mag) = decoder.parse_bignum(off, ai)?;
                let magnitude = alloc_util::try_vec_from_slice(mag, off)?;
                Self::big(negative, magnitude).map_err(|err| CborError::new(err.code, off))
            }
            _ => Err(CborError::new(ErrorCode::ExpectedInteger, off)),
        }
    }
}

impl<'de> CborDecode<'de> for f64 {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        decoder.parse_float64()
    }
}

impl<'de> CborDecode<'de> for f32 {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_float64()?;
        if v.is_nan() {
            return Ok(Self::NAN);
        }
        let bits = v.to_bits();
        let sign = ((bits >> 63) as u32) << 31;
        let exp = ((bits >> 52) & 0x7ff) as i32;
        let mant = bits & 0x000f_ffff_ffff_ffff;
        if exp == 0x7ff {
            if mant != 0 {
                return Ok(Self::NAN);
            }
            return Ok(Self::from_bits(sign | 0x7f80_0000));
        }
        if exp == 0 {
            if mant == 0 {
                return Ok(Self::from_bits(sign));
            }
            return Err(CborError::new(ErrorCode::ExpectedFloat, off));
        }

        let e = exp - 1023;
        let mant_with_hidden = (1u64 << 52) | mant;
        if e > 127 {
            return Err(CborError::new(ErrorCode::ExpectedFloat, off));
        }
        if e >= -126 {
            let lower = mant_with_hidden & ((1u64 << 29) - 1);
            if lower != 0 {
                return Err(CborError::new(ErrorCode::ExpectedFloat, off));
            }
            let mant32 = u32::try_from(mant_with_hidden >> 29)
                .map_err(|_| CborError::new(ErrorCode::ExpectedFloat, off))?
                & 0x7f_ffff;
            let exp32 = u32::try_from(e + 127)
                .map_err(|_| CborError::new(ErrorCode::ExpectedFloat, off))?;
            return Ok(Self::from_bits(sign | (exp32 << 23) | mant32));
        }
        if e >= -149 {
            let shift = u32::try_from(-e - 97)
                .map_err(|_| CborError::new(ErrorCode::ExpectedFloat, off))?;
            let lower = mant_with_hidden & ((1u64 << shift) - 1);
            if lower != 0 {
                return Err(CborError::new(ErrorCode::ExpectedFloat, off));
            }
            let mant32 = u32::try_from(mant_with_hidden >> shift)
                .map_err(|_| CborError::new(ErrorCode::ExpectedFloat, off))?;
            if mant32 == 0 || mant32 > 0x7f_ffff {
                return Err(CborError::new(ErrorCode::ExpectedFloat, off));
            }
            return Ok(Self::from_bits(sign | mant32));
        }
        Err(CborError::new(ErrorCode::ExpectedFloat, off))
    }
}

impl<'de, 'a> CborDecode<'de> for &'a str
where
    'de: 'a,
{
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        decoder.parse_text()
    }
}

impl<'de, 'a> CborDecode<'de> for &'a [u8]
where
    'de: 'a,
{
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        decoder.parse_bytes()
    }
}

impl<'de, 'a> CborDecode<'de> for BytesRef<'a>
where
    'de: 'a,
{
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        decoder.parse_bytes().map(BytesRef::new)
    }
}

impl<'de> CborDecode<'de> for CborValueRef<'de> {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let start = decoder.position();
        decoder.skip_value()?;
        let end = decoder.position();
        Ok(CborValueRef::new(decoder.data(), start, end))
    }
}

#[cfg(feature = "alloc")]
impl<'de, T: CborDecode<'de>> CborDecode<'de> for Option<T> {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let map_off = decoder.position();
        let mut map = decoder.map()?;
        if map.remaining() != 1 {
            return Err(CborError::new(ErrorCode::MapLenMismatch, map_off));
        }
        let Some(key) = map.next_key_ref()? else {
            return Err(CborError::new(ErrorCode::MapLenMismatch, map_off));
        };
        match key.text {
            "none" => {
                let _: () = map.next_value()?;
                Ok(None)
            }
            "some" => map.next_value().map(Some),
            _ => Err(CborError::new(ErrorCode::UnknownEnumVariant, key.offset)),
        }
    }
}

#[cfg(feature = "collections")]
impl<'de, T: CborDecode<'de>> CborDecode<'de> for Vec<T> {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let mut array = decoder.array()?;
        let mut out = alloc_util::try_vec_with_capacity::<T>(array.remaining(), off)?;
        while let Some(item) = array.next_value()? {
            out.push(item);
        }
        Ok(out)
    }
}

#[cfg(feature = "collections")]
impl<'de, V: CborDecode<'de>> CborDecode<'de> for MapEntries<&'de str, V> {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let mut map = decoder.map()?;
        let mut out = alloc_util::try_vec_with_capacity::<(&'de str, V)>(map.remaining(), off)?;
        while let Some((key, value)) = map.next_entry()? {
            out.push((key, value));
        }
        Ok(Self(out))
    }
}

#[cfg(feature = "collections")]
impl<'de, V: CborDecode<'de>> CborDecode<'de> for MapEntries<String, V> {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let mut map = decoder.map()?;
        let mut out = alloc_util::try_vec_with_capacity::<(String, V)>(map.remaining(), off)?;
        while let Some(key) = map.next_key_ref()? {
            let value = map.next_value()?;
            let owned = alloc_util::try_string_from_str(key.text, off)?;
            out.push((owned, value));
        }
        Ok(Self(out))
    }
}

#[cfg(feature = "alloc")]
impl<'de> CborDecode<'de> for String {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let s = decoder.parse_text()?;
        alloc_util::try_string_from_str(s, off)
    }
}

#[cfg(feature = "alloc")]
impl<'de> CborDecode<'de> for Bytes {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let bytes = decoder.parse_bytes()?;
        Ok(Self::new(alloc_util::try_vec_from_slice(bytes, off)?))
    }
}

impl<'de, const N: usize> CborDecode<'de> for [u8; N] {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let bytes = decoder.parse_bytes()?;
        if bytes.len() != N {
            return Err(CborError::new(ErrorCode::ExpectedBytes, off));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }
}

impl<'de> CborDecode<'de> for CanonicalCborRef<'de> {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let start = decoder.position();
        decoder.skip_value()?;
        let end = decoder.position();
        Ok(CanonicalCborRef::new(&decoder.data()[start..end]))
    }
}

#[cfg(feature = "alloc")]
impl<'de> CborDecode<'de> for CanonicalCbor {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let off = decoder.position();
        let canon_ref = CanonicalCborRef::decode(decoder)?;
        let bytes = alloc_util::try_vec_from_slice(canon_ref.as_bytes(), off)?;
        Ok(Self::new_unchecked(bytes))
    }
}
