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
use crate::query::{peek_kind_at, BigIntRef, CborKind, CborValueRef, IntegerRef};
use crate::wire::{self, Cursor};
use crate::{CborError, DecodeLimits, ErrorCode, ValidationOptions};

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
    options: ValidationOptions,
    depth: usize,
    items_seen: usize,
    /// Values fully consumed at depth 0 — exactly 1 for a witnessable pass.
    root_values: usize,
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

/// Raw parts of one consumed integer-kind value (the single counted
/// funnel behind every integer decode).
#[cfg(feature = "alloc")]
enum IntegerParts<'de> {
    SafePos(u64),
    SafeNeg(u64),
    Big { negative: bool, mag: &'de [u8] },
}

/// A scalar (leaf) kind of the canonical profile.
///
/// The scalar consumption funnels ([`Decoder::skip_scalar`],
/// [`ArrayDecoder::skip_scalars`], [`ArrayDecoder::next_scalar_span`]) take
/// this instead of [`CborKind`] so a container kind cannot be requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarKind {
    /// Safe integer (major 0/1) or bignum (tag 2/3).
    Integer,
    /// Byte string (major 2).
    Bytes,
    /// Text string (major 3).
    Text,
    /// Boolean simple value.
    Bool,
    /// Null simple value.
    Null,
    /// Float64 value.
    Float,
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
            self.decoder.exit_container();
            if self.remaining == 0 {
                self.decoder.note_value_end();
            } else {
                let off = self.decoder.position();
                self.decoder.poison(ErrorCode::MalformedCanonical, off);
            }
        }
    }
}

impl<const CHECKED: bool> Drop for MapDecoder<'_, '_, CHECKED> {
    fn drop(&mut self) {
        if self.entered {
            self.decoder.exit_container();
            if self.remaining == 0 && !self.pending_value {
                self.decoder.note_value_end();
            } else {
                let off = self.decoder.position();
                self.decoder.poison(ErrorCode::MalformedCanonical, off);
            }
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
        Self::new_with(bytes, limits, ValidationOptions::new())
    }

    /// Construct a checked decoder that additionally enforces the given
    /// restriction modes (e.g. [`ValidationOptions::no_float`]) on every
    /// consumed value, including skipped subtrees.
    ///
    /// # Errors
    ///
    /// Returns `MessageLenLimitExceeded` if `bytes` exceeds the input limit.
    pub const fn new_checked_with(
        bytes: &'de [u8],
        limits: DecodeLimits,
        options: ValidationOptions,
    ) -> Result<Self, CborError> {
        Self::new_with(bytes, limits, options)
    }

    /// Complete a checked pass and return the canonical witness.
    ///
    /// Succeeds only when this decoder consumed the input as **exactly one
    /// canonical item**: no poisoned container guard, no trailing bytes,
    /// and exactly one value completed at the root. Every consuming method
    /// of a checked decoder applies the same canonical-grammar checks as
    /// [`validate_canonical`](crate::validate_canonical) (and the same
    /// restriction modes as
    /// [`validate_canonical_with`](crate::validate_canonical_with) when
    /// constructed via [`new_checked_with`](Self::new_checked_with)), so a
    /// successful `finish` attests the same property — one validation-grade
    /// pass, no second traversal.
    ///
    /// # Errors
    ///
    /// Returns the stored poison, `TrailingBytes` when input remains, or
    /// `MalformedCanonical` when the pass did not consume exactly one root
    /// value.
    pub fn finish(self) -> Result<CanonicalCborRef<'de>, CborError> {
        self.check_poison()?;
        let pos = self.cursor.position();
        let data = self.cursor.data();
        if pos != data.len() {
            return Err(CborError::new(ErrorCode::TrailingBytes, pos));
        }
        if self.root_values != 1 {
            return Err(CborError::new(ErrorCode::MalformedCanonical, pos));
        }
        Ok(CanonicalCborRef::new(data))
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
        Self::new_with(canon.as_bytes(), limits, ValidationOptions::new())
    }
}

impl<'de, const CHECKED: bool> Decoder<'de, CHECKED> {
    const fn new_with(
        bytes: &'de [u8],
        limits: DecodeLimits,
        options: ValidationOptions,
    ) -> Result<Self, CborError> {
        if let Err(err) = limits.validate() {
            return Err(err);
        }
        if bytes.len() > limits.max_input_bytes {
            return Err(CborError::new(ErrorCode::MessageLenLimitExceeded, 0));
        }
        Ok(Self {
            cursor: Cursor::with_pos(bytes, 0),
            limits,
            options,
            depth: 0,
            items_seen: 0,
            root_values: 0,
            poison: None,
            scratch: wire::SkipScratch::new(),
        })
    }

    /// Record the completion of one whole value at the current depth.
    ///
    /// Hot-path note: root counting feeds `finish`, which exists only on
    /// checked decoders — the whole body const-folds away for the trusted
    /// path. On the checked path it is one register compare; in nested
    /// positions (the overwhelmingly common case) the branch is never
    /// taken and predicts perfectly.
    #[inline]
    fn note_value_end(&mut self) {
        if CHECKED && self.depth == 0 {
            self.root_values += 1;
        }
    }

    /// Seal a value-consuming operation: success completes a value,
    /// failure poisons the decoder.
    ///
    /// Errors are sticky by design: a failed consuming operation may have
    /// advanced the cursor past a partial value, so continuing would
    /// traverse an incoherent framing of the input. Poisoning makes every
    /// later operation — `finish` included — return the original error
    /// instead. Cost on the success path: one branch on `Ok` plus the
    /// `note_value_end` compare; the poison store is on the cold error arm.
    #[inline]
    fn seal_value<T>(&mut self, result: Result<T, CborError>) -> Result<T, CborError> {
        match result {
            Ok(value) => {
                self.note_value_end();
                Ok(value)
            }
            Err(err) => {
                self.poison_err(err);
                Err(err)
            }
        }
    }

    /// Poison a non-completing operation's failure (container entry, key
    /// reads): sticky, but no value completion on success.
    #[inline]
    fn seal_step<T>(&mut self, result: Result<T, CborError>) -> Result<T, CborError> {
        if let Err(err) = &result {
            self.poison_err(*err);
        }
        result
    }

    #[inline]
    fn poison_err(&mut self, err: CborError) {
        if self.poison.is_none() {
            self.poison = Some(err);
        }
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

    /// Consume one integer-kind value (safe int or bignum) and return its
    /// raw parts plus the header offset. The counted funnel for the
    /// arbitrary-precision decoders (`BigInt`, `Integer`); the primitive
    /// paths below stay direct for hot-loop performance.
    #[cfg(feature = "alloc")]
    fn parse_integer_parts(&mut self) -> Result<(IntegerParts<'de>, usize), CborError> {
        let result = self.parse_integer_parts_raw();
        self.seal_value(result)
    }

    #[cfg(feature = "alloc")]
    fn parse_integer_parts_raw(&mut self) -> Result<(IntegerParts<'de>, usize), CborError> {
        let (major, ai, off) = self.read_header()?;
        match major {
            0 => {
                let v = self.read_uint_arg(ai, off)?;
                if CHECKED && v > MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                Ok((IntegerParts::SafePos(v), off))
            }
            1 => {
                let n = self.read_uint_arg(ai, off)?;
                if CHECKED && n >= MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                Ok((IntegerParts::SafeNeg(n), off))
            }
            6 => {
                let (negative, mag) = self.parse_bignum(off, ai)?;
                Ok((IntegerParts::Big { negative, mag }, off))
            }
            _ => Err(CborError::new(ErrorCode::ExpectedInteger, off)),
        }
    }

    /// Consume one scalar value of the expected kind through the direct
    /// scalar funnel: one header read, no subtree walk, no allocation.
    ///
    /// A value of a different kind is rejected with the kind's
    /// `Expected*` error code at the header offset. All canonical-grammar
    /// checks, decode limits, and restriction modes of this decoder apply.
    ///
    /// # Errors
    ///
    /// Returns an error if the next value is not a scalar of `kind`, is
    /// malformed, or violates limits or validation options.
    pub fn skip_scalar(&mut self, kind: ScalarKind) -> Result<(), CborError> {
        self.check_poison()?;
        let result = self.consume_scalar_raw(kind);
        self.seal_value(result)
    }

    #[inline]
    fn consume_scalar_raw(&mut self, kind: ScalarKind) -> Result<(), CborError> {
        match kind {
            ScalarKind::Integer => self.parse_integer_ref_raw().map(|_| ()),
            ScalarKind::Bytes => self.parse_bytes_raw().map(|_| ()),
            ScalarKind::Text => self.consume_text_raw(),
            ScalarKind::Bool => self.parse_bool_raw().map(|_| ()),
            ScalarKind::Null => self.parse_null_raw(),
            ScalarKind::Float => self.parse_float64_raw().map(|_| ()),
        }
    }

    /// Consume one text value without materializing the `&str`.
    ///
    /// Mirrors the skip path: UTF-8 is validated on the checked decoder and
    /// trusted on the trusted decoder, exactly like [`Decoder::skip_value`].
    /// (`parse_text_raw` must produce a `&str`, so it validates in both
    /// modes; a pure consume has no such obligation.)
    #[inline]
    fn consume_text_raw(&mut self) -> Result<(), CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 3 {
            return Err(CborError::new(ErrorCode::ExpectedText, off));
        }
        let len = self.read_len(ai, off)?;
        if len > self.limits.max_text_len {
            return Err(CborError::new(ErrorCode::TextLenLimitExceeded, off));
        }
        let bytes = self.cursor.read_exact(len)?;
        if CHECKED {
            crate::utf8::validate_utf8(bytes)
                .map_err(|()| CborError::new(ErrorCode::Utf8Invalid, off))?;
        }
        Ok(())
    }

    fn parse_integer_ref(&mut self) -> Result<IntegerRef<'de>, CborError> {
        let result = self.parse_integer_ref_raw();
        self.seal_value(result)
    }

    /// Consume one integer-kind value as a zero-copy [`IntegerRef`]: the
    /// direct scalar funnel, no subtree walk and no allocation.
    #[inline]
    fn parse_integer_ref_raw(&mut self) -> Result<IntegerRef<'de>, CborError> {
        let (major, ai, off) = self.read_header()?;
        match major {
            0 => {
                let v = self.read_uint_arg(ai, off)?;
                if CHECKED && v > MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                let v = i64::try_from(v)
                    .map_err(|_| CborError::new(ErrorCode::IntegerOutsideSafeRange, off))?;
                Ok(IntegerRef::Safe(v))
            }
            1 => {
                let n = self.read_uint_arg(ai, off)?;
                if CHECKED && n >= MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                let n = i64::try_from(n)
                    .map_err(|_| CborError::new(ErrorCode::IntegerOutsideSafeRange, off))?;
                Ok(IntegerRef::Safe(-1 - n))
            }
            6 => {
                let (negative, mag) = self.parse_bignum(off, ai)?;
                Ok(IntegerRef::Big(BigIntRef::new(negative, mag)))
            }
            _ => Err(CborError::new(ErrorCode::ExpectedInteger, off)),
        }
    }

    fn parse_integer_i128(&mut self) -> Result<i128, CborError> {
        let result = self.parse_integer_i128_raw();
        self.seal_value(result)
    }

    #[inline]
    fn parse_integer_i128_raw(&mut self) -> Result<i128, CborError> {
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
        let result = self.parse_integer_u128_raw();
        self.seal_value(result)
    }

    #[inline]
    fn parse_integer_u128_raw(&mut self) -> Result<u128, CborError> {
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
        let result = self.parse_float64_raw();
        self.seal_value(result)
    }

    fn parse_float64_raw(&mut self) -> Result<f64, CborError> {
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
        if CHECKED && self.options.forbid_float {
            return Err(CborError::new(ErrorCode::FloatForbidden, off));
        }
        let bits = self.cursor.read_be_u64()?;
        if CHECKED {
            validate_f64_bits(bits).map_err(|code| CborError::new(code, off))?;
        }
        Ok(f64::from_bits(bits))
    }

    fn parse_bool(&mut self) -> Result<bool, CborError> {
        let result = self.parse_bool_raw();
        self.seal_value(result)
    }

    fn parse_bool_raw(&mut self) -> Result<bool, CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 7 {
            return Err(CborError::new(ErrorCode::ExpectedBool, off));
        }
        match ai {
            20 | 21 => {
                if CHECKED && self.options.forbid_simple {
                    return Err(CborError::new(ErrorCode::SimpleForbidden, off));
                }
                Ok(ai == 21)
            }
            22 | 27 => Err(CborError::new(ErrorCode::ExpectedBool, off)),
            _ => self.reject_unexpected_simple(ai, off, ErrorCode::ExpectedBool),
        }
    }

    fn parse_null(&mut self) -> Result<(), CborError> {
        let result = self.parse_null_raw();
        self.seal_value(result)
    }

    fn parse_null_raw(&mut self) -> Result<(), CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 7 {
            return Err(CborError::new(ErrorCode::ExpectedNull, off));
        }
        match ai {
            22 => {
                if CHECKED && self.options.forbid_simple {
                    return Err(CborError::new(ErrorCode::SimpleForbidden, off));
                }
                Ok(())
            }
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
        let result = self.parse_bytes_raw();
        self.seal_value(result)
    }

    fn parse_bytes_raw(&mut self) -> Result<&'de [u8], CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 2 {
            return Err(CborError::new(ErrorCode::ExpectedBytes, off));
        }
        self.parse_bytes_from_header(off, ai)
    }

    fn parse_text(&mut self) -> Result<&'de str, CborError> {
        let result = self.parse_text_raw();
        self.seal_value(result)
    }

    fn parse_text_raw(&mut self) -> Result<&'de str, CborError> {
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
        let entry = self.array_entry();
        let (len, entered) = self.seal_step(entry)?;
        if !entered {
            // An empty array is already a complete value.
            self.note_value_end();
        }
        Ok(ArrayDecoder {
            decoder: self,
            remaining: len,
            entered,
        })
    }

    fn array_entry(&mut self) -> Result<(usize, bool), CborError> {
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
        Ok((len, entered))
    }

    /// Decode a map header and return a guard for its entries.
    ///
    /// # Errors
    ///
    /// Returns `ExpectedMap` if the next value is not a map, or a limit error.
    pub fn map(&mut self) -> Result<MapDecoder<'_, 'de, CHECKED>, CborError> {
        let entry = self.map_entry();
        let (len, entered) = self.seal_step(entry)?;
        if !entered {
            // An empty map is already a complete value.
            self.note_value_end();
        }
        Ok(MapDecoder {
            decoder: self,
            remaining: len,
            entered,
            pending_value: false,
            prev_key_range: None,
        })
    }

    fn map_entry(&mut self) -> Result<(usize, bool), CborError> {
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
        Ok((len, entered))
    }

    /// Skip exactly one CBOR value while enforcing decode limits.
    ///
    /// # Errors
    ///
    /// Returns a decode error if the value is malformed or violates limits.
    pub fn skip_value(&mut self) -> Result<(), CborError> {
        self.check_poison()?;
        let result = wire::skip_one_value_with_scratch::<CHECKED>(
            &mut self.cursor,
            wire::WalkPolicy::new(Some(&self.limits), self.options),
            &mut self.items_seen,
            self.depth,
            &mut self.scratch,
        );
        self.seal_value(result)
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

    /// Current byte offset of the underlying decoder.
    #[inline]
    #[must_use]
    pub const fn position(&self) -> usize {
        self.decoder.position()
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
        self.decode_next_with(f)
    }

    /// Decode the next array element using a custom decoder with a
    /// caller-defined error type.
    ///
    /// A caller error aborts the element mid-consumption, so it poisons
    /// the decoder like any decode failure: the pass can no longer reach
    /// [`Decoder::finish`].
    ///
    /// # Errors
    ///
    /// Returns the closure's error, or a decode error if the array is
    /// malformed.
    pub fn decode_next_with<F, T, E>(&mut self, f: F) -> Result<Option<T>, E>
    where
        F: FnOnce(&mut Decoder<'de, CHECKED>) -> Result<T, E>,
        E: From<CborError>,
    {
        if self.remaining == 0 {
            return Ok(None);
        }
        match f(self.decoder) {
            Ok(value) => {
                self.remaining -= 1;
                Ok(Some(value))
            }
            Err(err) => {
                let off = self.decoder.position();
                self.decoder.poison(ErrorCode::MalformedCanonical, off);
                Err(err)
            }
        }
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

    /// Consume all remaining elements, requiring each to be a scalar of
    /// `kind`.
    ///
    /// This is the batch form of [`Decoder::skip_scalar`]: one tight loop of
    /// direct scalar funnels, with no per-element dispatch. All
    /// canonical-grammar checks, decode limits, and restriction modes apply
    /// to every element.
    ///
    /// # Errors
    ///
    /// Returns an error at the first element that is not a scalar of `kind`
    /// (the kind's `Expected*` code at that element's header offset), is
    /// malformed, or violates limits or validation options.
    pub fn skip_scalars(&mut self, kind: ScalarKind) -> Result<(), CborError> {
        self.decoder.check_poison()?;
        while self.remaining > 0 {
            let result = self.decoder.consume_scalar_raw(kind);
            self.decoder.seal_value(result)?;
            self.remaining -= 1;
        }
        Ok(())
    }

    /// Consume the next element, requiring a scalar of `kind`, and return
    /// the byte range of its canonical encoding inside the input.
    ///
    /// Returns `Ok(None)` when the array is exhausted. The returned range is
    /// the element's complete encoding (header and payload), suitable for
    /// canonical byte comparisons.
    ///
    /// # Errors
    ///
    /// Returns an error if the next element is not a scalar of `kind`, is
    /// malformed, or violates limits or validation options.
    pub fn next_scalar_span(
        &mut self,
        kind: ScalarKind,
    ) -> Result<Option<Range<usize>>, CborError> {
        self.decoder.check_poison()?;
        if self.remaining == 0 {
            return Ok(None);
        }
        let start = self.decoder.position();
        let result = self.decoder.consume_scalar_raw(kind);
        self.decoder.seal_value(result)?;
        self.remaining -= 1;
        Ok(Some(start..self.decoder.position()))
    }

    /// Consume all remaining elements, requiring each to be a scalar of
    /// `kind` and the sequence to be strictly ascending by unsigned
    /// lexicographic (memcmp) order of the elements' canonical encodings.
    ///
    /// This is the sorted-set form of [`skip_scalars`](Self::skip_scalars)
    /// with the order comparison inlined into the batch loop. Canonical
    /// encodings are self-delimiting — no element encoding is a proper
    /// prefix of a different complete encoding — so memcmp order is total,
    /// and equality of encodings is equality of values.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::DuplicateElement`] when an element's encoding
    /// equals its predecessor's and [`ErrorCode::NonAscendingElement`] when
    /// it sorts below it, both at the element's header offset; otherwise as
    /// [`skip_scalars`](Self::skip_scalars). Order failures poison the
    /// decoder like any failed consuming operation.
    pub fn skip_sorted_scalars(&mut self, kind: ScalarKind) -> Result<(), CborError> {
        self.decoder.check_poison()?;
        let data = self.decoder.cursor.data();
        let mut prev: Option<Range<usize>> = None;
        while self.remaining > 0 {
            let start = self.decoder.position();
            let result = self.decoder.consume_scalar_raw(kind);
            self.decoder.seal_value(result)?;
            self.remaining -= 1;
            let end = self.decoder.position();
            if let Some(prev_range) = prev {
                let order = data[prev_range].cmp(&data[start..end]);
                if order != core::cmp::Ordering::Less {
                    let code = if order == core::cmp::Ordering::Equal {
                        ErrorCode::DuplicateElement
                    } else {
                        ErrorCode::NonAscendingElement
                    };
                    let err = CborError::new(code, start);
                    self.decoder.poison_err(err);
                    return Err(err);
                }
            }
            prev = Some(start..end);
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

    /// Current byte offset of the underlying decoder.
    #[inline]
    #[must_use]
    pub const fn position(&self) -> usize {
        self.decoder.position()
    }

    /// Decode the next map key as text with source offsets.
    ///
    /// Returns `Ok(None)` when the map is exhausted.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails or the map is malformed.
    pub fn next_key_ref(&mut self) -> Result<Option<MapKey<'de>>, CborError> {
        // Pending-state misuse is detected before any byte is consumed —
        // recoverable, never sticky.
        if self.pending_value {
            return Err(CborError::new(
                ErrorCode::MalformedCanonical,
                self.decoder.position(),
            ));
        }
        if self.remaining == 0 {
            return Ok(None);
        }
        let result = self.next_key_ref_consume();
        if let Err(err) = &result {
            self.decoder.poison_err(*err);
        }
        result
    }

    fn next_key_ref_consume(&mut self) -> Result<Option<MapKey<'de>>, CborError> {
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
        self.decode_value_with(f)
    }

    /// Decode the value corresponding to the last returned key using a
    /// custom decoder with a caller-defined error type.
    ///
    /// A caller error aborts the value mid-consumption, so it poisons the
    /// decoder like any decode failure: the pass can no longer reach
    /// [`Decoder::finish`].
    ///
    /// # Errors
    ///
    /// Returns the closure's error, or a decode error if the map is
    /// malformed.
    pub fn decode_value_with<F, T, E>(&mut self, f: F) -> Result<T, E>
    where
        F: FnOnce(&mut Decoder<'de, CHECKED>) -> Result<T, E>,
        E: From<CborError>,
    {
        if !self.pending_value {
            // Detected before any byte is consumed — recoverable.
            let err = CborError::new(ErrorCode::MalformedCanonical, self.decoder.position());
            return Err(E::from(err));
        }
        match f(self.decoder) {
            Ok(value) => {
                self.pending_value = false;
                self.remaining -= 1;
                Ok(value)
            }
            Err(err) => {
                // The value may be partially consumed; the original decode
                // error (if any) was already stored by the failing funnel
                // and poison_err keeps the first error.
                let off = self.decoder.position();
                self.decoder.poison(ErrorCode::MalformedCanonical, off);
                Err(err)
            }
        }
    }

    /// Skip the value corresponding to the last returned key.
    ///
    /// # Errors
    ///
    /// Returns an error if no key is pending or if skipping fails.
    pub fn skip_value(&mut self) -> Result<(), CborError> {
        if !self.pending_value {
            // Detected before any byte is consumed — recoverable.
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
        let (parts, off) = decoder.parse_integer_parts()?;
        match parts {
            IntegerParts::Big { negative, mag } => {
                let magnitude = alloc_util::try_vec_from_slice(mag, off)?;
                Self::new(negative, magnitude).map_err(|err| CborError::new(err.code, off))
            }
            IntegerParts::SafePos(_) | IntegerParts::SafeNeg(_) => {
                Err(CborError::new(ErrorCode::ExpectedInteger, off))
            }
        }
    }
}

#[cfg(feature = "alloc")]
impl<'de> CborDecode<'de> for Integer {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        let (parts, off) = decoder.parse_integer_parts()?;
        match parts {
            IntegerParts::SafePos(v) => {
                let v_i = i64::try_from(v)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))?;
                Self::safe(v_i).map_err(|err| CborError::new(err.code, off))
            }
            IntegerParts::SafeNeg(n) => {
                let n_i = i64::try_from(n)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))?;
                Self::safe(-1 - n_i).map_err(|err| CborError::new(err.code, off))
            }
            IntegerParts::Big { negative, mag } => {
                let magnitude = alloc_util::try_vec_from_slice(mag, off)?;
                Self::big(negative, magnitude).map_err(|err| CborError::new(err.code, off))
            }
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

impl<'de> CborDecode<'de> for IntegerRef<'de> {
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError> {
        decoder.parse_integer_ref()
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
