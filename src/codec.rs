#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::canonical::CborBytesRef;
use crate::parse::validate_canonical;
use crate::query::{CborKind, CborValueRef};
use crate::wire::{self, Cursor};
use crate::{CborError, DecodeLimits, ErrorCode};

#[cfg(feature = "alloc")]
use crate::encode::Encoder;
#[cfg(feature = "alloc")]
use crate::CborBytes;

/// A CBOR map represented as ordered key/value entries.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapEntries<K, V>(pub Vec<(K, V)>);

#[cfg(feature = "alloc")]
impl<K, V> MapEntries<K, V> {
    /// Wrap an existing vector of entries.
    #[must_use]
    pub const fn new(entries: Vec<(K, V)>) -> Self {
        Self(entries)
    }
}

/// Streaming decoder over canonical CBOR bytes.
pub struct Decoder<'de> {
    cursor: Cursor<'de, CborError>,
    limits: DecodeLimits,
    depth: usize,
    items_seen: usize,
}

impl<'de> Decoder<'de> {
    /// Construct a decoder over canonical bytes with the provided limits.
    ///
    /// # Errors
    ///
    /// Returns `MessageLenLimitExceeded` if `bytes` exceeds the input limit.
    pub const fn new(bytes: &'de [u8], limits: DecodeLimits) -> Result<Self, CborError> {
        if bytes.len() > limits.max_input_bytes {
            return Err(CborError::new(ErrorCode::MessageLenLimitExceeded, 0));
        }
        Ok(Self {
            cursor: Cursor::with_pos(bytes, 0),
            limits,
            depth: 0,
            items_seen: 0,
        })
    }

    /// Return the current byte offset in the input.
    #[must_use]
    #[inline]
    pub const fn position(&self) -> usize {
        self.cursor.position()
    }

    #[inline]
    const fn data(&self) -> &'de [u8] {
        self.cursor.data()
    }

    #[inline]
    fn peek_u8(&self) -> Result<u8, CborError> {
        let off = self.cursor.position();
        self.data()
            .get(off)
            .copied()
            .ok_or_else(|| CborError::new(ErrorCode::UnexpectedEof, off))
    }

    #[inline]
    fn read_header(&mut self) -> Result<(u8, u8, usize), CborError> {
        let off = self.cursor.position();
        let ib = self.cursor.read_u8()?;
        Ok((ib >> 5, ib & 0x1f, off))
    }

    #[inline]
    fn read_uint_arg(&mut self, ai: u8, off: usize) -> Result<u64, CborError> {
        wire::read_uint_arg::<false, CborError>(&mut self.cursor, ai, off)
    }

    #[inline]
    fn read_len(&mut self, ai: u8, off: usize) -> Result<usize, CborError> {
        wire::read_len::<false, CborError>(&mut self.cursor, ai, off)
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
        if len == 0 {
            return Ok(false);
        }
        let next_depth = self.depth + 1;
        if next_depth > self.limits.max_depth {
            return Err(CborError::new(ErrorCode::DepthLimitExceeded, off));
        }
        self.depth = next_depth;
        Ok(true)
    }

    /// Exit a container entered by `parse_array_len` or `parse_map_len`.
    #[inline]
    pub fn exit_container(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    #[inline]
    fn parse_text_from_header(&mut self, off: usize, ai: u8) -> Result<&'de str, CborError> {
        wire::parse_text_from_header::<false, CborError>(
            &mut self.cursor,
            Some(&self.limits),
            off,
            ai,
        )
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
        wire::parse_bignum::<false, CborError>(&mut self.cursor, Some(&self.limits), off, ai)
    }

    fn parse_safe_i64(&mut self) -> Result<i64, CborError> {
        let (major, ai, off) = self.read_header()?;
        match major {
            0 => {
                let v = self.read_uint_arg(ai, off)?;
                i64::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
            }
            1 => {
                let n = self.read_uint_arg(ai, off)?;
                let n = i64::try_from(n)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))?;
                Ok(-1 - n)
            }
            _ => Err(CborError::new(ErrorCode::ExpectedInteger, off)),
        }
    }

    fn parse_safe_u64(&mut self) -> Result<u64, CborError> {
        let off = self.position();
        let v = self.parse_safe_i64()?;
        u64::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }

    fn parse_float64(&mut self) -> Result<f64, CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 7 || ai != 27 {
            return Err(CborError::new(ErrorCode::ExpectedFloat, off));
        }
        let bits = self.cursor.read_be_u64()?;
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
            _ => Err(CborError::new(ErrorCode::ExpectedBool, off)),
        }
    }

    fn parse_null(&mut self) -> Result<(), CborError> {
        let (major, ai, off) = self.read_header()?;
        if major == 7 && ai == 22 {
            Ok(())
        } else {
            Err(CborError::new(ErrorCode::ExpectedNull, off))
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

    /// Decode an array header and return `(len, entered_container)`.
    ///
    /// # Errors
    ///
    /// Returns `ExpectedArray` if the next value is not an array, or a limit error.
    pub fn parse_array_len(&mut self) -> Result<(usize, bool), CborError> {
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

    /// Decode a map header and return `(len, entered_container)`.
    ///
    /// # Errors
    ///
    /// Returns `ExpectedMap` if the next value is not a map, or a limit error.
    pub fn parse_map_len(&mut self) -> Result<(usize, bool), CborError> {
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

    /// Decode the next map key as a text string.
    ///
    /// # Errors
    ///
    /// Returns `MapKeyMustBeText` if the next key is not a text string.
    pub fn parse_text_key(&mut self) -> Result<&'de str, CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 3 {
            return Err(CborError::new(ErrorCode::MapKeyMustBeText, off));
        }
        self.parse_text_from_header(off, ai)
    }

    /// Skip exactly one CBOR value while enforcing decode limits.
    ///
    /// # Errors
    ///
    /// Returns a decode error if the value is malformed or violates limits.
    pub fn skip_value(&mut self) -> Result<(), CborError> {
        wire::skip_one_value::<false, CborError>(
            &mut self.cursor,
            Some(&self.limits),
            &mut self.items_seen,
            self.depth,
        )
    }

    /// Peek at the kind of the next CBOR value without consuming it.
    ///
    /// # Errors
    ///
    /// Returns a decode error if the header is malformed.
    pub fn peek_kind(&self) -> Result<CborKind, CborError> {
        let mut pos = self.cursor.position();
        let off = pos;
        let ib = wire::read_u8(self.data(), &mut pos)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        match major {
            0 | 1 => Ok(CborKind::Integer),
            2 => Ok(CborKind::Bytes),
            3 => Ok(CborKind::Text),
            4 => Ok(CborKind::Array),
            5 => Ok(CborKind::Map),
            6 => {
                let tag =
                    wire::read_uint_arg_at::<false, CborError>(self.data(), &mut pos, ai, off)?;
                match tag {
                    2 | 3 => Ok(CborKind::Integer),
                    _ => Err(CborError::new(ErrorCode::MalformedCanonical, off)),
                }
            }
            7 => match ai {
                20 | 21 => Ok(CborKind::Bool),
                22 => Ok(CborKind::Null),
                27 => Ok(CborKind::Float),
                _ => Err(CborError::new(ErrorCode::MalformedCanonical, off)),
            },
            _ => Err(CborError::new(ErrorCode::MalformedCanonical, off)),
        }
    }
}

/// Decode a value from a streaming decoder.
pub trait CborDecode<'de>: Sized {
    /// Decode `Self` from a streaming decoder.
    ///
    /// # Errors
    ///
    /// Returns an error if the CBOR value does not match the expected type or violates profile
    /// constraints.
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError>;
}

#[cfg(feature = "alloc")]
/// Encode a value into canonical CBOR bytes using the streaming encoder.
pub trait CborEncode {
    /// Encode `self` into the provided encoder.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError>;
}

#[cfg(feature = "alloc")]
/// Marker trait for values that can appear as CBOR array elements.
pub trait CborArrayElem {}

/// Validate canonical CBOR and decode a value using `CborDecode`.
///
/// # Errors
///
/// Returns an error if the input is not canonical CBOR or if decoding fails.
pub fn decode<'de, T: CborDecode<'de>>(
    bytes: &'de [u8],
    limits: DecodeLimits,
) -> Result<T, CborError> {
    let canon = validate_canonical(bytes, limits)?;
    let bytes = canon.as_bytes();
    let mut decoder = Decoder::new(bytes, limits)?;
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
pub fn decode_canonical<'de, T: CborDecode<'de>>(canon: CborBytesRef<'de>) -> Result<T, CborError> {
    let bytes = canon.as_bytes();
    let limits = DecodeLimits::for_bytes(bytes.len());
    let mut decoder = Decoder::new(bytes, limits)?;
    let value = T::decode(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, decoder.position()));
    }
    Ok(value)
}

/// Decode a value from owned canonical bytes.
///
/// # Errors
///
/// Returns an error if decoding fails.
#[cfg(feature = "alloc")]
pub fn decode_canonical_owned<'de, T: CborDecode<'de>>(
    canon: &'de CborBytes,
) -> Result<T, CborError> {
    decode_canonical(canon.as_ref())
}

#[cfg(feature = "alloc")]
/// Encode a value into canonical CBOR bytes.
///
/// # Errors
///
/// Returns an error if encoding fails.
pub fn encode_to_vec<T: CborEncode>(value: &T) -> Result<Vec<u8>, CborError> {
    let mut enc = Encoder::new();
    value.encode(&mut enc)?;
    Ok(enc.into_vec())
}

#[cfg(feature = "alloc")]
/// Encode a value into owned canonical CBOR bytes.
///
/// # Errors
///
/// Returns an error if encoding fails.
pub fn encode_to_canonical<T: CborEncode>(value: &T) -> Result<CborBytes, CborError> {
    let mut enc = Encoder::new();
    value.encode(&mut enc)?;
    enc.into_canonical()
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

impl<'de> CborDecode<'de> for () {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        decoder.parse_null()
    }
}

impl<'de> CborDecode<'de> for bool {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        decoder.parse_bool()
    }
}

impl<'de> CborDecode<'de> for i64 {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        decoder.parse_safe_i64()
    }
}

impl<'de> CborDecode<'de> for i32 {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_safe_i64()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for i16 {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_safe_i64()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for i8 {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_safe_i64()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for isize {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_safe_i64()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for i128 {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        let (major, ai, off) = decoder.read_header()?;
        match major {
            0 => {
                let v = decoder.read_uint_arg(ai, off)?;
                let v_i = i64::try_from(v)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))?;
                Ok(Self::from(v_i))
            }
            1 => {
                let n = decoder.read_uint_arg(ai, off)?;
                let n_i = i64::try_from(n)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))?;
                Ok(Self::from(-1 - n_i))
            }
            6 => {
                let (negative, mag) = decoder.parse_bignum(off, ai)?;
                let n = mag_to_u128(mag)
                    .ok_or_else(|| CborError::new(ErrorCode::ExpectedInteger, off))?;
                let n_i = Self::try_from(n)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))?;
                Ok(if negative { -1 - n_i } else { n_i })
            }
            _ => Err(CborError::new(ErrorCode::ExpectedInteger, off)),
        }
    }
}

impl<'de> CborDecode<'de> for u64 {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        decoder.parse_safe_u64()
    }
}

impl<'de> CborDecode<'de> for u32 {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_safe_u64()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for u16 {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_safe_u64()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for u8 {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_safe_u64()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for usize {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_safe_u64()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for u128 {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        let (major, ai, off) = decoder.read_header()?;
        match major {
            0 => {
                let v = decoder.read_uint_arg(ai, off)?;
                let v_i = i64::try_from(v)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))?;
                let v_u64 = u64::try_from(v_i)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))?;
                Ok(Self::from(v_u64))
            }
            6 => {
                let (negative, mag) = decoder.parse_bignum(off, ai)?;
                if negative {
                    return Err(CborError::new(ErrorCode::ExpectedInteger, off));
                }
                mag_to_u128(mag).ok_or_else(|| CborError::new(ErrorCode::ExpectedInteger, off))
            }
            _ => Err(CborError::new(ErrorCode::ExpectedInteger, off)),
        }
    }
}

impl<'de> CborDecode<'de> for f64 {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        decoder.parse_float64()
    }
}

impl<'de> CborDecode<'de> for f32 {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
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

impl<'de> CborDecode<'de> for &'de str {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        decoder.parse_text()
    }
}

impl<'de> CborDecode<'de> for &'de [u8] {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        decoder.parse_bytes()
    }
}

impl<'de> CborDecode<'de> for CborValueRef<'de> {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        let start = decoder.position();
        decoder.skip_value()?;
        let end = decoder.position();
        Ok(CborValueRef::new(decoder.data(), start, end))
    }
}

impl<'de, T: CborDecode<'de>> CborDecode<'de> for Option<T> {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        if decoder.peek_u8()? == 0xf6 {
            decoder.parse_null()?;
            Ok(None)
        } else {
            T::decode(decoder).map(Some)
        }
    }
}

#[cfg(feature = "alloc")]
impl<'de, T: CborDecode<'de> + CborArrayElem> CborDecode<'de> for Vec<T> {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        let (len, entered) = decoder.parse_array_len()?;
        let mut out = Self::with_capacity(len);
        for _ in 0..len {
            out.push(T::decode(decoder)?);
        }
        if entered {
            decoder.exit_container();
        }
        Ok(out)
    }
}

#[cfg(feature = "alloc")]
impl<'de, V: CborDecode<'de>> CborDecode<'de> for MapEntries<&'de str, V> {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        let (len, entered) = decoder.parse_map_len()?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            let key = decoder.parse_text_key()?;
            let value = V::decode(decoder)?;
            out.push((key, value));
        }
        if entered {
            decoder.exit_container();
        }
        Ok(Self(out))
    }
}

#[cfg(feature = "alloc")]
impl<'de, V: CborDecode<'de>> CborDecode<'de> for MapEntries<String, V> {
    fn decode(decoder: &mut Decoder<'de>) -> Result<Self, CborError> {
        let (len, entered) = decoder.parse_map_len()?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            let key = decoder.parse_text_key()?;
            let value = V::decode(decoder)?;
            out.push((key.to_string(), value));
        }
        if entered {
            decoder.exit_container();
        }
        Ok(Self(out))
    }
}

#[cfg(feature = "alloc")]
impl CborDecode<'_> for String {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CborError> {
        decoder.parse_text().map(str::to_string)
    }
}

#[cfg(feature = "alloc")]
impl CborDecode<'_> for Vec<u8> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CborError> {
        decoder.parse_bytes().map(<[u8]>::to_vec)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for () {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.null()
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for bool {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.bool(*self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for i64 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(*self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for i32 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for i16 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for i8 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for isize {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(
            i64::try_from(*self)
                .map_err(|_| CborError::new(ErrorCode::LengthOverflow, enc.len()))?,
        )
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for i128 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int_i128(*self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for u64 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        if *self <= crate::MAX_SAFE_INTEGER {
            let v = i64::try_from(*self)
                .map_err(|_| CborError::new(ErrorCode::LengthOverflow, enc.len()))?;
            enc.int(v)
        } else {
            enc.int_u128(u128::from(*self))
        }
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for u32 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for u16 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for u8 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for usize {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        let v = u64::try_from(*self)
            .map_err(|_| CborError::new(ErrorCode::LengthOverflow, enc.len()))?;
        if v <= crate::MAX_SAFE_INTEGER {
            let v = i64::try_from(v)
                .map_err(|_| CborError::new(ErrorCode::LengthOverflow, enc.len()))?;
            enc.int(v)
        } else {
            enc.int_u128(u128::from(v))
        }
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for u128 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int_u128(*self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for f64 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        let bits = crate::scalar::F64Bits::try_from_f64(*self)?;
        enc.float(bits)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for f32 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        let bits = crate::scalar::F64Bits::try_from_f64(f64::from(*self))?;
        enc.float(bits)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for &str {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.text(self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for &[u8] {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.bytes(self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for String {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.text(self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for Vec<u8> {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.bytes(self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for CborValueRef<'_> {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.raw_value_ref(*self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for CborBytesRef<'_> {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.raw_cbor(*self)
    }
}

#[cfg(feature = "alloc")]
impl<T: CborEncode> CborEncode for Option<T> {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        match self {
            Some(v) => v.encode(enc),
            None => enc.null(),
        }
    }
}

#[cfg(feature = "alloc")]
impl<T: CborEncode + CborArrayElem> CborEncode for Vec<T> {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.array(self.len(), |a| {
            for item in self {
                a.value(item)?;
            }
            Ok(())
        })
    }
}

#[cfg(feature = "alloc")]
impl<K, V> CborEncode for MapEntries<K, V>
where
    K: AsRef<str>,
    V: CborEncode,
{
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.map(self.0.len(), |m| {
            for (k, v) in &self.0 {
                m.entry(k.as_ref(), |enc| v.encode(enc))?;
            }
            Ok(())
        })
    }
}

#[cfg(feature = "alloc")]
impl CborArrayElem for bool {}
#[cfg(feature = "alloc")]
impl CborArrayElem for i64 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for i32 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for i16 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for i8 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for isize {}
#[cfg(feature = "alloc")]
impl CborArrayElem for i128 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for u64 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for u32 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for u16 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for usize {}
#[cfg(feature = "alloc")]
impl CborArrayElem for u128 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for f64 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for f32 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for String {}
#[cfg(feature = "alloc")]
impl CborArrayElem for &str {}
#[cfg(feature = "alloc")]
impl CborArrayElem for &[u8] {}
#[cfg(feature = "alloc")]
impl CborArrayElem for CborValueRef<'_> {}
#[cfg(feature = "alloc")]
impl CborArrayElem for CborBytesRef<'_> {}
#[cfg(feature = "alloc")]
impl<T: CborArrayElem> CborArrayElem for Option<T> {}
#[cfg(feature = "alloc")]
impl<T: CborArrayElem> CborArrayElem for Vec<T> {}
#[cfg(feature = "alloc")]
impl<K, V> CborArrayElem for MapEntries<K, V>
where
    K: AsRef<str>,
    V: CborArrayElem,
{
}
