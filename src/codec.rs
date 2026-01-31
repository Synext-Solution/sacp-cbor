#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use crate::alloc_util;
use crate::canonical::CborBytesRef;
#[cfg(not(feature = "alloc"))]
use crate::limits::DEFAULT_MAX_DEPTH;
use crate::profile::{validate_f64_bits, MAX_SAFE_INTEGER};
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

#[derive(Clone, Copy)]
enum ContainerFrame {
    Array,
    Map {
        prev_key_range: Option<(usize, usize)>,
    },
}

#[cfg(feature = "alloc")]
const INLINE_CONTAINER_FRAMES: usize = 32;

#[cfg(not(feature = "alloc"))]
const INLINE_CONTAINER_FRAMES: usize = DEFAULT_MAX_DEPTH + 2;

#[cfg(feature = "alloc")]
struct ContainerStack {
    inline: [ContainerFrame; INLINE_CONTAINER_FRAMES],
    len: usize,
    heap: Option<Vec<ContainerFrame>>,
}

#[cfg(feature = "alloc")]
impl ContainerStack {
    const fn new() -> Self {
        Self {
            inline: [ContainerFrame::Array; INLINE_CONTAINER_FRAMES],
            len: 0,
            heap: None,
        }
    }

    fn push(&mut self, frame: ContainerFrame, off: usize) -> Result<(), CborError> {
        match &mut self.heap {
            Some(items) => {
                alloc_util::try_reserve(items, 1, off)?;
                items.push(frame);
            }
            None => {
                if self.len < INLINE_CONTAINER_FRAMES {
                    self.inline[self.len] = frame;
                    self.len += 1;
                } else {
                    let mut items = Vec::new();
                    alloc_util::try_reserve(&mut items, self.len + 1, off)?;
                    items.extend_from_slice(&self.inline[..self.len]);
                    items.push(frame);
                    self.heap = Some(items);
                }
            }
        }
        Ok(())
    }

    fn pop(&mut self) -> Option<ContainerFrame> {
        match &mut self.heap {
            Some(items) => items.pop(),
            None => {
                if self.len == 0 {
                    None
                } else {
                    self.len -= 1;
                    Some(self.inline[self.len])
                }
            }
        }
    }

    fn peek(&self) -> Option<ContainerFrame> {
        self.heap.as_ref().map_or_else(
            || self.len.checked_sub(1).map(|i| self.inline[i]),
            |items| items.last().copied(),
        )
    }

    fn peek_mut(&mut self) -> Option<&mut ContainerFrame> {
        match &mut self.heap {
            Some(items) => items.last_mut(),
            None => self.len.checked_sub(1).map(|i| &mut self.inline[i]),
        }
    }
}

#[cfg(not(feature = "alloc"))]
struct ContainerStack<const N: usize> {
    buf: [ContainerFrame; N],
    len: usize,
}

#[cfg(not(feature = "alloc"))]
impl<const N: usize> ContainerStack<N> {
    const fn new() -> Self {
        Self {
            buf: [ContainerFrame::Array; N],
            len: 0,
        }
    }

    fn push(&mut self, frame: ContainerFrame, off: usize) -> Result<(), CborError> {
        if self.len < N {
            self.buf[self.len] = frame;
            self.len += 1;
            Ok(())
        } else {
            Err(CborError::new(ErrorCode::DepthLimitExceeded, off))
        }
    }

    fn pop(&mut self) -> Option<ContainerFrame> {
        if self.len == 0 {
            None
        } else {
            self.len -= 1;
            Some(self.buf[self.len])
        }
    }

    fn peek(&self) -> Option<ContainerFrame> {
        if self.len == 0 {
            None
        } else {
            Some(self.buf[self.len - 1])
        }
    }

    fn peek_mut(&mut self) -> Option<&mut ContainerFrame> {
        if self.len == 0 {
            None
        } else {
            Some(&mut self.buf[self.len - 1])
        }
    }
}

#[cfg(feature = "alloc")]
type ContainerStackImpl = ContainerStack;
#[cfg(not(feature = "alloc"))]
type ContainerStackImpl = ContainerStack<INLINE_CONTAINER_FRAMES>;

/// Streaming decoder over canonical CBOR bytes.
pub struct Decoder<'de> {
    cursor: Cursor<'de, CborError>,
    limits: DecodeLimits,
    depth: usize,
    items_seen: usize,
    checked: bool,
    containers: ContainerStackImpl,
}

impl<'de> Decoder<'de> {
    /// Construct a decoder over canonical bytes with the provided limits.
    ///
    /// This assumes the input is already canonical; use `new_checked` to enforce canonical
    /// constraints while decoding.
    ///
    /// # Errors
    ///
    /// Returns `MessageLenLimitExceeded` if `bytes` exceeds the input limit.
    pub const fn new_trusted(
        canon: CborBytesRef<'de>,
        limits: DecodeLimits,
    ) -> Result<Self, CborError> {
        Self::new_with(canon.as_bytes(), limits, false)
    }

    /// Construct a decoder that enforces canonical constraints while decoding.
    ///
    /// # Errors
    ///
    /// Returns `MessageLenLimitExceeded` if `bytes` exceeds the input limit.
    pub const fn new_checked(bytes: &'de [u8], limits: DecodeLimits) -> Result<Self, CborError> {
        Self::new_with(bytes, limits, true)
    }

    const fn new_with(
        bytes: &'de [u8],
        limits: DecodeLimits,
        checked: bool,
    ) -> Result<Self, CborError> {
        if bytes.len() > limits.max_input_bytes {
            return Err(CborError::new(ErrorCode::MessageLenLimitExceeded, 0));
        }
        Ok(Self {
            cursor: Cursor::with_pos(bytes, 0),
            limits,
            depth: 0,
            items_seen: 0,
            checked,
            containers: ContainerStackImpl::new(),
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
        if self.checked {
            wire::read_uint_arg::<true, CborError>(&mut self.cursor, ai, off)
        } else {
            wire::read_uint_arg::<false, CborError>(&mut self.cursor, ai, off)
        }
    }

    #[inline]
    fn read_len(&mut self, ai: u8, off: usize) -> Result<usize, CborError> {
        if self.checked {
            wire::read_len::<true, CborError>(&mut self.cursor, ai, off)
        } else {
            wire::read_len::<false, CborError>(&mut self.cursor, ai, off)
        }
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
        if self.checked {
            let _ = self.containers.pop();
        }
    }

    #[inline]
    fn parse_text_from_header(&mut self, off: usize, ai: u8) -> Result<&'de str, CborError> {
        if self.checked {
            wire::parse_text_from_header::<true, CborError>(
                &mut self.cursor,
                Some(&self.limits),
                off,
                ai,
            )
        } else {
            wire::parse_text_from_header::<false, CborError>(
                &mut self.cursor,
                Some(&self.limits),
                off,
                ai,
            )
        }
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
        if self.checked {
            wire::parse_bignum::<true, CborError>(&mut self.cursor, Some(&self.limits), off, ai)
        } else {
            wire::parse_bignum::<false, CborError>(&mut self.cursor, Some(&self.limits), off, ai)
        }
    }

    fn parse_safe_i64(&mut self) -> Result<i64, CborError> {
        let (major, ai, off) = self.read_header()?;
        match major {
            0 => {
                let v = self.read_uint_arg(ai, off)?;
                if self.checked && v > MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                i64::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
            }
            1 => {
                let n = self.read_uint_arg(ai, off)?;
                if self.checked && n >= MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
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
        if major != 7 {
            return Err(CborError::new(ErrorCode::ExpectedFloat, off));
        }
        if ai != 27 {
            if !self.checked {
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
        if self.checked {
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
            24 => {
                if !self.checked {
                    return Err(CborError::new(ErrorCode::ExpectedBool, off));
                }
                let simple = self.cursor.read_u8()?;
                if simple < 24 {
                    return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off))
            }
            28..=30 => {
                if self.checked {
                    Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off))
                } else {
                    Err(CborError::new(ErrorCode::ExpectedBool, off))
                }
            }
            _ => {
                if self.checked {
                    Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off))
                } else {
                    Err(CborError::new(ErrorCode::ExpectedBool, off))
                }
            }
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
            24 => {
                if !self.checked {
                    return Err(CborError::new(ErrorCode::ExpectedNull, off));
                }
                let simple = self.cursor.read_u8()?;
                if simple < 24 {
                    return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off))
            }
            28..=30 => {
                if self.checked {
                    Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off))
                } else {
                    Err(CborError::new(ErrorCode::ExpectedNull, off))
                }
            }
            _ => {
                if self.checked {
                    Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off))
                } else {
                    Err(CborError::new(ErrorCode::ExpectedNull, off))
                }
            }
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
        if entered && self.checked {
            self.containers.push(ContainerFrame::Array, off)?;
        }
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
        if entered && self.checked {
            self.containers.push(
                ContainerFrame::Map {
                    prev_key_range: None,
                },
                off,
            )?;
        }
        Ok((len, entered))
    }

    /// Decode the next map key as a text string.
    ///
    /// # Errors
    ///
    /// Returns `MapKeyMustBeText` if the next key is not a text string.
    pub fn parse_text_key(&mut self) -> Result<&'de str, CborError> {
        let key_start = self.position();
        let (major, ai, off) = self.read_header()?;
        if major != 3 {
            return Err(CborError::new(ErrorCode::MapKeyMustBeText, off));
        }
        let s = self.parse_text_from_header(off, ai)?;
        if self.checked {
            let key_end = self.position();
            let prev = match self.containers.peek() {
                Some(ContainerFrame::Map { prev_key_range }) => prev_key_range,
                Some(ContainerFrame::Array) | None => {
                    return Err(CborError::new(ErrorCode::MalformedCanonical, key_start));
                }
            };
            let mut next_prev = prev;
            wire::check_map_key_order(self.data(), &mut next_prev, key_start, key_end)?;
            let frame = self
                .containers
                .peek_mut()
                .ok_or_else(|| CborError::new(ErrorCode::MalformedCanonical, key_start))?;
            match frame {
                ContainerFrame::Map { prev_key_range } => {
                    *prev_key_range = next_prev;
                }
                ContainerFrame::Array => {
                    return Err(CborError::new(ErrorCode::MalformedCanonical, key_start));
                }
            }
        }
        Ok(s)
    }

    /// Skip exactly one CBOR value while enforcing decode limits.
    ///
    /// # Errors
    ///
    /// Returns a decode error if the value is malformed or violates limits.
    pub fn skip_value(&mut self) -> Result<(), CborError> {
        if self.checked {
            wire::skip_one_value::<true, CborError>(
                &mut self.cursor,
                Some(&self.limits),
                &mut self.items_seen,
                self.depth,
            )
        } else {
            wire::skip_one_value::<false, CborError>(
                &mut self.cursor,
                Some(&self.limits),
                &mut self.items_seen,
                self.depth,
            )
        }
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
                let tag = if self.checked {
                    wire::read_uint_arg_at::<true, CborError>(self.data(), &mut pos, ai, off)?
                } else {
                    wire::read_uint_arg_at::<false, CborError>(self.data(), &mut pos, ai, off)?
                };
                match tag {
                    2 | 3 => Ok(CborKind::Integer),
                    _ => Err(CborError::new(ErrorCode::MalformedCanonical, off)),
                }
            }
            7 => match ai {
                20 | 21 => Ok(CborKind::Bool),
                22 => Ok(CborKind::Null),
                27 => Ok(CborKind::Float),
                24 => {
                    if !self.checked {
                        return Err(CborError::new(ErrorCode::MalformedCanonical, off));
                    }
                    let simple = wire::read_u8(self.data(), &mut pos)?;
                    if simple < 24 {
                        Err(CborError::new(ErrorCode::NonCanonicalEncoding, off))
                    } else {
                        Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off))
                    }
                }
                28..=30 => {
                    if self.checked {
                        Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off))
                    } else {
                        Err(CborError::new(ErrorCode::MalformedCanonical, off))
                    }
                }
                _ => {
                    if self.checked {
                        Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off))
                    } else {
                        Err(CborError::new(ErrorCode::MalformedCanonical, off))
                    }
                }
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
    let mut decoder = Decoder::new_checked(bytes, limits)?;
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
    let limits = DecodeLimits::for_bytes(canon.len());
    let mut decoder = Decoder::new_trusted(canon, limits)?;
    let value = T::decode(&mut decoder)?;
    if decoder.position() != canon.len() {
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
/// Encode a value into an existing encoder, reusing its capacity.
///
/// # Errors
///
/// Returns an error if encoding fails.
pub fn encode_into<T: CborEncode>(enc: &mut Encoder, value: &T) -> Result<(), CborError> {
    enc.clear();
    value.encode(enc)
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
                if decoder.checked && v > MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                let v_i = i64::try_from(v)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))?;
                Ok(Self::from(v_i))
            }
            1 => {
                let n = decoder.read_uint_arg(ai, off)?;
                if decoder.checked && n >= MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
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
                if decoder.checked && v > MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
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
        let mut out = alloc_util::try_vec_with_capacity::<T>(len, decoder.position())?;
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
        let mut out = alloc_util::try_vec_with_capacity::<(&'de str, V)>(len, decoder.position())?;
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
        let mut out = alloc_util::try_vec_with_capacity::<(String, V)>(len, decoder.position())?;
        for _ in 0..len {
            let key = decoder.parse_text_key()?;
            let value = V::decode(decoder)?;
            out.push((String::from(key), value));
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
        decoder.parse_text().map(Self::from)
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
