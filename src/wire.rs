use core::marker::PhantomData;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use core::alloc::Layout;

use crate::limits::DEFAULT_MAX_DEPTH;
use crate::profile::{
    is_strictly_increasing_encoded, validate_bignum_bytes, validate_f64_bits, MAX_SAFE_INTEGER,
};
use crate::utf8;
use crate::{CborError, DecodeLimits, ErrorCode};

pub trait DecodeError: Sized {
    fn new(code: ErrorCode, offset: usize) -> Self;
}

impl DecodeError for CborError {
    #[inline]
    fn new(code: ErrorCode, offset: usize) -> Self {
        Self::new(code, offset)
    }
}

pub struct Cursor<'a, E: DecodeError> {
    data: &'a [u8],
    pos: usize,
    _marker: PhantomData<E>,
}

impl<'a, E: DecodeError> Cursor<'a, E> {
    #[inline]
    pub const fn with_pos(data: &'a [u8], pos: usize) -> Self {
        Self {
            data,
            pos,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub const fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    #[inline]
    pub fn read_u8(&mut self) -> Result<u8, E> {
        read_u8_at(self.data, &mut self.pos)
    }

    #[inline]
    pub fn read_exact(&mut self, n: usize) -> Result<&'a [u8], E> {
        read_exact_at(self.data, &mut self.pos, n)
    }

    #[inline]
    pub fn read_be_u64(&mut self) -> Result<u64, E> {
        let s = self.read_exact(8)?;
        Ok(u64::from_be_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }
}

#[inline]
fn read_u8_at<E: DecodeError>(data: &[u8], pos: &mut usize) -> Result<u8, E> {
    let off = *pos;
    let b = *data
        .get(*pos)
        .ok_or_else(|| E::new(ErrorCode::UnexpectedEof, off))?;
    *pos += 1;
    Ok(b)
}

#[inline]
fn read_exact_at<'a, E: DecodeError>(
    data: &'a [u8],
    pos: &mut usize,
    n: usize,
) -> Result<&'a [u8], E> {
    let off = *pos;
    let end = pos
        .checked_add(n)
        .ok_or_else(|| E::new(ErrorCode::LengthOverflow, off))?;
    if end > data.len() {
        return Err(E::new(ErrorCode::UnexpectedEof, off));
    }
    let s = &data[*pos..end];
    *pos = end;
    Ok(s)
}

pub fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8, CborError> {
    read_u8_at::<CborError>(data, pos)
}

pub fn read_exact<'a>(data: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], CborError> {
    read_exact_at::<CborError>(data, pos, n)
}

#[inline]
pub fn read_uint_arg_at<const CHECKED: bool, E: DecodeError>(
    data: &[u8],
    pos: &mut usize,
    ai: u8,
    off: usize,
) -> Result<u64, E> {
    match ai {
        0..=23 => Ok(u64::from(ai)),
        24 => {
            let v = u64::from(read_u8_at::<E>(data, pos)?);
            if CHECKED && v < 24 {
                return Err(E::new(ErrorCode::NonCanonicalEncoding, off));
            }
            Ok(v)
        }
        25 => {
            let v = u64::from({
                let s = read_exact_at::<E>(data, pos, 2)?;
                u16::from_be_bytes([s[0], s[1]])
            });
            if CHECKED && u8::try_from(v).is_ok() {
                return Err(E::new(ErrorCode::NonCanonicalEncoding, off));
            }
            Ok(v)
        }
        26 => {
            let v = u64::from({
                let s = read_exact_at::<E>(data, pos, 4)?;
                u32::from_be_bytes([s[0], s[1], s[2], s[3]])
            });
            if CHECKED && u16::try_from(v).is_ok() {
                return Err(E::new(ErrorCode::NonCanonicalEncoding, off));
            }
            Ok(v)
        }
        27 => {
            let v = {
                let s = read_exact_at::<E>(data, pos, 8)?;
                u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
            };
            if CHECKED && u32::try_from(v).is_ok() {
                return Err(E::new(ErrorCode::NonCanonicalEncoding, off));
            }
            Ok(v)
        }
        _ => Err(E::new(ErrorCode::ReservedAdditionalInfo, off)),
    }
}

#[inline]
pub fn read_uint_arg<const CHECKED: bool, E: DecodeError>(
    cursor: &mut Cursor<'_, E>,
    ai: u8,
    off: usize,
) -> Result<u64, E> {
    read_uint_arg_at::<CHECKED, E>(cursor.data, &mut cursor.pos, ai, off)
}

#[inline]
pub fn read_len_at<const CHECKED: bool, E: DecodeError>(
    data: &[u8],
    pos: &mut usize,
    ai: u8,
    off: usize,
) -> Result<usize, E> {
    if ai == 31 {
        return Err(E::new(ErrorCode::IndefiniteLengthForbidden, off));
    }
    let len = read_uint_arg_at::<CHECKED, E>(data, pos, ai, off)?;
    usize::try_from(len).map_err(|_| E::new(ErrorCode::LengthOverflow, off))
}

#[inline]
pub fn read_len<const CHECKED: bool, E: DecodeError>(
    cursor: &mut Cursor<'_, E>,
    ai: u8,
    off: usize,
) -> Result<usize, E> {
    read_len_at::<CHECKED, E>(cursor.data, &mut cursor.pos, ai, off)
}

pub fn read_uint_trusted(
    data: &[u8],
    pos: &mut usize,
    ai: u8,
    off: usize,
) -> Result<u64, CborError> {
    read_uint_arg_at::<false, CborError>(data, pos, ai, off)
}

pub fn read_len_trusted(
    data: &[u8],
    pos: &mut usize,
    ai: u8,
    off: usize,
) -> Result<usize, CborError> {
    read_len_at::<false, CborError>(data, pos, ai, off)
}

#[inline]
pub fn parse_text_from_header<'a, const CHECKED: bool, E: DecodeError>(
    cursor: &mut Cursor<'a, E>,
    limits: Option<&DecodeLimits>,
    off: usize,
    ai: u8,
) -> Result<&'a str, E> {
    let len = read_len::<CHECKED, E>(cursor, ai, off)?;
    if let Some(limits) = limits {
        if len > limits.max_text_len {
            return Err(E::new(ErrorCode::TextLenLimitExceeded, off));
        }
    }
    let bytes = cursor.read_exact(len)?;
    let s = if CHECKED {
        utf8::validate(bytes).map_err(|()| E::new(ErrorCode::Utf8Invalid, off))?
    } else {
        utf8::trusted(bytes).map_err(|()| E::new(ErrorCode::Utf8Invalid, off))?
    };
    Ok(s)
}

#[inline]
pub fn parse_bignum<'a, const CHECKED: bool, E: DecodeError>(
    cursor: &mut Cursor<'a, E>,
    limits: Option<&DecodeLimits>,
    off: usize,
    ai: u8,
) -> Result<(bool, &'a [u8]), E> {
    let tag = read_uint_arg::<CHECKED, E>(cursor, ai, off)?;
    let negative = match tag {
        2 => false,
        3 => true,
        _ => return Err(E::new(ErrorCode::ForbiddenOrMalformedTag, off)),
    };

    let m_off = cursor.position();
    let first = cursor.read_u8()?;
    let m_major = first >> 5;
    let m_ai = first & 0x1f;
    if m_major != 2 {
        return Err(E::new(ErrorCode::ForbiddenOrMalformedTag, m_off));
    }

    let m_len = read_len::<CHECKED, E>(cursor, m_ai, m_off)?;
    if let Some(limits) = limits {
        if m_len > limits.max_bytes_len {
            return Err(E::new(ErrorCode::BytesLenLimitExceeded, m_off));
        }
    }
    let mag = cursor.read_exact(m_len)?;

    if CHECKED {
        validate_bignum_bytes(negative, mag).map_err(|code| E::new(code, m_off))?;
    }

    Ok((negative, mag))
}

#[inline]
fn check_map_key_order<E: DecodeError>(
    data: &[u8],
    prev_key_range: &mut Option<(usize, usize)>,
    key_start: usize,
    key_end: usize,
) -> Result<(), E> {
    if let Some((ps, pe)) = *prev_key_range {
        let prev = &data[ps..pe];
        let curr = &data[key_start..key_end];
        if prev == curr {
            return Err(E::new(ErrorCode::DuplicateMapKey, key_start));
        }
        if !is_strictly_increasing_encoded(prev, curr) {
            return Err(E::new(ErrorCode::NonCanonicalMapOrder, key_start));
        }
    }
    *prev_key_range = Some((key_start, key_end));
    Ok(())
}

#[derive(Clone, Copy)]
enum Frame {
    Root {
        remaining: usize,
    },
    Array {
        remaining: usize,
    },
    Map {
        remaining_pairs: usize,
        expecting_key: bool,
        prev_key_range: Option<(usize, usize)>,
    },
}

impl Frame {
    const fn is_container(self) -> bool {
        matches!(self, Self::Array { .. } | Self::Map { .. })
    }

    const fn is_done(self) -> bool {
        match self {
            Self::Root { remaining } | Self::Array { remaining } => remaining == 0,
            Self::Map {
                remaining_pairs,
                expecting_key,
                ..
            } => remaining_pairs == 0 && expecting_key,
        }
    }
}

#[cfg(feature = "alloc")]
struct FrameStack {
    items: Vec<Frame>,
}

#[cfg(feature = "alloc")]
impl FrameStack {
    fn new() -> Self {
        Self {
            items: Vec::with_capacity(INLINE_STACK),
        }
    }

    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    fn push<E: DecodeError>(&mut self, frame: Frame, off: usize) -> Result<(), E> {
        try_reserve_vec::<Frame, E>(&mut self.items, 1, off)?;
        self.items.push(frame);
        Ok(())
    }

    fn pop(&mut self) -> Option<Frame> {
        self.items.pop()
    }

    fn peek(&self) -> Option<Frame> {
        self.items.last().copied()
    }

    fn peek_mut(&mut self) -> Option<&mut Frame> {
        self.items.last_mut()
    }
}

#[cfg(feature = "alloc")]
#[inline]
fn try_reserve_vec<T, E: DecodeError>(
    v: &mut Vec<T>,
    additional: usize,
    offset: usize,
) -> Result<(), E> {
    let needed = v
        .len()
        .checked_add(additional)
        .ok_or_else(|| E::new(ErrorCode::LengthOverflow, offset))?;
    if needed <= v.capacity() {
        return Ok(());
    }
    Layout::array::<T>(needed).map_err(|_| E::new(ErrorCode::LengthOverflow, offset))?;
    v.try_reserve(additional)
        .map_err(|_| E::new(ErrorCode::AllocationFailed, offset))
}

#[cfg(not(feature = "alloc"))]
struct FrameStack<const N: usize> {
    inline: [Option<Frame>; N],
    len: usize,
}

#[cfg(not(feature = "alloc"))]
impl<const N: usize> FrameStack<N> {
    const fn new() -> Self {
        Self {
            inline: [None; N],
            len: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push<E: DecodeError>(&mut self, frame: Frame, off: usize) -> Result<(), E> {
        if self.len < N {
            self.inline[self.len] = Some(frame);
            self.len += 1;
            Ok(())
        } else {
            Err(E::new(ErrorCode::DepthLimitExceeded, off))
        }
    }

    fn pop(&mut self) -> Option<Frame> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        self.inline[self.len].take()
    }

    fn peek(&self) -> Option<Frame> {
        if self.len == 0 {
            return None;
        }
        self.inline[self.len - 1]
    }

    fn peek_mut(&mut self) -> Option<&mut Frame> {
        if self.len == 0 {
            return None;
        }
        self.inline[self.len - 1].as_mut()
    }
}

const INLINE_STACK: usize = DEFAULT_MAX_DEPTH + 2;

#[inline]
fn bump_items<E: DecodeError>(
    limits: Option<&DecodeLimits>,
    items_seen: &mut usize,
    add: usize,
    off: usize,
) -> Result<(), E> {
    let Some(limits) = limits else {
        return Ok(());
    };
    *items_seen = items_seen
        .checked_add(add)
        .ok_or_else(|| E::new(ErrorCode::LengthOverflow, off))?;
    if *items_seen > limits.max_total_items {
        return Err(E::new(ErrorCode::TotalItemsLimitExceeded, off));
    }
    Ok(())
}

#[inline]
fn ensure_depth<E: DecodeError>(
    limits: Option<&DecodeLimits>,
    next_depth: usize,
    off: usize,
) -> Result<(), E> {
    let Some(limits) = limits else {
        return Ok(());
    };
    if next_depth > limits.max_depth {
        return Err(E::new(ErrorCode::DepthLimitExceeded, off));
    }
    Ok(())
}

#[inline]
fn consume_value<E: DecodeError>(frame: &mut Frame, off: usize) -> Result<(), E> {
    match frame {
        Frame::Root { remaining } | Frame::Array { remaining } => {
            *remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| E::new(ErrorCode::MalformedCanonical, off))?;
        }
        Frame::Map {
            remaining_pairs,
            expecting_key,
            ..
        } => {
            if *expecting_key {
                return Err(E::new(ErrorCode::MalformedCanonical, off));
            }
            *remaining_pairs = remaining_pairs
                .checked_sub(1)
                .ok_or_else(|| E::new(ErrorCode::MalformedCanonical, off))?;
            *expecting_key = true;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub fn skip_one_value<const CHECKED: bool, E: DecodeError>(
    cursor: &mut Cursor<'_, E>,
    limits: Option<&DecodeLimits>,
    items_seen: &mut usize,
    base_depth: usize,
) -> Result<(), E> {
    #[cfg(feature = "alloc")]
    let mut stack = FrameStack::new();
    #[cfg(not(feature = "alloc"))]
    let mut stack = FrameStack::<INLINE_STACK>::new();

    stack.push(Frame::Root { remaining: 1 }, cursor.position())?;
    let mut local_depth: usize = 0;

    loop {
        loop {
            let done = match stack.peek() {
                Some(frame) => frame.is_done(),
                None => return Ok(()),
            };
            if !done {
                break;
            }
            let popped = stack
                .pop()
                .ok_or_else(|| E::new(ErrorCode::MalformedCanonical, cursor.position()))?;
            if popped.is_container() {
                local_depth = local_depth.saturating_sub(1);
            }
            if stack.is_empty() {
                return Ok(());
            }
        }

        let expecting_key = matches!(
            stack.peek(),
            Some(Frame::Map {
                expecting_key: true,
                ..
            })
        );
        if expecting_key {
            let frame = stack
                .peek_mut()
                .ok_or_else(|| E::new(ErrorCode::MalformedCanonical, cursor.position()))?;
            let Frame::Map {
                expecting_key,
                prev_key_range,
                ..
            } = frame
            else {
                return Err(E::new(ErrorCode::MalformedCanonical, cursor.position()));
            };

            let key_start = cursor.position();
            let ib = cursor.read_u8()?;
            let major = ib >> 5;
            let ai = ib & 0x1f;
            if major != 3 {
                return Err(E::new(ErrorCode::MapKeyMustBeText, key_start));
            }
            let _ = parse_text_from_header::<CHECKED, E>(cursor, limits, key_start, ai)?;
            let key_end = cursor.position();

            if CHECKED {
                check_map_key_order::<E>(cursor.data(), prev_key_range, key_start, key_end)?;
            }

            *expecting_key = false;
            continue;
        }

        let off = cursor.position();
        let ib = cursor.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        let mut new_frame: Option<Frame> = None;

        match major {
            0 => {
                let v = read_uint_arg::<CHECKED, E>(cursor, ai, off)?;
                if CHECKED && v > MAX_SAFE_INTEGER {
                    return Err(E::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
            }
            1 => {
                let n = read_uint_arg::<CHECKED, E>(cursor, ai, off)?;
                if CHECKED && n >= MAX_SAFE_INTEGER {
                    return Err(E::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
            }
            2 => {
                let len = read_len::<CHECKED, E>(cursor, ai, off)?;
                if let Some(limits) = limits {
                    if len > limits.max_bytes_len {
                        return Err(E::new(ErrorCode::BytesLenLimitExceeded, off));
                    }
                }
                let _ = cursor.read_exact(len)?;
            }
            3 => {
                let len = read_len::<CHECKED, E>(cursor, ai, off)?;
                if let Some(limits) = limits {
                    if len > limits.max_text_len {
                        return Err(E::new(ErrorCode::TextLenLimitExceeded, off));
                    }
                }
                let bytes = cursor.read_exact(len)?;
                if CHECKED {
                    utf8::validate(bytes).map_err(|()| E::new(ErrorCode::Utf8Invalid, off))?;
                } else {
                    utf8::trusted(bytes).map_err(|()| E::new(ErrorCode::Utf8Invalid, off))?;
                }
            }
            4 => {
                let len = read_len::<CHECKED, E>(cursor, ai, off)?;
                if let Some(limits) = limits {
                    if len > limits.max_array_len {
                        return Err(E::new(ErrorCode::ArrayLenLimitExceeded, off));
                    }
                }
                bump_items::<E>(limits, items_seen, len, off)?;
                ensure_depth::<E>(limits, base_depth + local_depth + 1, off)?;
                if len > 0 {
                    new_frame = Some(Frame::Array { remaining: len });
                }
            }
            5 => {
                let len = read_len::<CHECKED, E>(cursor, ai, off)?;
                if let Some(limits) = limits {
                    if len > limits.max_map_len {
                        return Err(E::new(ErrorCode::MapLenLimitExceeded, off));
                    }
                }
                let items = len
                    .checked_mul(2)
                    .ok_or_else(|| E::new(ErrorCode::LengthOverflow, off))?;
                bump_items::<E>(limits, items_seen, items, off)?;
                ensure_depth::<E>(limits, base_depth + local_depth + 1, off)?;
                if len > 0 {
                    new_frame = Some(Frame::Map {
                        remaining_pairs: len,
                        expecting_key: true,
                        prev_key_range: None,
                    });
                }
            }
            6 => {
                let _ = parse_bignum::<CHECKED, E>(cursor, limits, off, ai)?;
            }
            7 => match ai {
                20..=22 => {}
                27 => {
                    let bits = cursor.read_be_u64()?;
                    validate_f64_bits(bits).map_err(|code| E::new(code, off))?;
                }
                24 => {
                    let simple = cursor.read_u8()?;
                    if simple < 24 {
                        return Err(E::new(ErrorCode::NonCanonicalEncoding, off));
                    }
                    return Err(E::new(ErrorCode::UnsupportedSimpleValue, off));
                }
                28..=30 => return Err(E::new(ErrorCode::ReservedAdditionalInfo, off)),
                _ => return Err(E::new(ErrorCode::UnsupportedSimpleValue, off)),
            },
            _ => return Err(E::new(ErrorCode::MalformedCanonical, off)),
        }

        let frame = stack
            .peek_mut()
            .ok_or_else(|| E::new(ErrorCode::MalformedCanonical, cursor.position()))?;
        consume_value::<E>(frame, off)?;

        if let Some(frame) = new_frame {
            stack.push::<E>(frame, off)?;
            if frame.is_container() {
                local_depth = local_depth.saturating_add(1);
            }
        }
    }
}
