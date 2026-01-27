use crate::canonical::CborBytesRef;
use crate::limits::DEFAULT_MAX_DEPTH;
use crate::profile::MAX_SAFE_INTEGER;
use crate::profile::{is_strictly_increasing_encoded, validate_bignum_bytes, validate_f64_bits};
use crate::utf8;
use crate::wire;
use crate::{CborError, DecodeLimits, ErrorCode};

#[cfg(feature = "alloc")]
use crate::alloc_util::try_reserve;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

const INLINE_STACK: usize = DEFAULT_MAX_DEPTH + 2;

#[derive(Clone, Copy)]
enum Frame {
    Root {
        remaining: usize,
    },
    Array {
        remaining: usize,
    },
    MapChecked {
        remaining_pairs: usize,
        expecting_key: bool,
        prev_key_range: Option<(usize, usize)>,
    },
}

impl Frame {
    const fn is_container(self) -> bool {
        matches!(self, Self::Array { .. } | Self::MapChecked { .. })
    }

    const fn is_done(self) -> bool {
        match self {
            Self::Root { remaining } | Self::Array { remaining } => remaining == 0,
            Self::MapChecked {
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

    fn push(&mut self, frame: Frame, off: usize) -> Result<(), CborError> {
        try_reserve(&mut self.items, 1, off)?;
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

    fn push(&mut self, frame: Frame, off: usize) -> Result<(), CborError> {
        if self.len < N {
            self.inline[self.len] = Some(frame);
            self.len += 1;
            Ok(())
        } else {
            Err(CborError::new(ErrorCode::DepthLimitExceeded, off))
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

struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
    limits: Option<DecodeLimits>,
    items_seen: usize,
}

impl<'a> Parser<'a> {
    const fn new(data: &'a [u8], pos: usize, limits: Option<DecodeLimits>) -> Self {
        Self {
            data,
            pos,
            limits,
            items_seen: 0,
        }
    }

    fn skip_value(&mut self) -> Result<usize, CborError> {
        #[cfg(feature = "alloc")]
        let mut stack = FrameStack::new();
        #[cfg(not(feature = "alloc"))]
        let mut stack = FrameStack::<INLINE_STACK>::new();
        stack.push(Frame::Root { remaining: 1 }, self.pos)?;
        let mut depth: usize = 0;

        loop {
            loop {
                let done = match stack.peek() {
                    Some(frame) => frame.is_done(),
                    None => return Ok(self.pos),
                };
                if !done {
                    break;
                }
                let popped = stack
                    .pop()
                    .ok_or_else(|| CborError::new(ErrorCode::MalformedCanonical, self.pos))?;
                if popped.is_container() {
                    depth = depth.saturating_sub(1);
                }
                if stack.is_empty() {
                    return Ok(self.pos);
                }
            }

            let expecting_key = matches!(
                stack.peek(),
                Some(Frame::MapChecked {
                    expecting_key: true,
                    ..
                })
            );

            if expecting_key {
                let frame = stack
                    .peek_mut()
                    .ok_or_else(|| CborError::new(ErrorCode::MalformedCanonical, self.pos))?;
                self.parse_map_key_checked(frame)?;
                continue;
            }

            let off = self.pos;
            let new_frame = self.parse_value(off, depth)?;
            let frame = stack
                .peek_mut()
                .ok_or_else(|| CborError::new(ErrorCode::MalformedCanonical, self.pos))?;
            Self::consume_value(frame, off)?;
            if let Some(frame) = new_frame {
                stack.push(frame, off)?;
                if frame.is_container() {
                    depth = depth.saturating_add(1);
                }
            }
        }
    }

    fn parse_map_key_checked(&mut self, frame: &mut Frame) -> Result<(), CborError> {
        let Frame::MapChecked {
            expecting_key,
            prev_key_range,
            ..
        } = frame
        else {
            return Err(CborError::new(ErrorCode::MalformedCanonical, self.pos));
        };

        let key_start = self.pos;
        let ib = wire::read_u8(self.data, &mut self.pos)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if major != 3 {
            return Err(CborError::new(ErrorCode::MapKeyMustBeText, key_start));
        }
        let len = self.read_len(ai, key_start)?;
        if let Some(limits) = self.limits {
            Self::enforce_len(
                len,
                limits.max_text_len,
                ErrorCode::TextLenLimitExceeded,
                key_start,
            )?;
        }
        let bytes = wire::read_exact(self.data, &mut self.pos, len)?;
        utf8::validate(bytes).map_err(|()| CborError::new(ErrorCode::Utf8Invalid, key_start))?;
        let key_end = self.pos;
        let curr = &self.data[key_start..key_end];

        if let Some((ps, pe)) = *prev_key_range {
            let prev = &self.data[ps..pe];
            if prev == curr {
                return Err(CborError::new(ErrorCode::DuplicateMapKey, key_start));
            }
            if !is_strictly_increasing_encoded(prev, curr) {
                return Err(CborError::new(ErrorCode::NonCanonicalMapOrder, key_start));
            }
        }

        *prev_key_range = Some((key_start, key_end));
        *expecting_key = false;
        Ok(())
    }

    fn parse_value(&mut self, off: usize, depth: usize) -> Result<Option<Frame>, CborError> {
        let ib = wire::read_u8(self.data, &mut self.pos)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        match major {
            0 => self.parse_major0(ai, off),
            1 => self.parse_major1(ai, off),
            2 => self.parse_major2(ai, off),
            3 => self.parse_major3(ai, off),
            4 => self.parse_major4(ai, off, depth),
            5 => self.parse_major5(ai, off, depth),
            6 => self.parse_major6(ai, off),
            7 => self.parse_major7(ai, off),
            _ => Err(CborError::new(ErrorCode::MalformedCanonical, off)),
        }
    }

    fn parse_major0(&mut self, ai: u8, off: usize) -> Result<Option<Frame>, CborError> {
        let v = self.read_uint_arg(ai, off)?;
        if v > MAX_SAFE_INTEGER {
            return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
        }
        Ok(None)
    }

    fn parse_major1(&mut self, ai: u8, off: usize) -> Result<Option<Frame>, CborError> {
        let n = self.read_uint_arg(ai, off)?;
        if n >= MAX_SAFE_INTEGER {
            return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
        }
        Ok(None)
    }

    fn parse_major2(&mut self, ai: u8, off: usize) -> Result<Option<Frame>, CborError> {
        let len = self.read_len(ai, off)?;
        if let Some(limits) = self.limits {
            Self::enforce_len(
                len,
                limits.max_bytes_len,
                ErrorCode::BytesLenLimitExceeded,
                off,
            )?;
        }
        wire::read_exact(self.data, &mut self.pos, len)?;
        Ok(None)
    }

    fn parse_major3(&mut self, ai: u8, off: usize) -> Result<Option<Frame>, CborError> {
        let len = self.read_len(ai, off)?;
        if let Some(limits) = self.limits {
            Self::enforce_len(
                len,
                limits.max_text_len,
                ErrorCode::TextLenLimitExceeded,
                off,
            )?;
        }
        let bytes = wire::read_exact(self.data, &mut self.pos, len)?;
        utf8::validate(bytes).map_err(|()| CborError::new(ErrorCode::Utf8Invalid, off))?;
        Ok(None)
    }

    fn parse_major4(
        &mut self,
        ai: u8,
        off: usize,
        depth: usize,
    ) -> Result<Option<Frame>, CborError> {
        let len = self.read_len(ai, off)?;
        if let Some(limits) = self.limits {
            Self::enforce_len(
                len,
                limits.max_array_len,
                ErrorCode::ArrayLenLimitExceeded,
                off,
            )?;
        }
        self.bump_items(len, off)?;
        Self::ensure_depth(self, depth + 1, off)?;
        if len > 0 {
            Ok(Some(Frame::Array { remaining: len }))
        } else {
            Ok(None)
        }
    }

    fn parse_major5(
        &mut self,
        ai: u8,
        off: usize,
        depth: usize,
    ) -> Result<Option<Frame>, CborError> {
        let len = self.read_len(ai, off)?;
        if let Some(limits) = self.limits {
            Self::enforce_len(len, limits.max_map_len, ErrorCode::MapLenLimitExceeded, off)?;
        }
        let items = len
            .checked_mul(2)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
        self.bump_items(items, off)?;
        Self::ensure_depth(self, depth + 1, off)?;
        if len == 0 {
            return Ok(None);
        }
        Ok(Some(Frame::MapChecked {
            remaining_pairs: len,
            expecting_key: true,
            prev_key_range: None,
        }))
    }

    fn parse_major6(&mut self, ai: u8, off: usize) -> Result<Option<Frame>, CborError> {
        let tag = self.read_uint_arg(ai, off)?;
        let negative = match tag {
            2 => false,
            3 => true,
            _ => return Err(CborError::new(ErrorCode::ForbiddenOrMalformedTag, off)),
        };
        let m_off = self.pos;
        let first = wire::read_u8(self.data, &mut self.pos)?;
        let m_major = first >> 5;
        let m_ai = first & 0x1f;
        if m_major != 2 {
            return Err(CborError::new(ErrorCode::ForbiddenOrMalformedTag, m_off));
        }
        let m_len = self.read_len(m_ai, m_off)?;
        if let Some(limits) = self.limits {
            Self::enforce_len(
                m_len,
                limits.max_bytes_len,
                ErrorCode::BytesLenLimitExceeded,
                m_off,
            )?;
        }
        let mag = wire::read_exact(self.data, &mut self.pos, m_len)?;
        validate_bignum_bytes(negative, mag).map_err(|code| CborError::new(code, m_off))?;
        Ok(None)
    }

    fn parse_major7(&mut self, ai: u8, off: usize) -> Result<Option<Frame>, CborError> {
        match ai {
            20..=22 => Ok(None),
            27 => {
                let bits = wire::read_be_u64(self.data, &mut self.pos)?;
                validate_f64_bits(bits).map_err(|code| CborError::new(code, off))?;
                Ok(None)
            }
            28..=30 => Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
            24 => {
                let simple = wire::read_u8(self.data, &mut self.pos)?;
                if simple < 24 {
                    return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off))
            }
            _ => Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off)),
        }
    }

    fn consume_value(frame: &mut Frame, off: usize) -> Result<(), CborError> {
        match frame {
            Frame::Root { remaining } | Frame::Array { remaining } => {
                *remaining = remaining
                    .checked_sub(1)
                    .ok_or_else(|| CborError::new(ErrorCode::MalformedCanonical, off))?;
            }
            Frame::MapChecked {
                remaining_pairs,
                expecting_key,
                ..
            } => {
                if *expecting_key {
                    return Err(CborError::new(ErrorCode::MalformedCanonical, off));
                }
                *remaining_pairs = remaining_pairs
                    .checked_sub(1)
                    .ok_or_else(|| CborError::new(ErrorCode::MalformedCanonical, off))?;
                *expecting_key = true;
            }
        }
        Ok(())
    }

    fn read_uint_arg(&mut self, ai: u8, off: usize) -> Result<u64, CborError> {
        wire::read_uint_checked(self.data, &mut self.pos, ai, off)
    }

    fn read_len(&mut self, ai: u8, off: usize) -> Result<usize, CborError> {
        let len_u64 = wire::read_len_checked(self.data, &mut self.pos, ai, off)?;
        wire::len_to_usize(len_u64, off)
    }

    const fn enforce_len(
        len: usize,
        max_len: usize,
        code: ErrorCode,
        off: usize,
    ) -> Result<(), CborError> {
        if len > max_len {
            return Err(CborError::new(code, off));
        }
        Ok(())
    }

    fn bump_items(&mut self, add: usize, off: usize) -> Result<(), CborError> {
        let Some(limits) = self.limits else {
            return Ok(());
        };
        self.items_seen = self
            .items_seen
            .checked_add(add)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
        if self.items_seen > limits.max_total_items {
            return Err(CborError::new(ErrorCode::TotalItemsLimitExceeded, off));
        }
        Ok(())
    }

    const fn ensure_depth(&self, next_depth: usize, off: usize) -> Result<(), CborError> {
        let Some(limits) = self.limits else {
            return Ok(());
        };
        if next_depth > limits.max_depth {
            return Err(CborError::new(ErrorCode::DepthLimitExceeded, off));
        }
        Ok(())
    }
}

/// Validate that `bytes` contain exactly one canonical SACP-CBOR/1 data item.
///
/// This is an allocation-free hot-path validator.
///
/// # Errors
///
/// Returns an error if decoding fails (EOF, trailing bytes, limit violations) or if validation fails
/// (non-canonical encoding, forbidden tags, map ordering, etc.).
pub fn validate(bytes: &[u8], limits: DecodeLimits) -> Result<(), CborError> {
    validate_canonical(bytes, limits).map(|_| ())
}

/// Validate that `bytes` contain exactly one canonical SACP-CBOR/1 data item and return a wrapper.
///
/// # Errors
///
/// Returns an error if decoding fails (EOF, trailing bytes, limit violations) or if validation fails
/// (non-canonical encoding, forbidden tags, map ordering, etc.).
pub fn validate_canonical(
    bytes: &'_ [u8],
    limits: DecodeLimits,
) -> Result<CborBytesRef<'_>, CborError> {
    if bytes.len() > limits.max_input_bytes {
        return Err(CborError::new(ErrorCode::MessageLenLimitExceeded, 0));
    }
    let end = value_end_internal(bytes, 0, Some(limits))?;
    if end != bytes.len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, end));
    }
    Ok(CborBytesRef::new(bytes))
}

pub fn value_end_trusted(data: &[u8], start: usize) -> Result<usize, CborError> {
    wire::skip_value_trusted(data, start)
}

fn value_end_internal(
    data: &[u8],
    start: usize,
    limits: Option<DecodeLimits>,
) -> Result<usize, CborError> {
    let mut p = Parser::new(data, start, limits);
    p.skip_value()
}
