use crate::canonical::CborBytesRef;
use crate::limits::DEFAULT_MAX_DEPTH;
use crate::profile::MAX_SAFE_INTEGER;
use crate::profile::{is_strictly_increasing_encoded, validate_bignum_bytes, validate_f64_bits};
use crate::{CborError, DecodeLimits, ErrorCode};

#[cfg(feature = "alloc")]
use crate::scalar::F64Bits;
#[cfg(feature = "alloc")]
use crate::value::{BigInt, CborInteger, CborMap, CborValue};
#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

const INLINE_STACK: usize = DEFAULT_MAX_DEPTH + 2;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Checked,
    Trusted,
}

#[derive(Clone, Copy)]
enum Frame {
    Root {
        remaining: usize,
    },
    Array {
        remaining: usize,
    },
    MapAny {
        remaining: usize,
    },
    MapChecked {
        remaining_pairs: usize,
        expecting_key: bool,
        prev_key_range: Option<(usize, usize)>,
    },
    Tag {
        remaining: usize,
    },
}

impl Frame {
    const fn is_container(self) -> bool {
        matches!(
            self,
            Self::Array { .. } | Self::MapAny { .. } | Self::MapChecked { .. }
        )
    }

    const fn is_done(self) -> bool {
        match self {
            Self::Root { remaining }
            | Self::Array { remaining }
            | Self::MapAny { remaining }
            | Self::Tag { remaining } => remaining == 0,
            Self::MapChecked {
                remaining_pairs,
                expecting_key,
                ..
            } => remaining_pairs == 0 && expecting_key,
        }
    }
}

struct FrameStack<const N: usize> {
    inline: [Option<Frame>; N],
    len: usize,
    #[cfg(feature = "alloc")]
    overflow: Vec<Frame>,
}

impl<const N: usize> FrameStack<N> {
    const fn new() -> Self {
        Self {
            inline: [None; N],
            len: 0,
            #[cfg(feature = "alloc")]
            overflow: Vec::new(),
        }
    }

    fn len(&self) -> usize {
        #[cfg(feature = "alloc")]
        {
            self.len + self.overflow.len()
        }
        #[cfg(not(feature = "alloc"))]
        {
            self.len
        }
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(feature = "alloc")]
    fn push(&mut self, frame: Frame, _off: usize) -> Result<(), CborError> {
        if !self.overflow.is_empty() {
            self.overflow.push(frame);
            return Ok(());
        }
        let idx = self.len;
        if idx < N {
            self.inline[idx] = Some(frame);
            self.len = idx
                .checked_add(1)
                .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, _off))?;
            return Ok(());
        }
        self.overflow.push(frame);
        Ok(())
    }

    #[cfg(not(feature = "alloc"))]
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
        #[cfg(feature = "alloc")]
        {
            if let Some(frame) = self.overflow.pop() {
                return Some(frame);
            }
        }
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        self.inline[self.len].take()
    }

    fn peek(&self) -> Option<Frame> {
        #[cfg(feature = "alloc")]
        {
            if let Some(frame) = self.overflow.last() {
                return Some(*frame);
            }
        }
        if self.len == 0 {
            return None;
        }
        self.inline[self.len - 1]
    }

    fn peek_mut(&mut self) -> Option<&mut Frame> {
        #[cfg(feature = "alloc")]
        {
            if let Some(frame) = self.overflow.last_mut() {
                return Some(frame);
            }
        }
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
    mode: Mode,
}

impl<'a> Parser<'a> {
    const fn new(data: &'a [u8], pos: usize, limits: Option<DecodeLimits>, mode: Mode) -> Self {
        Self {
            data,
            pos,
            limits,
            items_seen: 0,
            mode,
        }
    }

    fn skip_value(&mut self) -> Result<usize, CborError> {
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
        let ib = self.read_u8()?;
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
        let bytes = self.read_exact(len)?;
        core::str::from_utf8(bytes)
            .map_err(|_| CborError::new(ErrorCode::Utf8Invalid, key_start))?;
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
        let ib = self.read_u8()?;
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
        if self.mode == Mode::Checked && v > MAX_SAFE_INTEGER {
            return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
        }
        Ok(None)
    }

    fn parse_major1(&mut self, ai: u8, off: usize) -> Result<Option<Frame>, CborError> {
        let n = self.read_uint_arg(ai, off)?;
        if self.mode == Mode::Checked && n >= MAX_SAFE_INTEGER {
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
        self.read_exact(len)?;
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
        let bytes = self.read_exact(len)?;
        if self.mode == Mode::Checked {
            core::str::from_utf8(bytes).map_err(|_| CborError::new(ErrorCode::Utf8Invalid, off))?;
        }
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
        if self.mode == Mode::Checked {
            self.bump_items(len, off)?;
            Self::ensure_depth(self, depth + 1, off)?;
        }
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
        if self.mode == Mode::Checked {
            let items = len
                .checked_mul(2)
                .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
            self.bump_items(items, off)?;
            Self::ensure_depth(self, depth + 1, off)?;
        }
        if len == 0 {
            return Ok(None);
        }
        if self.mode == Mode::Checked {
            Ok(Some(Frame::MapChecked {
                remaining_pairs: len,
                expecting_key: true,
                prev_key_range: None,
            }))
        } else {
            let items = len
                .checked_mul(2)
                .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
            Ok(Some(Frame::MapAny { remaining: items }))
        }
    }

    fn parse_major6(&mut self, ai: u8, off: usize) -> Result<Option<Frame>, CborError> {
        let tag = self.read_uint_arg(ai, off)?;
        if self.mode == Mode::Checked {
            let negative = match tag {
                2 => false,
                3 => true,
                _ => return Err(CborError::new(ErrorCode::ForbiddenOrMalformedTag, off)),
            };
            let m_off = self.pos;
            let first = self.read_u8()?;
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
            let mag = self.read_exact(m_len)?;
            validate_bignum_bytes(negative, mag).map_err(|code| CborError::new(code, m_off))?;
            Ok(None)
        } else {
            Ok(Some(Frame::Tag { remaining: 1 }))
        }
    }

    fn parse_major7(&mut self, ai: u8, off: usize) -> Result<Option<Frame>, CborError> {
        if self.mode == Mode::Checked {
            match ai {
                20..=22 => Ok(None),
                27 => {
                    let bits = self.read_be_u64()?;
                    validate_f64_bits(bits).map_err(|code| CborError::new(code, off))?;
                    Ok(None)
                }
                28..=30 => Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
                24 => {
                    let simple = self.read_u8()?;
                    if simple < 24 {
                        return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                    }
                    Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off))
                }
                _ => Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off)),
            }
        } else {
            match ai {
                0..=23 => Ok(None),
                24 => {
                    self.read_u8()?;
                    Ok(None)
                }
                25 => {
                    self.read_be_u16()?;
                    Ok(None)
                }
                26 => {
                    self.read_be_u32()?;
                    Ok(None)
                }
                27 => {
                    self.read_be_u64()?;
                    Ok(None)
                }
                28..=30 => Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
                _ => Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off)),
            }
        }
    }

    fn consume_value(frame: &mut Frame, off: usize) -> Result<(), CborError> {
        match frame {
            Frame::Root { remaining }
            | Frame::Array { remaining }
            | Frame::MapAny { remaining }
            | Frame::Tag { remaining } => {
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

    fn read_u8(&mut self) -> Result<u8, CborError> {
        let off = self.pos;
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| CborError::new(ErrorCode::UnexpectedEof, off))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_exact(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let off = self.pos;
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
        if end > self.data.len() {
            return Err(CborError::new(ErrorCode::UnexpectedEof, off));
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn read_be_u16(&mut self) -> Result<u16, CborError> {
        let s = self.read_exact(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn read_be_u32(&mut self) -> Result<u32, CborError> {
        let s = self.read_exact(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_be_u64(&mut self) -> Result<u64, CborError> {
        let s = self.read_exact(8)?;
        Ok(u64::from_be_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn read_uint_arg(&mut self, ai: u8, off: usize) -> Result<u64, CborError> {
        match self.mode {
            Mode::Checked => self.read_uint_arg_checked(ai, off),
            Mode::Trusted => self.read_uint_arg_trusted(ai, off),
        }
    }

    fn read_uint_arg_checked(&mut self, ai: u8, off: usize) -> Result<u64, CborError> {
        let v = self.read_uint_arg_trusted(ai, off)?;
        match ai {
            0..=23 => Ok(v),
            24 => {
                if v < 24 {
                    return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Ok(v)
            }
            25 => {
                if u8::try_from(v).is_ok() {
                    return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Ok(v)
            }
            26 => {
                if u16::try_from(v).is_ok() {
                    return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Ok(v)
            }
            27 => {
                if u32::try_from(v).is_ok() {
                    return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Ok(v)
            }
            _ => Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
        }
    }

    fn read_uint_arg_trusted(&mut self, ai: u8, off: usize) -> Result<u64, CborError> {
        match ai {
            0..=23 => Ok(u64::from(ai)),
            24 => Ok(u64::from(self.read_u8()?)),
            25 => Ok(u64::from(self.read_be_u16()?)),
            26 => Ok(u64::from(self.read_be_u32()?)),
            27 => Ok(self.read_be_u64()?),
            _ => Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
        }
    }

    fn read_len(&mut self, ai: u8, off: usize) -> Result<usize, CborError> {
        let len_u64 = match self.mode {
            Mode::Checked => self.read_len_arg_checked(ai, off)?,
            Mode::Trusted => self.read_len_arg_trusted(ai, off)?,
        };
        usize::try_from(len_u64).map_err(|_| CborError::new(ErrorCode::LengthOverflow, off))
    }

    fn read_len_arg_checked(&mut self, ai: u8, off: usize) -> Result<u64, CborError> {
        if ai == 31 {
            return Err(CborError::new(ErrorCode::IndefiniteLengthForbidden, off));
        }
        self.read_uint_arg_checked(ai, off)
    }

    fn read_len_arg_trusted(&mut self, ai: u8, off: usize) -> Result<u64, CborError> {
        if ai == 31 {
            return Err(CborError::new(ErrorCode::IndefiniteLengthForbidden, off));
        }
        self.read_uint_arg_trusted(ai, off)
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
    let end = value_end_internal(bytes, 0, Some(limits), Mode::Checked)?;
    if end != bytes.len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, end));
    }
    Ok(CborBytesRef::new(bytes))
}

pub fn value_end_trusted(data: &[u8], start: usize) -> Result<usize, CborError> {
    value_end_internal(data, start, None, Mode::Trusted)
}

fn value_end_internal(
    data: &[u8],
    start: usize,
    limits: Option<DecodeLimits>,
    mode: Mode,
) -> Result<usize, CborError> {
    let mut p = Parser::new(data, start, limits, mode);
    p.skip_value()
}

#[cfg(feature = "alloc")]
enum ParsedItem {
    Value(CborValue),
    ArrayStart { len: usize },
    MapStart { len: usize },
}

#[cfg(feature = "alloc")]
enum BuildFrame {
    Array {
        items: Vec<CborValue>,
        remaining: usize,
    },
    Map {
        entries: Vec<(Box<str>, CborValue)>,
        remaining_pairs: usize,
        key: Option<Box<str>>,
    },
}

#[cfg(feature = "alloc")]
fn decode_value_trusted_inner(data: &[u8], start: usize) -> Result<(CborValue, usize), CborError> {
    use crate::alloc_util::{alloc_failed, try_vec_with_capacity};

    let mut p = Parser::new(data, start, None, Mode::Trusted);
    let mut stack: Vec<BuildFrame> = Vec::new();
    let mut pending: Option<CborValue> = None;

    loop {
        if let Some(value) = pending.take() {
            if let Some(frame) = stack.last_mut() {
                match frame {
                    BuildFrame::Array { items, remaining } => {
                        items.push(value);
                        *remaining = remaining
                            .checked_sub(1)
                            .ok_or_else(|| CborError::new(ErrorCode::MalformedCanonical, p.pos))?;
                        if *remaining == 0 {
                            let items = core::mem::take(items);
                            stack.pop();
                            pending = Some(CborValue::array(items));
                        }
                    }
                    BuildFrame::Map {
                        entries,
                        remaining_pairs,
                        key,
                    } => {
                        let Some(k) = key.take() else {
                            return Err(CborError::new(ErrorCode::MalformedCanonical, p.pos));
                        };
                        entries.push((k, value));
                        *remaining_pairs = remaining_pairs
                            .checked_sub(1)
                            .ok_or_else(|| CborError::new(ErrorCode::MalformedCanonical, p.pos))?;
                        if *remaining_pairs == 0 {
                            let entries = core::mem::take(entries);
                            stack.pop();
                            pending = Some(CborValue::map(CborMap::from_sorted_entries(entries)));
                        }
                    }
                }
            } else {
                return Ok((value, p.pos));
            }
            continue;
        }

        if let Some(BuildFrame::Map { key, .. }) = stack.last_mut() {
            if key.is_none() {
                let k = parse_map_key(&mut p)?;
                *key = Some(k);
                continue;
            }
        }

        match parse_item(&mut p)? {
            ParsedItem::Value(v) => pending = Some(v),
            ParsedItem::ArrayStart { len } => {
                if len == 0 {
                    pending = Some(CborValue::array(Vec::new()));
                } else {
                    stack.try_reserve(1).map_err(|_| alloc_failed(p.pos))?;
                    stack.push(BuildFrame::Array {
                        items: try_vec_with_capacity(len, p.pos)?,
                        remaining: len,
                    });
                }
            }
            ParsedItem::MapStart { len } => {
                if len == 0 {
                    pending = Some(CborValue::map(CborMap::from_sorted_entries(Vec::new())));
                } else {
                    stack.try_reserve(1).map_err(|_| alloc_failed(p.pos))?;
                    stack.push(BuildFrame::Map {
                        entries: try_vec_with_capacity(len, p.pos)?,
                        remaining_pairs: len,
                        key: None,
                    });
                }
            }
        }
    }
}

#[cfg(feature = "alloc")]
pub fn decode_value_trusted_range(
    data: &[u8],
    start: usize,
    end: usize,
) -> Result<CborValue, CborError> {
    let (value, pos) = decode_value_trusted_inner(data, start)?;
    if pos != end {
        return Err(CborError::new(ErrorCode::MalformedCanonical, start));
    }
    Ok(value)
}

#[cfg(feature = "alloc")]
fn parse_map_key(p: &mut Parser<'_>) -> Result<Box<str>, CborError> {
    use crate::alloc_util::try_box_str_from_str;

    let off = p.pos;
    let ib = p.read_u8()?;
    let major = ib >> 5;
    let ai = ib & 0x1f;
    if major != 3 {
        return Err(CborError::new(ErrorCode::MapKeyMustBeText, off));
    }
    let len = p.read_len(ai, off)?;
    let bytes = p.read_exact(len)?;
    let text =
        core::str::from_utf8(bytes).map_err(|_| CborError::new(ErrorCode::Utf8Invalid, off))?;
    try_box_str_from_str(text, off)
}

#[cfg(feature = "alloc")]
fn parse_item(p: &mut Parser<'_>) -> Result<ParsedItem, CborError> {
    use crate::alloc_util::{try_box_str_from_str, try_vec_from_slice};

    let off = p.pos;
    let ib = p.read_u8()?;
    let major = ib >> 5;
    let ai = ib & 0x1f;

    match major {
        0 => {
            let v = p.read_uint_arg(ai, off)?;
            let v_i64 = i64::try_from(v)
                .map_err(|_| CborError::new(ErrorCode::IntegerOutsideSafeRange, off))?;
            Ok(ParsedItem::Value(CborValue::integer(
                CborInteger::new_safe_unchecked(v_i64),
            )))
        }
        1 => {
            let n = p.read_uint_arg(ai, off)?;
            let n_i128 = i128::from(n);
            let v_i128 = -1 - n_i128;
            let v_i64 = i64::try_from(v_i128)
                .map_err(|_| CborError::new(ErrorCode::IntegerOutsideSafeRange, off))?;
            Ok(ParsedItem::Value(CborValue::integer(
                CborInteger::new_safe_unchecked(v_i64),
            )))
        }
        2 => {
            let len = p.read_len(ai, off)?;
            let bytes = p.read_exact(len)?;
            let out = try_vec_from_slice(bytes, off)?;
            Ok(ParsedItem::Value(CborValue::bytes(out)))
        }
        3 => {
            let len = p.read_len(ai, off)?;
            let bytes = p.read_exact(len)?;
            let text = core::str::from_utf8(bytes)
                .map_err(|_| CborError::new(ErrorCode::Utf8Invalid, off))?;
            let boxed = try_box_str_from_str(text, off)?;
            Ok(ParsedItem::Value(CborValue::text(boxed)))
        }
        4 => {
            let len = p.read_len(ai, off)?;
            Ok(ParsedItem::ArrayStart { len })
        }
        5 => {
            let len = p.read_len(ai, off)?;
            Ok(ParsedItem::MapStart { len })
        }
        6 => {
            let tag = p.read_uint_arg(ai, off)?;
            let negative = match tag {
                2 => false,
                3 => true,
                _ => return Err(CborError::new(ErrorCode::ForbiddenOrMalformedTag, off)),
            };
            let m_off = p.pos;
            let first = p.read_u8()?;
            let m_major = first >> 5;
            let m_ai = first & 0x1f;
            if m_major != 2 {
                return Err(CborError::new(ErrorCode::ForbiddenOrMalformedTag, m_off));
            }
            let m_len = p.read_len(m_ai, m_off)?;
            let mag = p.read_exact(m_len)?;
            let mag = try_vec_from_slice(mag, m_off)?;
            let big = BigInt::new_unchecked(negative, mag);
            Ok(ParsedItem::Value(CborValue::integer(
                CborInteger::from_bigint(big),
            )))
        }
        7 => match ai {
            20 => Ok(ParsedItem::Value(CborValue::bool(false))),
            21 => Ok(ParsedItem::Value(CborValue::bool(true))),
            22 => Ok(ParsedItem::Value(CborValue::null())),
            27 => {
                let bits = p.read_be_u64()?;
                Ok(ParsedItem::Value(CborValue::float(F64Bits::new_unchecked(
                    bits,
                ))))
            }
            _ => Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off)),
        },
        _ => Err(CborError::new(ErrorCode::MalformedCanonical, off)),
    }
}
