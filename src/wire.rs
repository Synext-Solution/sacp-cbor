#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use crate::alloc_util::try_reserve;
#[cfg(not(feature = "alloc"))]
use crate::limits::DEFAULT_MAX_DEPTH;
use crate::profile::{
    check_encoded_key_order, is_minimal_uint_ai, validate_bignum_bytes, validate_f64_bits,
    MAX_SAFE_INTEGER,
};
use crate::utf8;
use crate::{CborError, DecodeLimits, ErrorCode, ValidationOptions};

/// Resource limits plus grammar-restriction options for one walk of a value.
///
/// Limits bound resources; options select restriction modes (checked walks only).
#[derive(Clone, Copy)]
pub struct WalkPolicy<'a> {
    pub limits: Option<&'a DecodeLimits>,
    pub options: ValidationOptions,
}

impl<'a> WalkPolicy<'a> {
    #[inline]
    pub const fn new(limits: Option<&'a DecodeLimits>, options: ValidationOptions) -> Self {
        Self { limits, options }
    }

    /// Policy for trusted re-traversal: no limits, no restriction modes.
    #[inline]
    pub const fn trusted() -> Self {
        Self {
            limits: None,
            options: ValidationOptions::new(),
        }
    }
}

pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    #[inline]
    pub const fn with_pos(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
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
    pub fn read_u8(&mut self) -> Result<u8, CborError> {
        read_u8_at(self.data, &mut self.pos)
    }

    #[inline]
    pub fn read_exact(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        read_exact_at(self.data, &mut self.pos, n)
    }

    #[inline]
    pub fn read_be_u64(&mut self) -> Result<u64, CborError> {
        let s = self.read_exact(8)?;
        Ok(u64::from_be_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }
}

#[inline]
fn read_u8_at(data: &[u8], pos: &mut usize) -> Result<u8, CborError> {
    let off = *pos;
    let b = *data
        .get(*pos)
        .ok_or_else(|| CborError::new(ErrorCode::UnexpectedEof, off))?;
    *pos += 1;
    Ok(b)
}

#[inline]
fn read_exact_at<'a>(data: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], CborError> {
    let off = *pos;
    let end = pos
        .checked_add(n)
        .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
    if end > data.len() {
        return Err(CborError::new(ErrorCode::UnexpectedEof, off));
    }
    let s = &data[*pos..end];
    *pos = end;
    Ok(s)
}

pub fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8, CborError> {
    read_u8_at(data, pos)
}

pub fn read_exact<'a>(data: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], CborError> {
    read_exact_at(data, pos, n)
}

#[inline]
pub fn read_uint_arg_at<const CHECKED: bool>(
    data: &[u8],
    pos: &mut usize,
    ai: u8,
    off: usize,
) -> Result<u64, CborError> {
    match ai {
        0..=23 => Ok(u64::from(ai)),
        24 => {
            let v = u64::from(read_u8_at(data, pos)?);
            if CHECKED && !is_minimal_uint_ai(ai, v) {
                return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
            }
            Ok(v)
        }
        25 => {
            let v = u64::from({
                let s = read_exact_at(data, pos, 2)?;
                u16::from_be_bytes([s[0], s[1]])
            });
            if CHECKED && !is_minimal_uint_ai(ai, v) {
                return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
            }
            Ok(v)
        }
        26 => {
            let v = u64::from({
                let s = read_exact_at(data, pos, 4)?;
                u32::from_be_bytes([s[0], s[1], s[2], s[3]])
            });
            if CHECKED && !is_minimal_uint_ai(ai, v) {
                return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
            }
            Ok(v)
        }
        27 => {
            let v = {
                let s = read_exact_at(data, pos, 8)?;
                u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
            };
            if CHECKED && !is_minimal_uint_ai(ai, v) {
                return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
            }
            Ok(v)
        }
        _ => Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
    }
}

#[inline]
pub fn read_uint_arg<const CHECKED: bool>(
    cursor: &mut Cursor<'_>,
    ai: u8,
    off: usize,
) -> Result<u64, CborError> {
    read_uint_arg_at::<CHECKED>(cursor.data, &mut cursor.pos, ai, off)
}

#[inline]
pub fn read_len_at<const CHECKED: bool>(
    data: &[u8],
    pos: &mut usize,
    ai: u8,
    off: usize,
) -> Result<usize, CborError> {
    if ai == 31 {
        return Err(CborError::new(ErrorCode::IndefiniteLengthForbidden, off));
    }
    let len = read_uint_arg_at::<CHECKED>(data, pos, ai, off)?;
    usize::try_from(len).map_err(|_| CborError::new(ErrorCode::LengthOverflow, off))
}

#[inline]
pub fn read_len<const CHECKED: bool>(
    cursor: &mut Cursor<'_>,
    ai: u8,
    off: usize,
) -> Result<usize, CborError> {
    read_len_at::<CHECKED>(cursor.data, &mut cursor.pos, ai, off)
}

pub fn read_uint_trusted(
    data: &[u8],
    pos: &mut usize,
    ai: u8,
    off: usize,
) -> Result<u64, CborError> {
    read_uint_arg_at::<false>(data, pos, ai, off)
}

pub fn read_len_trusted(
    data: &[u8],
    pos: &mut usize,
    ai: u8,
    off: usize,
) -> Result<usize, CborError> {
    read_len_at::<false>(data, pos, ai, off)
}

#[inline]
const fn trusted_canonical_err(cause: CborError) -> CborError {
    CborError::new(ErrorCode::MalformedCanonical, cause.offset)
}

#[inline]
pub fn read_u8_trusted_canonical(data: &[u8], pos: &mut usize) -> Result<u8, CborError> {
    read_u8(data, pos).map_err(trusted_canonical_err)
}

#[inline]
pub fn read_exact_trusted_canonical<'a>(
    data: &'a [u8],
    pos: &mut usize,
    n: usize,
) -> Result<&'a [u8], CborError> {
    read_exact(data, pos, n).map_err(trusted_canonical_err)
}

#[inline]
pub fn read_uint_trusted_canonical(
    data: &[u8],
    pos: &mut usize,
    ai: u8,
    off: usize,
) -> Result<u64, CborError> {
    read_uint_trusted(data, pos, ai, off).map_err(trusted_canonical_err)
}

#[inline]
pub fn read_len_trusted_canonical(
    data: &[u8],
    pos: &mut usize,
    ai: u8,
    off: usize,
) -> Result<usize, CborError> {
    read_len_trusted(data, pos, ai, off).map_err(trusted_canonical_err)
}

pub fn read_text_payload_trusted<'a>(
    data: &'a [u8],
    pos: &mut usize,
) -> Result<&'a [u8], CborError> {
    let off = *pos;
    let initial = read_u8_trusted_canonical(data, pos)?;
    if initial >> 5 != 3 {
        return Err(CborError::new(ErrorCode::MalformedCanonical, off));
    }
    let len = read_len_trusted_canonical(data, pos, initial & 0x1f, off)?;
    read_exact_trusted_canonical(data, pos, len)
}

pub fn read_text_trusted<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a str, CborError> {
    let off = *pos;
    let bytes = read_text_payload_trusted(data, pos)?;
    utf8::trusted(bytes).map_err(|()| CborError::new(ErrorCode::MalformedCanonical, off))
}

pub fn value_end_trusted(data: &[u8], start: usize) -> Result<usize, CborError> {
    let mut cursor = Cursor::with_pos(data, start);
    let mut items_seen = 0;
    let mut pending = 1usize;
    while pending != 0 {
        let off = cursor.position();
        let initial = cursor.read_u8()?;
        let frame = skip_primitive::<false>(
            &mut cursor,
            WalkPolicy::trusted(),
            &mut items_seen,
            0,
            off,
            initial >> 5,
            initial & 0x1f,
        )?;
        pending -= 1;
        let children = match frame {
            Some(Frame::Array { remaining }) => remaining,
            Some(Frame::Map {
                remaining_pairs, ..
            }) => remaining_pairs
                .checked_mul(2)
                .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?,
            None => 0,
        };
        pending = pending
            .checked_add(children)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
    }
    Ok(cursor.position())
}

#[inline]
pub fn parse_text_from_header<'a, const CHECKED: bool>(
    cursor: &mut Cursor<'a>,
    limits: Option<&DecodeLimits>,
    off: usize,
    ai: u8,
) -> Result<&'a str, CborError> {
    let len = read_len::<CHECKED>(cursor, ai, off)?;
    if let Some(limits) = limits {
        if len > limits.max_text_len {
            return Err(CborError::new(ErrorCode::TextLenLimitExceeded, off));
        }
    }
    let bytes = cursor.read_exact(len)?;
    let s = if CHECKED {
        utf8::validate_utf8(bytes).map_err(|()| CborError::new(ErrorCode::Utf8Invalid, off))?
    } else {
        utf8::trusted(bytes).map_err(|()| CborError::new(ErrorCode::Utf8Invalid, off))?
    };
    Ok(s)
}

#[inline]
pub fn parse_bignum<'a, const CHECKED: bool>(
    cursor: &mut Cursor<'a>,
    limits: Option<&DecodeLimits>,
    off: usize,
    ai: u8,
) -> Result<(bool, &'a [u8]), CborError> {
    let tag = read_uint_arg::<CHECKED>(cursor, ai, off)?;
    let negative = match tag {
        2 => false,
        3 => true,
        _ => return Err(CborError::new(ErrorCode::ForbiddenOrMalformedTag, off)),
    };

    let m_off = cursor.position();
    let first = cursor.read_u8()?;
    let m_major = first >> 5;
    let m_ai = first & 0x1f;
    if m_major != 2 {
        return Err(CborError::new(ErrorCode::ForbiddenOrMalformedTag, m_off));
    }

    let m_len = read_len::<CHECKED>(cursor, m_ai, m_off)?;
    if let Some(limits) = limits {
        if m_len > limits.max_bytes_len {
            return Err(CborError::new(ErrorCode::BytesLenLimitExceeded, m_off));
        }
    }
    let mag = cursor.read_exact(m_len)?;

    if CHECKED {
        validate_bignum_bytes(negative, mag).map_err(|code| CborError::new(code, m_off))?;
    }

    Ok((negative, mag))
}

#[inline]
pub fn check_map_key_order(
    data: &[u8],
    prev_key_range: &mut Option<(usize, usize)>,
    key_start: usize,
    key_end: usize,
) -> Result<(), CborError> {
    if let Some((ps, pe)) = *prev_key_range {
        let prev = &data[ps..pe];
        let curr = &data[key_start..key_end];
        if let Err(code) = check_encoded_key_order(prev, curr) {
            return Err(CborError::new(code, key_start));
        }
    }
    *prev_key_range = Some((key_start, key_end));
    Ok(())
}

#[derive(Clone, Copy)]
enum Frame {
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
    #[inline]
    const fn is_done(&self) -> bool {
        match self {
            Self::Array { remaining } => *remaining == 0,
            Self::Map {
                remaining_pairs,
                expecting_key,
                ..
            } => *remaining_pairs == 0 && *expecting_key,
        }
    }
}

trait StackOps {
    fn push(&mut self, frame: Frame, off: usize) -> Result<(), CborError>;
    fn pop(&mut self) -> Option<Frame>;
}

#[cfg(feature = "alloc")]
const INLINE_FRAMES: usize = 32;

#[cfg(feature = "alloc")]
struct FrameStack {
    inline: [Frame; INLINE_FRAMES],
    len: usize,
    heap: Option<Vec<Frame>>,
}

#[cfg(feature = "alloc")]
impl FrameStack {
    const fn new() -> Self {
        Self {
            inline: [Frame::Array { remaining: 0 }; INLINE_FRAMES],
            len: 0,
            heap: None,
        }
    }

    #[inline]
    fn clear(&mut self) {
        self.len = 0;
        if let Some(items) = &mut self.heap {
            items.clear();
        }
    }

    #[inline]
    fn push(&mut self, frame: Frame, off: usize) -> Result<(), CborError> {
        match &mut self.heap {
            Some(items) => {
                try_reserve(items, 1, off)?;
                items.push(frame);
            }
            None => {
                if self.len < INLINE_FRAMES {
                    self.inline[self.len] = frame;
                    self.len += 1;
                } else {
                    let mut items = Vec::new();
                    try_reserve(&mut items, self.len + 1, off)?;
                    items.extend_from_slice(&self.inline[..self.len]);
                    items.push(frame);
                    self.heap = Some(items);
                }
            }
        }
        Ok(())
    }

    #[inline]
    fn pop(&mut self) -> Option<Frame> {
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
}

#[cfg(feature = "alloc")]
impl StackOps for FrameStack {
    #[inline]
    fn push(&mut self, frame: Frame, off: usize) -> Result<(), CborError> {
        Self::push(self, frame, off)
    }

    #[inline]
    fn pop(&mut self) -> Option<Frame> {
        Self::pop(self)
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

    #[inline]
    fn clear(&mut self) {
        self.len = 0;
    }

    #[inline]
    fn push(&mut self, frame: Frame, off: usize) -> Result<(), CborError> {
        if self.len < N {
            self.inline[self.len] = Some(frame);
            self.len += 1;
            Ok(())
        } else {
            Err(CborError::new(ErrorCode::DepthLimitExceeded, off))
        }
    }

    #[inline]
    fn pop(&mut self) -> Option<Frame> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        self.inline[self.len].take()
    }
}

#[cfg(not(feature = "alloc"))]
impl<const N: usize> StackOps for FrameStack<N> {
    #[inline]
    fn push(&mut self, frame: Frame, off: usize) -> Result<(), CborError> {
        Self::push(self, frame, off)
    }

    #[inline]
    fn pop(&mut self) -> Option<Frame> {
        Self::pop(self)
    }
}

#[cfg(feature = "alloc")]
pub struct SkipScratch {
    stack: FrameStack,
}

#[cfg(not(feature = "alloc"))]
pub struct SkipScratch {
    stack: FrameStack<INLINE_STACK>,
}

impl SkipScratch {
    #[cfg(feature = "alloc")]
    pub(crate) const fn new() -> Self {
        Self {
            stack: FrameStack::new(),
        }
    }

    #[cfg(not(feature = "alloc"))]
    pub(crate) const fn new() -> Self {
        Self {
            stack: FrameStack::<INLINE_STACK>::new(),
        }
    }
}

#[cfg(not(feature = "alloc"))]
const INLINE_STACK: usize = DEFAULT_MAX_DEPTH + 2;

#[inline]
fn bump_items(
    limits: Option<&DecodeLimits>,
    items_seen: &mut usize,
    add: usize,
    off: usize,
) -> Result<(), CborError> {
    let Some(limits) = limits else {
        return Ok(());
    };
    *items_seen = items_seen
        .checked_add(add)
        .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
    if *items_seen > limits.max_total_items {
        return Err(CborError::new(ErrorCode::TotalItemsLimitExceeded, off));
    }
    Ok(())
}

#[inline]
const fn ensure_depth(
    limits: Option<&DecodeLimits>,
    next_depth: usize,
    off: usize,
) -> Result<(), CborError> {
    let Some(limits) = limits else {
        return Ok(());
    };
    if next_depth > limits.max_depth {
        return Err(CborError::new(ErrorCode::DepthLimitExceeded, off));
    }
    Ok(())
}

#[inline]
fn consume_value(frame: &mut Frame, off: usize) -> Result<(), CborError> {
    match frame {
        Frame::Array { remaining } => {
            *remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| CborError::new(ErrorCode::MalformedCanonical, off))?;
        }
        Frame::Map {
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

#[allow(clippy::too_many_lines)]
#[inline]
fn skip_primitive<const CHECKED: bool>(
    cursor: &mut Cursor<'_>,
    policy: WalkPolicy<'_>,
    items_seen: &mut usize,
    next_depth: usize,
    off: usize,
    major: u8,
    ai: u8,
) -> Result<Option<Frame>, CborError> {
    let limits = policy.limits;
    match major {
        0 => {
            let v = read_uint_arg::<CHECKED>(cursor, ai, off)?;
            if CHECKED && v > MAX_SAFE_INTEGER {
                return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
            }
            Ok(None)
        }
        1 => {
            let n = read_uint_arg::<CHECKED>(cursor, ai, off)?;
            if CHECKED && n >= MAX_SAFE_INTEGER {
                return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
            }
            Ok(None)
        }
        2 => {
            let len = read_len::<CHECKED>(cursor, ai, off)?;
            if let Some(limits) = limits {
                if len > limits.max_bytes_len {
                    return Err(CborError::new(ErrorCode::BytesLenLimitExceeded, off));
                }
            }
            let _ = cursor.read_exact(len)?;
            Ok(None)
        }
        3 => {
            let len = read_len::<CHECKED>(cursor, ai, off)?;
            if let Some(limits) = limits {
                if len > limits.max_text_len {
                    return Err(CborError::new(ErrorCode::TextLenLimitExceeded, off));
                }
            }
            let bytes = cursor.read_exact(len)?;
            if CHECKED {
                utf8::validate_utf8(bytes)
                    .map_err(|()| CborError::new(ErrorCode::Utf8Invalid, off))?;
            }
            Ok(None)
        }
        4 => {
            let len = read_len::<CHECKED>(cursor, ai, off)?;
            if let Some(limits) = limits {
                if len > limits.max_array_len {
                    return Err(CborError::new(ErrorCode::ArrayLenLimitExceeded, off));
                }
            }
            bump_items(limits, items_seen, len, off)?;
            ensure_depth(limits, next_depth, off)?;
            if len == 0 {
                Ok(None)
            } else {
                Ok(Some(Frame::Array { remaining: len }))
            }
        }
        5 => {
            let len = read_len::<CHECKED>(cursor, ai, off)?;
            if let Some(limits) = limits {
                if len > limits.max_map_len {
                    return Err(CborError::new(ErrorCode::MapLenLimitExceeded, off));
                }
            }
            let items = len
                .checked_mul(2)
                .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
            bump_items(limits, items_seen, items, off)?;
            ensure_depth(limits, next_depth, off)?;
            if len == 0 {
                Ok(None)
            } else {
                Ok(Some(Frame::Map {
                    remaining_pairs: len,
                    expecting_key: true,
                    prev_key_range: None,
                }))
            }
        }
        6 => {
            let _ = parse_bignum::<CHECKED>(cursor, limits, off, ai)?;
            Ok(None)
        }
        7 => {
            match ai {
                20..=22 => {
                    if CHECKED && policy.options.forbid_simple {
                        return Err(CborError::new(ErrorCode::SimpleForbidden, off));
                    }
                }
                27 => {
                    if CHECKED && policy.options.forbid_float {
                        return Err(CborError::new(ErrorCode::FloatForbidden, off));
                    }
                    let bits = cursor.read_be_u64()?;
                    if CHECKED {
                        validate_f64_bits(bits).map_err(|code| CborError::new(code, off))?;
                    }
                }
                24 => {
                    let simple = cursor.read_u8()?;
                    if simple < 24 {
                        return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                    }
                    return Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off));
                }
                28..=30 => return Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
                _ => return Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off)),
            }
            Ok(None)
        }
        _ => Err(CborError::new(ErrorCode::MalformedCanonical, off)),
    }
}

fn skip_one_value_inner<const CHECKED: bool, S: StackOps>(
    cursor: &mut Cursor<'_>,
    policy: WalkPolicy<'_>,
    items_seen: &mut usize,
    base_depth: usize,
    stack: &mut S,
) -> Result<(), CborError> {
    let limits = policy.limits;
    // The innermost open container lives in `cur`; the spill stack is touched
    // only when opening or closing a nested container, keeping the per-item
    // loop free of stack peeks.
    let mut cur: Option<Frame> = None;
    // Number of open containers, including `cur`.
    let mut open_depth: usize = 0;

    loop {
        if let Some(frame) = &mut cur {
            if frame.is_done() {
                open_depth -= 1;
                match stack.pop() {
                    Some(parent) => {
                        cur = Some(parent);
                        continue;
                    }
                    None => return Ok(()),
                }
            }

            if let Frame::Map {
                expecting_key,
                prev_key_range,
                ..
            } = frame
            {
                if *expecting_key {
                    let key_start = cursor.position();
                    let ib = cursor.read_u8()?;
                    let major = ib >> 5;
                    let ai = ib & 0x1f;
                    if major != 3 {
                        return Err(CborError::new(ErrorCode::MapKeyMustBeText, key_start));
                    }
                    if CHECKED {
                        let _ = parse_text_from_header::<CHECKED>(cursor, limits, key_start, ai)?;
                    } else {
                        let len = read_len::<CHECKED>(cursor, ai, key_start)?;
                        if let Some(limits) = limits {
                            if len > limits.max_text_len {
                                return Err(CborError::new(
                                    ErrorCode::TextLenLimitExceeded,
                                    key_start,
                                ));
                            }
                        }
                        let _ = cursor.read_exact(len)?;
                    }
                    let key_end = cursor.position();

                    if CHECKED {
                        check_map_key_order(cursor.data(), prev_key_range, key_start, key_end)?;
                    }

                    *expecting_key = false;
                }
            }
        }

        let off = cursor.position();
        let ib = cursor.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        let next_depth = base_depth + open_depth + 1;
        let new_frame =
            skip_primitive::<CHECKED>(cursor, policy, items_seen, next_depth, off, major, ai)?;

        if let Some(frame) = &mut cur {
            consume_value(frame, off)?;
        }

        match new_frame {
            Some(frame) => {
                if let Some(parent) = cur.take() {
                    stack.push(parent, off)?;
                }
                cur = Some(frame);
                open_depth += 1;
            }
            None => {
                if cur.is_none() {
                    return Ok(());
                }
            }
        }
    }
}

pub fn skip_one_value<const CHECKED: bool>(
    cursor: &mut Cursor<'_>,
    policy: WalkPolicy<'_>,
    items_seen: &mut usize,
    base_depth: usize,
) -> Result<(), CborError> {
    #[cfg(feature = "alloc")]
    let mut stack = FrameStack::new();
    #[cfg(not(feature = "alloc"))]
    let mut stack = FrameStack::<INLINE_STACK>::new();
    skip_one_value_inner::<CHECKED, _>(cursor, policy, items_seen, base_depth, &mut stack)
}

pub fn skip_one_value_with_scratch<const CHECKED: bool>(
    cursor: &mut Cursor<'_>,
    policy: WalkPolicy<'_>,
    items_seen: &mut usize,
    base_depth: usize,
    scratch: &mut SkipScratch,
) -> Result<(), CborError> {
    scratch.stack.clear();
    skip_one_value_inner::<CHECKED, _>(cursor, policy, items_seen, base_depth, &mut scratch.stack)
}
