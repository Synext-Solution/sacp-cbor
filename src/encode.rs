//! Canonical encoder state machine for SACP-CBOR/1.

use crate::alloc_util::try_reserve;
#[cfg(feature = "edit")]
use crate::canonical::EncodedTextKey;
use crate::canonical::{CanonicalCbor, CanonicalCborRef};
use crate::codec::CborEncode;
use crate::limits::EncodeLimits;
use crate::profile::{
    check_encoded_key_order, minimal_uint_ai, uint_argument_payload_len, validate_bignum_bytes,
    validate_int_safe_i64,
};
use crate::query::CborValueRef;
use crate::scalar::F64Bits;
use crate::wire::{self, Cursor};
use crate::{CborError, ErrorCode};
use alloc::vec::Vec;

struct VecSink {
    buf: Vec<u8>,
    max_len: usize,
}

impl VecSink {
    const fn new() -> Self {
        Self {
            buf: Vec::new(),
            max_len: usize::MAX,
        }
    }

    fn try_with_capacity(capacity: usize) -> Result<Self, CborError> {
        Self::try_with_capacity_and_limit(capacity, usize::MAX)
    }

    const fn with_limit(max_len: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_len,
        }
    }

    fn try_with_capacity_and_limit(capacity: usize, max_len: usize) -> Result<Self, CborError> {
        if capacity > max_len {
            return Err(CborError::new(ErrorCode::MessageLenLimitExceeded, 0));
        }
        let mut buf = Vec::new();
        try_reserve(&mut buf, capacity, 0)?;
        Ok(Self { buf, max_len })
    }

    fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    #[inline]
    fn reserve(&mut self, additional: usize) -> Result<(), CborError> {
        if self.max_len != usize::MAX {
            self.ensure_additional(additional)?;
        }
        let available = self.buf.capacity().saturating_sub(self.buf.len());
        if additional <= available {
            return Ok(());
        }
        let offset = self.buf.len();
        try_reserve(&mut self.buf, additional, offset)
    }

    #[inline]
    fn ensure_additional(&self, additional: usize) -> Result<(), CborError> {
        let end = self
            .buf
            .len()
            .checked_add(additional)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, self.buf.len()))?;
        if end > self.max_len {
            return Err(CborError::new(
                ErrorCode::MessageLenLimitExceeded,
                self.buf.len(),
            ));
        }
        Ok(())
    }
}

impl VecSink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), CborError> {
        self.reserve(bytes.len())?;
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    fn write_u8(&mut self, byte: u8) -> Result<(), CborError> {
        if self.buf.len() == self.buf.capacity() || self.buf.len() == self.max_len {
            self.reserve(1)?;
        }
        self.buf.push(byte);
        Ok(())
    }

    fn position(&self) -> usize {
        self.buf.len()
    }
}

fn err_at(sink: &VecSink, code: ErrorCode) -> CborError {
    CborError::new(code, sink.position())
}

fn encode_int(sink: &mut VecSink, v: i64) -> Result<(), CborError> {
    if v >= 0 {
        let u = u64::try_from(v).map_err(|_| err_at(sink, ErrorCode::LengthOverflow))?;
        encode_major_uint(sink, 0, u)
    } else {
        let n_i128 = -1_i128 - i128::from(v);
        let n_u64 = u64::try_from(n_i128).map_err(|_| err_at(sink, ErrorCode::LengthOverflow))?;
        encode_major_uint(sink, 1, n_u64)
    }
}

fn encode_bytes(sink: &mut VecSink, bytes: &[u8]) -> Result<(), CborError> {
    encode_major_len(sink, 2, bytes.len())?;
    sink.write(bytes)
}

fn encode_text(sink: &mut VecSink, s: &str) -> Result<(), CborError> {
    // `str` guarantees valid UTF-8.
    let b = s.as_bytes();
    encode_major_len(sink, 3, b.len())?;
    sink.write(b)
}

fn encode_float64(sink: &mut VecSink, bits: F64Bits) -> Result<(), CborError> {
    let raw = bits.bits();
    let mut buf = [0u8; 9];
    buf[0] = 0xfb;
    buf[1..9].copy_from_slice(&raw.to_be_bytes());
    sink.write(&buf)
}

fn encode_major_len(sink: &mut VecSink, major: u8, len: usize) -> Result<(), CborError> {
    let len_u64 = u64::try_from(len).map_err(|_| err_at(sink, ErrorCode::LengthOverflow))?;
    encode_major_uint(sink, major, len_u64)
}

fn encode_major_uint(sink: &mut VecSink, major: u8, value: u64) -> Result<(), CborError> {
    debug_assert!(major <= 7);
    let ai = minimal_uint_ai(value);
    debug_assert!(uint_argument_payload_len(ai).is_some());
    sink.write_u8((major << 5) | ai)?;
    match ai {
        0..=23 => Ok(()),
        24 => {
            let v = u8::try_from(value).map_err(|_| err_at(sink, ErrorCode::LengthOverflow))?;
            sink.write_u8(v)
        }
        25 => {
            let v = u16::try_from(value).map_err(|_| err_at(sink, ErrorCode::LengthOverflow))?;
            sink.write(&v.to_be_bytes())
        }
        26 => {
            let v = u32::try_from(value).map_err(|_| err_at(sink, ErrorCode::LengthOverflow))?;
            sink.write(&v.to_be_bytes())
        }
        27 => sink.write(&value.to_be_bytes()),
        _ => unreachable!("minimal_uint_ai never returns reserved additional info"),
    }
}

#[derive(Clone, Copy)]
enum Frame {
    Array {
        remaining: usize,
    },
    Map {
        remaining_pairs: usize,
        pending_value: bool,
        prev_key_range: Option<(usize, usize)>,
        pending_key_range: Option<(usize, usize)>,
    },
}

#[derive(Clone, Copy)]
pub(crate) struct EncoderCheckpoint {
    buf_len: usize,
    root_remaining: u8,
    stack_len: usize,
    parent_frame: Option<Frame>,
    items_seen: usize,
}

#[derive(Clone, Copy)]
enum ValueState {
    Root {
        remaining: u8,
    },
    Array {
        frame_index: usize,
        remaining: usize,
    },
    Map {
        frame_index: usize,
        frame: Frame,
    },
}

#[derive(Clone, Copy)]
struct ValueCheckpoint {
    buf_len: usize,
    items_seen: usize,
    state: ValueState,
}

/// Streaming encoder that writes canonical CBOR directly into a `Vec<u8>`.
///
/// This supports splicing validated canonical bytes.
pub struct Encoder {
    sink: VecSink,
    root_remaining: u8,
    stack: Vec<Frame>,
    limits: EncodeLimits,
    items_seen: usize,
}

impl Encoder {
    /// Create a new canonical encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sink: VecSink::new(),
            root_remaining: 1,
            stack: Vec::new(),
            limits: EncodeLimits::unbounded(),
            items_seen: 0,
        }
    }

    /// Create a canonical encoder with explicit resource limits.
    ///
    /// # Errors
    ///
    /// Returns `InvalidLimits` when the limit set cannot be enforced.
    pub fn with_limits(limits: EncodeLimits) -> Result<Self, CborError> {
        limits.validate()?;
        Ok(Self {
            sink: VecSink::with_limit(limits.max_output_bytes),
            root_remaining: 1,
            stack: Vec::new(),
            limits,
            items_seen: 0,
        })
    }

    /// Create a canonical encoder with fallibly pre-allocated byte capacity.
    ///
    /// # Errors
    ///
    /// Returns `AllocationFailed` if the requested capacity cannot be reserved.
    pub fn try_with_capacity(capacity: usize) -> Result<Self, CborError> {
        Ok(Self {
            sink: VecSink::try_with_capacity(capacity)?,
            root_remaining: 1,
            stack: Vec::new(),
            limits: EncodeLimits::unbounded(),
            items_seen: 0,
        })
    }

    /// Create a limited canonical encoder with fallibly pre-allocated byte capacity.
    ///
    /// # Errors
    ///
    /// Returns `InvalidLimits`, `MessageLenLimitExceeded`, or `AllocationFailed`.
    pub fn try_with_capacity_and_limits(
        capacity: usize,
        limits: EncodeLimits,
    ) -> Result<Self, CborError> {
        limits.validate()?;
        Ok(Self {
            sink: VecSink::try_with_capacity_and_limit(capacity, limits.max_output_bytes)?,
            root_remaining: 1,
            stack: Vec::new(),
            limits,
            items_seen: 0,
        })
    }

    /// Return the number of bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sink.buf.len()
    }

    /// Returns `true` if no bytes have been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sink.buf.is_empty()
    }

    pub(crate) fn into_unchecked_vec(self) -> Vec<u8> {
        self.sink.into_vec()
    }

    /// Consume and return canonical bytes as a `CanonicalCbor`.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer does not contain exactly one canonical CBOR item.
    pub fn finish(self) -> Result<CanonicalCbor, CborError> {
        if self.root_remaining != 0 || !self.stack.is_empty() {
            return Err(CborError::new(ErrorCode::UnexpectedEof, 0));
        }
        Ok(CanonicalCbor::new_unchecked(self.into_unchecked_vec()))
    }

    /// Clear the encoder while retaining allocated capacity.
    pub fn clear(&mut self) {
        self.sink.buf.clear();
        self.root_remaining = 1;
        self.stack.clear();
        self.items_seen = 0;
    }

    /// Borrow the bytes emitted so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.sink.buf
    }

    #[inline]
    pub(crate) fn checkpoint(&self) -> EncoderCheckpoint {
        EncoderCheckpoint {
            buf_len: self.sink.buf.len(),
            root_remaining: self.root_remaining,
            stack_len: self.stack.len(),
            parent_frame: self.stack.last().copied(),
            items_seen: self.items_seen,
        }
    }

    #[inline]
    pub(crate) fn restore(&mut self, checkpoint: EncoderCheckpoint) {
        self.sink.buf.truncate(checkpoint.buf_len);
        self.root_remaining = checkpoint.root_remaining;
        self.stack.truncate(checkpoint.stack_len);
        if let Some(frame) = checkpoint.parent_frame {
            if let Some(parent) = self.stack.last_mut() {
                *parent = frame;
            }
        }
        self.items_seen = checkpoint.items_seen;
    }

    #[inline]
    fn begin_value(&mut self) -> Result<ValueState, CborError> {
        let frame_index = self.stack.len().saturating_sub(1);
        match self.stack.last_mut() {
            Some(Frame::Array { remaining }) => {
                let before = *remaining;
                if *remaining == 0 {
                    return Err(CborError::new(
                        ErrorCode::ArrayLenMismatch,
                        self.sink.position(),
                    ));
                }
                *remaining -= 1;
                Ok(ValueState::Array {
                    frame_index,
                    remaining: before,
                })
            }
            Some(frame @ Frame::Map { .. }) => {
                let before = *frame;
                let Frame::Map {
                    remaining_pairs,
                    pending_value,
                    prev_key_range,
                    pending_key_range,
                } = frame
                else {
                    unreachable!();
                };
                if !*pending_value {
                    return Err(CborError::new(
                        ErrorCode::MapLenMismatch,
                        self.sink.position(),
                    ));
                }
                if *remaining_pairs == 0 {
                    return Err(CborError::new(
                        ErrorCode::MapLenMismatch,
                        self.sink.position(),
                    ));
                }
                *pending_value = false;
                *remaining_pairs -= 1;
                *prev_key_range = pending_key_range.take();
                Ok(ValueState::Map {
                    frame_index,
                    frame: before,
                })
            }
            None => {
                let before = self.root_remaining;
                if self.root_remaining == 0 {
                    return Err(CborError::new(
                        ErrorCode::TrailingBytes,
                        self.sink.position(),
                    ));
                }
                self.root_remaining = 0;
                Ok(ValueState::Root { remaining: before })
            }
        }
    }

    #[inline]
    fn restore_value_state(&mut self, state: ValueState) {
        match state {
            ValueState::Root { remaining } => self.root_remaining = remaining,
            ValueState::Array {
                frame_index,
                remaining,
            } => {
                if let Some(Frame::Array { remaining: dst }) = self.stack.get_mut(frame_index) {
                    *dst = remaining;
                }
            }
            ValueState::Map { frame_index, frame } => {
                if let Some(dst) = self.stack.get_mut(frame_index) {
                    *dst = frame;
                }
            }
        }
    }

    #[inline]
    fn restore_value(&mut self, checkpoint: ValueCheckpoint) {
        self.sink.buf.truncate(checkpoint.buf_len);
        self.items_seen = checkpoint.items_seen;
        self.restore_value_state(checkpoint.state);
    }

    #[inline]
    fn emit_value<F>(&mut self, write: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut Self) -> Result<(), CborError>,
    {
        let state = self.begin_value()?;
        let checkpoint = ValueCheckpoint {
            buf_len: self.sink.buf.len(),
            items_seen: self.items_seen,
            state,
        };
        if let Err(err) = write(self) {
            self.restore_value(checkpoint);
            return Err(err);
        }
        Ok(())
    }

    #[inline]
    fn emit_single_byte_value(&mut self, byte: u8) -> Result<(), CborError> {
        let state = self.begin_value()?;
        if let Err(err) = self.sink.write_u8(byte) {
            self.restore_value_state(state);
            return Err(err);
        }
        Ok(())
    }

    #[inline]
    fn push_frame(&mut self, frame: Frame) -> Result<(), CborError> {
        if self.stack.len() >= self.limits.max_depth {
            return Err(CborError::new(
                ErrorCode::DepthLimitExceeded,
                self.sink.position(),
            ));
        }
        try_reserve(&mut self.stack, 1, self.sink.position())?;
        self.stack.push(frame);
        Ok(())
    }

    #[inline]
    fn account_items(&mut self, add: usize) -> Result<(), CborError> {
        self.items_seen = self
            .items_seen
            .checked_add(add)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, self.sink.position()))?;
        if self.items_seen > self.limits.max_total_items {
            return Err(CborError::new(
                ErrorCode::TotalItemsLimitExceeded,
                self.sink.position(),
            ));
        }
        Ok(())
    }

    #[inline]
    fn close_container(&mut self) -> Result<(), CborError> {
        let code = match self.stack.last() {
            Some(Frame::Array { remaining: 0 }) => None,
            Some(Frame::Array { .. }) => Some(ErrorCode::ArrayLenMismatch),
            Some(Frame::Map {
                remaining_pairs,
                pending_value,
                ..
            }) if *remaining_pairs == 0 && !*pending_value => None,
            Some(Frame::Map { .. }) => Some(ErrorCode::MapLenMismatch),
            None => Some(ErrorCode::MalformedCanonical),
        };

        if let Some(code) = code {
            return Err(CborError::new(code, self.sink.position()));
        }

        let _ = self.stack.pop();
        Ok(())
    }

    fn check_array_len(&self, len: usize) -> Result<(), CborError> {
        if len > self.limits.max_array_len {
            return Err(CborError::new(
                ErrorCode::ArrayLenLimitExceeded,
                self.sink.position(),
            ));
        }
        Ok(())
    }

    fn check_map_len(&self, len: usize) -> Result<(), CborError> {
        if len > self.limits.max_map_len {
            return Err(CborError::new(
                ErrorCode::MapLenLimitExceeded,
                self.sink.position(),
            ));
        }
        Ok(())
    }

    fn check_bytes_len(&self, len: usize) -> Result<(), CborError> {
        if len > self.limits.max_bytes_len {
            return Err(CborError::new(
                ErrorCode::BytesLenLimitExceeded,
                self.sink.position(),
            ));
        }
        Ok(())
    }

    fn check_text_len(&self, len: usize) -> Result<(), CborError> {
        if len > self.limits.max_text_len {
            return Err(CborError::new(
                ErrorCode::TextLenLimitExceeded,
                self.sink.position(),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "edit")]
    fn check_encoded_text_key_len(&self, bytes: &[u8]) -> Result<(), CborError> {
        let mut cursor = Cursor::with_pos(bytes, 0);
        let off = cursor.position();
        let initial = cursor.read_u8()?;
        if initial >> 5 != 3 {
            return Err(CborError::new(ErrorCode::MapKeyMustBeText, off));
        }
        let len = wire::read_len::<true>(&mut cursor, initial & 0x1f, off)?;
        if cursor
            .position()
            .checked_add(len)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?
            != bytes.len()
        {
            return Err(CborError::new(ErrorCode::MalformedCanonical, off));
        }
        self.check_text_len(len)
    }

    fn account_canonical_value(&mut self, bytes: &[u8]) -> Result<(), CborError> {
        let limits = self.limits.to_decode_limits(bytes.len());
        let mut cursor = Cursor::with_pos(bytes, 0);
        let mut items_seen = self.items_seen;
        wire::skip_one_value::<false>(
            &mut cursor,
            Some(&limits),
            &mut items_seen,
            self.stack.len(),
        )?;
        if cursor.position() != bytes.len() {
            return Err(CborError::new(ErrorCode::TrailingBytes, cursor.position()));
        }
        self.items_seen = items_seen;
        Ok(())
    }

    #[inline]
    fn array_remaining_at(&self, frame_index: usize) -> Result<usize, CborError> {
        match self.stack.get(frame_index) {
            Some(Frame::Array { remaining }) => Ok(*remaining),
            _ => Err(CborError::new(
                ErrorCode::MalformedCanonical,
                self.sink.position(),
            )),
        }
    }

    #[inline]
    fn set_array_remaining_at(
        &mut self,
        frame_index: usize,
        value: usize,
    ) -> Result<(), CborError> {
        match self.stack.get_mut(frame_index) {
            Some(Frame::Array { remaining }) => {
                *remaining = value;
                Ok(())
            }
            _ => Err(CborError::new(
                ErrorCode::MalformedCanonical,
                self.sink.position(),
            )),
        }
    }

    #[inline]
    fn map_remaining_at(&self, frame_index: usize) -> Result<(usize, bool), CborError> {
        match self.stack.get(frame_index) {
            Some(Frame::Map {
                remaining_pairs,
                pending_value,
                ..
            }) => Ok((*remaining_pairs, *pending_value)),
            _ => Err(CborError::new(
                ErrorCode::MalformedCanonical,
                self.sink.position(),
            )),
        }
    }

    #[inline]
    pub(crate) fn begin_map_key(&self) -> Result<usize, CborError> {
        match self.stack.last() {
            Some(Frame::Map {
                remaining_pairs,
                pending_value,
                ..
            }) if *remaining_pairs > 0 && !*pending_value => Ok(self.sink.position()),
            Some(Frame::Map { .. }) => Err(CborError::new(
                ErrorCode::MapLenMismatch,
                self.sink.position(),
            )),
            _ => Err(CborError::new(
                ErrorCode::MapKeyMustBeText,
                self.sink.position(),
            )),
        }
    }

    #[inline]
    pub(crate) fn finish_map_key(
        &mut self,
        key_start: usize,
        key_end: usize,
    ) -> Result<(), CborError> {
        match self.stack.last_mut() {
            Some(Frame::Map {
                pending_value,
                prev_key_range,
                pending_key_range,
                ..
            }) if !*pending_value => {
                if let Some((ps, pe)) = *prev_key_range {
                    let prev = &self.sink.buf[ps..pe];
                    let curr = &self.sink.buf[key_start..key_end];
                    if let Err(code) = check_encoded_key_order(prev, curr) {
                        return Err(CborError::new(code, key_start));
                    }
                }
                *pending_key_range = Some((key_start, key_end));
                *pending_value = true;
                Ok(())
            }
            Some(Frame::Map { .. }) => Err(CborError::new(
                ErrorCode::MapLenMismatch,
                self.sink.position(),
            )),
            _ => Err(CborError::new(
                ErrorCode::MapKeyMustBeText,
                self.sink.position(),
            )),
        }
    }

    #[cfg(feature = "serde")]
    #[inline]
    pub(crate) fn finish_container(&mut self) -> Result<(), CborError> {
        self.close_container()
    }

    #[inline]
    fn write_int(&mut self, v: i64) -> Result<(), CborError> {
        validate_int_safe_i64(v).map_err(|code| CborError::new(code, self.sink.position()))?;
        encode_int(&mut self.sink, v)
    }

    #[inline]
    fn write_int_u128(&mut self, v: u128) -> Result<(), CborError> {
        let safe_max = u128::from(crate::profile::MAX_SAFE_INTEGER);
        if v <= safe_max {
            let i = i64::try_from(v)
                .map_err(|_| CborError::new(ErrorCode::LengthOverflow, self.sink.position()))?;
            return self.write_int(i);
        }

        let magnitude = crate::int::magnitude_from_u128(v)
            .map_err(|code| CborError::new(code, self.sink.position()))?;
        self.write_bignum(false, &magnitude)
    }

    #[inline]
    fn write_int_i128(&mut self, v: i128) -> Result<(), CborError> {
        let min = i128::from(crate::profile::MIN_SAFE_INTEGER);
        let max = i128::from(crate::profile::MAX_SAFE_INTEGER_I64);

        if v >= min && v <= max {
            let i = i64::try_from(v)
                .map_err(|_| CborError::new(ErrorCode::LengthOverflow, self.sink.position()))?;
            return self.write_int(i);
        }

        let negative = v < 0;
        let n_u128 = if negative {
            let n_i128 = -1_i128 - v;
            u128::try_from(n_i128)
                .map_err(|_| CborError::new(ErrorCode::LengthOverflow, self.sink.position()))?
        } else {
            u128::try_from(v)
                .map_err(|_| CborError::new(ErrorCode::LengthOverflow, self.sink.position()))?
        };

        let magnitude = crate::int::magnitude_from_u128(n_u128)
            .map_err(|code| CborError::new(code, self.sink.position()))?;
        self.write_bignum(negative, &magnitude)
    }

    #[inline]
    fn write_bignum(&mut self, negative: bool, magnitude: &[u8]) -> Result<(), CborError> {
        self.check_bytes_len(magnitude.len())?;
        validate_bignum_bytes(negative, magnitude)
            .map_err(|code| CborError::new(code, self.sink.position()))?;
        let tag = if negative { 3u64 } else { 2u64 };
        encode_major_uint(&mut self.sink, 6, tag)?;
        encode_bytes(&mut self.sink, magnitude)
    }

    #[inline]
    fn write_bytes(&mut self, b: &[u8]) -> Result<(), CborError> {
        self.check_bytes_len(b.len())?;
        encode_bytes(&mut self.sink, b)
    }

    #[inline]
    #[cfg(feature = "serde")]
    pub(crate) fn write_text_key(&mut self, s: &str) -> Result<(), CborError> {
        self.check_text_len(s.len())?;
        encode_text(&mut self.sink, s)
    }

    #[inline]
    fn write_text(&mut self, s: &str) -> Result<(), CborError> {
        self.check_text_len(s.len())?;
        encode_text(&mut self.sink, s)
    }

    #[inline]
    fn write_float(&mut self, bits: F64Bits) -> Result<(), CborError> {
        encode_float64(&mut self.sink, bits)
    }

    #[inline]
    fn write_raw_cbor(&mut self, v: CanonicalCborRef<'_>) -> Result<(), CborError> {
        self.account_canonical_value(v.as_bytes())?;
        self.sink.write(v.as_bytes())
    }

    #[inline]
    fn write_raw_value_ref(&mut self, v: CborValueRef<'_>) -> Result<(), CborError> {
        self.account_canonical_value(v.as_bytes())?;
        self.sink.write(v.as_bytes())
    }

    #[cfg(feature = "serde")]
    #[inline]
    fn write_trusted_canonical_bytes(&mut self, bytes: &[u8]) -> Result<(), CborError> {
        self.account_canonical_value(bytes)?;
        self.sink.write(bytes)
    }

    #[cfg(feature = "serde")]
    #[inline]
    pub(crate) fn raw_trusted_canonical_bytes(&mut self, bytes: &[u8]) -> Result<(), CborError> {
        self.emit_value(|enc| enc.write_trusted_canonical_bytes(bytes))
    }

    #[cfg(feature = "serde")]
    pub(crate) fn buf_len(&self) -> usize {
        self.sink.buf.len()
    }

    /// Encode CBOR null.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying buffer fails.
    pub fn null(&mut self) -> Result<(), CborError> {
        self.emit_single_byte_value(0xf6)
    }

    /// Encode a CBOR boolean.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying buffer fails.
    pub fn bool(&mut self, v: bool) -> Result<(), CborError> {
        self.emit_single_byte_value(if v { 0xf5 } else { 0xf4 })
    }

    /// Encode a safe-range integer.
    ///
    /// # Errors
    ///
    /// Returns an error if the integer is outside the safe range or if encoding fails.
    pub fn int(&mut self, v: i64) -> Result<(), CborError> {
        self.emit_value(|enc| enc.write_int(v))
    }

    /// Encode an unsigned integer, using a bignum when outside the safe range.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails or allocation for the bignum magnitude fails.
    pub fn int_u128(&mut self, v: u128) -> Result<(), CborError> {
        self.emit_value(|enc| enc.write_int_u128(v))
    }

    /// Encode a signed integer, using a bignum when outside the safe range.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails or allocation for the bignum magnitude fails.
    pub fn int_i128(&mut self, v: i128) -> Result<(), CborError> {
        self.emit_value(|enc| enc.write_int_i128(v))
    }

    /// Encode a CBOR bignum (tag 2/3 + byte string magnitude).
    ///
    /// # Errors
    ///
    /// Returns an error if the magnitude is not canonical or if encoding fails.
    pub fn bignum(&mut self, negative: bool, magnitude: &[u8]) -> Result<(), CborError> {
        self.emit_value(|enc| enc.write_bignum(negative, magnitude))
    }

    /// Encode a byte string.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn bytes(&mut self, b: &[u8]) -> Result<(), CborError> {
        self.emit_value(|enc| enc.write_bytes(b))
    }

    /// Encode a text string.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn text(&mut self, s: &str) -> Result<(), CborError> {
        self.emit_value(|enc| enc.write_text(s))
    }

    /// Encode a float64 bit pattern.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn float(&mut self, bits: F64Bits) -> Result<(), CborError> {
        self.emit_value(|enc| enc.write_float(bits))
    }

    /// Splice already validated canonical CBOR bytes as the next value.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying buffer fails.
    pub fn raw_cbor(&mut self, v: CanonicalCborRef<'_>) -> Result<(), CborError> {
        self.emit_value(|enc| enc.write_raw_cbor(v))
    }

    /// Splice a canonical sub-value reference.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying buffer fails.
    pub fn raw_value_ref(&mut self, v: CborValueRef<'_>) -> Result<(), CborError> {
        self.emit_value(|enc| enc.write_raw_value_ref(v))
    }

    /// Encode a definite-length array and fill it via the provided builder.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails or if the builder emits a different number of items.
    pub fn array<F>(&mut self, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut ArrayEncoder<'_>) -> Result<(), CborError>,
    {
        let checkpoint = self.checkpoint();
        self.begin_value()?;
        if let Err(err) = encode_major_len(&mut self.sink, 4, len)
            .and_then(|()| self.reserve_min_array_items(len))
            .and_then(|()| {
                self.push_frame(Frame::Array { remaining: len })?;
                Ok(())
            })
        {
            self.restore(checkpoint);
            return Err(err);
        }
        let frame_index = self.stack.len() - 1;
        let (res, remaining) = {
            let mut a = ArrayEncoder {
                enc: self,
                frame_index,
                remaining: len,
            };
            let res = f(&mut a);
            let remaining = a.remaining;
            (res, remaining)
        };
        if let Err(err) = res
            .and_then(|()| self.set_array_remaining_at(frame_index, remaining))
            .and_then(|()| self.close_container())
        {
            self.restore(checkpoint);
            return Err(err);
        }
        Ok(())
    }

    #[cfg(feature = "serde")]
    pub(crate) fn array_header(&mut self, len: usize) -> Result<(), CborError> {
        let checkpoint = self.checkpoint();
        if let Err(err) = self
            .begin_value()
            .and_then(|_| encode_major_len(&mut self.sink, 4, len))
            .and_then(|()| self.reserve_min_array_items(len))
            .and_then(|()| self.push_frame(Frame::Array { remaining: len }))
        {
            self.restore(checkpoint);
            return Err(err);
        }
        Ok(())
    }

    /// Encode a definite-length map and fill it via the provided builder.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails or if the builder emits a different number of entries.
    pub fn map<F>(&mut self, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut MapEncoder<'_>) -> Result<(), CborError>,
    {
        let checkpoint = self.checkpoint();
        self.begin_value()?;
        if let Err(err) = encode_major_len(&mut self.sink, 5, len)
            .and_then(|()| self.reserve_min_map_items(len))
            .and_then(|()| {
                self.push_frame(Frame::Map {
                    remaining_pairs: len,
                    pending_value: false,
                    prev_key_range: None,
                    pending_key_range: None,
                })?;
                Ok(())
            })
        {
            self.restore(checkpoint);
            return Err(err);
        }
        let frame_index = self.stack.len() - 1;
        let res = {
            let mut m = MapEncoder {
                enc: self,
                frame_index,
            };
            f(&mut m)
        };
        if let Err(err) = res.and_then(|()| self.close_container()) {
            self.restore(checkpoint);
            return Err(err);
        }
        Ok(())
    }

    #[cfg(feature = "serde")]
    pub(crate) fn map_header(&mut self, len: usize) -> Result<(), CborError> {
        let checkpoint = self.checkpoint();
        if let Err(err) = self
            .begin_value()
            .and_then(|_| encode_major_len(&mut self.sink, 5, len))
            .and_then(|()| self.reserve_min_map_items(len))
            .and_then(|()| {
                self.push_frame(Frame::Map {
                    remaining_pairs: len,
                    pending_value: false,
                    prev_key_range: None,
                    pending_key_range: None,
                })
            })
        {
            self.restore(checkpoint);
            return Err(err);
        }
        Ok(())
    }

    fn reserve_min_array_items(&mut self, len: usize) -> Result<(), CborError> {
        self.check_array_len(len)?;
        self.account_items(len)?;
        if len == 0 {
            return Ok(());
        }
        self.sink.reserve(len)
    }

    fn reserve_min_map_items(&mut self, len: usize) -> Result<(), CborError> {
        self.check_map_len(len)?;
        let items = len
            .checked_mul(2)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, self.sink.position()))?;
        self.account_items(items)?;
        if len == 0 {
            return Ok(());
        }
        self.sink.reserve(items)
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for writing array elements into a canonical CBOR stream.
pub struct ArrayEncoder<'a> {
    enc: &'a mut Encoder,
    frame_index: usize,
    remaining: usize,
}

impl ArrayEncoder<'_> {
    #[cfg(feature = "collections")]
    pub(crate) fn encoded_len(&self) -> usize {
        self.enc.len()
    }

    #[inline]
    fn sync_to_stack(&mut self) -> Result<(), CborError> {
        self.enc
            .set_array_remaining_at(self.frame_index, self.remaining)
    }

    #[inline]
    fn sync_from_stack(&mut self) -> Result<(), CborError> {
        self.remaining = self.enc.array_remaining_at(self.frame_index)?;
        Ok(())
    }

    #[inline]
    fn consume_one(&mut self) -> Result<(), CborError> {
        if self.remaining == 0 {
            return Err(CborError::new(
                ErrorCode::ArrayLenMismatch,
                self.enc.sink.position(),
            ));
        }
        self.remaining -= 1;
        Ok(())
    }

    #[inline]
    fn restore_one(&mut self) {
        self.remaining = self.remaining.saturating_add(1);
    }

    #[inline]
    fn write_single_byte_item(&mut self, byte: u8) -> Result<(), CborError> {
        self.consume_one()?;
        if let Err(err) = self.enc.sink.write_u8(byte) {
            self.restore_one();
            return Err(err);
        }
        Ok(())
    }

    #[inline]
    fn write_item<F>(&mut self, write: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut Encoder) -> Result<(), CborError>,
    {
        let buf_len = self.enc.sink.buf.len();
        self.consume_one()?;
        if let Err(err) = write(self.enc) {
            self.enc.sink.buf.truncate(buf_len);
            self.restore_one();
            return Err(err);
        }
        Ok(())
    }

    #[inline]
    fn delegate<F>(&mut self, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut Encoder) -> Result<(), CborError>,
    {
        self.sync_to_stack()?;
        let res = f(self.enc);
        let sync = self.sync_from_stack();
        match (res, sync) {
            (Err(err), _) | (Ok(()), Err(err)) => Err(err),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    /// Encode CBOR null.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn null(&mut self) -> Result<(), CborError> {
        self.write_single_byte_item(0xf6)
    }

    /// Encode a CBOR boolean.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn bool(&mut self, v: bool) -> Result<(), CborError> {
        self.write_single_byte_item(if v { 0xf5 } else { 0xf4 })
    }

    /// Encode a safe-range integer.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn int(&mut self, v: i64) -> Result<(), CborError> {
        self.write_item(|enc| enc.write_int(v))
    }

    /// Encode a CBOR bignum (tag 2/3 + byte string magnitude).
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn bignum(&mut self, negative: bool, magnitude: &[u8]) -> Result<(), CborError> {
        self.write_item(|enc| enc.write_bignum(negative, magnitude))
    }

    /// Encode a byte string.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn bytes(&mut self, b: &[u8]) -> Result<(), CborError> {
        self.write_item(|enc| enc.write_bytes(b))
    }

    /// Encode a text string.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn text(&mut self, s: &str) -> Result<(), CborError> {
        self.write_item(|enc| enc.write_text(s))
    }

    /// Encode a float64 bit pattern.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn float(&mut self, bits: F64Bits) -> Result<(), CborError> {
        self.write_item(|enc| enc.write_float(bits))
    }

    /// Splice canonical CBOR bytes as the next array element.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn raw_cbor(&mut self, v: CanonicalCborRef<'_>) -> Result<(), CborError> {
        self.delegate(|enc| enc.raw_cbor(v))
    }

    /// Splice a canonical sub-value reference as the next array element.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn raw_value_ref(&mut self, v: CborValueRef<'_>) -> Result<(), CborError> {
        self.delegate(|enc| enc.raw_value_ref(v))
    }

    /// Encode a value using a custom encoder callback as the next array element.
    ///
    /// The callback must emit exactly one complete CBOR value.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded, the callback fails, or the callback emits
    /// zero or multiple values.
    pub fn value_with<F>(&mut self, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut Encoder) -> Result<(), CborError>,
    {
        let before = self.remaining;
        if before == 0 {
            return Err(CborError::new(
                ErrorCode::ArrayLenMismatch,
                self.enc.sink.position(),
            ));
        }
        self.sync_to_stack()?;
        let checkpoint = self.enc.checkpoint();
        if let Err(err) = f(self.enc) {
            self.enc.restore(checkpoint);
            self.remaining = before;
            return Err(err);
        }
        self.sync_from_stack()?;
        if self.remaining + 1 != before {
            self.enc.restore(checkpoint);
            self.remaining = before;
            return Err(CborError::new(
                ErrorCode::ArrayLenMismatch,
                self.enc.sink.position(),
            ));
        }
        Ok(())
    }

    /// Encode a value using the native `CborEncode` trait.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn value<T: CborEncode + ?Sized>(&mut self, value: &T) -> Result<(), CborError> {
        value.encode_array_item(self)
    }

    /// Encode a nested array.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn array<F>(&mut self, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut ArrayEncoder<'_>) -> Result<(), CborError>,
    {
        self.delegate(|enc| enc.array(len, f))
    }

    /// Encode a nested map.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn map<F>(&mut self, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut MapEncoder<'_>) -> Result<(), CborError>,
    {
        self.delegate(|enc| enc.map(len, f))
    }
}

#[cfg(feature = "edit")]
pub(crate) trait EmitValue {
    fn raw_value_ref(&mut self, v: CborValueRef<'_>) -> Result<(), CborError>;
    fn raw_cbor(&mut self, v: CanonicalCborRef<'_>) -> Result<(), CborError>;
    fn map<F>(&mut self, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut MapEncoder<'_>) -> Result<(), CborError>;
    fn array<F>(&mut self, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut ArrayEncoder<'_>) -> Result<(), CborError>;
}

#[cfg(feature = "edit")]
impl EmitValue for Encoder {
    fn raw_value_ref(&mut self, v: CborValueRef<'_>) -> Result<(), CborError> {
        Self::raw_value_ref(self, v)
    }

    fn raw_cbor(&mut self, v: CanonicalCborRef<'_>) -> Result<(), CborError> {
        Self::raw_cbor(self, v)
    }

    fn map<F>(&mut self, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut MapEncoder<'_>) -> Result<(), CborError>,
    {
        Self::map(self, len, f)
    }

    fn array<F>(&mut self, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut ArrayEncoder<'_>) -> Result<(), CborError>,
    {
        Self::array(self, len, f)
    }
}

#[cfg(feature = "edit")]
impl EmitValue for ArrayEncoder<'_> {
    fn raw_value_ref(&mut self, v: CborValueRef<'_>) -> Result<(), CborError> {
        ArrayEncoder::raw_value_ref(self, v)
    }

    fn raw_cbor(&mut self, v: CanonicalCborRef<'_>) -> Result<(), CborError> {
        ArrayEncoder::raw_cbor(self, v)
    }

    fn map<F>(&mut self, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut MapEncoder<'_>) -> Result<(), CborError>,
    {
        ArrayEncoder::map(self, len, f)
    }

    fn array<F>(&mut self, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut ArrayEncoder<'_>) -> Result<(), CborError>,
    {
        ArrayEncoder::array(self, len, f)
    }
}

/// Builder for writing map entries into a canonical CBOR stream.
pub struct MapEncoder<'a> {
    enc: &'a mut Encoder,
    frame_index: usize,
}

impl MapEncoder<'_> {
    #[inline]
    fn write_entry<K, F>(&mut self, write_key: K, f: F) -> Result<(), CborError>
    where
        K: FnOnce(&mut VecSink) -> Result<(), CborError>,
        F: FnOnce(&mut Encoder) -> Result<(), CborError>,
    {
        let (before, pending) = self.enc.map_remaining_at(self.frame_index)?;
        if before == 0 || pending {
            return Err(CborError::new(
                ErrorCode::MapLenMismatch,
                self.enc.sink.position(),
            ));
        }

        let checkpoint = self.enc.checkpoint();
        let entry_start = self.enc.begin_map_key()?;
        let (key_start, key_end) = self.write_key(entry_start, write_key)?;
        if let Err(err) = self.enc.finish_map_key(key_start, key_end) {
            self.enc.restore(checkpoint);
            return Err(err);
        }
        let res = f(self.enc);
        self.finish_entry(checkpoint, before, res)
    }

    #[inline]
    fn finish_entry(
        &mut self,
        checkpoint: EncoderCheckpoint,
        before: usize,
        res: Result<(), CborError>,
    ) -> Result<(), CborError> {
        if let Err(err) = res {
            self.enc.restore(checkpoint);
            return Err(err);
        }
        let (after, pending) = self.enc.map_remaining_at(self.frame_index)?;
        if pending || after + 1 != before {
            self.enc.restore(checkpoint);
            return Err(CborError::new(
                ErrorCode::MapLenMismatch,
                self.enc.sink.position(),
            ));
        }
        Ok(())
    }

    #[inline]
    fn write_key<F>(&mut self, entry_start: usize, write: F) -> Result<(usize, usize), CborError>
    where
        F: FnOnce(&mut VecSink) -> Result<(), CborError>,
    {
        if let Err(err) = write(&mut self.enc.sink) {
            self.enc.sink.buf.truncate(entry_start);
            return Err(err);
        }
        Ok((entry_start, self.enc.sink.buf.len()))
    }

    /// Insert a map entry. Keys must be in canonical order; duplicates are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails, if keys are out of order, or if duplicates are found.
    pub fn entry<F>(&mut self, key: &str, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut Encoder) -> Result<(), CborError>,
    {
        self.enc.check_text_len(key.len())?;
        self.write_entry(|sink| encode_text(sink, key), f)
    }

    /// Insert a map entry using a pre-encoded canonical text key.
    ///
    /// This avoids re-encoding keys when splicing from validated canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails, if keys are out of order, or if duplicates are found.
    #[cfg(feature = "edit")]
    pub(crate) fn entry_raw_key<F>(
        &mut self,
        key: EncodedTextKey<'_>,
        f: F,
    ) -> Result<(), CborError>
    where
        F: FnOnce(&mut Encoder) -> Result<(), CborError>,
    {
        let key_bytes = key.as_bytes();
        self.enc.check_encoded_text_key_len(key_bytes)?;
        self.write_entry(|sink| sink.write(key_bytes), f)
    }
}
