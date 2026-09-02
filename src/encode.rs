//! Canonical, sink-generic encoder state machine for SACP-CBOR/1.
//!
//! Every fallible encoding operation returns the first profile, limit, or
//! owned sink error. After that first error, the encoder is poisoned and every
//! later fallible encoding or finish operation returns [`EncodeError::Poisoned`].

#![allow(clippy::missing_errors_doc)]

use crate::alloc_util::{try_reserve, try_reserve_exact_str};
use crate::canonical::CanonicalCborRef;
#[cfg(feature = "edit")]
use crate::canonical::EncodedTextKey;
use crate::codec::CborEncode;
use crate::limits::EncodeLimits;
use crate::profile::{
    cmp_text_keys_canonical, minimal_uint_ai, uint_argument_payload_len, validate_bignum_bytes,
    validate_int_safe_i64,
};
use crate::query::CborValueRef;
use crate::scalar::F64Bits;
use crate::wire::{self, Cursor};
use crate::work::{NoopWorkObserver, WorkMeter, WorkObserver};
use crate::{CborError, ErrorCode};
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
#[cfg(feature = "sha2")]
use core::convert::Infallible;
use core::fmt;

/// A destination for canonical CBOR bytes.
///
/// `write` may have side effects before returning an error. The encoder never
/// assumes rollback and becomes poisoned after the first sink failure.
pub trait ByteSink {
    /// The owned sink error returned by a failed write or finish.
    type Error;
    /// The completed sink product.
    type Output;

    /// Write the complete byte slice or return the owned failure.
    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;

    /// Complete the sink and return its product.
    fn finish(self) -> Result<Self::Output, Self::Error>;
}

/// An encoding failure.
#[derive(Debug, PartialEq, Eq)]
pub enum EncodeError<E> {
    /// The requested value violates the SACP-CBOR profile or configured limits.
    Cbor(CborError),
    /// The first owned error returned by the sink.
    Sink(E),
    /// A prior failure may have left bytes in the sink.
    Poisoned,
}

impl<E> From<CborError> for EncodeError<E> {
    fn from(error: CborError) -> Self {
        Self::Cbor(error)
    }
}

impl<E: fmt::Display> fmt::Display for EncodeError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => fmt::Display::fmt(error, formatter),
            Self::Sink(error) => write!(formatter, "CBOR sink error: {error}"),
            Self::Poisoned => formatter.write_str("CBOR encoder is poisoned"),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for EncodeError<E> where E: std::error::Error + 'static {}

/// Result returned by a sink-generic encoding operation.
pub type EncodeResult<T, S> = Result<T, EncodeError<<S as ByteSink>::Error>>;

/// Identifies which child of a [`FanoutSink`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanoutError<L, R> {
    /// The left sink failed before the write or finish could proceed to the right sink.
    Left(L),
    /// The right sink failed after the corresponding left operation succeeded.
    Right(R),
}

impl<L: fmt::Display, R: fmt::Display> fmt::Display for FanoutError<L, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Left(error) => write!(formatter, "left fan-out sink failed: {error}"),
            Self::Right(error) => write!(formatter, "right fan-out sink failed: {error}"),
        }
    }
}

#[cfg(feature = "std")]
impl<L, R> std::error::Error for FanoutError<L, R>
where
    L: std::error::Error + 'static,
    R: std::error::Error + 'static,
{
}

/// Sink that forwards every byte chunk to two child sinks without copying it.
///
/// Writes and finish operations are deliberately ordered left then right. Fan-out is not atomic:
/// either child may have side effects before returning an error, and a right-side failure happens
/// after the matching left-side operation has succeeded. When used through [`Encoder`], any such
/// write failure poisons the encoder, so no later write or finish is attempted. Put the sink whose
/// failure must prevent the other side effect on the left.
#[derive(Debug)]
pub struct FanoutSink<L, R> {
    left: L,
    right: R,
}

impl<L, R> FanoutSink<L, R> {
    /// Create a left-then-right fan-out sink.
    #[must_use]
    pub const fn new(left: L, right: R) -> Self {
        Self { left, right }
    }
}

impl<L: ByteSink, R: ByteSink> ByteSink for FanoutSink<L, R> {
    type Error = FanoutError<L::Error, R::Error>;
    type Output = (L::Output, R::Output);

    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.left.write(bytes).map_err(FanoutError::Left)?;
        self.right.write(bytes).map_err(FanoutError::Right)
    }

    fn finish(self) -> Result<Self::Output, Self::Error> {
        let left = self.left.finish().map_err(FanoutError::Left)?;
        let right = self.right.finish().map_err(FanoutError::Right)?;
        Ok((left, right))
    }
}

/// Allocation-backed byte sink.
#[derive(Debug, Default)]
pub struct VecSink {
    bytes: Vec<u8>,
}

impl VecSink {
    /// Create an empty sink.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Create an empty sink with fallibly reserved capacity.
    pub fn try_with_capacity(capacity: usize) -> Result<Self, CborError> {
        let mut bytes = Vec::new();
        try_reserve(&mut bytes, capacity, 0)?;
        Ok(Self { bytes })
    }

    /// Borrow bytes written so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl ByteSink for VecSink {
    type Error = CborError;
    type Output = Vec<u8>;

    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let offset = self.bytes.len();
        try_reserve(&mut self.bytes, bytes.len(), offset)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn finish(self) -> Result<Self::Output, Self::Error> {
        Ok(self.bytes)
    }
}

/// Error returned if a counting sink's byte count overflows `usize`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountOverflow;

impl fmt::Display for CountOverflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("encoded byte count overflow")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CountOverflow {}

/// Sink that counts encoded bytes without retaining the payload.
#[derive(Debug, Default)]
pub struct CountingSink {
    count: usize,
}

impl CountingSink {
    /// Create an empty counting sink.
    #[must_use]
    pub const fn new() -> Self {
        Self { count: 0 }
    }
}

impl ByteSink for CountingSink {
    type Error = CountOverflow;
    type Output = usize;

    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.count = self.count.checked_add(bytes.len()).ok_or(CountOverflow)?;
        Ok(())
    }

    fn finish(self) -> Result<Self::Output, Self::Error> {
        Ok(self.count)
    }
}

/// Sink that hashes encoded bytes without retaining the payload.
#[cfg(feature = "sha2")]
pub struct DigestSink<D> {
    digest: D,
}

#[cfg(feature = "sha2")]
impl<D: sha2::Digest> DigestSink<D> {
    /// Create a sink from a digest state.
    #[must_use]
    pub const fn new(digest: D) -> Self {
        Self { digest }
    }
}

#[cfg(feature = "sha2")]
impl<D: sha2::Digest> ByteSink for DigestSink<D> {
    type Error = Infallible;
    type Output = sha2::digest::Output<D>;

    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.digest.update(bytes);
        Ok(())
    }

    fn finish(self) -> Result<Self::Output, Self::Error> {
        Ok(self.digest.finalize())
    }
}

/// Standard-library writer sink.
#[cfg(feature = "std")]
pub struct IoSink<W> {
    writer: W,
}

#[cfg(feature = "std")]
impl<W> IoSink<W> {
    /// Wrap a writer.
    #[must_use]
    pub const fn new(writer: W) -> Self {
        Self { writer }
    }
}

#[cfg(feature = "std")]
impl<W: std::io::Write> ByteSink for IoSink<W> {
    type Error = std::io::Error;
    type Output = W;

    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.writer.write_all(bytes)
    }

    fn finish(mut self) -> Result<Self::Output, Self::Error> {
        self.writer.flush()?;
        Ok(self.writer)
    }
}

const fn format_error<E>(code: ErrorCode, offset: usize) -> EncodeError<E> {
    EncodeError::Cbor(CborError::new(code, offset))
}

/// Builds the minimal canonical header for `major` and `value`.
#[allow(clippy::cast_possible_truncation)]
#[inline]
pub(crate) fn major_uint_header(major: u8, value: u64) -> ([u8; 9], usize) {
    debug_assert!(major <= 7);
    let ai = minimal_uint_ai(value);
    debug_assert!(uint_argument_payload_len(ai).is_some());
    let mut buf = [0u8; 9];
    buf[0] = (major << 5) | ai;
    match ai {
        0..=23 => (buf, 1),
        24 => {
            buf[1] = value as u8;
            (buf, 2)
        }
        25 => {
            buf[1..3].copy_from_slice(&(value as u16).to_be_bytes());
            (buf, 3)
        }
        26 => {
            buf[1..5].copy_from_slice(&(value as u32).to_be_bytes());
            (buf, 5)
        }
        _ => {
            buf[1..9].copy_from_slice(&value.to_be_bytes());
            (buf, 9)
        }
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
    },
}

const INLINE_ENCODER_FRAMES: usize = 32;

/// Container stack with an allocation-free common path.
///
/// Schema hashing and ordinary ABI projections stay within the inline prefix. Exceptionally deep
/// values retain the existing fallible heap-growth behavior after the prefix is exhausted.
struct EncoderFrameStack {
    inline: [Frame; INLINE_ENCODER_FRAMES],
    len: usize,
    heap: Option<Vec<Frame>>,
}

impl EncoderFrameStack {
    const fn new() -> Self {
        Self {
            inline: [Frame::Array { remaining: 0 }; INLINE_ENCODER_FRAMES],
            len: 0,
            heap: None,
        }
    }

    fn prepare_push(&mut self, offset: usize) -> Result<(), CborError> {
        if let Some(heap) = &mut self.heap {
            return try_reserve(heap, 1, offset);
        }
        if self.len < INLINE_ENCODER_FRAMES {
            return Ok(());
        }

        let mut heap = Vec::new();
        try_reserve(&mut heap, self.len + 1, offset)?;
        heap.extend_from_slice(&self.inline[..self.len]);
        self.heap = Some(heap);
        Ok(())
    }

    fn push_prepared(&mut self, frame: Frame) {
        if let Some(heap) = &mut self.heap {
            debug_assert!(heap.len() < heap.capacity());
            heap.push(frame);
            self.len = heap.len();
        } else {
            debug_assert!(self.len < INLINE_ENCODER_FRAMES);
            self.inline[self.len] = frame;
            self.len += 1;
        }
    }

    fn pop(&mut self) -> Option<Frame> {
        if let Some(heap) = &mut self.heap {
            let frame = heap.pop();
            self.len = heap.len();
            frame
        } else if self.len == 0 {
            None
        } else {
            self.len -= 1;
            Some(self.inline[self.len])
        }
    }

    fn last(&self) -> Option<&Frame> {
        if let Some(heap) = &self.heap {
            heap.last()
        } else {
            self.inline.get(self.len.checked_sub(1)?)
        }
    }

    fn last_mut(&mut self) -> Option<&mut Frame> {
        if let Some(heap) = &mut self.heap {
            heap.last_mut()
        } else {
            self.inline.get_mut(self.len.checked_sub(1)?)
        }
    }

    fn get(&self, index: usize) -> Option<&Frame> {
        self.heap.as_ref().map_or_else(
            || self.inline[..self.len].get(index),
            |heap| heap.get(index),
        )
    }

    const fn len(&self) -> usize {
        self.len
    }

    const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Clone, Copy)]
enum SlotState {
    Root(u8),
    Array {
        index: usize,
        remaining: usize,
    },
    Map {
        index: usize,
        remaining_pairs: usize,
        pending_value: bool,
    },
}

/// Streaming canonical encoder over an arbitrary byte sink.
pub struct Encoder<S: ByteSink = VecSink, O: WorkObserver = NoopWorkObserver> {
    sink: S,
    meter: WorkMeter<O>,
    written: usize,
    root_remaining: u8,
    stack: EncoderFrameStack,
    limits: EncodeLimits,
    items_seen: usize,
    poisoned: bool,
}

impl Encoder<VecSink, NoopWorkObserver> {
    /// Create a vector-backed encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self::from_parts(VecSink::new(), EncodeLimits::unbounded(), NoopWorkObserver)
    }

    /// Create a vector-backed encoder with limits.
    pub fn with_limits(limits: EncodeLimits) -> Result<Self, CborError> {
        limits.validate()?;
        Ok(Self::from_parts(VecSink::new(), limits, NoopWorkObserver))
    }

    /// Create a vector-backed encoder with fallibly reserved capacity.
    pub fn try_with_capacity(capacity: usize) -> Result<Self, CborError> {
        Ok(Self::from_parts(
            VecSink::try_with_capacity(capacity)?,
            EncodeLimits::unbounded(),
            NoopWorkObserver,
        ))
    }

    /// Create a limited vector-backed encoder with fallibly reserved capacity.
    pub fn try_with_capacity_and_limits(
        capacity: usize,
        limits: EncodeLimits,
    ) -> Result<Self, CborError> {
        limits.validate()?;
        if capacity > limits.max_output_bytes {
            return Err(CborError::new(ErrorCode::MessageLenLimitExceeded, 0));
        }
        Ok(Self::from_parts(
            VecSink::try_with_capacity(capacity)?,
            limits,
            NoopWorkObserver,
        ))
    }
}

impl<O: WorkObserver> Encoder<VecSink, O> {
    /// Borrow bytes emitted so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.sink.as_bytes()
    }
}

impl Default for Encoder<VecSink, NoopWorkObserver> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: ByteSink> Encoder<S, NoopWorkObserver> {
    /// Create an encoder over `sink` with unbounded encoding limits.
    #[must_use]
    pub const fn with_sink(sink: S) -> Self {
        Self::from_parts(sink, EncodeLimits::unbounded(), NoopWorkObserver)
    }

    /// Create an encoder over `sink` with explicit limits.
    pub fn with_sink_and_limits(sink: S, limits: EncodeLimits) -> Result<Self, CborError> {
        limits.validate()?;
        Ok(Self::from_parts(sink, limits, NoopWorkObserver))
    }
}

impl<S: ByteSink, O: WorkObserver> Encoder<S, O> {
    const fn from_parts(sink: S, limits: EncodeLimits, observer: O) -> Self {
        Self {
            sink,
            meter: WorkMeter::new(observer),
            written: 0,
            root_remaining: 1,
            stack: EncoderFrameStack::new(),
            limits,
            items_seen: 0,
            poisoned: false,
        }
    }

    /// Create an observed encoder over `sink` with unbounded encoding limits.
    pub fn with_sink_and_observer(sink: S, observer: O) -> Result<Self, CborError> {
        let mut encoder = Self::from_parts(sink, EncodeLimits::unbounded(), observer);
        encoder
            .meter
            .start()
            .map_err(|_| CborError::new(ErrorCode::WorkCancelled, 0))?;
        Ok(encoder)
    }

    /// Create an observed encoder over `sink` with explicit limits.
    pub fn with_sink_limits_and_observer(
        sink: S,
        limits: EncodeLimits,
        observer: O,
    ) -> Result<Self, CborError> {
        limits.validate()?;
        let mut encoder = Self::from_parts(sink, limits, observer);
        encoder
            .meter
            .start()
            .map_err(|_| CborError::new(ErrorCode::WorkCancelled, 0))?;
        Ok(encoder)
    }

    /// Return the number of bytes in chunks whose writes completed successfully.
    ///
    /// A failing sink may physically accept part of a chunk before returning an
    /// error; those unconfirmed bytes are not included in this logical count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.written
    }

    /// Return whether no complete chunk write has been confirmed by the sink.
    ///
    /// This does not assert that a failing sink has no partial physical side
    /// effects.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.written == 0
    }

    /// Complete exactly one root item and return the sink product.
    pub fn finish(mut self) -> EncodeResult<S::Output, S> {
        if self.poisoned {
            return Err(EncodeError::Poisoned);
        }
        if self.root_remaining != 0 || !self.stack.is_empty() {
            return Err(format_error(ErrorCode::UnexpectedEof, self.written));
        }
        if self.meter.finish().is_err() {
            self.poisoned = true;
            return Err(format_error(ErrorCode::WorkCancelled, self.written));
        }
        self.sink.finish().map_err(EncodeError::Sink)
    }

    /// Report one completed cooperative structural or projection work unit.
    ///
    /// This is an observation boundary, not a resumable checkpoint. Observer cancellation is
    /// terminal, poisons this encoder, and preserves any sink output already confirmed by prior
    /// writes.
    pub fn checkpoint(&mut self) -> EncodeResult<(), S> {
        self.attempt(|encoder| encoder.complete_work(1))
    }

    pub(crate) const fn ensure_healthy(&self) -> EncodeResult<(), S> {
        if self.poisoned {
            Err(EncodeError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn attempt<T, F>(&mut self, operation: F) -> EncodeResult<T, S>
    where
        F: FnOnce(&mut Self) -> EncodeResult<T, S>,
    {
        self.attempt_with_caller_error(operation)
    }

    fn attempt_with_caller_error<T, E, F>(&mut self, operation: F) -> Result<T, E>
    where
        E: From<EncodeError<S::Error>>,
        F: FnOnce(&mut Self) -> Result<T, E>,
    {
        self.ensure_healthy().map_err(E::from)?;
        match operation(self) {
            Ok(value) => Ok(value),
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    pub(crate) const fn poison(&mut self) {
        self.poisoned = true;
    }

    #[inline]
    fn complete_work(&mut self, completed_units: usize) -> EncodeResult<(), S> {
        self.meter
            .complete(completed_units)
            .map_err(|_| format_error(ErrorCode::WorkCancelled, self.written))
    }

    pub(crate) fn guarded_value<E, F>(&mut self, operation: F) -> Result<(), E>
    where
        E: From<EncodeError<S::Error>>,
        F: FnOnce(&mut Self) -> Result<(), E>,
    {
        self.attempt_with_caller_error(|encoder| {
            let before = encoder.slot_state();
            operation(encoder)?;
            encoder.ensure_healthy().map_err(E::from)?;
            if encoder.consumed_exactly_one(before) {
                Ok(())
            } else {
                Err(E::from(format_error(
                    ErrorCode::MalformedCanonical,
                    encoder.written,
                )))
            }
        })
    }

    fn write_chunks(&mut self, chunks: &[&[u8]]) -> EncodeResult<(), S> {
        self.ensure_healthy()?;
        self.check_output_chunks(chunks)?;
        for chunk in chunks {
            if !O::ENABLED {
                if let Err(error) = self.sink.write(chunk) {
                    self.poisoned = true;
                    return Err(EncodeError::Sink(error));
                }
                self.written += chunk.len();
                continue;
            }

            let mut remaining = *chunk;
            while !remaining.is_empty() {
                let chunk_len = self.meter.next_chunk(remaining.len());
                let (next, rest) = remaining.split_at(chunk_len);
                if let Err(error) = self.sink.write(next) {
                    self.poisoned = true;
                    return Err(EncodeError::Sink(error));
                }
                self.written += next.len();
                if let Err(error) = self.complete_work(next.len()) {
                    self.poisoned = true;
                    return Err(error);
                }
                remaining = rest;
            }
        }
        Ok(())
    }

    fn check_output_chunks(&self, chunks: &[&[u8]]) -> EncodeResult<(), S> {
        let mut total = 0usize;
        for chunk in chunks {
            total = total
                .checked_add(chunk.len())
                .ok_or_else(|| format_error(ErrorCode::LengthOverflow, self.written))?;
        }
        let end = self
            .written
            .checked_add(total)
            .ok_or_else(|| format_error(ErrorCode::LengthOverflow, self.written))?;
        if end > self.limits.max_output_bytes {
            return Err(format_error(
                ErrorCode::MessageLenLimitExceeded,
                self.written,
            ));
        }
        Ok(())
    }

    fn check_text_output(&self, text: &str) -> EncodeResult<(), S> {
        let length = u64::try_from(text.len())
            .map_err(|_| format_error(ErrorCode::LengthOverflow, self.written))?;
        let (header, header_len) = major_uint_header(3, length);
        self.check_output_chunks(&[&header[..header_len], text.as_bytes()])
    }

    fn begin_value(&mut self) -> EncodeResult<(), S> {
        self.ensure_healthy()?;
        match self.stack.last_mut() {
            Some(Frame::Array { remaining }) => {
                if *remaining == 0 {
                    return Err(format_error(ErrorCode::ArrayLenMismatch, self.written));
                }
                *remaining -= 1;
            }
            Some(Frame::Map {
                remaining_pairs,
                pending_value,
                ..
            }) => {
                if !*pending_value || *remaining_pairs == 0 {
                    return Err(format_error(ErrorCode::MapLenMismatch, self.written));
                }
                *pending_value = false;
                *remaining_pairs -= 1;
            }
            None => {
                if self.root_remaining == 0 {
                    return Err(format_error(ErrorCode::TrailingBytes, self.written));
                }
                self.root_remaining = 0;
            }
        }
        self.complete_work(1)
    }

    fn check_value_slot(&self) -> EncodeResult<(), S> {
        self.ensure_healthy()?;
        match self.stack.last() {
            Some(Frame::Array { remaining }) if *remaining > 0 => Ok(()),
            Some(Frame::Array { .. }) => {
                Err(format_error(ErrorCode::ArrayLenMismatch, self.written))
            }
            Some(Frame::Map {
                remaining_pairs,
                pending_value,
            }) if *remaining_pairs > 0 && *pending_value => Ok(()),
            Some(Frame::Map { .. }) => Err(format_error(ErrorCode::MapLenMismatch, self.written)),
            None if self.root_remaining != 0 => Ok(()),
            None => Err(format_error(ErrorCode::TrailingBytes, self.written)),
        }
    }

    fn slot_state(&self) -> SlotState {
        match self.stack.last() {
            Some(Frame::Array { remaining }) => SlotState::Array {
                index: self.stack.len() - 1,
                remaining: *remaining,
            },
            Some(Frame::Map {
                remaining_pairs,
                pending_value,
            }) => SlotState::Map {
                index: self.stack.len() - 1,
                remaining_pairs: *remaining_pairs,
                pending_value: *pending_value,
            },
            None => SlotState::Root(self.root_remaining),
        }
    }

    fn consumed_exactly_one(&self, before: SlotState) -> bool {
        match before {
            SlotState::Root(1) => self.stack.is_empty() && self.root_remaining == 0,
            SlotState::Array { index, remaining } if remaining > 0 => matches!(
                self.stack.get(index),
                Some(Frame::Array { remaining: after }) if after.checked_add(1) == Some(remaining)
            ),
            SlotState::Map {
                index,
                remaining_pairs,
                pending_value: true,
            } if remaining_pairs > 0 => matches!(
                self.stack.get(index),
                Some(Frame::Map {
                    remaining_pairs: after,
                    pending_value: false,
                }) if after.checked_add(1) == Some(remaining_pairs)
            ),
            _ => false,
        }
    }

    fn write_scalar(&mut self, chunks: &[&[u8]]) -> EncodeResult<(), S> {
        self.check_output_chunks(chunks)?;
        self.begin_value()?;
        self.write_chunks(chunks)
    }

    const fn check_array_len(&self, len: usize) -> EncodeResult<(), S> {
        if len > self.limits.max_array_len {
            return Err(format_error(ErrorCode::ArrayLenLimitExceeded, self.written));
        }
        Ok(())
    }

    const fn check_map_len(&self, len: usize) -> EncodeResult<(), S> {
        if len > self.limits.max_map_len {
            return Err(format_error(ErrorCode::MapLenLimitExceeded, self.written));
        }
        Ok(())
    }

    const fn check_bytes_len(&self, len: usize) -> EncodeResult<(), S> {
        if len > self.limits.max_bytes_len {
            return Err(format_error(ErrorCode::BytesLenLimitExceeded, self.written));
        }
        Ok(())
    }

    pub(crate) const fn check_text_len(&self, len: usize) -> EncodeResult<(), S> {
        if len > self.limits.max_text_len {
            return Err(format_error(ErrorCode::TextLenLimitExceeded, self.written));
        }
        Ok(())
    }

    fn checked_items(&self, add: usize) -> EncodeResult<usize, S> {
        let total = self
            .items_seen
            .checked_add(add)
            .ok_or_else(|| format_error(ErrorCode::LengthOverflow, self.written))?;
        if total > self.limits.max_total_items {
            return Err(format_error(
                ErrorCode::TotalItemsLimitExceeded,
                self.written,
            ));
        }
        Ok(total)
    }

    fn prepare_frame(&mut self) -> EncodeResult<(), S> {
        if self.stack.len() >= self.limits.max_depth {
            return Err(format_error(ErrorCode::DepthLimitExceeded, self.written));
        }
        self.stack
            .prepare_push(self.written)
            .map_err(EncodeError::Cbor)
    }

    fn preflight_array(&self, len: usize) -> EncodeResult<(usize, [u8; 9], usize), S> {
        self.ensure_healthy()?;
        self.check_array_len(len)?;
        let items = self.checked_items(len)?;
        if self.stack.len() >= self.limits.max_depth {
            return Err(format_error(ErrorCode::DepthLimitExceeded, self.written));
        }
        self.check_value_slot()?;
        let length = u64::try_from(len)
            .map_err(|_| format_error(ErrorCode::LengthOverflow, self.written))?;
        let (header, header_len) = major_uint_header(4, length);
        let minimum_output = self
            .written
            .checked_add(header_len)
            .and_then(|value| value.checked_add(len))
            .ok_or_else(|| format_error(ErrorCode::LengthOverflow, self.written))?;
        if minimum_output > self.limits.max_output_bytes {
            return Err(format_error(
                ErrorCode::MessageLenLimitExceeded,
                self.written,
            ));
        }
        Ok((items, header, header_len))
    }

    fn preflight_map(&self, len: usize) -> EncodeResult<(usize, [u8; 9], usize), S> {
        self.ensure_healthy()?;
        self.check_map_len(len)?;
        let item_count = len
            .checked_mul(2)
            .ok_or_else(|| format_error(ErrorCode::LengthOverflow, self.written))?;
        let items = self.checked_items(item_count)?;
        if self.stack.len() >= self.limits.max_depth {
            return Err(format_error(ErrorCode::DepthLimitExceeded, self.written));
        }
        self.check_value_slot()?;
        let length = u64::try_from(len)
            .map_err(|_| format_error(ErrorCode::LengthOverflow, self.written))?;
        let (header, header_len) = major_uint_header(5, length);
        let minimum_output = self
            .written
            .checked_add(header_len)
            .and_then(|value| value.checked_add(item_count))
            .ok_or_else(|| format_error(ErrorCode::LengthOverflow, self.written))?;
        if minimum_output > self.limits.max_output_bytes {
            return Err(format_error(
                ErrorCode::MessageLenLimitExceeded,
                self.written,
            ));
        }
        Ok((items, header, header_len))
    }

    #[cfg(feature = "serde")]
    pub(crate) fn preflight_buffered_map(&self, len: usize) -> EncodeResult<(usize, usize), S> {
        let (items, _, header_len) = self.preflight_map(len)?;
        Ok((header_len, items))
    }

    #[cfg(feature = "serde")]
    pub(crate) const fn encode_limits(&self) -> EncodeLimits {
        self.limits
    }

    #[cfg(feature = "serde")]
    pub(crate) const fn items_seen(&self) -> usize {
        self.items_seen
    }

    #[cfg(feature = "serde")]
    pub(crate) const fn container_depth(&self) -> usize {
        self.stack.len()
    }

    fn close_container(&mut self) -> EncodeResult<(), S> {
        let valid = matches!(
            self.stack.last(),
            Some(
                Frame::Array { remaining: 0 }
                    | Frame::Map {
                        remaining_pairs: 0,
                        pending_value: false,
                        ..
                    },
            )
        );
        if !valid {
            let code = match self.stack.last() {
                Some(Frame::Array { .. }) => ErrorCode::ArrayLenMismatch,
                Some(Frame::Map { .. }) => ErrorCode::MapLenMismatch,
                None => ErrorCode::MalformedCanonical,
            };
            return Err(format_error(code, self.written));
        }
        let _ = self.stack.pop();
        Ok(())
    }

    fn write_major_value(&mut self, major: u8, value: u64) -> EncodeResult<(), S> {
        let (header, len) = major_uint_header(major, value);
        self.write_scalar(&[&header[..len]])
    }

    fn write_int_value(&mut self, value: i64) -> EncodeResult<(), S> {
        validate_int_safe_i64(value).map_err(|code| format_error(code, self.written))?;
        let (major, argument) = if value >= 0 {
            (
                0,
                u64::try_from(value)
                    .map_err(|_| format_error(ErrorCode::LengthOverflow, self.written))?,
            )
        } else {
            let argument = -1_i128 - i128::from(value);
            (
                1,
                u64::try_from(argument)
                    .map_err(|_| format_error(ErrorCode::LengthOverflow, self.written))?,
            )
        };
        self.write_major_value(major, argument)
    }

    fn write_bignum_value(&mut self, negative: bool, magnitude: &[u8]) -> EncodeResult<(), S> {
        self.check_bytes_len(magnitude.len())?;
        validate_bignum_bytes(negative, magnitude)
            .map_err(|code| format_error(code, self.written))?;
        let (tag, tag_len) = major_uint_header(6, if negative { 3 } else { 2 });
        let length = u64::try_from(magnitude.len())
            .map_err(|_| format_error(ErrorCode::LengthOverflow, self.written))?;
        let (header, header_len) = major_uint_header(2, length);
        self.write_scalar(&[&tag[..tag_len], &header[..header_len], magnitude])
    }

    fn write_bytes_value(&mut self, bytes: &[u8]) -> EncodeResult<(), S> {
        self.check_bytes_len(bytes.len())?;
        let length = u64::try_from(bytes.len())
            .map_err(|_| format_error(ErrorCode::LengthOverflow, self.written))?;
        let (header, header_len) = major_uint_header(2, length);
        self.write_scalar(&[&header[..header_len], bytes])
    }

    fn write_text_value(&mut self, text: &str) -> EncodeResult<(), S> {
        self.check_text_len(text.len())?;
        let length = u64::try_from(text.len())
            .map_err(|_| format_error(ErrorCode::LengthOverflow, self.written))?;
        let (header, header_len) = major_uint_header(3, length);
        self.write_scalar(&[&header[..header_len], text.as_bytes()])
    }

    fn account_canonical_value(&mut self, bytes: &[u8]) -> EncodeResult<usize, S> {
        let limits = self.limits.to_decode_limits(bytes.len());
        let mut cursor = Cursor::with_pos(bytes, 0);
        let mut items = self.items_seen;
        wire::skip_one_value_observed::<false, O>(
            &mut cursor,
            wire::WalkPolicy::new(Some(&limits), crate::ValidationOptions::new()),
            &mut items,
            self.stack.len(),
            &mut self.meter,
        )
        .map_err(EncodeError::Cbor)?;
        if cursor.position() != bytes.len() {
            return Err(format_error(ErrorCode::TrailingBytes, cursor.position()));
        }
        Ok(items)
    }

    fn write_raw_value(&mut self, bytes: &[u8]) -> EncodeResult<(), S> {
        self.check_output_chunks(&[bytes])?;
        self.check_value_slot()?;
        let items = self.account_canonical_value(bytes)?;
        self.begin_value()?;
        self.write_chunks(&[bytes])?;
        self.items_seen = items;
        Ok(())
    }

    fn write_map_key_bytes(&mut self, text: &str) -> EncodeResult<(), S> {
        self.ensure_healthy()?;
        match self.stack.last() {
            Some(Frame::Map {
                remaining_pairs,
                pending_value,
            }) if *remaining_pairs > 0 && !*pending_value => {}
            Some(Frame::Map { .. }) => {
                return Err(format_error(ErrorCode::MapLenMismatch, self.written))
            }
            _ => return Err(format_error(ErrorCode::MapKeyMustBeText, self.written)),
        }
        self.check_text_len(text.len())?;
        let length = u64::try_from(text.len())
            .map_err(|_| format_error(ErrorCode::LengthOverflow, self.written))?;
        let (header, header_len) = major_uint_header(3, length);
        self.write_chunks(&[&header[..header_len], text.as_bytes()])?;
        let Some(Frame::Map { pending_value, .. }) = self.stack.last_mut() else {
            unreachable!();
        };
        *pending_value = true;
        self.complete_work(1)
    }

    #[cfg(feature = "edit")]
    fn encoded_text_key_source<'a>(&self, key: &'a [u8]) -> EncodeResult<&'a str, S> {
        let mut cursor = Cursor::with_pos(key, 0);
        let offset = cursor.position();
        let initial = cursor.read_u8().map_err(EncodeError::Cbor)?;
        if initial >> 5 != 3 {
            return Err(format_error(ErrorCode::MapKeyMustBeText, offset));
        }
        let len = wire::read_len::<true>(&mut cursor, initial & 0x1f, offset)
            .map_err(EncodeError::Cbor)?;
        if cursor.position().checked_add(len) != Some(key.len()) {
            return Err(format_error(ErrorCode::MalformedCanonical, offset));
        }
        self.check_text_len(len)?;
        core::str::from_utf8(&key[cursor.position()..])
            .map_err(|_| format_error(ErrorCode::Utf8Invalid, offset))
    }

    /// Encode CBOR null.
    pub fn null(&mut self) -> EncodeResult<(), S> {
        self.attempt(|encoder| encoder.write_scalar(&[&[0xf6]]))
    }

    /// Encode a CBOR boolean.
    pub fn bool(&mut self, value: bool) -> EncodeResult<(), S> {
        self.attempt(|encoder| encoder.write_scalar(&[&[if value { 0xf5 } else { 0xf4 }]]))
    }

    /// Encode a safe-range integer.
    pub fn int(&mut self, value: i64) -> EncodeResult<(), S> {
        self.attempt(|encoder| encoder.write_int_value(value))
    }

    /// Encode an unsigned integer, using a bignum outside the safe range.
    pub fn int_u128(&mut self, value: u128) -> EncodeResult<(), S> {
        self.attempt(|encoder| {
            let safe_max = u128::from(crate::profile::MAX_SAFE_INTEGER);
            if value <= safe_max {
                return encoder.write_int_value(
                    i64::try_from(value)
                        .map_err(|_| format_error(ErrorCode::LengthOverflow, encoder.written))?,
                );
            }
            let magnitude = value.to_be_bytes();
            let first = (value.leading_zeros() / 8) as usize;
            encoder.write_bignum_value(false, &magnitude[first..])
        })
    }

    /// Encode a signed integer, using a bignum outside the safe range.
    pub fn int_i128(&mut self, value: i128) -> EncodeResult<(), S> {
        self.attempt(|encoder| {
            let min = i128::from(crate::profile::MIN_SAFE_INTEGER);
            let max = i128::from(crate::profile::MAX_SAFE_INTEGER_I64);
            if value >= min && value <= max {
                return encoder.write_int_value(
                    i64::try_from(value)
                        .map_err(|_| format_error(ErrorCode::LengthOverflow, encoder.written))?,
                );
            }
            let negative = value < 0;
            let magnitude_value = if negative {
                u128::try_from(-1_i128 - value)
                    .map_err(|_| format_error(ErrorCode::LengthOverflow, encoder.written))?
            } else {
                u128::try_from(value)
                    .map_err(|_| format_error(ErrorCode::LengthOverflow, encoder.written))?
            };
            let magnitude = magnitude_value.to_be_bytes();
            let first = (magnitude_value.leading_zeros() / 8) as usize;
            encoder.write_bignum_value(negative, &magnitude[first..])
        })
    }

    /// Encode a canonical CBOR bignum.
    pub fn bignum(&mut self, negative: bool, magnitude: &[u8]) -> EncodeResult<(), S> {
        self.attempt(|encoder| encoder.write_bignum_value(negative, magnitude))
    }

    /// Encode a byte string.
    pub fn bytes(&mut self, bytes: &[u8]) -> EncodeResult<(), S> {
        self.attempt(|encoder| encoder.write_bytes_value(bytes))
    }

    /// Encode a text string.
    pub fn text(&mut self, text: &str) -> EncodeResult<(), S> {
        self.attempt(|encoder| encoder.write_text_value(text))
    }

    /// Encode a canonical float64 bit pattern.
    pub fn float(&mut self, bits: F64Bits) -> EncodeResult<(), S> {
        self.attempt(|encoder| {
            let mut encoded = [0u8; 9];
            encoded[0] = 0xfb;
            encoded[1..].copy_from_slice(&bits.bits().to_be_bytes());
            encoder.write_scalar(&[&encoded])
        })
    }

    /// Splice one validated canonical CBOR value.
    pub fn raw_cbor(&mut self, value: CanonicalCborRef<'_>) -> EncodeResult<(), S> {
        self.attempt(|encoder| encoder.write_raw_value(value.as_bytes()))
    }

    /// Splice one validated canonical CBOR sub-value.
    pub fn raw_value_ref(&mut self, value: CborValueRef<'_>) -> EncodeResult<(), S> {
        self.attempt(|encoder| encoder.write_raw_value(value.as_bytes()))
    }

    /// Encode one native value through the controlled trait adapter.
    pub fn encode<T: CborEncode + ?Sized>(&mut self, value: &T) -> EncodeResult<(), S> {
        self.encode_with(|encoder| value.encode(encoder))
    }

    /// Encode one value through a controlled adapter.
    ///
    /// This is the integration point for encoding traits layered on top of
    /// SACP-CBOR. The closure cannot obtain the underlying encoder directly,
    /// and every returned failure is made sticky by this method.
    pub fn encode_with<F>(&mut self, encode: F) -> EncodeResult<(), S>
    where
        F: FnOnce(&mut ValueEncoder<'_, S, O>) -> EncodeResult<(), S>,
    {
        self.encode_with_caller_error(encode)
    }

    /// Encode exactly one value while preserving a caller-defined error domain.
    ///
    /// `E` must losslessly accept core profile and owned sink errors. Any caller error, core error,
    /// sink failure, or callback that emits other than one value poisons this encoder. This makes
    /// the method suitable for fallible projections that must not be collapsed into a CBOR error.
    pub fn encode_with_caller_error<E, F>(&mut self, encode: F) -> Result<(), E>
    where
        E: From<EncodeError<S::Error>>,
        F: FnOnce(&mut ValueEncoder<'_, S, O>) -> Result<(), E>,
    {
        self.guarded_value(|encoder| {
            let mut value_encoder = ValueEncoder { encoder };
            encode(&mut value_encoder)
        })
    }

    #[cfg(feature = "serde")]
    pub(crate) fn raw_trusted_canonical_bytes(&mut self, bytes: &[u8]) -> EncodeResult<(), S> {
        self.attempt(|encoder| encoder.write_raw_value(bytes))
    }

    /// Encode a definite-length array.
    pub fn array<F>(&mut self, len: usize, build: F) -> EncodeResult<(), S>
    where
        F: FnOnce(&mut ArrayEncoder<'_, S, O>) -> EncodeResult<(), S>,
    {
        self.array_with_caller_error(len, build)
    }

    /// Encode a definite-length array while preserving a caller-defined error domain.
    ///
    /// The declared length is preflighted before allocation or output. The callback must emit
    /// exactly `len` elements. Any caller error, length mismatch, core error, or sink failure is
    /// returned in `E` and poisons this encoder.
    pub fn array_with_caller_error<E, F>(&mut self, len: usize, build: F) -> Result<(), E>
    where
        E: From<EncodeError<S::Error>>,
        F: FnOnce(&mut ArrayEncoder<'_, S, O>) -> Result<(), E>,
    {
        self.attempt_with_caller_error(|encoder| encoder.array_inner(len, build))
    }

    fn array_inner<E, F>(&mut self, len: usize, build: F) -> Result<(), E>
    where
        E: From<EncodeError<S::Error>>,
        F: FnOnce(&mut ArrayEncoder<'_, S, O>) -> Result<(), E>,
    {
        let (items, header, header_len) = self.preflight_array(len).map_err(E::from)?;
        self.prepare_frame().map_err(E::from)?;
        self.begin_value().map_err(E::from)?;
        self.write_chunks(&[&header[..header_len]])
            .map_err(E::from)?;
        self.items_seen = items;
        self.stack.push_prepared(Frame::Array { remaining: len });
        let frame_index = self.stack.len() - 1;
        let result = {
            let mut array = ArrayEncoder {
                enc: self,
                frame_index,
            };
            build(&mut array)
        };
        result?;
        self.ensure_healthy().map_err(E::from)?;
        self.close_container().map_err(E::from)
    }

    /// Encode a definite-length text-keyed map.
    pub fn map<F>(&mut self, len: usize, build: F) -> EncodeResult<(), S>
    where
        F: FnOnce(&mut MapEncoder<'_, S, O>) -> EncodeResult<(), S>,
    {
        self.attempt(|encoder| encoder.map_inner(len, build))
    }

    fn map_inner<F>(&mut self, len: usize, build: F) -> EncodeResult<(), S>
    where
        F: FnOnce(&mut MapEncoder<'_, S, O>) -> EncodeResult<(), S>,
    {
        let (items, header, header_len) = self.preflight_map(len)?;
        self.prepare_frame()?;
        self.begin_value()?;
        self.write_chunks(&[&header[..header_len]])?;
        self.items_seen = items;
        self.stack.push_prepared(Frame::Map {
            remaining_pairs: len,
            pending_value: false,
        });
        let frame_index = self.stack.len() - 1;
        let result = {
            let mut map = MapEncoder {
                enc: self,
                frame_index,
                previous_key: String::new(),
                has_previous_key: false,
            };
            build(&mut map)
        };
        result?;
        self.ensure_healthy()?;
        self.close_container()
    }

    #[cfg(feature = "serde")]
    pub(crate) fn array_header(&mut self, len: usize) -> EncodeResult<(), S> {
        self.attempt(|encoder| encoder.array_header_inner(len))
    }

    #[cfg(feature = "serde")]
    fn array_header_inner(&mut self, len: usize) -> EncodeResult<(), S> {
        let (items, header, header_len) = self.preflight_array(len)?;
        self.prepare_frame()?;
        self.begin_value()?;
        self.write_chunks(&[&header[..header_len]])?;
        self.items_seen = items;
        self.stack.push_prepared(Frame::Array { remaining: len });
        Ok(())
    }

    #[cfg(feature = "serde")]
    pub(crate) fn map_header(&mut self, len: usize) -> EncodeResult<(), S> {
        self.attempt(|encoder| encoder.map_header_inner(len))
    }

    #[cfg(feature = "serde")]
    fn map_header_inner(&mut self, len: usize) -> EncodeResult<(), S> {
        let (items, header, header_len) = self.preflight_map(len)?;
        self.prepare_frame()?;
        self.begin_value()?;
        self.write_chunks(&[&header[..header_len]])?;
        self.items_seen = items;
        self.stack.push_prepared(Frame::Map {
            remaining_pairs: len,
            pending_value: false,
        });
        Ok(())
    }

    #[cfg(feature = "serde")]
    pub(crate) fn finish_container(&mut self) -> EncodeResult<(), S> {
        self.attempt(Self::close_container)
    }

    #[cfg(feature = "serde")]
    pub(crate) fn write_map_key(&mut self, key: &str) -> EncodeResult<(), S> {
        self.attempt(|encoder| encoder.write_map_key_bytes(key))
    }
}

/// Controlled single-value adapter passed to [`CborEncode`].
///
/// Values cannot construct this adapter or access the underlying encoder, so
/// every trait failure is observed by [`Encoder::encode`] and becomes sticky.
pub struct ValueEncoder<'a, S: ByteSink, O: WorkObserver = NoopWorkObserver> {
    encoder: &'a mut Encoder<S, O>,
}

impl<S: ByteSink, O: WorkObserver> ValueEncoder<'_, S, O> {
    /// Report one completed cooperative projection work unit.
    ///
    /// This reports progress to the encoder's observer; it is not a resumable checkpoint.
    pub fn checkpoint(&mut self) -> EncodeResult<(), S> {
        self.encoder.checkpoint()
    }

    /// Encode null.
    pub fn null(&mut self) -> EncodeResult<(), S> {
        self.encoder.null()
    }

    /// Encode a boolean.
    pub fn bool(&mut self, value: bool) -> EncodeResult<(), S> {
        self.encoder.bool(value)
    }

    /// Encode a safe-range integer.
    pub fn int(&mut self, value: i64) -> EncodeResult<(), S> {
        self.encoder.int(value)
    }

    /// Encode a signed integer, using a bignum when required.
    pub fn int_i128(&mut self, value: i128) -> EncodeResult<(), S> {
        self.encoder.int_i128(value)
    }

    /// Encode an unsigned integer, using a bignum when required.
    pub fn int_u128(&mut self, value: u128) -> EncodeResult<(), S> {
        self.encoder.int_u128(value)
    }

    /// Encode a bignum.
    pub fn bignum(&mut self, negative: bool, magnitude: &[u8]) -> EncodeResult<(), S> {
        self.encoder.bignum(negative, magnitude)
    }

    /// Encode bytes.
    pub fn bytes(&mut self, bytes: &[u8]) -> EncodeResult<(), S> {
        self.encoder.bytes(bytes)
    }

    /// Encode text.
    pub fn text(&mut self, text: &str) -> EncodeResult<(), S> {
        self.encoder.text(text)
    }

    /// Encode a float.
    pub fn float(&mut self, bits: F64Bits) -> EncodeResult<(), S> {
        self.encoder.float(bits)
    }

    /// Splice canonical bytes.
    pub fn raw_cbor(&mut self, value: CanonicalCborRef<'_>) -> EncodeResult<(), S> {
        self.encoder.raw_cbor(value)
    }

    /// Splice a canonical sub-value.
    pub fn raw_value_ref(&mut self, value: CborValueRef<'_>) -> EncodeResult<(), S> {
        self.encoder.raw_value_ref(value)
    }

    /// Encode a nested native value.
    pub fn value<T: CborEncode + ?Sized>(&mut self, value: &T) -> EncodeResult<(), S> {
        self.encoder.encode(value)
    }

    /// Encode exactly one value while preserving a caller-defined error domain.
    ///
    /// Any returned caller error or core encoding failure poisons the underlying encoder.
    pub fn encode_with_caller_error<E, F>(&mut self, encode: F) -> Result<(), E>
    where
        E: From<EncodeError<S::Error>>,
        F: FnOnce(&mut ValueEncoder<'_, S, O>) -> Result<(), E>,
    {
        self.encoder.encode_with_caller_error(encode)
    }

    /// Encode an array.
    pub fn array<F>(&mut self, len: usize, build: F) -> EncodeResult<(), S>
    where
        F: FnOnce(&mut ArrayEncoder<'_, S, O>) -> EncodeResult<(), S>,
    {
        self.encoder.array(len, build)
    }

    /// Encode an array while preserving a caller-defined error domain.
    ///
    /// Any returned caller error, declared-length mismatch, or core encoding failure poisons the
    /// underlying encoder.
    pub fn array_with_caller_error<E, F>(&mut self, len: usize, build: F) -> Result<(), E>
    where
        E: From<EncodeError<S::Error>>,
        F: FnOnce(&mut ArrayEncoder<'_, S, O>) -> Result<(), E>,
    {
        self.encoder.array_with_caller_error(len, build)
    }

    /// Encode a map.
    pub fn map<F>(&mut self, len: usize, build: F) -> EncodeResult<(), S>
    where
        F: FnOnce(&mut MapEncoder<'_, S, O>) -> EncodeResult<(), S>,
    {
        self.encoder.map(len, build)
    }
}

/// Builder for array elements.
pub struct ArrayEncoder<'a, S: ByteSink = VecSink, O: WorkObserver = NoopWorkObserver> {
    enc: &'a mut Encoder<S, O>,
    frame_index: usize,
}

impl<S: ByteSink, O: WorkObserver> ArrayEncoder<'_, S, O> {
    /// Report one completed cooperative projection work unit.
    ///
    /// This reports progress to the encoder's observer; it is not a resumable checkpoint.
    pub fn checkpoint(&mut self) -> EncodeResult<(), S> {
        self.enc.checkpoint()
    }

    fn remaining(&self) -> EncodeResult<usize, S> {
        match self.enc.stack.get(self.frame_index) {
            Some(Frame::Array { remaining }) => Ok(*remaining),
            _ => Err(format_error(
                ErrorCode::MalformedCanonical,
                self.enc.written,
            )),
        }
    }

    fn delegate<F>(&mut self, emit: F) -> EncodeResult<(), S>
    where
        F: FnOnce(&mut Encoder<S, O>) -> EncodeResult<(), S>,
    {
        emit(self.enc)
    }

    /// Encode null as the next item.
    pub fn null(&mut self) -> EncodeResult<(), S> {
        self.delegate(Encoder::null)
    }

    /// Encode a boolean as the next item.
    pub fn bool(&mut self, value: bool) -> EncodeResult<(), S> {
        self.delegate(|encoder| encoder.bool(value))
    }

    /// Encode an integer as the next item.
    pub fn int(&mut self, value: i64) -> EncodeResult<(), S> {
        self.delegate(|encoder| encoder.int(value))
    }

    /// Encode a bignum as the next item.
    pub fn bignum(&mut self, negative: bool, magnitude: &[u8]) -> EncodeResult<(), S> {
        self.delegate(|encoder| encoder.bignum(negative, magnitude))
    }

    /// Encode bytes as the next item.
    pub fn bytes(&mut self, bytes: &[u8]) -> EncodeResult<(), S> {
        self.delegate(|encoder| encoder.bytes(bytes))
    }

    /// Encode text as the next item.
    pub fn text(&mut self, text: &str) -> EncodeResult<(), S> {
        self.delegate(|encoder| encoder.text(text))
    }

    /// Encode a float as the next item.
    pub fn float(&mut self, bits: F64Bits) -> EncodeResult<(), S> {
        self.delegate(|encoder| encoder.float(bits))
    }

    /// Splice canonical bytes as the next item.
    pub fn raw_cbor(&mut self, value: CanonicalCborRef<'_>) -> EncodeResult<(), S> {
        self.delegate(|encoder| encoder.raw_cbor(value))
    }

    /// Splice a canonical sub-value as the next item.
    pub fn raw_value_ref(&mut self, value: CborValueRef<'_>) -> EncodeResult<(), S> {
        self.delegate(|encoder| encoder.raw_value_ref(value))
    }

    /// Emit exactly one item through a callback.
    pub fn value_with<F>(&mut self, emit: F) -> EncodeResult<(), S>
    where
        F: FnOnce(&mut Encoder<S, O>) -> EncodeResult<(), S>,
    {
        self.value_with_caller_error(emit)
    }

    /// Emit exactly one item while preserving a caller-defined error domain.
    ///
    /// The callback receives the underlying encoder for low-level composition. Any returned caller
    /// error, core error, or callback that emits other than one item poisons the encoder.
    pub fn value_with_caller_error<E, F>(&mut self, emit: F) -> Result<(), E>
    where
        E: From<EncodeError<S::Error>>,
        F: FnOnce(&mut Encoder<S, O>) -> Result<(), E>,
    {
        self.enc.ensure_healthy().map_err(E::from)?;
        let before = match self.remaining() {
            Ok(value) => value,
            Err(error) => {
                self.enc.poison();
                return Err(E::from(error));
            }
        };
        if before == 0 {
            self.enc.poison();
            return Err(E::from(format_error(
                ErrorCode::ArrayLenMismatch,
                self.enc.written,
            )));
        }
        if let Err(error) = emit(self.enc) {
            self.enc.poison();
            return Err(error);
        }
        self.enc.ensure_healthy().map_err(E::from)?;
        let after = match self.remaining() {
            Ok(value) => value,
            Err(error) => {
                self.enc.poison();
                return Err(E::from(error));
            }
        };
        if after.checked_add(1) != Some(before) {
            self.enc.poison();
            return Err(E::from(format_error(
                ErrorCode::ArrayLenMismatch,
                self.enc.written,
            )));
        }
        Ok(())
    }

    /// Encode a native value as the next item.
    pub fn value<T: CborEncode + ?Sized>(&mut self, value: &T) -> EncodeResult<(), S> {
        self.enc.encode(value)
    }

    /// Encode the next item through a controlled adapter.
    pub fn encode_with<F>(&mut self, emit: F) -> EncodeResult<(), S>
    where
        F: FnOnce(&mut ValueEncoder<'_, S, O>) -> EncodeResult<(), S>,
    {
        self.enc.encode_with(emit)
    }

    /// Encode exactly one item while preserving a caller-defined error domain.
    ///
    /// Any returned caller error or core encoding failure poisons the underlying encoder.
    pub fn encode_with_caller_error<E, F>(&mut self, emit: F) -> Result<(), E>
    where
        E: From<EncodeError<S::Error>>,
        F: FnOnce(&mut ValueEncoder<'_, S, O>) -> Result<(), E>,
    {
        self.enc.encode_with_caller_error(emit)
    }

    /// Encode a nested array.
    pub fn array<F>(&mut self, len: usize, build: F) -> EncodeResult<(), S>
    where
        F: FnOnce(&mut ArrayEncoder<'_, S, O>) -> EncodeResult<(), S>,
    {
        self.delegate(|encoder| encoder.array(len, build))
    }

    /// Encode a nested array while preserving a caller-defined error domain.
    ///
    /// Any returned caller error, declared-length mismatch, or core encoding failure poisons the
    /// underlying encoder.
    pub fn array_with_caller_error<E, F>(&mut self, len: usize, build: F) -> Result<(), E>
    where
        E: From<EncodeError<S::Error>>,
        F: FnOnce(&mut ArrayEncoder<'_, S, O>) -> Result<(), E>,
    {
        self.enc.array_with_caller_error(len, build)
    }

    /// Encode a nested map.
    pub fn map<F>(&mut self, len: usize, build: F) -> EncodeResult<(), S>
    where
        F: FnOnce(&mut MapEncoder<'_, S, O>) -> EncodeResult<(), S>,
    {
        self.delegate(|encoder| encoder.map(len, build))
    }
}

/// Builder for canonical text-keyed map entries.
pub struct MapEncoder<'a, S: ByteSink = VecSink, O: WorkObserver = NoopWorkObserver> {
    enc: &'a mut Encoder<S, O>,
    frame_index: usize,
    previous_key: String,
    has_previous_key: bool,
}

impl<S: ByteSink, O: WorkObserver> MapEncoder<'_, S, O> {
    /// Report one completed cooperative projection work unit.
    ///
    /// This reports progress to the encoder's observer; it is not a resumable checkpoint.
    pub fn checkpoint(&mut self) -> EncodeResult<(), S> {
        self.enc.checkpoint()
    }

    #[cfg(feature = "collections")]
    pub(crate) const fn offset(&self) -> usize {
        self.enc.written
    }

    fn remaining(&self) -> EncodeResult<(usize, bool), S> {
        match self.enc.stack.get(self.frame_index) {
            Some(Frame::Map {
                remaining_pairs,
                pending_value,
                ..
            }) => Ok((*remaining_pairs, *pending_value)),
            _ => Err(format_error(
                ErrorCode::MalformedCanonical,
                self.enc.written,
            )),
        }
    }

    fn write_entry<F>(&mut self, key: &str, value: F) -> EncodeResult<(), S>
    where
        F: FnOnce(&mut Encoder<S, O>) -> EncodeResult<(), S>,
    {
        let (before, pending) = self.remaining()?;
        if before == 0 || pending {
            return Err(format_error(ErrorCode::MapLenMismatch, self.enc.written));
        }
        self.enc.check_text_len(key.len())?;
        if self.has_previous_key {
            match cmp_text_keys_canonical(&self.previous_key, key) {
                Ordering::Less => {}
                Ordering::Equal => {
                    self.enc.poison();
                    return Err(format_error(ErrorCode::DuplicateMapKey, self.enc.written));
                }
                Ordering::Greater => {
                    self.enc.poison();
                    return Err(format_error(
                        ErrorCode::NonCanonicalMapOrder,
                        self.enc.written,
                    ));
                }
            }
        }
        self.enc.check_text_output(key)?;
        self.previous_key.clear();
        try_reserve_exact_str(&mut self.previous_key, key.len(), self.enc.written)
            .map_err(EncodeError::Cbor)?;
        self.enc.write_map_key_bytes(key)?;
        self.previous_key.push_str(key);
        self.has_previous_key = true;
        let start = self.enc.written;
        if let Err(error) = value(self.enc) {
            self.enc.poison();
            return Err(error);
        }
        self.enc.ensure_healthy()?;
        let (after, pending) = self.remaining()?;
        if pending || after.checked_add(1) != Some(before) {
            self.enc.poison();
            return Err(format_error(ErrorCode::MapLenMismatch, start));
        }
        Ok(())
    }

    /// Insert one entry. Keys must already arrive in canonical order.
    pub fn entry<F>(&mut self, key: &str, value: F) -> EncodeResult<(), S>
    where
        F: FnOnce(&mut Encoder<S, O>) -> EncodeResult<(), S>,
    {
        self.enc.ensure_healthy()?;
        let result = self.write_entry(key, value);
        if result.is_err() {
            self.enc.poison();
        }
        result
    }

    /// Insert an entry using a validated, pre-encoded text key.
    #[cfg(feature = "edit")]
    pub(crate) fn entry_raw_key<F>(
        &mut self,
        key: EncodedTextKey<'_>,
        value: F,
    ) -> EncodeResult<(), S>
    where
        F: FnOnce(&mut Encoder<S, O>) -> EncodeResult<(), S>,
    {
        self.enc.ensure_healthy()?;
        let result = self
            .enc
            .encoded_text_key_source(key.as_bytes())
            .and_then(|text| self.write_entry(text, value));
        if result.is_err() {
            self.enc.poison();
        }
        result
    }
}

#[cfg(feature = "edit")]
impl<O: WorkObserver> MapEncoder<'_, VecSink, O> {
    pub(crate) fn entry_cbor<F>(&mut self, key: &str, value: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut Encoder<VecSink, O>) -> Result<(), CborError>,
    {
        self.entry(key, |encoder| value(encoder).map_err(EncodeError::Cbor))
            .map_err(collapse_vec_error)
    }

    pub(crate) fn entry_raw_key_cbor<F>(
        &mut self,
        key: EncodedTextKey<'_>,
        value: F,
    ) -> Result<(), CborError>
    where
        F: FnOnce(&mut Encoder<VecSink, O>) -> Result<(), CborError>,
    {
        self.entry_raw_key(key, |encoder| value(encoder).map_err(EncodeError::Cbor))
            .map_err(collapse_vec_error)
    }
}

#[cfg(feature = "edit")]
#[allow(clippy::needless_pass_by_value)]
const fn collapse_vec_error(error: EncodeError<CborError>) -> CborError {
    match error {
        EncodeError::Cbor(error) | EncodeError::Sink(error) => error,
        EncodeError::Poisoned => CborError::new(ErrorCode::EncoderPoisoned, 0),
    }
}

#[cfg(feature = "edit")]
pub(crate) trait EmitValue {
    fn raw_value_ref(&mut self, value: CborValueRef<'_>) -> Result<(), CborError>;
    fn raw_cbor(&mut self, value: CanonicalCborRef<'_>) -> Result<(), CborError>;
    fn map<F>(&mut self, len: usize, build: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut MapEncoder<'_>) -> Result<(), CborError>;
    fn array<F>(&mut self, len: usize, build: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut ArrayEncoder<'_>) -> Result<(), CborError>;
}

#[cfg(feature = "edit")]
impl EmitValue for Encoder<VecSink> {
    fn raw_value_ref(&mut self, value: CborValueRef<'_>) -> Result<(), CborError> {
        Self::raw_value_ref(self, value).map_err(collapse_vec_error)
    }
    fn raw_cbor(&mut self, value: CanonicalCborRef<'_>) -> Result<(), CborError> {
        Self::raw_cbor(self, value).map_err(collapse_vec_error)
    }
    fn map<F>(&mut self, len: usize, build: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut MapEncoder<'_>) -> Result<(), CborError>,
    {
        Self::map(self, len, |map| build(map).map_err(EncodeError::Cbor))
            .map_err(collapse_vec_error)
    }
    fn array<F>(&mut self, len: usize, build: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut ArrayEncoder<'_>) -> Result<(), CborError>,
    {
        Self::array(self, len, |array| build(array).map_err(EncodeError::Cbor))
            .map_err(collapse_vec_error)
    }
}

#[cfg(feature = "edit")]
impl EmitValue for ArrayEncoder<'_> {
    fn raw_value_ref(&mut self, value: CborValueRef<'_>) -> Result<(), CborError> {
        ArrayEncoder::raw_value_ref(self, value).map_err(collapse_vec_error)
    }
    fn raw_cbor(&mut self, value: CanonicalCborRef<'_>) -> Result<(), CborError> {
        ArrayEncoder::raw_cbor(self, value).map_err(collapse_vec_error)
    }
    fn map<F>(&mut self, len: usize, build: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut MapEncoder<'_>) -> Result<(), CborError>,
    {
        ArrayEncoder::map(self, len, |map| build(map).map_err(EncodeError::Cbor))
            .map_err(collapse_vec_error)
    }
    fn array<F>(&mut self, len: usize, build: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut ArrayEncoder<'_>) -> Result<(), CborError>,
    {
        ArrayEncoder::array(self, len, |array| build(array).map_err(EncodeError::Cbor))
            .map_err(collapse_vec_error)
    }
}
