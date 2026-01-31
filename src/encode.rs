use crate::alloc_util::try_reserve;
use crate::canonical::{CanonicalCbor, CanonicalCborRef, EncodedTextKey};
use crate::codec::CborEncode;
use crate::profile::{check_encoded_key_order, validate_bignum_bytes, validate_int_safe_i64};
use crate::query::CborValueRef;
use crate::scalar::F64Bits;
use crate::{CborError, ErrorCode};
use alloc::vec::Vec;

trait Sink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), CborError>;

    fn write_u8(&mut self, byte: u8) -> Result<(), CborError> {
        self.write(&[byte])
    }

    fn position(&self) -> usize;
}

struct VecSink {
    buf: Vec<u8>,
}

impl VecSink {
    const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn with_capacity(capacity: usize) -> Self {
        let mut buf = Vec::new();
        let _ = buf.try_reserve(capacity);
        Self { buf }
    }

    fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    #[inline]
    fn reserve(&mut self, additional: usize) -> Result<(), CborError> {
        let available = self.buf.capacity().saturating_sub(self.buf.len());
        if additional <= available {
            return Ok(());
        }
        let offset = self.buf.len();
        try_reserve(&mut self.buf, additional, offset)
    }
}

impl Sink for VecSink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), CborError> {
        self.reserve(bytes.len())?;
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    fn write_u8(&mut self, byte: u8) -> Result<(), CborError> {
        if self.buf.len() == self.buf.capacity() {
            self.reserve(1)?;
        }
        self.buf.push(byte);
        Ok(())
    }

    fn position(&self) -> usize {
        self.buf.len()
    }
}

fn err_at<S: Sink>(sink: &S, code: ErrorCode) -> CborError {
    CborError::new(code, sink.position())
}

fn encode_int<S: Sink>(sink: &mut S, v: i64) -> Result<(), CborError> {
    if v >= 0 {
        let u = u64::try_from(v).map_err(|_| err_at(sink, ErrorCode::LengthOverflow))?;
        encode_major_uint(sink, 0, u)
    } else {
        let n_i128 = -1_i128 - i128::from(v);
        let n_u64 = u64::try_from(n_i128).map_err(|_| err_at(sink, ErrorCode::LengthOverflow))?;
        encode_major_uint(sink, 1, n_u64)
    }
}

fn encode_bytes<S: Sink>(sink: &mut S, bytes: &[u8]) -> Result<(), CborError> {
    encode_major_len(sink, 2, bytes.len())?;
    sink.write(bytes)
}

fn encode_text<S: Sink>(sink: &mut S, s: &str) -> Result<(), CborError> {
    // `str` guarantees valid UTF-8.
    let b = s.as_bytes();
    encode_major_len(sink, 3, b.len())?;
    sink.write(b)
}

fn encode_float64<S: Sink>(sink: &mut S, bits: F64Bits) -> Result<(), CborError> {
    let raw = bits.bits();
    let mut buf = [0u8; 9];
    buf[0] = 0xfb;
    buf[1..9].copy_from_slice(&raw.to_be_bytes());
    sink.write(&buf)
}

fn encode_major_len<S: Sink>(sink: &mut S, major: u8, len: usize) -> Result<(), CborError> {
    let len_u64 = u64::try_from(len).map_err(|_| err_at(sink, ErrorCode::LengthOverflow))?;
    encode_major_uint(sink, major, len_u64)
}

fn encode_major_uint<S: Sink>(sink: &mut S, major: u8, value: u64) -> Result<(), CborError> {
    debug_assert!(major <= 7);
    if value < 24 {
        let v = u8::try_from(value).unwrap();
        return sink.write_u8((major << 5) | v);
    }
    if value <= 0xff {
        let v = u8::try_from(value).unwrap();
        sink.write_u8((major << 5) | 24)?;
        return sink.write_u8(v);
    }
    if value <= 0xffff {
        let v = u16::try_from(value).unwrap();
        sink.write_u8((major << 5) | 25)?;
        return sink.write(&v.to_be_bytes());
    }
    if value <= 0xffff_ffff {
        let v = u32::try_from(value).unwrap();
        sink.write_u8((major << 5) | 26)?;
        return sink.write(&v.to_be_bytes());
    }
    sink.write_u8((major << 5) | 27)?;
    sink.write(&value.to_be_bytes())
}

/// Streaming encoder that writes canonical CBOR directly into a `Vec<u8>`.
///
/// This supports splicing validated canonical bytes.
pub struct Encoder {
    sink: VecSink,
    depth: usize,
    root_done: bool,
    root_end: usize,
}

impl Encoder {
    /// Create a new canonical encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sink: VecSink::new(),
            depth: 0,
            root_done: false,
            root_end: 0,
        }
    }

    /// Create a canonical encoder with pre-allocated capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            sink: VecSink::with_capacity(capacity),
            depth: 0,
            root_done: false,
            root_end: 0,
        }
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

    /// Consume and return the encoded bytes.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.sink.into_vec()
    }

    /// Consume and return canonical bytes as a `CanonicalCbor`.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer does not contain exactly one canonical CBOR item.
    pub fn into_canonical(self) -> Result<CanonicalCbor, CborError> {
        if self.depth != 0 {
            return Err(CborError::new(
                ErrorCode::UnexpectedEof,
                self.sink.position(),
            ));
        }
        if !self.root_done {
            return Err(CborError::new(ErrorCode::UnexpectedEof, 0));
        }
        Ok(CanonicalCbor::new_unchecked(self.into_vec()))
    }

    /// Clear the encoder while retaining allocated capacity.
    pub fn clear(&mut self) {
        self.sink.buf.clear();
        self.depth = 0;
        self.root_done = false;
        self.root_end = 0;
    }

    /// Borrow the bytes emitted so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.sink.buf
    }

    #[inline]
    const fn begin_value(&self) -> Result<bool, CborError> {
        if self.depth == 0 {
            if self.root_done {
                return Err(CborError::new(ErrorCode::TrailingBytes, self.root_end));
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    #[inline]
    fn finish_value(&mut self, root: bool) {
        if root {
            self.root_done = true;
            self.root_end = self.sink.position();
        }
    }

    #[inline]
    fn enter_container(&mut self) {
        self.depth = self.depth.saturating_add(1);
    }

    #[inline]
    fn exit_container(&mut self) {
        debug_assert!(self.depth > 0);
        self.depth = self.depth.saturating_sub(1);
    }

    #[cfg(feature = "serde")]
    #[inline]
    pub(crate) const fn in_container(&self) -> bool {
        self.depth != 0
    }

    #[cfg(feature = "serde")]
    #[inline]
    pub(crate) fn finish_container(&mut self, root: bool) {
        self.exit_container();
        self.finish_value(root);
    }

    #[cfg(feature = "serde")]
    #[inline]
    pub(crate) fn abort_container(&mut self) {
        self.exit_container();
    }

    #[inline]
    pub(crate) fn emit_null(&mut self) -> Result<(), CborError> {
        self.sink.write_u8(0xf6)
    }

    #[inline]
    pub(crate) fn emit_bool(&mut self, v: bool) -> Result<(), CborError> {
        self.sink.write_u8(if v { 0xf5 } else { 0xf4 })
    }

    #[inline]
    pub(crate) fn emit_int(&mut self, v: i64) -> Result<(), CborError> {
        validate_int_safe_i64(v).map_err(|code| CborError::new(code, self.sink.position()))?;
        encode_int(&mut self.sink, v)
    }

    #[cfg(feature = "serde")]
    #[inline]
    pub(crate) fn emit_int_u128(&mut self, v: u128) -> Result<(), CborError> {
        let safe_max = u128::from(crate::profile::MAX_SAFE_INTEGER);
        if v <= safe_max {
            let i = i64::try_from(v)
                .map_err(|_| CborError::new(ErrorCode::LengthOverflow, self.sink.position()))?;
            return self.emit_int(i);
        }

        let magnitude = crate::int::magnitude_from_u128(v)
            .map_err(|code| CborError::new(code, self.sink.position()))?;
        self.emit_bignum(false, &magnitude)
    }

    #[cfg(feature = "serde")]
    #[inline]
    pub(crate) fn emit_int_i128(&mut self, v: i128) -> Result<(), CborError> {
        let min = i128::from(crate::profile::MIN_SAFE_INTEGER);
        let max = i128::from(crate::profile::MAX_SAFE_INTEGER_I64);

        if v >= min && v <= max {
            let i = i64::try_from(v)
                .map_err(|_| CborError::new(ErrorCode::LengthOverflow, self.sink.position()))?;
            return self.emit_int(i);
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
        self.emit_bignum(negative, &magnitude)
    }

    #[inline]
    pub(crate) fn emit_bignum(
        &mut self,
        negative: bool,
        magnitude: &[u8],
    ) -> Result<(), CborError> {
        validate_bignum_bytes(negative, magnitude)
            .map_err(|code| CborError::new(code, self.sink.position()))?;
        let tag = if negative { 3u64 } else { 2u64 };
        encode_major_uint(&mut self.sink, 6, tag)?;
        encode_bytes(&mut self.sink, magnitude)
    }

    #[inline]
    pub(crate) fn emit_bytes(&mut self, b: &[u8]) -> Result<(), CborError> {
        encode_bytes(&mut self.sink, b)
    }

    #[inline]
    pub(crate) fn emit_text(&mut self, s: &str) -> Result<(), CborError> {
        encode_text(&mut self.sink, s)
    }

    #[inline]
    pub(crate) fn emit_float(&mut self, bits: F64Bits) -> Result<(), CborError> {
        encode_float64(&mut self.sink, bits)
    }

    #[inline]
    pub(crate) fn emit_raw_cbor(&mut self, v: CanonicalCborRef<'_>) -> Result<(), CborError> {
        self.sink.write(v.as_bytes())
    }

    #[inline]
    pub(crate) fn emit_raw_value_ref(&mut self, v: CborValueRef<'_>) -> Result<(), CborError> {
        self.sink.write(v.as_bytes())
    }

    #[cfg(feature = "serde")]
    pub(crate) fn buf_len(&self) -> usize {
        self.sink.buf.len()
    }

    #[cfg(feature = "serde")]
    pub(crate) fn truncate(&mut self, len: usize) {
        self.sink.buf.truncate(len);
    }

    /// Encode CBOR null.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying buffer fails.
    pub fn null(&mut self) -> Result<(), CborError> {
        let root = self.begin_value()?;
        self.emit_null()?;
        self.finish_value(root);
        Ok(())
    }

    /// Encode a CBOR boolean.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying buffer fails.
    pub fn bool(&mut self, v: bool) -> Result<(), CborError> {
        let root = self.begin_value()?;
        self.emit_bool(v)?;
        self.finish_value(root);
        Ok(())
    }

    /// Encode a safe-range integer.
    ///
    /// # Errors
    ///
    /// Returns an error if the integer is outside the safe range or if encoding fails.
    pub fn int(&mut self, v: i64) -> Result<(), CborError> {
        let root = self.begin_value()?;
        self.emit_int(v)?;
        self.finish_value(root);
        Ok(())
    }

    /// Encode an unsigned integer, using a bignum when outside the safe range.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails or allocation for the bignum magnitude fails.
    pub fn int_u128(&mut self, v: u128) -> Result<(), CborError> {
        let safe_max = u128::from(crate::profile::MAX_SAFE_INTEGER);
        if v <= safe_max {
            let i = i64::try_from(v)
                .map_err(|_| CborError::new(ErrorCode::LengthOverflow, self.sink.position()))?;
            return self.int(i);
        }

        let magnitude = crate::int::magnitude_from_u128(v)
            .map_err(|code| CborError::new(code, self.sink.position()))?;
        self.bignum(false, &magnitude)
    }

    /// Encode a signed integer, using a bignum when outside the safe range.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails or allocation for the bignum magnitude fails.
    pub fn int_i128(&mut self, v: i128) -> Result<(), CborError> {
        let min = i128::from(crate::profile::MIN_SAFE_INTEGER);
        let max = i128::from(crate::profile::MAX_SAFE_INTEGER_I64);

        if v >= min && v <= max {
            let i = i64::try_from(v)
                .map_err(|_| CborError::new(ErrorCode::LengthOverflow, self.sink.position()))?;
            return self.int(i);
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
        self.bignum(negative, &magnitude)
    }

    /// Encode a CBOR bignum (tag 2/3 + byte string magnitude).
    ///
    /// # Errors
    ///
    /// Returns an error if the magnitude is not canonical or if encoding fails.
    pub fn bignum(&mut self, negative: bool, magnitude: &[u8]) -> Result<(), CborError> {
        let root = self.begin_value()?;
        self.emit_bignum(negative, magnitude)?;
        self.finish_value(root);
        Ok(())
    }

    /// Encode a byte string.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn bytes(&mut self, b: &[u8]) -> Result<(), CborError> {
        let root = self.begin_value()?;
        self.emit_bytes(b)?;
        self.finish_value(root);
        Ok(())
    }

    /// Encode a text string.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn text(&mut self, s: &str) -> Result<(), CborError> {
        let root = self.begin_value()?;
        self.emit_text(s)?;
        self.finish_value(root);
        Ok(())
    }

    /// Encode a float64 bit pattern.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn float(&mut self, bits: F64Bits) -> Result<(), CborError> {
        let root = self.begin_value()?;
        self.emit_float(bits)?;
        self.finish_value(root);
        Ok(())
    }

    /// Splice already validated canonical CBOR bytes as the next value.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying buffer fails.
    pub fn raw_cbor(&mut self, v: CanonicalCborRef<'_>) -> Result<(), CborError> {
        let root = self.begin_value()?;
        self.emit_raw_cbor(v)?;
        self.finish_value(root);
        Ok(())
    }

    /// Splice a canonical sub-value reference.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying buffer fails.
    pub fn raw_value_ref(&mut self, v: CborValueRef<'_>) -> Result<(), CborError> {
        let root = self.begin_value()?;
        self.emit_raw_value_ref(v)?;
        self.finish_value(root);
        Ok(())
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
        let root = self.begin_value()?;
        let start = self.sink.buf.len();
        if let Err(err) = encode_major_len(&mut self.sink, 4, len) {
            self.sink.buf.truncate(start);
            return Err(err);
        }
        if let Err(err) = self.reserve_min_array_items(len) {
            self.sink.buf.truncate(start);
            return Err(err);
        }
        self.enter_container();
        let (res, remaining) = {
            let mut a = ArrayEncoder {
                enc: self,
                remaining: len,
            };
            let res = f(&mut a);
            (res, a.remaining)
        };
        self.exit_container();
        if let Err(err) = res {
            self.sink.buf.truncate(start);
            return Err(err);
        }
        if remaining != 0 {
            let err = CborError::new(ErrorCode::ArrayLenMismatch, self.sink.position());
            self.sink.buf.truncate(start);
            return Err(err);
        }
        self.finish_value(root);
        Ok(())
    }

    #[cfg(feature = "serde")]
    pub(crate) fn array_header(&mut self, len: usize) -> Result<bool, CborError> {
        let root = self.begin_value()?;
        encode_major_len(&mut self.sink, 4, len)?;
        self.reserve_min_array_items(len)?;
        self.enter_container();
        Ok(root)
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
        let root = self.begin_value()?;
        let start = self.sink.buf.len();
        if let Err(err) = encode_major_len(&mut self.sink, 5, len) {
            self.sink.buf.truncate(start);
            return Err(err);
        }
        if let Err(err) = self.reserve_min_map_items(len) {
            self.sink.buf.truncate(start);
            return Err(err);
        }
        self.enter_container();
        let (res, remaining) = {
            let mut m = MapEncoder {
                enc: self,
                remaining: len,
                prev_key_range: None,
            };
            let res = f(&mut m);
            (res, m.remaining)
        };
        self.exit_container();
        if let Err(err) = res {
            self.sink.buf.truncate(start);
            return Err(err);
        }
        if remaining != 0 {
            let err = CborError::new(ErrorCode::MapLenMismatch, self.sink.position());
            self.sink.buf.truncate(start);
            return Err(err);
        }
        self.finish_value(root);
        Ok(())
    }

    #[cfg(feature = "serde")]
    pub(crate) fn map_header(&mut self, len: usize) -> Result<bool, CborError> {
        let root = self.begin_value()?;
        encode_major_len(&mut self.sink, 5, len)?;
        self.reserve_min_map_items(len)?;
        self.enter_container();
        Ok(root)
    }

    /// Internal hook used by `cbor_bytes!` for `$expr` values.
    #[doc(hidden)]
    #[allow(missing_docs)]
    pub fn __encode_any<T>(&mut self, v: T) -> Result<(), CborError>
    where
        T: crate::__cbor_macro::IntoCborBytes,
    {
        crate::__cbor_macro::IntoCborBytes::into_cbor_bytes(v, self)
    }

    fn reserve_min_array_items(&mut self, len: usize) -> Result<(), CborError> {
        if len == 0 {
            return Ok(());
        }
        self.sink.reserve(len)
    }

    fn reserve_min_map_items(&mut self, len: usize) -> Result<(), CborError> {
        if len == 0 {
            return Ok(());
        }
        let items = len
            .checked_mul(2)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, self.sink.position()))?;
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
    remaining: usize,
}

#[allow(missing_docs)]
impl ArrayEncoder<'_> {
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

    /// Encode CBOR null.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn null(&mut self) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.emit_null()
    }

    /// Encode a CBOR boolean.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn bool(&mut self, v: bool) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.emit_bool(v)
    }

    /// Encode a safe-range integer.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn int(&mut self, v: i64) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.emit_int(v)
    }

    /// Encode a CBOR bignum (tag 2/3 + byte string magnitude).
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn bignum(&mut self, negative: bool, magnitude: &[u8]) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.emit_bignum(negative, magnitude)
    }

    /// Encode a byte string.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn bytes(&mut self, b: &[u8]) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.emit_bytes(b)
    }

    /// Encode a text string.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn text(&mut self, s: &str) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.emit_text(s)
    }

    /// Encode a float64 bit pattern.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn float(&mut self, bits: F64Bits) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.emit_float(bits)
    }

    /// Splice canonical CBOR bytes as the next array element.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn raw_cbor(&mut self, v: CanonicalCborRef<'_>) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.emit_raw_cbor(v)
    }

    /// Splice a canonical sub-value reference as the next array element.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn raw_value_ref(&mut self, v: CborValueRef<'_>) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.emit_raw_value_ref(v)
    }

    /// Encode a value using the native `CborEncode` trait.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn value<T: CborEncode>(&mut self, value: &T) -> Result<(), CborError> {
        self.consume_one()?;
        value.encode(self.enc)
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
        self.consume_one()?;
        self.enc.array(len, f)
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
        self.consume_one()?;
        self.enc.map(len, f)
    }

    #[doc(hidden)]
    #[allow(missing_docs)]
    pub fn __encode_any<T>(&mut self, v: T) -> Result<(), CborError>
    where
        T: crate::__cbor_macro::IntoCborBytes,
    {
        self.consume_one()?;
        crate::__cbor_macro::IntoCborBytes::into_cbor_bytes(v, self.enc)
    }
}

/// Builder for writing map entries into a canonical CBOR stream.
pub struct MapEncoder<'a> {
    enc: &'a mut Encoder,
    remaining: usize,
    prev_key_range: Option<(usize, usize)>,
}

#[allow(missing_docs)]
impl MapEncoder<'_> {
    fn write_entry<K, F>(&mut self, write_key: K, f: F) -> Result<(), CborError>
    where
        K: FnOnce(&mut VecSink) -> Result<(), CborError>,
        F: FnOnce(&mut Encoder) -> Result<(), CborError>,
    {
        if self.remaining == 0 {
            return Err(CborError::new(
                ErrorCode::MapLenMismatch,
                self.enc.sink.position(),
            ));
        }

        let entry_start = self.enc.sink.buf.len();
        let (key_start, key_end) = self.write_key(entry_start, write_key)?;
        self.enforce_key_order(entry_start, key_start, key_end)?;
        let res = f(self.enc);
        self.finish_entry(entry_start, key_start, key_end, res)
    }

    fn enforce_key_order(
        &mut self,
        entry_start: usize,
        key_start: usize,
        key_end: usize,
    ) -> Result<(), CborError> {
        if let Some((ps, pe)) = self.prev_key_range {
            let prev = &self.enc.sink.buf[ps..pe];
            let curr = &self.enc.sink.buf[key_start..key_end];
            if let Err(code) = check_encoded_key_order(prev, curr) {
                return self.fail_entry(entry_start, CborError::new(code, key_start));
            }
        }
        Ok(())
    }

    fn finish_entry(
        &mut self,
        entry_start: usize,
        key_start: usize,
        key_end: usize,
        res: Result<(), CborError>,
    ) -> Result<(), CborError> {
        if let Err(err) = res {
            return self.fail_entry(entry_start, err);
        }
        self.prev_key_range = Some((key_start, key_end));
        self.remaining -= 1;
        Ok(())
    }

    fn write_key<F>(&mut self, entry_start: usize, write: F) -> Result<(usize, usize), CborError>
    where
        F: FnOnce(&mut VecSink) -> Result<(), CborError>,
    {
        if let Err(err) = write(&mut self.enc.sink) {
            return self.fail_entry(entry_start, err);
        }
        Ok((entry_start, self.enc.sink.buf.len()))
    }

    fn fail_entry<T>(&mut self, entry_start: usize, err: CborError) -> Result<T, CborError> {
        self.enc.sink.buf.truncate(entry_start);
        Err(err)
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
        self.write_entry(|sink| encode_text(sink, key), f)
    }

    /// Insert a map entry using a pre-encoded canonical text key.
    ///
    /// This avoids re-encoding keys when splicing from validated canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails, if keys are out of order, or if duplicates are found.
    pub fn entry_raw_key<F>(&mut self, key: EncodedTextKey<'_>, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut Encoder) -> Result<(), CborError>,
    {
        let key_bytes = key.as_bytes();
        self.write_entry(|sink| sink.write(key_bytes), f)
    }
}
