use crate::canonical::{CanonicalCbor, CanonicalCborRef};
use crate::profile::{
    is_strictly_increasing_encoded, validate_bignum_bytes, validate_int_safe_i64,
};
use crate::query::CborValueRef;
use crate::scalar::F64Bits;
use crate::value::{BigInt, CborInteger, CborValue, ValueRepr};
use crate::{CborError, ErrorCode};
use alloc::vec::Vec;

#[derive(Clone, Copy)]
enum Frame<'a> {
    Value(&'a CborValue),
    TextKey(&'a str),
}

struct SmallStack<'a, const N: usize> {
    inline: [Option<Frame<'a>>; N],
    len: usize,
    overflow: Vec<Frame<'a>>,
}

impl<'a, const N: usize> SmallStack<'a, N> {
    const fn new() -> Self {
        Self {
            inline: [None; N],
            len: 0,
            overflow: Vec::new(),
        }
    }

    fn push(&mut self, frame: Frame<'a>) {
        if !self.overflow.is_empty() {
            self.overflow.push(frame);
            return;
        }
        if self.len < N {
            self.inline[self.len] = Some(frame);
            self.len += 1;
        } else {
            self.overflow.push(frame);
        }
    }

    fn pop(&mut self) -> Option<Frame<'a>> {
        if let Some(frame) = self.overflow.pop() {
            return Some(frame);
        }
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        self.inline[self.len].take()
    }
}

pub fn encode_to_vec(value: &CborValue) -> Result<Vec<u8>, CborError> {
    let mut sink = VecSink::new();
    encode_value(&mut sink, value)?;
    Ok(sink.into_vec())
}

#[cfg(feature = "sha2")]
pub fn encode_sha256(value: &CborValue) -> Result<[u8; 32], CborError> {
    use sha2::{Digest, Sha256};

    let mut sink = HashSink::new(Sha256::new());
    encode_value(&mut sink, value)?;
    let out = sink.hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(out.as_slice());
    Ok(digest)
}

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

    fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    fn reserve(&mut self, additional: usize) -> Result<(), CborError> {
        self.buf
            .try_reserve(additional)
            .map_err(|_| CborError::new(ErrorCode::AllocationFailed, self.buf.len()))?;
        Ok(())
    }
}

impl Sink for VecSink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), CborError> {
        self.reserve(bytes.len())?;
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    fn write_u8(&mut self, byte: u8) -> Result<(), CborError> {
        self.reserve(1)?;
        self.buf.push(byte);
        Ok(())
    }

    fn position(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(feature = "sha2")]
struct HashSink<D> {
    hasher: D,
    len: usize,
}

#[cfg(feature = "sha2")]
impl<D> HashSink<D> {
    const fn new(hasher: D) -> Self {
        Self { hasher, len: 0 }
    }
}

#[cfg(feature = "sha2")]
impl<D: sha2::Digest> Sink for HashSink<D> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), CborError> {
        self.hasher.update(bytes);
        self.len = self
            .len
            .checked_add(bytes.len())
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, self.len))?;
        Ok(())
    }

    fn position(&self) -> usize {
        self.len
    }
}

fn encode_value<S: Sink>(sink: &mut S, value: &CborValue) -> Result<(), CborError> {
    let mut stack = SmallStack::<64>::new();
    stack.push(Frame::Value(value));

    while let Some(frame) = stack.pop() {
        match frame {
            Frame::TextKey(key) => {
                encode_text(sink, key)?;
            }
            Frame::Value(v) => match v.repr() {
                ValueRepr::Integer(i) => encode_integer(sink, i)?,
                ValueRepr::Bytes(b) => encode_bytes(sink, b)?,
                ValueRepr::Text(s) => encode_text(sink, s)?,
                ValueRepr::Array(items) => {
                    encode_major_len(sink, 4, items.len())?;
                    for item in items.iter().rev() {
                        stack.push(Frame::Value(item));
                    }
                }
                ValueRepr::Map(map) => {
                    encode_major_len(sink, 5, map.len())?;
                    for (k, v) in map.entries().iter().rev() {
                        stack.push(Frame::Value(v));
                        stack.push(Frame::TextKey(k));
                    }
                }
                ValueRepr::Bool(false) => sink.write_u8(0xf4)?,
                ValueRepr::Bool(true) => sink.write_u8(0xf5)?,
                ValueRepr::Null => sink.write_u8(0xf6)?,
                ValueRepr::Float(bits) => encode_float64(sink, *bits)?,
            },
        }
    }
    Ok(())
}

fn err_at<S: Sink>(sink: &S, code: ErrorCode) -> CborError {
    CborError::new(code, sink.position())
}

fn encode_integer<S: Sink>(sink: &mut S, value: &CborInteger) -> Result<(), CborError> {
    if let Some(v) = value.as_i64() {
        return encode_int(sink, v);
    }
    let b = value
        .as_bigint()
        .ok_or_else(|| err_at(sink, ErrorCode::LengthOverflow))?;
    encode_bignum(sink, b)
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

fn encode_bignum<S: Sink>(sink: &mut S, b: &BigInt) -> Result<(), CborError> {
    let tag = if b.is_negative() { 3u64 } else { 2u64 };
    encode_major_uint(sink, 6, tag)?;
    encode_bytes(sink, b.magnitude())
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
    if let Ok(v8) = u8::try_from(value) {
        if v8 < 24 {
            return sink.write_u8((major << 5) | v8);
        }
        sink.write_u8((major << 5) | 24)?;
        return sink.write_u8(v8);
    }
    if let Ok(v16) = u16::try_from(value) {
        sink.write_u8((major << 5) | 25)?;
        return sink.write(&v16.to_be_bytes());
    }
    if let Ok(v32) = u32::try_from(value) {
        sink.write_u8((major << 5) | 26)?;
        return sink.write(&v32.to_be_bytes());
    }
    sink.write_u8((major << 5) | 27)?;
    sink.write(&value.to_be_bytes())
}

/// Streaming encoder that writes canonical CBOR directly into a `Vec<u8>`.
///
/// This avoids building a `CborValue` tree and supports splicing validated canonical bytes.
pub struct CanonicalEncoder {
    sink: VecSink,
}

impl CanonicalEncoder {
    /// Create a new canonical encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sink: VecSink::new(),
        }
    }

    /// Consume and return the encoded bytes.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.sink.into_vec()
    }

    /// Consume and return canonical bytes as a `CanonicalCbor`.
    #[must_use]
    pub fn into_canonical(self) -> CanonicalCbor {
        CanonicalCbor::new_unchecked(self.into_vec())
    }

    /// Borrow the bytes emitted so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.sink.buf
    }

    /// Encode CBOR null.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying buffer fails.
    pub fn null(&mut self) -> Result<(), CborError> {
        self.sink.write_u8(0xf6)
    }

    /// Encode a CBOR boolean.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying buffer fails.
    pub fn bool(&mut self, v: bool) -> Result<(), CborError> {
        self.sink.write_u8(if v { 0xf5 } else { 0xf4 })
    }

    /// Encode a safe-range integer.
    ///
    /// # Errors
    ///
    /// Returns an error if the integer is outside the safe range or if encoding fails.
    pub fn int(&mut self, v: i64) -> Result<(), CborError> {
        validate_int_safe_i64(v).map_err(|code| CborError::new(code, self.sink.position()))?;
        encode_int(&mut self.sink, v)
    }

    /// Encode a CBOR bignum (tag 2/3 + byte string magnitude).
    ///
    /// # Errors
    ///
    /// Returns an error if the magnitude is not canonical or if encoding fails.
    pub fn bignum(&mut self, negative: bool, magnitude: &[u8]) -> Result<(), CborError> {
        validate_bignum_bytes(negative, magnitude)
            .map_err(|code| CborError::new(code, self.sink.position()))?;
        let tag = if negative { 3u64 } else { 2u64 };
        encode_major_uint(&mut self.sink, 6, tag)?;
        encode_bytes(&mut self.sink, magnitude)
    }

    /// Encode a byte string.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn bytes(&mut self, b: &[u8]) -> Result<(), CborError> {
        encode_bytes(&mut self.sink, b)
    }

    /// Encode a text string.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn text(&mut self, s: &str) -> Result<(), CborError> {
        encode_text(&mut self.sink, s)
    }

    /// Encode a float64 bit pattern.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn float(&mut self, bits: F64Bits) -> Result<(), CborError> {
        encode_float64(&mut self.sink, bits)
    }

    /// Encode an existing `CborValue`.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn value(&mut self, v: &CborValue) -> Result<(), CborError> {
        encode_value(&mut self.sink, v)
    }

    /// Splice already validated canonical CBOR bytes as the next value.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying buffer fails.
    pub fn raw_cbor(&mut self, v: CanonicalCborRef<'_>) -> Result<(), CborError> {
        self.sink.write(v.as_bytes())
    }

    /// Splice a canonical sub-value reference.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying buffer fails.
    pub fn raw_value_ref(&mut self, v: CborValueRef<'_>) -> Result<(), CborError> {
        self.sink.write(v.as_bytes())
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
        encode_major_len(&mut self.sink, 4, len)?;
        let mut a = ArrayEncoder {
            enc: self,
            remaining: len,
        };
        f(&mut a)?;
        if a.remaining != 0 {
            return Err(CborError::new(
                ErrorCode::ArrayLenMismatch,
                self.sink.position(),
            ));
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
        encode_major_len(&mut self.sink, 5, len)?;
        let mut m = MapEncoder {
            enc: self,
            remaining: len,
            prev_key_range: None,
        };
        f(&mut m)?;
        if m.remaining != 0 {
            return Err(CborError::new(
                ErrorCode::MapLenMismatch,
                self.sink.position(),
            ));
        }
        Ok(())
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
}

impl Default for CanonicalEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for writing array elements into a canonical CBOR stream.
pub struct ArrayEncoder<'a> {
    enc: &'a mut CanonicalEncoder,
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
        self.enc.null()
    }

    /// Encode a CBOR boolean.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn bool(&mut self, v: bool) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.bool(v)
    }

    /// Encode a safe-range integer.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn int(&mut self, v: i64) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.int(v)
    }

    /// Encode a CBOR bignum (tag 2/3 + byte string magnitude).
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn bignum(&mut self, negative: bool, magnitude: &[u8]) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.bignum(negative, magnitude)
    }

    /// Encode a byte string.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn bytes(&mut self, b: &[u8]) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.bytes(b)
    }

    /// Encode a text string.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn text(&mut self, s: &str) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.text(s)
    }

    /// Encode a float64 bit pattern.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn float(&mut self, bits: F64Bits) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.float(bits)
    }

    /// Encode an existing `CborValue`.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn value(&mut self, v: &CborValue) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.value(v)
    }

    /// Splice canonical CBOR bytes as the next array element.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn raw_cbor(&mut self, v: CanonicalCborRef<'_>) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.raw_cbor(v)
    }

    /// Splice a canonical sub-value reference as the next array element.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length is exceeded or if encoding fails.
    pub fn raw_value_ref(&mut self, v: CborValueRef<'_>) -> Result<(), CborError> {
        self.consume_one()?;
        self.enc.raw_value_ref(v)
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
    enc: &'a mut CanonicalEncoder,
    remaining: usize,
    prev_key_range: Option<(usize, usize)>,
}

#[allow(missing_docs)]
impl MapEncoder<'_> {
    /// Insert a map entry. Keys must be in canonical order; duplicates are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails, if keys are out of order, or if duplicates are found.
    pub fn entry<F>(&mut self, key: &str, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut CanonicalEncoder) -> Result<(), CborError>,
    {
        if self.remaining == 0 {
            return Err(CborError::new(
                ErrorCode::MapLenMismatch,
                self.enc.sink.position(),
            ));
        }

        let entry_start = self.enc.sink.buf.len();
        encode_text(&mut self.enc.sink, key).map_err(|err| {
            self.enc.sink.buf.truncate(entry_start);
            err
        })?;
        let key_start = entry_start;
        let key_end = self.enc.sink.buf.len();

        if let Some((ps, pe)) = self.prev_key_range {
            let prev = &self.enc.sink.buf[ps..pe];
            let curr = &self.enc.sink.buf[key_start..key_end];

            if prev == curr {
                self.enc.sink.buf.truncate(entry_start);
                return Err(CborError::new(ErrorCode::DuplicateMapKey, key_start));
            }
            if !is_strictly_increasing_encoded(prev, curr) {
                self.enc.sink.buf.truncate(entry_start);
                return Err(CborError::new(ErrorCode::NonCanonicalMapOrder, key_start));
            }
        }

        let res = f(self.enc);
        if let Err(err) = res {
            self.enc.sink.buf.truncate(entry_start);
            return Err(err);
        }
        self.prev_key_range = Some((key_start, key_end));
        self.remaining -= 1;
        Ok(())
    }
}
