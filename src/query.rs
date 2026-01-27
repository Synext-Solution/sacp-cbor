//! Query support for canonical CBOR messages.
//!
//! This module provides a lightweight, allocation-free query engine for
//! [`CborBytesRef`](crate::CborBytesRef). Queries return borrowed views
//! ([`CborValueRef`]) pointing into the original message bytes.
//!
//! The query layer assumes the input bytes are already validated as canonical via
//! [`validate_canonical`](crate::validate_canonical). If invariants are violated,
//! APIs may return [`ErrorCode::MalformedCanonical`].

use core::cmp::Ordering;

use crate::canonical::CborBytesRef;
use crate::parse;
use crate::profile::{checked_text_len, cmp_text_keys_by_canonical_encoding};
use crate::stream::CborStream;
use crate::{CborError, ErrorCode};

#[cfg(feature = "alloc")]
use crate::canonical::CborBytes;

#[cfg(feature = "alloc")]
use crate::value::{CborMap, CborValue};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// The CBOR data model supported by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborKind {
    /// Major type 0/1 (safe-range) or tag 2/3 bignum.
    Integer,
    /// Major type 2.
    Bytes,
    /// Major type 3.
    Text,
    /// Major type 4.
    Array,
    /// Major type 5 (text keys only).
    Map,
    /// Simple value true/false.
    Bool,
    /// Simple value null.
    Null,
    /// IEEE-754 float64 (major 7, ai 27).
    Float,
}

const fn err(code: ErrorCode, offset: usize) -> CborError {
    CborError::new(code, offset)
}

const fn malformed(offset: usize) -> CborError {
    err(ErrorCode::MalformedCanonical, offset)
}

const fn expected_map(offset: usize) -> CborError {
    err(ErrorCode::ExpectedMap, offset)
}

const fn expected_array(offset: usize) -> CborError {
    err(ErrorCode::ExpectedArray, offset)
}

const fn expected_integer(offset: usize) -> CborError {
    err(ErrorCode::ExpectedInteger, offset)
}

const fn expected_text(offset: usize) -> CborError {
    err(ErrorCode::ExpectedText, offset)
}

const fn expected_bytes(offset: usize) -> CborError {
    err(ErrorCode::ExpectedBytes, offset)
}

const fn expected_bool(offset: usize) -> CborError {
    err(ErrorCode::ExpectedBool, offset)
}

const fn expected_float(offset: usize) -> CborError {
    err(ErrorCode::ExpectedFloat, offset)
}

const fn missing_key(offset: usize) -> CborError {
    err(ErrorCode::MissingKey, offset)
}

/// A path element for navigating inside a CBOR value.
///
/// The query engine supports map keys (text) and array indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathElem<'p> {
    /// Select a text key from a CBOR map.
    Key(&'p str),
    /// Select an index from a CBOR array.
    Index(usize),
}

impl<'p> From<&'p str> for PathElem<'p> {
    fn from(key: &'p str) -> Self {
        Self::Key(key)
    }
}

impl From<usize> for PathElem<'_> {
    fn from(index: usize) -> Self {
        Self::Index(index)
    }
}

/// A borrowed view of a CBOR bignum (tag 2 / tag 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BigIntRef<'a> {
    negative: bool,
    magnitude: &'a [u8],
}

impl<'a> BigIntRef<'a> {
    /// Returns whether the bignum is negative (tag 3).
    #[must_use]
    pub const fn is_negative(self) -> bool {
        self.negative
    }

    /// Returns the big-endian magnitude bytes.
    #[must_use]
    pub const fn magnitude(self) -> &'a [u8] {
        self.magnitude
    }
}

/// A borrowed view of an integer (safe or bignum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborIntegerRef<'a> {
    /// Safe-range integer (major 0/1).
    Safe(i64),
    /// Bignum integer (tag 2/3).
    Big(BigIntRef<'a>),
}

impl<'a> CborIntegerRef<'a> {
    /// Return the safe integer value, if present.
    #[must_use]
    pub const fn as_i64(self) -> Option<i64> {
        match self {
            Self::Safe(v) => Some(v),
            Self::Big(_) => None,
        }
    }

    /// Return the bignum reference, if present.
    #[must_use]
    pub const fn as_bigint(self) -> Option<BigIntRef<'a>> {
        match self {
            Self::Safe(_) => None,
            Self::Big(b) => Some(b),
        }
    }
}

/// A borrowed view into a canonical CBOR message.
///
/// The view carries the full message bytes plus a `(start, end)` range for the
/// current value. All nested values returned from queries keep referencing the
/// original message bytes.
#[derive(Debug, Clone, Copy)]
pub struct CborValueRef<'a> {
    data: &'a [u8],
    start: usize,
    end: usize,
}

#[allow(clippy::elidable_lifetime_names)]
impl<'a> CborValueRef<'a> {
    #[inline]
    const fn new(data: &'a [u8], start: usize, end: usize) -> Self {
        Self { data, start, end }
    }

    /// Returns the raw bytes (canonical CBOR encoding) for this value.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        // Invariants are guaranteed by construction from validated canonical bytes.
        &self.data[self.start..self.end]
    }

    /// Returns the starting offset (in bytes) of this value within the message.
    #[must_use]
    pub const fn offset(self) -> usize {
        self.start
    }

    /// Returns the byte length of this value's canonical encoding.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Returns whether this value's canonical encoding is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start >= self.end
    }

    /// Returns the kind of this value.
    ///
    /// # Errors
    ///
    /// Returns `CborError` if the underlying bytes are malformed.
    pub fn kind(self) -> Result<CborKind, CborError> {
        let mut s = CborStream::new(self.data, self.start);
        let off = self.start;
        let ib = read_u8(&mut s)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        match major {
            0 | 1 => Ok(CborKind::Integer),
            2 => Ok(CborKind::Bytes),
            3 => Ok(CborKind::Text),
            4 => Ok(CborKind::Array),
            5 => Ok(CborKind::Map),
            6 => {
                let tag = read_uint_arg(&mut s, ai, off)?;
                match tag {
                    2 | 3 => Ok(CborKind::Integer),
                    _ => Err(malformed(off)),
                }
            }
            7 => match ai {
                20 | 21 => Ok(CborKind::Bool),
                22 => Ok(CborKind::Null),
                27 => Ok(CborKind::Float),
                _ => Err(malformed(off)),
            },
            _ => Err(malformed(off)),
        }
    }

    /// Returns `true` if this value is CBOR `null`.
    #[must_use]
    pub fn is_null(self) -> bool {
        self.data.get(self.start) == Some(&0xf6)
    }

    /// Interprets this value as a CBOR map and returns a borrowed map view.
    ///
    /// # Errors
    ///
    /// Returns `CborError::ExpectedMap` if the value is not a map.
    pub fn map(self) -> Result<MapRef<'a>, CborError> {
        let (len, entries_start) = parse_map_header(self.data, self.start)?;
        Ok(MapRef {
            data: self.data,
            map_off: self.start,
            entries_start,
            len,
        })
    }

    /// Interprets this value as a CBOR array and returns a borrowed array view.
    ///
    /// # Errors
    ///
    /// Returns `CborError::ExpectedArray` if the value is not an array.
    pub fn array(self) -> Result<ArrayRef<'a>, CborError> {
        let (len, items_start) = parse_array_header(self.data, self.start)?;
        Ok(ArrayRef {
            data: self.data,
            array_off: self.start,
            items_start,
            len,
        })
    }

    /// Retrieves a value by map key from this value (which must be a map).
    ///
    /// # Errors
    ///
    /// Returns `CborError::ExpectedMap` if the value is not a map.
    pub fn get_key(self, key: &str) -> Result<Option<Self>, CborError> {
        self.map()?.get(key)
    }

    /// Retrieves a value by array index from this value (which must be an array).
    ///
    /// # Errors
    ///
    /// Returns `CborError::ExpectedArray` if the value is not an array.
    pub fn get_index(self, index: usize) -> Result<Option<Self>, CborError> {
        self.array()?.get(index)
    }

    /// Traverses a nested path starting from this value.
    ///
    /// Returns `Ok(None)` if any map key is missing or any array index is out of
    /// bounds. Returns `Err(_)` on type mismatches or malformed canonical input.
    ///
    /// # Errors
    ///
    /// Returns `CborError` for type mismatches or malformed canonical input.
    pub fn at(self, path: &[PathElem<'_>]) -> Result<Option<Self>, CborError> {
        let mut cur = self;
        for pe in path {
            match *pe {
                PathElem::Key(k) => match cur.get_key(k)? {
                    Some(v) => cur = v,
                    None => return Ok(None),
                },
                PathElem::Index(i) => match cur.get_index(i)? {
                    Some(v) => cur = v,
                    None => return Ok(None),
                },
            }
        }
        Ok(Some(cur))
    }

    /// Decodes this value as a CBOR integer (safe or bignum).
    ///
    /// # Errors
    ///
    /// Returns `CborError::ExpectedInteger` if the value is not an integer or is malformed.
    pub fn integer(self) -> Result<CborIntegerRef<'a>, CborError> {
        let mut s = CborStream::new(self.data, self.start);
        let off = self.start;
        let ib = read_u8(&mut s)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        match major {
            0 => {
                let u = read_uint_arg(&mut s, ai, off)?;
                let i = i64::try_from(u).map_err(|_| malformed(off))?;
                Ok(CborIntegerRef::Safe(i))
            }
            1 => {
                let n = read_uint_arg(&mut s, ai, off)?;
                let n_i = i64::try_from(n).map_err(|_| malformed(off))?;
                Ok(CborIntegerRef::Safe(-1 - n_i))
            }
            6 => {
                let tag = read_uint_arg(&mut s, ai, off)?;
                let negative = match tag {
                    2 => false,
                    3 => true,
                    _ => return Err(expected_integer(off)),
                };

                let m_off = s.position();
                let first = read_u8(&mut s)?;
                let m_major = first >> 5;
                let m_ai = first & 0x1f;
                if m_major != 2 {
                    return Err(malformed(m_off));
                }

                let m_len = read_len(&mut s, m_ai, m_off)?;
                let mag = read_exact(&mut s, m_len)?;

                Ok(CborIntegerRef::Big(BigIntRef {
                    negative,
                    magnitude: mag,
                }))
            }
            _ => Err(expected_integer(off)),
        }
    }

    /// Decodes this value as a CBOR text string.
    ///
    /// # Errors
    ///
    /// Returns `CborError::ExpectedText` if the value is not a text string or is malformed.
    pub fn text(self) -> Result<&'a str, CborError> {
        let mut s = CborStream::new(self.data, self.start);
        let off = self.start;
        let ib = read_u8(&mut s)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        if major != 3 {
            return Err(expected_text(off));
        }

        let len = read_len(&mut s, ai, off)?;
        let bytes = read_exact(&mut s, len)?;
        let s = core::str::from_utf8(bytes).map_err(|_| malformed(off))?;
        Ok(s)
    }

    /// Decodes this value as a CBOR byte string.
    ///
    /// # Errors
    ///
    /// Returns `CborError::ExpectedBytes` if the value is not a byte string or is malformed.
    pub fn bytes(self) -> Result<&'a [u8], CborError> {
        let mut s = CborStream::new(self.data, self.start);
        let off = self.start;
        let ib = read_u8(&mut s)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        if major != 2 {
            return Err(expected_bytes(off));
        }

        let len = read_len(&mut s, ai, off)?;
        let bytes = read_exact(&mut s, len)?;
        Ok(bytes)
    }

    /// Decodes this value as a CBOR boolean.
    ///
    /// # Errors
    ///
    /// Returns `CborError::ExpectedBool` if the value is not a boolean or is malformed.
    pub fn bool(self) -> Result<bool, CborError> {
        let off = self.start;
        let b = *self.data.get(off).ok_or_else(|| malformed(off))?;

        match b {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(expected_bool(off)),
        }
    }

    /// Decodes this value as a CBOR float64.
    ///
    /// # Errors
    ///
    /// Returns `CborError::ExpectedFloat` if the value is not a float64 or is malformed.
    pub fn float64(self) -> Result<f64, CborError> {
        let mut s = CborStream::new(self.data, self.start);
        let off = self.start;
        let ib = read_u8(&mut s)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        if major != 7 || ai != 27 {
            return Err(expected_float(off));
        }

        let b = read_exact(&mut s, 8)?;
        let bits = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        Ok(f64::from_bits(bits))
    }
}

impl PartialEq for CborValueRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for CborValueRef<'_> {}

/// A borrowed view into a canonical CBOR map.
///
/// Map keys are text strings and appear in canonical order (encoded length then
/// lexicographic byte order).
#[derive(Debug, Clone, Copy)]
pub struct MapRef<'a> {
    data: &'a [u8],
    map_off: usize,
    entries_start: usize,
    len: usize,
}

impl<'a> MapRef<'a> {
    /// Returns the number of entries in the map.
    #[must_use]
    pub const fn len(self) -> usize {
        self.len
    }

    /// Returns whether the map is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Looks up a single key in the map.
    ///
    /// This is efficient for canonical maps: it scans entries once and can stop early.
    ///
    /// # Errors
    ///
    /// Returns `CborError` if the map is malformed.
    pub fn get(self, key: &str) -> Result<Option<CborValueRef<'a>>, CborError> {
        checked_text_len(key.len()).map_err(|code| CborError::new(code, self.map_off))?;
        let mut pos = self.entries_start;

        for _ in 0..self.len {
            let key_off = pos;
            let mut s = CborStream::new(self.data, pos);
            let parsed = read_text(&mut s)?;
            let value_start = s.position();

            let cmp = cmp_text_key_bytes_to_query(parsed.bytes, key);
            match cmp {
                Ordering::Less => {
                    pos = value_end(self.data, value_start)?;
                }
                Ordering::Equal => {
                    let end = value_end(self.data, value_start)?;
                    return Ok(Some(CborValueRef::new(self.data, value_start, end)));
                }
                Ordering::Greater => return Ok(None),
            }

            // Ensure the scan continues from the end of the value we just skipped.
            if pos <= key_off {
                return Err(malformed(key_off));
            }
        }

        Ok(None)
    }

    /// Looks up a required key in the map.
    ///
    /// # Errors
    ///
    /// Returns `CborError::MissingKey` if the key is not present.
    pub fn require(self, key: &str) -> Result<CborValueRef<'a>, CborError> {
        self.get(key)?.ok_or_else(|| missing_key(self.map_off))
    }

    /// Looks up multiple required keys in a single pass.
    ///
    /// # Errors
    ///
    /// Returns `CborError::MissingKey` if any key is not present.
    pub fn require_many_sorted<const N: usize>(
        self,
        keys: [&str; N],
    ) -> Result<[CborValueRef<'a>; N], CborError> {
        let got = self.get_many_sorted(keys)?;
        for v in &got {
            if v.is_none() {
                return Err(missing_key(self.map_off));
            }
        }

        let mut err: Option<CborError> = None;
        let data = self.data;
        let off = self.map_off;
        let out = core::array::from_fn(|i| {
            got[i].unwrap_or_else(|| {
                err = Some(missing_key(off));
                CborValueRef::new(data, off, off)
            })
        });

        if let Some(e) = err {
            return Err(e);
        }

        Ok(out)
    }

    /// Looks up multiple keys in a single pass.
    ///
    /// Keys may be in any order; results preserve the input key order. Missing keys yield `None`.
    ///
    /// # Errors
    ///
    /// Returns `CborError` for invalid query inputs or malformed canonical data.
    pub fn get_many_sorted<const N: usize>(
        self,
        keys: [&str; N],
    ) -> Result<[Option<CborValueRef<'a>>; N], CborError> {
        let mut out: [Option<CborValueRef<'a>>; N] = [None; N];

        validate_query_keys(&keys, self.map_off)?;

        if keys.is_empty() || self.len == 0 {
            return Ok(out);
        }

        let mut idxs: [usize; N] = core::array::from_fn(|i| i);
        idxs[..].sort_unstable_by(|&i, &j| cmp_text_keys_by_canonical_encoding(keys[i], keys[j]));

        for w in idxs.windows(2) {
            if keys[w[0]] == keys[w[1]] {
                return Err(CborError::new(ErrorCode::InvalidQuery, self.map_off));
            }
        }

        let mut state = MapScanState::new(self.data, self.entries_start, self.len);
        state.scan_sorted(&keys, &idxs, |out_idx, value_start, end| {
            out[out_idx] = Some(CborValueRef::new(self.data, value_start, end));
        })?;

        Ok(out)
    }

    /// The slice-based form of [`MapRef::get_many_sorted`].
    ///
    /// `out` is cleared to `None` for all entries before results are written.
    ///
    /// # Errors
    ///
    /// Returns `CborError` for invalid query inputs or malformed canonical data.
    #[cfg(feature = "alloc")]
    pub fn get_many_sorted_into(
        self,
        keys: &[&str],
        out: &mut [Option<CborValueRef<'a>>],
    ) -> Result<(), CborError> {
        self.get_many_into(keys, out)
    }

    /// Iterates over `(key, value)` pairs in canonical order.
    ///
    /// The iterator yields `Result` to remain robust if canonical invariants are violated.
    pub fn iter(self) -> impl Iterator<Item = Result<(&'a str, CborValueRef<'a>), CborError>> + 'a {
        MapIter {
            data: self.data,
            pos: self.entries_start,
            remaining: self.len,
        }
    }

    /// Iterates over map entries excluding `used_keys` (keys must be sorted canonically).
    ///
    /// # Errors
    ///
    /// Returns `CborError` if `used_keys` are not strictly increasing or if the map is malformed.
    pub fn extras_sorted<'k>(
        self,
        used_keys: &'k [&'k str],
    ) -> Result<impl Iterator<Item = Result<(&'a str, CborValueRef<'a>), CborError>> + 'k, CborError>
    where
        'a: 'k,
    {
        validate_query_keys(used_keys, self.map_off)?;
        ensure_strictly_increasing_keys(used_keys, self.map_off)?;

        let it = MapIter {
            data: self.data,
            pos: self.entries_start,
            remaining: self.len,
        };

        Ok(ExtrasIter {
            iter: it,
            used: used_keys,
            idx: 0,
        })
    }

    /// Collects extras for sorted `used_keys` into a Vec.
    ///
    /// # Errors
    ///
    /// Returns `CborError` if `used_keys` are not strictly increasing or if the map is malformed.
    #[cfg(feature = "alloc")]
    pub fn extras_sorted_vec<'k>(
        self,
        used_keys: &'k [&'k str],
    ) -> Result<Vec<(&'a str, CborValueRef<'a>)>, CborError>
    where
        'a: 'k,
    {
        self.extras_sorted(used_keys)?
            .collect::<Result<Vec<_>, _>>()
    }

    /// Accepts `used_keys` in any order (allocates to sort them), then returns extras.
    ///
    /// # Errors
    ///
    /// Returns `CborError` if `used_keys` contain duplicates or if the map is malformed.
    #[cfg(feature = "alloc")]
    pub fn extras_vec<'k>(
        self,
        used_keys: &'k [&'k str],
    ) -> Result<Vec<(&'a str, CborValueRef<'a>)>, CborError>
    where
        'a: 'k,
    {
        use crate::alloc_util::try_vec_with_capacity;

        validate_query_keys(used_keys, self.map_off)?;
        if used_keys.is_empty() {
            return self.extras_sorted_vec(&[]);
        }

        let mut idxs = try_vec_with_capacity(used_keys.len(), self.map_off)?;
        for idx in 0..used_keys.len() {
            idxs.push(idx);
        }
        idxs.sort_by(|&i, &j| cmp_text_keys_by_canonical_encoding(used_keys[i], used_keys[j]));
        for w in idxs.windows(2) {
            if used_keys[w[0]] == used_keys[w[1]] {
                return Err(CborError::new(ErrorCode::InvalidQuery, self.map_off));
            }
        }

        let mut sorted = try_vec_with_capacity(used_keys.len(), self.map_off)?;
        for idx in idxs {
            sorted.push(used_keys[idx]);
        }
        self.extras_sorted_vec(&sorted)
    }

    /// Looks up multiple keys in one pass (keys may be in any order).
    ///
    /// This API is available with the `alloc` feature. Results preserve the input key order.
    ///
    /// # Errors
    ///
    /// Returns `CborError` for invalid query inputs or malformed canonical data.
    #[cfg(feature = "alloc")]
    pub fn get_many(self, keys: &[&str]) -> Result<Vec<Option<CborValueRef<'a>>>, CborError> {
        let mut out = crate::alloc_util::try_vec_repeat_copy(keys.len(), None, self.map_off)?;
        self.get_many_into(keys, &mut out)?;
        Ok(out)
    }

    /// Looks up multiple required keys in one pass (keys may be in any order).
    ///
    /// This API is available with the `alloc` feature. Results preserve the input key order.
    ///
    /// # Errors
    ///
    /// Returns `CborError::MissingKey` if any key is not present.
    #[cfg(feature = "alloc")]
    pub fn require_many(self, keys: &[&str]) -> Result<Vec<CborValueRef<'a>>, CborError> {
        let mut out = crate::alloc_util::try_vec_repeat_copy(keys.len(), None, self.map_off)?;
        self.get_many_into(keys, &mut out)?;

        let mut req = crate::alloc_util::try_vec_with_capacity(out.len(), self.map_off)?;
        for slot in out {
            match slot {
                Some(v) => req.push(v),
                None => return Err(missing_key(self.map_off)),
            }
        }
        Ok(req)
    }

    /// The slice-based form of [`MapRef::get_many`].
    ///
    /// `out` is cleared to `None` for all entries before results are written.
    ///
    /// # Errors
    ///
    /// Returns `CborError` for invalid query inputs or malformed canonical data.
    #[cfg(feature = "alloc")]
    pub fn get_many_into(
        self,
        keys: &[&str],
        out: &mut [Option<CborValueRef<'a>>],
    ) -> Result<(), CborError> {
        if keys.len() != out.len() {
            return Err(CborError::new(ErrorCode::InvalidQuery, self.map_off));
        }

        validate_query_keys(keys, self.map_off)?;

        for slot in out.iter_mut() {
            *slot = None;
        }

        if keys.is_empty() || self.len == 0 {
            return Ok(());
        }

        // Sort indices by canonical ordering of the corresponding keys.
        let mut idxs: Vec<usize> = (0..keys.len()).collect();
        idxs.sort_by(|&i, &j| cmp_text_keys_by_canonical_encoding(keys[i], keys[j]));

        // Detect duplicate query keys.
        for w in idxs.windows(2) {
            if keys[w[0]] == keys[w[1]] {
                return Err(CborError::new(ErrorCode::InvalidQuery, self.map_off));
            }
        }

        // Merge-join scan over the map and the sorted query list.
        let mut state = MapScanState::new(self.data, self.entries_start, self.len);
        state.scan_sorted(keys, &idxs, |out_idx, value_start, end| {
            out[out_idx] = Some(CborValueRef::new(self.data, value_start, end));
        })?;

        Ok(())
    }
}

/// A borrowed view into a canonical CBOR array.
#[derive(Debug, Clone, Copy)]
pub struct ArrayRef<'a> {
    data: &'a [u8],
    array_off: usize,
    items_start: usize,
    len: usize,
}

impl<'a> ArrayRef<'a> {
    /// Returns the number of items in the array.
    #[must_use]
    pub const fn len(self) -> usize {
        self.len
    }

    /// Returns whether the array is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Returns the array item at `index`, or `None` if out of bounds.
    ///
    /// # Errors
    ///
    /// Returns `CborError` if the array is malformed.
    pub fn get(self, index: usize) -> Result<Option<CborValueRef<'a>>, CborError> {
        if index >= self.len {
            return Ok(None);
        }

        let mut pos = self.items_start;
        for i in 0..self.len {
            let start = pos;
            let end = value_end(self.data, start)?;
            if i == index {
                return Ok(Some(CborValueRef::new(self.data, start, end)));
            }
            pos = end;
        }

        Err(malformed(self.array_off))
    }

    /// Iterates over array items in order.
    ///
    /// The iterator yields `Result` to remain robust if canonical invariants are violated.
    pub fn iter(self) -> impl Iterator<Item = Result<CborValueRef<'a>, CborError>> + 'a {
        ArrayIter {
            data: self.data,
            pos: self.items_start,
            remaining: self.len,
        }
    }
}

/// Adds query methods to `CborBytesRef`.
impl<'a> CborBytesRef<'a> {
    /// Returns a borrowed view of the root CBOR item.
    ///
    /// Canonical validation guarantees the message is exactly one CBOR item, so the
    /// root value spans the full byte slice.
    #[must_use]
    pub const fn root(self) -> CborValueRef<'a> {
        CborValueRef::new(self.as_bytes(), 0, self.len())
    }

    /// Convenience wrapper around `self.root().at(path)`.
    ///
    /// # Errors
    ///
    /// Returns `CborError` for type mismatches or malformed canonical input.
    pub fn at(self, path: &[PathElem<'_>]) -> Result<Option<CborValueRef<'a>>, CborError> {
        self.root().at(path)
    }
}

#[cfg(feature = "alloc")]
impl CborBytes {
    /// Returns a borrowed view of the root CBOR item.
    #[must_use]
    pub fn root(&self) -> CborValueRef<'_> {
        let b = self.as_bytes();
        CborValueRef::new(b, 0, b.len())
    }

    /// Convenience wrapper around `self.root().at(path)`.
    ///
    /// # Errors
    ///
    /// Returns `CborError` for type mismatches or malformed canonical input.
    pub fn at(&self, path: &[PathElem<'_>]) -> Result<Option<CborValueRef<'_>>, CborError> {
        self.root().at(path)
    }
}

#[cfg(feature = "alloc")]
#[allow(clippy::elidable_lifetime_names)]
impl<'a> CborValueRef<'a> {
    /// Convert this borrowed value into an owned [`CborValue`].
    ///
    /// # Errors
    ///
    /// Returns `CborError` if the value is malformed.
    pub fn to_owned(self) -> Result<CborValue, CborError> {
        parse::decode_value_trusted_range(self.data, self.start, self.end)
    }
}

#[cfg(feature = "alloc")]
impl CborValue {
    /// Traverses a nested path inside a decoded `CborValue`.
    ///
    /// Returns `Ok(None)` if any key/index is missing. Returns `Err(_)` on type mismatches.
    ///
    /// # Errors
    ///
    /// Returns `CborError` for type mismatches.
    pub fn at<'a>(&'a self, path: &[PathElem<'_>]) -> Result<Option<&'a Self>, CborError> {
        let mut cur: &Self = self;

        for pe in path {
            match *pe {
                PathElem::Key(k) => {
                    let map = cur.as_map().ok_or_else(|| expected_map(0))?;
                    match map.get(k) {
                        Some(v) => cur = v,
                        None => return Ok(None),
                    }
                }
                PathElem::Index(i) => {
                    let items = cur.as_array().ok_or_else(|| expected_array(0))?;
                    match items.get(i) {
                        Some(v) => cur = v,
                        None => return Ok(None),
                    }
                }
            }
        }

        Ok(Some(cur))
    }
}

#[cfg(feature = "alloc")]
impl CborMap {
    /// Looks up multiple keys in a single pass.
    ///
    /// Keys may be in any order; results preserve the input key order.
    ///
    /// # Errors
    ///
    /// Returns `CborError` for invalid query inputs.
    pub fn get_many_sorted<'a, const N: usize>(
        &'a self,
        keys: [&str; N],
    ) -> Result<[Option<&'a CborValue>; N], CborError> {
        let mut out: [Option<&'a CborValue>; N] = [None; N];

        validate_query_keys(&keys, 0)?;

        if keys.is_empty() || self.is_empty() {
            return Ok(out);
        }

        let mut idxs: [usize; N] = core::array::from_fn(|i| i);
        idxs[..].sort_unstable_by(|&i, &j| cmp_text_keys_by_canonical_encoding(keys[i], keys[j]));

        for w in idxs.windows(2) {
            if keys[w[0]] == keys[w[1]] {
                return Err(CborError::new(ErrorCode::InvalidQuery, 0));
            }
        }

        let mut it = self.iter().peekable();
        scan_sorted_iter(&keys, &idxs, &mut it, |idx, mv| {
            out[idx] = Some(mv);
        });

        Ok(out)
    }

    /// The slice-based form of [`CborMap::get_many_sorted`].
    ///
    /// `out` is cleared to `None` for all entries before results are written.
    ///
    /// # Errors
    ///
    /// Returns `CborError` for invalid query inputs.
    pub fn get_many_sorted_into<'a>(
        &'a self,
        keys: &[&str],
        out: &mut [Option<&'a CborValue>],
    ) -> Result<(), CborError> {
        if keys.len() != out.len() {
            return Err(CborError::new(ErrorCode::InvalidQuery, 0));
        }

        validate_query_keys(keys, 0)?;

        for slot in out.iter_mut() {
            *slot = None;
        }

        if keys.is_empty() || self.is_empty() {
            return Ok(());
        }

        let mut idxs: Vec<usize> = (0..keys.len()).collect();
        idxs.sort_by(|&i, &j| cmp_text_keys_by_canonical_encoding(keys[i], keys[j]));

        for w in idxs.windows(2) {
            if keys[w[0]] == keys[w[1]] {
                return Err(CborError::new(ErrorCode::InvalidQuery, 0));
            }
        }

        let mut it = self.iter().peekable();
        scan_sorted_iter(keys, &idxs, &mut it, |idx, mv| {
            out[idx] = Some(mv);
        });

        Ok(())
    }
}

/* =========================
 * Internal parsing helpers
 * ========================= */

#[inline]
const fn map_stream_err(cause: CborError) -> CborError {
    err(ErrorCode::MalformedCanonical, cause.offset)
}

#[inline]
fn read_u8(s: &mut CborStream<'_>) -> Result<u8, CborError> {
    s.read_u8().map_err(map_stream_err)
}

#[inline]
fn read_exact<'a>(s: &mut CborStream<'a>, n: usize) -> Result<&'a [u8], CborError> {
    s.read_exact(n).map_err(map_stream_err)
}

#[inline]
fn read_uint_arg(s: &mut CborStream<'_>, ai: u8, off: usize) -> Result<u64, CborError> {
    s.read_uint_arg(ai, off).map_err(map_stream_err)
}

#[inline]
fn read_len(s: &mut CborStream<'_>, ai: u8, off: usize) -> Result<usize, CborError> {
    let n = s.read_len_arg(ai, off).map_err(map_stream_err)?;
    usize::try_from(n).map_err(|_| malformed(off))
}

#[derive(Clone, Copy)]
struct CachedKey<'a> {
    key_bytes: &'a [u8],
    value_start: usize,
}

struct MapScanState<'a> {
    data: &'a [u8],
    pos: usize,
    cached: Option<CachedKey<'a>>,
    map_remaining: usize,
}

impl<'a> MapScanState<'a> {
    const fn new(data: &'a [u8], pos: usize, map_remaining: usize) -> Self {
        Self {
            data,
            pos,
            cached: None,
            map_remaining,
        }
    }

    fn fill_cache(&mut self) -> Result<(), CborError> {
        if self.cached.is_none() {
            let mut s = CborStream::new(self.data, self.pos);
            let parsed = read_text(&mut s)?;
            let value_start = s.position();
            self.pos = value_start;
            self.cached = Some(CachedKey {
                key_bytes: parsed.bytes,
                value_start,
            });
        }
        Ok(())
    }

    fn consume_cached_entry(&mut self, ck: CachedKey<'a>) -> Result<usize, CborError> {
        let end = value_end(self.data, ck.value_start)?;
        self.pos = end;
        self.cached = None;
        self.map_remaining -= 1;
        Ok(end)
    }

    fn handle_query_match<F>(
        &mut self,
        query: &str,
        q_idx: usize,
        on_match: F,
    ) -> Result<usize, CborError>
    where
        F: FnOnce(usize),
    {
        let Some(ck) = self.cached else {
            return Ok(q_idx);
        };

        match cmp_text_key_bytes_to_query(ck.key_bytes, query) {
            Ordering::Less => {
                let _ = self.consume_cached_entry(ck)?;
                Ok(q_idx)
            }
            Ordering::Equal => {
                let end = self.consume_cached_entry(ck)?;
                on_match(end);
                Ok(q_idx + 1)
            }
            Ordering::Greater => Ok(q_idx + 1),
        }
    }

    fn scan_sorted<F>(
        &mut self,
        keys: &[&str],
        idxs: &[usize],
        mut on_match: F,
    ) -> Result<(), CborError>
    where
        F: FnMut(usize, usize, usize),
    {
        let mut q_pos = 0usize;

        while q_pos < idxs.len() {
            if self.map_remaining == 0 {
                break;
            }

            self.fill_cache()?;

            let Some(ck) = self.cached else {
                continue;
            };

            let out_idx = idxs[q_pos];
            let value_start = ck.value_start;
            q_pos = self.handle_query_match(keys[out_idx], q_pos, |end| {
                on_match(out_idx, value_start, end);
            })?;
        }

        Ok(())
    }
}

#[derive(Clone, Copy)]
struct ParsedText<'a> {
    s: &'a str,
    bytes: &'a [u8],
}

#[cfg(feature = "alloc")]
fn scan_sorted_iter<'a, I, V>(
    keys: &[&str],
    idxs: &[usize],
    iter: &mut core::iter::Peekable<I>,
    mut on_match: impl FnMut(usize, V),
) where
    I: Iterator<Item = (&'a str, V)>,
    V: Copy,
{
    for &idx in idxs {
        let qk = keys[idx];
        loop {
            let Some((mk, mv)) = iter.peek().copied() else {
                break;
            };

            match cmp_text_keys_by_canonical_encoding(mk, qk) {
                Ordering::Less => {
                    iter.next();
                }
                Ordering::Equal => {
                    on_match(idx, mv);
                    iter.next();
                    break;
                }
                Ordering::Greater => break,
            }
        }
    }
}

fn read_text<'a>(s: &mut CborStream<'a>) -> Result<ParsedText<'a>, CborError> {
    let off = s.position();
    let ib = read_u8(s)?;
    let major = ib >> 5;
    let ai = ib & 0x1f;

    if major != 3 {
        return Err(malformed(off));
    }

    let len = read_len(s, ai, off)?;
    let bytes = read_exact(s, len)?;
    let text = core::str::from_utf8(bytes).map_err(|_| malformed(off))?;
    Ok(ParsedText { s: text, bytes })
}

fn value_end(data: &[u8], start: usize) -> Result<usize, CborError> {
    parse::value_end_trusted(data, start)
}

fn parse_map_header(data: &[u8], start: usize) -> Result<(usize, usize), CborError> {
    let mut s = CborStream::new(data, start);
    let off = start;
    let ib = read_u8(&mut s)?;
    let major = ib >> 5;
    let ai = ib & 0x1f;

    if major != 5 {
        return Err(expected_map(off));
    }

    let len = read_len(&mut s, ai, off)?;
    Ok((len, s.position()))
}

fn parse_array_header(data: &[u8], start: usize) -> Result<(usize, usize), CborError> {
    let mut s = CborStream::new(data, start);
    let off = start;
    let ib = read_u8(&mut s)?;
    let major = ib >> 5;
    let ai = ib & 0x1f;

    if major != 4 {
        return Err(expected_array(off));
    }

    let len = read_len(&mut s, ai, off)?;
    Ok((len, s.position()))
}

fn cmp_text_key_bytes_to_query(key_payload: &[u8], query: &str) -> Ordering {
    let q_bytes = query.as_bytes();
    match key_payload.len().cmp(&q_bytes.len()) {
        Ordering::Equal => key_payload.cmp(q_bytes),
        other => other,
    }
}

fn validate_query_keys(keys: &[&str], err_off: usize) -> Result<(), CborError> {
    for &k in keys {
        checked_text_len(k.len()).map_err(|code| CborError::new(code, err_off))?;
    }
    Ok(())
}

fn ensure_strictly_increasing_keys(keys: &[&str], err_off: usize) -> Result<(), CborError> {
    let mut prev: Option<&str> = None;

    for &k in keys {
        if let Some(p) = prev {
            match cmp_text_keys_by_canonical_encoding(p, k) {
                Ordering::Less => {}
                Ordering::Equal | Ordering::Greater => {
                    return Err(CborError::new(ErrorCode::InvalidQuery, err_off));
                }
            }
        }
        prev = Some(k);
    }

    Ok(())
}

struct ExtrasIter<'a, 'k> {
    iter: MapIter<'a>,
    used: &'k [&'k str],
    idx: usize,
}

impl<'a> Iterator for ExtrasIter<'a, '_> {
    type Item = Result<(&'a str, CborValueRef<'a>), CborError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let next = self.iter.next()?;
            return match next {
                Err(e) => Some(Err(e)),
                Ok((k, v)) => {
                    while self.idx < self.used.len()
                        && cmp_text_keys_by_canonical_encoding(self.used[self.idx], k)
                            == Ordering::Less
                    {
                        self.idx += 1;
                    }
                    if self.idx < self.used.len()
                        && cmp_text_keys_by_canonical_encoding(self.used[self.idx], k)
                            == Ordering::Equal
                    {
                        self.idx += 1;
                        continue;
                    }
                    Some(Ok((k, v)))
                }
            };
        }
    }
}

struct MapIter<'a> {
    data: &'a [u8],
    pos: usize,
    remaining: usize,
}

impl<'a> Iterator for MapIter<'a> {
    type Item = Result<(&'a str, CborValueRef<'a>), CborError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        let mut s = CborStream::new(self.data, self.pos);
        let parsed = match read_text(&mut s) {
            Ok(v) => v,
            Err(e) => {
                self.remaining = 0;
                return Some(Err(e));
            }
        };

        let value_start = s.position();
        let end = match value_end(self.data, value_start) {
            Ok(e) => e,
            Err(e) => {
                self.remaining = 0;
                return Some(Err(e));
            }
        };

        self.pos = end;
        self.remaining -= 1;

        Some(Ok((
            parsed.s,
            CborValueRef::new(self.data, value_start, end),
        )))
    }
}

struct ArrayIter<'a> {
    data: &'a [u8],
    pos: usize,
    remaining: usize,
}

impl<'a> Iterator for ArrayIter<'a> {
    type Item = Result<CborValueRef<'a>, CborError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        let start = self.pos;
        let end = match value_end(self.data, start) {
            Ok(e) => e,
            Err(e) => {
                self.remaining = 0;
                return Some(Err(e));
            }
        };

        self.pos = end;
        self.remaining -= 1;

        Some(Ok(CborValueRef::new(self.data, start, end)))
    }
}
