//! Query support for canonical CBOR messages.
//!
//! This module provides a lightweight, allocation-free query engine for
//! [`CanonicalCborRef`](crate::CanonicalCborRef). Queries return borrowed views
//! ([`CborValueRef`]) pointing into the original message bytes.
//!
//! The query layer assumes the input bytes are already validated as canonical via
//! [`validate_canonical`](crate::validate_canonical). If invariants are violated,
//! APIs may return [`QueryErrorCode::MalformedCanonical`].

use core::cmp::Ordering;
use core::fmt;

use crate::canonical::CanonicalCborRef;

#[cfg(feature = "alloc")]
use crate::canonical::CanonicalCbor;

#[cfg(feature = "alloc")]
use crate::value::{CborMap, CborValue};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// The CBOR data model supported by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborKind {
    /// Major type 0/1 (safe-range integer).
    Int,
    /// Major type 2.
    Bytes,
    /// Major type 3.
    Text,
    /// Major type 4.
    Array,
    /// Major type 5 (text keys only).
    Map,
    /// Major type 6 tag 2/3 + byte string payload.
    Bignum,
    /// Simple value true/false.
    Bool,
    /// Simple value null.
    Null,
    /// IEEE-754 float64 (major 7, ai 27).
    Float,
}

/// Query error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QueryErrorCode {
    /// Expected a map at the current location.
    ExpectedMap,
    /// Expected an array at the current location.
    ExpectedArray,
    /// Expected an integer at the current location.
    ExpectedInt,
    /// Expected a text string at the current location.
    ExpectedText,
    /// Expected a byte string at the current location.
    ExpectedBytes,
    /// Expected a boolean at the current location.
    ExpectedBool,
    /// Expected a float64 at the current location.
    ExpectedFloat,
    /// Expected a bignum (tag 2 or 3) at the current location.
    ExpectedBignum,

    /// Keys passed to `*_sorted*` APIs are not strictly increasing in canonical order.
    KeysNotSorted,
    /// The query includes the same key more than once.
    DuplicateQueryKey,
    /// Invalid query arguments (e.g., output slice length mismatch).
    InvalidQuery,

    /// Parsing failed even though the input was expected to be canonical.
    ///
    /// This should be unreachable when values originate from
    /// [`validate_canonical`](crate::validate_canonical).
    MalformedCanonical,
}

/// Error returned by the query APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryError {
    /// The error category.
    pub code: QueryErrorCode,
    /// Byte offset within the message where the error was detected.
    pub offset: usize,
}

impl QueryError {
    #[inline]
    const fn new(code: QueryErrorCode, offset: usize) -> Self {
        Self { code, offset }
    }

    #[inline]
    const fn malformed(offset: usize) -> Self {
        Self::new(QueryErrorCode::MalformedCanonical, offset)
    }

    #[inline]
    const fn expected_map(offset: usize) -> Self {
        Self::new(QueryErrorCode::ExpectedMap, offset)
    }

    #[inline]
    const fn expected_array(offset: usize) -> Self {
        Self::new(QueryErrorCode::ExpectedArray, offset)
    }

    #[inline]
    const fn expected_int(offset: usize) -> Self {
        Self::new(QueryErrorCode::ExpectedInt, offset)
    }

    #[inline]
    const fn expected_text(offset: usize) -> Self {
        Self::new(QueryErrorCode::ExpectedText, offset)
    }

    #[inline]
    const fn expected_bytes(offset: usize) -> Self {
        Self::new(QueryErrorCode::ExpectedBytes, offset)
    }

    #[inline]
    const fn expected_bool(offset: usize) -> Self {
        Self::new(QueryErrorCode::ExpectedBool, offset)
    }

    #[inline]
    const fn expected_float(offset: usize) -> Self {
        Self::new(QueryErrorCode::ExpectedFloat, offset)
    }

    #[inline]
    const fn expected_bignum(offset: usize) -> Self {
        Self::new(QueryErrorCode::ExpectedBignum, offset)
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self.code {
            QueryErrorCode::ExpectedMap => "expected CBOR map",
            QueryErrorCode::ExpectedArray => "expected CBOR array",
            QueryErrorCode::ExpectedInt => "expected CBOR int",
            QueryErrorCode::ExpectedText => "expected CBOR text string",
            QueryErrorCode::ExpectedBytes => "expected CBOR byte string",
            QueryErrorCode::ExpectedBool => "expected CBOR bool",
            QueryErrorCode::ExpectedFloat => "expected CBOR float64",
            QueryErrorCode::ExpectedBignum => "expected CBOR bignum (tag 2/3)",

            QueryErrorCode::KeysNotSorted => {
                "query keys must be strictly increasing in canonical order"
            }
            QueryErrorCode::DuplicateQueryKey => "duplicate query key",
            QueryErrorCode::InvalidQuery => "invalid query arguments",
            QueryErrorCode::MalformedCanonical => "malformed canonical CBOR",
        };

        write!(f, "cbor query failed at {}: {msg}", self.offset)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for QueryError {}

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

/// A borrowed view into a canonical CBOR message.
///
/// The view carries the full message bytes plus a `(start, end)` range for the
/// current value. All nested values returned from queries keep referencing the
/// original message bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CborValueRef<'a> {
    data: &'a [u8],
    start: usize,
    end: usize,
}

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
    /// Returns `QueryError` if the underlying bytes are malformed.
    pub fn kind(self) -> Result<CborKind, QueryError> {
        let mut c = Cursor::new(self.data, self.start);
        let off = self.start;
        let ib = c.read_u8(off)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        match major {
            0 | 1 => Ok(CborKind::Int),
            2 => Ok(CborKind::Bytes),
            3 => Ok(CborKind::Text),
            4 => Ok(CborKind::Array),
            5 => Ok(CborKind::Map),
            6 => {
                let tag = c.read_uint(ai, off)?;
                match tag {
                    2 | 3 => Ok(CborKind::Bignum),
                    _ => Err(QueryError::malformed(off)),
                }
            }
            7 => match ai {
                20 | 21 => Ok(CborKind::Bool),
                22 => Ok(CborKind::Null),
                27 => Ok(CborKind::Float),
                _ => Err(QueryError::malformed(off)),
            },
            _ => Err(QueryError::malformed(off)),
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
    /// Returns `QueryError::ExpectedMap` if the value is not a map.
    pub fn map(self) -> Result<MapRef<'a>, QueryError> {
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
    /// Returns `QueryError::ExpectedArray` if the value is not an array.
    pub fn array(self) -> Result<ArrayRef<'a>, QueryError> {
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
    /// Returns `QueryError::ExpectedMap` if the value is not a map.
    pub fn get_key(self, key: &str) -> Result<Option<Self>, QueryError> {
        self.map()?.get(key)
    }

    /// Retrieves a value by array index from this value (which must be an array).
    ///
    /// # Errors
    ///
    /// Returns `QueryError::ExpectedArray` if the value is not an array.
    pub fn get_index(self, index: usize) -> Result<Option<Self>, QueryError> {
        self.array()?.get(index)
    }

    /// Traverses a nested path starting from this value.
    ///
    /// Returns `Ok(None)` if any map key is missing or any array index is out of
    /// bounds. Returns `Err(_)` on type mismatches or malformed canonical input.
    ///
    /// # Errors
    ///
    /// Returns `QueryError` for type mismatches or malformed canonical input.
    pub fn at(self, path: &[PathElem<'_>]) -> Result<Option<Self>, QueryError> {
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

    /// Decodes this value as a safe-range CBOR integer.
    ///
    /// # Errors
    ///
    /// Returns `QueryError::ExpectedInt` if the value is not an integer or is malformed.
    pub fn int(self) -> Result<i64, QueryError> {
        let mut c = Cursor::new(self.data, self.start);
        let off = self.start;
        let ib = c.read_u8(off)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        match major {
            0 => {
                let u = c.read_uint(ai, off)?;
                let i = i64::try_from(u).map_err(|_| QueryError::malformed(off))?;
                Ok(i)
            }
            1 => {
                let n = c.read_uint(ai, off)?;
                let n_i = i64::try_from(n).map_err(|_| QueryError::malformed(off))?;
                Ok(-1 - n_i)
            }
            _ => Err(QueryError::expected_int(off)),
        }
    }

    /// Decodes this value as a CBOR text string.
    ///
    /// # Errors
    ///
    /// Returns `QueryError::ExpectedText` if the value is not a text string or is malformed.
    pub fn text(self) -> Result<&'a str, QueryError> {
        let mut c = Cursor::new(self.data, self.start);
        let off = self.start;
        let ib = c.read_u8(off)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        if major != 3 {
            return Err(QueryError::expected_text(off));
        }

        let len = c.read_len(ai, off)?;
        let bytes = c.read_exact(len, off)?;
        let s = core::str::from_utf8(bytes).map_err(|_| QueryError::malformed(off))?;
        Ok(s)
    }

    /// Decodes this value as a CBOR byte string.
    ///
    /// # Errors
    ///
    /// Returns `QueryError::ExpectedBytes` if the value is not a byte string or is malformed.
    pub fn bytes(self) -> Result<&'a [u8], QueryError> {
        let mut c = Cursor::new(self.data, self.start);
        let off = self.start;
        let ib = c.read_u8(off)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        if major != 2 {
            return Err(QueryError::expected_bytes(off));
        }

        let len = c.read_len(ai, off)?;
        let bytes = c.read_exact(len, off)?;
        Ok(bytes)
    }

    /// Decodes this value as a CBOR boolean.
    ///
    /// # Errors
    ///
    /// Returns `QueryError::ExpectedBool` if the value is not a boolean or is malformed.
    pub fn bool(self) -> Result<bool, QueryError> {
        let off = self.start;
        let b = *self
            .data
            .get(off)
            .ok_or_else(|| QueryError::malformed(off))?;

        match b {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(QueryError::expected_bool(off)),
        }
    }

    /// Decodes this value as a CBOR float64.
    ///
    /// # Errors
    ///
    /// Returns `QueryError::ExpectedFloat` if the value is not a float64 or is malformed.
    pub fn float64(self) -> Result<f64, QueryError> {
        let mut c = Cursor::new(self.data, self.start);
        let off = self.start;
        let ib = c.read_u8(off)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        if major != 7 || ai != 27 {
            return Err(QueryError::expected_float(off));
        }

        let b = c.read_exact(8, off)?;
        let bits = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        Ok(f64::from_bits(bits))
    }

    /// Decodes this value as a CBOR bignum (tag 2 / tag 3).
    ///
    /// # Errors
    ///
    /// Returns `QueryError::ExpectedBignum` if the value is not a bignum or is malformed.
    pub fn bignum(self) -> Result<BigIntRef<'a>, QueryError> {
        let mut c = Cursor::new(self.data, self.start);
        let off = self.start;
        let ib = c.read_u8(off)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        if major != 6 {
            return Err(QueryError::expected_bignum(off));
        }

        let tag = c.read_uint(ai, off)?;
        let negative = match tag {
            2 => false,
            3 => true,
            _ => return Err(QueryError::malformed(off)),
        };

        let m_off = c.pos;
        let first = c.read_u8(m_off)?;
        let m_major = first >> 5;
        let m_ai = first & 0x1f;
        if m_major != 2 {
            return Err(QueryError::malformed(m_off));
        }

        let m_len = c.read_len(m_ai, m_off)?;
        let mag = c.read_exact(m_len, m_off)?;

        Ok(BigIntRef {
            negative,
            magnitude: mag,
        })
    }
}

/// A borrowed view into a canonical CBOR map.
///
/// Map keys are text strings and appear in canonical order (encoded length then
/// lexicographic byte order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Returns `QueryError` if the map is malformed.
    pub fn get(self, key: &str) -> Result<Option<CborValueRef<'a>>, QueryError> {
        let mut pos = self.entries_start;

        for _ in 0..self.len {
            let key_off = pos;
            let mut c = Cursor::new(self.data, pos);
            let parsed = read_text(&mut c)?;
            let value_start = c.pos;

            let cmp = cmp_text_key_bytes_to_query(parsed.bytes, parsed.enc_len, key);
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
                return Err(QueryError::malformed(key_off));
            }
        }

        Ok(None)
    }

    /// Looks up multiple keys in canonical order in a single pass.
    ///
    /// `keys` must be strictly increasing under canonical CBOR map key ordering.
    /// Missing keys yield `None`.
    ///
    /// # Errors
    ///
    /// Returns `QueryError` for invalid query inputs or malformed canonical data.
    pub fn get_many_sorted<const N: usize>(
        self,
        keys: [&str; N],
    ) -> Result<[Option<CborValueRef<'a>>; N], QueryError> {
        let mut out: [Option<CborValueRef<'a>>; N] = [None; N];
        self.get_many_sorted_into(&keys, &mut out)?;
        Ok(out)
    }

    /// The slice-based form of [`MapRef::get_many_sorted`].
    ///
    /// `out` is cleared to `None` for all entries before results are written.
    ///
    /// # Errors
    ///
    /// Returns `QueryError` for invalid query inputs or malformed canonical data.
    pub fn get_many_sorted_into(
        self,
        keys: &[&str],
        out: &mut [Option<CborValueRef<'a>>],
    ) -> Result<(), QueryError> {
        if keys.len() != out.len() {
            return Err(QueryError::new(QueryErrorCode::InvalidQuery, self.map_off));
        }

        for slot in out.iter_mut() {
            *slot = None;
        }

        ensure_strictly_increasing_keys(keys, self.map_off)?;

        if keys.is_empty() || self.len == 0 {
            return Ok(());
        }

        let mut state = MapScanState::new(self.data, self.entries_start, self.len);
        let mut q_idx = 0usize;

        while q_idx < keys.len() {
            if state.map_remaining == 0 {
                break;
            }

            state.fill_cache()?;

            let Some(ck) = state.cached else {
                continue;
            };

            q_idx = state.handle_query_match(keys[q_idx], q_idx, |end| {
                out[q_idx] = Some(CborValueRef::new(self.data, ck.value_start, end));
            })?;
        }

        Ok(())
    }

    /// Iterates over `(key, value)` pairs in canonical order.
    ///
    /// The iterator yields `Result` to remain robust if canonical invariants are violated.
    pub fn iter(
        self,
    ) -> impl Iterator<Item = Result<(&'a str, CborValueRef<'a>), QueryError>> + 'a {
        MapIter {
            data: self.data,
            pos: self.entries_start,
            remaining: self.len,
        }
    }

    /// Looks up multiple keys in one pass (keys may be in any order).
    ///
    /// This API is available with the `alloc` feature. Results preserve the input key order.
    ///
    /// # Errors
    ///
    /// Returns `QueryError` for invalid query inputs or malformed canonical data.
    #[cfg(feature = "alloc")]
    pub fn get_many(self, keys: &[&str]) -> Result<Vec<Option<CborValueRef<'a>>>, QueryError> {
        let mut out: Vec<Option<CborValueRef<'a>>> = vec![None; keys.len()];
        self.get_many_into(keys, &mut out)?;
        Ok(out)
    }

    /// The slice-based form of [`MapRef::get_many`].
    ///
    /// `out` is cleared to `None` for all entries before results are written.
    ///
    /// # Errors
    ///
    /// Returns `QueryError` for invalid query inputs or malformed canonical data.
    #[cfg(feature = "alloc")]
    pub fn get_many_into(
        self,
        keys: &[&str],
        out: &mut [Option<CborValueRef<'a>>],
    ) -> Result<(), QueryError> {
        if keys.len() != out.len() {
            return Err(QueryError::new(QueryErrorCode::InvalidQuery, self.map_off));
        }

        for slot in out.iter_mut() {
            *slot = None;
        }

        if keys.is_empty() || self.len == 0 {
            return Ok(());
        }

        // Sort indices by canonical ordering of the corresponding keys.
        let mut idxs: Vec<usize> = (0..keys.len()).collect();
        idxs.sort_by(|&i, &j| cmp_text_keys_canon(keys[i], keys[j]));

        // Detect duplicate query keys.
        for w in idxs.windows(2) {
            if keys[w[0]] == keys[w[1]] {
                return Err(QueryError::new(
                    QueryErrorCode::DuplicateQueryKey,
                    self.map_off,
                ));
            }
        }

        // Merge-join scan over the map and the sorted query list.
        let mut state = MapScanState::new(self.data, self.entries_start, self.len);
        let mut q_pos = 0usize;

        while q_pos < idxs.len() {
            if state.map_remaining == 0 {
                break;
            }

            state.fill_cache()?;

            let Some(ck) = state.cached else {
                continue;
            };
            let out_idx = idxs[q_pos];
            q_pos = state.handle_query_match(keys[out_idx], q_pos, |end| {
                out[out_idx] = Some(CborValueRef::new(self.data, ck.value_start, end));
            })?;
        }

        Ok(())
    }
}

/// A borrowed view into a canonical CBOR array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Returns `QueryError` if the array is malformed.
    pub fn get(self, index: usize) -> Result<Option<CborValueRef<'a>>, QueryError> {
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

        Err(QueryError::malformed(self.array_off))
    }

    /// Iterates over array items in order.
    ///
    /// The iterator yields `Result` to remain robust if canonical invariants are violated.
    pub fn iter(self) -> impl Iterator<Item = Result<CborValueRef<'a>, QueryError>> + 'a {
        ArrayIter {
            data: self.data,
            pos: self.items_start,
            remaining: self.len,
        }
    }
}

/// Adds query methods to `CanonicalCborRef`.
impl<'a> CanonicalCborRef<'a> {
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
    /// Returns `QueryError` for type mismatches or malformed canonical input.
    pub fn at(self, path: &[PathElem<'_>]) -> Result<Option<CborValueRef<'a>>, QueryError> {
        self.root().at(path)
    }
}

#[cfg(feature = "alloc")]
impl CanonicalCbor {
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
    /// Returns `QueryError` for type mismatches or malformed canonical input.
    pub fn at(&self, path: &[PathElem<'_>]) -> Result<Option<CborValueRef<'_>>, QueryError> {
        self.root().at(path)
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
    /// Returns `QueryError` for type mismatches.
    pub fn at<'a>(&'a self, path: &[PathElem<'_>]) -> Result<Option<&'a Self>, QueryError> {
        let mut cur: &Self = self;

        for pe in path {
            match *pe {
                PathElem::Key(k) => {
                    let Self::Map(map) = cur else {
                        return Err(QueryError::expected_map(0));
                    };
                    match map.get(k) {
                        Some(v) => cur = v,
                        None => return Ok(None),
                    }
                }
                PathElem::Index(i) => {
                    let Self::Array(items) = cur else {
                        return Err(QueryError::expected_array(0));
                    };
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
    /// Looks up multiple keys in canonical order in a single pass.
    ///
    /// `keys` must be strictly increasing under canonical CBOR map key ordering.
    ///
    /// # Errors
    ///
    /// Returns `QueryError` for invalid query inputs.
    pub fn get_many_sorted<'a, const N: usize>(
        &'a self,
        keys: [&str; N],
    ) -> Result<[Option<&'a CborValue>; N], QueryError> {
        let mut out: [Option<&'a CborValue>; N] = [None; N];
        self.get_many_sorted_into(&keys, &mut out)?;
        Ok(out)
    }

    /// The slice-based form of [`CborMap::get_many_sorted`].
    ///
    /// `out` is cleared to `None` for all entries before results are written.
    ///
    /// # Errors
    ///
    /// Returns `QueryError` for invalid query inputs.
    pub fn get_many_sorted_into<'a>(
        &'a self,
        keys: &[&str],
        out: &mut [Option<&'a CborValue>],
    ) -> Result<(), QueryError> {
        if keys.len() != out.len() {
            return Err(QueryError::new(QueryErrorCode::InvalidQuery, 0));
        }

        for slot in out.iter_mut() {
            *slot = None;
        }

        ensure_strictly_increasing_keys(keys, 0)?;

        if keys.is_empty() || self.is_empty() {
            return Ok(());
        }

        let mut it = self.iter().peekable();

        for (i, &qk) in keys.iter().enumerate() {
            loop {
                let Some((mk, mv)) = it.peek().copied() else {
                    break;
                };

                match cmp_text_keys_canon(mk, qk) {
                    Ordering::Less => {
                        it.next();
                    }
                    Ordering::Equal => {
                        out[i] = Some(mv);
                        it.next();
                        break;
                    }
                    Ordering::Greater => break,
                }
            }
        }

        Ok(())
    }
}

/* =========================
 * Internal parsing helpers
 * ========================= */

#[derive(Clone, Copy)]
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    fn read_u8(&mut self, off: usize) -> Result<u8, QueryError> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| QueryError::malformed(off))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_exact(&mut self, n: usize, off: usize) -> Result<&'a [u8], QueryError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| QueryError::malformed(off))?;
        if end > self.data.len() {
            return Err(QueryError::malformed(off));
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn read_uint(&mut self, ai: u8, off: usize) -> Result<u64, QueryError> {
        match ai {
            0..=23 => Ok(u64::from(ai)),
            24 => Ok(u64::from(self.read_u8(off)?)),
            25 => {
                let s = self.read_exact(2, off)?;
                Ok(u64::from(u16::from_be_bytes([s[0], s[1]])))
            }
            26 => {
                let s = self.read_exact(4, off)?;
                Ok(u64::from(u32::from_be_bytes([s[0], s[1], s[2], s[3]])))
            }
            27 => {
                let s = self.read_exact(8, off)?;
                Ok(u64::from_be_bytes([
                    s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
                ]))
            }
            // Indefinite length and reserved AIs are forbidden in this crate's canonical profile.
            _ => Err(QueryError::malformed(off)),
        }
    }

    fn read_len(&mut self, ai: u8, off: usize) -> Result<usize, QueryError> {
        let n = self.read_uint(ai, off)?;
        usize::try_from(n).map_err(|_| QueryError::malformed(off))
    }

    fn skip_value(&mut self) -> Result<(), QueryError> {
        let off = self.pos;
        let ib = self.read_u8(off)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        match major {
            0 | 1 => {
                let _ = self.read_uint(ai, off)?;
                Ok(())
            }
            2 | 3 => {
                let len = self.read_len(ai, off)?;
                let _ = self.read_exact(len, off)?;
                Ok(())
            }
            4 => {
                let len = self.read_len(ai, off)?;
                for _ in 0..len {
                    self.skip_value()?;
                }
                Ok(())
            }
            5 => {
                let len = self.read_len(ai, off)?;
                for _ in 0..len {
                    self.skip_value()?; // key
                    self.skip_value()?; // value
                }
                Ok(())
            }
            6 => {
                // Only tag 2/3 are supported, and they must wrap a byte string.
                let tag = self.read_uint(ai, off)?;
                if tag != 2 && tag != 3 {
                    return Err(QueryError::malformed(off));
                }
                let inner_off = self.pos;
                let first = self.read_u8(inner_off)?;
                if (first >> 5) != 2 {
                    return Err(QueryError::malformed(inner_off));
                }
                let len = self.read_len(first & 0x1f, inner_off)?;
                let _ = self.read_exact(len, inner_off)?;
                Ok(())
            }
            7 => match ai {
                20..=22 => Ok(()),
                27 => {
                    let _ = self.read_exact(8, off)?;
                    Ok(())
                }
                _ => Err(QueryError::malformed(off)),
            },
            _ => Err(QueryError::malformed(off)),
        }
    }
}

#[derive(Clone, Copy)]
struct CachedKey<'a> {
    key_bytes: &'a [u8],
    key_enc_len: usize,
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

    fn fill_cache(&mut self) -> Result<(), QueryError> {
        if self.cached.is_none() {
            let mut c = Cursor::new(self.data, self.pos);
            let parsed = read_text(&mut c)?;
            let value_start = c.pos;
            self.pos = value_start;
            self.cached = Some(CachedKey {
                key_bytes: parsed.bytes,
                key_enc_len: parsed.enc_len,
                value_start,
            });
        }
        Ok(())
    }

    fn consume_cached_entry(&mut self, ck: CachedKey<'a>) -> Result<usize, QueryError> {
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
    ) -> Result<usize, QueryError>
    where
        F: FnOnce(usize),
    {
        let Some(ck) = self.cached else {
            return Ok(q_idx);
        };

        match cmp_text_key_bytes_to_query(ck.key_bytes, ck.key_enc_len, query) {
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
}

#[derive(Clone, Copy)]
struct ParsedText<'a> {
    s: &'a str,
    bytes: &'a [u8],
    enc_len: usize,
}

fn read_text<'a>(c: &mut Cursor<'a>) -> Result<ParsedText<'a>, QueryError> {
    let off = c.pos;
    let ib = c.read_u8(off)?;
    let major = ib >> 5;
    let ai = ib & 0x1f;

    if major != 3 {
        return Err(QueryError::malformed(off));
    }

    let len = c.read_len(ai, off)?;
    let bytes = c.read_exact(len, off)?;
    let s = core::str::from_utf8(bytes).map_err(|_| QueryError::malformed(off))?;
    let enc_len = c.pos - off;

    Ok(ParsedText { s, bytes, enc_len })
}

fn value_end(data: &[u8], start: usize) -> Result<usize, QueryError> {
    let mut c = Cursor::new(data, start);
    c.skip_value()?;
    Ok(c.pos)
}

fn parse_map_header(data: &[u8], start: usize) -> Result<(usize, usize), QueryError> {
    let mut c = Cursor::new(data, start);
    let off = start;
    let ib = c.read_u8(off)?;
    let major = ib >> 5;
    let ai = ib & 0x1f;

    if major != 5 {
        return Err(QueryError::expected_map(off));
    }

    let len = c.read_len(ai, off)?;
    Ok((len, c.pos))
}

fn parse_array_header(data: &[u8], start: usize) -> Result<(usize, usize), QueryError> {
    let mut c = Cursor::new(data, start);
    let off = start;
    let ib = c.read_u8(off)?;
    let major = ib >> 5;
    let ai = ib & 0x1f;

    if major != 4 {
        return Err(QueryError::expected_array(off));
    }

    let len = c.read_len(ai, off)?;
    Ok((len, c.pos))
}

const fn add_or_max(a: usize, b: usize) -> usize {
    match a.checked_add(b) {
        Some(v) => v,
        None => usize::MAX,
    }
}

const fn encoded_text_len(n: usize) -> usize {
    if n < 24 {
        add_or_max(1, n)
    } else if n <= 0xff {
        add_or_max(2, n)
    } else if n <= 0xffff {
        add_or_max(3, n)
    } else if n <= 0xffff_ffff {
        add_or_max(5, n)
    } else {
        add_or_max(9, n)
    }
}

fn cmp_text_keys_canon(a: &str, b: &str) -> Ordering {
    let a_len = encoded_text_len(a.len());
    let b_len = encoded_text_len(b.len());

    match a_len.cmp(&b_len) {
        Ordering::Equal => a.as_bytes().cmp(b.as_bytes()),
        other => other,
    }
}

fn cmp_text_key_bytes_to_query(key_payload: &[u8], key_enc_len: usize, query: &str) -> Ordering {
    let q_bytes = query.as_bytes();
    let q_enc_len = encoded_text_len(q_bytes.len());

    match key_enc_len.cmp(&q_enc_len) {
        Ordering::Equal => key_payload.cmp(q_bytes),
        other => other,
    }
}

fn ensure_strictly_increasing_keys(keys: &[&str], err_off: usize) -> Result<(), QueryError> {
    let mut prev: Option<&str> = None;

    for &k in keys {
        if let Some(p) = prev {
            match cmp_text_keys_canon(p, k) {
                Ordering::Less => {}
                Ordering::Equal => {
                    return Err(QueryError::new(QueryErrorCode::DuplicateQueryKey, err_off));
                }
                Ordering::Greater => {
                    return Err(QueryError::new(QueryErrorCode::KeysNotSorted, err_off));
                }
            }
        }
        prev = Some(k);
    }

    Ok(())
}

struct MapIter<'a> {
    data: &'a [u8],
    pos: usize,
    remaining: usize,
}

impl<'a> Iterator for MapIter<'a> {
    type Item = Result<(&'a str, CborValueRef<'a>), QueryError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        let mut c = Cursor::new(self.data, self.pos);
        let parsed = match read_text(&mut c) {
            Ok(v) => v,
            Err(e) => {
                self.remaining = 0;
                return Some(Err(e));
            }
        };

        let value_start = c.pos;
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
    type Item = Result<CborValueRef<'a>, QueryError>;

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
