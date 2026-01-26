use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::encode;
use crate::float::{validate_f64_bits, CANONICAL_NAN_BITS, NEGATIVE_ZERO_BITS};
use crate::limits::{MAX_SAFE_INTEGER_I64, MIN_SAFE_INTEGER};
use crate::order::cmp_text_keys_by_canonical_encoding;
use crate::{CborError, CborErrorCode};

/// Canonical big-endian bytes of `MAX_SAFE_INTEGER` (2^53-1) with leading zeros stripped.
///
/// 2^53-1 = `0x001f_ffff_ffff_ffff`, so the canonical magnitude is 7 bytes:
/// `1f ff ff ff ff ff ff`.
const MAX_SAFE_INTEGER_BE: [u8; 7] = [0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

/// A tagged bignum integer (CBOR tag 2 or 3).
///
/// SACP-CBOR/1 represents integers outside the safe range using CBOR tags 2 (positive) and 3 (negative),
/// with a byte string magnitude encoded canonically (non-empty, no leading zeros).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BigInt {
    negative: bool,
    magnitude: Vec<u8>,
}

impl BigInt {
    /// Construct a `BigInt` from sign and big-endian magnitude bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the magnitude is empty or has a leading zero, or
    /// - the represented integer would be within the safe integer range.
    pub fn new(negative: bool, magnitude: Vec<u8>) -> Result<Self, CborError> {
        validate_bignum_bytes(negative, &magnitude).map_err(CborError::encode)?;
        Ok(Self {
            negative,
            magnitude,
        })
    }

    /// Sign flag: `true` if this represents a negative bignum (tag 3).
    #[inline]
    #[must_use]
    pub const fn is_negative(&self) -> bool {
        self.negative
    }

    /// Return the canonical big-endian magnitude bytes.
    #[inline]
    #[must_use]
    pub fn magnitude(&self) -> &[u8] {
        &self.magnitude
    }

    /// Internal constructor used by the decoder after validation.
    #[inline]
    pub(crate) const fn new_unchecked(negative: bool, magnitude: Vec<u8>) -> Self {
        Self {
            negative,
            magnitude,
        }
    }
}

/// A validated float64 bit-pattern suitable for SACP-CBOR/1 encoding.
///
/// - Encoded as CBOR float64 (major 7, additional info 27).
/// - `-0.0` is forbidden.
/// - NaN must use the canonical bit pattern `0x7ff8_0000_0000_0000`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct F64Bits(u64);

impl F64Bits {
    /// Construct from raw IEEE-754 bits.
    ///
    /// # Errors
    ///
    /// Returns an error if bits encode `-0.0` or a non-canonical NaN.
    pub fn new(bits: u64) -> Result<Self, CborError> {
        validate_f64_bits(bits).map_err(CborError::encode)?;
        Ok(Self(bits))
    }

    /// Construct from an `f64` value.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is `-0.0`. NaNs are canonicalized to the required NaN bit pattern.
    pub fn try_from_f64(value: f64) -> Result<Self, CborError> {
        let bits = value.to_bits();
        if bits == NEGATIVE_ZERO_BITS {
            return Err(CborError::encode(CborErrorCode::NegativeZeroForbidden));
        }
        if value.is_nan() {
            return Ok(Self(CANONICAL_NAN_BITS));
        }
        Ok(Self(bits))
    }

    /// Return the raw IEEE-754 bits.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Internal constructor used by the decoder after validation.
    #[inline]
    pub(crate) const fn new_unchecked(bits: u64) -> Self {
        Self(bits)
    }

    /// Convert into an `f64`.
    #[inline]
    #[must_use]
    pub fn to_f64(self) -> f64 {
        f64::from_bits(self.0)
    }
}

/// A map with text keys sorted by canonical CBOR key ordering.
///
/// The ordering is **not** lexicographic by Unicode scalar values; it is by:
/// 1) length of the canonical CBOR encoding of the key, and
/// 2) lexicographic order of the key's UTF-8 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CborMap {
    entries: Vec<(String, CborValue)>,
}

impl CborMap {
    /// Construct a map from unsorted entries.
    ///
    /// The resulting map is sorted by SACP-CBOR/1 canonical key ordering and is validated to contain
    /// no duplicate keys.
    ///
    /// # Errors
    ///
    /// Returns `DuplicateMapKey` if two entries have the same key.
    pub fn new(mut entries: Vec<(String, CborValue)>) -> Result<Self, CborError> {
        entries.sort_by(|(ka, _), (kb, _)| cmp_text_keys_by_canonical_encoding(ka, kb));

        for w in entries.windows(2) {
            if w[0].0 == w[1].0 {
                return Err(CborError::encode(CborErrorCode::DuplicateMapKey));
            }
        }

        Ok(Self { entries })
    }

    /// Internal constructor used by the decoder; assumes entries are already in canonical order and unique.
    #[inline]
    pub(crate) const fn from_sorted_entries(entries: Vec<(String, CborValue)>) -> Self {
        Self { entries }
    }

    /// Number of key/value pairs.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` iff the map has no entries.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over map entries in canonical key order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&str, &CborValue)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Get a value by key using canonical key ordering.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&CborValue> {
        let idx = self
            .entries
            .binary_search_by(|(k, _)| cmp_text_keys_by_canonical_encoding(k, key))
            .ok()?;
        Some(&self.entries[idx].1)
    }
}

/// An owned representation of SACP-CBOR/1 values.
///
/// This type can represent any data item permitted by SACP-CBOR/1. It can be encoded into canonical
/// CBOR using [`CborValue::encode_canonical`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborValue {
    /// Safe integer in the range `[-(2^53-1), +(2^53-1)]`.
    Int(i64),
    /// Bignum integer (tag 2/3), always outside the safe integer range.
    Bignum(BigInt),
    /// Byte string.
    Bytes(Vec<u8>),
    /// Text string (valid UTF-8).
    Text(String),
    /// Array.
    Array(Vec<CborValue>),
    /// Map with text keys in canonical key order.
    Map(CborMap),
    /// Boolean.
    Bool(bool),
    /// Null.
    Null,
    /// Float64 with SACP-CBOR/1 restrictions.
    Float(F64Bits),
}

impl CborValue {
    /// Encode the value into canonical CBOR bytes according to SACP-CBOR/1.
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be represented under SACP-CBOR/1 (e.g., integer outside
    /// `int_safe`, map keys not sorted, invalid bignum, invalid float bits).
    pub fn encode_canonical(&self) -> Result<Vec<u8>, CborError> {
        encode::encode_to_vec(self)
    }

    /// Encode the value into canonical CBOR and compute its SHA-256 digest without allocating.
    ///
    /// This method is available with the `sha2` feature.
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be represented under SACP-CBOR/1.
    #[cfg(feature = "sha2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2")))]
    pub fn sha256_canonical(&self) -> Result<[u8; 32], CborError> {
        encode::encode_sha256(self)
    }

    /// Convenience constructor for a text value.
    #[must_use]
    pub fn text<S: AsRef<str>>(s: S) -> Self {
        Self::Text(s.as_ref().to_string())
    }
}

/// Strict structural equality for SACP-CBOR/1 values.
///
/// Since the type enforces canonical constraints (for floats and bignums), this is also a
/// reasonable semantic equality for protocol use.
#[inline]
#[must_use]
pub fn cbor_equal(a: &CborValue, b: &CborValue) -> bool {
    a == b
}

fn validate_bignum_bytes(negative: bool, magnitude: &[u8]) -> Result<(), CborErrorCode> {
    if magnitude.is_empty() || magnitude[0] == 0 {
        return Err(CborErrorCode::BignumNotCanonical);
    }

    let cmp = cmp_big_endian(magnitude, &MAX_SAFE_INTEGER_BE);

    let outside = if negative {
        // tag 3: value is -1 - n. Safe ints cover n <= MAX_SAFE_INTEGER-1.
        cmp != Ordering::Less
    } else {
        // tag 2: value is +n. Safe ints cover n <= MAX_SAFE_INTEGER.
        cmp == Ordering::Greater
    };

    if !outside {
        return Err(CborErrorCode::BignumMustBeOutsideSafeRange);
    }

    Ok(())
}

fn cmp_big_endian(a: &[u8], b: &[u8]) -> Ordering {
    match a.len().cmp(&b.len()) {
        Ordering::Equal => a.cmp(b),
        other => other,
    }
}

// Encode-time helpers used by the encoder; these map to `Encode` errors.
pub const fn validate_int_safe_i64(v: i64) -> Result<(), CborErrorCode> {
    if v < MIN_SAFE_INTEGER || v > MAX_SAFE_INTEGER_I64 {
        return Err(CborErrorCode::IntegerOutsideSafeRange);
    }
    Ok(())
}

pub fn validate_bignum(negative: bool, magnitude: &[u8]) -> Result<(), CborErrorCode> {
    validate_bignum_bytes(negative, magnitude)
}

pub const fn validate_f64(bits: u64) -> Result<(), CborErrorCode> {
    validate_f64_bits(bits)
}
