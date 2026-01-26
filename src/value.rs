use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::encode;
use crate::profile::{
    checked_text_len, cmp_text_keys_by_canonical_encoding, validate_bignum_bytes,
    validate_f64_bits, validate_int_safe_i64, CANONICAL_NAN_BITS, NEGATIVE_ZERO_BITS,
};
use crate::{CborError, ErrorCode};

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
        validate_bignum_bytes(negative, &magnitude).map_err(|code| CborError::new(code, 0))?;
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
        validate_f64_bits(bits).map_err(|code| CborError::new(code, 0))?;
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
            return Err(CborError::new(ErrorCode::NegativeZeroForbidden, 0));
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
    entries: Box<[(Box<str>, CborValue)]>,
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
    pub fn new(mut entries: Vec<(Box<str>, CborValue)>) -> Result<Self, CborError> {
        for (k, _) in &entries {
            checked_text_len(k.len()).map_err(|code| CborError::new(code, 0))?;
        }
        entries.sort_by(|(ka, _), (kb, _)| cmp_text_keys_by_canonical_encoding(ka, kb));

        for w in entries.windows(2) {
            if w[0].0 == w[1].0 {
                return Err(CborError::new(ErrorCode::DuplicateMapKey, 0));
            }
        }

        Ok(Self {
            entries: entries.into_boxed_slice(),
        })
    }

    /// Internal constructor used by the decoder; assumes entries are already in canonical order and unique.
    #[inline]
    pub(crate) fn from_sorted_entries(entries: Vec<(Box<str>, CborValue)>) -> Self {
        Self {
            entries: entries.into_boxed_slice(),
        }
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
        self.entries.iter().map(|(k, v)| (k.as_ref(), v))
    }

    #[inline]
    pub(crate) fn entries(&self) -> &[(Box<str>, CborValue)] {
        &self.entries
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

/// An integer value permitted by SACP-CBOR/1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CborInteger(IntegerRepr);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegerRepr {
    Safe(i64),
    Big(BigInt),
}

impl CborInteger {
    /// Construct a safe-range integer.
    ///
    /// # Errors
    ///
    /// Returns `IntegerOutsideSafeRange` if the value is outside the safe range.
    pub fn safe(value: i64) -> Result<Self, CborError> {
        validate_int_safe_i64(value).map_err(|code| CborError::new(code, 0))?;
        Ok(Self(IntegerRepr::Safe(value)))
    }

    /// Construct a bignum integer from sign and magnitude bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the magnitude is not canonical or is within the safe integer range.
    pub fn big(negative: bool, magnitude: Vec<u8>) -> Result<Self, CborError> {
        Ok(Self(IntegerRepr::Big(BigInt::new(negative, magnitude)?)))
    }

    /// Construct a bignum integer from an existing `BigInt`.
    #[inline]
    #[must_use]
    pub const fn from_bigint(big: BigInt) -> Self {
        Self(IntegerRepr::Big(big))
    }

    /// Returns `true` iff this is a safe-range integer.
    #[inline]
    #[must_use]
    pub const fn is_safe(&self) -> bool {
        matches!(self.0, IntegerRepr::Safe(_))
    }

    /// Returns `true` iff this is a bignum integer.
    #[inline]
    #[must_use]
    pub const fn is_big(&self) -> bool {
        matches!(self.0, IntegerRepr::Big(_))
    }

    /// Return the safe integer value if available.
    #[inline]
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        match &self.0 {
            IntegerRepr::Safe(v) => Some(*v),
            IntegerRepr::Big(_) => None,
        }
    }

    /// Return the underlying bignum if available.
    #[inline]
    #[must_use]
    pub const fn as_bigint(&self) -> Option<&BigInt> {
        match &self.0 {
            IntegerRepr::Big(b) => Some(b),
            IntegerRepr::Safe(_) => None,
        }
    }

    #[inline]
    pub(crate) const fn new_safe_unchecked(value: i64) -> Self {
        Self(IntegerRepr::Safe(value))
    }
}

impl From<BigInt> for CborInteger {
    fn from(value: BigInt) -> Self {
        Self(IntegerRepr::Big(value))
    }
}

/// An owned representation of SACP-CBOR/1 values.
///
/// This type can represent any data item permitted by SACP-CBOR/1. It can be encoded into canonical
/// CBOR using [`CborValue::encode_canonical`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CborValue(ValueRepr);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueRepr {
    Integer(CborInteger),
    Bytes(Vec<u8>),
    Text(Box<str>),
    Array(Box<[CborValue]>),
    Map(CborMap),
    Bool(bool),
    Null,
    Float(F64Bits),
}

impl CborValue {
    /// Construct from a validated integer.
    #[inline]
    #[must_use]
    pub const fn integer(value: CborInteger) -> Self {
        Self(ValueRepr::Integer(value))
    }

    /// Construct a safe-range integer.
    ///
    /// # Errors
    ///
    /// Returns `IntegerOutsideSafeRange` if the value is outside the safe range.
    pub fn int(value: i64) -> Result<Self, CborError> {
        Ok(Self(ValueRepr::Integer(CborInteger::safe(value)?)))
    }

    /// Construct a bignum integer from sign and magnitude bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the magnitude is not canonical or is within the safe integer range.
    pub fn bigint(negative: bool, magnitude: Vec<u8>) -> Result<Self, CborError> {
        Ok(Self(ValueRepr::Integer(CborInteger::big(
            negative, magnitude,
        )?)))
    }

    /// Construct a byte-string value.
    #[inline]
    #[must_use]
    pub const fn bytes(bytes: Vec<u8>) -> Self {
        Self(ValueRepr::Bytes(bytes))
    }

    /// Convenience constructor for a text value.
    #[must_use]
    pub fn text<S: Into<Box<str>>>(s: S) -> Self {
        Self(ValueRepr::Text(s.into()))
    }

    /// Construct an array value.
    #[inline]
    #[must_use]
    pub fn array(items: impl Into<Box<[Self]>>) -> Self {
        Self(ValueRepr::Array(items.into()))
    }

    /// Construct a map value.
    #[inline]
    #[must_use]
    pub const fn map(map: CborMap) -> Self {
        Self(ValueRepr::Map(map))
    }

    /// Construct a boolean value.
    #[inline]
    #[must_use]
    pub const fn bool(value: bool) -> Self {
        Self(ValueRepr::Bool(value))
    }

    /// Construct a null value.
    #[inline]
    #[must_use]
    pub const fn null() -> Self {
        Self(ValueRepr::Null)
    }

    /// Construct a float64 value from validated bits.
    #[inline]
    #[must_use]
    pub const fn float(bits: F64Bits) -> Self {
        Self(ValueRepr::Float(bits))
    }

    /// Construct a float64 value from an `f64`.
    /// Construct a float64 value.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is negative zero.
    pub fn float64(value: f64) -> Result<Self, CborError> {
        Ok(Self::float(F64Bits::try_from_f64(value)?))
    }

    /// Borrow the integer value, if present.
    #[inline]
    #[must_use]
    pub const fn as_integer(&self) -> Option<&CborInteger> {
        match &self.0 {
            ValueRepr::Integer(i) => Some(i),
            _ => None,
        }
    }

    /// Borrow the safe integer value, if present.
    #[inline]
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        self.as_integer().and_then(CborInteger::as_i64)
    }

    /// Borrow the bignum value, if present.
    #[inline]
    #[must_use]
    pub fn as_bigint(&self) -> Option<&BigInt> {
        self.as_integer().and_then(CborInteger::as_bigint)
    }

    /// Borrow the byte-string payload, if present.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.0 {
            ValueRepr::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Borrow the text value, if present.
    #[inline]
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match &self.0 {
            ValueRepr::Text(s) => Some(s.as_ref()),
            _ => None,
        }
    }

    /// Borrow the array payload, if present.
    #[inline]
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match &self.0 {
            ValueRepr::Array(items) => Some(items.as_ref()),
            _ => None,
        }
    }

    /// Borrow the map payload, if present.
    #[inline]
    #[must_use]
    pub const fn as_map(&self) -> Option<&CborMap> {
        match &self.0 {
            ValueRepr::Map(map) => Some(map),
            _ => None,
        }
    }

    /// Return the boolean value, if present.
    #[inline]
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match &self.0 {
            ValueRepr::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns `true` iff this value is null.
    #[inline]
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self.0, ValueRepr::Null)
    }

    /// Return the float value, if present.
    #[inline]
    #[must_use]
    pub const fn as_float(&self) -> Option<F64Bits> {
        match &self.0 {
            ValueRepr::Float(bits) => Some(*bits),
            _ => None,
        }
    }

    /// Encode the value into canonical CBOR bytes according to SACP-CBOR/1.
    ///
    /// # Errors
    ///
    /// Returns an error if allocation fails or lengths overflow on the current target.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, CborError> {
        encode::encode_to_vec(self)
    }

    /// Encode the value into canonical CBOR and compute its SHA-256 digest without allocating.
    ///
    /// This method is available with the `sha2` feature.
    ///
    /// # Errors
    ///
    /// Returns an error if allocation fails or lengths overflow on the current target.
    #[cfg(feature = "sha2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2")))]
    pub fn sha256_canonical(&self) -> Result<[u8; 32], CborError> {
        encode::encode_sha256(self)
    }

    #[inline]
    pub(crate) const fn repr(&self) -> &ValueRepr {
        &self.0
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
