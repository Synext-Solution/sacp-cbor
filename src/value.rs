use alloc::vec::Vec;

use crate::profile::{validate_bignum_bytes, validate_int_safe_i64};
use crate::CborError;

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
}

impl From<BigInt> for CborInteger {
    fn from(value: BigInt) -> Self {
        Self(IntegerRepr::Big(value))
    }
}
