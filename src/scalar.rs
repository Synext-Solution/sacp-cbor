use crate::profile::{validate_f64_bits, CANONICAL_NAN_BITS, NEGATIVE_ZERO_BITS};
use crate::{CborError, ErrorCode};

/// A validated float64 bit-pattern suitable for SACP-CBOR/1 encoding.
///
/// - Encoded as CBOR float64 (major 7, ai 27).
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
    #[cfg(feature = "alloc")]
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
