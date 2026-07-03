//! Arbitrary-precision integer support for schema bounds and enum members.

use alloc::vec::Vec;
use core::cmp::Ordering;

use sacp_cbor::query::IntegerRef;
use sacp_cbor::{profile, Encoder};

use crate::SchemaError;

/// Normalized arbitrary-precision integer.
///
/// The representation is sign plus absolute big-endian magnitude. Zero is always non-negative and
/// has an empty magnitude.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Int {
    negative: bool,
    magnitude: Vec<u8>,
}

impl Int {
    /// Construct an integer from sign and absolute big-endian magnitude bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaError::NonNormalizedInt`] when the input has a leading zero byte or encodes
    /// negative zero.
    pub fn from_sign_magnitude(negative: bool, magnitude: &[u8]) -> Result<Self, SchemaError> {
        if magnitude.first() == Some(&0) || (negative && magnitude.is_empty()) {
            return Err(SchemaError::NonNormalizedInt);
        }
        Ok(Self {
            negative,
            magnitude: magnitude.to_vec(),
        })
    }

    /// Returns `true` when this integer is negative.
    #[must_use]
    pub const fn is_negative(&self) -> bool {
        self.negative
    }

    /// Returns the normalized absolute big-endian magnitude.
    #[must_use]
    pub fn magnitude(&self) -> &[u8] {
        &self.magnitude
    }

    /// Returns `true` when this integer is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.magnitude.is_empty()
    }

    pub(crate) fn encode_canonical(&self) -> Result<Vec<u8>, SchemaError> {
        let mut enc = Encoder::new();
        if let Some(v) = self.as_safe_i64() {
            enc.int(v).map_err(SchemaError::CanonicalEncodingFailed)?;
        } else if self.negative {
            let mag = self.negative_bignum_magnitude();
            enc.bignum(true, &mag)
                .map_err(SchemaError::CanonicalEncodingFailed)?;
        } else {
            enc.bignum(false, &self.magnitude)
                .map_err(SchemaError::CanonicalEncodingFailed)?;
        }
        let canon = enc.finish().map_err(SchemaError::CanonicalEncodingFailed)?;
        Ok(canon.into_bytes())
    }

    fn as_safe_i64(&self) -> Option<i64> {
        let mag = magnitude_to_u64(&self.magnitude)?;
        let max = u64::try_from(profile::MAX_SAFE_INTEGER_I64).ok()?;
        if mag > max {
            return None;
        }
        if self.negative {
            let signed = i64::try_from(mag).ok()?;
            Some(-signed)
        } else {
            i64::try_from(mag).ok()
        }
    }

    fn negative_bignum_magnitude(&self) -> Vec<u8> {
        debug_assert!(self.negative);
        debug_assert!(!self.magnitude.is_empty());

        let mut out = self.magnitude.clone();
        let mut idx = out.len();
        while idx > 0 {
            idx -= 1;
            if out[idx] == 0 {
                out[idx] = 0xff;
            } else {
                out[idx] -= 1;
                break;
            }
        }
        while out.first() == Some(&0) {
            out.remove(0);
        }
        out
    }
}

impl Ord for Int {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.negative, other.negative) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => cmp_abs(&self.magnitude, &other.magnitude),
            (true, true) => cmp_abs(&other.magnitude, &self.magnitude),
        }
    }
}

impl PartialOrd for Int {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<u128> for Int {
    fn from(value: u128) -> Self {
        Self {
            negative: false,
            magnitude: magnitude_from_u128(value),
        }
    }
}

impl From<u64> for Int {
    fn from(value: u64) -> Self {
        Self::from(u128::from(value))
    }
}

impl From<i128> for Int {
    fn from(value: i128) -> Self {
        if value < 0 {
            Self {
                negative: true,
                magnitude: magnitude_from_u128(value.unsigned_abs()),
            }
        } else {
            Self {
                negative: false,
                magnitude: magnitude_from_u128(value.unsigned_abs()),
            }
        }
    }
}

impl From<i64> for Int {
    fn from(value: i64) -> Self {
        Self::from(i128::from(value))
    }
}

pub(crate) fn cmp_integer_ref_to_int(value: IntegerRef<'_>, bound: &Int) -> Ordering {
    match value {
        IntegerRef::Safe(v) => cmp_safe_to_int(v, bound),
        IntegerRef::Big(big) if big.is_negative() => {
            cmp_big_negative_to_int(big.magnitude(), bound)
        }
        IntegerRef::Big(big) => cmp_signed_abs_to_int(false, big.magnitude(), bound),
    }
}

fn cmp_safe_to_int(value: i64, bound: &Int) -> Ordering {
    let negative = value < 0;
    let abs = value.unsigned_abs();
    let (buf, len) = magnitude_from_u64_array(abs);
    cmp_signed_abs_to_int(negative, &buf[..len], bound)
}

fn cmp_big_negative_to_int(tag_magnitude: &[u8], bound: &Int) -> Ordering {
    if !bound.negative {
        return Ordering::Less;
    }
    cmp_incremented_abs_to_slice(&bound.magnitude, tag_magnitude)
}

fn cmp_signed_abs_to_int(negative: bool, magnitude: &[u8], bound: &Int) -> Ordering {
    match (negative, bound.negative) {
        (false, true) => Ordering::Greater,
        (true, false) => Ordering::Less,
        (false, false) => cmp_abs(magnitude, &bound.magnitude),
        (true, true) => cmp_abs(&bound.magnitude, magnitude),
    }
}

fn cmp_abs(a: &[u8], b: &[u8]) -> Ordering {
    match a.len().cmp(&b.len()) {
        Ordering::Equal => a.cmp(b),
        other => other,
    }
}

fn cmp_incremented_abs_to_slice(bound_abs: &[u8], tag_magnitude: &[u8]) -> Ordering {
    let Some(pivot) = tag_magnitude.iter().rposition(|&b| b != 0xff) else {
        let inc_len = tag_magnitude.len().saturating_add(1);
        return match bound_abs.len().cmp(&inc_len) {
            Ordering::Equal => {
                let first_cmp = bound_abs.first().copied().unwrap_or_default().cmp(&1);
                if first_cmp != Ordering::Equal {
                    return first_cmp;
                }
                if bound_abs.iter().skip(1).any(|&b| b != 0) {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                }
            }
            other => other,
        };
    };

    match bound_abs.len().cmp(&tag_magnitude.len()) {
        Ordering::Equal => {
            for (idx, &bound_byte) in bound_abs.iter().enumerate() {
                let inc_byte = match idx.cmp(&pivot) {
                    Ordering::Less => tag_magnitude[idx],
                    Ordering::Equal => tag_magnitude[idx].saturating_add(1),
                    Ordering::Greater => 0,
                };
                match bound_byte.cmp(&inc_byte) {
                    Ordering::Equal => {}
                    other => return other,
                }
            }
            Ordering::Equal
        }
        other => other,
    }
}

fn magnitude_from_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

fn magnitude_from_u64_array(value: u64) -> ([u8; 8], usize) {
    if value == 0 {
        return ([0; 8], 0);
    }
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let mut out = [0u8; 8];
    let len = bytes.len() - first;
    out[..len].copy_from_slice(&bytes[first..]);
    (out, len)
}

fn magnitude_to_u64(magnitude: &[u8]) -> Option<u64> {
    if magnitude.len() > 8 {
        return None;
    }
    let mut out = 0u64;
    for &b in magnitude {
        out = (out << 8) | u64::from(b);
    }
    Some(out)
}
