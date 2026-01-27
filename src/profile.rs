use core::cmp::Ordering;

use crate::ErrorCode;

/// Maximum safe integer (2^53-1).
///
/// SACP-CBOR/1 permits major-type integers only in the safe range
/// `[-(2^53-1), +(2^53-1)]`.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Maximum safe integer as i64 (2^53-1).
pub const MAX_SAFE_INTEGER_I64: i64 = 9_007_199_254_740_991;

/// Minimum safe integer (-(2^53-1)).
pub const MIN_SAFE_INTEGER: i64 = -MAX_SAFE_INTEGER_I64;

/// Canonical big-endian bytes of `MAX_SAFE_INTEGER` (2^53-1) with leading zeros stripped.
///
/// 2^53-1 = `0x001f_ffff_ffff_ffff`, so the canonical magnitude is 7 bytes:
/// `1f ff ff ff ff ff ff`.
const MAX_SAFE_INTEGER_BE: [u8; 7] = [0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

/// Canonical NaN bit pattern for SACP-CBOR/1 float64.
pub const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;
/// Negative zero bit pattern (forbidden).
pub const NEGATIVE_ZERO_BITS: u64 = 0x8000_0000_0000_0000;

const EXP_MASK: u64 = 0x7ff0_0000_0000_0000;
const MANT_MASK: u64 = 0x000f_ffff_ffff_ffff;

/// Validate an IEEE-754 f64 bit pattern for SACP-CBOR/1.
#[inline]
pub const fn validate_f64_bits(bits: u64) -> Result<(), ErrorCode> {
    if bits == NEGATIVE_ZERO_BITS {
        return Err(ErrorCode::NegativeZeroForbidden);
    }

    let is_nan = (bits & EXP_MASK) == EXP_MASK && (bits & MANT_MASK) != 0;
    if is_nan && bits != CANONICAL_NAN_BITS {
        return Err(ErrorCode::NonCanonicalNaN);
    }

    Ok(())
}

/// Validate that an i64 is within the SACP-CBOR/1 safe integer range.
#[inline]
#[cfg(feature = "alloc")]
pub const fn validate_int_safe_i64(v: i64) -> Result<(), ErrorCode> {
    if v < MIN_SAFE_INTEGER || v > MAX_SAFE_INTEGER_I64 {
        return Err(ErrorCode::IntegerOutsideSafeRange);
    }
    Ok(())
}

/// Validate that a bignum magnitude is canonical and outside the safe range.
pub fn validate_bignum_bytes(negative: bool, magnitude: &[u8]) -> Result<(), ErrorCode> {
    if magnitude.is_empty() || magnitude[0] == 0 {
        return Err(ErrorCode::BignumNotCanonical);
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
        return Err(ErrorCode::BignumMustBeOutsideSafeRange);
    }

    Ok(())
}

fn cmp_big_endian(a: &[u8], b: &[u8]) -> Ordering {
    match a.len().cmp(&b.len()) {
        Ordering::Equal => a.cmp(b),
        other => other,
    }
}

/// Compare two CBOR-encoded map keys by the canonical CBOR ordering rule.
///
/// Canonical ordering is:
/// 1) shorter encoded byte string sorts first, then
/// 2) lexicographic byte comparison.
///
/// This is used by the validator when it already has the encoded key slices.
#[inline]
#[must_use]
pub fn cmp_encoded_key_bytes(a: &[u8], b: &[u8]) -> Ordering {
    match a.len().cmp(&b.len()) {
        Ordering::Equal => a.cmp(b),
        other => other,
    }
}

/// Returns true iff `prev < curr` under canonical CBOR ordering (by encoded bytes).
#[inline]
#[must_use]
pub fn is_strictly_increasing_encoded(prev: &[u8], curr: &[u8]) -> bool {
    cmp_encoded_key_bytes(prev, curr) == Ordering::Less
}

/// Compare two UTF-8 text keys by SACP-CBOR/1 canonical map ordering.
///
/// For SACP-CBOR/1 maps, keys are restricted to CBOR text strings. Canonical map ordering is defined
/// over the *canonical CBOR encoding* of each key:
///
/// 1) shorter encoded key sorts first (this includes the header bytes), then
/// 2) lexicographic ordering of the encoded key bytes.
///
/// For text strings, encoded length is strictly monotone in payload length, so this reduces to
/// comparing payload lengths and then the UTF-8 bytes.
#[inline]
#[must_use]
pub fn cmp_text_keys_by_canonical_encoding(a: &str, b: &str) -> Ordering {
    match a.len().cmp(&b.len()) {
        Ordering::Equal => a.as_bytes().cmp(b.as_bytes()),
        other => other,
    }
}

/// Return the length in bytes of the canonical CBOR encoding of a text string payload of length `n`.
///
/// This is `header_len(n) + n`, where `header_len(n)` depends on the canonical CBOR length encoding:
///
/// - `n < 24`   => 1-byte header
/// - `n <= 255` => 2-byte header
/// - `n <= 65535` => 3-byte header
/// - `n <= 2^32-1` => 5-byte header
/// - otherwise => 9-byte header
#[inline]
pub fn checked_text_len(n: usize) -> Result<u64, ErrorCode> {
    let n_u64 = u64::try_from(n).map_err(|_| ErrorCode::LengthOverflow)?;
    let header = if n < 24 {
        1
    } else if n <= 0xff {
        2
    } else if n <= 0xffff {
        3
    } else if n <= 0xffff_ffff {
        5
    } else {
        9
    };
    n_u64.checked_add(header).ok_or(ErrorCode::LengthOverflow)
}
