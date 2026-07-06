//! Interoperability bridge between SACP-CBOR/1 and RFC 8949 Core Deterministic
//! Encoding (CDE).
//!
//! Both profiles are deterministic encodings of the same data model and differ
//! in exactly two normal forms:
//!
//! - **Integers.** CDE (preferred serialization) head-encodes every integer
//!   whose argument fits an unsigned 64-bit head (major types 0/1) and uses
//!   tags 2/3 only beyond that. SACP-CBOR/1 head-encodes only the safe range
//!   `[-(2^53-1), +(2^53-1)]` and uses tags 2/3 for every larger integer.
//! - **Floats.** CDE uses the shortest of float16/float32/float64 that
//!   preserves the value, with `0xf97e00` as the preferred NaN. SACP-CBOR/1
//!   uses float64 only, with a single canonical NaN bit pattern.
//!
//! Everything else — definite lengths, shortest-form heads, byte/text/array/map
//! layout, and text-key map order — coincides byte for byte: for text keys the
//! SACP-CBOR/1 length-first key order equals the CDE bytewise order of encoded
//! keys, because the canonical text header is a strictly monotone function of
//! the payload length.
//!
//! [`to_cde`] is total over SACP-CBOR/1: every canonical item has exactly one
//! CDE image. [`from_cde`] is partial: CDE admits values SACP-CBOR/1 excludes —
//! non-text map keys, tags other than 2/3, simple values beyond
//! false/true/null, negative zero, NaNs other than `0xf97e00` — and each is
//! rejected with the matching typed error. On the shared subset the two
//! functions are mutually inverse: `from_cde(to_cde(x)) == x` for every
//! canonical `x`, and `to_cde(from_cde(y)) == y` for every accepted `y`.
//!
//! Array element order is preserved verbatim in both directions. A schema
//! layer that imposes an order over encoded element bytes (a sorted-set
//! convention) re-canonicalizes that order under the target profile itself;
//! this bridge carries values, not schema conventions.

use alloc::vec::Vec;

use crate::alloc_util::try_reserve;
use crate::canonical::{CanonicalCbor, CanonicalCborRef};
use crate::encode::major_uint_header;
use crate::error::{CborError, ErrorCode};
use crate::limits::DecodeLimits;
use crate::profile::{CANONICAL_NAN_BITS, MAX_SAFE_INTEGER, NEGATIVE_ZERO_BITS};
use crate::wire::{read_exact, read_len_at, read_u8, read_uint_arg_at};

const MAJOR_UNSIGNED: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;

const TAG_POSITIVE_BIGNUM: u64 = 2;
const TAG_NEGATIVE_BIGNUM: u64 = 3;

/// CDE preferred NaN: float16 quiet NaN with an empty payload.
const CDE_NAN_F16: [u8; 3] = [0xf9, 0x7e, 0x00];

const F64_EXP_MASK: u64 = 0x7ff0_0000_0000_0000;
const F64_MANT_MASK: u64 = 0x000f_ffff_ffff_ffff;

/// Convert one canonical SACP-CBOR/1 item to its RFC 8949 CDE image.
///
/// Total: every canonical item has exactly one CDE image, and the image is
/// never longer than the input. Only integer and float spellings are
/// rewritten; every other octet is copied verbatim, so array order, map order,
/// and all container counts are preserved.
///
/// # Errors
///
/// Returns an error only on allocation failure or on bytes that violate the
/// canonical witness contract (`MalformedCanonical`).
pub fn to_cde(item: CanonicalCborRef<'_>) -> Result<Vec<u8>, CborError> {
    let data = item.as_bytes();
    let mut out = Vec::new();
    try_reserve(&mut out, data.len(), 0)?;
    let end = walk_items(data, usize::MAX, |data, pos| {
        cde_image_item(data, pos, &mut out)
    })?;
    if end != data.len() {
        return Err(CborError::new(ErrorCode::MalformedCanonical, end));
    }
    Ok(out)
}

/// Convert one RFC 8949 CDE item to canonical SACP-CBOR/1 bytes.
///
/// The input is untrusted: this function validates CDE-specific canonicality
/// (shortest-form heads and arguments, definite lengths, head-form integers up
/// to the 64-bit bound, minimal bignum magnitudes beyond it, shortest-form
/// floats, the preferred NaN) at input offsets, converts the two deviating
/// normal forms, and then validates the converted image with
/// [`CanonicalCbor::from_vec`], which enforces the remaining SACP-CBOR/1 rules
/// — UTF-8, text-only map keys, key order and uniqueness, and the declared
/// limits. Errors from that second pass report offsets in the converted image,
/// not in the CDE input.
///
/// # Errors
///
/// Rejects, with the matching typed code: truncated or trailing input, reserved
/// or indefinite-length heads, non-shortest spellings (`NonCanonicalEncoding`),
/// tags other than 2/3 or a non-byte-string tag payload
/// (`ForbiddenOrMalformedTag`), empty or zero-led bignum magnitudes
/// (`BignumNotCanonical`), simple values beyond false/true/null
/// (`UnsupportedSimpleValue`), negative zero (`NegativeZeroForbidden`), NaN
/// spellings other than `0xf97e00` (`NonCanonicalNaN`), depth or size beyond
/// `limits`, and every SACP-CBOR/1 violation the second pass detects.
pub fn from_cde(bytes: &[u8], limits: DecodeLimits) -> Result<CanonicalCbor, CborError> {
    limits.validate()?;
    if bytes.len() > limits.max_input_bytes {
        return Err(CborError::new(ErrorCode::MessageLenLimitExceeded, 0));
    }
    let mut out = Vec::new();
    try_reserve(&mut out, bytes.len(), 0)?;
    let end = walk_items(bytes, limits.max_depth, |data, pos| {
        sacp_image_item(data, pos, &mut out)
    })?;
    if end != bytes.len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, end));
    }
    CanonicalCbor::from_vec(out, limits)
}

/// Drives `item` over exactly one complete value: `item` consumes one head
/// (and any scalar payload) and reports `Some(children)` when it opened a
/// container. Returns the end position of the value.
fn walk_items<F>(data: &[u8], max_depth: usize, mut item: F) -> Result<usize, CborError>
where
    F: FnMut(&[u8], &mut usize) -> Result<Option<u64>, CborError>,
{
    let mut pos = 0usize;
    let mut pending: Vec<u64> = Vec::new();
    loop {
        let off = pos;
        if let Some(children) = item(data, &mut pos)? {
            if children > 0 {
                if pending.len() >= max_depth {
                    return Err(CborError::new(ErrorCode::DepthLimitExceeded, off));
                }
                try_reserve(&mut pending, 1, off)?;
                pending.push(children);
                continue;
            }
        }
        // One item is complete; close every container it completes in turn.
        loop {
            match pending.last_mut() {
                None => return Ok(pos),
                Some(remaining) => {
                    *remaining -= 1;
                    if *remaining == 0 {
                        pending.pop();
                    } else {
                        break;
                    }
                }
            }
        }
    }
}

fn emit(out: &mut Vec<u8>, bytes: &[u8], offset: usize) -> Result<(), CborError> {
    try_reserve(out, bytes.len(), offset)?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn emit_uint(out: &mut Vec<u8>, major: u8, value: u64, offset: usize) -> Result<(), CborError> {
    let (header, header_len) = major_uint_header(major, value);
    emit(out, &header[..header_len], offset)
}

/// Map-entry count doubled into an item count (keys and values both walk as
/// items), guarding the arithmetic on hostile lengths.
fn map_children(entries: usize, offset: usize) -> Result<u64, CborError> {
    let entries =
        u64::try_from(entries).map_err(|_| CborError::new(ErrorCode::LengthOverflow, offset))?;
    entries
        .checked_mul(2)
        .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, offset))
}

fn array_children(entries: usize, offset: usize) -> Result<u64, CborError> {
    u64::try_from(entries).map_err(|_| CborError::new(ErrorCode::LengthOverflow, offset))
}

fn minimal_be(value: u64) -> ([u8; 8], usize) {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(7);
    (bytes, first)
}

/// One item of the SACP → CDE direction, over canonical-trusted input.
fn cde_image_item(
    data: &[u8],
    pos: &mut usize,
    out: &mut Vec<u8>,
) -> Result<Option<u64>, CborError> {
    let off = *pos;
    let initial = read_u8(data, pos)?;
    let major = initial >> 5;
    let ai = initial & 0x1f;
    match major {
        MAJOR_UNSIGNED | MAJOR_NEGATIVE => {
            read_uint_arg_at::<false>(data, pos, ai, off)?;
            emit(out, &data[off..*pos], off)?;
            Ok(None)
        }
        MAJOR_BYTES | 3 => {
            let len = read_len_at::<false>(data, pos, ai, off)?;
            read_exact(data, pos, len)?;
            emit(out, &data[off..*pos], off)?;
            Ok(None)
        }
        MAJOR_ARRAY => {
            let len = read_len_at::<false>(data, pos, ai, off)?;
            emit(out, &data[off..*pos], off)?;
            Ok(Some(array_children(len, off)?))
        }
        MAJOR_MAP => {
            let len = read_len_at::<false>(data, pos, ai, off)?;
            emit(out, &data[off..*pos], off)?;
            Ok(Some(map_children(len, off)?))
        }
        MAJOR_TAG => {
            let tag = read_uint_arg_at::<false>(data, pos, ai, off)?;
            let payload_head = read_u8(data, pos)?;
            if !matches!(tag, TAG_POSITIVE_BIGNUM | TAG_NEGATIVE_BIGNUM)
                || payload_head >> 5 != MAJOR_BYTES
            {
                return Err(CborError::new(ErrorCode::MalformedCanonical, off));
            }
            let len = read_len_at::<false>(data, pos, payload_head & 0x1f, off)?;
            let magnitude = read_exact(data, pos, len)?;
            if len <= 8 {
                // The magnitude fits a 64-bit head: CDE head-encodes it.
                let value = magnitude.iter().fold(0u64, |v, b| (v << 8) | u64::from(*b));
                let head_major = if tag == TAG_POSITIVE_BIGNUM {
                    MAJOR_UNSIGNED
                } else {
                    MAJOR_NEGATIVE
                };
                emit_uint(out, head_major, value, off)?;
            } else {
                emit(out, &data[off..*pos], off)?;
            }
            Ok(None)
        }
        MAJOR_SIMPLE => match ai {
            20..=22 => {
                emit(out, &data[off..*pos], off)?;
                Ok(None)
            }
            27 => {
                let payload = read_exact(data, pos, 8)?;
                let bits = u64::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                    payload[6], payload[7],
                ]);
                if bits == CANONICAL_NAN_BITS {
                    emit(out, &CDE_NAN_F16, off)?;
                } else if let Some(half) = f64_bits_to_f16_exact(bits) {
                    let be = half.to_be_bytes();
                    emit(out, &[0xf9, be[0], be[1]], off)?;
                } else {
                    let value = f64::from_bits(bits);
                    #[allow(clippy::cast_possible_truncation)] // rounding probe, exactness checked
                    let narrowed = value as f32;
                    if f64::from(narrowed).to_bits() == bits {
                        let be = narrowed.to_bits().to_be_bytes();
                        emit(out, &[0xfa, be[0], be[1], be[2], be[3]], off)?;
                    } else {
                        emit(out, &data[off..*pos], off)?;
                    }
                }
                Ok(None)
            }
            _ => Err(CborError::new(ErrorCode::MalformedCanonical, off)),
        },
        _ => Err(CborError::new(ErrorCode::MalformedCanonical, off)),
    }
}

/// One item of the CDE → SACP direction, over untrusted input, checking the
/// CDE-specific canonical forms at input offsets.
fn sacp_image_item(
    data: &[u8],
    pos: &mut usize,
    out: &mut Vec<u8>,
) -> Result<Option<u64>, CborError> {
    let off = *pos;
    let initial = read_u8(data, pos)?;
    let major = initial >> 5;
    let ai = initial & 0x1f;
    match major {
        MAJOR_UNSIGNED => {
            let value = read_uint_arg_at::<true>(data, pos, ai, off)?;
            if value <= MAX_SAFE_INTEGER {
                emit(out, &data[off..*pos], off)?;
            } else {
                emit_bignum(out, TAG_POSITIVE_BIGNUM, value, off)?;
            }
            Ok(None)
        }
        MAJOR_NEGATIVE => {
            let argument = read_uint_arg_at::<true>(data, pos, ai, off)?;
            // Value is -1 - argument; the safe range covers arguments up to
            // MAX_SAFE_INTEGER - 1.
            if argument < MAX_SAFE_INTEGER {
                emit(out, &data[off..*pos], off)?;
            } else {
                emit_bignum(out, TAG_NEGATIVE_BIGNUM, argument, off)?;
            }
            Ok(None)
        }
        MAJOR_BYTES | 3 => {
            let len = read_len_at::<true>(data, pos, ai, off)?;
            read_exact(data, pos, len)?;
            emit(out, &data[off..*pos], off)?;
            Ok(None)
        }
        MAJOR_ARRAY => {
            let len = read_len_at::<true>(data, pos, ai, off)?;
            emit(out, &data[off..*pos], off)?;
            Ok(Some(array_children(len, off)?))
        }
        MAJOR_MAP => {
            let len = read_len_at::<true>(data, pos, ai, off)?;
            emit(out, &data[off..*pos], off)?;
            Ok(Some(map_children(len, off)?))
        }
        MAJOR_TAG => {
            let tag = read_uint_arg_at::<true>(data, pos, ai, off)?;
            if !matches!(tag, TAG_POSITIVE_BIGNUM | TAG_NEGATIVE_BIGNUM) {
                return Err(CborError::new(ErrorCode::ForbiddenOrMalformedTag, off));
            }
            let payload_off = *pos;
            let payload_head = read_u8(data, pos)?;
            if payload_head >> 5 != MAJOR_BYTES {
                return Err(CborError::new(
                    ErrorCode::ForbiddenOrMalformedTag,
                    payload_off,
                ));
            }
            let len = read_len_at::<true>(data, pos, payload_head & 0x1f, payload_off)?;
            let magnitude = read_exact(data, pos, len)?;
            if magnitude.is_empty() || magnitude[0] == 0 {
                return Err(CborError::new(ErrorCode::BignumNotCanonical, payload_off));
            }
            if len <= 8 {
                // The magnitude fits a 64-bit head, so CDE requires head form.
                return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
            }
            emit(out, &data[off..*pos], off)?;
            Ok(None)
        }
        MAJOR_SIMPLE => sacp_image_simple(data, pos, out, ai, off).map(|()| None),
        _ => Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
    }
}

/// The major-type-7 arm of the CDE → SACP direction: simple values pass
/// through, floats widen to float64 after CDE shortest-form checks.
fn sacp_image_simple(
    data: &[u8],
    pos: &mut usize,
    out: &mut Vec<u8>,
    ai: u8,
    off: usize,
) -> Result<(), CborError> {
    match ai {
        20..=22 => emit(out, &data[off..*pos], off),
        23 | 24 => Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off)),
        25 => {
            let payload = read_exact(data, pos, 2)?;
            let half = u16::from_be_bytes([payload[0], payload[1]]);
            if half & 0x7c00 == 0x7c00 && half & 0x03ff != 0 {
                if half != 0x7e00 {
                    return Err(CborError::new(ErrorCode::NonCanonicalNaN, off));
                }
                return emit_f64(out, CANONICAL_NAN_BITS, off);
            }
            if half == 0x8000 {
                return Err(CborError::new(ErrorCode::NegativeZeroForbidden, off));
            }
            emit_f64(out, f16_bits_to_f64_bits(half), off)
        }
        26 => {
            let payload = read_exact(data, pos, 4)?;
            let single = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            if single & 0x7f80_0000 == 0x7f80_0000 && single & 0x007f_ffff != 0 {
                return Err(CborError::new(ErrorCode::NonCanonicalNaN, off));
            }
            if single == 0x8000_0000 {
                return Err(CborError::new(ErrorCode::NegativeZeroForbidden, off));
            }
            let widened = f64::from(f32::from_bits(single)).to_bits();
            if f64_bits_to_f16_exact(widened).is_some() {
                // Representable in float16, so CDE requires the shorter form.
                return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
            }
            emit_f64(out, widened, off)
        }
        27 => {
            let payload = read_exact(data, pos, 8)?;
            let bits = u64::from_be_bytes([
                payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
                payload[7],
            ]);
            if bits & F64_EXP_MASK == F64_EXP_MASK && bits & F64_MANT_MASK != 0 {
                // Every float64 NaN spelling loses to the preferred 0xf97e00.
                return Err(CborError::new(ErrorCode::NonCanonicalNaN, off));
            }
            if bits == NEGATIVE_ZERO_BITS {
                return Err(CborError::new(ErrorCode::NegativeZeroForbidden, off));
            }
            let value = f64::from_bits(bits);
            #[allow(clippy::cast_possible_truncation)] // rounding probe, exactness checked
            let narrowed = value as f32;
            if f64::from(narrowed).to_bits() == bits {
                // Representable in float32, so CDE requires a shorter form.
                return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
            }
            emit(out, &data[off..*pos], off)
        }
        _ => Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
    }
}

fn emit_bignum(
    out: &mut Vec<u8>,
    tag: u64,
    magnitude: u64,
    offset: usize,
) -> Result<(), CborError> {
    emit_uint(out, MAJOR_TAG, tag, offset)?;
    let (bytes, first) = minimal_be(magnitude);
    emit_uint(out, MAJOR_BYTES, (8 - first) as u64, offset)?;
    emit(out, &bytes[first..], offset)
}

fn emit_f64(out: &mut Vec<u8>, bits: u64, offset: usize) -> Result<(), CborError> {
    let be = bits.to_be_bytes();
    emit(
        out,
        &[0xfb, be[0], be[1], be[2], be[3], be[4], be[5], be[6], be[7]],
        offset,
    )
}

/// Widen non-NaN float16 bits to float64 bits, exactly, in pure bit
/// arithmetic (every float16 value is exact in float64).
fn f16_bits_to_f64_bits(half: u16) -> u64 {
    let sign = u64::from(half >> 15) << 63;
    let exponent = (half >> 10) & 0x1f;
    let mantissa = u64::from(half & 0x03ff);
    if exponent == 0x1f {
        // Infinity; NaN is handled by the caller.
        return sign | F64_EXP_MASK;
    }
    if exponent == 0 {
        if mantissa == 0 {
            return sign;
        }
        // Subnormal: value = mantissa * 2^-24. Normalize the leading one to
        // the implied position.
        let leading = 63 - i32::try_from(mantissa.leading_zeros()).unwrap_or(63);
        let unbiased = leading - 24;
        #[allow(clippy::cast_sign_loss)] // leading is 0..=9, so the shift is 43..=52
        let fraction = (mantissa << ((52 - leading) as u32)) & F64_MANT_MASK;
        #[allow(clippy::cast_sign_loss)] // unbiased ≥ -24, so the sum is positive
        let biased = (unbiased + 1023) as u64;
        return sign | (biased << 52) | fraction;
    }
    let unbiased = i32::from(exponent) - 15;
    #[allow(clippy::cast_sign_loss)] // unbiased ≥ -14, so the sum is positive
    let biased = (unbiased + 1023) as u64;
    sign | (biased << 52) | (mantissa << 42)
}

/// Narrow float64 bits to float16 bits when the value is exactly
/// representable, in pure bit arithmetic. NaN is rejected (the caller owns
/// NaN policy).
#[allow(clippy::cast_possible_truncation)] // all narrowing is shift-checked
fn f64_bits_to_f16_exact(bits: u64) -> Option<u16> {
    let sign = ((bits >> 63) as u16) << 15;
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    let mantissa = bits & F64_MANT_MASK;
    if exponent == 0x7ff {
        if mantissa != 0 {
            return None;
        }
        return Some(sign | 0x7c00);
    }
    if exponent == 0 {
        // Float64 subnormals are far below the float16 range; only zero maps.
        return if mantissa == 0 { Some(sign) } else { None };
    }
    let unbiased = exponent - 1023;
    if (-14..=15).contains(&unbiased) {
        if mantissa & ((1u64 << 42) - 1) != 0 {
            return None;
        }
        #[allow(clippy::cast_sign_loss)] // unbiased ≥ -14, so the sum is positive
        let biased = (unbiased + 15) as u16;
        return Some(sign | (biased << 10) | ((mantissa >> 42) as u16));
    }
    if (-24..=-15).contains(&unbiased) {
        let significand = (1u64 << 52) | mantissa;
        #[allow(clippy::cast_sign_loss)] // unbiased ≤ -15, so the shift is 43..=52
        let shift = (28 - unbiased) as u32;
        if significand & ((1u64 << shift) - 1) != 0 {
            return None;
        }
        return Some(sign | ((significand >> shift) as u16));
    }
    None
}
