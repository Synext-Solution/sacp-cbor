use crate::CborErrorCode;

pub const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;
pub const NEGATIVE_ZERO_BITS: u64 = 0x8000_0000_0000_0000;

const EXP_MASK: u64 = 0x7ff0_0000_0000_0000;
const MANT_MASK: u64 = 0x000f_ffff_ffff_ffff;

#[inline]
pub const fn validate_f64_bits(bits: u64) -> Result<(), CborErrorCode> {
    if bits == NEGATIVE_ZERO_BITS {
        return Err(CborErrorCode::NegativeZeroForbidden);
    }

    let is_nan = (bits & EXP_MASK) == EXP_MASK && (bits & MANT_MASK) != 0;
    if is_nan && bits != CANONICAL_NAN_BITS {
        return Err(CborErrorCode::NonCanonicalNaN);
    }

    Ok(())
}
