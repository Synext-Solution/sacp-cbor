use crate::alloc_util::try_reserve_exact;
#[cfg(feature = "serde")]
use crate::profile::{MAX_SAFE_INTEGER, MAX_SAFE_INTEGER_I64, MIN_SAFE_INTEGER};
#[cfg(feature = "serde")]
use crate::value::{BigInt, CborInteger};
use crate::ErrorCode;
use alloc::vec::Vec;

#[cfg(feature = "serde")]
pub fn integer_from_u128(v: u128) -> Result<CborInteger, ErrorCode> {
    let max = u128::from(MAX_SAFE_INTEGER);
    if v <= max {
        let i = i64::try_from(v).map_err(|_| ErrorCode::LengthOverflow)?;
        return Ok(CborInteger::new_safe_unchecked(i));
    }

    let magnitude = magnitude_from_u128(v)?;
    let bigint = BigInt::new(false, magnitude).map_err(|err| err.code)?;
    Ok(CborInteger::from_bigint(bigint))
}

#[cfg(feature = "serde")]
pub fn integer_from_i128(v: i128) -> Result<CborInteger, ErrorCode> {
    let min = i128::from(MIN_SAFE_INTEGER);
    let max = i128::from(MAX_SAFE_INTEGER_I64);

    if v >= min && v <= max {
        let i = i64::try_from(v).map_err(|_| ErrorCode::LengthOverflow)?;
        return Ok(CborInteger::new_safe_unchecked(i));
    }

    let negative = v < 0;
    let n_u128 = if negative {
        let n_i128 = -1_i128 - v;
        u128::try_from(n_i128).map_err(|_| ErrorCode::LengthOverflow)?
    } else {
        u128::try_from(v).map_err(|_| ErrorCode::LengthOverflow)?
    };

    let magnitude = magnitude_from_u128(n_u128)?;
    let bigint = BigInt::new(negative, magnitude).map_err(|err| err.code)?;
    Ok(CborInteger::from_bigint(bigint))
}

pub fn magnitude_from_u128(n: u128) -> Result<Vec<u8>, ErrorCode> {
    if n == 0 {
        return Err(ErrorCode::BignumNotCanonical);
    }
    let leading = (n.leading_zeros() / 8) as usize;
    let raw = n.to_be_bytes();
    let mut out = Vec::new();
    try_reserve_exact(&mut out, raw.len().saturating_sub(leading), 0).map_err(|err| err.code)?;
    out.extend_from_slice(&raw[leading..]);
    Ok(out)
}
