#[cfg(feature = "alloc")]
use crate::alloc_util::try_reserve_exact;
#[cfg(feature = "alloc")]
use crate::ErrorCode;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
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

pub fn magnitude_to_u128(mag: &[u8]) -> Option<u128> {
    if mag.len() > 16 {
        return None;
    }
    let mut out = 0u128;
    for &b in mag {
        out = (out << 8) | u128::from(b);
    }
    Some(out)
}
