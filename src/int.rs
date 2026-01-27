use crate::alloc_util::try_reserve_exact;
use crate::ErrorCode;
use alloc::vec::Vec;

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
