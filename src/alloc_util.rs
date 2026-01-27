use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::{CborError, ErrorCode};

#[inline]
pub const fn alloc_failed(offset: usize) -> CborError {
    CborError::new(ErrorCode::AllocationFailed, offset)
}

#[inline]
pub fn try_vec_from_slice(bytes: &[u8], offset: usize) -> Result<Vec<u8>, CborError> {
    let mut v = Vec::new();
    v.try_reserve_exact(bytes.len())
        .map_err(|_| alloc_failed(offset))?;
    v.extend_from_slice(bytes);
    Ok(v)
}

#[inline]
pub fn try_box_str_from_str(s: &str, offset: usize) -> Result<Box<str>, CborError> {
    let mut out = String::new();
    out.try_reserve_exact(s.len())
        .map_err(|_| alloc_failed(offset))?;
    out.push_str(s);
    Ok(out.into_boxed_str())
}

#[inline]
pub fn try_vec_with_capacity<T>(cap: usize, offset: usize) -> Result<Vec<T>, CborError> {
    let mut v: Vec<T> = Vec::new();
    v.try_reserve_exact(cap).map_err(|_| alloc_failed(offset))?;
    Ok(v)
}

#[inline]
pub fn try_vec_repeat_copy<T: Copy>(
    n: usize,
    value: T,
    offset: usize,
) -> Result<Vec<T>, CborError> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| alloc_failed(offset))?;
    for _ in 0..n {
        v.push(value);
    }
    Ok(v)
}
