use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::Layout;

use crate::{CborError, ErrorCode};

#[inline]
fn check_reserve_len<T>(len: usize, additional: usize, offset: usize) -> Result<(), CborError> {
    let needed = len
        .checked_add(additional)
        .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, offset))?;
    Layout::array::<T>(needed).map_err(|_| CborError::new(ErrorCode::LengthOverflow, offset))?;
    Ok(())
}

#[inline]
pub fn try_reserve_exact<T>(
    v: &mut Vec<T>,
    additional: usize,
    offset: usize,
) -> Result<(), CborError> {
    let needed = v
        .len()
        .checked_add(additional)
        .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, offset))?;
    if needed <= v.capacity() {
        return Ok(());
    }
    check_reserve_len::<T>(v.len(), additional, offset)?;
    v.try_reserve_exact(additional)
        .map_err(|_| CborError::new(ErrorCode::AllocationFailed, offset))
}

#[inline]
pub fn try_reserve<T>(v: &mut Vec<T>, additional: usize, offset: usize) -> Result<(), CborError> {
    let needed = v
        .len()
        .checked_add(additional)
        .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, offset))?;
    if needed <= v.capacity() {
        return Ok(());
    }
    check_reserve_len::<T>(v.len(), additional, offset)?;
    v.try_reserve(additional)
        .map_err(|_| CborError::new(ErrorCode::AllocationFailed, offset))
}

#[inline]
pub fn try_reserve_exact_str(
    s: &mut String,
    additional: usize,
    offset: usize,
) -> Result<(), CborError> {
    let needed = s
        .len()
        .checked_add(additional)
        .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, offset))?;
    if needed <= s.capacity() {
        return Ok(());
    }
    check_reserve_len::<u8>(s.len(), additional, offset)?;
    s.try_reserve_exact(additional)
        .map_err(|_| CborError::new(ErrorCode::AllocationFailed, offset))
}

#[inline]
pub fn try_vec_from_slice(bytes: &[u8], offset: usize) -> Result<Vec<u8>, CborError> {
    let mut v = Vec::new();
    try_reserve_exact(&mut v, bytes.len(), offset)?;
    v.extend_from_slice(bytes);
    Ok(v)
}

#[inline]
pub fn try_box_str_from_str(s: &str, offset: usize) -> Result<Box<str>, CborError> {
    let mut out = String::new();
    try_reserve_exact_str(&mut out, s.len(), offset)?;
    out.push_str(s);
    Ok(out.into_boxed_str())
}

#[inline]
pub fn try_vec_with_capacity<T>(cap: usize, offset: usize) -> Result<Vec<T>, CborError> {
    let mut v: Vec<T> = Vec::new();
    try_reserve_exact(&mut v, cap, offset)?;
    Ok(v)
}

#[inline]
pub fn try_vec_repeat_copy<T: Copy>(
    n: usize,
    value: T,
    offset: usize,
) -> Result<Vec<T>, CborError> {
    let mut v = Vec::new();
    try_reserve_exact(&mut v, n, offset)?;
    v.resize(n, value);
    Ok(v)
}
