#[cfg(not(feature = "alloc"))]
use crate::limits::DEFAULT_MAX_DEPTH;
use crate::{CborError, ErrorCode};

#[cfg(feature = "alloc")]
use crate::alloc_util::try_reserve;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
const TRUSTED_INLINE: usize = 64;
#[cfg(not(feature = "alloc"))]
const TRUSTED_INLINE: usize = DEFAULT_MAX_DEPTH + 2;

pub fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8, CborError> {
    let off = *pos;
    let b = *data
        .get(*pos)
        .ok_or_else(|| CborError::new(ErrorCode::UnexpectedEof, off))?;
    *pos += 1;
    Ok(b)
}

pub fn read_exact<'a>(data: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], CborError> {
    let off = *pos;
    let end = pos
        .checked_add(n)
        .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
    if end > data.len() {
        return Err(CborError::new(ErrorCode::UnexpectedEof, off));
    }
    let s = &data[*pos..end];
    *pos = end;
    Ok(s)
}

pub fn read_be_u16(data: &[u8], pos: &mut usize) -> Result<u16, CborError> {
    let s = read_exact(data, pos, 2)?;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

pub fn read_be_u32(data: &[u8], pos: &mut usize) -> Result<u32, CborError> {
    let s = read_exact(data, pos, 4)?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

pub fn read_be_u64(data: &[u8], pos: &mut usize) -> Result<u64, CborError> {
    let s = read_exact(data, pos, 8)?;
    Ok(u64::from_be_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

pub fn read_uint_checked(
    data: &[u8],
    pos: &mut usize,
    ai: u8,
    off: usize,
) -> Result<u64, CborError> {
    let v = read_uint_trusted(data, pos, ai, off)?;
    match ai {
        0..=23 => Ok(v),
        24 => {
            if v < 24 {
                return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
            }
            Ok(v)
        }
        25 => {
            if u8::try_from(v).is_ok() {
                return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
            }
            Ok(v)
        }
        26 => {
            if u16::try_from(v).is_ok() {
                return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
            }
            Ok(v)
        }
        27 => {
            if u32::try_from(v).is_ok() {
                return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
            }
            Ok(v)
        }
        _ => Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
    }
}

pub fn read_uint_trusted(
    data: &[u8],
    pos: &mut usize,
    ai: u8,
    off: usize,
) -> Result<u64, CborError> {
    match ai {
        0..=23 => Ok(u64::from(ai)),
        24 => Ok(u64::from(read_u8(data, pos)?)),
        25 => Ok(u64::from(read_be_u16(data, pos)?)),
        26 => Ok(u64::from(read_be_u32(data, pos)?)),
        27 => Ok(read_be_u64(data, pos)?),
        _ => Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
    }
}

pub fn read_len_checked(
    data: &[u8],
    pos: &mut usize,
    ai: u8,
    off: usize,
) -> Result<u64, CborError> {
    if ai == 31 {
        return Err(CborError::new(ErrorCode::IndefiniteLengthForbidden, off));
    }
    read_uint_checked(data, pos, ai, off)
}

pub fn read_len_trusted(
    data: &[u8],
    pos: &mut usize,
    ai: u8,
    off: usize,
) -> Result<u64, CborError> {
    if ai == 31 {
        return Err(CborError::new(ErrorCode::IndefiniteLengthForbidden, off));
    }
    read_uint_trusted(data, pos, ai, off)
}

pub fn len_to_usize(len: u64, off: usize) -> Result<usize, CborError> {
    usize::try_from(len).map_err(|_| CborError::new(ErrorCode::LengthOverflow, off))
}

struct SmallStack<const N: usize> {
    inline: [usize; N],
    len: usize,
    #[cfg(feature = "alloc")]
    overflow: Vec<usize>,
}

impl<const N: usize> SmallStack<N> {
    const fn new() -> Self {
        Self {
            inline: [0; N],
            len: 0,
            #[cfg(feature = "alloc")]
            overflow: Vec::new(),
        }
    }

    fn push(&mut self, value: usize, off: usize) -> Result<(), CborError> {
        #[cfg(feature = "alloc")]
        {
            if !self.overflow.is_empty() {
                try_reserve(&mut self.overflow, 1, off)?;
                self.overflow.push(value);
                return Ok(());
            }
        }

        if self.len < N {
            self.inline[self.len] = value;
            self.len += 1;
            return Ok(());
        }

        #[cfg(feature = "alloc")]
        {
            try_reserve(&mut self.overflow, 1, off)?;
            self.overflow.push(value);
            Ok(())
        }

        #[cfg(not(feature = "alloc"))]
        {
            Err(CborError::new(ErrorCode::DepthLimitExceeded, off))
        }
    }

    fn peek_mut(&mut self) -> Option<&mut usize> {
        #[cfg(feature = "alloc")]
        {
            if let Some(v) = self.overflow.last_mut() {
                return Some(v);
            }
        }
        if self.len == 0 {
            None
        } else {
            Some(&mut self.inline[self.len - 1])
        }
    }

    fn pop(&mut self) -> Option<usize> {
        #[cfg(feature = "alloc")]
        {
            if let Some(v) = self.overflow.pop() {
                return Some(v);
            }
        }
        if self.len == 0 {
            None
        } else {
            self.len -= 1;
            Some(self.inline[self.len])
        }
    }
}

pub fn skip_value_trusted(data: &[u8], start: usize) -> Result<usize, CborError> {
    let mut pos = start;
    let mut stack = SmallStack::<TRUSTED_INLINE>::new();
    stack.push(1, start)?;

    while let Some(remaining) = stack.peek_mut() {
        if *remaining == 0 {
            stack.pop();
            continue;
        }

        *remaining = remaining
            .checked_sub(1)
            .ok_or_else(|| CborError::new(ErrorCode::MalformedCanonical, pos))?;

        let off = pos;
        let ib = read_u8(data, &mut pos)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        match major {
            0 | 1 => {
                let _ = read_uint_trusted(data, &mut pos, ai, off)?;
            }
            2 | 3 => {
                let len = read_len_trusted(data, &mut pos, ai, off)?;
                let len = len_to_usize(len, off)?;
                let _ = read_exact(data, &mut pos, len)?;
            }
            4 => {
                let len = read_len_trusted(data, &mut pos, ai, off)?;
                let len = len_to_usize(len, off)?;
                stack.push(len, off)?;
            }
            5 => {
                let len = read_len_trusted(data, &mut pos, ai, off)?;
                let len = len_to_usize(len, off)?;
                let items = len
                    .checked_mul(2)
                    .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
                stack.push(items, off)?;
            }
            6 => {
                let _ = read_uint_trusted(data, &mut pos, ai, off)?;
                stack.push(1, off)?;
            }
            7 => match ai {
                20..=23 => {}
                24 => {
                    let _ = read_u8(data, &mut pos)?;
                }
                25 => {
                    let _ = read_be_u16(data, &mut pos)?;
                }
                26 => {
                    let _ = read_be_u32(data, &mut pos)?;
                }
                27 => {
                    let _ = read_be_u64(data, &mut pos)?;
                }
                _ => return Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
            },
            _ => return Err(CborError::new(ErrorCode::MalformedCanonical, off)),
        }
    }

    Ok(pos)
}
