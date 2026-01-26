use crate::{CborError, ErrorCode};

#[derive(Clone, Copy)]
pub struct CborStream<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> CborStream<'a> {
    pub const fn new(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    pub const fn position(&self) -> usize {
        self.pos
    }

    pub fn read_u8(&mut self) -> Result<u8, CborError> {
        let off = self.pos;
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| CborError::new(ErrorCode::UnexpectedEof, off))?;
        self.pos += 1;
        Ok(b)
    }

    pub fn read_exact(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let off = self.pos;
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
        if end > self.data.len() {
            return Err(CborError::new(ErrorCode::UnexpectedEof, off));
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn read_be_u16(&mut self) -> Result<u16, CborError> {
        let s = self.read_exact(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    pub fn read_be_u32(&mut self) -> Result<u32, CborError> {
        let s = self.read_exact(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub fn read_be_u64(&mut self) -> Result<u64, CborError> {
        let s = self.read_exact(8)?;
        Ok(u64::from_be_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    pub fn read_uint_arg(&mut self, ai: u8, off: usize) -> Result<u64, CborError> {
        match ai {
            0..=23 => Ok(u64::from(ai)),
            24 => {
                let v = self.read_u8()?;
                if v < 24 {
                    return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Ok(u64::from(v))
            }
            25 => {
                let v = u64::from(self.read_be_u16()?);
                if u8::try_from(v).is_ok() {
                    return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Ok(v)
            }
            26 => {
                let v = u64::from(self.read_be_u32()?);
                if u16::try_from(v).is_ok() {
                    return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Ok(v)
            }
            27 => {
                let v = self.read_be_u64()?;
                if u32::try_from(v).is_ok() {
                    return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Ok(v)
            }
            _ => Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
        }
    }

    pub fn read_len_arg(&mut self, ai: u8, off: usize) -> Result<u64, CborError> {
        match ai {
            31 => Err(CborError::new(ErrorCode::IndefiniteLengthForbidden, off)),
            _ => self.read_uint_arg(ai, off),
        }
    }
}
