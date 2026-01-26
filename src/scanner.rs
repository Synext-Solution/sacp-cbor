use core::cmp::Ordering;

use crate::canonical::CanonicalCborRef;
use crate::float::validate_f64_bits;
use crate::limits::MAX_SAFE_INTEGER;
use crate::order::is_strictly_increasing_encoded;
use crate::{CborError, CborErrorCode, DecodeLimits};

const MAX_SAFE_INTEGER_BE: [u8; 7] = [0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

/// Validate that `bytes` contain exactly one canonical SACP-CBOR/1 data item.
///
/// This is an allocation-free hot-path validator.
///
/// # Errors
///
/// Returns an error if decoding fails (EOF, trailing bytes, limit violations) or if validation fails
/// (non-canonical encoding, forbidden tags, map ordering, etc.).
pub fn validate(bytes: &[u8], limits: DecodeLimits) -> Result<(), CborError> {
    validate_canonical(bytes, limits).map(|_| ())
}

/// Validate that `bytes` contain exactly one canonical SACP-CBOR/1 data item and return a wrapper.
///
/// # Errors
///
/// Returns an error if decoding fails (EOF, trailing bytes, limit violations) or if validation fails
/// (non-canonical encoding, forbidden tags, map ordering, etc.).
pub fn validate_canonical(
    bytes: &'_ [u8],
    limits: DecodeLimits,
) -> Result<CanonicalCborRef<'_>, CborError> {
    let mut s = Scanner::new(bytes, limits);
    s.skip_value(0)?;
    if !s.eof() {
        return Err(CborError::decode(CborErrorCode::TrailingBytes, s.pos));
    }
    Ok(CanonicalCborRef::new(bytes))
}

struct Scanner<'a> {
    data: &'a [u8],
    pos: usize,
    limits: DecodeLimits,
    items_seen: usize,
}

impl<'a> Scanner<'a> {
    const fn new(data: &'a [u8], limits: DecodeLimits) -> Self {
        Self {
            data,
            pos: 0,
            limits,
            items_seen: 0,
        }
    }

    const fn eof(&self) -> bool {
        self.pos == self.data.len()
    }

    fn read_u8(&mut self, err_off: usize) -> Result<u8, CborError> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| CborError::decode(CborErrorCode::UnexpectedEof, err_off))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_exact(&mut self, n: usize, err_off: usize) -> Result<&'a [u8], CborError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| CborError::decode(CborErrorCode::LengthOverflow, err_off))?;
        if end > self.data.len() {
            return Err(CborError::decode(CborErrorCode::UnexpectedEof, err_off));
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn read_be_u16(&mut self, err_off: usize) -> Result<u16, CborError> {
        let s = self.read_exact(2, err_off)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn read_be_u32(&mut self, err_off: usize) -> Result<u32, CborError> {
        let s = self.read_exact(4, err_off)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_be_u64(&mut self, err_off: usize) -> Result<u64, CborError> {
        let s = self.read_exact(8, err_off)?;
        Ok(u64::from_be_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn read_uint(&mut self, ai: u8, off: usize) -> Result<u64, CborError> {
        match ai {
            0..=23 => Ok(u64::from(ai)),
            24 => {
                let v = self.read_u8(off)?;
                if v < 24 {
                    return Err(CborError::validate(
                        CborErrorCode::NonCanonicalEncoding,
                        off,
                    ));
                }
                Ok(u64::from(v))
            }
            25 => {
                let v = u64::from(self.read_be_u16(off)?);
                if u8::try_from(v).is_ok() {
                    return Err(CborError::validate(
                        CborErrorCode::NonCanonicalEncoding,
                        off,
                    ));
                }
                Ok(v)
            }
            26 => {
                let v = u64::from(self.read_be_u32(off)?);
                if u16::try_from(v).is_ok() {
                    return Err(CborError::validate(
                        CborErrorCode::NonCanonicalEncoding,
                        off,
                    ));
                }
                Ok(v)
            }
            27 => {
                let v = self.read_be_u64(off)?;
                if u32::try_from(v).is_ok() {
                    return Err(CborError::validate(
                        CborErrorCode::NonCanonicalEncoding,
                        off,
                    ));
                }
                Ok(v)
            }
            31 => Err(CborError::validate(
                CborErrorCode::IndefiniteLengthForbidden,
                off,
            )),
            _ => Err(CborError::validate(
                CborErrorCode::ReservedAdditionalInfo,
                off,
            )),
        }
    }

    fn read_len(
        &mut self,
        ai: u8,
        off: usize,
        max_len: usize,
        limit_code: CborErrorCode,
    ) -> Result<usize, CborError> {
        let len_u64 = self.read_uint(ai, off)?;
        let len = usize::try_from(len_u64)
            .map_err(|_| CborError::decode(CborErrorCode::LengthOverflow, off))?;
        if len > max_len {
            return Err(CborError::decode(limit_code, off));
        }
        Ok(len)
    }

    fn bump_items(&mut self, add: usize, off: usize) -> Result<(), CborError> {
        self.items_seen = self
            .items_seen
            .checked_add(add)
            .ok_or_else(|| CborError::decode(CborErrorCode::LengthOverflow, off))?;
        if self.items_seen > self.limits.max_total_items {
            return Err(CborError::decode(
                CborErrorCode::TotalItemsLimitExceeded,
                off,
            ));
        }
        Ok(())
    }

    const fn ensure_depth(&self, next_depth: usize, off: usize) -> Result<(), CborError> {
        if next_depth > self.limits.max_depth {
            return Err(CborError::decode(CborErrorCode::DepthLimitExceeded, off));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn skip_value(&mut self, depth: usize) -> Result<(), CborError> {
        let off = self.pos;
        let ib = self.read_u8(off)?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        debug_assert!(major <= 7);
        match major {
            0 => {
                let v = self.read_uint(ai, off)?;
                if v > MAX_SAFE_INTEGER {
                    return Err(CborError::validate(
                        CborErrorCode::IntegerOutsideSafeRange,
                        off,
                    ));
                }
                Ok(())
            }
            1 => {
                let n = self.read_uint(ai, off)?;
                if n >= MAX_SAFE_INTEGER {
                    return Err(CborError::validate(
                        CborErrorCode::IntegerOutsideSafeRange,
                        off,
                    ));
                }
                Ok(())
            }
            2 => {
                let len = self.read_len(
                    ai,
                    off,
                    self.limits.max_bytes_len,
                    CborErrorCode::BytesLenLimitExceeded,
                )?;
                self.read_exact(len, off)?;
                Ok(())
            }
            3 => {
                let len = self.read_len(
                    ai,
                    off,
                    self.limits.max_text_len,
                    CborErrorCode::TextLenLimitExceeded,
                )?;
                let bytes = self.read_exact(len, off)?;
                core::str::from_utf8(bytes)
                    .map_err(|_| CborError::validate(CborErrorCode::Utf8Invalid, off))?;
                Ok(())
            }
            4 => {
                let len = self.read_len(
                    ai,
                    off,
                    self.limits.max_array_len,
                    CborErrorCode::ArrayLenLimitExceeded,
                )?;
                self.bump_items(len, off)?;
                self.ensure_depth(depth + 1, off)?;
                for _ in 0..len {
                    self.skip_value(depth + 1)?;
                }
                Ok(())
            }
            5 => {
                let len = self.read_len(
                    ai,
                    off,
                    self.limits.max_map_len,
                    CborErrorCode::MapLenLimitExceeded,
                )?;
                let items = len
                    .checked_mul(2)
                    .ok_or_else(|| CborError::decode(CborErrorCode::LengthOverflow, off))?;
                self.bump_items(items, off)?;
                self.ensure_depth(depth + 1, off)?;

                let mut prev_key: Option<&[u8]> = None;
                for _ in 0..len {
                    // key
                    let k_off = self.pos;
                    let key_first = self.read_u8(k_off)?;
                    let k_major = key_first >> 5;
                    let k_ai = key_first & 0x1f;
                    if k_major != 3 {
                        return Err(CborError::validate(CborErrorCode::MapKeyMustBeText, k_off));
                    }
                    let k_len = self.read_len(
                        k_ai,
                        k_off,
                        self.limits.max_text_len,
                        CborErrorCode::TextLenLimitExceeded,
                    )?;
                    let key_bytes = self.read_exact(k_len, k_off)?;
                    core::str::from_utf8(key_bytes)
                        .map_err(|_| CborError::validate(CborErrorCode::Utf8Invalid, k_off))?;
                    let k_end = self.pos;
                    let enc_key = &self.data[k_off..k_end];

                    if let Some(prev) = prev_key {
                        if prev == enc_key {
                            return Err(CborError::validate(CborErrorCode::DuplicateMapKey, k_off));
                        }
                        if !is_strictly_increasing_encoded(prev, enc_key) {
                            return Err(CborError::validate(
                                CborErrorCode::NonCanonicalMapOrder,
                                k_off,
                            ));
                        }
                    }
                    prev_key = Some(enc_key);

                    // value
                    self.skip_value(depth + 1)?;
                }
                Ok(())
            }
            6 => {
                let tag = self.read_uint(ai, off)?;
                let negative = match tag {
                    2 => false,
                    3 => true,
                    _ => {
                        return Err(CborError::validate(
                            CborErrorCode::ForbiddenOrMalformedTag,
                            off,
                        ))
                    }
                };

                // Tagged item must be a definite byte string.
                let m_off = self.pos;
                let first = self.read_u8(m_off)?;
                let m_major = first >> 5;
                let m_ai = first & 0x1f;
                if m_major != 2 {
                    return Err(CborError::validate(
                        CborErrorCode::ForbiddenOrMalformedTag,
                        m_off,
                    ));
                }
                let m_len = self.read_len(
                    m_ai,
                    m_off,
                    self.limits.max_bytes_len,
                    CborErrorCode::BytesLenLimitExceeded,
                )?;
                let mag = self.read_exact(m_len, m_off)?;
                validate_bignum_bytes(negative, mag)
                    .map_err(|code| CborError::validate(code, m_off))?;
                Ok(())
            }
            7 => match ai {
                20..=22 => Ok(()),
                27 => {
                    let bits = self.read_be_u64(off)?;
                    validate_f64_bits(bits).map_err(|code| CborError::validate(code, off))?;
                    Ok(())
                }
                28..=30 => Err(CborError::validate(
                    CborErrorCode::ReservedAdditionalInfo,
                    off,
                )),
                24 => {
                    // Non-canonical encoding for simple values < 24.
                    let simple = self.read_u8(off)?;
                    if simple < 24 {
                        Err(CborError::validate(
                            CborErrorCode::NonCanonicalEncoding,
                            off,
                        ))
                    } else {
                        Err(CborError::validate(
                            CborErrorCode::UnsupportedSimpleValue,
                            off,
                        ))
                    }
                }
                _ => Err(CborError::validate(
                    CborErrorCode::UnsupportedSimpleValue,
                    off,
                )),
            },
            _ => unreachable!("major out of range"),
        }
    }
}

fn validate_bignum_bytes(negative: bool, magnitude: &[u8]) -> Result<(), CborErrorCode> {
    if magnitude.is_empty() || magnitude[0] == 0 {
        return Err(CborErrorCode::BignumNotCanonical);
    }

    let cmp = match magnitude.len().cmp(&MAX_SAFE_INTEGER_BE.len()) {
        Ordering::Equal => magnitude.cmp(&MAX_SAFE_INTEGER_BE),
        other => other,
    };

    let outside = if negative {
        cmp != Ordering::Less
    } else {
        cmp == Ordering::Greater
    };

    if !outside {
        return Err(CborErrorCode::BignumMustBeOutsideSafeRange);
    }

    Ok(())
}

#[cfg(feature = "alloc")]
mod decode {
    use super::Scanner;
    use alloc::borrow::ToOwned;
    use alloc::string::String;
    use alloc::vec::Vec;

    use crate::limits::MAX_SAFE_INTEGER;
    use crate::order::is_strictly_increasing_encoded;
    use crate::value::{BigInt, CborMap, CborValue, F64Bits};
    use crate::{CborError, CborErrorCode, DecodeLimits};

    /// Decode SACP-CBOR/1 bytes into an owned [`CborValue`].
    ///
    /// This validates the input while decoding.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding or validation fails.
    pub fn decode_value(bytes: &[u8], limits: DecodeLimits) -> Result<CborValue, CborError> {
        let mut s = Scanner::new(bytes, limits);
        let v = s.parse_value(0)?;
        if !s.eof() {
            return Err(CborError::decode(CborErrorCode::TrailingBytes, s.pos));
        }
        Ok(v)
    }

    impl Scanner<'_> {
        #[allow(clippy::too_many_lines)]
        fn parse_value(&mut self, depth: usize) -> Result<CborValue, CborError> {
            let off = self.pos;
            let ib = self.read_u8(off)?;
            let major = ib >> 5;
            let ai = ib & 0x1f;

            debug_assert!(major <= 7);
            match major {
                0 => {
                    let v = self.read_uint(ai, off)?;
                    if v > MAX_SAFE_INTEGER {
                        return Err(CborError::validate(
                            CborErrorCode::IntegerOutsideSafeRange,
                            off,
                        ));
                    }
                    let i = i64::try_from(v)
                        .map_err(|_| CborError::decode(CborErrorCode::LengthOverflow, off))?;
                    Ok(CborValue::Int(i))
                }
                1 => {
                    let n = self.read_uint(ai, off)?;
                    if n >= MAX_SAFE_INTEGER {
                        return Err(CborError::validate(
                            CborErrorCode::IntegerOutsideSafeRange,
                            off,
                        ));
                    }
                    let n_i64 = i64::try_from(n)
                        .map_err(|_| CborError::decode(CborErrorCode::LengthOverflow, off))?;
                    Ok(CborValue::Int(-1 - n_i64))
                }
                2 => {
                    let len = self.read_len(
                        ai,
                        off,
                        self.limits.max_bytes_len,
                        CborErrorCode::BytesLenLimitExceeded,
                    )?;
                    let b = self.read_exact(len, off)?.to_vec();
                    Ok(CborValue::Bytes(b))
                }
                3 => {
                    let len = self.read_len(
                        ai,
                        off,
                        self.limits.max_text_len,
                        CborErrorCode::TextLenLimitExceeded,
                    )?;
                    let bytes = self.read_exact(len, off)?;
                    let s = core::str::from_utf8(bytes)
                        .map_err(|_| CborError::validate(CborErrorCode::Utf8Invalid, off))?
                        .to_owned();
                    Ok(CborValue::Text(s))
                }
                4 => {
                    let len = self.read_len(
                        ai,
                        off,
                        self.limits.max_array_len,
                        CborErrorCode::ArrayLenLimitExceeded,
                    )?;
                    self.bump_items(len, off)?;
                    self.ensure_depth(depth + 1, off)?;

                    let mut items = Vec::new();
                    items
                        .try_reserve_exact(len)
                        .map_err(|_| CborError::decode(CborErrorCode::AllocationFailed, off))?;

                    for _ in 0..len {
                        items.push(self.parse_value(depth + 1)?);
                    }
                    Ok(CborValue::Array(items))
                }
                5 => {
                    let len = self.read_len(
                        ai,
                        off,
                        self.limits.max_map_len,
                        CborErrorCode::MapLenLimitExceeded,
                    )?;
                    let items = len
                        .checked_mul(2)
                        .ok_or_else(|| CborError::decode(CborErrorCode::LengthOverflow, off))?;
                    self.bump_items(items, off)?;
                    self.ensure_depth(depth + 1, off)?;

                    let mut entries: Vec<(String, CborValue)> = Vec::new();
                    entries
                        .try_reserve_exact(len)
                        .map_err(|_| CborError::decode(CborErrorCode::AllocationFailed, off))?;

                    let mut prev_key_bytes: Option<&[u8]> = None;

                    for _ in 0..len {
                        // key
                        let k_off = self.pos;
                        let key_first = self.read_u8(k_off)?;
                        let k_major = key_first >> 5;
                        let k_ai = key_first & 0x1f;
                        if k_major != 3 {
                            return Err(CborError::validate(
                                CborErrorCode::MapKeyMustBeText,
                                k_off,
                            ));
                        }
                        let k_len = self.read_len(
                            k_ai,
                            k_off,
                            self.limits.max_text_len,
                            CborErrorCode::TextLenLimitExceeded,
                        )?;
                        let key_payload = self.read_exact(k_len, k_off)?;
                        let key_str = core::str::from_utf8(key_payload)
                            .map_err(|_| CborError::validate(CborErrorCode::Utf8Invalid, k_off))?;
                        let k_end = self.pos;
                        let enc_key = &self.data[k_off..k_end];

                        if let Some(prev) = prev_key_bytes {
                            if prev == enc_key {
                                return Err(CborError::validate(
                                    CborErrorCode::DuplicateMapKey,
                                    k_off,
                                ));
                            }
                            if !is_strictly_increasing_encoded(prev, enc_key) {
                                return Err(CborError::validate(
                                    CborErrorCode::NonCanonicalMapOrder,
                                    k_off,
                                ));
                            }
                        }
                        prev_key_bytes = Some(enc_key);

                        // value
                        let val = self.parse_value(depth + 1)?;
                        entries.push((key_str.to_owned(), val));
                    }

                    Ok(CborValue::Map(CborMap::from_sorted_entries(entries)))
                }
                6 => {
                    let tag = self.read_uint(ai, off)?;
                    let negative = match tag {
                        2 => false,
                        3 => true,
                        _ => {
                            return Err(CborError::validate(
                                CborErrorCode::ForbiddenOrMalformedTag,
                                off,
                            ))
                        }
                    };

                    let m_off = self.pos;
                    let first = self.read_u8(m_off)?;
                    let m_major = first >> 5;
                    let m_ai = first & 0x1f;
                    if m_major != 2 {
                        return Err(CborError::validate(
                            CborErrorCode::ForbiddenOrMalformedTag,
                            m_off,
                        ));
                    }
                    let m_len = self.read_len(
                        m_ai,
                        m_off,
                        self.limits.max_bytes_len,
                        CborErrorCode::BytesLenLimitExceeded,
                    )?;
                    let mag = self.read_exact(m_len, m_off)?;
                    super::validate_bignum_bytes(negative, mag)
                        .map_err(|code| CborError::validate(code, m_off))?;

                    Ok(CborValue::Bignum(BigInt::new_unchecked(
                        negative,
                        mag.to_vec(),
                    )))
                }
                7 => match ai {
                    20 => Ok(CborValue::Bool(false)),
                    21 => Ok(CborValue::Bool(true)),
                    22 => Ok(CborValue::Null),
                    27 => {
                        let bits = self.read_be_u64(off)?;
                        crate::float::validate_f64_bits(bits)
                            .map_err(|code| CborError::validate(code, off))?;
                        Ok(CborValue::Float(F64Bits::new_unchecked(bits)))
                    }
                    28..=30 => Err(CborError::validate(
                        CborErrorCode::ReservedAdditionalInfo,
                        off,
                    )),
                    24 => {
                        let simple = self.read_u8(off)?;
                        if simple < 24 {
                            Err(CborError::validate(
                                CborErrorCode::NonCanonicalEncoding,
                                off,
                            ))
                        } else {
                            Err(CborError::validate(
                                CborErrorCode::UnsupportedSimpleValue,
                                off,
                            ))
                        }
                    }
                    _ => Err(CborError::validate(
                        CborErrorCode::UnsupportedSimpleValue,
                        off,
                    )),
                },
                _ => unreachable!("major out of range"),
            }
        }
    }
}

#[cfg(feature = "alloc")]
pub use decode::decode_value;
