use crate::canonical::CanonicalCborRef;
use crate::profile::MAX_SAFE_INTEGER;
use crate::profile::{is_strictly_increasing_encoded, validate_bignum_bytes, validate_f64_bits};
use crate::stream::CborStream;
use crate::{CborError, DecodeLimits, ErrorCode};

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
    if bytes.len() > limits.max_input_bytes {
        return Err(CborError::new(ErrorCode::MessageLenLimitExceeded, 0));
    }
    let end = value_end_with_limits(bytes, 0, limits)?;
    if end != bytes.len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, end));
    }
    Ok(CanonicalCborRef::new(bytes))
}

pub fn value_end(data: &[u8], start: usize) -> Result<usize, CborError> {
    value_end_internal(data, start, None)
}

fn value_end_with_limits(
    data: &[u8],
    start: usize,
    limits: DecodeLimits,
) -> Result<usize, CborError> {
    value_end_internal(data, start, Some(limits))
}

fn value_end_internal(
    data: &[u8],
    start: usize,
    limits: Option<DecodeLimits>,
) -> Result<usize, CborError> {
    let mut w = Walker::new(data, start, limits);
    w.skip_value(0)?;
    Ok(w.pos())
}

struct Walker<'a> {
    stream: CborStream<'a>,
    limits: Option<DecodeLimits>,
    items_seen: usize,
}

impl<'a> Walker<'a> {
    const fn new(data: &'a [u8], pos: usize, limits: Option<DecodeLimits>) -> Self {
        Self {
            stream: CborStream::new(data, pos),
            limits,
            items_seen: 0,
        }
    }

    const fn pos(&self) -> usize {
        self.stream.position()
    }

    const fn data(&self) -> &'a [u8] {
        self.stream.data()
    }

    fn read_u8(&mut self) -> Result<u8, CborError> {
        self.stream.read_u8()
    }

    fn read_exact(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        self.stream.read_exact(n)
    }

    fn read_be_u64(&mut self) -> Result<u64, CborError> {
        let s = self.read_exact(8)?;
        Ok(u64::from_be_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn read_uint_arg(&mut self, ai: u8, off: usize) -> Result<u64, CborError> {
        self.stream.read_uint_arg(ai, off)
    }

    fn read_len(&mut self, ai: u8, off: usize) -> Result<usize, CborError> {
        let len_u64 = self.stream.read_len_arg(ai, off)?;
        usize::try_from(len_u64).map_err(|_| CborError::new(ErrorCode::LengthOverflow, off))
    }

    const fn enforce_len(
        len: usize,
        max_len: usize,
        code: ErrorCode,
        off: usize,
    ) -> Result<(), CborError> {
        if len > max_len {
            return Err(CborError::new(code, off));
        }
        Ok(())
    }

    fn bump_items(&mut self, add: usize, off: usize) -> Result<(), CborError> {
        let Some(limits) = self.limits else {
            return Ok(());
        };
        self.items_seen = self
            .items_seen
            .checked_add(add)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
        if self.items_seen > limits.max_total_items {
            return Err(CborError::new(ErrorCode::TotalItemsLimitExceeded, off));
        }
        Ok(())
    }

    const fn ensure_depth(&self, next_depth: usize, off: usize) -> Result<(), CborError> {
        let Some(limits) = self.limits else {
            return Ok(());
        };
        if next_depth > limits.max_depth {
            return Err(CborError::new(ErrorCode::DepthLimitExceeded, off));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn skip_value(&mut self, depth: usize) -> Result<(), CborError> {
        let off = self.pos();
        let ib = self.read_u8()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;

        debug_assert!(major <= 7);
        match major {
            0 => {
                let v = self.read_uint_arg(ai, off)?;
                if v > MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                Ok(())
            }
            1 => {
                let n = self.read_uint_arg(ai, off)?;
                if n >= MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                Ok(())
            }
            2 => {
                let len = self.read_len(ai, off)?;
                if let Some(limits) = self.limits {
                    Self::enforce_len(
                        len,
                        limits.max_bytes_len,
                        ErrorCode::BytesLenLimitExceeded,
                        off,
                    )?;
                }
                self.read_exact(len)?;
                Ok(())
            }
            3 => {
                let len = self.read_len(ai, off)?;
                if let Some(limits) = self.limits {
                    Self::enforce_len(
                        len,
                        limits.max_text_len,
                        ErrorCode::TextLenLimitExceeded,
                        off,
                    )?;
                }
                let bytes = self.read_exact(len)?;
                core::str::from_utf8(bytes)
                    .map_err(|_| CborError::new(ErrorCode::Utf8Invalid, off))?;
                Ok(())
            }
            4 => {
                let len = self.read_len(ai, off)?;
                if let Some(limits) = self.limits {
                    Self::enforce_len(
                        len,
                        limits.max_array_len,
                        ErrorCode::ArrayLenLimitExceeded,
                        off,
                    )?;
                }
                self.bump_items(len, off)?;
                self.ensure_depth(depth + 1, off)?;
                for _ in 0..len {
                    self.skip_value(depth + 1)?;
                }
                Ok(())
            }
            5 => {
                let len = self.read_len(ai, off)?;
                if let Some(limits) = self.limits {
                    Self::enforce_len(
                        len,
                        limits.max_map_len,
                        ErrorCode::MapLenLimitExceeded,
                        off,
                    )?;
                }
                let items = len
                    .checked_mul(2)
                    .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
                self.bump_items(items, off)?;
                self.ensure_depth(depth + 1, off)?;

                let mut prev_key: Option<&[u8]> = None;
                for _ in 0..len {
                    let k_off = self.pos();
                    let key_first = self.read_u8()?;
                    let k_major = key_first >> 5;
                    let k_ai = key_first & 0x1f;
                    if k_major != 3 {
                        return Err(CborError::new(ErrorCode::MapKeyMustBeText, k_off));
                    }
                    let k_len = self.read_len(k_ai, k_off)?;
                    if let Some(limits) = self.limits {
                        Self::enforce_len(
                            k_len,
                            limits.max_text_len,
                            ErrorCode::TextLenLimitExceeded,
                            k_off,
                        )?;
                    }
                    let key_bytes = self.read_exact(k_len)?;
                    core::str::from_utf8(key_bytes)
                        .map_err(|_| CborError::new(ErrorCode::Utf8Invalid, k_off))?;
                    let k_end = self.pos();
                    let enc_key = &self.data()[k_off..k_end];

                    if let Some(prev) = prev_key {
                        if prev == enc_key {
                            return Err(CborError::new(ErrorCode::DuplicateMapKey, k_off));
                        }
                        if !is_strictly_increasing_encoded(prev, enc_key) {
                            return Err(CborError::new(ErrorCode::NonCanonicalMapOrder, k_off));
                        }
                    }
                    prev_key = Some(enc_key);

                    self.skip_value(depth + 1)?;
                }
                Ok(())
            }
            6 => {
                let tag = self.read_uint_arg(ai, off)?;
                let negative = match tag {
                    2 => false,
                    3 => true,
                    _ => return Err(CborError::new(ErrorCode::ForbiddenOrMalformedTag, off)),
                };

                let m_off = self.pos();
                let first = self.read_u8()?;
                let m_major = first >> 5;
                let m_ai = first & 0x1f;
                if m_major != 2 {
                    return Err(CborError::new(ErrorCode::ForbiddenOrMalformedTag, m_off));
                }
                let m_len = self.read_len(m_ai, m_off)?;
                if let Some(limits) = self.limits {
                    Self::enforce_len(
                        m_len,
                        limits.max_bytes_len,
                        ErrorCode::BytesLenLimitExceeded,
                        m_off,
                    )?;
                }
                let mag = self.read_exact(m_len)?;
                validate_bignum_bytes(negative, mag).map_err(|code| CborError::new(code, m_off))?;
                Ok(())
            }
            7 => match ai {
                20..=22 => Ok(()),
                27 => {
                    let bits = self.read_be_u64()?;
                    validate_f64_bits(bits).map_err(|code| CborError::new(code, off))?;
                    Ok(())
                }
                28..=30 => Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
                24 => {
                    let simple = self.read_u8()?;
                    if simple < 24 {
                        Err(CborError::new(ErrorCode::NonCanonicalEncoding, off))
                    } else {
                        Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off))
                    }
                }
                _ => Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off)),
            },
            _ => unreachable!("major out of range"),
        }
    }
}
