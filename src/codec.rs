#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::canonical::CborBytesRef;
use crate::parse::validate_canonical;
use crate::query::{CborIntegerRef, CborValueRef};
use crate::{CborError, DecodeLimits, ErrorCode};

#[cfg(feature = "alloc")]
use crate::encode::Encoder;
#[cfg(feature = "alloc")]
use crate::CborBytes;

/// A CBOR map represented as ordered key/value entries.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapEntries<K, V>(pub Vec<(K, V)>);

#[cfg(feature = "alloc")]
impl<K, V> MapEntries<K, V> {
    /// Wrap an existing vector of entries.
    #[must_use]
    pub const fn new(entries: Vec<(K, V)>) -> Self {
        Self(entries)
    }
}

/// Decode a value from a `CborValueRef` without allocating strings/bytes unless required by `T`.
pub trait CborDecode<'de>: Sized {
    /// Decode `Self` from a canonical CBOR value reference.
    ///
    /// # Errors
    ///
    /// Returns an error if the CBOR value does not match the expected type or violates profile
    /// constraints.
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError>;
}

#[cfg(feature = "alloc")]
/// Encode a value into canonical CBOR bytes using the streaming encoder.
pub trait CborEncode {
    /// Encode `self` into the provided encoder.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError>;
}

#[cfg(feature = "alloc")]
/// Marker trait for values that can appear as CBOR array elements.
pub trait CborArrayElem {}

/// Validate canonical CBOR and decode a value using `CborDecode`.
///
/// # Errors
///
/// Returns an error if the input is not canonical CBOR or if decoding fails.
pub fn decode<'de, T: CborDecode<'de>>(
    bytes: &'de [u8],
    limits: DecodeLimits,
) -> Result<T, CborError> {
    let canon = validate_canonical(bytes, limits)?;
    decode_canonical(canon)
}

/// Decode a value from validated canonical bytes.
///
/// # Errors
///
/// Returns an error if decoding fails.
pub fn decode_canonical<'de, T: CborDecode<'de>>(canon: CborBytesRef<'de>) -> Result<T, CborError> {
    let bytes = canon.as_bytes();
    let value = CborValueRef::new(bytes, 0, bytes.len());
    T::decode(value)
}

/// Decode a value from owned canonical bytes.
///
/// # Errors
///
/// Returns an error if decoding fails.
#[cfg(feature = "alloc")]
pub fn decode_canonical_owned<'de, T: CborDecode<'de>>(
    canon: &'de CborBytes,
) -> Result<T, CborError> {
    decode_canonical(canon.as_ref())
}

#[cfg(feature = "alloc")]
/// Encode a value into canonical CBOR bytes.
///
/// # Errors
///
/// Returns an error if encoding fails.
pub fn encode_to_vec<T: CborEncode>(value: &T) -> Result<Vec<u8>, CborError> {
    let mut enc = Encoder::new();
    value.encode(&mut enc)?;
    Ok(enc.into_vec())
}

#[cfg(feature = "alloc")]
/// Encode a value into owned canonical CBOR bytes.
///
/// # Errors
///
/// Returns an error if encoding fails.
pub fn encode_to_canonical<T: CborEncode>(value: &T) -> Result<CborBytes, CborError> {
    let mut enc = Encoder::new();
    value.encode(&mut enc)?;
    enc.into_canonical()
}

fn decode_safe_i64(value: CborValueRef<'_>) -> Result<i64, CborError> {
    match value.integer()? {
        CborIntegerRef::Safe(v) => Ok(v),
        CborIntegerRef::Big(_) => Err(CborError::new(ErrorCode::ExpectedInteger, value.offset())),
    }
}

fn decode_safe_u64(value: CborValueRef<'_>) -> Result<u64, CborError> {
    let v = decode_safe_i64(value)?;
    u64::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, value.offset()))
}

fn mag_to_u128(mag: &[u8]) -> Option<u128> {
    if mag.len() > 16 {
        return None;
    }
    let mut buf = [0u8; 16];
    let start = 16 - mag.len();
    buf[start..].copy_from_slice(mag);
    Some(u128::from_be_bytes(buf))
}

impl<'de> CborDecode<'de> for () {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        if value.is_null() {
            Ok(())
        } else {
            Err(CborError::new(ErrorCode::ExpectedNull, value.offset()))
        }
    }
}

impl<'de> CborDecode<'de> for bool {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        value.bool()
    }
}

impl<'de> CborDecode<'de> for i64 {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        decode_safe_i64(value)
    }
}

impl<'de> CborDecode<'de> for i32 {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        let v = decode_safe_i64(value)?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, value.offset()))
    }
}

impl<'de> CborDecode<'de> for i16 {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        let v = decode_safe_i64(value)?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, value.offset()))
    }
}

impl<'de> CborDecode<'de> for i8 {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        let v = decode_safe_i64(value)?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, value.offset()))
    }
}

impl<'de> CborDecode<'de> for isize {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        let v = decode_safe_i64(value)?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, value.offset()))
    }
}

impl<'de> CborDecode<'de> for i128 {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        match value.integer()? {
            CborIntegerRef::Safe(v) => Ok(Self::from(v)),
            CborIntegerRef::Big(b) => {
                let mag = mag_to_u128(b.magnitude())
                    .ok_or_else(|| CborError::new(ErrorCode::ExpectedInteger, value.offset()))?;
                let n = Self::try_from(mag)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, value.offset()))?;
                if b.is_negative() {
                    Ok(-1 - n)
                } else {
                    Ok(n)
                }
            }
        }
    }
}

impl<'de> CborDecode<'de> for u64 {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        decode_safe_u64(value)
    }
}

impl<'de> CborDecode<'de> for u32 {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        let v = decode_safe_u64(value)?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, value.offset()))
    }
}

impl<'de> CborDecode<'de> for u16 {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        let v = decode_safe_u64(value)?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, value.offset()))
    }
}

impl<'de> CborDecode<'de> for u8 {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        let v = decode_safe_u64(value)?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, value.offset()))
    }
}

impl<'de> CborDecode<'de> for usize {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        let v = decode_safe_u64(value)?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, value.offset()))
    }
}

impl<'de> CborDecode<'de> for u128 {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        match value.integer()? {
            CborIntegerRef::Safe(v) => {
                let v_u64 = u64::try_from(v)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, value.offset()))?;
                Ok(Self::from(v_u64))
            }
            CborIntegerRef::Big(b) => {
                if b.is_negative() {
                    return Err(CborError::new(ErrorCode::ExpectedInteger, value.offset()));
                }
                mag_to_u128(b.magnitude())
                    .ok_or_else(|| CborError::new(ErrorCode::ExpectedInteger, value.offset()))
            }
        }
    }
}

impl<'de> CborDecode<'de> for f64 {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        value.float64()
    }
}

impl<'de> CborDecode<'de> for f32 {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        let v = value.float64()?;
        if v.is_nan() {
            return Ok(Self::NAN);
        }
        let off = value.offset();
        let bits = v.to_bits();
        let sign = ((bits >> 63) as u32) << 31;
        let exp = ((bits >> 52) & 0x7ff) as i32;
        let mant = bits & 0x000f_ffff_ffff_ffff;
        if exp == 0x7ff {
            if mant != 0 {
                return Ok(Self::NAN);
            }
            return Ok(Self::from_bits(sign | 0x7f80_0000));
        }
        if exp == 0 {
            if mant == 0 {
                return Ok(Self::from_bits(sign));
            }
            return Err(CborError::new(ErrorCode::ExpectedFloat, off));
        }

        let e = exp - 1023;
        let mant_with_hidden = (1u64 << 52) | mant;
        if e > 127 {
            return Err(CborError::new(ErrorCode::ExpectedFloat, off));
        }
        if e >= -126 {
            let lower = mant_with_hidden & ((1u64 << 29) - 1);
            if lower != 0 {
                return Err(CborError::new(ErrorCode::ExpectedFloat, off));
            }
            let mant32 = u32::try_from(mant_with_hidden >> 29)
                .map_err(|_| CborError::new(ErrorCode::ExpectedFloat, off))?
                & 0x7f_ffff;
            let exp32 = u32::try_from(e + 127)
                .map_err(|_| CborError::new(ErrorCode::ExpectedFloat, off))?;
            return Ok(Self::from_bits(sign | (exp32 << 23) | mant32));
        }
        if e >= -149 {
            let shift = u32::try_from(-e - 97)
                .map_err(|_| CborError::new(ErrorCode::ExpectedFloat, off))?;
            let lower = mant_with_hidden & ((1u64 << shift) - 1);
            if lower != 0 {
                return Err(CborError::new(ErrorCode::ExpectedFloat, off));
            }
            let mant32 = u32::try_from(mant_with_hidden >> shift)
                .map_err(|_| CborError::new(ErrorCode::ExpectedFloat, off))?;
            if mant32 == 0 || mant32 > 0x7f_ffff {
                return Err(CborError::new(ErrorCode::ExpectedFloat, off));
            }
            return Ok(Self::from_bits(sign | mant32));
        }
        Err(CborError::new(ErrorCode::ExpectedFloat, off))
    }
}

impl<'de> CborDecode<'de> for &'de str {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        value.text()
    }
}

impl<'de> CborDecode<'de> for &'de [u8] {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        value.bytes()
    }
}

impl<'de> CborDecode<'de> for CborValueRef<'de> {
    fn decode(value: Self) -> Result<Self, CborError> {
        Ok(value)
    }
}

impl<'de, T: CborDecode<'de>> CborDecode<'de> for Option<T> {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        if value.is_null() {
            Ok(None)
        } else {
            T::decode(value).map(Some)
        }
    }
}

#[cfg(feature = "alloc")]
impl<'de, T: CborDecode<'de> + CborArrayElem> CborDecode<'de> for Vec<T> {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        let arr = value.array()?;
        let mut out = Self::with_capacity(arr.len());
        for item in arr.iter() {
            out.push(T::decode(item?)?);
        }
        Ok(out)
    }
}

#[cfg(feature = "alloc")]
impl<'de, V: CborDecode<'de>> CborDecode<'de> for MapEntries<&'de str, V> {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        let map = value.map()?;
        let mut out = Vec::with_capacity(map.len());
        for entry in map.iter() {
            let (k, v) = entry?;
            out.push((k, V::decode(v)?));
        }
        Ok(Self(out))
    }
}

#[cfg(feature = "alloc")]
impl<'de, V: CborDecode<'de>> CborDecode<'de> for MapEntries<String, V> {
    fn decode(value: CborValueRef<'de>) -> Result<Self, CborError> {
        let map = value.map()?;
        let mut out = Vec::with_capacity(map.len());
        for entry in map.iter() {
            let (k, v) = entry?;
            out.push((k.to_string(), V::decode(v)?));
        }
        Ok(Self(out))
    }
}

#[cfg(feature = "alloc")]
impl CborDecode<'_> for String {
    fn decode(value: CborValueRef<'_>) -> Result<Self, CborError> {
        value.text().map(str::to_string)
    }
}

#[cfg(feature = "alloc")]
impl CborDecode<'_> for Vec<u8> {
    fn decode(value: CborValueRef<'_>) -> Result<Self, CborError> {
        value.bytes().map(<[u8]>::to_vec)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for () {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.null()
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for bool {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.bool(*self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for i64 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(*self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for i32 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for i16 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for i8 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for isize {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(
            i64::try_from(*self)
                .map_err(|_| CborError::new(ErrorCode::LengthOverflow, enc.len()))?,
        )
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for i128 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int_i128(*self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for u64 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        if *self <= crate::MAX_SAFE_INTEGER {
            let v = i64::try_from(*self)
                .map_err(|_| CborError::new(ErrorCode::LengthOverflow, enc.len()))?;
            enc.int(v)
        } else {
            enc.int_u128(u128::from(*self))
        }
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for u32 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for u16 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for u8 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for usize {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        let v = u64::try_from(*self)
            .map_err(|_| CborError::new(ErrorCode::LengthOverflow, enc.len()))?;
        if v <= crate::MAX_SAFE_INTEGER {
            let v = i64::try_from(v)
                .map_err(|_| CborError::new(ErrorCode::LengthOverflow, enc.len()))?;
            enc.int(v)
        } else {
            enc.int_u128(u128::from(v))
        }
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for u128 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int_u128(*self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for f64 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        let bits = crate::scalar::F64Bits::try_from_f64(*self)?;
        enc.float(bits)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for f32 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        let bits = crate::scalar::F64Bits::try_from_f64(f64::from(*self))?;
        enc.float(bits)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for &str {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.text(self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for &[u8] {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.bytes(self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for String {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.text(self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for Vec<u8> {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.bytes(self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for CborValueRef<'_> {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.raw_value_ref(*self)
    }
}

#[cfg(feature = "alloc")]
impl CborEncode for CborBytesRef<'_> {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.raw_cbor(*self)
    }
}

#[cfg(feature = "alloc")]
impl<T: CborEncode> CborEncode for Option<T> {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        match self {
            Some(v) => v.encode(enc),
            None => enc.null(),
        }
    }
}

#[cfg(feature = "alloc")]
impl<T: CborEncode + CborArrayElem> CborEncode for Vec<T> {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.array(self.len(), |a| {
            for item in self {
                a.value(item)?;
            }
            Ok(())
        })
    }
}

#[cfg(feature = "alloc")]
impl<K, V> CborEncode for MapEntries<K, V>
where
    K: AsRef<str>,
    V: CborEncode,
{
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.map(self.0.len(), |m| {
            for (k, v) in &self.0 {
                m.entry(k.as_ref(), |enc| v.encode(enc))?;
            }
            Ok(())
        })
    }
}

#[cfg(feature = "alloc")]
impl CborArrayElem for bool {}
#[cfg(feature = "alloc")]
impl CborArrayElem for i64 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for i32 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for i16 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for i8 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for isize {}
#[cfg(feature = "alloc")]
impl CborArrayElem for i128 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for u64 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for u32 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for u16 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for usize {}
#[cfg(feature = "alloc")]
impl CborArrayElem for u128 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for f64 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for f32 {}
#[cfg(feature = "alloc")]
impl CborArrayElem for String {}
#[cfg(feature = "alloc")]
impl CborArrayElem for &str {}
#[cfg(feature = "alloc")]
impl CborArrayElem for &[u8] {}
#[cfg(feature = "alloc")]
impl CborArrayElem for CborValueRef<'_> {}
#[cfg(feature = "alloc")]
impl CborArrayElem for CborBytesRef<'_> {}
#[cfg(feature = "alloc")]
impl<T: CborArrayElem> CborArrayElem for Option<T> {}
#[cfg(feature = "alloc")]
impl<T: CborArrayElem> CborArrayElem for Vec<T> {}
#[cfg(feature = "alloc")]
impl<K, V> CborArrayElem for MapEntries<K, V>
where
    K: AsRef<str>,
    V: CborArrayElem,
{
}
