//! Native encode helpers and `CborEncode` implementations.

#[cfg(feature = "collections")]
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(all(feature = "collections", feature = "std"))]
use std::collections::HashMap;
#[cfg(all(feature = "collections", feature = "std"))]
use std::hash::BuildHasher;

#[cfg(feature = "collections")]
use crate::alloc_util;
use crate::bytes::{Bytes, BytesRef};
use crate::canonical::{CanonicalCbor, CanonicalCborRef};
use crate::codec::CborEncode;
#[cfg(feature = "collections")]
use crate::decode::MapEntries;
use crate::encode::{ArrayEncoder, Encoder};
use crate::query::CborValueRef;
use crate::scalar::F64Bits;
use crate::value::{BigInt, Integer};
use crate::{CborError, ErrorCode};

/// Encode a value into canonical CBOR bytes.
///
/// # Errors
///
/// Returns an error if encoding fails.
pub fn encode_to_vec<T: CborEncode>(value: &T) -> Result<Vec<u8>, CborError> {
    let mut enc = Encoder::new();
    value.encode(&mut enc)?;
    Ok(enc.finish()?.into_bytes())
}

/// Encode a value into owned canonical CBOR bytes.
///
/// # Errors
///
/// Returns an error if encoding fails.
pub fn encode_to_canonical<T: CborEncode>(value: &T) -> Result<CanonicalCbor, CborError> {
    let mut enc = Encoder::new();
    value.encode(&mut enc)?;
    enc.finish()
}

impl<T: CborEncode + ?Sized> CborEncode for &T {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        (*self).encode(enc)
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        (*self).encode_array_item(array)
    }
}

impl CborEncode for () {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.null()
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.null()
    }
}

impl CborEncode for bool {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.bool(*self)
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.bool(*self)
    }
}

impl CborEncode for i64 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(*self)
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.int(*self)
    }
}

impl CborEncode for i32 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.int(i64::from(*self))
    }
}

impl CborEncode for i16 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.int(i64::from(*self))
    }
}

impl CborEncode for i8 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.int(i64::from(*self))
    }
}

impl CborEncode for isize {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(
            i64::try_from(*self)
                .map_err(|_| CborError::new(ErrorCode::LengthOverflow, enc.len()))?,
        )
    }
}

impl CborEncode for i128 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int_i128(*self)
    }
}

impl CborEncode for u64 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int_u128(u128::from(*self))
    }
}

impl CborEncode for u32 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.int(i64::from(*self))
    }
}

impl CborEncode for u16 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.int(i64::from(*self))
    }
}

impl CborEncode for u8 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int(i64::from(*self))
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.int(i64::from(*self))
    }
}

impl CborEncode for usize {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        let v = u64::try_from(*self)
            .map_err(|_| CborError::new(ErrorCode::LengthOverflow, enc.len()))?;
        enc.int_u128(u128::from(v))
    }
}

impl CborEncode for u128 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.int_u128(*self)
    }
}

impl CborEncode for BigInt {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.bignum(self.is_negative(), self.magnitude())
    }
}

impl CborEncode for Integer {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        if let Some(value) = self.as_i64() {
            enc.int(value)
        } else if let Some(big) = self.as_bigint() {
            enc.bignum(big.is_negative(), big.magnitude())
        } else {
            Err(CborError::new(ErrorCode::ExpectedInteger, enc.len()))
        }
    }
}

impl CborEncode for F64Bits {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.float(*self)
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.float(*self)
    }
}

impl CborEncode for f64 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.float(F64Bits::try_from_f64(*self)?)
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.float(F64Bits::try_from_f64(*self)?)
    }
}

impl CborEncode for f32 {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.float(F64Bits::try_from_f64(f64::from(*self))?)
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.float(F64Bits::try_from_f64(f64::from(*self))?)
    }
}

impl CborEncode for str {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.text(self)
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.text(self)
    }
}

impl CborEncode for [u8] {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.bytes(self)
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.bytes(self)
    }
}

impl CborEncode for String {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.text(self)
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.text(self)
    }
}

impl CborEncode for BytesRef<'_> {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.bytes(self.as_slice())
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.bytes(self.as_slice())
    }
}

impl CborEncode for Bytes {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.bytes(self.as_slice())
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.bytes(self.as_slice())
    }
}

impl<const N: usize> CborEncode for [u8; N] {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.bytes(self)
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.bytes(self)
    }
}

impl CborEncode for CborValueRef<'_> {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.raw_value_ref(*self)
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.raw_value_ref(*self)
    }
}

impl CborEncode for CanonicalCborRef<'_> {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.raw_cbor(*self)
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.raw_cbor(*self)
    }
}

impl CborEncode for CanonicalCbor {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.raw_cbor(self.as_canonical_ref())
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.raw_cbor(self.as_canonical_ref())
    }
}

impl<T: CborEncode> CborEncode for Option<T> {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.map(1, |map| match self {
            None => map.entry("none", Encoder::null),
            Some(value) => map.entry("some", |enc| value.encode(enc)),
        })
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.map(1, |map| match self {
            None => map.entry("none", Encoder::null),
            Some(value) => map.entry("some", |enc| value.encode(enc)),
        })
    }
}

#[cfg(feature = "collections")]
impl<T: CborEncode> CborEncode for Vec<T> {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.array(self.len(), |a| {
            for item in self {
                a.value(item)?;
            }
            Ok(())
        })
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.array(self.len(), |a| {
            for item in self {
                a.value(item)?;
            }
            Ok(())
        })
    }
}

#[cfg(feature = "collections")]
impl<K, V> CborEncode for BTreeMap<K, V>
where
    K: AsRef<str> + Ord,
    V: CborEncode,
{
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        encode_sorted_text_entries(enc, self.len(), self.iter().map(|(k, v)| (k.as_ref(), v)))
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        encode_sorted_text_entries_in_array(
            array,
            self.len(),
            self.iter().map(|(k, v)| (k.as_ref(), v)),
        )
    }
}

#[cfg(all(feature = "collections", feature = "std"))]
impl<K, V, S> CborEncode for HashMap<K, V, S>
where
    K: AsRef<str> + Eq + core::hash::Hash,
    V: CborEncode,
    S: BuildHasher,
{
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        encode_sorted_text_entries(enc, self.len(), self.iter().map(|(k, v)| (k.as_ref(), v)))
    }

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        encode_sorted_text_entries_in_array(
            array,
            self.len(),
            self.iter().map(|(k, v)| (k.as_ref(), v)),
        )
    }
}

#[cfg(feature = "collections")]
fn encode_sorted_text_entries<'a, V, I>(
    enc: &mut Encoder,
    len: usize,
    entries: I,
) -> Result<(), CborError>
where
    V: CborEncode + 'a,
    I: IntoIterator<Item = (&'a str, &'a V)>,
{
    let off = enc.len();
    let mut sorted = alloc_util::try_vec_with_capacity::<(&str, &V)>(len, off)?;
    for (k, v) in entries {
        sorted.push((k, v));
    }
    sorted.sort_by(|(a, _), (b, _)| crate::profile::cmp_text_keys_canonical(a, b));

    enc.map(sorted.len(), |m| {
        for (k, v) in sorted {
            m.entry(k, |enc| v.encode(enc))?;
        }
        Ok(())
    })
}

#[cfg(feature = "collections")]
fn encode_sorted_text_entries_in_array<'a, V, I>(
    array: &mut ArrayEncoder<'_>,
    len: usize,
    entries: I,
) -> Result<(), CborError>
where
    V: CborEncode + 'a,
    I: IntoIterator<Item = (&'a str, &'a V)>,
{
    let mut sorted = alloc_util::try_vec_with_capacity::<(&str, &V)>(len, array.encoded_len())?;
    for (k, v) in entries {
        sorted.push((k, v));
    }
    sorted.sort_by(|(a, _), (b, _)| crate::profile::cmp_text_keys_canonical(a, b));

    array.map(sorted.len(), |m| {
        for (k, v) in sorted {
            m.entry(k, |enc| v.encode(enc))?;
        }
        Ok(())
    })
}

#[cfg(feature = "collections")]
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

    fn encode_array_item(&self, array: &mut ArrayEncoder<'_>) -> Result<(), CborError> {
        array.map(self.0.len(), |m| {
            for (k, v) in &self.0 {
                m.entry(k.as_ref(), |enc| v.encode(enc))?;
            }
            Ok(())
        })
    }
}
