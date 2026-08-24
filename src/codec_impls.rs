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
use crate::encode::{ByteSink, EncodeResult, Encoder, ValueEncoder};
use crate::query::CborValueRef;
use crate::scalar::F64Bits;
use crate::value::{BigInt, Integer};
use crate::{CborError, ErrorCode};

#[allow(clippy::needless_pass_by_value)]
const fn vector_error(error: crate::EncodeError<CborError>) -> CborError {
    match error {
        crate::EncodeError::Cbor(error) | crate::EncodeError::Sink(error) => error,
        crate::EncodeError::Poisoned => CborError::new(ErrorCode::EncoderPoisoned, 0),
    }
}

/// Encode a value into canonical CBOR bytes.
///
/// # Errors
///
/// Returns the first profile, allocation, or vector-sink error.
pub fn encode_to_vec<T: CborEncode>(value: &T) -> Result<Vec<u8>, CborError> {
    let mut encoder = Encoder::new();
    encoder.encode(value).map_err(vector_error)?;
    encoder.finish().map_err(vector_error)
}

/// Encode a value into an owned canonical witness.
///
/// # Errors
///
/// Returns the first profile, allocation, or vector-sink error.
pub fn encode_to_canonical<T: CborEncode>(value: &T) -> Result<CanonicalCbor, CborError> {
    Ok(CanonicalCbor::new_unchecked(encode_to_vec(value)?))
}

/// Encode one value emitted through the controlled adapter into an owned
/// canonical witness.
///
/// # Errors
///
/// Returns the first error produced by the emitter or vector sink.
pub fn encode_with_to_canonical<F>(encode: F) -> Result<CanonicalCbor, CborError>
where
    F: FnOnce(
        &mut ValueEncoder<'_, crate::encode::VecSink>,
    ) -> EncodeResult<(), crate::encode::VecSink>,
{
    let mut encoder = Encoder::new();
    encoder.encode_with(encode).map_err(vector_error)?;
    let bytes = encoder.finish().map_err(vector_error)?;
    Ok(CanonicalCbor::new_unchecked(bytes))
}

impl<T: CborEncode + ?Sized> CborEncode for &T {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        (*self).encode(encoder)
    }
}

impl CborEncode for () {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.null()
    }
}

impl CborEncode for bool {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.bool(*self)
    }
}

macro_rules! narrow_integer {
    ($ty:ty) => {
        impl CborEncode for $ty {
            fn encode<S: ByteSink>(
                &self,
                encoder: &mut ValueEncoder<'_, S>,
            ) -> EncodeResult<(), S> {
                encoder.int(i64::from(*self))
            }
        }
    };
}

narrow_integer!(i8);
narrow_integer!(i16);
narrow_integer!(i32);
narrow_integer!(u8);
narrow_integer!(u16);
narrow_integer!(u32);

impl CborEncode for i64 {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.int(*self)
    }
}

impl CborEncode for isize {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.int(i64::try_from(*self).map_err(|_| CborError::new(ErrorCode::LengthOverflow, 0))?)
    }
}

impl CborEncode for i128 {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.int_i128(*self)
    }
}

impl CborEncode for u64 {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.int_u128(u128::from(*self))
    }
}

impl CborEncode for usize {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        let value =
            u64::try_from(*self).map_err(|_| CborError::new(ErrorCode::LengthOverflow, 0))?;
        encoder.int_u128(u128::from(value))
    }
}

impl CborEncode for u128 {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.int_u128(*self)
    }
}

impl CborEncode for BigInt {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.bignum(self.is_negative(), self.magnitude())
    }
}

impl CborEncode for Integer {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        if let Some(value) = self.as_i64() {
            encoder.int(value)
        } else if let Some(big) = self.as_bigint() {
            encoder.bignum(big.is_negative(), big.magnitude())
        } else {
            Err(CborError::new(ErrorCode::ExpectedInteger, 0).into())
        }
    }
}

impl CborEncode for F64Bits {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.float(*self)
    }
}

impl CborEncode for f64 {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.float(F64Bits::try_from_f64(*self)?)
    }
}

impl CborEncode for f32 {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.float(F64Bits::try_from_f64(f64::from(*self))?)
    }
}

impl CborEncode for str {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.text(self)
    }
}

impl CborEncode for String {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.text(self)
    }
}

impl CborEncode for [u8] {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.bytes(self)
    }
}

impl CborEncode for BytesRef<'_> {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.bytes((*self).as_slice())
    }
}

impl CborEncode for Bytes {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.bytes(self.as_slice())
    }
}

impl<const N: usize> CborEncode for [u8; N] {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.bytes(self)
    }
}

impl CborEncode for CborValueRef<'_> {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.raw_value_ref(*self)
    }
}

impl CborEncode for CanonicalCborRef<'_> {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.raw_cbor(*self)
    }
}

impl CborEncode for CanonicalCbor {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.raw_cbor(self.as_canonical_ref())
    }
}

impl<T: CborEncode> CborEncode for Option<T> {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.map(1, |map| match self {
            None => map.entry("none", Encoder::null),
            Some(value) => map.entry("some", |encoder| encoder.encode(value)),
        })
    }
}

#[cfg(feature = "collections")]
impl<T: CborEncode> CborEncode for Vec<T> {
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.array(self.len(), |array| {
            for item in self {
                array.value(item)?;
            }
            Ok(())
        })
    }
}

#[cfg(feature = "collections")]
fn sorted_entries<'a, V, I>(
    len: usize,
    entries: I,
    offset: usize,
) -> Result<Vec<(&'a str, &'a V)>, CborError>
where
    V: 'a,
    I: IntoIterator<Item = (&'a str, &'a V)>,
{
    let mut sorted = alloc_util::try_vec_with_capacity(len, offset)?;
    sorted.extend(entries);
    sorted.sort_unstable_by(|(a, _), (b, _)| crate::profile::cmp_text_keys_canonical(a, b));
    if sorted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(CborError::new(ErrorCode::DuplicateMapKey, offset));
    }
    Ok(sorted)
}

#[cfg(feature = "collections")]
impl<K, V> CborEncode for BTreeMap<K, V>
where
    K: AsRef<str> + Ord,
    V: CborEncode,
{
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.map(self.len(), |map| {
            let entries = sorted_entries(
                self.len(),
                self.iter().map(|(k, v)| (k.as_ref(), v)),
                map.offset(),
            )?;
            for (key, value) in entries {
                map.entry(key, |encoder| encoder.encode(value))?;
            }
            Ok(())
        })
    }
}

#[cfg(all(feature = "collections", feature = "std"))]
impl<K, V, H> CborEncode for HashMap<K, V, H>
where
    K: AsRef<str> + Eq + core::hash::Hash,
    V: CborEncode,
    H: BuildHasher,
{
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.map(self.len(), |map| {
            let entries = sorted_entries(
                self.len(),
                self.iter().map(|(k, v)| (k.as_ref(), v)),
                map.offset(),
            )?;
            for (key, value) in entries {
                map.entry(key, |encoder| encoder.encode(value))?;
            }
            Ok(())
        })
    }
}

#[cfg(feature = "collections")]
impl<K, V> CborEncode for MapEntries<K, V>
where
    K: AsRef<str>,
    V: CborEncode,
{
    fn encode<S: ByteSink>(&self, encoder: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encoder.map(self.0.len(), |map| {
            for (key, value) in &self.0 {
                map.entry(key.as_ref(), |encoder| encoder.encode(value))?;
            }
            Ok(())
        })
    }
}
