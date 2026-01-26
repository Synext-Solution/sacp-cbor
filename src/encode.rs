use crate::order::cmp_text_keys_by_canonical_encoding;
use crate::value::{
    validate_bignum, validate_f64, validate_int_safe_i64, BigInt, CborMap, CborValue, F64Bits,
};
use crate::{CborError, CborErrorCode};
use alloc::vec::Vec;

pub fn encode_to_vec(value: &CborValue) -> Result<Vec<u8>, CborError> {
    let mut sink = VecSink::new();
    encode_value(&mut sink, value)?;
    Ok(sink.into_vec())
}

#[cfg(feature = "sha2")]
pub fn encode_sha256(value: &CborValue) -> Result<[u8; 32], CborError> {
    use sha2::{Digest, Sha256};

    let mut sink = HashSink::new(Sha256::new());
    encode_value(&mut sink, value)?;
    let out = sink.hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(out.as_slice());
    Ok(digest)
}

trait Sink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), CborError>;

    fn write_u8(&mut self, byte: u8) -> Result<(), CborError> {
        self.write(&[byte])
    }
}

struct VecSink {
    buf: Vec<u8>,
}

impl VecSink {
    const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    fn reserve(&mut self, additional: usize) -> Result<(), CborError> {
        self.buf
            .try_reserve(additional)
            .map_err(|_| CborError::encode(CborErrorCode::AllocationFailed))?;
        Ok(())
    }
}

impl Sink for VecSink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), CborError> {
        self.reserve(bytes.len())?;
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    fn write_u8(&mut self, byte: u8) -> Result<(), CborError> {
        self.reserve(1)?;
        self.buf.push(byte);
        Ok(())
    }
}

#[cfg(feature = "sha2")]
struct HashSink<D> {
    hasher: D,
}

#[cfg(feature = "sha2")]
impl<D> HashSink<D> {
    const fn new(hasher: D) -> Self {
        Self { hasher }
    }
}

#[cfg(feature = "sha2")]
impl<D: sha2::Digest> Sink for HashSink<D> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), CborError> {
        self.hasher.update(bytes);
        Ok(())
    }
}

fn encode_value<S: Sink>(sink: &mut S, value: &CborValue) -> Result<(), CborError> {
    match value {
        CborValue::Int(v) => encode_int(sink, *v),
        CborValue::Bignum(b) => encode_bignum(sink, b),
        CborValue::Bytes(b) => encode_bytes(sink, b),
        CborValue::Text(s) => encode_text(sink, s),
        CborValue::Array(items) => encode_array(sink, items),
        CborValue::Map(map) => encode_map(sink, map),
        CborValue::Bool(false) => sink.write_u8(0xf4),
        CborValue::Bool(true) => sink.write_u8(0xf5),
        CborValue::Null => sink.write_u8(0xf6),
        CborValue::Float(bits) => encode_float64(sink, *bits),
    }
}

fn encode_int<S: Sink>(sink: &mut S, v: i64) -> Result<(), CborError> {
    validate_int_safe_i64(v).map_err(CborError::encode)?;

    if v >= 0 {
        let u = u64::try_from(v).map_err(|_| CborError::encode(CborErrorCode::LengthOverflow))?;
        encode_major_uint(sink, 0, u)
    } else {
        let n_i128 = -1_i128 - i128::from(v);
        let n_u64 =
            u64::try_from(n_i128).map_err(|_| CborError::encode(CborErrorCode::LengthOverflow))?;
        encode_major_uint(sink, 1, n_u64)
    }
}

fn encode_bignum<S: Sink>(sink: &mut S, b: &BigInt) -> Result<(), CborError> {
    validate_bignum(b.is_negative(), b.magnitude()).map_err(CborError::encode)?;

    let tag = if b.is_negative() { 3u64 } else { 2u64 };
    encode_major_uint(sink, 6, tag)?;
    encode_bytes(sink, b.magnitude())
}

fn encode_bytes<S: Sink>(sink: &mut S, bytes: &[u8]) -> Result<(), CborError> {
    encode_major_len(sink, 2, bytes.len())?;
    sink.write(bytes)
}

fn encode_text<S: Sink>(sink: &mut S, s: &str) -> Result<(), CborError> {
    // `str` guarantees valid UTF-8.
    let b = s.as_bytes();
    encode_major_len(sink, 3, b.len())?;
    sink.write(b)
}

fn encode_array<S: Sink>(sink: &mut S, items: &[CborValue]) -> Result<(), CborError> {
    encode_major_len(sink, 4, items.len())?;
    for it in items {
        encode_value(sink, it)?;
    }
    Ok(())
}

fn encode_map<S: Sink>(sink: &mut S, map: &CborMap) -> Result<(), CborError> {
    encode_major_len(sink, 5, map.len())?;

    // Defensive check: ensure keys are strictly increasing in canonical order.
    let mut prev: Option<&str> = None;
    for (k, v) in map.iter() {
        if let Some(pk) = prev {
            match cmp_text_keys_by_canonical_encoding(pk, k) {
                core::cmp::Ordering::Less => {}
                core::cmp::Ordering::Equal => {
                    return Err(CborError::encode(CborErrorCode::DuplicateMapKey));
                }
                core::cmp::Ordering::Greater => {
                    return Err(CborError::encode(CborErrorCode::NonCanonicalMapOrder));
                }
            }
        }
        prev = Some(k);

        encode_text(sink, k)?;
        encode_value(sink, v)?;
    }
    Ok(())
}

fn encode_float64<S: Sink>(sink: &mut S, bits: F64Bits) -> Result<(), CborError> {
    let raw = bits.bits();
    validate_f64(raw).map_err(CborError::encode)?;
    sink.write_u8(0xfb)?;
    sink.write(&raw.to_be_bytes())
}

fn encode_major_len<S: Sink>(sink: &mut S, major: u8, len: usize) -> Result<(), CborError> {
    let len_u64 =
        u64::try_from(len).map_err(|_| CborError::encode(CborErrorCode::LengthOverflow))?;
    encode_major_uint(sink, major, len_u64)
}

fn encode_major_uint<S: Sink>(sink: &mut S, major: u8, value: u64) -> Result<(), CborError> {
    debug_assert!(major <= 7);
    if let Ok(v8) = u8::try_from(value) {
        if v8 < 24 {
            return sink.write_u8((major << 5) | v8);
        }
        sink.write_u8((major << 5) | 24)?;
        return sink.write_u8(v8);
    }
    if let Ok(v16) = u16::try_from(value) {
        sink.write_u8((major << 5) | 25)?;
        return sink.write(&v16.to_be_bytes());
    }
    if let Ok(v32) = u32::try_from(value) {
        sink.write_u8((major << 5) | 26)?;
        return sink.write(&v32.to_be_bytes());
    }
    sink.write_u8((major << 5) | 27)?;
    sink.write(&value.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::encode_to_vec;
    use crate::value::{CborMap, CborValue};
    use crate::CborErrorCode;

    #[test]
    fn encode_map_rejects_unsorted_entries_even_if_constructed_unsafely() {
        let m = CborMap::from_sorted_entries(vec![
            ("aa".to_string(), CborValue::Int(1)),
            ("b".to_string(), CborValue::Int(2)),
        ]);
        let v = CborValue::Map(m);
        let err = encode_to_vec(&v).unwrap_err();
        assert_eq!(err.code, CborErrorCode::NonCanonicalMapOrder);
    }

    #[test]
    fn encode_map_rejects_duplicate_keys_if_constructed_unsafely() {
        let m = CborMap::from_sorted_entries(vec![
            ("a".to_string(), CborValue::Int(1)),
            ("a".to_string(), CborValue::Int(2)),
        ]);
        let v = CborValue::Map(m);
        let err = encode_to_vec(&v).unwrap_err();
        assert_eq!(err.code, CborErrorCode::DuplicateMapKey);
    }
}
