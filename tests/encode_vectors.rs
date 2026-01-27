#![cfg(feature = "alloc")]

use sacp_cbor::{CborError, Encoder, ErrorCode, F64Bits, MAX_SAFE_INTEGER_I64, MIN_SAFE_INTEGER};

fn encode_one(f: impl FnOnce(&mut Encoder) -> Result<(), CborError>) -> Vec<u8> {
    let mut enc = Encoder::new();
    f(&mut enc).unwrap();
    enc.into_vec()
}

#[test]
fn encode_uint_boundaries() {
    assert_eq!(encode_one(|e| e.int(0)), vec![0x00]);
    assert_eq!(encode_one(|e| e.int(23)), vec![0x17]);
    assert_eq!(encode_one(|e| e.int(24)), vec![0x18, 0x18]);
    assert_eq!(encode_one(|e| e.int(255)), vec![0x18, 0xff]);
    assert_eq!(encode_one(|e| e.int(256)), vec![0x19, 0x01, 0x00]);
    assert_eq!(encode_one(|e| e.int(65_535)), vec![0x19, 0xff, 0xff]);
    assert_eq!(
        encode_one(|e| e.int(65_536)),
        vec![0x1a, 0x00, 0x01, 0x00, 0x00]
    );

    let mut expected = vec![0x1b];
    expected.extend_from_slice(&u64::try_from(MAX_SAFE_INTEGER_I64).unwrap().to_be_bytes());
    assert_eq!(encode_one(|e| e.int(MAX_SAFE_INTEGER_I64)), expected);
}

#[test]
fn encode_nint_boundaries() {
    assert_eq!(encode_one(|e| e.int(-1)), vec![0x20]);
    assert_eq!(encode_one(|e| e.int(-24)), vec![0x37]);
    assert_eq!(encode_one(|e| e.int(-25)), vec![0x38, 0x18]);
    assert_eq!(encode_one(|e| e.int(-256)), vec![0x38, 0xff]);
    assert_eq!(encode_one(|e| e.int(-257)), vec![0x39, 0x01, 0x00]);
    assert_eq!(encode_one(|e| e.int(-65_536)), vec![0x39, 0xff, 0xff]);
    assert_eq!(
        encode_one(|e| e.int(-65_537)),
        vec![0x3a, 0x00, 0x01, 0x00, 0x00]
    );
}

#[test]
fn encode_rejects_int_outside_safe_range() {
    let too_big = MAX_SAFE_INTEGER_I64 + 1;
    let err = Encoder::new().int(too_big).unwrap_err();
    assert_eq!(err.code, ErrorCode::IntegerOutsideSafeRange);

    let too_small = MIN_SAFE_INTEGER - 1;
    let err = Encoder::new().int(too_small).unwrap_err();
    assert_eq!(err.code, ErrorCode::IntegerOutsideSafeRange);
}

#[test]
fn encode_text_len_boundaries() {
    for &len in &[0usize, 23, 24, 255, 256] {
        let s = "a".repeat(len);
        let mut expected = Vec::new();
        if len < 24 {
            expected.push(0x60 | (len as u8));
        } else if len <= 0xff {
            expected.push(0x78);
            expected.push(len as u8);
        } else {
            expected.push(0x79);
            expected.extend_from_slice(&(len as u16).to_be_bytes());
        }
        expected.extend_from_slice(s.as_bytes());
        assert_eq!(encode_one(|e| e.text(&s)), expected);
    }
}

#[test]
fn encode_bytes_len_boundaries() {
    for &len in &[0usize, 23, 24, 255, 256] {
        let b = vec![0u8; len];
        let mut expected = Vec::new();
        if len < 24 {
            expected.push(0x40 | (len as u8));
        } else if len <= 0xff {
            expected.push(0x58);
            expected.push(len as u8);
        } else {
            expected.push(0x59);
            expected.extend_from_slice(&(len as u16).to_be_bytes());
        }
        expected.extend_from_slice(&b);
        assert_eq!(encode_one(|e| e.bytes(&b)), expected);
    }
}

#[test]
fn encode_float_nan_is_canonical() {
    let bits = F64Bits::try_from_f64(f64::NAN).unwrap();
    let bytes = encode_one(|e| e.float(bits));

    let mut expected = vec![0xfb];
    expected.extend_from_slice(&0x7ff8_0000_0000_0000u64.to_be_bytes());
    assert_eq!(bytes, expected);
}

#[test]
fn encode_float_rejects_negative_zero() {
    let err = F64Bits::try_from_f64(-0.0).unwrap_err();
    assert_eq!(err.code, ErrorCode::NegativeZeroForbidden);
}
