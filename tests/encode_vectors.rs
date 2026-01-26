#![cfg(feature = "alloc")]

use sacp_cbor::{
    CborErrorCode, CborValue, F64Bits, MAX_SAFE_INTEGER, MAX_SAFE_INTEGER_I64, MIN_SAFE_INTEGER,
};

#[test]
fn encode_uint_boundaries() {
    assert_eq!(CborValue::Int(0).encode_canonical().unwrap(), vec![0x00]);
    assert_eq!(CborValue::Int(23).encode_canonical().unwrap(), vec![0x17]);
    assert_eq!(
        CborValue::Int(24).encode_canonical().unwrap(),
        vec![0x18, 0x18]
    );
    assert_eq!(
        CborValue::Int(255).encode_canonical().unwrap(),
        vec![0x18, 0xff]
    );
    assert_eq!(
        CborValue::Int(256).encode_canonical().unwrap(),
        vec![0x19, 0x01, 0x00]
    );
    assert_eq!(
        CborValue::Int(65_535).encode_canonical().unwrap(),
        vec![0x19, 0xff, 0xff]
    );
    assert_eq!(
        CborValue::Int(65_536).encode_canonical().unwrap(),
        vec![0x1a, 0x00, 0x01, 0x00, 0x00]
    );

    let mut expected = vec![0x1b];
    expected.extend_from_slice(&MAX_SAFE_INTEGER.to_be_bytes());
    assert_eq!(
        CborValue::Int(MAX_SAFE_INTEGER_I64)
            .encode_canonical()
            .unwrap(),
        expected
    );
}

#[test]
fn encode_nint_boundaries() {
    assert_eq!(CborValue::Int(-1).encode_canonical().unwrap(), vec![0x20]);
    assert_eq!(CborValue::Int(-24).encode_canonical().unwrap(), vec![0x37]);
    assert_eq!(
        CborValue::Int(-25).encode_canonical().unwrap(),
        vec![0x38, 0x18]
    );
    assert_eq!(
        CborValue::Int(-256).encode_canonical().unwrap(),
        vec![0x38, 0xff]
    );
    assert_eq!(
        CborValue::Int(-257).encode_canonical().unwrap(),
        vec![0x39, 0x01, 0x00]
    );
    assert_eq!(
        CborValue::Int(-65_536).encode_canonical().unwrap(),
        vec![0x39, 0xff, 0xff]
    );
    assert_eq!(
        CborValue::Int(-65_537).encode_canonical().unwrap(),
        vec![0x3a, 0x00, 0x01, 0x00, 0x00]
    );
}

#[test]
fn encode_rejects_int_outside_safe_range() {
    let too_big = MAX_SAFE_INTEGER_I64 + 1;
    let err = CborValue::Int(too_big).encode_canonical().unwrap_err();
    assert_eq!(err.code, CborErrorCode::IntegerOutsideSafeRange);

    let too_small = MIN_SAFE_INTEGER - 1;
    let err = CborValue::Int(too_small).encode_canonical().unwrap_err();
    assert_eq!(err.code, CborErrorCode::IntegerOutsideSafeRange);
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
        assert_eq!(CborValue::Text(s).encode_canonical().unwrap(), expected);
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
        assert_eq!(CborValue::Bytes(b).encode_canonical().unwrap(), expected);
    }
}

#[test]
fn encode_float_nan_is_canonical() {
    let bits = F64Bits::try_from_f64(f64::NAN).unwrap();
    let bytes = CborValue::Float(bits).encode_canonical().unwrap();

    let mut expected = vec![0xfb];
    expected.extend_from_slice(&0x7ff8_0000_0000_0000u64.to_be_bytes());
    assert_eq!(bytes, expected);
}

#[test]
fn encode_float_rejects_negative_zero() {
    let err = F64Bits::try_from_f64(-0.0).unwrap_err();
    assert_eq!(err.code, CborErrorCode::NegativeZeroForbidden);
}
