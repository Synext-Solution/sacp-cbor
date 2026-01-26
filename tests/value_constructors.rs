#![cfg(feature = "alloc")]

use sacp_cbor::{BigInt, ErrorCode, F64Bits};

#[test]
fn bigint_rejects_empty_and_leading_zero() {
    let err = BigInt::new(false, Vec::new()).unwrap_err();
    assert_eq!(err.code, ErrorCode::BignumNotCanonical);

    let err = BigInt::new(false, vec![0x00, 0x01]).unwrap_err();
    assert_eq!(err.code, ErrorCode::BignumNotCanonical);
}

#[test]
fn bigint_rejects_safe_range_magnitudes() {
    let max_safe = vec![0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let max_safe_minus_one = vec![0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe];

    let err = BigInt::new(false, max_safe.clone()).unwrap_err();
    assert_eq!(err.code, ErrorCode::BignumMustBeOutsideSafeRange);

    let err = BigInt::new(true, max_safe_minus_one).unwrap_err();
    assert_eq!(err.code, ErrorCode::BignumMustBeOutsideSafeRange);

    let ok = BigInt::new(true, max_safe).unwrap();
    assert!(ok.is_negative());
}

#[test]
fn f64bits_rejects_negative_zero_and_non_canonical_nan() {
    let err = F64Bits::new(0x8000_0000_0000_0000).unwrap_err();
    assert_eq!(err.code, ErrorCode::NegativeZeroForbidden);

    let err = F64Bits::new(0x7ff9_0000_0000_0000).unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalNaN);
}

#[test]
fn f64bits_try_from_f64_canonicalizes_nan() {
    let bits = F64Bits::try_from_f64(f64::NAN).unwrap();
    assert_eq!(bits.bits(), 0x7ff8_0000_0000_0000);
}

#[test]
fn f64bits_try_from_f64_rejects_negative_zero() {
    let err = F64Bits::try_from_f64(-0.0).unwrap_err();
    assert_eq!(err.code, ErrorCode::NegativeZeroForbidden);
}
