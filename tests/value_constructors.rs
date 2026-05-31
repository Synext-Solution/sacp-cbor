#![cfg(feature = "alloc")]

use sacp_cbor::bytes::{Bytes, BytesRef};
use sacp_cbor::scalar::F64Bits;
use sacp_cbor::value::{BigInt, Integer};
use sacp_cbor::{Encoder, ErrorCode};

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

#[test]
fn fallible_capacity_rejects_impossible_reservation() {
    let err = match Encoder::try_with_capacity(usize::MAX) {
        Ok(_) => panic!("impossible reservation succeeded"),
        Err(err) => err,
    };
    assert_eq!(err.code, ErrorCode::LengthOverflow);
}

#[test]
fn bytes_wrappers_expose_slice_views_and_owned_bytes() {
    let borrowed = BytesRef::new(b"abc");
    assert_eq!(borrowed.as_slice(), b"abc");
    assert_eq!(borrowed.as_ref(), b"abc");
    assert_eq!(borrowed.len(), 3);
    assert!(!borrowed.is_empty());

    let owned = Bytes::copy_from_slice(b"xy").unwrap();
    assert_eq!(owned.as_slice(), b"xy");
    assert_eq!(owned.as_ref().as_slice(), b"xy");
    assert_eq!(AsRef::<[u8]>::as_ref(&owned), b"xy");
    assert_eq!(owned.into_vec(), vec![b'x', b'y']);

    let owned_empty = Bytes::new(Vec::new());
    let empty = owned_empty.as_ref();
    assert!(empty.is_empty());
}

#[test]
fn integer_accessors_distinguish_safe_and_big() {
    let safe = Integer::safe(-7).unwrap();
    assert!(safe.is_safe());
    assert!(!safe.is_big());
    assert_eq!(safe.as_i64(), Some(-7));
    assert!(safe.as_bigint().is_none());

    let big = Integer::big(false, vec![0x20, 0, 0, 0, 0, 0, 0]).unwrap();
    assert!(!big.is_safe());
    assert!(big.is_big());
    assert_eq!(big.as_i64(), None);
    let bigint = big.as_bigint().unwrap();
    assert!(!bigint.is_negative());
    assert_eq!(bigint.magnitude(), &[0x20, 0, 0, 0, 0, 0, 0]);

    let from_big = Integer::from_bigint(
        BigInt::new(true, vec![0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).unwrap(),
    );
    assert!(from_big.as_bigint().unwrap().is_negative());
}
