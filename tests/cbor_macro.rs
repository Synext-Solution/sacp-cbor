#![cfg(feature = "alloc")]

use sacp_cbor::{cbor_bytes, validate_canonical, DecodeLimits, ErrorCode};

#[test]
fn cbor_bytes_primitives() {
    let v = cbor_bytes!(null).unwrap();
    assert_eq!(v.as_bytes(), &[0xf6]);

    let v = cbor_bytes!(true).unwrap();
    assert_eq!(v.as_bytes(), &[0xf5]);

    let v = cbor_bytes!(false).unwrap();
    assert_eq!(v.as_bytes(), &[0xf4]);

    let v = cbor_bytes!("hi").unwrap();
    assert_eq!(v.as_bytes(), &[0x62, 0x68, 0x69]);

    let v = cbor_bytes!(b"hi").unwrap();
    assert_eq!(v.as_bytes(), &[0x42, 0x68, 0x69]);
}

#[test]
fn cbor_bytes_arrays_and_maps_are_canonical() {
    let v = cbor_bytes!([1, true, null]).unwrap();
    let limits = DecodeLimits::for_bytes(v.as_bytes().len());
    validate_canonical(v.as_bytes(), limits).unwrap();

    let v = cbor_bytes!({ a: 1, b: 2 }).unwrap();
    let limits = DecodeLimits::for_bytes(v.as_bytes().len());
    validate_canonical(v.as_bytes(), limits).unwrap();
}

#[test]
fn cbor_bytes_map_keys() {
    let v = cbor_bytes!({ key: 1 }).unwrap();
    let limits = DecodeLimits::for_bytes(v.as_bytes().len());
    validate_canonical(v.as_bytes(), limits).unwrap();

    let key = "dyn";
    let v = cbor_bytes!({ ((key)): 2 }).unwrap();
    let limits = DecodeLimits::for_bytes(v.as_bytes().len());
    validate_canonical(v.as_bytes(), limits).unwrap();
}

#[test]
fn cbor_bytes_duplicate_keys_error() {
    let err = cbor_bytes!({ a: 1, a: 2 }).unwrap_err();
    assert_eq!(err.code, ErrorCode::DuplicateMapKey);
}

#[test]
fn cbor_bytes_negative_zero_rejected() {
    let err = cbor_bytes!(-0.0f64).unwrap_err();
    assert_eq!(err.code, ErrorCode::NegativeZeroForbidden);
}

#[test]
fn cbor_bytes_splice_payloads() {
    let inner = cbor_bytes!([1, 2]).unwrap();
    let outer = cbor_bytes!({ payload: (&inner) }).unwrap();
    let expected = cbor_bytes!({ payload: [1, 2] }).unwrap();
    assert_eq!(outer.as_bytes(), expected.as_bytes());
}
