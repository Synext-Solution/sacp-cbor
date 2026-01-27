#![cfg(feature = "alloc")]

use sacp_cbor::{validate_canonical, CborValue, DecodeLimits, ErrorCode};

#[test]
fn cbor_macro_primitives() {
    assert_eq!(sacp_cbor::cbor!(null).unwrap(), CborValue::null());
    assert_eq!(sacp_cbor::cbor!(true).unwrap(), CborValue::bool(true));
    assert_eq!(sacp_cbor::cbor!(false).unwrap(), CborValue::bool(false));

    assert_eq!(sacp_cbor::cbor!("hi").unwrap(), CborValue::text("hi"));

    assert_eq!(
        sacp_cbor::cbor!(b"hi").unwrap(),
        CborValue::bytes(vec![0x68, 0x69])
    );

    assert_eq!(sacp_cbor::cbor!(42).unwrap(), CborValue::int(42).unwrap());

    let v = sacp_cbor::cbor!(1.5f64).unwrap();
    let bits = v.as_float().expect("expected float");
    assert_eq!(bits.bits(), 1.5f64.to_bits());
}

#[test]
fn cbor_macro_array_and_map_encode_canonical() {
    let v = sacp_cbor::cbor!([1, true, null]).unwrap();
    let bytes = v.encode_canonical().unwrap();
    assert_eq!(bytes, vec![0x83, 0x01, 0xf5, 0xf6]);

    let v = sacp_cbor::cbor!({ b: 2, a: 1 }).unwrap();
    let bytes = v.encode_canonical().unwrap();
    // Should be sorted canonically as { "a": 1, "b": 2 }
    assert_eq!(bytes, vec![0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02]);
}

#[test]
fn cbor_macro_duplicate_keys_error() {
    let err = sacp_cbor::cbor!({ a: 1, a: 2 }).unwrap_err();
    assert_eq!(err.code, ErrorCode::DuplicateMapKey);
}

#[test]
fn cbor_macro_key_ident_vs_expr() {
    let key = "dynamic";

    // `key:` becomes literal "key"
    let v = sacp_cbor::cbor!({ key: 1 }).unwrap();
    let map = v.as_map().expect("expected map");
    assert!(map.get("key").is_some());
    assert!(map.get(key).is_none());

    // `(key):` uses the expression value
    let v = sacp_cbor::cbor!({ (key): 1 }).unwrap();
    let map = v.as_map().expect("expected map");
    assert!(map.get("dynamic").is_some());
    assert!(map.get("key").is_none());
}

#[test]
fn cbor_bytes_macro_matches_value_encoding() {
    let v = sacp_cbor::cbor!({ a: 1, b: [true, null] }).unwrap();
    let bytes = sacp_cbor::cbor_bytes!({ a: 1, b: [true, null] })
        .unwrap()
        .into_bytes();
    assert_eq!(bytes, v.encode_canonical().unwrap());
}

#[test]
fn cbor_bytes_macro_splices_canonical_values() {
    let inner = sacp_cbor::cbor_bytes!([1, 2]).unwrap();
    let outer = sacp_cbor::cbor_bytes!({ payload: (&inner) }).unwrap();
    let expected = sacp_cbor::cbor_bytes!({ payload: [1, 2] }).unwrap();
    assert_eq!(outer.as_bytes(), expected.as_bytes());
}

#[test]
fn cbor_macro_safe_int_boundary_becomes_bignum() {
    // MAX_SAFE_INTEGER stays an Int
    let v = sacp_cbor::cbor!(sacp_cbor::MAX_SAFE_INTEGER).unwrap();
    assert_eq!(v, CborValue::int(sacp_cbor::MAX_SAFE_INTEGER_I64).unwrap());

    // MAX_SAFE_INTEGER + 1 becomes a positive bignum (tag 2)
    let v = sacp_cbor::cbor!(sacp_cbor::MAX_SAFE_INTEGER + 1).unwrap();
    let big = v.as_bigint().expect("expected bignum");
    assert!(!big.is_negative());
    assert_eq!(big.magnitude(), &[0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let bytes = v.encode_canonical().unwrap();
    assert_eq!(
        bytes,
        vec![0xc2, 0x47, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );

    // MIN_SAFE_INTEGER stays an Int
    let v = sacp_cbor::cbor!(sacp_cbor::MIN_SAFE_INTEGER).unwrap();
    assert_eq!(v, CborValue::int(sacp_cbor::MIN_SAFE_INTEGER).unwrap());

    // MIN_SAFE_INTEGER - 1 becomes a negative bignum (tag 3)
    let v = sacp_cbor::cbor!(sacp_cbor::MIN_SAFE_INTEGER - 1).unwrap();
    let big = v.as_bigint().expect("expected bignum");
    assert!(big.is_negative());
    // magnitude is n = -1 - v = MAX_SAFE_INTEGER
    assert_eq!(big.magnitude(), &[0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

    let bytes = v.encode_canonical().unwrap();
    assert_eq!(
        bytes,
        vec![0xc3, 0x47, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
}

#[test]
fn cbor_macro_float_nan_and_negative_zero() {
    let v = sacp_cbor::cbor!(f64::NAN).unwrap();
    let bytes = v.encode_canonical().unwrap();
    assert_eq!(
        bytes,
        vec![0xfb, 0x7f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );

    let err = sacp_cbor::cbor!(-0.0f64).unwrap_err();
    assert_eq!(err.code, ErrorCode::NegativeZeroForbidden);
}

#[test]
fn cbor_macro_roundtrip_validate() {
    let v = sacp_cbor::cbor!({
        b: [true, null, 1, 2, 3],
        a: { nested: "ok" },
    })
    .unwrap();

    let encoded = v.encode_canonical().unwrap();
    let limits = DecodeLimits::for_bytes(encoded.len());

    let canon = validate_canonical(&encoded, limits).unwrap();
    assert_eq!(canon.as_bytes(), encoded.as_slice());

    assert_eq!(canon.as_bytes(), encoded.as_slice());
}

#[test]
fn cbor_macro_option_support() {
    let v = sacp_cbor::cbor!(None::<i32>).unwrap();
    assert_eq!(v, CborValue::null());

    let v = sacp_cbor::cbor!(Some(123u32)).unwrap();
    assert_eq!(v, CborValue::int(123).unwrap());
}
