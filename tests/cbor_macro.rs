#![cfg(feature = "alloc")]

use sacp_cbor::{decode_value, validate_canonical, CborErrorCode, CborValue, DecodeLimits};

#[test]
fn cbor_macro_primitives() {
    assert_eq!(sacp_cbor::cbor!(null).unwrap(), CborValue::Null);
    assert_eq!(sacp_cbor::cbor!(true).unwrap(), CborValue::Bool(true));
    assert_eq!(sacp_cbor::cbor!(false).unwrap(), CborValue::Bool(false));

    assert_eq!(
        sacp_cbor::cbor!("hi").unwrap(),
        CborValue::Text("hi".to_string())
    );

    assert_eq!(
        sacp_cbor::cbor!(b"hi").unwrap(),
        CborValue::Bytes(vec![0x68, 0x69])
    );

    assert_eq!(sacp_cbor::cbor!(42).unwrap(), CborValue::Int(42));

    let v = sacp_cbor::cbor!(1.5f64).unwrap();
    match v {
        CborValue::Float(bits) => assert_eq!(bits.bits(), 1.5f64.to_bits()),
        _ => panic!("expected float"),
    }
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
    assert_eq!(err.code, CborErrorCode::DuplicateMapKey);
}

#[test]
fn cbor_macro_key_ident_vs_expr() {
    let key = "dynamic";

    // `key:` becomes literal "key"
    let v = sacp_cbor::cbor!({ key: 1 }).unwrap();
    let CborValue::Map(map) = v else {
        panic!("expected map")
    };
    assert!(map.get("key").is_some());
    assert!(map.get(key).is_none());

    // `(key):` uses the expression value
    let v = sacp_cbor::cbor!({ (key): 1 }).unwrap();
    let CborValue::Map(map) = v else {
        panic!("expected map")
    };
    assert!(map.get("dynamic").is_some());
    assert!(map.get("key").is_none());
}

#[test]
fn cbor_macro_safe_int_boundary_becomes_bignum() {
    // MAX_SAFE_INTEGER stays an Int
    let v = sacp_cbor::cbor!(sacp_cbor::MAX_SAFE_INTEGER).unwrap();
    assert_eq!(v, CborValue::Int(sacp_cbor::MAX_SAFE_INTEGER_I64));

    // MAX_SAFE_INTEGER + 1 becomes a positive bignum (tag 2)
    let v = sacp_cbor::cbor!(sacp_cbor::MAX_SAFE_INTEGER + 1).unwrap();
    let CborValue::Bignum(big) = v else {
        panic!("expected bignum")
    };
    assert!(!big.is_negative());
    assert_eq!(big.magnitude(), &[0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let bytes = CborValue::Bignum(big).encode_canonical().unwrap();
    assert_eq!(
        bytes,
        vec![0xc2, 0x47, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );

    // MIN_SAFE_INTEGER stays an Int
    let v = sacp_cbor::cbor!(sacp_cbor::MIN_SAFE_INTEGER).unwrap();
    assert_eq!(v, CborValue::Int(sacp_cbor::MIN_SAFE_INTEGER));

    // MIN_SAFE_INTEGER - 1 becomes a negative bignum (tag 3)
    let v = sacp_cbor::cbor!(sacp_cbor::MIN_SAFE_INTEGER - 1).unwrap();
    let CborValue::Bignum(big) = v else {
        panic!("expected bignum")
    };
    assert!(big.is_negative());
    // magnitude is n = -1 - v = MAX_SAFE_INTEGER
    assert_eq!(big.magnitude(), &[0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

    let bytes = CborValue::Bignum(big).encode_canonical().unwrap();
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
    assert_eq!(err.code, CborErrorCode::NegativeZeroForbidden);
}

#[test]
fn cbor_macro_roundtrip_validate_and_decode() {
    let v = sacp_cbor::cbor!({
        b: [true, null, 1, 2, 3],
        a: { nested: "ok" },
    })
    .unwrap();

    let encoded = v.encode_canonical().unwrap();
    let limits = DecodeLimits::for_bytes(encoded.len());

    let canon = validate_canonical(&encoded, limits).unwrap();
    assert_eq!(canon.as_bytes(), encoded.as_slice());

    let decoded = decode_value(&encoded, limits).unwrap();
    assert_eq!(decoded, v);
}

#[test]
fn cbor_macro_option_support() {
    let v = sacp_cbor::cbor!(None::<i32>).unwrap();
    assert_eq!(v, CborValue::Null);

    let v = sacp_cbor::cbor!(Some(123u32)).unwrap();
    assert_eq!(v, CborValue::Int(123));
}
