#![cfg(feature = "serde")]

use sacp_cbor::{from_slice, from_value_ref, to_value, to_vec, DecodeLimits, ErrorCode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[test]
fn serde_rejects_negative_zero() {
    let err = to_vec(&(-0.0_f64)).unwrap_err();
    assert_eq!(err.code, ErrorCode::NegativeZeroForbidden);
}

#[test]
fn serde_nan_encodes_to_canonical_nan_bits() {
    let bytes = to_vec(&f64::NAN).unwrap();
    assert_eq!(bytes[0], 0xfb);
    assert_eq!(&bytes[1..], &0x7ff8_0000_0000_0000u64.to_be_bytes());
}

#[test]
fn serde_f32_accepts_infinities() {
    let pos_inf = [0xfb, 0x7f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let neg_inf = [0xfb, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let v_pos: f32 = from_slice(&pos_inf, DecodeLimits::for_bytes(pos_inf.len())).unwrap();
    assert!(v_pos.is_infinite() && v_pos.is_sign_positive());

    let v_neg: f32 = from_slice(&neg_inf, DecodeLimits::for_bytes(neg_inf.len())).unwrap();
    assert!(v_neg.is_infinite() && v_neg.is_sign_negative());
}

#[test]
fn serde_rejects_non_text_map_keys() {
    let mut m = BTreeMap::new();
    m.insert(1u8, 2u8);

    let err = to_vec(&m).unwrap_err();
    assert_eq!(err.code, ErrorCode::MapKeyMustBeText);
}

#[test]
fn serde_large_u64_becomes_bignum() {
    let v: u64 = sacp_cbor::MAX_SAFE_INTEGER + 1;
    let bytes = to_vec(&v).unwrap();
    assert_eq!(bytes[0], 0xc2); // tag 2
    assert_eq!(bytes[1], 0x47); // length 7
    assert_eq!(&bytes[2..], &[0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn serde_large_negative_i128_becomes_bignum() {
    let v: i128 = i128::from(sacp_cbor::MIN_SAFE_INTEGER) - 1;
    let bytes = to_vec(&v).unwrap();
    assert_eq!(bytes[0], 0xc3); // tag 3
    assert_eq!(bytes[1], 0x47); // length 7
    assert_eq!(&bytes[2..], &[0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Msg {
    op: String,
    n: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum Simple {
    Ready,
    Count(u64),
}

#[test]
fn serde_roundtrip_struct_and_enum() {
    let m = Msg {
        op: "ping".to_string(),
        n: 42,
    };

    let value = to_value(&m).unwrap();
    let decoded: Msg = from_value_ref(&value).unwrap();
    assert_eq!(decoded, m);

    let bytes = value.encode_canonical().unwrap();
    let decoded: Msg = from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, m);

    let s = Simple::Count(7);
    let value = to_value(&s).unwrap();
    let decoded: Simple = from_value_ref(&value).unwrap();
    assert_eq!(decoded, s);

    let bytes = value.encode_canonical().unwrap();
    let decoded: Simple = from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn serde_roundtrip_vec_and_option() {
    let tags = vec!["x".to_string(), "y".to_string()];
    let bytes = to_vec(&tags).unwrap();
    let decoded: Vec<String> = from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, tags);

    let opt = Some(3u8);
    let bytes = to_vec(&opt).unwrap();
    let decoded: Option<u8> = from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, opt);
}
