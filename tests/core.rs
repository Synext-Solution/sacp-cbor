#![cfg(all(feature = "alloc", feature = "collections"))]

use sacp_cbor::bytes::{Bytes, BytesRef};
use sacp_cbor::value::BigInt;
use sacp_cbor::{
    decode, decode_canonical, encode_to_canonical, encode_to_vec, DecodeLimits, ErrorCode,
};

#[test]
fn empty_array_counts_depth() {
    let bytes = [0x80u8];
    let mut limits = DecodeLimits::for_bytes(bytes.len());
    limits.max_depth = 0;
    let err = decode::<Vec<bool>>(&bytes, limits).unwrap_err();
    assert_eq!(err.code, ErrorCode::DepthLimitExceeded);
}

#[test]
fn u64_outside_safe_range_roundtrips_as_bignum() {
    let bytes = encode_to_vec(&u64::MAX).unwrap();
    assert_eq!(bytes[0], 0xc2);
    let decoded: u64 = decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, u64::MAX);
}

#[test]
fn bigint_roundtrip() {
    let big = BigInt::new(false, vec![0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();
    let canon = encode_to_canonical(&big).unwrap();
    let decoded: BigInt = decode_canonical(
        canon.as_canonical_ref(),
        DecodeLimits::for_bytes(canon.as_bytes().len()),
    )
    .unwrap();
    assert_eq!(decoded, big);
}

#[test]
fn bytes_wrapper_is_byte_string_and_vec_u8_is_array() {
    let bytes = encode_to_vec(&BytesRef::new(&[1, 2])).unwrap();
    assert_eq!(bytes, [0x42, 1, 2]);

    let vec_bytes = encode_to_vec(&vec![1u8, 2]).unwrap();
    assert_eq!(vec_bytes, [0x82, 1, 2]);

    let decoded_vec: Vec<u8> =
        decode(&vec_bytes, DecodeLimits::for_bytes(vec_bytes.len())).unwrap();
    assert_eq!(decoded_vec, vec![1, 2]);

    let decoded_bytes: Bytes = decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded_bytes.as_slice(), &[1, 2]);
}
