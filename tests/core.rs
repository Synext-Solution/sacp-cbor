use sacp_cbor::{
    decode, decode_canonical, encode_to_canonical, encode_to_vec, BigInt, DecodeLimits, ErrorCode,
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
fn u64_outside_safe_range_errors() {
    let err = encode_to_vec(&u64::MAX).unwrap_err();
    assert_eq!(err.code, ErrorCode::IntegerOutsideSafeRange);
}

#[test]
fn bigint_roundtrip() {
    let big = BigInt::new(false, vec![0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();
    let canon = encode_to_canonical(&big).unwrap();
    let decoded: BigInt = decode_canonical(canon.as_ref()).unwrap();
    assert_eq!(decoded, big);
}
