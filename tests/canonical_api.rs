#![cfg(feature = "alloc")]

use sacp_cbor::{validate_canonical, CanonicalCbor, CborErrorCode, CborValue, DecodeLimits};

#[test]
fn canonical_from_slice_accepts_and_to_owned_roundtrips() {
    let bytes = [0xa1, 0x61, 0x61, 0x01];
    let limits = DecodeLimits::for_bytes(bytes.len());

    let owned = CanonicalCbor::from_slice(&bytes, limits).unwrap();
    assert_eq!(owned.as_bytes(), bytes);

    let borrowed = validate_canonical(&bytes, limits).unwrap();
    let owned2 = borrowed.to_owned();
    assert_eq!(owned2.as_bytes(), bytes);
}

#[test]
fn canonical_from_slice_rejects_invalid() {
    let bytes = [0x18];
    let err = CanonicalCbor::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::UnexpectedEof);
}

#[cfg(feature = "sha2")]
#[test]
fn canonical_sha256_matches_value_hash() {
    let v = CborValue::Array(vec![CborValue::Int(1), CborValue::Bool(true)]);
    let bytes = v.encode_canonical().unwrap();
    let limits = DecodeLimits::for_bytes(bytes.len());

    let canon = CanonicalCbor::from_slice(&bytes, limits).unwrap();
    let h1 = canon.sha256();
    let h2 = v.sha256_canonical().unwrap();
    assert_eq!(h1, h2);
}
