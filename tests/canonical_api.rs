#![cfg(feature = "alloc")]

use sacp_cbor::{validate_canonical, CborBytes, DecodeLimits, ErrorCode};

#[test]
fn canonical_from_slice_accepts_and_to_owned_roundtrips() {
    let bytes = [0xa1, 0x61, 0x61, 0x01];
    let limits = DecodeLimits::for_bytes(bytes.len());

    let owned = CborBytes::from_slice(&bytes, limits).unwrap();
    assert_eq!(owned.as_bytes(), bytes);

    let borrowed = validate_canonical(&bytes, limits).unwrap();
    let owned2 = borrowed.to_owned().unwrap();
    assert_eq!(owned2.as_bytes(), bytes);
}

#[test]
fn canonical_from_slice_rejects_invalid() {
    let bytes = [0x18];
    let err = CborBytes::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::UnexpectedEof);
}

#[cfg(feature = "sha2")]
#[test]
fn canonical_sha256_matches_manual_hash() {
    use sha2::{Digest, Sha256};

    let bytes = sacp_cbor::cbor_bytes!([1, true]).unwrap();
    let limits = DecodeLimits::for_bytes(bytes.as_bytes().len());

    let canon = CborBytes::from_slice(bytes.as_bytes(), limits).unwrap();
    let h1 = canon.sha256();

    let mut hasher = Sha256::new();
    hasher.update(bytes.as_bytes());
    let digest = hasher.finalize();
    let mut h2 = [0u8; 32];
    h2.copy_from_slice(digest.as_slice());

    assert_eq!(h1, h2);
}
