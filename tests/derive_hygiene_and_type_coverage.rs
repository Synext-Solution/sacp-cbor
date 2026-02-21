#![cfg(feature = "alloc")]

use std::collections::BTreeSet;

use sacp_cbor::{
    cbor_bytes, decode, encode_to_vec, CanonicalCbor, CanonicalCborRef, CborDecode, CborEncode,
    DecodeLimits, ErrorCode,
};

type Result<T> = core::result::Result<T, LocalError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalError;

#[derive(Debug, PartialEq, Eq, CborEncode, CborDecode)]
struct AliasMsg {
    ok: bool,
}

#[test]
fn derive_hygiene_works_with_local_result_alias() -> Result<()> {
    let msg = AliasMsg { ok: true };
    let bytes = encode_to_vec(&msg).map_err(|_| LocalError)?;
    let decoded: AliasMsg =
        decode(&bytes, DecodeLimits::for_bytes(bytes.len())).map_err(|_| LocalError)?;
    assert_eq!(decoded, msg);
    Ok(())
}

#[derive(Debug, PartialEq, Eq, CborEncode, CborDecode)]
struct FixedBytesMsg {
    id: [u8; 16],
}

#[test]
fn derive_roundtrip_for_fixed_byte_arrays() {
    let msg = FixedBytesMsg {
        id: [
            0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0, 1, 2, 3, 4, 5, 6, 7,
        ],
    };
    let bytes = encode_to_vec(&msg).unwrap();
    let decoded: FixedBytesMsg = decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, msg);
}

#[test]
fn fixed_byte_array_decode_requires_exact_length() {
    let bytes = [0x41u8, 0xAA];
    let err = decode::<[u8; 2]>(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::ExpectedBytes);
}

#[derive(Debug, PartialEq, Eq, CborEncode, CborDecode)]
struct SetMsg {
    members: BTreeSet<u64>,
}

#[test]
fn derive_roundtrip_for_btreeset() {
    let mut members = BTreeSet::new();
    members.insert(1);
    members.insert(2);
    members.insert(3);
    let msg = SetMsg { members };

    let bytes = encode_to_vec(&msg).unwrap();
    let decoded: SetMsg = decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, msg);
}

#[test]
fn btreeset_decode_rejects_non_canonical_set_order() {
    let unsorted = [0x82u8, 0x02, 0x01];
    let err =
        decode::<BTreeSet<u64>>(&unsorted, DecodeLimits::for_bytes(unsorted.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalSetOrder);

    let duplicate = [0x82u8, 0x01, 0x01];
    let err =
        decode::<BTreeSet<u64>>(&duplicate, DecodeLimits::for_bytes(duplicate.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalSetOrder);
}

#[derive(Debug, Clone, PartialEq, Eq, CborEncode, CborDecode)]
struct CanonicalPayloadMsg {
    payload: CanonicalCbor,
}

#[test]
fn derive_roundtrip_for_owned_canonical_payloads() {
    let payload = cbor_bytes!({
        "x": [1, 2, 3],
        "y": true
    })
    .unwrap();
    let msg = CanonicalPayloadMsg {
        payload: payload.clone(),
    };
    let bytes = encode_to_vec(&msg).unwrap();
    let decoded: CanonicalPayloadMsg =
        decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, msg);
}

#[test]
fn decode_canonical_ref_borrows_current_item_bytes() {
    let bytes = [0xA1u8, 0x61, b'a', 0x01];
    let decoded: CanonicalCborRef<'_> =
        decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded.as_bytes(), &bytes);
}
