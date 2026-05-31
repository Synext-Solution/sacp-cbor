#![cfg(all(feature = "derive", feature = "collections"))]

use sacp_cbor::bytes::BytesRef;
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

#[test]
fn derive_decode_rejects_unknown_struct_fields() {
    let bytes = cbor_bytes!({ ok: true, extra: 1 }).unwrap();
    let err = decode::<AliasMsg>(
        bytes.as_bytes(),
        DecodeLimits::for_bytes(bytes.as_bytes().len()),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnknownField);
}

#[derive(Debug, PartialEq, Eq, CborEncode, CborDecode)]
struct RequiredOptionMsg {
    optional: Option<u64>,
}

#[test]
fn derive_decode_requires_explicit_option_fields() {
    let explicit = cbor_bytes!({ optional: { some: 7 } }).unwrap();
    let decoded: RequiredOptionMsg = decode(
        explicit.as_bytes(),
        DecodeLimits::for_bytes(explicit.as_bytes().len()),
    )
    .unwrap();
    assert_eq!(decoded, RequiredOptionMsg { optional: Some(7) });

    let missing = cbor_bytes!({}).unwrap();
    let err = decode::<RequiredOptionMsg>(
        missing.as_bytes(),
        DecodeLimits::for_bytes(missing.as_bytes().len()),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::MapLenMismatch);
}

#[test]
fn option_unit_is_injective() {
    let some = Some(());
    let none: Option<()> = None;

    let some_bytes = encode_to_vec(&some).unwrap();
    let none_bytes = encode_to_vec(&none).unwrap();
    assert_ne!(some_bytes, none_bytes);

    let decoded_some: Option<()> =
        decode(&some_bytes, DecodeLimits::for_bytes(some_bytes.len())).unwrap();
    let decoded_none: Option<()> =
        decode(&none_bytes, DecodeLimits::for_bytes(none_bytes.len())).unwrap();
    assert_eq!(decoded_some, some);
    assert_eq!(decoded_none, none);

    let nested = Some(Some(()));
    let nested_none = Some(None::<()>);
    let nested_bytes = encode_to_vec(&nested).unwrap();
    let nested_none_bytes = encode_to_vec(&nested_none).unwrap();
    assert_ne!(nested_bytes, nested_none_bytes);

    let decoded_nested: Option<Option<()>> =
        decode(&nested_bytes, DecodeLimits::for_bytes(nested_bytes.len())).unwrap();
    let decoded_nested_none: Option<Option<()>> = decode(
        &nested_none_bytes,
        DecodeLimits::for_bytes(nested_none_bytes.len()),
    )
    .unwrap();
    assert_eq!(decoded_nested, nested);
    assert_eq!(decoded_nested_none, nested_none);
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

#[derive(Debug, PartialEq, Eq, CborDecode)]
struct BorrowedMsg<'a> {
    name: &'a str,
    payload: BytesRef<'a>,
}

#[test]
fn derive_decode_borrowed_fields() {
    let bytes = cbor_bytes!({ name: "ana", payload: b"xy" }).unwrap();
    let decoded: BorrowedMsg<'_> = decode(
        bytes.as_bytes(),
        DecodeLimits::for_bytes(bytes.as_bytes().len()),
    )
    .unwrap();
    assert_eq!(decoded.name, "ana");
    assert_eq!(decoded.payload.as_slice(), b"xy");
}

#[derive(Debug, PartialEq, Eq, CborEncode, CborDecode)]
struct GenericMsg<T> {
    value: T,
}

#[test]
fn derive_roundtrip_for_generic_struct() {
    let msg = GenericMsg { value: 7u64 };
    let bytes = encode_to_vec(&msg).unwrap();
    let decoded: GenericMsg<u64> = decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, msg);
}

#[derive(Debug, Clone, PartialEq, Eq, CborEncode, CborDecode)]
struct RecursiveNode {
    value: u64,
    children: Vec<RecursiveNode>,
}

#[test]
fn derive_roundtrip_for_recursive_type() {
    let node = RecursiveNode {
        value: 1,
        children: vec![RecursiveNode {
            value: 2,
            children: Vec::new(),
        }],
    };
    let bytes = encode_to_vec(&node).unwrap();
    let decoded: RecursiveNode = decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, node);
}

#[derive(Debug, PartialEq, Eq, CborEncode, CborDecode)]
struct SkipMsg {
    id: u64,
    #[cbor(skip)]
    transient: bool,
    count: u64,
}

#[derive(Debug, PartialEq, Eq, CborEncode, CborDecode)]
struct SkipKeyReuseMsg {
    #[cbor(skip)]
    wire: bool,
    #[cbor(rename = "wire")]
    value: u64,
}

#[test]
fn derive_skip_fields_and_requires_present_values() {
    let msg = SkipMsg {
        id: 3,
        transient: true,
        count: 9,
    };
    let bytes = encode_to_vec(&msg).unwrap();
    let expected = cbor_bytes!({ id: 3, count: 9 }).unwrap();
    assert_eq!(bytes, expected.as_bytes());

    let missing = cbor_bytes!({ id: 3 }).unwrap();
    let err = decode::<SkipMsg>(
        missing.as_bytes(),
        DecodeLimits::for_bytes(missing.as_bytes().len()),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::MapLenMismatch);

    let reuse = SkipKeyReuseMsg {
        wire: true,
        value: 7,
    };
    let bytes = encode_to_vec(&reuse).unwrap();
    let expected = cbor_bytes!({ wire: 7 }).unwrap();
    assert_eq!(bytes, expected.as_bytes());
    let decoded: SkipKeyReuseMsg = decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(
        decoded,
        SkipKeyReuseMsg {
            wire: false,
            value: 7
        }
    );
}
