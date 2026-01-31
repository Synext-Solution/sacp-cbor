#![cfg(feature = "alloc")]

use sacp_cbor::{encode_to_vec, CborEncode};

#[derive(CborEncode)]
struct StructOrder {
    b: u8,
    a: u8,
}

#[test]
fn derive_struct_named_fields_sorted() {
    let v = StructOrder { b: 2, a: 1 };
    let bytes = encode_to_vec(&v).unwrap();
    assert_eq!(bytes, vec![0xa2, 0x61, b'a', 0x01, 0x61, b'b', 0x02]);
}

#[derive(CborEncode)]
struct StructRenameOrder {
    #[cbor(rename = "bb")]
    x: u8,
    #[cbor(rename = "a")]
    y: u8,
}

#[test]
fn derive_struct_rename_sorted_by_len_then_bytes() {
    let v = StructRenameOrder { x: 2, y: 1 };
    let bytes = encode_to_vec(&v).unwrap();
    assert_eq!(bytes, vec![0xa2, 0x61, b'a', 0x01, 0x62, b'b', b'b', 0x02]);
}

#[derive(CborEncode)]
enum TaggedEnum {
    Variant { b: u8, a: u8 },
}

#[test]
fn derive_enum_named_fields_sorted_tagged() {
    let v = TaggedEnum::Variant { b: 2, a: 1 };
    let bytes = encode_to_vec(&v).unwrap();
    assert_eq!(
        bytes,
        vec![
            0xa1, 0x67, b'V', b'a', b'r', b'i', b'a', b'n', b't', 0xa2, 0x61, b'a', 0x01, 0x61,
            b'b', 0x02,
        ]
    );
}

#[derive(CborEncode)]
#[cbor(untagged)]
enum UntaggedEnum {
    Variant { b: u8, a: u8 },
}

#[test]
fn derive_enum_named_fields_sorted_untagged() {
    let v = UntaggedEnum::Variant { b: 2, a: 1 };
    let bytes = encode_to_vec(&v).unwrap();
    assert_eq!(bytes, vec![0xa2, 0x61, b'a', 0x01, 0x61, b'b', 0x02]);
}
