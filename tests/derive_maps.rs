#![cfg(feature = "alloc")]

use std::collections::{BTreeMap, HashMap};

use sacp_cbor::{decode, encode_to_vec, validate_canonical, CborDecode, CborEncode, DecodeLimits};

#[derive(Debug, PartialEq, Eq, CborEncode, CborDecode)]
struct MsgBTree {
    flags: BTreeMap<String, bool>,
}

#[test]
fn derive_struct_with_btreemap_roundtrip_native() {
    // BTreeMap iteration is lexicographic ("aa" then "b"), but canonical order is
    // (len, then bytes), which requires "b" then "aa".
    let mut flags = BTreeMap::new();
    flags.insert("aa".to_string(), true);
    flags.insert("b".to_string(), false);

    let msg = MsgBTree { flags };
    let bytes = encode_to_vec(&msg).unwrap();
    validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let decoded: MsgBTree = decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, msg);
}

#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq, CborEncode, CborDecode)]
struct MsgHash {
    flags: HashMap<String, bool>,
}

#[cfg(feature = "std")]
#[test]
fn derive_struct_with_hashmap_roundtrip_native() {
    let mut flags = HashMap::new();
    flags.insert("aa".to_string(), true);
    flags.insert("b".to_string(), false);

    let msg = MsgHash { flags };
    let bytes = encode_to_vec(&msg).unwrap();
    validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let decoded: MsgHash = decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, msg);
}
