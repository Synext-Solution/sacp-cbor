#![cfg(all(feature = "derive", feature = "collections"))]

use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::collections::HashMap;

use sacp_cbor::{
    collections::MapEntries, decode, encode_to_vec, validate_canonical, CborEncode, DecodeLimits,
};

#[derive(Debug, PartialEq, Eq, CborEncode)]
struct MsgBTree {
    flags: BTreeMap<String, bool>,
}

#[test]
fn derive_struct_with_btreemap_encodes_canonical_map() {
    // BTreeMap iteration is lexicographic ("aa" then "b"), but canonical order is
    // (len, then bytes), which requires "b" then "aa".
    let mut flags = BTreeMap::new();
    flags.insert("aa".to_string(), true);
    flags.insert("b".to_string(), false);

    let msg = MsgBTree { flags };
    let bytes = encode_to_vec(&msg).unwrap();
    validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let decoded: MapEntries<String, MapEntries<String, bool>> =
        decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded.0[0].0, "flags");
    assert_eq!(decoded.0[0].1 .0[0], ("b".to_string(), false));
    assert_eq!(decoded.0[0].1 .0[1], ("aa".to_string(), true));
}

#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq, CborEncode)]
struct MsgHash {
    flags: HashMap<String, bool>,
}

#[cfg(feature = "std")]
#[test]
fn derive_struct_with_hashmap_encodes_canonical_map() {
    let mut flags = HashMap::new();
    flags.insert("aa".to_string(), true);
    flags.insert("b".to_string(), false);

    let msg = MsgHash { flags };
    let bytes = encode_to_vec(&msg).unwrap();
    validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let decoded: MapEntries<String, MapEntries<String, bool>> =
        decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded.0[0].0, "flags");
    assert_eq!(decoded.0[0].1 .0[0].0, "b");
    assert_eq!(decoded.0[0].1 .0[1].0, "aa");
}
