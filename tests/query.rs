use sacp_cbor::query::PathElem;
use sacp_cbor::{validate_canonical, DecodeLimits, ErrorCode};

#[test]
fn map_get_single_int() {
    // { "a": 1 }
    let bytes = [0xa1, 0x61, 0x61, 0x01];

    let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let root = canon.root();

    let v = root.map().unwrap().get("a").unwrap().unwrap();
    assert_eq!(v.integer().unwrap().as_i64().unwrap(), 1);

    assert!(root.map().unwrap().get("missing").unwrap().is_none());
}

#[test]
fn nested_path_key_key_index() {
    // { "a": { "b": [true, null] } }
    let bytes = [0xa1, 0x61, 0x61, 0xa1, 0x61, 0x62, 0x82, 0xf5, 0xf6];

    let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();

    let path0 = [PathElem::Key("a"), PathElem::Key("b"), PathElem::Index(0)];
    let v0 = canon.at(&path0).unwrap().unwrap();
    assert!(v0.bool().unwrap());

    let path1 = [PathElem::Key("a"), PathElem::Key("b"), PathElem::Index(1)];
    let v1 = canon.at(&path1).unwrap().unwrap();
    assert!(v1.is_null());

    let missing = [PathElem::Key("a"), PathElem::Key("nope")];
    assert!(canon.at(&missing).unwrap().is_none());
}

#[test]
fn array_out_of_bounds() {
    // [1, 2]
    let bytes = [0x82, 0x01, 0x02];

    let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let arr = canon.root().array().unwrap();

    assert_eq!(
        arr.get(0)
            .unwrap()
            .unwrap()
            .integer()
            .unwrap()
            .as_i64()
            .unwrap(),
        1
    );
    assert_eq!(
        arr.get(1)
            .unwrap()
            .unwrap()
            .integer()
            .unwrap()
            .as_i64()
            .unwrap(),
        2
    );
    assert!(arr.get(2).unwrap().is_none());
    assert!(canon.root().get_index(999).unwrap().is_none());
}

#[test]
fn type_mismatch_errors() {
    // 1
    let bytes = [0x01];

    let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let err = canon.root().get_key("x").unwrap_err();
    assert_eq!(err.code, ErrorCode::ExpectedMap);
}

#[test]
fn get_many_sorted_basic() {
    // { "a": 1, "b": 2, "c": 3 }
    let bytes = [0xa3, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02, 0x61, 0x63, 0x03];

    let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let map = canon.root().map().unwrap();

    let out = map.get_many_sorted(["a", "b", "c"]).unwrap();
    assert_eq!(out[0].unwrap().integer().unwrap().as_i64().unwrap(), 1);
    assert_eq!(out[1].unwrap().integer().unwrap().as_i64().unwrap(), 2);
    assert_eq!(out[2].unwrap().integer().unwrap().as_i64().unwrap(), 3);

    let out2 = map.get_many_sorted(["a", "c", "bb"]).unwrap();
    assert!(out2[2].is_none());

    let mut out3 = [None, None, None];
    map.get_many_sorted_into(&["a", "b", "c"], &mut out3)
        .unwrap();
    assert_eq!(out3[0].unwrap().integer().unwrap().as_i64().unwrap(), 1);
    assert_eq!(out3[1].unwrap().integer().unwrap().as_i64().unwrap(), 2);
    assert_eq!(out3[2].unwrap().integer().unwrap().as_i64().unwrap(), 3);
}

#[test]
#[cfg(feature = "alloc")]
fn get_many_accepts_unsorted_and_rejects_duplicates() {
    // { "a": 1, "b": 2 }
    let bytes = [0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02];

    let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let map = canon.root().map().unwrap();

    let out = map.get_many(&["b", "a"]).unwrap();
    assert_eq!(out[0].unwrap().integer().unwrap().as_i64().unwrap(), 2);
    assert_eq!(out[1].unwrap().integer().unwrap().as_i64().unwrap(), 1);

    let err = map.get_many(&["a", "a"]).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidQuery);

    let err = map.get_many_sorted(["b", "a"]).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidQuery);
}

#[test]
fn utf8_key_lookup() {
    // { "e": 1, "é": 2 }
    // "é" UTF-8: C3 A9
    let bytes = [0xa2, 0x61, 0x65, 0x01, 0x62, 0xc3, 0xa9, 0x02];

    let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let map = canon.root().map().unwrap();

    assert_eq!(
        map.get("e")
            .unwrap()
            .unwrap()
            .integer()
            .unwrap()
            .as_i64()
            .unwrap(),
        1
    );
    assert_eq!(
        map.get("é")
            .unwrap()
            .unwrap()
            .integer()
            .unwrap()
            .as_i64()
            .unwrap(),
        2
    );
}

#[test]
fn kind_and_bignum_accessors() {
    let bytes = [
        0x89, // array of 9 items
        0x01, // int 1
        0x40, // bstr empty
        0x60, // tstr empty
        0x80, // array empty
        0xa0, // map empty
        0xf4, // false
        0xf6, // null
        0xfb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // float 0.0
        0xc2, 0x47, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tag2 bignum
    ];

    let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let arr = canon.root().array().unwrap();

    let kinds = [
        arr.get(0).unwrap().unwrap().kind().unwrap(),
        arr.get(1).unwrap().unwrap().kind().unwrap(),
        arr.get(2).unwrap().unwrap().kind().unwrap(),
        arr.get(3).unwrap().unwrap().kind().unwrap(),
        arr.get(4).unwrap().unwrap().kind().unwrap(),
        arr.get(5).unwrap().unwrap().kind().unwrap(),
        arr.get(6).unwrap().unwrap().kind().unwrap(),
        arr.get(7).unwrap().unwrap().kind().unwrap(),
        arr.get(8).unwrap().unwrap().kind().unwrap(),
    ];

    assert_eq!(
        kinds,
        [
            sacp_cbor::query::CborKind::Integer,
            sacp_cbor::query::CborKind::Bytes,
            sacp_cbor::query::CborKind::Text,
            sacp_cbor::query::CborKind::Array,
            sacp_cbor::query::CborKind::Map,
            sacp_cbor::query::CborKind::Bool,
            sacp_cbor::query::CborKind::Null,
            sacp_cbor::query::CborKind::Float,
            sacp_cbor::query::CborKind::Integer,
        ]
    );

    let big = arr
        .get(8)
        .unwrap()
        .unwrap()
        .integer()
        .unwrap()
        .as_bigint()
        .unwrap();
    assert!(!big.is_negative());
    assert_eq!(big.magnitude(), &[0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let big_int = arr.get(8).unwrap().unwrap().integer().unwrap();
    assert_eq!(big_int.as_u128(), Some(9_007_199_254_740_992));
    assert_eq!(big_int.as_i128(), Some(9_007_199_254_740_992));
}

#[test]
#[cfg(feature = "alloc")]
fn get_many_respects_input_order_not_canonical_order() {
    // { "b": 1, "aa": 2 } (canonical order by encoded length)
    let bytes = [0xa2, 0x61, 0x62, 0x01, 0x62, 0x61, 0x61, 0x02];

    let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let map = canon.root().map().unwrap();

    let out = map.get_many(&["aa", "b"]).unwrap();
    assert_eq!(out[0].unwrap().integer().unwrap().as_i64().unwrap(), 2);
    assert_eq!(out[1].unwrap().integer().unwrap().as_i64().unwrap(), 1);
}

#[test]
#[cfg(feature = "alloc")]
fn extras_and_required_multi_key_queries_are_ordered() {
    let bytes = [0xa3, 0x61, b'a', 0x01, 0x61, b'b', 0x02, 0x61, b'c', 0x03];

    let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let map = canon.root().map().unwrap();

    assert_eq!(
        map.require("a").unwrap().integer().unwrap().as_i64(),
        Some(1)
    );
    assert_eq!(map.require("z").unwrap_err().code, ErrorCode::MissingKey);

    let required = map.require_many_sorted(["a", "c"]).unwrap();
    assert_eq!(required[0].integer().unwrap().as_i64(), Some(1));
    assert_eq!(required[1].integer().unwrap().as_i64(), Some(3));
    assert_eq!(
        map.require_many_sorted(["a", "z"]).unwrap_err().code,
        ErrorCode::MissingKey
    );
    assert_eq!(
        map.require_many_sorted(["c", "a"]).unwrap_err().code,
        ErrorCode::InvalidQuery
    );

    let extras: Vec<_> = map
        .extras_sorted(&["b"])
        .unwrap()
        .map(|entry| {
            let (key, value) = entry.unwrap();
            (key.to_string(), value.integer().unwrap().as_i64().unwrap())
        })
        .collect();
    assert_eq!(extras, vec![("a".to_string(), 1), ("c".to_string(), 3)]);

    let extras = map.extras_sorted_vec(&["a", "c"]).unwrap();
    assert_eq!(extras.len(), 1);
    assert_eq!(extras[0].0, "b");
    assert_eq!(extras[0].1.integer().unwrap().as_i64(), Some(2));

    let extras = map.extras_vec(&["c", "a"]).unwrap();
    assert_eq!(extras.len(), 1);
    assert_eq!(extras[0].0, "b");
    assert_eq!(extras[0].1.integer().unwrap().as_i64(), Some(2));

    let err = match map.extras_sorted(&["a", "a"]) {
        Err(err) => err,
        Ok(_) => panic!("duplicate sorted extras query accepted"),
    };
    assert_eq!(err.code, ErrorCode::InvalidQuery);
    assert_eq!(
        map.extras_vec(&["a", "a"]).unwrap_err().code,
        ErrorCode::InvalidQuery
    );
}

#[test]
#[cfg(feature = "alloc")]
fn array_iter_skips_deep_nested_values() {
    let depth = 40usize;
    let mut bytes = Vec::with_capacity(depth + 3);
    bytes.push(0x82);
    bytes.extend(std::iter::repeat(0x81).take(depth));
    bytes.push(0xf6);
    bytes.push(0xf5);

    let mut limits = DecodeLimits::for_bytes(bytes.len());
    limits.max_depth = depth + 1;
    limits.max_total_items = depth + 2;
    let canon = validate_canonical(&bytes, limits).unwrap();
    let mut iter = canon.root().array().unwrap().iter();

    let nested = iter.next().unwrap().unwrap();
    assert_eq!(nested.as_bytes().len(), depth + 1);
    assert!(iter.next().unwrap().unwrap().bool().unwrap());
    assert!(iter.next().is_none());
}

#[cfg(feature = "unsafe")]
#[test]
fn unsafe_value_ref_malformed_ranges_return_query_errors() {
    let empty = unsafe { sacp_cbor::query::CborValueRef::from_canonical_range(&[], 0, 0) };
    let err = empty.kind().unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedCanonical);

    // Declares two entries. Lookup for "a" can stop at first key "b"; lookup for "z" must scan
    // into the malformed second key and surface the query-layer malformed canonical error.
    let bytes = [0xa2, 0x61, b'b', 0x01, 0x01];
    let root =
        unsafe { sacp_cbor::query::CborValueRef::from_canonical_range(&bytes, 0, bytes.len()) };
    let map = root.map().unwrap();
    assert!(map.get("a").unwrap().is_none());

    let err = map.get("z").unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedCanonical);
}
