use sacp_cbor::{validate_canonical, DecodeLimits, ErrorCode, PathElem};

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
}

#[test]
fn get_many_sorted_accepts_unsorted_and_rejects_duplicates() {
    // { "a": 1, "b": 2 }
    let bytes = [0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02];

    let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let map = canon.root().map().unwrap();

    let out = map.get_many_sorted(["b", "a"]).unwrap();
    assert_eq!(out[0].unwrap().integer().unwrap().as_i64().unwrap(), 2);
    assert_eq!(out[1].unwrap().integer().unwrap().as_i64().unwrap(), 1);

    let err = map.get_many_sorted(["a", "a"]).unwrap_err();
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
            sacp_cbor::CborKind::Integer,
            sacp_cbor::CborKind::Bytes,
            sacp_cbor::CborKind::Text,
            sacp_cbor::CborKind::Array,
            sacp_cbor::CborKind::Map,
            sacp_cbor::CborKind::Bool,
            sacp_cbor::CborKind::Null,
            sacp_cbor::CborKind::Float,
            sacp_cbor::CborKind::Integer,
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
}

#[test]
fn get_many_sorted_respects_input_order_not_canonical_order() {
    // { "b": 1, "aa": 2 } (canonical order by encoded length)
    let bytes = [0xa2, 0x61, 0x62, 0x01, 0x62, 0x61, 0x61, 0x02];

    let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let map = canon.root().map().unwrap();

    let out = map.get_many_sorted(["aa", "b"]).unwrap();
    assert_eq!(out[0].unwrap().integer().unwrap().as_i64().unwrap(), 2);
    assert_eq!(out[1].unwrap().integer().unwrap().as_i64().unwrap(), 1);
}
