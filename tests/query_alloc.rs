#![cfg(feature = "alloc")]

use sacp_cbor::{decode_value, validate_canonical, CborMap, CborValue, DecodeLimits, PathElem};

#[test]
fn ref_query_matches_decoded_value_query() {
    let v = CborValue::Map(
        CborMap::new(vec![
            ("active".to_string(), CborValue::Bool(true)),
            (
                "user".to_string(),
                CborValue::Map(
                    CborMap::new(vec![
                        ("id".to_string(), CborValue::Int(42)),
                        (
                            "profile".to_string(),
                            CborValue::Map(
                                CborMap::new(vec![
                                    ("name".to_string(), CborValue::Text("Alice".to_string())),
                                    (
                                        "tags".to_string(),
                                        CborValue::Array(vec![
                                            CborValue::Text("a".to_string()),
                                            CborValue::Text("b".to_string()),
                                        ]),
                                    ),
                                ])
                                .unwrap(),
                            ),
                        ),
                    ])
                    .unwrap(),
                ),
            ),
        ])
        .unwrap(),
    );

    let bytes = v.encode_canonical().unwrap();
    let limits = DecodeLimits::for_bytes(bytes.len());

    let canon = validate_canonical(&bytes, limits).unwrap();
    let decoded = decode_value(&bytes, limits).unwrap();

    let path_name = [
        PathElem::Key("user"),
        PathElem::Key("profile"),
        PathElem::Key("name"),
    ];

    let got_ref = canon.at(&path_name).unwrap().unwrap();
    let got_owned = decoded.at(&path_name).unwrap().unwrap();

    assert_eq!(
        got_ref.as_bytes(),
        got_owned.encode_canonical().unwrap().as_slice()
    );

    let path_tag1 = [
        PathElem::Key("user"),
        PathElem::Key("profile"),
        PathElem::Key("tags"),
        PathElem::Index(1),
    ];

    let got_ref = canon.at(&path_tag1).unwrap().unwrap();
    let got_owned = decoded.at(&path_tag1).unwrap().unwrap();

    assert_eq!(got_ref.text().unwrap(), "b");
    assert_eq!(
        got_ref.as_bytes(),
        got_owned.encode_canonical().unwrap().as_slice()
    );
}

#[test]
fn mapref_get_many_unsorted_preserves_input_order() {
    let v = CborValue::Map(
        CborMap::new(vec![
            ("active".to_string(), CborValue::Bool(true)),
            ("user".to_string(), CborValue::Int(7)),
            ("z".to_string(), CborValue::Null),
        ])
        .unwrap(),
    );

    let bytes = v.encode_canonical().unwrap();
    let limits = DecodeLimits::for_bytes(bytes.len());
    let canon = validate_canonical(&bytes, limits).unwrap();
    let map = canon.root().map().unwrap();

    // Unsorted query order:
    let out = map.get_many(&["z", "active", "user", "missing"]).unwrap();

    assert!(out[0].unwrap().is_null());
    assert!(out[1].unwrap().bool().unwrap());
    assert_eq!(out[2].unwrap().int().unwrap(), 7);
    assert!(out[3].is_none());
}

#[test]
fn cbormap_get_many_sorted_single_pass() {
    let v = CborValue::Map(
        CborMap::new(vec![
            ("a".to_string(), CborValue::Int(1)),
            ("b".to_string(), CborValue::Int(2)),
            ("c".to_string(), CborValue::Int(3)),
        ])
        .unwrap(),
    );

    let bytes = v.encode_canonical().unwrap();
    let limits = DecodeLimits::for_bytes(bytes.len());
    let decoded = decode_value(&bytes, limits).unwrap();

    let CborValue::Map(map) = decoded else {
        panic!("expected map");
    };

    let out = map.get_many_sorted(["a", "b", "c"]).unwrap();
    assert_eq!(out[0].unwrap(), &CborValue::Int(1));
    assert_eq!(out[1].unwrap(), &CborValue::Int(2));
    assert_eq!(out[2].unwrap(), &CborValue::Int(3));
}
