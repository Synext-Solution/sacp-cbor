#![cfg(feature = "alloc")]

use sacp_cbor::{decode_value, validate_canonical, CborMap, CborValue, DecodeLimits, PathElem};

#[test]
fn ref_query_matches_decoded_value_query() {
    let v = CborValue::map(
        CborMap::new(vec![
            ("active".into(), CborValue::bool(true)),
            (
                "user".into(),
                CborValue::map(
                    CborMap::new(vec![
                        ("id".into(), CborValue::int(42).unwrap()),
                        (
                            "profile".into(),
                            CborValue::map(
                                CborMap::new(vec![
                                    ("name".into(), CborValue::text("Alice")),
                                    (
                                        "tags".into(),
                                        CborValue::array(vec![
                                            CborValue::text("a"),
                                            CborValue::text("b"),
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
    let v = CborValue::map(
        CborMap::new(vec![
            ("active".into(), CborValue::bool(true)),
            ("user".into(), CborValue::int(7).unwrap()),
            ("z".into(), CborValue::null()),
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
    assert_eq!(out[2].unwrap().integer().unwrap().as_i64().unwrap(), 7);
    assert!(out[3].is_none());
}

#[test]
fn cbormap_get_many_sorted_single_pass() {
    let v = CborValue::map(
        CborMap::new(vec![
            ("a".into(), CborValue::int(1).unwrap()),
            ("b".into(), CborValue::int(2).unwrap()),
            ("c".into(), CborValue::int(3).unwrap()),
        ])
        .unwrap(),
    );

    let bytes = v.encode_canonical().unwrap();
    let limits = DecodeLimits::for_bytes(bytes.len());
    let decoded = decode_value(&bytes, limits).unwrap();

    let map = decoded.as_map().expect("expected map");

    let out = map.get_many_sorted(["a", "b", "c"]).unwrap();
    assert_eq!(out[0].unwrap(), &CborValue::int(1).unwrap());
    assert_eq!(out[1].unwrap(), &CborValue::int(2).unwrap());
    assert_eq!(out[2].unwrap(), &CborValue::int(3).unwrap());
}
