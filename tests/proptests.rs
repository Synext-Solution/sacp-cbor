#![cfg(feature = "alloc")]
// Property-based tests for SACP-CBOR/1 canonical roundtrips.
//
// These tests are intentionally conservative in size/depth to keep CI fast.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;
use std::collections::BTreeMap;

use sacp_cbor::{
    validate_canonical, BigInt, CborInteger, CborMap, CborValue, DecodeLimits, F64Bits,
};

fn arb_key() -> impl Strategy<Value = Box<str>> {
    let ascii = proptest::collection::vec(proptest::char::range('a', 'z'), 0..=64)
        .prop_map(|chars| chars.into_iter().collect::<String>().into_boxed_str());
    let ascii_23 = proptest::collection::vec(proptest::char::range('a', 'z'), 23)
        .prop_map(|chars| chars.into_iter().collect::<String>().into_boxed_str());
    let ascii_24 = proptest::collection::vec(proptest::char::range('a', 'z'), 24)
        .prop_map(|chars| chars.into_iter().collect::<String>().into_boxed_str());
    let ascii_255 = proptest::collection::vec(proptest::char::range('a', 'z'), 255)
        .prop_map(|chars| chars.into_iter().collect::<String>().into_boxed_str());
    let ascii_256 = proptest::collection::vec(proptest::char::range('a', 'z'), 256)
        .prop_map(|chars| chars.into_iter().collect::<String>().into_boxed_str());
    let unicode = proptest::collection::vec(proptest::char::range('\u{00a1}', '\u{00ff}'), 0..=64)
        .prop_map(|chars| chars.into_iter().collect::<String>().into_boxed_str());

    prop_oneof![
        8 => ascii,
        1 => ascii_23,
        1 => ascii_24,
        1 => ascii_255,
        1 => ascii_256,
        1 => unicode,
    ]
}

fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    let any_small = proptest::collection::vec(any::<u8>(), 0..=64);
    let len_23 = proptest::collection::vec(any::<u8>(), 23);
    let len_24 = proptest::collection::vec(any::<u8>(), 24);
    let len_255 = proptest::collection::vec(any::<u8>(), 255);
    let len_256 = proptest::collection::vec(any::<u8>(), 256);

    prop_oneof![
        8 => any_small,
        1 => len_23,
        1 => len_24,
        1 => len_255,
        1 => len_256,
    ]
}

fn arb_bigint() -> impl Strategy<Value = BigInt> {
    // Magnitude length >= 8 guarantees it's larger than MAX_SAFE_INTEGER (7 bytes).
    let random = (
        any::<bool>(),
        proptest::collection::vec(any::<u8>(), 8..32).prop_map(|mut v| {
            if v[0] == 0 {
                v[0] = 1;
            }
            v
        }),
    )
        .prop_map(|(neg, mag)| BigInt::new(neg, mag).expect("bigint must be valid"));

    let max_safe = vec![0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let max_safe_plus_one = vec![0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    prop_oneof![
        6 => random,
        1 => Just(BigInt::new(false, max_safe_plus_one.clone()).expect("boundary bigint")),
        1 => Just(BigInt::new(true, max_safe.clone()).expect("boundary bigint")),
        1 => Just(BigInt::new(true, max_safe_plus_one).expect("boundary bigint")),
    ]
}

fn arb_float() -> impl Strategy<Value = F64Bits> {
    any::<f64>().prop_filter_map("exclude -0.0", |f| F64Bits::try_from_f64(f).ok())
}

fn arb_leaf() -> impl Strategy<Value = CborValue> {
    let int_any = (sacp_cbor::MIN_SAFE_INTEGER..=sacp_cbor::MAX_SAFE_INTEGER_I64)
        .prop_map(|v| CborValue::int(v).unwrap());
    let int_boundaries = prop_oneof![
        Just(CborValue::int(sacp_cbor::MIN_SAFE_INTEGER).unwrap()),
        Just(CborValue::int(sacp_cbor::MAX_SAFE_INTEGER_I64).unwrap()),
        Just(CborValue::int(23).unwrap()),
        Just(CborValue::int(24).unwrap()),
        Just(CborValue::int(-24).unwrap()),
        Just(CborValue::int(-25).unwrap()),
    ];

    prop_oneof![
        // Safe integers
        8 => int_any,
        1 => int_boundaries,
        // Bytes
        6 => arb_bytes().prop_map(CborValue::bytes),
        // Text
        6 => arb_key().prop_map(CborValue::text),
        // Bool / null
        4 => any::<bool>().prop_map(CborValue::bool),
        1 => Just(CborValue::null()),
        // Float64
        4 => arb_float().prop_map(CborValue::float),
        // Bignum
        3 => arb_bigint().prop_map(|b| CborValue::integer(CborInteger::from_bigint(b))),
    ]
}

fn arb_value() -> impl Strategy<Value = CborValue> {
    arb_leaf().prop_recursive(4, 256, 10, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..16).prop_map(CborValue::array),
            proptest::collection::vec((arb_key(), inner), 0..16).prop_map(|pairs| {
                let mut m: BTreeMap<Box<str>, CborValue> = BTreeMap::new();
                for (k, v) in pairs {
                    m.insert(k, v);
                }
                let entries = m.into_iter().collect::<Vec<_>>();
                CborValue::map(CborMap::new(entries).expect("unique keys"))
            }),
        ]
    })
}

proptest! {
    #[test]
    fn canonical_roundtrip(v in arb_value()) {
        let bytes = v.encode_canonical().unwrap();
        let limits = DecodeLimits::for_bytes(bytes.len());
        let canon = validate_canonical(&bytes, limits).unwrap();
        prop_assert_eq!(canon.as_bytes(), bytes.as_slice());

        let bytes2 = v.encode_canonical().unwrap();
        prop_assert_eq!(&bytes, &bytes2);
    }

    #[test]
    fn validate_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len()));
    }
}
