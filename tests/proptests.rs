// Property-based tests for SACP-CBOR/1 canonical roundtrips.
//
// These tests are intentionally conservative in size/depth to keep CI fast.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;
use std::collections::BTreeMap;

use sacp_cbor::{
    cbor_equal, decode_value, validate_canonical, BigInt, CborMap, CborValue, DecodeLimits, F64Bits,
};

fn arb_key() -> impl Strategy<Value = String> {
    // ASCII keys keep size predictable while still exercising the canonical ordering rules.
    proptest::collection::vec(proptest::char::range('a', 'z'), 0..32)
        .prop_map(|chars| chars.into_iter().collect())
}

fn arb_bigint() -> impl Strategy<Value = BigInt> {
    // Magnitude length >= 8 guarantees it's larger than MAX_SAFE_INTEGER (7 bytes).
    (
        any::<bool>(),
        proptest::collection::vec(any::<u8>(), 8..32).prop_map(|mut v| {
            if v[0] == 0 {
                v[0] = 1;
            }
            v
        }),
    )
        .prop_map(|(neg, mag)| BigInt::new(neg, mag).expect("bigint must be valid"))
}

fn arb_float() -> impl Strategy<Value = F64Bits> {
    any::<f64>().prop_filter_map("exclude -0.0", |f| F64Bits::try_from_f64(f).ok())
}

fn arb_leaf() -> impl Strategy<Value = CborValue> {
    prop_oneof![
        // Safe integers
        (sacp_cbor::MIN_SAFE_INTEGER..=sacp_cbor::MAX_SAFE_INTEGER_I64).prop_map(CborValue::Int),
        // Bytes
        proptest::collection::vec(any::<u8>(), 0..64).prop_map(CborValue::Bytes),
        // Text
        arb_key().prop_map(CborValue::Text),
        // Bool / null
        any::<bool>().prop_map(CborValue::Bool),
        Just(CborValue::Null),
        // Float64
        arb_float().prop_map(CborValue::Float),
        // Bignum
        arb_bigint().prop_map(CborValue::Bignum),
    ]
}

fn arb_value() -> impl Strategy<Value = CborValue> {
    arb_leaf().prop_recursive(4, 256, 10, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..16).prop_map(CborValue::Array),
            proptest::collection::vec((arb_key(), inner), 0..16).prop_map(|pairs| {
                let mut m: BTreeMap<String, CborValue> = BTreeMap::new();
                for (k, v) in pairs {
                    m.insert(k, v);
                }
                let entries = m.into_iter().collect::<Vec<_>>();
                CborValue::Map(CborMap::new(entries).expect("unique keys"))
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

        let decoded = decode_value(&bytes, limits).unwrap();
        prop_assert!(cbor_equal(&v, &decoded));

        let bytes2 = decoded.encode_canonical().unwrap();
        prop_assert_eq!(&bytes, &bytes2);

        #[cfg(feature = "sha2")]
        {
            let h1 = canon.sha256();
            let h2 = decoded.sha256_canonical().unwrap();
            prop_assert_eq!(h1, h2);
        }
    }
}
