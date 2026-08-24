#![cfg(feature = "cde")]

//! Structural differential property for the CDE bridge: arbitrary canonical
//! items built with the crate's own `Encoder` — an independently implemented
//! canonical writer — survive the bridge round trip byte-identically, in both
//! directions, and the CDE image never grows.

use proptest::prelude::*;
use sacp_cbor::cde::{from_cde, to_cde};
use sacp_cbor::scalar::F64Bits;
use sacp_cbor::{CanonicalCbor, DecodeLimits, EncodeResult, Encoder, VecSink};

#[derive(Clone, Debug)]
enum Value {
    Int(i128),
    Bignum { negative: bool, magnitude: Vec<u8> },
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
    Null,
    Float(f64),
    Array(Vec<Value>),
    Map(Vec<(String, Value)>),
}

/// Integers concentrated on the two profile boundaries (2^53 and 2^64) plus
/// uniform 64-bit noise, on both signs.
fn interesting_int() -> impl Strategy<Value = i128> {
    const SAFE: i128 = 9_007_199_254_740_991;
    let magnitude = prop_oneof![
        0..=24i128,
        (SAFE - 2)..=(SAFE + 2),
        ((1i128 << 64) - 2)..=((1i128 << 64) + 2),
        any::<u64>().prop_map(i128::from),
    ];
    (magnitude, any::<bool>()).prop_map(|(m, negative)| if negative { -m - 1 } else { m })
}

fn scalar() -> impl Strategy<Value = Value> {
    prop_oneof![
        interesting_int().prop_map(Value::Int),
        (
            any::<bool>(),
            1u8..=255,
            prop::collection::vec(any::<u8>(), 8..12)
        )
            .prop_map(|(negative, first, mut rest)| {
                let mut magnitude = vec![first];
                magnitude.append(&mut rest);
                Value::Bignum {
                    negative,
                    magnitude,
                }
            }),
        prop::collection::vec(any::<u8>(), 0..24).prop_map(Value::Bytes),
        "[a-zA-Z0-9\u{20AC}\u{4E2D}]{0,16}".prop_map(Value::Text),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
        any::<u64>().prop_map(|bits| {
            let value = f64::from_bits(bits);
            // Negative zero is outside the profile; NaNs canonicalize on encode.
            Value::Float(if bits == 0x8000_0000_0000_0000 {
                0.0
            } else {
                value
            })
        }),
    ]
}

fn value() -> impl Strategy<Value = Value> {
    scalar().prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::vec(("[a-z0-9]{0,12}", inner), 0..6).prop_map(|mut entries| {
                // Canonical text-key order is payload length first, then
                // payload bytes; duplicates collapse to the first entry.
                entries
                    .sort_by(|a, b| (a.0.len(), a.0.as_bytes()).cmp(&(b.0.len(), b.0.as_bytes())));
                entries.dedup_by(|a, b| a.0 == b.0);
                Value::Map(entries)
            }),
        ]
    })
}

fn encode_value(enc: &mut Encoder, value: &Value) -> EncodeResult<(), VecSink> {
    match value {
        Value::Int(v) => enc.int_i128(*v),
        Value::Bignum {
            negative,
            magnitude,
        } => enc.bignum(*negative, magnitude),
        Value::Bytes(b) => enc.bytes(b),
        Value::Text(t) => enc.text(t),
        Value::Bool(b) => enc.bool(*b),
        Value::Null => enc.null(),
        Value::Float(f) => enc.float(F64Bits::try_from_f64(*f)?),
        Value::Array(items) => enc.array(items.len(), |a| {
            for item in items {
                a.value_with(|e| encode_value(e, item))?;
            }
            Ok(())
        }),
        Value::Map(entries) => enc.map(entries.len(), |m| {
            for (key, item) in entries {
                m.entry(key, |e| encode_value(e, item))?;
            }
            Ok(())
        }),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn bridge_round_trips_arbitrary_canonical_items(v in value()) {
        let mut enc = Encoder::new();
        encode_value(&mut enc, &v).expect("generated value encodes");
        let bytes = enc.finish().expect("one complete root value");
        let canonical = CanonicalCbor::from_vec(bytes, DecodeLimits::for_bytes(1 << 20))
            .expect("encoder output is canonical");
        let sacp = canonical.as_bytes();

        let image = to_cde(canonical.as_canonical_ref()).expect("to_cde is total");
        prop_assert!(image.len() <= sacp.len(), "the CDE image never grows");

        let back = from_cde(&image, DecodeLimits::for_bytes(1 << 20))
            .expect("the CDE image of a canonical item is accepted");
        prop_assert_eq!(back.as_bytes(), sacp, "from_cde inverts to_cde");
        prop_assert_eq!(
            to_cde(back.as_canonical_ref()).expect("total"),
            image,
            "to_cde inverts from_cde"
        );
    }

    /// Raw-bytes invariant (the fuzz target's law, run in-process): `from_cde`
    /// never panics on arbitrary input, and whatever it accepts is canonical
    /// CDE, so `to_cde` must invert it byte-identically.
    #[test]
    fn from_cde_on_arbitrary_bytes_is_safe_and_invertible(
        data in prop::collection::vec(any::<u8>(), 0..256)
    ) {
        if let Ok(sacp) = from_cde(&data, DecodeLimits::for_bytes(1 << 20)) {
            let image = to_cde(sacp.as_canonical_ref()).expect("to_cde is total");
            prop_assert_eq!(image, data, "to_cde must invert from_cde");
        }
    }
}
