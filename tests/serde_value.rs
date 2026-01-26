#![cfg(feature = "serde")]

use sacp_cbor::{cbor, from_slice, to_vec, CborValue, DecodeLimits};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Envelope {
    #[serde(with = "sacp_cbor::serde_value")]
    details: CborValue,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct OptionalEnvelope {
    #[serde(with = "sacp_cbor::serde_value::option")]
    details: Option<CborValue>,
}

#[test]
fn serde_value_roundtrip() {
    let msg = Envelope {
        details: cbor!({"a": 1, "b": [true, null]}).unwrap(),
    };

    let bytes = to_vec(&msg).unwrap();
    let decoded: Envelope = from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, msg);
}

#[test]
fn serde_value_option_roundtrip() {
    let some = OptionalEnvelope {
        details: Some(cbor!({"x": 1}).unwrap()),
    };
    let none = OptionalEnvelope { details: None };

    let bytes = to_vec(&some).unwrap();
    let decoded: OptionalEnvelope =
        from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, some);

    let bytes = to_vec(&none).unwrap();
    let decoded: OptionalEnvelope =
        from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, none);
}
