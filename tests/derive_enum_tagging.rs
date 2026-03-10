#![cfg(all(feature = "alloc", feature = "serde"))]

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use sacp_cbor::{
    cbor_bytes, decode, encode_to_vec, from_slice, to_vec, CborDecode, CborEncode, DecodeLimits,
};

fn assert_derive_matches_serde<T>(value: T, expected_json: Value)
where
    T: Clone
        + core::fmt::Debug
        + PartialEq
        + Eq
        + Serialize
        + DeserializeOwned
        + CborEncode
        + for<'de> CborDecode<'de>,
{
    let serde_json_value = serde_json::to_value(&value).unwrap();
    assert_eq!(serde_json_value, expected_json);

    let derive_bytes = encode_to_vec(&value).unwrap();
    let serde_bytes = to_vec(&value).unwrap();
    assert_eq!(derive_bytes, serde_bytes);

    let decoded: T = decode(&derive_bytes, DecodeLimits::for_bytes(derive_bytes.len())).unwrap();
    assert_eq!(decoded, value);

    let via_serde: T =
        from_slice(&derive_bytes, DecodeLimits::for_bytes(derive_bytes.len())).unwrap();
    assert_eq!(via_serde, value);

    let as_json: Value =
        from_slice(&derive_bytes, DecodeLimits::for_bytes(derive_bytes.len())).unwrap();
    assert_eq!(as_json, expected_json);
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CborEncode, CborDecode)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[cbor(tag = "kind")]
#[cbor(rename_all = "snake_case")]
enum PrincipalRefWire {
    User { id: String },
    Service { id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CborEncode, CborDecode)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[cbor(tag = "kind")]
#[cbor(rename_all = "snake_case")]
enum SubjectRefWire {
    Principal {
        principal: PrincipalRefWire,
    },
    #[serde(rename = "team")]
    #[cbor(rename = "team")]
    Group {
        id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CborEncode, CborDecode)]
#[serde(rename_all = "snake_case")]
#[cbor(rename_all = "snake_case")]
enum DelegationAction {
    Grant,
    #[serde(rename = "hand_off")]
    #[cbor(rename = "hand_off")]
    Revoke,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CborEncode, CborDecode)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[cbor(tag = "kind")]
#[cbor(rename_all = "snake_case")]
enum PermissionTargetWire {
    Use {
        permission: String,
    },
    Delegate {
        action: DelegationAction,
        permission: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CborEncode, CborDecode)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
#[cbor(tag = "kind", content = "payload")]
#[cbor(rename_all = "snake_case")]
enum AdjacentExample {
    Unit,
    Struct {
        id: String,
    },
    Newtype(String),
    Tuple(String, u8),
    #[serde(rename = "override")]
    #[cbor(rename = "override")]
    Override {
        ready: bool,
    },
}

#[test]
fn internal_tagged_enums_match_serde_json_shape() {
    assert_derive_matches_serde(
        SubjectRefWire::Principal {
            principal: PrincipalRefWire::User {
                id: "user-1".to_string(),
            },
        },
        json!({
            "kind": "principal",
            "principal": {
                "kind": "user",
                "id": "user-1"
            }
        }),
    );

    assert_derive_matches_serde(
        SubjectRefWire::Group {
            id: "group-1".to_string(),
        },
        json!({
            "kind": "team",
            "id": "group-1"
        }),
    );

    assert_derive_matches_serde(
        PermissionTargetWire::Delegate {
            action: DelegationAction::Grant,
            permission: "authz:authz.grant.write".to_string(),
        },
        json!({
            "kind": "delegate",
            "action": "grant",
            "permission": "authz:authz.grant.write"
        }),
    );
}

#[test]
fn adjacent_tagged_enums_match_serde_json_shape() {
    assert_derive_matches_serde(AdjacentExample::Unit, json!({ "kind": "unit" }));

    assert_derive_matches_serde(
        AdjacentExample::Struct {
            id: "item-1".to_string(),
        },
        json!({
            "kind": "struct",
            "payload": {
                "id": "item-1"
            }
        }),
    );

    assert_derive_matches_serde(
        AdjacentExample::Newtype("token-1".to_string()),
        json!({
            "kind": "newtype",
            "payload": "token-1"
        }),
    );

    assert_derive_matches_serde(
        AdjacentExample::Tuple("token-2".to_string(), 7),
        json!({
            "kind": "tuple",
            "payload": ["token-2", 7]
        }),
    );

    assert_derive_matches_serde(
        AdjacentExample::Override { ready: true },
        json!({
            "kind": "override",
            "payload": {
                "ready": true
            }
        }),
    );
}

#[test]
fn renamed_unit_enums_use_text_variants() {
    assert_derive_matches_serde(DelegationAction::Grant, json!("grant"));
    assert_derive_matches_serde(DelegationAction::Revoke, json!("hand_off"));
}

#[test]
fn renamed_unit_enums_still_decode_legacy_map_shape() {
    let bytes = cbor_bytes!({ "grant": null }).unwrap();
    let decoded: DelegationAction = decode(
        bytes.as_bytes(),
        DecodeLimits::for_bytes(bytes.as_bytes().len()),
    )
    .unwrap();
    assert_eq!(decoded, DelegationAction::Grant);
}
