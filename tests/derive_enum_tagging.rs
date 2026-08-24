#![cfg(all(feature = "derive", feature = "serde"))]

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use sacp_cbor::serde::{from_slice, SerdeOptions};
use sacp_cbor::{
    cbor_bytes, decode, encode_to_vec, CborDecode, CborEncode, DecodeLimits, ErrorCode,
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
    assert_derive_matches_serde_as(value, expected_json.clone(), expected_json);
}

fn assert_derive_matches_serde_as<T>(
    value: T,
    expected_serde_json: Value,
    expected_cbor_json: Value,
) where
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
    assert_eq!(serde_json_value, expected_serde_json);

    let derive_bytes = encode_to_vec(&value).unwrap();
    let serde_bytes = SerdeOptions::sorted_maps().to_vec(&value).unwrap();
    assert_eq!(derive_bytes, serde_bytes);

    let decoded: T = decode(&derive_bytes, DecodeLimits::for_bytes(derive_bytes.len())).unwrap();
    assert_eq!(decoded, value);

    let via_serde: T =
        from_slice(&derive_bytes, DecodeLimits::for_bytes(derive_bytes.len())).unwrap();
    assert_eq!(via_serde, value);

    let as_json: Value =
        from_slice(&derive_bytes, DecodeLimits::for_bytes(derive_bytes.len())).unwrap();
    assert_eq!(as_json, expected_cbor_json);
}

fn assert_native_roundtrip_as<T>(value: T, expected_cbor_json: Value)
where
    T: core::fmt::Debug + PartialEq + Eq + CborEncode + for<'de> CborDecode<'de>,
{
    let derive_bytes = encode_to_vec(&value).unwrap();
    let decoded: T = decode(&derive_bytes, DecodeLimits::for_bytes(derive_bytes.len())).unwrap();
    assert_eq!(decoded, value);

    let as_json: Value =
        from_slice(&derive_bytes, DecodeLimits::for_bytes(derive_bytes.len())).unwrap();
    assert_eq!(as_json, expected_cbor_json);
}

fn assert_derive_error<T>(bytes: &sacp_cbor::CanonicalCbor, code: ErrorCode)
where
    T: core::fmt::Debug + for<'de> CborDecode<'de>,
{
    let err = decode::<T>(
        bytes.as_bytes(),
        DecodeLimits::for_bytes(bytes.as_bytes().len()),
    )
    .unwrap_err();
    assert_eq!(err.code, code);
}

fn assert_derive_and_serde_error<T>(bytes: &sacp_cbor::CanonicalCbor, code: ErrorCode)
where
    T: core::fmt::Debug + DeserializeOwned + for<'de> CborDecode<'de>,
{
    let err = decode::<T>(
        bytes.as_bytes(),
        DecodeLimits::for_bytes(bytes.as_bytes().len()),
    )
    .unwrap_err();
    assert_eq!(err.code, code);

    let err = from_slice::<T>(
        bytes.as_bytes(),
        DecodeLimits::for_bytes(bytes.as_bytes().len()),
    )
    .unwrap_err();
    assert_eq!(err.code, code);
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CborEncode, CborDecode)]
#[serde(rename_all = "snake_case")]
#[cbor(rename_all = "snake_case")]
enum ExternalDataOnlyWire {
    Token(String),
    Pair(String, u8),
    Record { id: String, version: u8 },
}

fn encoded_text(s: &str) -> Vec<u8> {
    assert!(s.len() < 24);
    let mut out = Vec::with_capacity(s.len() + 1);
    out.push(0x60 | u8::try_from(s.len()).unwrap());
    out.extend_from_slice(s.as_bytes());
    out
}

fn encoded_unit_variant(s: &str) -> Vec<u8> {
    let mut out = vec![0xa1];
    out.extend_from_slice(&encoded_text(s));
    out.push(0xf6);
    out
}

#[derive(Debug, Clone, PartialEq, Eq, CborEncode, CborDecode)]
#[cbor(rename_all = "lowercase")]
enum LowerRule {
    HttpServer2,
}

#[derive(Debug, Clone, PartialEq, Eq, CborEncode, CborDecode)]
#[cbor(rename_all = "UPPERCASE")]
enum UpperRule {
    HttpServer2,
}

#[derive(Debug, Clone, PartialEq, Eq, CborEncode, CborDecode)]
#[cbor(rename_all = "PascalCase")]
enum PascalRule {
    HttpServer2,
}

#[derive(Debug, Clone, PartialEq, Eq, CborEncode, CborDecode)]
#[cbor(rename_all = "camelCase")]
enum CamelRule {
    HttpServer2,
}

#[derive(Debug, Clone, PartialEq, Eq, CborEncode, CborDecode)]
#[cbor(rename_all = "snake_case")]
enum SnakeRule {
    HttpServer2,
}

#[derive(Debug, Clone, PartialEq, Eq, CborEncode, CborDecode)]
#[cbor(rename_all = "SCREAMING_SNAKE_CASE")]
enum ScreamingSnakeRule {
    HttpServer2,
}

#[derive(Debug, Clone, PartialEq, Eq, CborEncode, CborDecode)]
#[cbor(rename_all = "kebab-case")]
enum KebabRule {
    HttpServer2,
}

#[derive(Debug, Clone, PartialEq, Eq, CborEncode, CborDecode)]
#[cbor(rename_all = "SCREAMING-KEBAB-CASE")]
enum ScreamingKebabRule {
    HttpServer2,
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

    let delegate = PermissionTargetWire::Delegate {
        action: DelegationAction::Grant,
        permission: "authz:authz.grant.write".to_string(),
    };
    assert_eq!(
        serde_json::to_value(&delegate).unwrap(),
        json!({
            "kind": "delegate",
            "action": "grant",
            "permission": "authz:authz.grant.write"
        })
    );
    assert_native_roundtrip_as(
        delegate,
        json!({
            "kind": "delegate",
            "action": { "grant": null },
            "permission": "authz:authz.grant.write"
        }),
    );
}

#[test]
fn adjacent_tagged_enums_match_serde_json_shape() {
    let unit = AdjacentExample::Unit;
    let derive_bytes = encode_to_vec(&unit).unwrap();
    let expected = cbor_bytes!({ kind: "unit", payload: null }).unwrap();
    assert_eq!(derive_bytes, expected.as_bytes());
    let decoded: AdjacentExample =
        decode(&derive_bytes, DecodeLimits::for_bytes(derive_bytes.len())).unwrap();
    assert_eq!(decoded, unit);

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
fn external_tagged_enums_without_unit_variants_match_serde_json_shape() {
    assert_derive_matches_serde(
        ExternalDataOnlyWire::Token("token-1".to_string()),
        json!({
            "token": "token-1"
        }),
    );

    assert_derive_matches_serde(
        ExternalDataOnlyWire::Pair("token-2".to_string(), 7),
        json!({
            "pair": ["token-2", 7]
        }),
    );

    assert_derive_matches_serde(
        ExternalDataOnlyWire::Record {
            id: "item-1".to_string(),
            version: 2,
        },
        json!({
            "record": {
                "id": "item-1",
                "version": 2
            }
        }),
    );
}

#[test]
fn external_tagged_enums_without_unit_variants_reject_text_shape() {
    let bytes = cbor_bytes!("token").unwrap();
    assert_derive_and_serde_error::<ExternalDataOnlyWire>(&bytes, ErrorCode::ExpectedEnum);
}

#[test]
fn external_tagged_enums_without_unit_variants_reject_newtype_array_shape() {
    let bytes = cbor_bytes!({ "token": ["token-1"] }).unwrap();
    assert_derive_and_serde_error::<ExternalDataOnlyWire>(&bytes, ErrorCode::ExpectedText);
}

#[test]
fn renamed_unit_enums_use_uniform_external_maps() {
    assert_eq!(
        serde_json::to_value(DelegationAction::Grant).unwrap(),
        json!("grant")
    );
    assert_native_roundtrip_as(DelegationAction::Grant, json!({ "grant": null }));
    assert_eq!(
        serde_json::to_value(DelegationAction::Revoke).unwrap(),
        json!("hand_off")
    );
    assert_native_roundtrip_as(DelegationAction::Revoke, json!({ "hand_off": null }));
}

#[test]
fn rename_all_rules_encode_and_decode_unit_variants() {
    assert_eq!(
        encode_to_vec(&LowerRule::HttpServer2).unwrap(),
        encoded_unit_variant("httpserver2")
    );
    assert_eq!(
        encode_to_vec(&UpperRule::HttpServer2).unwrap(),
        encoded_unit_variant("HTTPSERVER2")
    );
    assert_eq!(
        encode_to_vec(&PascalRule::HttpServer2).unwrap(),
        encoded_unit_variant("HttpServer2")
    );
    assert_eq!(
        encode_to_vec(&CamelRule::HttpServer2).unwrap(),
        encoded_unit_variant("httpServer2")
    );
    assert_eq!(
        encode_to_vec(&SnakeRule::HttpServer2).unwrap(),
        encoded_unit_variant("http_server_2")
    );
    assert_eq!(
        encode_to_vec(&ScreamingSnakeRule::HttpServer2).unwrap(),
        encoded_unit_variant("HTTP_SERVER_2")
    );
    assert_eq!(
        encode_to_vec(&KebabRule::HttpServer2).unwrap(),
        encoded_unit_variant("http-server-2")
    );
    assert_eq!(
        encode_to_vec(&ScreamingKebabRule::HttpServer2).unwrap(),
        encoded_unit_variant("HTTP-SERVER-2")
    );

    let snake = encoded_unit_variant("http_server_2");
    let decoded: SnakeRule = decode(&snake, DecodeLimits::for_bytes(snake.len())).unwrap();
    assert_eq!(decoded, SnakeRule::HttpServer2);
}

#[test]
fn renamed_unit_enums_reject_text_shape() {
    let bytes = cbor_bytes!("grant").unwrap();
    assert_derive_error::<DelegationAction>(&bytes, ErrorCode::ExpectedEnum);
}

#[test]
fn internal_tagged_enums_reject_unknown_payload_fields() {
    let bytes = cbor_bytes!({ kind: "use", permission: "read", extra: true }).unwrap();
    let err = decode::<PermissionTargetWire>(
        bytes.as_bytes(),
        DecodeLimits::for_bytes(bytes.as_bytes().len()),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnknownField);
}

#[test]
fn adjacent_tagged_enums_reject_unknown_top_level_fields() {
    let bytes = cbor_bytes!({ kind: "unit", extra: true }).unwrap();
    let err = decode::<AdjacentExample>(
        bytes.as_bytes(),
        DecodeLimits::for_bytes(bytes.as_bytes().len()),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnknownField);
}

#[test]
fn adjacent_tagged_unit_variant_rejects_content() {
    let bytes = cbor_bytes!({ kind: "unit", payload: true }).unwrap();
    let err = decode::<AdjacentExample>(
        bytes.as_bytes(),
        DecodeLimits::for_bytes(bytes.as_bytes().len()),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::ExpectedNull);
}

#[test]
fn adjacent_tagged_payload_variant_requires_content() {
    let bytes = cbor_bytes!({ kind: "newtype" }).unwrap();
    let err = decode::<AdjacentExample>(
        bytes.as_bytes(),
        DecodeLimits::for_bytes(bytes.as_bytes().len()),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::MissingKey);
}
