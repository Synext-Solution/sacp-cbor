use sacp_cbor::{CanonicalCbor, DecodeLimits, ErrorCode};
use sacp_cbor_abi::{
    assert_abi_rejects, assert_abi_vector, decode, encode_to_vec, AbiType, CborAbi,
    CompatibilityClass, UnknownFields, UnknownVariant,
};

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "ledger.Transfer", version = 1)]
struct Transfer {
    #[abi(id = 3)]
    amount: u64,
    #[abi(id = 1)]
    from: u64,
    #[abi(id = 4, optional)]
    memo: Option<String>,
    #[abi(id = 2)]
    to: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "ledger.Transfer", version = 9)]
struct TransferRenamed {
    #[abi(id = 1)]
    source: u64,
    #[abi(id = 2)]
    target: u64,
    #[abi(id = 3)]
    units: u64,
    #[abi(id = 4, optional)]
    note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "ledger.Borrowed", version = 1)]
struct Borrowed<'a> {
    #[abi(id = 1)]
    name: &'a str,
}

type AccountAlias = u64;

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "ledger.Override", version = 1)]
struct OverrideA {
    #[abi(id = 1, ty = "ledger.AccountId")]
    from: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "ledger.Override", version = 1)]
struct OverrideB {
    #[abi(id = 1, ty = "ledger.AccountId")]
    from: AccountAlias,
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "ledger.Lenient", version = 1, unknown_fields = "ignore")]
struct Lenient {
    #[abi(id = 1)]
    value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(
    type_id = "ledger.Preserving",
    version = 1,
    unknown_fields = "preserve"
)]
struct Preserving {
    #[abi(id = 1)]
    value: u64,
    #[abi(unknown_fields)]
    unknown: UnknownFields,
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "ledger.Decision", version = 1)]
enum Decision {
    #[abi(id = 1)]
    Accepted {
        #[abi(id = 1)]
        id: u64,
    },
    #[abi(id = 2)]
    Rejected,
    #[abi(unknown)]
    Unknown(UnknownVariant),
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "ledger.AccountId", version = 1, transparent)]
struct AccountId(String);

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(
    type_id = "ledger.ValidatedAccountId",
    version = 1,
    transparent,
    try_from = "ValidatedAccountId::try_from_inner"
)]
struct ValidatedAccountId(String);

impl ValidatedAccountId {
    fn try_from_inner(value: String) -> Result<Self, ()> {
        if value.is_empty() {
            Err(())
        } else {
            Ok(Self(value))
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn canon(bytes: &[u8]) -> CanonicalCbor {
    CanonicalCbor::from_slice(bytes, DecodeLimits::for_bytes(bytes.len())).unwrap()
}

#[test]
fn struct_abi_uses_sorted_numeric_ids() {
    let value = Transfer {
        from: 1,
        to: 2,
        amount: 50,
        memo: Some(String::from("ok")),
    };
    assert_abi_vector("transfer-basic", &value, "880101020203183204626f6b");

    let bytes = encode_to_vec(&value).unwrap();
    let decoded: Transfer = decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn optional_none_is_omitted() {
    let value = Transfer {
        from: 1,
        to: 2,
        amount: 50,
        memo: None,
    };
    assert_abi_vector("transfer-no-memo", &value, "8601010202031832");
}

#[test]
fn wire_hash_ignores_metadata_and_full_hash_includes_it() {
    assert_eq!(
        Transfer::schema().wire_hash().unwrap(),
        TransferRenamed::schema().wire_hash().unwrap()
    );
    assert_ne!(
        Transfer::schema().full_hash().unwrap(),
        TransferRenamed::schema().full_hash().unwrap()
    );

    let report = sacp_cbor_abi::diff(&Transfer::schema(), &TransferRenamed::schema());
    assert_eq!(report.bidirectional, CompatibilityClass::Compatible);
}

#[test]
fn type_override_keeps_schema_identity_stable() {
    assert_eq!(
        OverrideA::schema().wire_hash().unwrap(),
        OverrideB::schema().wire_hash().unwrap()
    );
}

#[test]
fn borrowed_text_fields_decode_without_copying() {
    let bytes = [0x82, 0x01, 0x63, b'a', b'd', b'a'];
    let decoded: Borrowed<'_> = decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded.name, "ada");

    let start = bytes.as_ptr() as usize;
    let end = start + bytes.len();
    let ptr = decoded.name.as_ptr() as usize;
    assert!((start..end).contains(&ptr));
}

#[test]
fn unknown_fields_can_be_ignored_or_preserved() {
    let bytes = [0x84, 0x01, 0x05, 0x02, 0xf5];
    let decoded: Lenient = decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, Lenient { value: 5 });

    let decoded: Preserving = decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded.value, 5);
    assert_eq!(decoded.unknown.len(), 1);
    assert_eq!(encode_to_vec(&decoded).unwrap(), bytes);
}

#[test]
fn unknown_field_collisions_are_rejected_on_encode() {
    let unknown = UnknownFields::try_from_vec(vec![sacp_cbor_abi::UnknownField {
        id: 1,
        value: canon(&[0xf5]),
    }])
    .unwrap();
    let value = Preserving { value: 5, unknown };
    let err = encode_to_vec(&value).unwrap_err();
    assert_eq!(err.code, ErrorCode::DuplicateMapKey);
}

#[test]
fn enum_abi_preserves_unknown_variants() {
    assert_abi_vector(
        "decision-accepted",
        &Decision::Accepted { id: 7 },
        "8201820107",
    );
    assert_abi_vector(
        "decision-unknown",
        &Decision::Unknown(UnknownVariant {
            id: 9,
            payload: canon(&[0xf5]),
        }),
        "8209f5",
    );

    let decoded: Decision = decode(&[0x82, 0x09, 0xf5], DecodeLimits::for_bytes(3)).unwrap();
    assert!(matches!(
        decoded,
        Decision::Unknown(UnknownVariant { id: 9, .. })
    ));
    assert_eq!(hex(&encode_to_vec(&decoded).unwrap()), "8209f5");
}

#[test]
fn transparent_newtype_uses_inner_wire_encoding() {
    let value = AccountId(String::from("abc"));
    assert_abi_vector("account-id", &value, "63616263");

    let decoded: AccountId = decode(&[0x63, b'a', b'b', b'c'], DecodeLimits::for_bytes(4)).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn transparent_validation_failure_is_an_abi_value_error() {
    assert_abi_rejects::<ValidatedAccountId>(&[0x60], ErrorCode::InvalidAbiValue);
}

#[test]
fn decode_rejects_missing_unknown_duplicate_and_unsorted_fields() {
    assert_abi_rejects::<Transfer>(&[0x84, 0x01, 0x01, 0x02, 0x02], ErrorCode::MissingKey);

    let unknown = [
        0x88, 0x01, 0x01, 0x02, 0x02, 0x03, 0x18, 0x32, 0x18, 0x63, 0x00,
    ];
    assert_abi_rejects::<Transfer>(&unknown, ErrorCode::UnknownField);

    assert_abi_rejects::<Transfer>(
        &[0x86, 0x01, 0x01, 0x01, 0x02, 0x03, 0x18, 0x32],
        ErrorCode::DuplicateMapKey,
    );
    assert_abi_rejects::<Transfer>(
        &[0x86, 0x02, 0x02, 0x01, 0x01, 0x03, 0x18, 0x32],
        ErrorCode::NonCanonicalMapOrder,
    );
}
