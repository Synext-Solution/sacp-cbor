use sacp_cbor::bytes::Bytes;
use sacp_cbor::{CanonicalCbor, DecodeLimits, ErrorCode};
use sacp_cbor_abi::{
    assert_abi_rejects, assert_abi_vector, decode, encode_to_vec, AbiDeleteMode, AbiFieldSetRef,
    AbiPatchValue, AbiSetMode, AbiType, CborAbi, CompatibilityClass, UnknownFields, UnknownVariant,
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

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(
    type_id = "ledger.ViewPayload",
    version = 1,
    unknown_fields = "preserve"
)]
struct ViewPayload {
    #[abi(id = 1)]
    route: String,
    #[abi(id = 2, optional)]
    memo: Option<String>,
    #[abi(id = 3)]
    payload: Bytes,
    #[abi(unknown_fields)]
    unknown: UnknownFields,
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "ledger.VectorPayload", version = 1)]
struct VectorPayload {
    #[abi(id = 1)]
    items: Vec<u64>,
    #[abi(id = 2)]
    label: String,
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
fn generated_view_accessors_are_zero_copy() {
    let value = ViewPayload {
        route: String::from("route-a"),
        memo: Some(String::from("memo-a")),
        payload: Bytes::new(vec![1, 2, 3, 4]),
        unknown: UnknownFields::try_from_vec(vec![sacp_cbor_abi::UnknownField {
            id: 9,
            value: canon(&[0xf5]),
        }])
        .unwrap(),
    };
    let bytes = encode_to_vec(&value).unwrap();
    let canon = CanonicalCbor::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let view = ViewPayloadView::from_canonical(canon.as_canonical_ref()).unwrap();

    assert_eq!(view.route().unwrap(), "route-a");
    assert_eq!(view.memo().unwrap(), Some("memo-a"));
    assert_eq!(view.payload().unwrap().as_slice(), &[1, 2, 3, 4]);
    assert_eq!(view.payload_raw().unwrap().as_bytes(), &[0x44, 1, 2, 3, 4]);

    let start = canon.as_bytes().as_ptr() as usize;
    let end = start + canon.as_bytes().len();
    let route_ptr = view.route().unwrap().as_ptr() as usize;
    let payload_ptr = view.payload().unwrap().as_slice().as_ptr() as usize;
    assert!((start..end).contains(&route_ptr));
    assert!((start..end).contains(&payload_ptr));

    let unknown: Vec<_> = view.unknown_fields().unwrap().map(Result::unwrap).collect();
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].id, 9);
    assert_eq!(unknown[0].value.as_bytes(), &[0xf5]);

    assert_eq!(view.to_owned().unwrap(), value);
}

#[test]
fn generated_view_integer_accessors_preserve_bignum_semantics() {
    let value = Transfer {
        from: 1,
        to: 2,
        amount: u64::MAX,
        memo: None,
    };
    let bytes = encode_to_vec(&value).unwrap();
    let canon = CanonicalCbor::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let view = TransferView::from_canonical(canon.as_canonical_ref()).unwrap();

    assert_eq!(view.amount().unwrap(), u64::MAX);
    assert_eq!(view.amount_raw().unwrap().as_bytes()[0], 0xc2);
    assert_eq!(view.to_owned().unwrap(), value);
}

#[test]
fn generated_view_arrays_decode_items_lazily() {
    let bytes = [
        0x84, 0x01, 0x82, 0x01, 0x63, b'b', b'a', b'd', 0x02, 0x62, b'o', b'k',
    ];
    assert_abi_rejects::<VectorPayload>(&bytes, ErrorCode::ExpectedInteger);
    let canon = CanonicalCbor::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let view = VectorPayloadView::from_canonical(canon.as_canonical_ref()).unwrap();

    assert_eq!(view.label().unwrap(), "ok");
    let items = view.items().unwrap();
    assert_eq!(items.len().unwrap(), 2);
    assert_eq!(items.get(0).unwrap(), Some(1));
    let err = items.get(1).unwrap_err();
    assert_eq!(err.code, ErrorCode::ExpectedInteger);
    assert_eq!(
        view.to_owned().unwrap_err().code,
        ErrorCode::ExpectedInteger
    );
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
fn generated_view_rejects_invalid_field_ids() {
    let zero_unknown = [0x84, 0x00, 0xf5, 0x01, 0x05];
    assert_abi_rejects::<Lenient>(&zero_unknown, ErrorCode::InvalidAbiValue);
    let canon =
        CanonicalCbor::from_slice(&zero_unknown, DecodeLimits::for_bytes(zero_unknown.len()))
            .unwrap();
    let err = LenientView::from_canonical(canon.as_canonical_ref()).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidAbiValue);
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
fn generated_enum_view_validates_and_caches_payload() {
    let accepted =
        CanonicalCbor::from_slice(&[0x82, 0x01, 0x82, 0x01, 0x07], DecodeLimits::for_bytes(5))
            .unwrap();
    let view = DecisionView::from_canonical(accepted.as_canonical_ref()).unwrap();
    assert_eq!(view.variant_id(), 1);
    assert!(view.is_accepted());
    let payload = view.as_accepted().unwrap().unwrap();
    assert_eq!(payload.id().unwrap(), 7);

    let bad_payload =
        CanonicalCbor::from_slice(&[0x82, 0x01, 0xf6], DecodeLimits::for_bytes(3)).unwrap();
    let err = DecisionView::from_canonical(bad_payload.as_canonical_ref()).unwrap_err();
    assert_eq!(err.code, ErrorCode::ExpectedArray);

    let unknown =
        CanonicalCbor::from_slice(&[0x82, 0x09, 0xf5], DecodeLimits::for_bytes(3)).unwrap();
    let view = DecisionView::from_canonical(unknown.as_canonical_ref()).unwrap();
    let unknown = view.unknown_variant().unwrap();
    assert_eq!(unknown.id, 9);
    assert_eq!(unknown.payload.as_bytes(), &[0xf5]);

    assert_abi_rejects::<Decision>(&[0x82, 0x00, 0xf5], ErrorCode::InvalidAbiValue);
    let zero = CanonicalCbor::from_slice(&[0x82, 0x00, 0xf5], DecodeLimits::for_bytes(3)).unwrap();
    let err = DecisionView::from_canonical(zero.as_canonical_ref()).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidAbiValue);
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

    let canon = CanonicalCbor::from_slice(&[0x60], DecodeLimits::for_bytes(1)).unwrap();
    let err = ValidatedAccountIdView::from_canonical(canon.as_canonical_ref()).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidAbiValue);
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

#[test]
fn abi_field_set_editor_merges_raw_and_encoded_ops() {
    let bytes = [
        0x86, 0x01, 0x62, b'a', b'a', 0x03, 0x43, 1, 2, 3, 0x05, 0xf5,
    ];
    let doc = CanonicalCbor::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let fields = AbiFieldSetRef::from_value(doc.as_canonical_ref().root()).unwrap();
    let raw_one = fields.get(1).unwrap().unwrap();

    let mut editor = fields.edit();
    let err = editor
        .set(0, AbiSetMode::Upsert, AbiPatchValue::Raw(raw_one))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidAbiValue);

    editor
        .set(
            2,
            AbiSetMode::InsertOnly,
            AbiPatchValue::Encoded(canon(&[0xf4])),
        )
        .unwrap();
    editor
        .set(4, AbiSetMode::Upsert, AbiPatchValue::Raw(raw_one))
        .unwrap();
    editor.delete(3, AbiDeleteMode::Require).unwrap();

    let updated = editor.apply().unwrap();
    assert_eq!(hex(updated.as_bytes()), "880162616102f40462616105f5");

    let updated_fields = AbiFieldSetRef::from_value(updated.as_canonical_ref().root()).unwrap();
    assert!(updated_fields.get(3).unwrap().is_none());
    assert_eq!(
        updated_fields.get(4).unwrap().unwrap().as_bytes(),
        raw_one.as_bytes()
    );

    let err = match updated_fields.unknown_fields(&[4, 1]) {
        Ok(_) => panic!("unsorted known ABI field IDs accepted"),
        Err(err) => err,
    };
    assert_eq!(err.code, ErrorCode::InvalidQuery);
}
