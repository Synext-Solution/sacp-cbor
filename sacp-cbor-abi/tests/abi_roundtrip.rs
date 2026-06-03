use sacp_cbor::ErrorCode;
use sacp_cbor_abi::{decode, encode_to_vec, schema_hash, AbiType, CborAbi, CompatibilityClass};

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
#[abi(type_id = "ledger.Transfer", version = 1)]
struct TransferReordered {
    #[abi(id = 1)]
    from: u64,
    #[abi(id = 2)]
    to: u64,
    #[abi(id = 3)]
    amount: u64,
    #[abi(id = 4, optional)]
    memo: Option<String>,
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
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "ledger.Lenient", version = 1, unknown_fields = "ignore")]
struct Lenient {
    #[abi(id = 1)]
    value: u64,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn struct_abi_uses_numeric_ids_sorted_by_id() {
    let value = Transfer {
        from: 1,
        to: 2,
        amount: 50,
        memo: Some(String::from("ok")),
    };
    let bytes = encode_to_vec(&value).unwrap();
    assert_eq!(hex(&bytes), "880101020203183204626f6b");

    let decoded: Transfer =
        decode(&bytes, sacp_cbor::DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, value);

    let reordered = TransferReordered {
        from: 1,
        to: 2,
        amount: 50,
        memo: Some(String::from("ok")),
    };
    assert_eq!(encode_to_vec(&reordered).unwrap(), bytes);
    assert_eq!(
        schema_hash(&Transfer::schema()).unwrap(),
        schema_hash(&TransferReordered::schema()).unwrap()
    );
}

#[test]
fn optional_none_is_omitted() {
    let value = Transfer {
        from: 1,
        to: 2,
        amount: 50,
        memo: None,
    };
    let bytes = encode_to_vec(&value).unwrap();
    assert_eq!(hex(&bytes), "8601010202031832");
    let decoded: Transfer =
        decode(&bytes, sacp_cbor::DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn enum_abi_uses_variant_id_and_payload() {
    let accepted = encode_to_vec(&Decision::Accepted { id: 7 }).unwrap();
    assert_eq!(hex(&accepted), "8201820107");
    let decoded: Decision = decode(
        &accepted,
        sacp_cbor::DecodeLimits::for_bytes(accepted.len()),
    )
    .unwrap();
    assert_eq!(decoded, Decision::Accepted { id: 7 });

    let rejected = encode_to_vec(&Decision::Rejected).unwrap();
    assert_eq!(hex(&rejected), "8202f6");
    let decoded: Decision = decode(
        &rejected,
        sacp_cbor::DecodeLimits::for_bytes(rejected.len()),
    )
    .unwrap();
    assert_eq!(decoded, Decision::Rejected);
}

#[test]
fn decode_rejects_missing_unknown_duplicate_and_unsorted_fields() {
    let missing_required = [0x84, 0x01, 0x01, 0x02, 0x02];
    let err = decode::<Transfer>(
        &missing_required,
        sacp_cbor::DecodeLimits::for_bytes(missing_required.len()),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::MissingKey);

    let unknown = [
        0x88, 0x01, 0x01, 0x02, 0x02, 0x03, 0x18, 0x32, 0x18, 0x63, 0x00,
    ];
    let err = decode::<Transfer>(&unknown, sacp_cbor::DecodeLimits::for_bytes(unknown.len()))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnknownField);

    let duplicate = [0x86, 0x01, 0x01, 0x01, 0x02, 0x03, 0x18, 0x32];
    let err = decode::<Transfer>(
        &duplicate,
        sacp_cbor::DecodeLimits::for_bytes(duplicate.len()),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::DuplicateMapKey);

    let unsorted = [0x86, 0x02, 0x02, 0x01, 0x01, 0x03, 0x18, 0x32];
    let err = decode::<Transfer>(
        &unsorted,
        sacp_cbor::DecodeLimits::for_bytes(unsorted.len()),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalMapOrder);
}

#[test]
fn decode_can_ignore_unknown_fields_when_schema_allows_it() {
    let bytes = [0x84, 0x01, 0x05, 0x02, 0xf5];
    let decoded: Lenient = decode(&bytes, sacp_cbor::DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, Lenient { value: 5 });
}

#[test]
fn schema_hash_is_stable_golden_vector() {
    let hash = schema_hash(&Transfer::schema()).unwrap();
    assert_eq!(
        hash.to_string(),
        "c0e87050832901cdaa2883eea955b60b651aeed8238efafc0332fdbfeb028e93"
    );
    assert_eq!(
        sacp_cbor_abi::diff(&Transfer::schema(), &TransferReordered::schema()).class,
        CompatibilityClass::Compatible
    );
}
