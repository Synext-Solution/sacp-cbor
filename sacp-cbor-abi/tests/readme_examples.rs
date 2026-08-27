use sacp_cbor::{CanonicalCbor, DecodeLimits};
use sacp_cbor_abi::{
    compile_runtime_schema, decode, encode_to_vec, AbiType, CborAbi, CompatibilityClass,
    NoNamedSchemas, RuntimeSchema, UnknownFields, UnknownVariant,
};

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(type_id = "ledger.Transfer", version = 1)]
struct Transfer {
    #[abi(id = 1)]
    from: u64,
    #[abi(id = 2)]
    to: u64,
    #[abi(id = 3)]
    amount: u64,
    #[abi(id = 4, optional)]
    memo: Option<String>,
}

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(type_id = "ledger.Command", version = 1)]
enum Command {
    #[abi(id = 1)]
    Route {
        #[abi(id = 1)]
        transfer_id: String,
        #[abi(id = 2)]
        priority: u64,
    },
    #[abi(id = 2)]
    Ping,
    #[abi(unknown)]
    Unknown(UnknownVariant),
}

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(
    type_id = "ledger.TransferEnvelope",
    version = 1,
    unknown_fields = "preserve"
)]
struct TransferEnvelope {
    #[abi(id = 1)]
    transfer: Transfer,
    #[abi(unknown_fields)]
    unknown: UnknownFields,
}

#[derive(CborAbi)]
#[abi(type_id = "ledger.Transfer", version = 1, unknown_fields = "preserve")]
struct TransferV1 {
    #[abi(id = 1)]
    from: u64,
    #[abi(id = 2)]
    to: u64,
    #[abi(id = 3)]
    amount: u64,
    #[abi(unknown_fields)]
    unknown: UnknownFields,
}

#[derive(CborAbi)]
#[abi(type_id = "ledger.Transfer", version = 2, unknown_fields = "preserve")]
struct TransferV2 {
    #[abi(id = 1)]
    from: u64,
    #[abi(id = 2)]
    to: u64,
    #[abi(id = 3)]
    amount: u64,
    #[abi(id = 4, optional)]
    memo: Option<String>,
    #[abi(unknown_fields)]
    unknown: UnknownFields,
}

pub mod wire {
    pub mod abi {
        pub use sacp_cbor_abi::*;
    }
    pub mod cbor {
        pub use sacp_cbor::{
            ByteSink, CanonicalCbor, CborDecode, CborError, Decoder, EncodeResult, ErrorCode,
            ValueEncoder,
        };
    }
}

#[derive(wire::abi::CborAbi)]
#[abi(
    crate = crate::wire::abi,
    cbor = crate::wire::cbor,
    type_id = "facade.Transfer",
    version = 1
)]
struct FacadeTransfer {
    #[abi(id = 1)]
    amount: u64,
}

#[test]
fn stable_public_abi_readme_examples_match_api() {
    let value = Transfer {
        from: 1001,
        to: 2002,
        amount: 5000,
        memo: None,
    };

    let bytes = encode_to_vec(&value).unwrap();
    let decoded: Transfer = decode(&bytes, DecodeLimits::for_bytes(bytes.len()), &mut ()).unwrap();
    assert_eq!(decoded, value);
    assert_eq!(
        bytes,
        [0x86, 0x01, 0x19, 0x03, 0xe9, 0x02, 0x19, 0x07, 0xd2, 0x03, 0x19, 0x13, 0x88]
    );

    let wire_hash = Transfer::schema().wire_hash().unwrap();
    let full_hash = Transfer::schema().full_hash().unwrap();
    assert_ne!(wire_hash, full_hash);

    let canon = CanonicalCbor::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let view = TransferView::from_canonical(canon.as_canonical_ref()).unwrap();
    assert_eq!(view.amount().unwrap(), 5000);
    assert_eq!(view.memo().unwrap(), None);
    assert_eq!(view.amount_raw().unwrap().as_bytes(), &[0x19, 0x13, 0x88]);
    assert_eq!(view.to_owned(&mut ()).unwrap(), value);

    let schema = Transfer::schema();
    let RuntimeSchema::Struct(runtime) = compile_runtime_schema(&schema).unwrap() else {
        unreachable!("Transfer schema is a struct")
    };
    let limits = sacp_cbor_abi::RuntimeValidationLimits::new(8, 64, 64, 16);
    let mut workspace = sacp_cbor_abi::RuntimeValidationWorkspace::new();
    workspace.prepare(limits).unwrap();
    let runtime_view = runtime
        .validate_value(
            canon.as_canonical_ref().root(),
            &NoNamedSchemas,
            limits,
            &mut workspace,
        )
        .unwrap();
    assert_eq!(
        runtime_view
            .require_raw(3)
            .unwrap()
            .integer()
            .unwrap()
            .as_u128(),
        Some(5000)
    );
}

#[test]
fn stable_public_abi_readme_schema_and_facade_examples_match_api() {
    let report = sacp_cbor_abi::diff(&TransferV1::schema(), &TransferV2::schema());
    assert_eq!(report.new_reads_old, CompatibilityClass::Compatible);
    assert_eq!(report.old_reads_new, CompatibilityClass::Compatible);
    assert_eq!(report.old_preserves_new, CompatibilityClass::Compatible);

    let command = Command::Route {
        transfer_id: String::from("tx-1"),
        priority: 7,
    };
    let bytes = encode_to_vec(&command).unwrap();
    assert_eq!(
        bytes,
        [0x82, 0x01, 0x84, 0x01, 0x64, b't', b'x', b'-', b'1', 0x02, 0x07]
    );

    let envelope = TransferEnvelope {
        transfer: Transfer {
            from: 1,
            to: 2,
            amount: 3,
            memo: None,
        },
        unknown: UnknownFields::empty(),
    };
    let envelope_bytes = encode_to_vec(&envelope).unwrap();
    let envelope_canon = CanonicalCbor::from_slice(
        &envelope_bytes,
        DecodeLimits::for_bytes(envelope_bytes.len()),
    )
    .unwrap();
    let envelope_view =
        TransferEnvelopeView::from_canonical(envelope_canon.as_canonical_ref()).unwrap();
    assert_eq!(envelope_view.transfer().unwrap().amount().unwrap(), 3);
    assert_eq!(envelope_view.unknown_fields().unwrap().count(), 0);

    let facade = FacadeTransfer { amount: 9 };
    assert_eq!(
        wire::abi::encode_to_vec(&facade).unwrap(),
        [0x82, 0x01, 0x09]
    );
}
