mod wire {
    pub mod abi {
        pub use sacp_cbor_abi::{
            __private, decode, decode_canonical, encode_to_vec, AbiDecode, AbiEncode,
            AbiFieldSetRef, AbiType, AbiTypeRef, AbiView, AbiViewField, CborAbi, FieldDef,
            FieldPresence, FieldSetDef, Schema, TypeDef, TypeRef, UnknownField, UnknownFieldPolicy,
            UnknownFieldRef, UnknownFields,
        };
    }

    pub mod cbor {
        pub use sacp_cbor::{CanonicalCbor, CborDecode, CborError, Decoder, Encoder, ErrorCode};
    }
}

use wire::abi::{decode, encode_to_vec, CborAbi, UnknownFields};

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(
    crate = crate::wire::abi,
    cbor = crate::wire::cbor,
    type_id = "facade.Transfer",
    version = 1,
    unknown_fields = "preserve"
)]
struct Transfer {
    #[abi(id = 1)]
    amount: u64,
    #[abi(unknown_fields)]
    unknown: UnknownFields,
}

#[test]
fn facade_abi_derive_roundtrips() {
    let bytes = [0x84, 0x01, 0x05, 0x02, 0xf5];
    let decoded: Transfer =
        decode(&bytes, sacp_cbor::DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded.amount, 5);
    assert_eq!(decoded.unknown.len(), 1);
    assert_eq!(encode_to_vec(&decoded).unwrap(), bytes);

    let canon = sacp_cbor::CanonicalCbor::from_slice(
        &bytes,
        sacp_cbor::DecodeLimits::for_bytes(bytes.len()),
    )
    .unwrap();
    let view = TransferView::from_canonical(canon.as_canonical_ref()).unwrap();
    assert_eq!(view.amount().unwrap(), 5);
    let unknown: Vec<_> = view.unknown_fields().unwrap().map(Result::unwrap).collect();
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].id, 2);
}
