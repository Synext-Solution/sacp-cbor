use sacp_cbor_abi::AbiDecode;

fn requires_legacy_decode<'de, T: AbiDecode<'de>>() {}

fn main() {
    requires_legacy_decode::<u64>();
}
