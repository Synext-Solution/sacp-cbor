use sacp_cbor::DecodeLimits;

fn main() {
    let bytes = [0x00];
    let _: u64 = sacp_cbor_abi::decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
}
