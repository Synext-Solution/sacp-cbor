use sacp_cbor::{validate_canonical, DecodeLimits};

fn main() {
    let bytes = [0x00];
    let canonical = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let _: u64 = sacp_cbor_abi::decode_canonical(canonical).unwrap();
}
