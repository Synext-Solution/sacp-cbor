use sacp_cbor::{CborDecode, CborEncode};

#[derive(CborEncode, CborDecode)]
struct WithDefault {
    #[cbor(default)]
    value: u64,
}

fn main() {}
