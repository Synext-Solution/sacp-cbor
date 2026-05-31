use sacp_cbor::{CborDecode, CborEncode};

#[derive(CborEncode, CborDecode)]
#[cbor(untagged)]
enum Ambiguous {
    A(u64),
    B(i64),
}

fn main() {}
