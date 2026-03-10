use sacp_cbor::{CborDecode, CborEncode};

#[derive(CborEncode, CborDecode)]
enum Empty {}

fn main() {}
