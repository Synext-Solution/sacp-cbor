use sacp_cbor::{CborDecode, CborEncode};

#[derive(CborEncode, CborDecode)]
#[cbor(tag = "kind")]
enum Invalid {
    Tuple(String),
}

fn main() {}
