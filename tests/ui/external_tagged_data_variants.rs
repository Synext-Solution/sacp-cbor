use sacp_cbor::{CborDecode, CborEncode};

#[derive(CborEncode, CborDecode)]
enum ExternalDataOnly {
    Newtype(String),
    Tuple(String, u8),
    Struct { id: String },
}

fn main() {}
