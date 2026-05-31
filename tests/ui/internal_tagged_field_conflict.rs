use sacp_cbor::{CborDecode, CborEncode};

#[derive(CborEncode, CborDecode)]
#[cbor(tag = "kind")]
enum Event {
    Data { kind: u8 },
}

fn main() {}
