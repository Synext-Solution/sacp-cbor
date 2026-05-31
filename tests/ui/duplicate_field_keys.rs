use sacp_cbor::CborEncode;

#[derive(CborEncode)]
struct DuplicateFields {
    #[cbor(rename = "x")]
    a: u8,
    #[cbor(rename = "x")]
    b: u8,
}

fn main() {}
