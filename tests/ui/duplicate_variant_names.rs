use sacp_cbor::CborEncode;

#[derive(CborEncode)]
enum DuplicateVariants {
    #[cbor(rename = "x")]
    A,
    #[cbor(rename = "x")]
    B,
}

fn main() {}
