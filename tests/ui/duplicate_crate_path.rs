use sacp_cbor::CborEncode;

#[derive(CborEncode)]
#[cbor(crate = "sacp_cbor", crate = "sacp_cbor")]
struct Bad {
    value: u64,
}

fn main() {}
