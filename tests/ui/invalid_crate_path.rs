use sacp_cbor::CborEncode;

#[derive(CborEncode)]
#[cbor(crate = "not a path")]
struct Bad {
    value: u64,
}

fn main() {}
