use sacp_cbor::CborEncode;

#[derive(CborEncode)]
#[cbor(rename_all = "snake_case")]
struct Bad {
    value: u64,
}

fn main() {}
