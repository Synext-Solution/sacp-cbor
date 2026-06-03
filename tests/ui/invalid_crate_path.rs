use sacp_cbor::CborEncode;

#[derive(CborEncode)]
#[cbor(crate = sacp_cbor::<u8>)]
struct Bad {
    value: u64,
}

fn main() {}
