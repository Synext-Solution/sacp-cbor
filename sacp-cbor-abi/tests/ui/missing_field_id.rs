use sacp_cbor_abi::CborAbi;

#[derive(CborAbi)]
#[abi(type_id = "bad.MissingFieldId", version = 1)]
struct Bad {
    value: u64,
}

fn main() {}
