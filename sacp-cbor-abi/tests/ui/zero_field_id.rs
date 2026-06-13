use sacp_cbor_abi::CborAbi;

#[derive(CborAbi)]
#[abi(type_id = "bad.ZeroFieldId", version = 1)]
struct Bad {
    #[abi(id = 0)]
    a: u64,
}

fn main() {}
