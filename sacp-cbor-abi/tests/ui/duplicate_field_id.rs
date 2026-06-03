use sacp_cbor_abi::CborAbi;

#[derive(CborAbi)]
#[abi(type_id = "bad.DuplicateFieldId", version = 1)]
struct Bad {
    #[abi(id = 1)]
    a: u64,
    #[abi(id = 1)]
    b: u64,
}

fn main() {}
