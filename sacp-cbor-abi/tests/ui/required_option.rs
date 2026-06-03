use sacp_cbor_abi::CborAbi;

#[derive(CborAbi)]
#[abi(type_id = "bad.RequiredOption", version = 1)]
struct Bad {
    #[abi(id = 1)]
    maybe: Option<u64>,
}

fn main() {}
