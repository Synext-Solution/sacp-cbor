use sacp_cbor_abi::CborAbi;

#[derive(CborAbi)]
#[abi(type_id = "bad.TypeVersion", version = 1)]
struct Bad {
    #[abi(id = 1, ty_version = 1)]
    value: u64,
}

fn main() {}
