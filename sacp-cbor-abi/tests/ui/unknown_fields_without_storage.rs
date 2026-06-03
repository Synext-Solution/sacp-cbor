use sacp_cbor_abi::CborAbi;

#[derive(CborAbi)]
#[abi(type_id = "bad.UnknownFields", version = 1, unknown_fields = "preserve")]
struct Bad {
    #[abi(id = 1)]
    value: u64,
}

fn main() {}
