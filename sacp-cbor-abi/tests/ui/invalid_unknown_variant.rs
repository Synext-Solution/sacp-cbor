use sacp_cbor_abi::CborAbi;

#[derive(CborAbi)]
#[abi(type_id = "bad.UnknownVariant", version = 1)]
enum Bad {
    #[abi(id = 1)]
    Known,
    #[abi(unknown)]
    Unknown { id: u32 },
}

fn main() {}
