use sacp_cbor_abi::CborAbi;

#[derive(CborAbi)]
#[abi(type_id = "bad.DuplicateVariantId", version = 1)]
enum Bad {
    #[abi(id = 1)]
    A,
    #[abi(id = 1)]
    B,
}

fn main() {}
