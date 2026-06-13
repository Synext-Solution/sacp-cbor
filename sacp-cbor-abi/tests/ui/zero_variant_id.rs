use sacp_cbor_abi::CborAbi;

#[derive(CborAbi)]
#[abi(type_id = "bad.ZeroVariantId", version = 1)]
enum Bad {
    #[abi(id = 0)]
    A,
}

fn main() {}
