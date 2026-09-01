use sacp_cbor_abi::CborAbi;

#[derive(CborAbi)]
#[abi(type_id = "ui.Override", version = 1)]
struct Override {
    #[abi(id = 1, ty = "ui.AccountId")]
    value: u64,
}

fn main() {}
