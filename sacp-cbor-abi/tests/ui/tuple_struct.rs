use sacp_cbor_abi::CborAbi;

#[derive(CborAbi)]
#[abi(type_id = "bad.Tuple", version = 1)]
struct Bad(#[abi(id = 1)] u64);

fn main() {}
