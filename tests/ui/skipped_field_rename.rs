use sacp_cbor::CborEncode;

#[derive(CborEncode)]
struct BadSkipRename {
    #[cbor(skip, rename = "wire")]
    transient: bool,
}

fn main() {}
