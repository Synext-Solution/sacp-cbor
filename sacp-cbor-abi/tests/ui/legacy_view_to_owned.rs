use sacp_cbor::{validate_canonical, DecodeLimits};
use sacp_cbor_abi::CborAbi;

#[derive(CborAbi)]
#[abi(type_id = "ui.LegacyView", version = 1)]
struct LegacyView {
    #[abi(id = 1)]
    value: u64,
}

fn main() {
    let bytes = [0x82, 0x01, 0x00];
    let canonical = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let view = LegacyViewView::from_canonical(canonical).unwrap();
    let _ = view.to_owned();
}
