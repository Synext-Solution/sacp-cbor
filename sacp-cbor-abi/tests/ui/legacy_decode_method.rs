use sacp_cbor::{DecodeLimits, Decoder};
use sacp_cbor_abi::AbiDecode;

fn main() {
    let bytes = [0x00];
    let mut decoder = Decoder::<true>::new_checked(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
    )
    .unwrap();
    let _ = <u64 as AbiDecode<'_, ()>>::abi_decode(&mut decoder);
}
