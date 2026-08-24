use sacp_cbor::{CborError, DecodeLimits, Decoder, TraversalWorkspace};

fn main() {
    let bytes = [0x81, 0x01];
    let limits = DecodeLimits::for_bytes(bytes.len());
    let mut decoder = Decoder::<true>::new_checked(&bytes, limits).unwrap();
    let mut workspace = TraversalWorkspace::new();

    let _escaped = decoder
        .with_traversal(&mut workspace, |session| Ok::<_, CborError>(session))
        .unwrap();
}
