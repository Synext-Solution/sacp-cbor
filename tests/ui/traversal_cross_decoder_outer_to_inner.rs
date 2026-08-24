use sacp_cbor::{DecodeLimits, Decoder, TraversalSession, TraversalWorkspace};

fn require_same_brand<'a, 'b, 'de, 'brand>(
    _: &mut TraversalSession<'a, 'de, 'brand, true>,
    _: &mut TraversalSession<'b, 'de, 'brand, true>,
) {
}

fn main() {
    let bytes = [0x81, 0x01];
    let limits = DecodeLimits::for_bytes(bytes.len());
    let mut outer_decoder = Decoder::<true>::new_checked(&bytes, limits).unwrap();
    let mut inner_decoder = Decoder::<true>::new_checked(&bytes, limits).unwrap();
    let mut outer_workspace = TraversalWorkspace::new();
    let mut inner_workspace = TraversalWorkspace::new();

    outer_decoder
        .with_traversal(&mut outer_workspace, |outer| -> Result<(), sacp_cbor::CborError> {
            inner_decoder.with_traversal(&mut inner_workspace, |inner| -> Result<(), sacp_cbor::CborError> {
                require_same_brand(outer, inner);
                Ok(())
            })
        })
        .unwrap();
}
