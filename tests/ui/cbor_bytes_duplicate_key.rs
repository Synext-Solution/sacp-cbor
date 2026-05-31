use sacp_cbor::cbor_bytes;

fn main() {
    let _ = cbor_bytes!({ a: 1, a: 2 });
}
