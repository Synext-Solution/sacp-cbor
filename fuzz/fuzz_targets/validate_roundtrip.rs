#![no_main]

use libfuzzer_sys::fuzz_target;

use sacp_cbor::{decode_value, validate_canonical, DecodeLimits};

fn fuzz_limits(input_len: usize) -> DecodeLimits {
    // Keep limits tight enough to avoid pathological allocations while still exploring structure.
    let max = input_len.min(1 << 20);
    DecodeLimits {
        max_depth: 64,
        max_total_items: 1 << 16,
        max_array_len: 1 << 12,
        max_map_len: 1 << 12,
        max_bytes_len: max,
        max_text_len: max,
    }
}

fuzz_target!(|data: &[u8]| {
    let limits = fuzz_limits(data.len());
    if let Ok(canon) = validate_canonical(data, limits) {
        // If validation succeeds, decoding should succeed and canonical re-encoding must be identical.
        if let Ok(v) = decode_value(data, limits) {
            let out = v.encode_canonical().expect("re-encode");
            assert_eq!(out, canon.as_bytes());

            let h1 = canon.sha256();
            let h2 = v.sha256_canonical().expect("hash");
            assert_eq!(h1, h2);
        } else {
            panic!("decode_value failed after validate_canonical succeeded");
        }
    }
});
