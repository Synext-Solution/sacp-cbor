#![no_main]

use libfuzzer_sys::fuzz_target;

use sacp_cbor::{validate_canonical, DecodeLimits};

fn fuzz_limits(input_len: usize) -> DecodeLimits {
    // Keep limits tight enough to avoid pathological allocations while still exploring structure.
    let max = input_len.min(1 << 20);
    DecodeLimits {
        max_input_bytes: max,
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
        // If validation succeeds, borrowed queries should be safe.
        let root = canon.root();
        let _ = root.kind();
        let _ = canon.sha256();
    }
});
