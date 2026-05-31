#![allow(dead_code)]

use sacp_cbor::{validate_canonical, CanonicalCborRef, DecodeLimits};

pub(crate) fn fuzz_limits(input_len: usize) -> DecodeLimits {
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

pub(crate) fn with_canonical(data: &[u8], f: impl FnOnce(CanonicalCborRef<'_>)) {
    if let Ok(canon) = validate_canonical(data, fuzz_limits(data.len())) {
        f(canon);
    }
}
