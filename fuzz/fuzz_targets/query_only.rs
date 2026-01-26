#![no_main]

use libfuzzer_sys::fuzz_target;

use sacp_cbor::{validate_canonical, DecodeLimits};

fn fuzz_limits(input_len: usize) -> DecodeLimits {
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
        let root = canon.root();

        let _ = root.kind();
        let _ = root.int();
        let _ = root.text();
        let _ = root.bytes();
        let _ = root.bool();
        let _ = root.float();
        let _ = root.bignum();

        if let Ok(arr) = root.array() {
            let _ = arr.len();
            let _ = arr.get(0);
        }

        if let Ok(map) = root.map() {
            for entry in map.iter().take(4) {
                if let Ok((k, v)) = entry {
                    let _ = map.get(k);
                    let _ = v.kind();
                }
            }
        }
    }
});
