#![no_main]

use libfuzzer_sys::fuzz_target;

mod common;

use common::with_canonical;

fuzz_target!(|data: &[u8]| {
    with_canonical(data, |canon| {
        let root = canon.root();

        let _ = root.kind();
        let _ = root.integer();
        let _ = root.text();
        let _ = root.bytes();
        let _ = root.bool();
        let _ = root.float64();
        let _ = root.integer().map(|i| i.as_bigint());

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
    });
});
