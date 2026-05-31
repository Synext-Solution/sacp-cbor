#![no_main]

use libfuzzer_sys::fuzz_target;

mod common;

use common::with_canonical;

fuzz_target!(|data: &[u8]| {
    with_canonical(data, |canon| {
        // If validation succeeds, borrowed queries should be safe.
        let root = canon.root();
        let _ = root.kind();
        let _ = canon.sha256();
    });
});
