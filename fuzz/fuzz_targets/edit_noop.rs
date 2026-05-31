#![no_main]

use libfuzzer_sys::fuzz_target;

mod common;

use common::with_canonical;

fuzz_target!(|data: &[u8]| {
    with_canonical(data, |canon| {
        if let Ok(edited) = canon.edit(|_| Ok(())) {
            assert_eq!(edited.as_bytes(), canon.as_bytes());
        }
    });
});
