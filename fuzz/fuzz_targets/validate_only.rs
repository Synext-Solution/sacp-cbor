#![no_main]

use libfuzzer_sys::fuzz_target;

mod common;

use common::fuzz_limits;
use sacp_cbor::validate_canonical;

fuzz_target!(|data: &[u8]| {
    let _ = validate_canonical(data, fuzz_limits(data.len()));
});
