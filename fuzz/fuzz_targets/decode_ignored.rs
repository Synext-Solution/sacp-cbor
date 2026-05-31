#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::de::IgnoredAny;

mod common;

use common::fuzz_limits;
use sacp_cbor::serde as sacp_serde;

fuzz_target!(|data: &[u8]| {
    let _ = sacp_serde::from_slice::<IgnoredAny>(data, fuzz_limits(data.len()));
});
