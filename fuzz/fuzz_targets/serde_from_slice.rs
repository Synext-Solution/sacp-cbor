#![no_main]

use libfuzzer_sys::fuzz_target;

mod common;

use common::fuzz_limits;
use sacp_cbor::serde as sacp_serde;

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct FuzzStruct<'a> {
    #[serde(borrow)]
    a: Option<&'a str>,
    b: Option<bool>,
    c: Option<i64>,
}

fuzz_target!(|data: &[u8]| {
    let _ = sacp_serde::from_slice::<FuzzStruct<'_>>(data, fuzz_limits(data.len()));
});
