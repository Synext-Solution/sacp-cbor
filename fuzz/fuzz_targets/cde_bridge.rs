#![no_main]

use libfuzzer_sys::fuzz_target;

mod common;

use common::{fuzz_limits, with_canonical};
use sacp_cbor::cde::{from_cde, to_cde};

fuzz_target!(|data: &[u8]| {
    // Direction 1: any bytes from_cde accepts are canonical CDE, so the
    // bridge must invert them byte-identically.
    if let Ok(sacp) = from_cde(data, fuzz_limits(data.len())) {
        let image = to_cde(sacp.as_canonical_ref()).expect("to_cde is total");
        assert_eq!(image, data, "to_cde must invert from_cde");
    }

    // Direction 2: any canonical SACP item has a CDE image that never grows
    // and converts back byte-identically.
    with_canonical(data, |canon| {
        let image = to_cde(canon).expect("to_cde is total");
        assert!(image.len() <= data.len(), "the CDE image never grows");
        let back =
            from_cde(&image, fuzz_limits(data.len())).expect("the CDE image is accepted");
        assert_eq!(back.as_bytes(), data, "from_cde must invert to_cde");
    });
});
