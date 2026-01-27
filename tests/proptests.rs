#![cfg(feature = "alloc")]
// Property-based tests for SACP-CBOR/1 validation.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;

use sacp_cbor::{validate_canonical, DecodeLimits};

proptest! {
    #[test]
    fn validate_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len()));
    }
}
