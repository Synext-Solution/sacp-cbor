#![cfg(feature = "alloc")]
// The checked-decoder witness contract: a complete `Decoder<true>` pass
// that ends in `finish()` attests exactly what `validate_canonical[_with]`
// attests — one validation-grade traversal, no second pass.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;

use sacp_cbor::Decoder;
use sacp_cbor::{
    cbor_bytes, validate_canonical, validate_canonical_with, CborError, DecodeLimits, ErrorCode,
    ValidationOptions,
};

/// Validate `bytes` through a checked-decoder skip pass plus `finish`.
fn decoder_validates(bytes: &[u8], options: ValidationOptions) -> Result<(), CborError> {
    let mut decoder =
        Decoder::<true>::new_checked_with(bytes, DecodeLimits::for_bytes(bytes.len()), options)?;
    decoder.skip_value()?;
    decoder.finish()?;
    Ok(())
}

proptest! {
    /// Acceptance equivalence on arbitrary bytes, full grammar.
    #[test]
    fn decoder_pass_equivalent_to_validate(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let limits = DecodeLimits::for_bytes(bytes.len());
        let reference = validate_canonical(&bytes, limits).is_ok();
        let streamed = decoder_validates(&bytes, ValidationOptions::new()).is_ok();
        prop_assert_eq!(streamed, reference);
    }

    /// Acceptance equivalence under the no-float restriction mode.
    #[test]
    fn decoder_pass_equivalent_to_validate_no_float(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let limits = DecodeLimits::for_bytes(bytes.len());
        let options = ValidationOptions::new().no_float();
        let reference = validate_canonical_with(&bytes, limits, options).is_ok();
        let streamed = decoder_validates(&bytes, options).is_ok();
        prop_assert_eq!(streamed, reference);
    }

    /// Single-byte mutations of a canonical document keep the equivalence:
    /// the decoder pass and the batch validator agree on every mutant.
    #[test]
    fn mutation_equivalence(idx in 0usize..256, xor in 1u8..=255) {
        let zeros = [0u8; 16];
        let doc = cbor_bytes!({
            "a": [1, 2, 3],
            "b": { "x": true, "y": null },
            "c": zeros,
            "d": "text-payload",
        })
        .unwrap();
        let mut bytes = doc.as_bytes().to_vec();
        let idx = idx % bytes.len();
        bytes[idx] ^= xor;
        let limits = DecodeLimits::for_bytes(bytes.len());
        let reference = validate_canonical(&bytes, limits).is_ok();
        let streamed = decoder_validates(&bytes, ValidationOptions::new()).is_ok();
        prop_assert_eq!(streamed, reference);
    }
}

/// A typed field-by-field traversal yields the same witness bytes as the
/// batch validator.
#[test]
fn typed_traversal_yields_witness() {
    let doc = cbor_bytes!({ "n": 7, "s": "hi", "t": true }).unwrap();
    let bytes = doc.as_bytes();
    let mut decoder =
        Decoder::<true>::new_checked(bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    {
        let mut map = decoder.map().unwrap();
        let key = map.next_key_ref().unwrap().unwrap();
        assert_eq!(key.text, "n");
        assert_eq!(map.next_value::<u64>().unwrap(), 7);
        let key = map.next_key_ref().unwrap().unwrap();
        assert_eq!(key.text, "s");
        assert_eq!(map.next_value::<&str>().unwrap(), "hi");
        let key = map.next_key_ref().unwrap().unwrap();
        assert_eq!(key.text, "t");
        assert!(map.next_value::<bool>().unwrap());
    }
    let witness = decoder.finish().unwrap();
    let reference = validate_canonical(bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(witness.as_bytes(), reference.as_bytes());
}

/// Two concatenated canonical items are not one item: a pass that consumes
/// both roots must not produce a witness.
#[test]
fn two_root_values_rejected() {
    let bytes = [0x01, 0x02];
    let mut decoder =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    decoder.skip_value().unwrap();
    decoder.skip_value().unwrap();
    let err = decoder.finish().unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedCanonical);
}

/// Trailing bytes after one root value reject with `TrailingBytes`.
#[test]
fn trailing_bytes_rejected() {
    let bytes = [0x01, 0x02];
    let mut decoder =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    decoder.skip_value().unwrap();
    let err = decoder.finish().unwrap_err();
    assert_eq!(err.code, ErrorCode::TrailingBytes);
}

/// Empty input has no root value.
#[test]
fn empty_input_rejected() {
    let decoder = Decoder::<true>::new_checked(&[], DecodeLimits::for_bytes(0)).unwrap();
    let err = decoder.finish().unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedCanonical);
}

/// Empty containers complete at their header: an empty root map or array
/// finishes cleanly.
#[test]
fn empty_containers_at_root_finish() {
    for bytes in [[0x80u8], [0xa0u8]] {
        let mut decoder =
            Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
        match decoder.peek_kind().unwrap() {
            sacp_cbor::query::CborKind::Array => {
                let guard = decoder.array().unwrap();
                assert_eq!(guard.remaining(), 0);
                drop(guard);
            }
            sacp_cbor::query::CborKind::Map => {
                let mut guard = decoder.map().unwrap();
                assert!(guard.next_key_ref().unwrap().is_none());
                drop(guard);
            }
            other => panic!("unexpected kind {other:?}"),
        }
        decoder.finish().unwrap();
    }
}

/// A partially consumed guard poisons the decoder; `finish` reports it.
#[test]
fn early_guard_drop_poisons_finish() {
    let doc = cbor_bytes!([1, 2, 3]).unwrap();
    let bytes = doc.as_bytes();
    let mut decoder =
        Decoder::<true>::new_checked(bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    {
        let mut array = decoder.array().unwrap();
        assert_eq!(array.next_value::<u64>().unwrap(), Some(1));
        // Dropped with 2 elements remaining.
    }
    assert!(decoder.finish().is_err());
}

/// The no-float restriction applies inside skipped subtrees (the decoder
/// carries its options into `skip_value`).
#[test]
fn no_float_rejects_inside_skipped_subtree() {
    let doc = cbor_bytes!({ "x": [1, 1.5f64, 2] }).unwrap();
    let bytes = doc.as_bytes();
    // Full grammar: the skip pass accepts.
    decoder_validates(bytes, ValidationOptions::new()).unwrap();
    // No-float: the skip pass rejects at the float header.
    let err = decoder_validates(bytes, ValidationOptions::new().no_float()).unwrap_err();
    assert_eq!(err.code, ErrorCode::FloatForbidden);
}

/// The no-float restriction applies to typed float decodes.
#[test]
fn no_float_rejects_typed_float_decode() {
    let doc = cbor_bytes!(1.5f64).unwrap();
    let bytes = doc.as_bytes();
    let mut decoder = Decoder::<true>::new_checked_with(
        bytes,
        DecodeLimits::for_bytes(bytes.len()),
        ValidationOptions::new().no_float(),
    )
    .unwrap();
    let err = <f64 as sacp_cbor::CborDecode>::decode(&mut decoder).unwrap_err();
    assert_eq!(err.code, ErrorCode::FloatForbidden);
}

/// Recoverable (non-consuming) misuse does not prevent a later witness.
#[test]
fn recoverable_misuse_then_witness() {
    let doc = cbor_bytes!({ "k": 1 }).unwrap();
    let bytes = doc.as_bytes();
    let mut decoder =
        Decoder::<true>::new_checked(bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    {
        let mut map = decoder.map().unwrap();
        // Value before key: detected before consuming a byte.
        assert!(map.next_value::<u64>().is_err());
        let key = map.next_key_ref().unwrap().unwrap();
        assert_eq!(key.text, "k");
        assert_eq!(map.next_value::<u64>().unwrap(), 1);
    }
    decoder.finish().unwrap();
}

/// A consuming type-mismatch error is sticky: the cursor may sit mid-value,
/// so every later operation — `finish` included — fails. This is what makes
/// the witness sound against callers that swallow errors.
#[test]
fn consuming_error_is_sticky() {
    // Root value: the integer 500 (0x19 0x01 0xf4 — three bytes).
    let doc = cbor_bytes!(500).unwrap();
    let bytes = doc.as_bytes();
    let mut decoder =
        Decoder::<true>::new_checked(bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    // Asking for a bool consumes the header before the mismatch is seen.
    let err = <bool as sacp_cbor::CborDecode>::decode(&mut decoder).unwrap_err();
    assert_eq!(err.code, ErrorCode::ExpectedBool);
    // The pass is poisoned: skip and finish both fail.
    assert!(decoder.skip_value().is_err());
    assert!(decoder.finish().is_err());
}

/// `decode_value_with` carries caller-defined errors and poisons the pass.
#[test]
fn decode_value_with_caller_error_poisons() {
    #[derive(Debug, PartialEq)]
    enum AppError {
        Domain,
        Cbor(ErrorCode),
    }
    impl From<CborError> for AppError {
        fn from(err: CborError) -> Self {
            Self::Cbor(err.code)
        }
    }

    let doc = cbor_bytes!({ "k": 1 }).unwrap();
    let bytes = doc.as_bytes();
    let mut decoder =
        Decoder::<true>::new_checked(bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    {
        let mut map = decoder.map().unwrap();
        map.next_key_ref().unwrap().unwrap();
        let err = map
            .decode_value_with(|_| Err::<(), AppError>(AppError::Domain))
            .unwrap_err();
        assert_eq!(err, AppError::Domain);
    }
    assert!(decoder.finish().is_err());
}

proptest! {
    /// Acceptance equivalence under the no-simple restriction mode.
    #[test]
    fn decoder_pass_equivalent_to_validate_no_simple(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let limits = DecodeLimits::for_bytes(bytes.len());
        let options = ValidationOptions::new().no_simple();
        let reference = validate_canonical_with(&bytes, limits, options).is_ok();
        let streamed = decoder_validates(&bytes, options).is_ok();
        prop_assert_eq!(streamed, reference);
    }
}

/// The no-simple restriction applies inside skipped subtrees (the decoder
/// carries its options into `skip_value`).
#[test]
fn no_simple_rejects_inside_skipped_subtree() {
    let doc = cbor_bytes!({ "x": [1, true, 2] }).unwrap();
    let bytes = doc.as_bytes();
    // Full grammar: the skip pass accepts.
    decoder_validates(bytes, ValidationOptions::new()).unwrap();
    // No-simple: the skip pass rejects at the simple-value header.
    let err = decoder_validates(bytes, ValidationOptions::new().no_simple()).unwrap_err();
    assert_eq!(err.code, ErrorCode::SimpleForbidden);
}

/// The no-simple restriction applies to typed bool and null decodes.
#[test]
fn no_simple_rejects_typed_bool_and_null_decode() {
    let no_simple = ValidationOptions::new().no_simple();

    let doc = cbor_bytes!(true).unwrap();
    let bytes = doc.as_bytes();
    let mut decoder =
        Decoder::<true>::new_checked_with(bytes, DecodeLimits::for_bytes(bytes.len()), no_simple)
            .unwrap();
    let err = <bool as sacp_cbor::CborDecode>::decode(&mut decoder).unwrap_err();
    assert_eq!(err.code, ErrorCode::SimpleForbidden);

    let doc = cbor_bytes!(null).unwrap();
    let bytes = doc.as_bytes();
    let mut decoder =
        Decoder::<true>::new_checked_with(bytes, DecodeLimits::for_bytes(bytes.len()), no_simple)
            .unwrap();
    let err = <() as sacp_cbor::CborDecode>::decode(&mut decoder).unwrap_err();
    assert_eq!(err.code, ErrorCode::SimpleForbidden);
}
