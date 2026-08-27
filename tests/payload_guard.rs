use sacp_cbor::{
    validate_canonical, CborError, DecodeLimits, Decoder, EncodedValueHeader, ErrorCode,
    PayloadHeader,
};

#[derive(Debug, PartialEq, Eq)]
enum GuardError {
    Rejected,
    Cbor(CborError),
}

impl From<CborError> for GuardError {
    fn from(error: CborError) -> Self {
        Self::Cbor(error)
    }
}

#[test]
fn guarded_payloads_report_header_metadata_and_decode_normally() {
    let text = [0x62, b'o', b'k'];
    let mut text_decoder =
        Decoder::<true>::new_checked(&text, DecodeLimits::for_bytes(text.len())).unwrap();
    let mut text_header = None;
    let decoded = text_decoder
        .decode_text_with_guard::<CborError, _>(|header| {
            text_header = Some(header);
            Ok(())
        })
        .unwrap();
    assert_eq!(decoded, "ok");
    assert_eq!(text_header.unwrap().header_offset(), 0);
    assert_eq!(text_header.unwrap().declared_len(), 2);
    text_decoder.finish().unwrap();

    let mut bytes = vec![0x58, 24];
    bytes.extend(0u8..24);
    let mut bytes_decoder =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let mut bytes_header = None;
    let decoded = bytes_decoder
        .decode_bytes_with_guard::<CborError, _>(|header| {
            bytes_header = Some(header);
            Ok(())
        })
        .unwrap();
    assert_eq!(decoded, &(0u8..24).collect::<Vec<_>>());
    assert_eq!(bytes_header.unwrap().header_offset(), 0);
    assert_eq!(bytes_header.unwrap().declared_len(), 24);
    bytes_decoder.finish().unwrap();
}

#[test]
fn payload_guard_runs_before_payload_read_and_rejection_is_sticky() {
    // The header declares two bytes, but only one is present. Rejection wins over the later EOF,
    // proving that the guard runs before the payload read.
    let bytes = [0x42, 0xaa];
    let mut decoder =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let error = decoder
        .decode_bytes_with_guard::<GuardError, _>(|header| {
            assert_eq!(header.header_offset(), 0);
            assert_eq!(header.declared_len(), 2);
            Err(GuardError::Rejected)
        })
        .unwrap_err();
    assert_eq!(error, GuardError::Rejected);

    let poison = decoder.finish().unwrap_err();
    assert_eq!(poison.code, ErrorCode::MalformedCanonical);
    assert_eq!(poison.offset, 0);
}

#[test]
fn accepted_guard_observes_declared_length_before_truncated_payload_fails() {
    let bytes = [0x62, b'a'];
    let mut decoder =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let mut calls = 0;
    let error = decoder
        .decode_text_with_guard::<CborError, _>(|header| {
            calls += 1;
            assert_eq!(header.declared_len(), 2);
            Ok(())
        })
        .unwrap_err();
    assert_eq!(calls, 1);
    assert_eq!(error.code, ErrorCode::UnexpectedEof);
    assert_eq!(error.offset, 1);
}

#[test]
fn canonical_length_and_core_limits_run_before_payload_guard() {
    let noncanonical = [0x78, 0x00];
    let mut decoder =
        Decoder::<true>::new_checked(&noncanonical, DecodeLimits::for_bytes(noncanonical.len()))
            .unwrap();
    let mut calls = 0;
    let error = decoder
        .decode_text_with_guard::<CborError, _>(|_| {
            calls += 1;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(calls, 0);
    assert_eq!(error.code, ErrorCode::NonCanonicalEncoding);
    assert_eq!(error.offset, 0);

    let over_limit = [0x42];
    let mut limits = DecodeLimits::for_bytes(2);
    limits.max_bytes_len = 1;
    let mut decoder = Decoder::<true>::new_checked(&over_limit, limits).unwrap();
    let mut calls = 0;
    let error = decoder
        .decode_bytes_with_guard::<CborError, _>(|_| {
            calls += 1;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(calls, 0);
    assert_eq!(error.code, ErrorCode::BytesLenLimitExceeded);
    assert_eq!(error.offset, 0);
}

#[test]
fn trusted_decoder_runs_the_same_payload_guard() {
    let bytes = [0x61, b'x'];
    let canonical = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let mut decoder =
        Decoder::<false>::new_trusted(canonical, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let mut observed = None;
    let text = decoder
        .decode_text_with_guard::<GuardError, _>(|header| {
            observed = Some((header.header_offset(), header.declared_len()));
            Ok(())
        })
        .unwrap();
    assert_eq!(text, "x");
    assert_eq!(observed, Some((0, 1)));
    assert_eq!(decoder.position(), bytes.len());

    let mut rejected =
        Decoder::<false>::new_trusted(canonical, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let error = rejected
        .decode_text_with_guard::<GuardError, _>(|_| Err(GuardError::Rejected))
        .unwrap_err();
    assert_eq!(error, GuardError::Rejected);
    let poison = rejected.skip_value().unwrap_err();
    assert_eq!(poison.code, ErrorCode::MalformedCanonical);
    assert_eq!(poison.offset, 0);
}

#[test]
fn array_admission_is_consuming_and_empty_rejection_is_sticky() {
    let bytes = [0x80];
    let mut decoder =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let array = decoder.array().unwrap();
    let error = match array.admit_with::<GuardError, _>(|header| {
        assert_eq!(header.header_offset(), 0);
        assert_eq!(header.declared_len(), 0);
        Err(GuardError::Rejected)
    }) {
        Ok(_) => panic!("empty array admission unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(error, GuardError::Rejected);
    let poison = decoder.finish().unwrap_err();
    assert_eq!(poison.code, ErrorCode::MalformedCanonical);
    assert_eq!(poison.offset, 0);
}

#[test]
fn array_admission_preserves_normal_traversal() {
    let bytes = [0x81, 0x01];
    let mut decoder =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    {
        let mut array = decoder
            .array()
            .unwrap()
            .admit_with::<CborError, _>(|header| {
                assert_eq!(header.header_offset(), 0);
                assert_eq!(header.declared_len(), 1);
                Ok(())
            })
            .unwrap();
        assert_eq!(array.next_value::<u64>().unwrap(), Some(1));
        assert_eq!(array.next_value::<u64>().unwrap(), None);
    }
    decoder.finish().unwrap();
}

#[test]
fn array_admission_cannot_be_repeated_or_delayed_until_after_traversal() {
    let bytes = [0x81, 0x01];
    let mut decoder =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let array = decoder
        .array()
        .unwrap()
        .admit_with::<CborError, _>(|_| Ok(()))
        .unwrap();
    let mut second_calls = 0;
    let error = match array.admit_with::<CborError, _>(|_| {
        second_calls += 1;
        Ok(())
    }) {
        Ok(_) => panic!("array admission unexpectedly ran twice"),
        Err(error) => error,
    };
    assert_eq!(second_calls, 0);
    assert_eq!(error.code, ErrorCode::MalformedCanonical);
    assert_eq!(decoder.finish().unwrap_err(), error);

    let mut decoder =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let mut array = decoder.array().unwrap();
    assert_eq!(array.next_value::<u64>().unwrap(), Some(1));
    let mut late_calls = 0;
    let error = match array.admit_with::<CborError, _>(|_| {
        late_calls += 1;
        Ok(())
    }) {
        Ok(_) => panic!("array admission unexpectedly ran after traversal"),
        Err(error) => error,
    };
    assert_eq!(late_calls, 0);
    assert_eq!(error.code, ErrorCode::MalformedCanonical);
    assert_eq!(decoder.finish().unwrap_err(), error);
}

#[test]
fn array_structure_and_limits_are_checked_before_admission_is_available() {
    let bytes = [0x81, 0x00];
    let mut limits = DecodeLimits::for_bytes(bytes.len());
    limits.max_array_len = 0;
    let mut decoder = Decoder::<true>::new_checked(&bytes, limits).unwrap();
    let error = match decoder.array() {
        Ok(_) => panic!("over-limit array unexpectedly decoded"),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::ArrayLenLimitExceeded);
    assert_eq!(error.offset, 0);
}

#[test]
fn payload_header_is_copyable_for_typed_guard_errors() {
    fn keep(header: PayloadHeader) -> (usize, usize) {
        (header.header_offset(), header.declared_len())
    }

    let bytes = [0x40];
    let mut decoder =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let mut metadata = None;
    decoder
        .decode_bytes_with_guard::<CborError, _>(|header| {
            metadata = Some(keep(header));
            Ok(())
        })
        .unwrap();
    assert_eq!(metadata, Some((0, 0)));
}

#[test]
fn canonical_guard_runs_after_validation_before_owner_copy_and_rejection_is_sticky() {
    let bytes = [0x82, 0x01, 0x61, b'x'];
    let mut decoder =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let mut observed = None;
    let value = decoder
        .decode_canonical_with_guard::<CborError, _>(|header| {
            observed = Some((header.header_offset(), header.encoded_len()));
            Ok(())
        })
        .unwrap();
    assert_eq!(value.as_bytes(), bytes);
    assert_eq!(observed, Some((0, bytes.len())));
    decoder.finish().unwrap();

    let mut rejected =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let error = rejected
        .decode_canonical_with_guard::<GuardError, _>(|header| {
            assert_eq!(header.encoded_len(), bytes.len());
            Err(GuardError::Rejected)
        })
        .unwrap_err();
    assert_eq!(error, GuardError::Rejected);
    let poison = rejected.finish().unwrap_err();
    assert_eq!(poison.code, ErrorCode::MalformedCanonical);
    assert_eq!(poison.offset, 0);
}

#[test]
fn canonical_guard_is_not_called_for_invalid_structure() {
    let bytes = [0x82, 0x01];
    let mut decoder =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let mut calls = 0;
    let error = decoder
        .decode_canonical_with_guard::<CborError, _>(|_| {
            calls += 1;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(calls, 0);
    assert_eq!(error.code, ErrorCode::UnexpectedEof);
}

#[test]
fn encoded_value_header_is_copyable_for_typed_guard_errors() {
    fn keep(header: EncodedValueHeader) -> (usize, usize) {
        (header.header_offset(), header.encoded_len())
    }

    let bytes = [0xf6];
    let mut decoder =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let mut metadata = None;
    decoder
        .decode_canonical_with_guard::<CborError, _>(|header| {
            metadata = Some(keep(header));
            Ok(())
        })
        .unwrap();
    assert_eq!(metadata, Some((0, 1)));
}
