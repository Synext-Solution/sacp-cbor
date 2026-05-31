use sacp_cbor::profile::MAX_SAFE_INTEGER;
use sacp_cbor::{validate_canonical, DecodeLimits, Decoder, ErrorCode};

fn assert_invalid(bytes: &[u8], limits: DecodeLimits, code: ErrorCode) -> usize {
    let err = validate_canonical(bytes, limits).unwrap_err();
    assert_eq!(err.code, code);
    err.offset
}

fn len_header(major: u8, len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    if len < 24 {
        out.push((major << 5) | (len as u8));
    } else if len <= u8::MAX as usize {
        out.extend_from_slice(&[(major << 5) | 24, len as u8]);
    } else if len <= u16::MAX as usize {
        out.push((major << 5) | 25);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        panic!("test helper only supports <= u16::MAX");
    }
    out
}

fn tstr_encoded(len: usize, fill: u8) -> Vec<u8> {
    let mut out = len_header(3, len);
    out.extend(std::iter::repeat(fill).take(len));
    out
}

fn bstr_encoded(bytes: &[u8]) -> Vec<u8> {
    let mut out = len_header(2, bytes.len());
    out.extend_from_slice(bytes);
    out
}

#[test]
fn accepts_minimal_valid_map() {
    let bytes = [0xa1, 0x61, 0x61, 0x01]; // {"a":1}
    let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(canon.as_bytes(), bytes);
}

#[test]
fn dropping_partially_consumed_array_poisons_decoder() {
    let bytes = [0x82, 0x01, 0x02];
    let mut decoder =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();

    {
        let mut array = decoder.array().unwrap();
        assert_eq!(array.next_value::<u8>().unwrap(), Some(1));
    }

    let err = decoder.peek_kind().unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedCanonical);
}

#[test]
fn dropping_map_with_pending_value_poisons_decoder() {
    let bytes = [0xa1, 0x61, b'a', 0x01];
    let mut decoder =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();

    {
        let mut map = decoder.map().unwrap();
        let key = map.next_key_ref().unwrap().unwrap();
        assert_eq!(key.text, "a");
    }

    let err = decoder.peek_kind().unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedCanonical);
}

#[test]
fn map_pending_value_misuse_is_rejected() {
    let bytes = [0xa1, 0x61, b'a', 0x01];
    let mut decoder =
        Decoder::<true>::new_checked(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let mut map = decoder.map().unwrap();

    let err = map.next_value::<u8>().unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedCanonical);

    let key = map.next_key_ref().unwrap().unwrap();
    assert_eq!(key.text, "a");
    let err = map.next_key_ref().unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedCanonical);
    assert_eq!(map.next_value::<u8>().unwrap(), 1);
    assert!(map.next_key_ref().unwrap().is_none());
}

#[test]
fn array_and_map_over_read_return_none() {
    let array_bytes = [0x81, 0x01];
    let mut array_decoder =
        Decoder::<true>::new_checked(&array_bytes, DecodeLimits::for_bytes(array_bytes.len()))
            .unwrap();
    let mut array = array_decoder.array().unwrap();
    assert_eq!(array.next_value::<u8>().unwrap(), Some(1));
    assert_eq!(array.next_value::<u8>().unwrap(), None);

    let map_bytes = [0xa1, 0x61, b'a', 0x01];
    let mut map_decoder =
        Decoder::<true>::new_checked(&map_bytes, DecodeLimits::for_bytes(map_bytes.len())).unwrap();
    let mut map = map_decoder.map().unwrap();
    let key = map.next_key_ref().unwrap().unwrap();
    assert_eq!(key.text, "a");
    assert_eq!(map.next_value::<u8>().unwrap(), 1);
    assert!(map.next_key_ref().unwrap().is_none());
}

#[test]
fn rejects_input_len_over_limit() {
    let bytes = [0xf6]; // null
    let limits = DecodeLimits::for_bytes(0);
    let err = validate_canonical(&bytes, limits).unwrap_err();
    assert_eq!(err.code, ErrorCode::MessageLenLimitExceeded);

    let err = validate_canonical(&bytes, limits).unwrap_err();
    assert_eq!(err.code, ErrorCode::MessageLenLimitExceeded);
}

#[test]
fn rejects_reserved_additional_info_for_all_major_types() {
    for major in 0..=7 {
        for ai in 28..=30 {
            let bytes = [(major << 5) | ai];
            assert_invalid(
                &bytes,
                DecodeLimits::for_bytes(bytes.len()),
                ErrorCode::ReservedAdditionalInfo,
            );
        }
    }

    for major in [0, 1, 6] {
        let bytes = [(major << 5) | 31];
        assert_invalid(
            &bytes,
            DecodeLimits::for_bytes(bytes.len()),
            ErrorCode::ReservedAdditionalInfo,
        );
    }
}

#[test]
fn rejects_trailing_bytes() {
    let bytes = [0xa0, 0x00]; // {} then trailing 0x00
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::TrailingBytes);
}

#[test]
fn rejects_indefinite_length_text() {
    let bytes = [0x7f, 0xff]; // indefinite text, immediately break
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::IndefiniteLengthForbidden);
}

#[test]
fn rejects_non_canonical_uint_encoding() {
    let bytes = [0x18, 0x17]; // 23 encoded with 1-byte length argument (non-canonical)
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalEncoding);
}

#[test]
fn rejects_non_canonical_length_encoding_for_text() {
    // length 23 text encoded with ai=24
    let mut bytes = vec![0x78, 23];
    bytes.extend(std::iter::repeat(b'a').take(23));
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalEncoding);
}

#[test]
fn rejects_non_canonical_nint_encoding() {
    let bytes = [0x38, 0x17]; // -24, should be 0x37
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalEncoding);
}

#[test]
fn rejects_non_canonical_tag_encoding() {
    // tag(2) encoded with ai=24 (non-canonical), followed by bstr magnitude
    let bytes = [0xd8, 0x02, 0x47, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalEncoding);
    assert_eq!(err.offset, 0);
}

#[test]
fn rejects_non_canonical_length_encoding_for_bytes() {
    let mut bytes = vec![0x58, 23];
    bytes.extend(std::iter::repeat(0u8).take(23));
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalEncoding);
}

#[test]
fn rejects_non_canonical_length_encoding_for_array_header() {
    let bytes = [0x98, 0x17]; // array length 23 encoded with ai=24
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalEncoding);
}

#[test]
fn rejects_non_canonical_length_encoding_for_map_header() {
    let bytes = [0xb8, 0x17]; // map length 23 encoded with ai=24
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalEncoding);
}

#[test]
fn rejects_map_key_not_text() {
    // { h'00': 0 }
    let bytes = [0xa1, 0x41, 0x00, 0x00];
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::MapKeyMustBeText);
}

#[test]
fn rejects_duplicate_map_key() {
    // {"a": 0, "a": 1}
    let bytes = [0xa2, 0x61, 0x61, 0x00, 0x61, 0x61, 0x01];
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::DuplicateMapKey);
}

#[test]
fn rejects_map_out_of_order_same_length() {
    // {"b": 0, "a": 1} (keys same encoded length; should be lexicographically sorted)
    let bytes = [0xa2, 0x61, 0x62, 0x00, 0x61, 0x61, 0x01];
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalMapOrder);
}

#[test]
fn rejects_map_out_of_order_23_24_boundary() {
    // key1 length 24, key2 length 23 => out of order because encoded key bytes are longer for len 24.
    let key_long = tstr_encoded(24, b'b');
    let key_short = tstr_encoded(23, b'a');

    let mut bytes = Vec::new();
    bytes.push(0xa2);
    bytes.extend_from_slice(&key_long);
    bytes.push(0x00);
    bytes.extend_from_slice(&key_short);
    bytes.push(0x01);

    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalMapOrder);
}

#[test]
fn rejects_map_out_of_order_255_256_boundary() {
    let key_256 = tstr_encoded(256, b'b');
    let key_255 = tstr_encoded(255, b'a');

    let mut bytes = Vec::new();
    bytes.push(0xa2);
    bytes.extend_from_slice(&key_256);
    bytes.push(0x00);
    bytes.extend_from_slice(&key_255);
    bytes.push(0x01);

    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalMapOrder);
}

#[test]
fn rejects_forbidden_tag() {
    let bytes = [0xc1, 0x00]; // tag(1) 0
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::ForbiddenOrMalformedTag);
}

#[test]
fn rejects_bignum_in_safe_range() {
    // tag(2) h'01'  => value 1, which must be encoded as int
    let mut bytes = vec![0xc2];
    bytes.extend_from_slice(&bstr_encoded(&[0x01]));
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::BignumMustBeOutsideSafeRange);
}

#[test]
fn rejects_bignum_with_leading_zero() {
    // tag(2) h'0001' => leading zero
    let mut bytes = vec![0xc2];
    bytes.extend_from_slice(&bstr_encoded(&[0x00, 0x01]));
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::BignumNotCanonical);
}

#[test]
fn rejects_negative_zero_float64() {
    let mut bytes = vec![0xfb];
    bytes.extend_from_slice(&0x8000_0000_0000_0000u64.to_be_bytes());
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::NegativeZeroForbidden);
}

#[test]
fn rejects_non_canonical_nan_float64() {
    let mut bytes = vec![0xfb];
    bytes.extend_from_slice(&0x7ff9_0000_0000_0000u64.to_be_bytes());
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalNaN);
}

#[test]
fn accepts_canonical_nan_float64() {
    let mut bytes = vec![0xfb];
    bytes.extend_from_slice(&0x7ff8_0000_0000_0000u64.to_be_bytes());
    validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
}

#[test]
fn accepts_safe_integer_boundaries() {
    let mut max_uint = vec![0x1b];
    max_uint.extend_from_slice(&MAX_SAFE_INTEGER.to_be_bytes());
    validate_canonical(&max_uint, DecodeLimits::for_bytes(max_uint.len())).unwrap();

    let n = MAX_SAFE_INTEGER - 1;
    let mut min_int = vec![0x3b];
    min_int.extend_from_slice(&n.to_be_bytes());
    validate_canonical(&min_int, DecodeLimits::for_bytes(min_int.len())).unwrap();
}

#[test]
fn rejects_safe_integer_overflow() {
    let mut too_big = vec![0x1b];
    too_big.extend_from_slice(&(MAX_SAFE_INTEGER + 1).to_be_bytes());
    assert_invalid(
        &too_big,
        DecodeLimits::for_bytes(too_big.len()),
        ErrorCode::IntegerOutsideSafeRange,
    );

    let mut too_small = vec![0x3b];
    too_small.extend_from_slice(&MAX_SAFE_INTEGER.to_be_bytes());
    assert_invalid(
        &too_small,
        DecodeLimits::for_bytes(too_small.len()),
        ErrorCode::IntegerOutsideSafeRange,
    );
}

#[test]
fn bignum_boundary_cases() {
    let max_safe_mag = [0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let max_safe_plus_one = [0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let max_safe_minus_one = [0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe];

    let mut pos_eq_safe = vec![0xc2];
    pos_eq_safe.extend_from_slice(&bstr_encoded(&max_safe_mag));
    assert_invalid(
        &pos_eq_safe,
        DecodeLimits::for_bytes(pos_eq_safe.len()),
        ErrorCode::BignumMustBeOutsideSafeRange,
    );

    let mut pos_gt_safe = vec![0xc2];
    pos_gt_safe.extend_from_slice(&bstr_encoded(&max_safe_plus_one));
    validate_canonical(&pos_gt_safe, DecodeLimits::for_bytes(pos_gt_safe.len())).unwrap();

    let mut neg_eq_safe = vec![0xc3];
    neg_eq_safe.extend_from_slice(&bstr_encoded(&max_safe_mag));
    validate_canonical(&neg_eq_safe, DecodeLimits::for_bytes(neg_eq_safe.len())).unwrap();

    let mut neg_lt_safe = vec![0xc3];
    neg_lt_safe.extend_from_slice(&bstr_encoded(&max_safe_minus_one));
    assert_invalid(
        &neg_lt_safe,
        DecodeLimits::for_bytes(neg_lt_safe.len()),
        ErrorCode::BignumMustBeOutsideSafeRange,
    );
}

#[test]
fn rejects_bignum_empty_magnitude() {
    let bytes = [0xc2, 0x40];
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        ErrorCode::BignumNotCanonical,
    );
}

#[test]
fn rejects_bignum_non_canonical_length_encoding() {
    let bytes = [0xc2, 0x58, 0x01, 0x01];
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        ErrorCode::NonCanonicalEncoding,
    );
}

#[test]
fn rejects_malformed_tag_shape() {
    let bytes = [0xc2, 0x00];
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        ErrorCode::ForbiddenOrMalformedTag,
    );
}

#[test]
fn rejects_tag_with_indefinite_bstr() {
    let bytes = [0xc2, 0x5f, 0xff];
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        ErrorCode::IndefiniteLengthForbidden,
    );
}

#[test]
fn rejects_invalid_utf8_text() {
    let bytes = [0x61, 0xff];
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        ErrorCode::Utf8Invalid,
    );
}

#[test]
fn rejects_invalid_utf8_map_key() {
    let bytes = [0xa1, 0x61, 0xff, 0x00];
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        ErrorCode::Utf8Invalid,
    );
}

#[test]
fn rejects_float16_float32_and_break() {
    let bytes_f16 = [0xf9, 0x00, 0x00];
    assert_invalid(
        &bytes_f16,
        DecodeLimits::for_bytes(bytes_f16.len()),
        ErrorCode::UnsupportedSimpleValue,
    );

    let bytes_f32 = [0xfa, 0x00, 0x00, 0x00, 0x00];
    assert_invalid(
        &bytes_f32,
        DecodeLimits::for_bytes(bytes_f32.len()),
        ErrorCode::UnsupportedSimpleValue,
    );

    let bytes_break = [0xff];
    assert_invalid(
        &bytes_break,
        DecodeLimits::for_bytes(bytes_break.len()),
        ErrorCode::UnsupportedSimpleValue,
    );
}

#[test]
fn rejects_additional_info_24_simple_values() {
    assert_invalid(
        &[0xf8, 0x17],
        DecodeLimits::for_bytes(2),
        ErrorCode::NonCanonicalEncoding,
    );
    assert_invalid(
        &[0xf8, 0x20],
        DecodeLimits::for_bytes(2),
        ErrorCode::UnsupportedSimpleValue,
    );
}

#[test]
fn rejects_indefinite_lengths() {
    let bytes_bstr = [0x5f, 0xff];
    assert_invalid(
        &bytes_bstr,
        DecodeLimits::for_bytes(bytes_bstr.len()),
        ErrorCode::IndefiniteLengthForbidden,
    );

    let bytes_array = [0x9f, 0xff];
    assert_invalid(
        &bytes_array,
        DecodeLimits::for_bytes(bytes_array.len()),
        ErrorCode::IndefiniteLengthForbidden,
    );

    let bytes_map = [0xbf, 0xff];
    assert_invalid(
        &bytes_map,
        DecodeLimits::for_bytes(bytes_map.len()),
        ErrorCode::IndefiniteLengthForbidden,
    );
}

#[test]
fn unexpected_eof_offsets_are_stable() {
    let bytes = [0x18]; // uint8 additional info but missing byte
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::UnexpectedEof);
    assert_eq!(err.offset, 1);

    let bytes = [0xfb, 0x00]; // float64 missing 7 bytes
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, ErrorCode::UnexpectedEof);
    assert_eq!(err.offset, 1);
}

#[test]
fn rejects_truncated_valid_document_at_every_byte_position() {
    let bytes = [0xa1, 0x61, b'a', 0x82, 0x01, 0xa1, 0x61, b'b', 0xf5];
    for len in 0..bytes.len() {
        assert_invalid(
            &bytes[..len],
            DecodeLimits::for_bytes(bytes.len()),
            ErrorCode::UnexpectedEof,
        );
    }
}

#[test]
fn enforces_limits() {
    let bytes_array = [0x81, 0x00];
    let mut limits = DecodeLimits::for_bytes(bytes_array.len());
    limits.max_array_len = 0;
    assert_invalid(&bytes_array, limits, ErrorCode::ArrayLenLimitExceeded);

    let bytes_map = [0xa1, 0x61, 0x61, 0x00];
    let mut limits = DecodeLimits::for_bytes(bytes_map.len());
    limits.max_map_len = 0;
    assert_invalid(&bytes_map, limits, ErrorCode::MapLenLimitExceeded);

    let bytes_bstr = [0x41, 0x00];
    let mut limits = DecodeLimits::for_bytes(bytes_bstr.len());
    limits.max_bytes_len = 0;
    assert_invalid(&bytes_bstr, limits, ErrorCode::BytesLenLimitExceeded);

    let bytes_tstr = [0x61, 0x61];
    let mut limits = DecodeLimits::for_bytes(bytes_tstr.len());
    limits.max_text_len = 0;
    assert_invalid(&bytes_tstr, limits, ErrorCode::TextLenLimitExceeded);

    let bytes_depth = [0x80];
    let mut limits = DecodeLimits::for_bytes(bytes_depth.len());
    limits.max_depth = 0;
    assert_invalid(&bytes_depth, limits, ErrorCode::DepthLimitExceeded);

    let mut limits = DecodeLimits::for_bytes(bytes_array.len());
    limits.max_total_items = 0;
    assert_invalid(&bytes_array, limits, ErrorCode::TotalItemsLimitExceeded);

    let mut limits = DecodeLimits::for_bytes(bytes_map.len());
    limits.max_total_items = 1;
    assert_invalid(&bytes_map, limits, ErrorCode::TotalItemsLimitExceeded);
}

#[test]
fn accepts_limits_at_boundary_and_rejects_boundary_plus_one() {
    let nested_array = [0x81, 0x80];
    let mut limits = DecodeLimits::for_bytes(nested_array.len());
    limits.max_depth = 2;
    validate_canonical(&nested_array, limits).unwrap();
    limits.max_depth = 1;
    assert_invalid(&nested_array, limits, ErrorCode::DepthLimitExceeded);

    let two_items = [0x82, 0x00, 0x01];
    let mut limits = DecodeLimits::for_bytes(two_items.len());
    limits.max_total_items = 2;
    validate_canonical(&two_items, limits).unwrap();
    limits.max_total_items = 1;
    assert_invalid(&two_items, limits, ErrorCode::TotalItemsLimitExceeded);
}

#[cfg(feature = "alloc")]
#[test]
fn accepts_nesting_beyond_inline_stack_capacity() {
    let depth = 40usize;
    let mut bytes = Vec::with_capacity(depth + 1);
    bytes.extend(std::iter::repeat(0x81).take(depth));
    bytes.push(0xf6);

    let mut limits = DecodeLimits::for_bytes(bytes.len());
    limits.max_depth = depth;
    limits.max_total_items = depth + 1;
    validate_canonical(&bytes, limits).unwrap();

    limits.max_depth = depth - 1;
    assert_invalid(&bytes, limits, ErrorCode::DepthLimitExceeded);
}

#[test]
fn enforces_declared_length_limits_at_encoding_boundaries() {
    let text_23 = tstr_encoded(23, b'a');
    let text_24 = tstr_encoded(24, b'a');
    let bytes_255 = bstr_encoded(&vec![0; 255]);
    let bytes_256 = bstr_encoded(&vec![0; 256]);

    let mut limits = DecodeLimits::for_bytes(text_24.len());
    limits.max_text_len = 23;
    validate_canonical(&text_23, limits).unwrap();
    assert_invalid(&text_24, limits, ErrorCode::TextLenLimitExceeded);

    let mut limits = DecodeLimits::for_bytes(bytes_256.len());
    limits.max_bytes_len = 255;
    validate_canonical(&bytes_255, limits).unwrap();
    assert_invalid(&bytes_256, limits, ErrorCode::BytesLenLimitExceeded);
}
