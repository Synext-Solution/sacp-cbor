#[cfg(feature = "alloc")]
use sacp_cbor::decode_value;
use sacp_cbor::{validate_canonical, CborErrorCode, DecodeLimits};

fn assert_invalid(bytes: &[u8], limits: DecodeLimits, code: CborErrorCode) -> usize {
    let err = validate_canonical(bytes, limits).unwrap_err();
    assert_eq!(err.code, code);
    err.offset
}

#[cfg(feature = "alloc")]
fn assert_decode_validate_match(bytes: &[u8], limits: DecodeLimits, code: CborErrorCode) {
    let v_err = validate_canonical(bytes, limits).unwrap_err();
    let d_err = decode_value(bytes, limits).unwrap_err();
    assert_eq!(v_err.code, code);
    assert_eq!(d_err.code, code);
    assert_eq!(v_err.offset, d_err.offset);
    assert_eq!(v_err.kind, d_err.kind);
}

fn tstr_encoded(len: usize, fill: u8) -> Vec<u8> {
    let mut out = Vec::new();
    if len < 24 {
        out.push(0x60u8 | (len as u8));
    } else if len <= u8::MAX as usize {
        out.push(0x78);
        out.push(len as u8);
    } else if len <= u16::MAX as usize {
        out.push(0x79);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        panic!("test helper only supports <= u16::MAX");
    }
    out.extend(std::iter::repeat(fill).take(len));
    out
}

fn bstr_encoded(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let len = bytes.len();
    if len < 24 {
        out.push(0x40u8 | (len as u8));
    } else if len <= u8::MAX as usize {
        out.push(0x58);
        out.push(len as u8);
    } else if len <= u16::MAX as usize {
        out.push(0x59);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        panic!("test helper only supports <= u16::MAX");
    }
    out.extend_from_slice(bytes);
    out
}

#[test]
fn accepts_minimal_valid_map() {
    let bytes = [0xa1, 0x61, 0x61, 0x01]; // {"a":1}
    let canon = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(canon.as_bytes(), bytes);

    #[cfg(feature = "alloc")]
    {
        let v = decode_value(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
        assert_eq!(v.encode_canonical().unwrap(), bytes);
    }
}

#[test]
fn rejects_trailing_bytes() {
    let bytes = [0xa0, 0x00]; // {} then trailing 0x00
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::TrailingBytes);
}

#[test]
fn rejects_indefinite_length_text() {
    let bytes = [0x7f, 0xff]; // indefinite text, immediately break
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::IndefiniteLengthForbidden);
}

#[test]
fn rejects_non_canonical_uint_encoding() {
    let bytes = [0x18, 0x17]; // 23 encoded with 1-byte length argument (non-canonical)
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::NonCanonicalEncoding);
}

#[test]
fn rejects_non_canonical_length_encoding_for_text() {
    // length 23 text encoded with ai=24
    let mut bytes = vec![0x78, 23];
    bytes.extend(std::iter::repeat(b'a').take(23));
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::NonCanonicalEncoding);
}

#[test]
fn rejects_non_canonical_nint_encoding() {
    let bytes = [0x38, 0x17]; // -24, should be 0x37
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::NonCanonicalEncoding);
}

#[test]
fn rejects_non_canonical_tag_encoding() {
    // tag(2) encoded with ai=24 (non-canonical), followed by bstr magnitude
    let bytes = [0xd8, 0x02, 0x47, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::NonCanonicalEncoding);
    assert_eq!(err.offset, 0);
}

#[test]
fn rejects_non_canonical_length_encoding_for_bytes() {
    let mut bytes = vec![0x58, 23];
    bytes.extend(std::iter::repeat(0u8).take(23));
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::NonCanonicalEncoding);
}

#[test]
fn rejects_non_canonical_length_encoding_for_array_header() {
    let bytes = [0x98, 0x17]; // array length 23 encoded with ai=24
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::NonCanonicalEncoding);
}

#[test]
fn rejects_non_canonical_length_encoding_for_map_header() {
    let bytes = [0xb8, 0x17]; // map length 23 encoded with ai=24
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::NonCanonicalEncoding);
}

#[test]
fn rejects_map_key_not_text() {
    // { h'00': 0 }
    let bytes = [0xa1, 0x41, 0x00, 0x00];
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::MapKeyMustBeText);
}

#[test]
fn rejects_duplicate_map_key() {
    // {"a": 0, "a": 1}
    let bytes = [0xa2, 0x61, 0x61, 0x00, 0x61, 0x61, 0x01];
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::DuplicateMapKey);
}

#[test]
fn rejects_map_out_of_order_same_length() {
    // {"b": 0, "a": 1} (keys same encoded length; should be lexicographically sorted)
    let bytes = [0xa2, 0x61, 0x62, 0x00, 0x61, 0x61, 0x01];
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::NonCanonicalMapOrder);
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
    assert_eq!(err.code, CborErrorCode::NonCanonicalMapOrder);
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
    assert_eq!(err.code, CborErrorCode::NonCanonicalMapOrder);
}

#[test]
fn rejects_forbidden_tag() {
    let bytes = [0xc1, 0x00]; // tag(1) 0
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::ForbiddenOrMalformedTag);
}

#[test]
fn rejects_bignum_in_safe_range() {
    // tag(2) h'01'  => value 1, which must be encoded as int
    let mut bytes = vec![0xc2];
    bytes.extend_from_slice(&bstr_encoded(&[0x01]));
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::BignumMustBeOutsideSafeRange);
}

#[test]
fn rejects_bignum_with_leading_zero() {
    // tag(2) h'0001' => leading zero
    let mut bytes = vec![0xc2];
    bytes.extend_from_slice(&bstr_encoded(&[0x00, 0x01]));
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::BignumNotCanonical);
}

#[test]
fn rejects_negative_zero_float64() {
    let mut bytes = vec![0xfb];
    bytes.extend_from_slice(&0x8000_0000_0000_0000u64.to_be_bytes());
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::NegativeZeroForbidden);
}

#[test]
fn rejects_non_canonical_nan_float64() {
    let mut bytes = vec![0xfb];
    bytes.extend_from_slice(&0x7ff9_0000_0000_0000u64.to_be_bytes());
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::NonCanonicalNaN);
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
    max_uint.extend_from_slice(&sacp_cbor::MAX_SAFE_INTEGER.to_be_bytes());
    validate_canonical(&max_uint, DecodeLimits::for_bytes(max_uint.len())).unwrap();

    let n = sacp_cbor::MAX_SAFE_INTEGER - 1;
    let mut min_int = vec![0x3b];
    min_int.extend_from_slice(&n.to_be_bytes());
    validate_canonical(&min_int, DecodeLimits::for_bytes(min_int.len())).unwrap();
}

#[test]
fn rejects_safe_integer_overflow() {
    let mut too_big = vec![0x1b];
    too_big.extend_from_slice(&(sacp_cbor::MAX_SAFE_INTEGER + 1).to_be_bytes());
    assert_invalid(
        &too_big,
        DecodeLimits::for_bytes(too_big.len()),
        CborErrorCode::IntegerOutsideSafeRange,
    );

    let mut too_small = vec![0x3b];
    too_small.extend_from_slice(&sacp_cbor::MAX_SAFE_INTEGER.to_be_bytes());
    assert_invalid(
        &too_small,
        DecodeLimits::for_bytes(too_small.len()),
        CborErrorCode::IntegerOutsideSafeRange,
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
        CborErrorCode::BignumMustBeOutsideSafeRange,
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
        CborErrorCode::BignumMustBeOutsideSafeRange,
    );
}

#[test]
fn rejects_bignum_empty_magnitude() {
    let bytes = [0xc2, 0x40];
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        CborErrorCode::BignumNotCanonical,
    );
}

#[test]
fn rejects_bignum_non_canonical_length_encoding() {
    let bytes = [0xc2, 0x58, 0x01, 0x01];
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        CborErrorCode::NonCanonicalEncoding,
    );
}

#[test]
fn rejects_malformed_tag_shape() {
    let bytes = [0xc2, 0x00];
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        CborErrorCode::ForbiddenOrMalformedTag,
    );
}

#[test]
fn rejects_tag_with_indefinite_bstr() {
    let bytes = [0xc2, 0x5f, 0xff];
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        CborErrorCode::IndefiniteLengthForbidden,
    );
}

#[test]
fn rejects_invalid_utf8_text() {
    let bytes = [0x61, 0xff];
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        CborErrorCode::Utf8Invalid,
    );
}

#[test]
fn rejects_invalid_utf8_map_key() {
    let bytes = [0xa1, 0x61, 0xff, 0x00];
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        CborErrorCode::Utf8Invalid,
    );
}

#[test]
fn rejects_float16_float32_and_break() {
    let bytes_f16 = [0xf9, 0x00, 0x00];
    assert_invalid(
        &bytes_f16,
        DecodeLimits::for_bytes(bytes_f16.len()),
        CborErrorCode::UnsupportedSimpleValue,
    );

    let bytes_f32 = [0xfa, 0x00, 0x00, 0x00, 0x00];
    assert_invalid(
        &bytes_f32,
        DecodeLimits::for_bytes(bytes_f32.len()),
        CborErrorCode::UnsupportedSimpleValue,
    );

    let bytes_break = [0xff];
    assert_invalid(
        &bytes_break,
        DecodeLimits::for_bytes(bytes_break.len()),
        CborErrorCode::UnsupportedSimpleValue,
    );
}

#[test]
fn rejects_indefinite_lengths() {
    let bytes_bstr = [0x5f, 0xff];
    assert_invalid(
        &bytes_bstr,
        DecodeLimits::for_bytes(bytes_bstr.len()),
        CborErrorCode::IndefiniteLengthForbidden,
    );

    let bytes_array = [0x9f, 0xff];
    assert_invalid(
        &bytes_array,
        DecodeLimits::for_bytes(bytes_array.len()),
        CborErrorCode::IndefiniteLengthForbidden,
    );

    let bytes_map = [0xbf, 0xff];
    assert_invalid(
        &bytes_map,
        DecodeLimits::for_bytes(bytes_map.len()),
        CborErrorCode::IndefiniteLengthForbidden,
    );
}

#[test]
fn rejects_reserved_additional_info() {
    let bytes = [0x1c];
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        CborErrorCode::ReservedAdditionalInfo,
    );
}

#[test]
fn rejects_reserved_additional_info_for_text() {
    let bytes = [0x7c]; // major 3, ai=28
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        CborErrorCode::ReservedAdditionalInfo,
    );
}

#[test]
fn rejects_reserved_additional_info_for_bytes() {
    let bytes = [0x5c]; // major 2, ai=28
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        CborErrorCode::ReservedAdditionalInfo,
    );
}

#[test]
fn rejects_reserved_additional_info_for_array() {
    let bytes = [0x9c]; // major 4, ai=28
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        CborErrorCode::ReservedAdditionalInfo,
    );
}

#[test]
fn rejects_reserved_additional_info_for_map() {
    let bytes = [0xbc]; // major 5, ai=28
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        CborErrorCode::ReservedAdditionalInfo,
    );
}

#[test]
fn rejects_reserved_additional_info_for_simple() {
    let bytes = [0xfc]; // major 7, ai=28
    assert_invalid(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        CborErrorCode::ReservedAdditionalInfo,
    );
}

#[test]
fn unexpected_eof_offsets_are_stable() {
    let bytes = [0x18]; // uint8 additional info but missing byte
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::UnexpectedEof);
    assert_eq!(err.offset, 0);

    let bytes = [0xfb, 0x00]; // float64 missing 7 bytes
    let err = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap_err();
    assert_eq!(err.code, CborErrorCode::UnexpectedEof);
    assert_eq!(err.offset, 0);
}

#[test]
fn enforces_limits() {
    let bytes_array = [0x81, 0x00];
    let mut limits = DecodeLimits::for_bytes(bytes_array.len());
    limits.max_array_len = 0;
    assert_invalid(&bytes_array, limits, CborErrorCode::ArrayLenLimitExceeded);

    let bytes_map = [0xa1, 0x61, 0x61, 0x00];
    let mut limits = DecodeLimits::for_bytes(bytes_map.len());
    limits.max_map_len = 0;
    assert_invalid(&bytes_map, limits, CborErrorCode::MapLenLimitExceeded);

    let bytes_bstr = [0x41, 0x00];
    let mut limits = DecodeLimits::for_bytes(bytes_bstr.len());
    limits.max_bytes_len = 0;
    assert_invalid(&bytes_bstr, limits, CborErrorCode::BytesLenLimitExceeded);

    let bytes_tstr = [0x61, 0x61];
    let mut limits = DecodeLimits::for_bytes(bytes_tstr.len());
    limits.max_text_len = 0;
    assert_invalid(&bytes_tstr, limits, CborErrorCode::TextLenLimitExceeded);

    let bytes_depth = [0x80];
    let mut limits = DecodeLimits::for_bytes(bytes_depth.len());
    limits.max_depth = 0;
    assert_invalid(&bytes_depth, limits, CborErrorCode::DepthLimitExceeded);

    let mut limits = DecodeLimits::for_bytes(bytes_array.len());
    limits.max_total_items = 0;
    assert_invalid(&bytes_array, limits, CborErrorCode::TotalItemsLimitExceeded);

    let mut limits = DecodeLimits::for_bytes(bytes_map.len());
    limits.max_total_items = 1;
    assert_invalid(&bytes_map, limits, CborErrorCode::TotalItemsLimitExceeded);
}

#[cfg(feature = "alloc")]
#[test]
fn decode_and_validate_error_parity() {
    let samples: &[(&[u8], CborErrorCode)] = &[
        (&[0x00, 0x00], CborErrorCode::TrailingBytes),
        (&[0x18, 0x17], CborErrorCode::NonCanonicalEncoding),
        (&[0x61, 0xff], CborErrorCode::Utf8Invalid),
        (&[0xc1, 0x00], CborErrorCode::ForbiddenOrMalformedTag),
        (&[0xf9, 0x00, 0x00], CborErrorCode::UnsupportedSimpleValue),
        (&[0xa1, 0x41, 0x00, 0x00], CborErrorCode::MapKeyMustBeText),
    ];

    for (bytes, code) in samples {
        assert_decode_validate_match(bytes, DecodeLimits::for_bytes(bytes.len()), *code);
    }
}
