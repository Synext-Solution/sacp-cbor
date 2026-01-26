use sacp_cbor::{decode_value, validate_canonical, CborErrorCode, DecodeLimits};

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

    let v = decode_value(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(v.encode_canonical().unwrap(), bytes);
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
