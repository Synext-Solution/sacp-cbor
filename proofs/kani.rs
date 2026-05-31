use core::cmp::Ordering;

use crate::profile::{
    cmp_encoded_key_bytes, cmp_text_key_payloads_canonical, is_minimal_uint_ai, minimal_uint_ai,
    uint_argument_payload_len, validate_bignum_bytes, validate_f64_bits, CANONICAL_NAN_BITS,
    NEGATIVE_ZERO_BITS,
};
use crate::wire::{read_len_at, read_uint_arg_at};
use crate::{CborError, Encoder, ErrorCode};

fn assert_err<T>(actual: Result<T, CborError>, expected: ErrorCode) {
    match actual {
        Err(err) => assert!(err.code == expected),
        Ok(_) => unreachable!(),
    }
}

fn assert_read_uint<const AI: u8>(bytes: &[u8], value: u64) {
    let mut pos = 0usize;
    let actual = read_uint_arg_at::<true>(bytes, &mut pos, AI, 0);
    if is_minimal_uint_ai(AI, value) {
        match actual {
            Ok(decoded) => {
                assert!(decoded == value);
                assert!(pos == uint_argument_payload_len(AI).unwrap());
            }
            Err(_) => unreachable!(),
        }
    } else {
        assert_err(actual, ErrorCode::NonCanonicalEncoding);
    }
}

fn same_prefix(a: &[u8; 3], a_len: usize, b: &[u8; 3], b_len: usize) -> bool {
    kani::assume(a_len <= 3);
    kani::assume(b_len <= 3);
    if a_len != b_len {
        return false;
    }
    let mut idx = 0usize;
    while idx < a_len {
        if a[idx] != b[idx] {
            return false;
        }
        idx += 1;
    }
    true
}

fn short_text_key(payload: &[u8; 3], len: usize) -> [u8; 4] {
    kani::assume(len <= 3);
    let mut out = [0u8; 4];
    out[0] = 0x60 | (len as u8);
    let mut idx = 0usize;
    while idx < len {
        out[idx + 1] = payload[idx];
        idx += 1;
    }
    out
}

#[kani::proof]
fn uint_argument_classifier_is_minimal() {
    let value: u64 = kani::any();
    let ai = minimal_uint_ai(value);
    assert!(ai <= 27);
    assert!(uint_argument_payload_len(ai).is_some());
    assert!(is_minimal_uint_ai(ai, value));
}

#[kani::proof]
fn encoded_uint_payload_roundtrips_through_checked_reader() {
    let value: u64 = kani::any();
    let ai = minimal_uint_ai(value);
    let payload_len = uint_argument_payload_len(ai).unwrap();
    let mut payload = [0u8; 8];

    match ai {
        0..=23 => {}
        24 => payload[0] = value as u8,
        25 => {
            let bytes = (value as u16).to_be_bytes();
            payload[0] = bytes[0];
            payload[1] = bytes[1];
        }
        26 => {
            let bytes = (value as u32).to_be_bytes();
            payload[0] = bytes[0];
            payload[1] = bytes[1];
            payload[2] = bytes[2];
            payload[3] = bytes[3];
        }
        27 => payload = value.to_be_bytes(),
        _ => unreachable!(),
    }

    let mut pos = 0usize;
    let decoded = read_uint_arg_at::<true>(&payload[..payload_len], &mut pos, ai, 0).unwrap();
    assert!(decoded == value);
    assert!(pos == payload_len);
}

#[kani::proof]
fn checked_uint_arg_ai24_matches_minimal_rule() {
    let value: u8 = kani::any();
    assert_read_uint::<24>(&[value], u64::from(value));
}

#[kani::proof]
fn checked_uint_arg_ai25_matches_minimal_rule() {
    let value: u16 = kani::any();
    assert_read_uint::<25>(&value.to_be_bytes(), u64::from(value));
}

#[kani::proof]
fn checked_uint_arg_ai26_matches_minimal_rule() {
    let value: u32 = kani::any();
    assert_read_uint::<26>(&value.to_be_bytes(), u64::from(value));
}

#[kani::proof]
fn checked_uint_arg_ai27_matches_minimal_rule() {
    let value: u64 = kani::any();
    assert_read_uint::<27>(&value.to_be_bytes(), value);
}

#[kani::proof]
fn checked_len_rejects_indefinite_without_advancing() {
    let mut pos = 0usize;
    let actual = read_len_at::<true>(&[], &mut pos, 31, 7);
    assert_err(actual, ErrorCode::IndefiniteLengthForbidden);
    assert!(pos == 0);
}

#[kani::proof]
fn float_profile_classifies_all_bit_patterns() {
    let bits: u64 = kani::any();
    let actual = validate_f64_bits(bits);
    let is_nan = (bits & 0x7ff0_0000_0000_0000) == 0x7ff0_0000_0000_0000
        && (bits & 0x000f_ffff_ffff_ffff) != 0;

    if bits == NEGATIVE_ZERO_BITS {
        assert_err(
            actual.map_err(|code| CborError::new(code, 0)),
            ErrorCode::NegativeZeroForbidden,
        );
    } else if is_nan && bits != CANONICAL_NAN_BITS {
        assert_err(
            actual.map_err(|code| CborError::new(code, 0)),
            ErrorCode::NonCanonicalNaN,
        );
    } else {
        assert!(actual.is_ok());
    }
}

#[kani::proof]
fn bignum_boundaries_are_classified() {
    let max_safe = [0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let max_safe_plus_one = [0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let max_safe_minus_one = [0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe];

    assert!(
        validate_bignum_bytes(false, &max_safe) == Err(ErrorCode::BignumMustBeOutsideSafeRange)
    );
    assert!(validate_bignum_bytes(false, &max_safe_plus_one).is_ok());
    assert!(validate_bignum_bytes(true, &max_safe).is_ok());
    assert!(
        validate_bignum_bytes(true, &max_safe_minus_one)
            == Err(ErrorCode::BignumMustBeOutsideSafeRange)
    );
}

#[kani::proof]
#[kani::unwind(5)]
fn text_key_payload_order_matches_encoded_order_for_short_payloads() {
    let a_len: usize = kani::any();
    let b_len: usize = kani::any();
    kani::assume(a_len <= 3);
    kani::assume(b_len <= 3);

    let a = [kani::any::<u8>(), kani::any::<u8>(), kani::any::<u8>()];
    let b = [kani::any::<u8>(), kani::any::<u8>(), kani::any::<u8>()];
    let a_encoded = short_text_key(&a, a_len);
    let b_encoded = short_text_key(&b, b_len);

    assert!(
        cmp_encoded_key_bytes(&a_encoded[..(a_len + 1)], &b_encoded[..(b_len + 1)])
            == cmp_text_key_payloads_canonical(&a[..a_len], &b[..b_len])
    );
}

#[kani::proof]
#[kani::unwind(5)]
fn payload_comparator_equal_means_duplicate_key() {
    let a_len: usize = kani::any();
    let b_len: usize = kani::any();
    kani::assume(a_len <= 3);
    kani::assume(b_len <= 3);

    let a = [kani::any::<u8>(), kani::any::<u8>(), kani::any::<u8>()];
    let b = [kani::any::<u8>(), kani::any::<u8>(), kani::any::<u8>()];
    let order = cmp_text_key_payloads_canonical(&a[..a_len], &b[..b_len]);
    if order == Ordering::Equal {
        assert!(same_prefix(&a, a_len, &b, b_len));
    }
}

#[kani::proof]
#[kani::unwind(12)]
fn text_key_payload_order_is_transitive_for_short_payloads() {
    let a_len: usize = kani::any();
    let b_len: usize = kani::any();
    let c_len: usize = kani::any();
    kani::assume(a_len <= 3);
    kani::assume(b_len <= 3);
    kani::assume(c_len <= 3);

    let a = [kani::any::<u8>(), kani::any::<u8>(), kani::any::<u8>()];
    let b = [kani::any::<u8>(), kani::any::<u8>(), kani::any::<u8>()];
    let c = [kani::any::<u8>(), kani::any::<u8>(), kani::any::<u8>()];

    let ab = cmp_text_key_payloads_canonical(&a[..a_len], &b[..b_len]);
    let bc = cmp_text_key_payloads_canonical(&b[..b_len], &c[..c_len]);
    let ac = cmp_text_key_payloads_canonical(&a[..a_len], &c[..c_len]);

    if ab != Ordering::Greater && bc != Ordering::Greater {
        assert!(ac != Ordering::Greater);
    }
    if ab == Ordering::Less && bc == Ordering::Less {
        assert!(ac == Ordering::Less);
    }
}

#[kani::proof]
#[kani::unwind(10)]
fn text_key_payload_order_is_antisymmetric_for_short_payloads() {
    let a_len: usize = kani::any();
    let b_len: usize = kani::any();
    kani::assume(a_len <= 3);
    kani::assume(b_len <= 3);

    let a = [kani::any::<u8>(), kani::any::<u8>(), kani::any::<u8>()];
    let b = [kani::any::<u8>(), kani::any::<u8>(), kani::any::<u8>()];

    let ab = cmp_text_key_payloads_canonical(&a[..a_len], &b[..b_len]);
    let ba = cmp_text_key_payloads_canonical(&b[..b_len], &a[..a_len]);

    match ab {
        Ordering::Less => assert!(ba == Ordering::Greater),
        Ordering::Equal => assert!(ba == Ordering::Equal),
        Ordering::Greater => assert!(ba == Ordering::Less),
    }
}

#[kani::proof]
fn encoder_rolls_back_after_failed_array_callback() {
    let mut enc = Encoder::new();
    let err = enc
        .array(1, |_array| Err(CborError::new(ErrorCode::PatchConflict, 0)))
        .unwrap_err();
    assert!(err.code == ErrorCode::PatchConflict);
    assert!(enc.is_empty());
    enc.null().unwrap();
    let out = enc.finish().unwrap();
    assert!(out.as_bytes() == [0xf6]);
}

#[kani::proof]
fn encoder_rolls_back_after_array_underfill() {
    let mut enc = Encoder::new();
    let err = enc.array(1, |_array| Ok(())).unwrap_err();
    assert!(err.code == ErrorCode::ArrayLenMismatch);
    assert!(enc.is_empty());
    enc.null().unwrap();
    let out = enc.finish().unwrap();
    assert!(out.as_bytes() == [0xf6]);
}

#[kani::proof]
fn encoder_root_slot_accepts_exactly_one_value() {
    let mut enc = Encoder::new();
    enc.null().unwrap();
    let err = enc.bool(true).unwrap_err();
    assert!(err.code == ErrorCode::TrailingBytes);
    let out = enc.finish().unwrap();
    assert!(out.as_bytes() == [0xf6]);
}

#[kani::proof]
fn encoder_array_slot_conservation_for_one_scalar() {
    let mut enc = Encoder::new();
    enc.array(1, |array| array.null()).unwrap();
    let out = enc.finish().unwrap();
    assert!(out.as_bytes() == [0x81, 0xf6]);
}
