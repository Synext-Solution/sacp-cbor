#![cfg(feature = "alloc")]

use sacp_cbor::{CborEncode, CborError, EncodeLimits, Encoder, ErrorCode};

struct EncodeZero;

impl CborEncode for EncodeZero {
    fn encode(&self, _enc: &mut Encoder) -> Result<(), CborError> {
        Ok(())
    }
}

struct EncodeTwo;

impl CborEncode for EncodeTwo {
    fn encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.null()?;
        enc.null()
    }
}

#[test]
fn empty_encoder_finish_is_error() {
    let err = Encoder::new().finish().unwrap_err();
    assert_eq!(err.code, ErrorCode::UnexpectedEof);
}

#[test]
fn second_root_value_is_error() {
    let mut enc = Encoder::new();
    enc.null().unwrap();
    let err = enc.null().unwrap_err();
    assert_eq!(err.code, ErrorCode::TrailingBytes);
}

#[test]
fn map_entry_callback_emits_zero_values_is_error() {
    let mut enc = Encoder::new();
    let err = enc.map(1, |m| m.entry("a", |_enc| Ok(()))).unwrap_err();
    assert_eq!(err.code, ErrorCode::MapLenMismatch);
    assert!(enc.is_empty());

    enc.null().unwrap();
    assert_eq!(enc.finish().unwrap().as_bytes(), [0xf6]);
}

#[test]
fn map_entry_callback_emits_two_values_is_error() {
    let mut enc = Encoder::new();
    let err = enc
        .map(1, |m| {
            m.entry("a", |enc| {
                enc.null()?;
                enc.null()
            })
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MapLenMismatch);
    assert!(enc.is_empty());

    enc.null().unwrap();
    assert_eq!(enc.finish().unwrap().as_bytes(), [0xf6]);
}

#[test]
fn duplicate_map_key_error_rolls_back_encoder() {
    let mut enc = Encoder::new();
    let err = enc
        .map(2, |map| {
            map.entry("a", |entry| entry.null())?;
            map.entry("a", |entry| entry.null())
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::DuplicateMapKey);
    assert!(enc.is_empty());

    enc.null().unwrap();
    assert_eq!(enc.finish().unwrap().as_bytes(), [0xf6]);
}

#[test]
fn out_of_order_map_key_error_rolls_back_encoder() {
    let mut enc = Encoder::new();
    let err = enc
        .map(2, |map| {
            map.entry("bb", |entry| entry.null())?;
            map.entry("a", |entry| entry.null())
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalMapOrder);
    assert!(enc.is_empty());

    enc.null().unwrap();
    assert_eq!(enc.finish().unwrap().as_bytes(), [0xf6]);
}

#[test]
fn array_value_custom_encode_emits_zero_values_is_error() {
    let mut enc = Encoder::new();
    let err = enc.array(1, |a| a.value(&EncodeZero)).unwrap_err();
    assert_eq!(err.code, ErrorCode::ArrayLenMismatch);
    assert!(enc.is_empty());

    enc.null().unwrap();
    assert_eq!(enc.finish().unwrap().as_bytes(), [0xf6]);
}

#[test]
fn array_value_custom_encode_emits_two_values_is_error() {
    let mut enc = Encoder::new();
    let err = enc.array(2, |a| a.value(&EncodeTwo)).unwrap_err();
    assert_eq!(err.code, ErrorCode::ArrayLenMismatch);
    assert!(enc.is_empty());

    enc.null().unwrap();
    assert_eq!(enc.finish().unwrap().as_bytes(), [0xf6]);
}

#[test]
fn array_scalar_error_rolls_back_encoder() {
    let limits = EncodeLimits {
        max_output_bytes: 3,
        ..EncodeLimits::unbounded()
    };
    let mut enc = Encoder::with_limits(limits).unwrap();
    let err = enc.array(1, |a| a.text("aa")).unwrap_err();
    assert_eq!(err.code, ErrorCode::MessageLenLimitExceeded);
    assert!(enc.is_empty());

    enc.null().unwrap();
    assert_eq!(enc.finish().unwrap().as_bytes(), [0xf6]);
}
