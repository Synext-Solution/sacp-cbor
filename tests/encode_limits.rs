#![cfg(feature = "alloc")]

use sacp_cbor::{EncodeLimits, Encoder, ErrorCode};

#[test]
fn encoder_rejects_output_byte_limit() {
    let limits = EncodeLimits {
        max_output_bytes: 2,
        ..EncodeLimits::unbounded()
    };
    let mut enc = Encoder::with_limits(limits).unwrap();
    let err = enc.text("aa").unwrap_err();
    assert_eq!(err.code, ErrorCode::MessageLenLimitExceeded);
    assert!(enc.is_empty());

    enc.null().unwrap();
    assert_eq!(enc.finish().unwrap().as_bytes(), &[0xf6]);
}

#[test]
fn encoder_rejects_output_byte_limit_without_partially_written_array_item() {
    let limits = EncodeLimits {
        max_output_bytes: 3,
        ..EncodeLimits::unbounded()
    };
    let mut enc = Encoder::with_limits(limits).unwrap();
    enc.array(1, |array| {
        let err = array.bytes(&[0, 1]).unwrap_err();
        assert_eq!(err.code, ErrorCode::MessageLenLimitExceeded);
        array.null()
    })
    .unwrap();
    assert_eq!(enc.finish().unwrap().as_bytes(), &[0x81, 0xf6]);
}

#[test]
fn encoder_rejects_container_depth_limit() {
    let limits = EncodeLimits {
        max_depth: 0,
        ..EncodeLimits::unbounded()
    };
    let mut enc = Encoder::with_limits(limits).unwrap();
    let err = enc.array(0, |_| Ok(())).unwrap_err();
    assert_eq!(err.code, ErrorCode::DepthLimitExceeded);
}

#[test]
fn encoder_rejects_total_item_limit() {
    let limits = EncodeLimits {
        max_total_items: 1,
        ..EncodeLimits::unbounded()
    };
    let mut enc = Encoder::with_limits(limits).unwrap();
    let err = enc.array(2, |_| Ok(())).unwrap_err();
    assert_eq!(err.code, ErrorCode::TotalItemsLimitExceeded);
}

#[test]
fn encoder_rejects_text_limit() {
    let limits = EncodeLimits {
        max_text_len: 1,
        ..EncodeLimits::unbounded()
    };
    let mut enc = Encoder::with_limits(limits).unwrap();
    let err = enc.text("aa").unwrap_err();
    assert_eq!(err.code, ErrorCode::TextLenLimitExceeded);
}

#[test]
fn encoder_clear_resets_item_accounting() {
    let limits = EncodeLimits {
        max_total_items: 1,
        ..EncodeLimits::unbounded()
    };
    let mut enc = Encoder::with_limits(limits).unwrap();
    enc.array(1, |arr| arr.value(&1i64)).unwrap();
    enc.clear();
    enc.array(1, |arr| arr.value(&2i64)).unwrap();
}
