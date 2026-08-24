#![cfg(feature = "alloc")]

use sacp_cbor::{EncodeError, EncodeLimits, Encoder, ErrorCode};

fn assert_cbor(error: EncodeError<sacp_cbor::CborError>, code: ErrorCode) {
    assert!(matches!(error, EncodeError::Cbor(error) if error.code == code));
}

#[test]
fn encoder_rejects_output_byte_limit() {
    let limits = EncodeLimits {
        max_output_bytes: 2,
        ..EncodeLimits::unbounded()
    };
    let mut enc = Encoder::with_limits(limits).unwrap();
    let err = enc.text("aa").unwrap_err();
    assert_cbor(err, ErrorCode::MessageLenLimitExceeded);
    assert!(enc.is_empty());
    assert!(matches!(enc.null(), Err(EncodeError::Poisoned)));
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
        assert_cbor(err, ErrorCode::MessageLenLimitExceeded);
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(enc.null(), Err(EncodeError::Poisoned)));
}

#[test]
fn encoder_rejects_container_depth_limit() {
    let limits = EncodeLimits {
        max_depth: 0,
        ..EncodeLimits::unbounded()
    };
    let mut enc = Encoder::with_limits(limits).unwrap();
    let err = enc.array(0, |_| Ok(())).unwrap_err();
    assert_cbor(err, ErrorCode::DepthLimitExceeded);
}

#[test]
fn encoder_rejects_total_item_limit() {
    let limits = EncodeLimits {
        max_total_items: 1,
        ..EncodeLimits::unbounded()
    };
    let mut enc = Encoder::with_limits(limits).unwrap();
    let err = enc.array(2, |_| Ok(())).unwrap_err();
    assert_cbor(err, ErrorCode::TotalItemsLimitExceeded);
}

#[test]
fn encoder_rejects_text_limit() {
    let limits = EncodeLimits {
        max_text_len: 1,
        ..EncodeLimits::unbounded()
    };
    let mut enc = Encoder::with_limits(limits).unwrap();
    let err = enc.text("aa").unwrap_err();
    assert_cbor(err, ErrorCode::TextLenLimitExceeded);
}

#[test]
fn item_accounting_is_per_encoder() {
    let limits = EncodeLimits {
        max_total_items: 1,
        ..EncodeLimits::unbounded()
    };
    let mut enc = Encoder::with_limits(limits).unwrap();
    enc.array(1, |arr| arr.value(&1i64)).unwrap();
    let mut next = Encoder::with_limits(limits).unwrap();
    next.array(1, |arr| arr.value(&2i64)).unwrap();
}
