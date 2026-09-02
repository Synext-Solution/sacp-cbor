#![cfg(feature = "alloc")]

use sacp_cbor::{
    validate_canonical, ByteSink, CborEncode, DecodeLimits, EncodeError, EncodeLimits,
    EncodeResult, Encoder, ErrorCode, ValueEncoder, WorkObserver,
};

#[cfg(feature = "collections")]
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "collections")]
static AS_REF_CALLS: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "collections")]
#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct ObservableKey(&'static str);

#[cfg(feature = "collections")]
impl AsRef<str> for ObservableKey {
    fn as_ref(&self) -> &str {
        AS_REF_CALLS.fetch_add(1, Ordering::Relaxed);
        self.0
    }
}

#[cfg(all(feature = "collections", feature = "std"))]
#[derive(Eq, Hash, PartialEq)]
struct AliasedKey {
    identity: u8,
    text: &'static str,
}

#[cfg(all(feature = "collections", feature = "std"))]
impl AsRef<str> for AliasedKey {
    fn as_ref(&self) -> &str {
        self.text
    }
}

fn assert_cbor<E>(error: EncodeError<E>, code: ErrorCode) {
    assert!(matches!(error, EncodeError::Cbor(error) if error.code == code));
}

#[derive(Debug, PartialEq, Eq)]
enum ProjectionError {
    Encode(EncodeError<sacp_cbor::CborError>),
    Refused,
}

impl From<EncodeError<sacp_cbor::CborError>> for ProjectionError {
    fn from(error: EncodeError<sacp_cbor::CborError>) -> Self {
        Self::Encode(error)
    }
}

struct EncodeZero;

impl CborEncode for EncodeZero {
    fn encode<S: ByteSink, O: WorkObserver>(
        &self,
        _enc: &mut ValueEncoder<'_, S, O>,
    ) -> EncodeResult<(), S> {
        Ok(())
    }
}

struct EncodeTwo;

impl CborEncode for EncodeTwo {
    fn encode<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> EncodeResult<(), S> {
        enc.null()?;
        enc.null()
    }
}

struct EncodeFailure;

impl CborEncode for EncodeFailure {
    fn encode<S: ByteSink, O: WorkObserver>(
        &self,
        _enc: &mut ValueEncoder<'_, S, O>,
    ) -> EncodeResult<(), S> {
        Err(sacp_cbor::CborError::new(ErrorCode::PatchConflict, 0).into())
    }
}

struct SwallowsInnerError;

impl CborEncode for SwallowsInnerError {
    fn encode<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> EncodeResult<(), S> {
        enc.null()?;
        let _ = enc.null();
        Ok(())
    }
}

struct NestedArray(usize);

impl CborEncode for NestedArray {
    fn encode<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> EncodeResult<(), S> {
        if self.0 == 0 {
            enc.null()
        } else {
            enc.array(1, |array| array.value(&Self(self.0 - 1)))
        }
    }
}

#[test]
fn empty_encoder_finish_is_error() {
    let err = Encoder::new().finish().unwrap_err();
    assert_cbor(err, ErrorCode::UnexpectedEof);
}

#[test]
fn second_root_value_is_error() {
    let mut enc = Encoder::new();
    enc.null().unwrap();
    let err = enc.null().unwrap_err();
    assert_cbor(err, ErrorCode::TrailingBytes);
    assert!(matches!(enc.finish(), Err(EncodeError::Poisoned)));
}

#[test]
fn direct_trait_error_is_observed_and_poisoned() {
    let mut enc = Encoder::new();
    let err = enc.encode(&EncodeFailure).unwrap_err();
    assert_cbor(err, ErrorCode::PatchConflict);
    assert!(matches!(enc.null(), Err(EncodeError::Poisoned)));
    assert!(matches!(enc.finish(), Err(EncodeError::Poisoned)));
}

#[test]
fn trait_conversion_error_before_output_is_observed_and_poisoned() {
    let mut enc = Encoder::new();
    let err = enc.encode(&-0.0_f64).unwrap_err();
    assert_cbor(err, ErrorCode::NegativeZeroForbidden);
    assert!(enc.is_empty());
    assert!(matches!(enc.null(), Err(EncodeError::Poisoned)));
    assert!(matches!(enc.finish(), Err(EncodeError::Poisoned)));
}

#[test]
fn trait_cannot_hide_a_swallowed_inner_error() {
    let mut enc = Encoder::new();
    assert!(matches!(
        enc.encode(&SwallowsInnerError),
        Err(EncodeError::Poisoned)
    ));
    assert!(matches!(enc.finish(), Err(EncodeError::Poisoned)));
}

#[test]
fn controlled_value_callback_cannot_hide_a_swallowed_inner_error() {
    let mut enc = Encoder::new();
    let error = enc
        .encode_with(|value| {
            value.null()?;
            let _ = value.null();
            Ok(())
        })
        .unwrap_err();
    assert!(matches!(error, EncodeError::Poisoned));
}

#[test]
fn encoder_migrates_beyond_the_inline_frame_stack() {
    let depth = 40usize;
    let limits = EncodeLimits {
        max_depth: depth,
        max_total_items: depth + 1,
        ..EncodeLimits::unbounded()
    };
    let mut encoder = Encoder::with_limits(limits).unwrap();
    encoder.encode(&NestedArray(depth)).unwrap();
    let bytes = encoder.finish().unwrap();

    let mut decode_limits = DecodeLimits::for_bytes(bytes.len());
    decode_limits.max_depth = depth;
    decode_limits.max_total_items = depth + 1;
    validate_canonical(&bytes, decode_limits).unwrap();
}

#[test]
fn caller_error_is_preserved_after_output_and_poisons_the_encoder() {
    let mut encoder = Encoder::new();
    let error = encoder
        .encode_with_caller_error(|value| {
            value.null()?;
            Err(ProjectionError::Refused)
        })
        .unwrap_err();

    assert_eq!(error, ProjectionError::Refused);
    assert_eq!(encoder.as_bytes(), [0xf6]);
    assert!(matches!(encoder.null(), Err(EncodeError::Poisoned)));
    assert!(matches!(encoder.finish(), Err(EncodeError::Poisoned)));
}

#[test]
fn caller_error_array_underfill_is_typed_and_sticky() {
    let mut encoder = Encoder::new();
    let error: ProjectionError = encoder
        .array_with_caller_error(2, |array| {
            array.null()?;
            Ok(())
        })
        .unwrap_err();

    assert!(matches!(
        error,
        ProjectionError::Encode(EncodeError::Cbor(error))
            if error.code == ErrorCode::ArrayLenMismatch
    ));
    assert_eq!(encoder.as_bytes(), [0x82, 0xf6]);
    assert!(matches!(encoder.finish(), Err(EncodeError::Poisoned)));
}

#[test]
fn impossible_array_length_fails_before_output_or_projection() {
    let mut encoder = Encoder::new();
    let mut projected = false;
    let error = encoder
        .array(usize::MAX, |_array| {
            projected = true;
            Ok(())
        })
        .unwrap_err();

    assert_cbor(error, ErrorCode::LengthOverflow);
    assert!(!projected);
    assert!(encoder.is_empty());
    assert!(matches!(encoder.finish(), Err(EncodeError::Poisoned)));
}

#[test]
fn array_build_callback_cannot_hide_a_swallowed_inner_error() {
    let mut enc = Encoder::new();
    let error = enc
        .array(1, |array| {
            array.null()?;
            let _ = array.null();
            Ok(())
        })
        .unwrap_err();
    assert!(matches!(error, EncodeError::Poisoned));
}

#[test]
fn array_value_callback_cannot_hide_a_swallowed_inner_error() {
    let mut enc = Encoder::new();
    let error = enc
        .array(1, |array| {
            array.value_with(|value| {
                value.null()?;
                let _ = value.null();
                Ok(())
            })
        })
        .unwrap_err();
    assert!(matches!(error, EncodeError::Poisoned));
}

#[test]
fn map_build_callback_cannot_hide_a_swallowed_inner_error() {
    let mut enc = Encoder::new();
    let error = enc
        .map(1, |map| {
            map.entry("a", Encoder::null)?;
            let _ = map.entry("b", Encoder::null);
            Ok(())
        })
        .unwrap_err();
    assert!(matches!(error, EncodeError::Poisoned));
}

#[test]
fn map_value_callback_cannot_hide_a_swallowed_inner_error() {
    let mut enc = Encoder::new();
    let error = enc
        .map(1, |map| {
            map.entry("a", |value| {
                value.null()?;
                let _ = value.null();
                Ok(())
            })
        })
        .unwrap_err();
    assert!(matches!(error, EncodeError::Poisoned));
}

#[test]
fn map_entry_callback_emits_zero_values_is_error() {
    let mut enc = Encoder::new();
    let err = enc.map(1, |m| m.entry("a", |_enc| Ok(()))).unwrap_err();
    assert_cbor(err, ErrorCode::MapLenMismatch);
    assert_eq!(enc.as_bytes(), [0xa1, 0x61, b'a']);
    assert!(matches!(enc.null(), Err(EncodeError::Poisoned)));
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
    assert_cbor(err, ErrorCode::MapLenMismatch);
    assert!(matches!(enc.null(), Err(EncodeError::Poisoned)));
}

#[test]
fn duplicate_map_key_is_rejected_before_offending_key_bytes() {
    let mut enc = Encoder::new();
    let err = enc
        .map(2, |map| {
            map.entry("a", |entry| entry.null())?;
            map.entry("a", |entry| entry.null())
        })
        .unwrap_err();
    assert_cbor(err, ErrorCode::DuplicateMapKey);
    assert_eq!(enc.as_bytes(), [0xa2, 0x61, b'a', 0xf6]);
    assert!(matches!(enc.null(), Err(EncodeError::Poisoned)));
}

#[test]
fn out_of_order_map_key_is_rejected_before_offending_key_bytes() {
    let mut enc = Encoder::new();
    let err = enc
        .map(2, |map| {
            map.entry("bb", |entry| entry.null())?;
            map.entry("a", |entry| entry.null())
        })
        .unwrap_err();
    assert_cbor(err, ErrorCode::NonCanonicalMapOrder);
    assert_eq!(enc.as_bytes(), [0xa2, 0x62, b'b', b'b', 0xf6]);
    assert!(matches!(enc.null(), Err(EncodeError::Poisoned)));
}

#[test]
fn array_value_custom_encode_emits_zero_values_is_error() {
    let mut enc = Encoder::new();
    let err = enc.array(1, |a| a.value(&EncodeZero)).unwrap_err();
    assert_cbor(err, ErrorCode::MalformedCanonical);
    assert_eq!(enc.as_bytes(), [0x81]);
    assert!(matches!(enc.null(), Err(EncodeError::Poisoned)));
}

#[test]
fn array_value_custom_encode_emits_two_values_is_error() {
    let mut enc = Encoder::new();
    let err = enc.array(2, |a| a.value(&EncodeTwo)).unwrap_err();
    assert_cbor(err, ErrorCode::MalformedCanonical);
    assert_eq!(enc.as_bytes(), [0x82, 0xf6, 0xf6]);
    assert!(matches!(enc.null(), Err(EncodeError::Poisoned)));
}

#[test]
fn array_scalar_error_poison_is_sticky() {
    let limits = EncodeLimits {
        max_output_bytes: 3,
        ..EncodeLimits::unbounded()
    };
    let mut enc = Encoder::with_limits(limits).unwrap();
    let err = enc.array(1, |a| a.text("aa")).unwrap_err();
    assert_cbor(err, ErrorCode::MessageLenLimitExceeded);
    assert_eq!(enc.as_bytes(), [0x81]);
    assert!(matches!(enc.null(), Err(EncodeError::Poisoned)));
}

#[test]
fn raw_value_output_limit_is_checked_before_canonical_walk() {
    let bytes = [0x81, 0x81, 0x81, 0xf6];
    let value = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let limits = EncodeLimits {
        max_output_bytes: 0,
        max_depth: 0,
        ..EncodeLimits::unbounded()
    };
    let mut encoder = Encoder::with_limits(limits).unwrap();
    let error = encoder.raw_value_ref(value.root()).unwrap_err();
    assert_cbor(error, ErrorCode::MessageLenLimitExceeded);
}

#[test]
fn raw_value_slot_is_checked_before_canonical_walk() {
    let bytes = [0x81, 0x81, 0x81, 0xf6];
    let value = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let limits = EncodeLimits {
        max_depth: 0,
        ..EncodeLimits::unbounded()
    };
    let mut encoder = Encoder::with_limits(limits).unwrap();
    encoder.null().unwrap();
    let error = encoder.raw_value_ref(value.root()).unwrap_err();
    assert_cbor(error, ErrorCode::TrailingBytes);
}

#[cfg(feature = "collections")]
#[test]
fn native_sorted_map_preflights_limits_before_sorting_or_key_projection() {
    let mut map = std::collections::BTreeMap::new();
    map.insert(ObservableKey("a"), 1_u8);
    AS_REF_CALLS.store(0, Ordering::Relaxed);
    let limits = EncodeLimits {
        max_map_len: 0,
        ..EncodeLimits::unbounded()
    };
    let mut encoder = Encoder::with_limits(limits).unwrap();
    let error = encoder.encode(&map).unwrap_err();
    assert_cbor(error, ErrorCode::MapLenLimitExceeded);
    assert_eq!(AS_REF_CALLS.load(Ordering::Relaxed), 0);
    assert!(matches!(encoder.finish(), Err(EncodeError::Poisoned)));
}

#[cfg(feature = "collections")]
#[test]
fn native_sorted_map_preflights_wire_lower_bound_before_sorting() {
    let mut map = std::collections::BTreeMap::new();
    map.insert(ObservableKey("a"), 1_u8);
    AS_REF_CALLS.store(0, Ordering::Relaxed);
    let limits = EncodeLimits {
        max_output_bytes: 1,
        ..EncodeLimits::unbounded()
    };
    let mut encoder = Encoder::with_limits(limits).unwrap();
    let error = encoder.encode(&map).unwrap_err();
    assert_cbor(error, ErrorCode::MessageLenLimitExceeded);
    assert_eq!(AS_REF_CALLS.load(Ordering::Relaxed), 0);
    assert!(encoder.is_empty());
    assert!(matches!(encoder.finish(), Err(EncodeError::Poisoned)));
}

#[cfg(all(feature = "collections", feature = "std"))]
#[test]
fn native_map_rejects_aliased_source_keys_before_any_entry_output() {
    let mut map = std::collections::HashMap::new();
    map.insert(
        AliasedKey {
            identity: 1,
            text: "same",
        },
        1_u8,
    );
    map.insert(
        AliasedKey {
            identity: 2,
            text: "same",
        },
        2_u8,
    );
    let mut encoder = Encoder::new();
    let error = encoder.encode(&map).unwrap_err();
    assert_cbor(error, ErrorCode::DuplicateMapKey);
    assert_eq!(encoder.as_bytes(), [0xa2]);
    assert!(matches!(encoder.finish(), Err(EncodeError::Poisoned)));
}
