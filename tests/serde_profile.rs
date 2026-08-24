#![cfg(all(feature = "std", feature = "serde", feature = "collections"))]

use sacp_cbor::profile::{MAX_SAFE_INTEGER, MIN_SAFE_INTEGER};
use sacp_cbor::serde::{
    from_canonical_bytes, from_canonical_bytes_ref, from_slice, to_vec, SerdeEncodeError,
    SerdeOptions,
};
use sacp_cbor::{
    collections::MapEntries, decode, CanonicalCbor, DecodeLimits, EncodeError, EncodeLimits,
    Encoder, ErrorCode,
};
use serde::ser::{SerializeMap, SerializeSeq, SerializeStruct};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[test]
fn serde_rejects_negative_zero() {
    let err = to_vec(&(-0.0_f64)).unwrap_err();
    assert_eq!(err.code, ErrorCode::NegativeZeroForbidden);
}

struct SwallowsSequenceError;

impl Serialize for SwallowsSequenceError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(1))?;
        let _ = sequence.serialize_element(&-0.0_f64);
        sequence.end()
    }
}

struct SwallowsStructFieldError;

impl Serialize for SwallowsStructFieldError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SwallowsStructFieldError", 1)?;
        let _ = state.serialize_field("value", &-0.0_f64);
        state.end()
    }
}

#[test]
fn serde_root_custom_serialize_cannot_hide_a_swallowed_float_error() {
    let mut encoder = Encoder::new();
    let error = SerdeOptions::strict()
        .encode(&SwallowsSequenceError, &mut encoder)
        .unwrap_err();
    assert!(matches!(
        error,
        SerdeEncodeError::Encode(EncodeError::Poisoned)
    ));
    assert!(matches!(encoder.null(), Err(EncodeError::Poisoned)));
}

struct SortedMapStartFailure;

impl Serialize for SortedMapStartFailure {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_map(Some(1 << 30))?.end()
    }
}

struct SwallowsSortedMapStartError;

impl Serialize for SwallowsSortedMapStartError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(1))?;
        let _ = sequence.serialize_element(&SortedMapStartFailure);
        sequence.end()
    }
}

#[test]
fn serde_custom_serialize_cannot_hide_sorted_map_start_preflight_error() {
    let limits = EncodeLimits {
        max_map_len: 0,
        ..EncodeLimits::unbounded()
    };
    let mut encoder = Encoder::with_limits(limits).unwrap();
    let error = SerdeOptions::sorted_maps()
        .encode(&SwallowsSortedMapStartError, &mut encoder)
        .unwrap_err();
    assert!(matches!(
        error,
        SerdeEncodeError::Encode(EncodeError::Poisoned)
    ));
    assert!(matches!(encoder.null(), Err(EncodeError::Poisoned)));
}

#[test]
fn serde_strict_struct_cannot_hide_a_swallowed_field_error() {
    let mut encoder = Encoder::new();
    let error = SerdeOptions::strict()
        .encode(&SwallowsStructFieldError, &mut encoder)
        .unwrap_err();
    assert!(matches!(
        error,
        SerdeEncodeError::Encode(EncodeError::Poisoned)
    ));
    assert!(matches!(encoder.null(), Err(EncodeError::Poisoned)));
}

#[test]
fn serde_nan_encodes_to_canonical_nan_bits() {
    let bytes = to_vec(&f64::NAN).unwrap();
    assert_eq!(bytes[0], 0xfb);
    assert_eq!(&bytes[1..], &0x7ff8_0000_0000_0000u64.to_be_bytes());
}

#[test]
fn serde_f32_accepts_infinities() {
    let pos_inf = [0xfb, 0x7f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let neg_inf = [0xfb, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let v_pos: f32 = from_slice(&pos_inf, DecodeLimits::for_bytes(pos_inf.len())).unwrap();
    assert!(v_pos.is_infinite() && v_pos.is_sign_positive());

    let v_neg: f32 = from_slice(&neg_inf, DecodeLimits::for_bytes(neg_inf.len())).unwrap();
    assert!(v_neg.is_infinite() && v_neg.is_sign_negative());
}

#[test]
fn serde_rejects_non_text_map_keys() {
    let mut m = BTreeMap::new();
    m.insert(1u8, 2u8);

    let err = to_vec(&m).unwrap_err();
    assert_eq!(err.code, ErrorCode::MapKeyMustBeText);
    assert_eq!(err.offset, 1);
}

#[test]
fn serde_to_vec_rejects_btreemap_noncanonical_order() {
    let mut m = BTreeMap::new();
    m.insert("aa".to_string(), true);
    m.insert("b".to_string(), false);

    let err = to_vec(&m).unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalMapOrder);
    assert!(err.offset > 0);
}

#[test]
fn serde_options_sorted_maps_accepts_btreemap_and_is_canonical() {
    let mut m = BTreeMap::new();
    m.insert("aa".to_string(), true);
    m.insert("b".to_string(), false);

    let bytes = SerdeOptions::sorted_maps().to_vec(&m).unwrap();
    let decoded: MapEntries<String, bool> =
        decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(
        decoded.0,
        vec![("b".to_string(), false), ("aa".to_string(), true)]
    );
}

#[test]
fn serde_options_sorted_maps_accepts_hashmap_and_is_canonical() {
    let mut m = std::collections::HashMap::new();
    m.insert("aa".to_string(), true);
    m.insert("b".to_string(), false);

    let bytes = SerdeOptions::sorted_maps().to_vec(&m).unwrap();
    let decoded: MapEntries<String, bool> =
        decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(
        decoded.0,
        vec![("b".to_string(), false), ("aa".to_string(), true)]
    );
}

#[derive(Serialize)]
struct NonCanonicalStructOrder {
    longer: u8,
    x: u8,
}

#[test]
fn serde_strict_struct_rejects_noncanonical_declaration_order() {
    let value = NonCanonicalStructOrder { longer: 1, x: 2 };
    let error = SerdeOptions::strict().to_vec(&value).unwrap_err();
    assert_eq!(error.code, ErrorCode::NonCanonicalMapOrder);
}

#[test]
fn serde_sorted_struct_explicitly_repairs_noncanonical_declaration_order() {
    let value = NonCanonicalStructOrder { longer: 1, x: 2 };
    let bytes = SerdeOptions::sorted_maps().to_vec(&value).unwrap();
    assert_eq!(bytes[0], 0xa2);
    assert_eq!(&bytes[1..4], &[0x61, b'x', 0x02]);
}

struct HugeMapHint;

impl Serialize for HugeMapHint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_map(Some(1 << 30))?.end()
    }
}

fn serde_cbor_code<E>(error: SerdeEncodeError<E>) -> ErrorCode {
    match error {
        SerdeEncodeError::Encode(EncodeError::Cbor(error)) => error.code,
        SerdeEncodeError::Encode(EncodeError::Sink(_) | EncodeError::Poisoned) => {
            panic!("expected canonical-profile error")
        }
    }
}

#[test]
fn serde_sorted_map_preflights_size_hint_before_entry_allocation() {
    let limits = EncodeLimits {
        max_map_len: 0,
        ..EncodeLimits::unbounded()
    };
    let mut encoder = Encoder::with_limits(limits).unwrap();
    let error = SerdeOptions::sorted_maps()
        .encode(&HugeMapHint, &mut encoder)
        .unwrap_err();
    assert_eq!(serde_cbor_code(error), ErrorCode::MapLenLimitExceeded);
    assert!(encoder.is_empty());
    assert!(matches!(encoder.finish(), Err(EncodeError::Poisoned)));
}

#[test]
fn serde_sorted_map_preflights_wire_lower_bound_before_entry_allocation() {
    let limits = EncodeLimits {
        // The five-byte map header fits exactly; only the checked two-byte-per-pair
        // wire lower bound makes this declaration impossible.
        max_output_bytes: 5,
        ..EncodeLimits::unbounded()
    };
    let mut encoder = Encoder::with_limits(limits).unwrap();
    let error = SerdeOptions::sorted_maps()
        .encode(&HugeMapHint, &mut encoder)
        .unwrap_err();
    assert_eq!(serde_cbor_code(error), ErrorCode::MessageLenLimitExceeded);
    assert!(encoder.is_empty());
    assert!(matches!(encoder.finish(), Err(EncodeError::Poisoned)));
}

struct SwallowsStrictFieldKeyLimit;

impl Serialize for SwallowsStrictFieldKeyLimit {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SwallowsStrictFieldKeyLimit", 1)?;
        let _ = state.serialize_field("too-long", &0_u8);
        state.serialize_field("a", &1_u8)?;
        state.end()
    }
}

#[test]
fn serde_strict_struct_cannot_hide_a_swallowed_key_limit_error() {
    let limits = EncodeLimits {
        max_text_len: 1,
        ..EncodeLimits::unbounded()
    };
    let mut encoder = Encoder::with_limits(limits).unwrap();
    let error = SerdeOptions::strict()
        .encode(&SwallowsStrictFieldKeyLimit, &mut encoder)
        .unwrap_err();
    assert!(matches!(
        error,
        SerdeEncodeError::Encode(EncodeError::Poisoned)
    ));
    assert_eq!(encoder.as_bytes(), [0xa1]);
}

#[test]
fn serde_sorted_map_applies_remaining_output_to_buffered_values() {
    let mut values = BTreeMap::new();
    values.insert("a", vec![0_u8; 1024]);
    let limits = EncodeLimits {
        max_output_bytes: 8,
        ..EncodeLimits::unbounded()
    };
    let mut encoder = Encoder::with_limits(limits).unwrap();
    let error = SerdeOptions::sorted_maps()
        .encode(&values, &mut encoder)
        .unwrap_err();
    assert_eq!(serde_cbor_code(error), ErrorCode::MessageLenLimitExceeded);
    assert!(encoder.is_empty());
}

#[test]
fn serde_sorted_map_items_are_cumulative_across_buffered_values() {
    let mut values = BTreeMap::new();
    values.insert("a", vec![1_u8]);
    values.insert("b", vec![2_u8]);
    let limits = EncodeLimits {
        max_total_items: 5,
        ..EncodeLimits::unbounded()
    };
    let mut encoder = Encoder::with_limits(limits).unwrap();
    let error = SerdeOptions::sorted_maps()
        .encode(&values, &mut encoder)
        .unwrap_err();
    assert_eq!(serde_cbor_code(error), ErrorCode::TotalItemsLimitExceeded);
    assert!(encoder.is_empty());
}

#[test]
fn serde_sorted_map_values_inherit_outer_container_depth() {
    let mut values = BTreeMap::new();
    values.insert("a", vec![1_u8]);
    let limits = EncodeLimits {
        max_depth: 1,
        ..EncodeLimits::unbounded()
    };
    let mut encoder = Encoder::with_limits(limits).unwrap();
    let error = SerdeOptions::sorted_maps()
        .encode(&values, &mut encoder)
        .unwrap_err();
    assert_eq!(serde_cbor_code(error), ErrorCode::DepthLimitExceeded);
    assert!(encoder.is_empty());
}

#[test]
fn serde_sorted_buffer_errors_use_the_current_outer_output_offset() {
    let mut values = BTreeMap::new();
    values.insert("a", -0.0_f64);
    let error = SerdeOptions::sorted_maps().to_vec(&(values,)).unwrap_err();
    assert_eq!(error.code, ErrorCode::NegativeZeroForbidden);
    assert_eq!(error.offset, 1);
}

#[derive(Serialize)]
struct SortedOversizedKey {
    oversized: u8,
}

#[test]
fn serde_sorted_struct_key_limit_uses_current_outer_output_offset() {
    let limits = EncodeLimits {
        max_text_len: 1,
        ..EncodeLimits::unbounded()
    };
    let mut encoder = Encoder::with_limits(limits).unwrap();
    let error = SerdeOptions::sorted_maps()
        .encode(&(SortedOversizedKey { oversized: 1 },), &mut encoder)
        .unwrap_err();
    match error {
        SerdeEncodeError::Encode(EncodeError::Cbor(error)) => {
            assert_eq!(error.code, ErrorCode::TextLenLimitExceeded);
            assert_eq!(error.offset, 1);
        }
        _ => panic!("expected canonical-profile error"),
    }
}

#[test]
fn serde_large_u64_becomes_bignum() {
    let v: u64 = MAX_SAFE_INTEGER + 1;
    let bytes = to_vec(&v).unwrap();
    assert_eq!(bytes[0], 0xc2); // tag 2
    assert_eq!(bytes[1], 0x47); // length 7
    assert_eq!(&bytes[2..], &[0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn serde_large_negative_i128_becomes_bignum() {
    let v: i128 = i128::from(MIN_SAFE_INTEGER) - 1;
    let bytes = to_vec(&v).unwrap();
    assert_eq!(bytes[0], 0xc3); // tag 3
    assert_eq!(bytes[1], 0x47); // length 7
    assert_eq!(&bytes[2..], &[0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Msg {
    n: u64,
    op: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum Simple {
    Ready,
    Count(u64),
}

#[test]
fn serde_roundtrip_struct_and_enum() {
    let m = Msg {
        n: 42,
        op: "ping".to_string(),
    };

    let bytes = to_vec(&m).unwrap();
    let decoded: Msg = from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, m);

    let s = Simple::Count(7);
    let bytes = to_vec(&s).unwrap();
    let decoded: Simple = from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn serde_roundtrip_vec_and_injective_option() {
    let tags = vec!["x".to_string(), "y".to_string()];
    let bytes = to_vec(&tags).unwrap();
    let decoded: Vec<String> = from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, tags);

    let opt = Some(3u8);
    let bytes = to_vec(&opt).unwrap();
    let decoded: Option<u8> = from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, opt);

    let some_unit = Some(());
    let some_bytes = to_vec(&some_unit).unwrap();
    let none_unit: Option<()> = None;
    let none_bytes = to_vec(&none_unit).unwrap();
    assert_ne!(some_bytes, none_bytes);

    let decoded_some: Option<()> =
        from_slice(&some_bytes, DecodeLimits::for_bytes(some_bytes.len())).unwrap();
    let decoded_none: Option<()> =
        from_slice(&none_bytes, DecodeLimits::for_bytes(none_bytes.len())).unwrap();
    assert_eq!(decoded_some, some_unit);
    assert_eq!(decoded_none, none_unit);

    let nested_some = Some(Some(()));
    let nested_none = Some(None::<()>);
    let nested_some_bytes = to_vec(&nested_some).unwrap();
    let nested_none_bytes = to_vec(&nested_none).unwrap();
    assert_ne!(nested_some_bytes, nested_none_bytes);

    let decoded_nested_some: Option<Option<()>> = from_slice(
        &nested_some_bytes,
        DecodeLimits::for_bytes(nested_some_bytes.len()),
    )
    .unwrap();
    let decoded_nested_none: Option<Option<()>> = from_slice(
        &nested_none_bytes,
        DecodeLimits::for_bytes(nested_none_bytes.len()),
    )
    .unwrap();
    assert_eq!(decoded_nested_some, nested_some);
    assert_eq!(decoded_nested_none, nested_none);
}

struct OverlongSeq;

impl Serialize for OverlongSeq {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(1))?;
        seq.serialize_element(&1u8)?;
        seq.serialize_element(&2u8)?;
        seq.end()
    }
}

#[test]
fn serde_rejects_custom_serialize_that_overfills_sequence() {
    let err = to_vec(&OverlongSeq).unwrap_err();
    assert_eq!(err.code, ErrorCode::ArrayLenMismatch);
}

struct IndefiniteSeq;

impl Serialize for IndefiniteSeq {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&1u8)?;
        seq.end()
    }
}

struct ByteString<'a>(&'a [u8]);

impl Serialize for ByteString<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ByteBuf(Vec<u8>);

impl<'de> Deserialize<'de> for ByteBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;

        impl<'de> serde::de::Visitor<'de> for V {
            type Value = ByteBuf;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a byte buffer")
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ByteBuf(v))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ByteBuf(v.to_vec()))
            }
        }

        deserializer.deserialize_byte_buf(V)
    }
}

#[test]
fn serde_rejects_indefinite_sequences() {
    let err = to_vec(&IndefiniteSeq).unwrap_err();
    assert_eq!(err.code, ErrorCode::IndefiniteLengthForbidden);
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
enum Shape {
    Unit,
    Newtype(u8),
    Tuple(u8, bool),
    Struct { x: u8, y: bool },
}

#[test]
fn serde_roundtrips_all_enum_variant_shapes() {
    let values = [
        Shape::Unit,
        Shape::Newtype(7),
        Shape::Tuple(1, true),
        Shape::Struct { x: 2, y: false },
    ];

    for value in values {
        let bytes = to_vec(&value).unwrap();
        let decoded: Shape = from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
        assert_eq!(decoded, value);
    }
}

#[test]
fn serde_decodes_primitives_and_canonical_wrappers() {
    assert_eq!(to_vec(&true).unwrap(), vec![0xf5]);
    assert_eq!(to_vec(&-1i8).unwrap(), vec![0x20]);
    assert_eq!(to_vec(&24u16).unwrap(), vec![0x18, 0x18]);
    assert_eq!(to_vec(&'x').unwrap(), vec![0x61, b'x']);
    assert_eq!(to_vec(&ByteString(b"xy")).unwrap(), vec![0x42, b'x', b'y']);

    let n: i8 = from_slice(&[0x20], DecodeLimits::for_bytes(1)).unwrap();
    assert_eq!(n, -1);
    let ch: char = from_slice(&[0x61, b'x'], DecodeLimits::for_bytes(2)).unwrap();
    assert_eq!(ch, 'x');
    let buf: ByteBuf = from_slice(&[0x42, 1, 2], DecodeLimits::for_bytes(3)).unwrap();
    assert_eq!(buf, ByteBuf(vec![1, 2]));

    let err = from_slice::<char>(&[0x62, b'x', b'y'], DecodeLimits::for_bytes(3)).unwrap_err();
    assert_eq!(err.code, ErrorCode::ExpectedText);

    let canon = CanonicalCbor::from_slice(&[0x01], DecodeLimits::for_bytes(1)).unwrap();
    let owned: u8 = from_canonical_bytes(&canon).unwrap();
    let borrowed: u8 = from_canonical_bytes_ref(canon.as_canonical_ref()).unwrap();
    assert_eq!((owned, borrowed), (1, 1));

    let json = serde_json::to_value(&canon).unwrap();
    assert_eq!(json, serde_json::json!([1]));

    let wrapped: CanonicalCbor = from_slice(&[0x41, 0x01], DecodeLimits::for_bytes(2)).unwrap();
    assert_eq!(wrapped.as_bytes(), &[0x01]);

    let err = from_slice::<CanonicalCbor>(&[0x41, 0x18], DecodeLimits::for_bytes(2)).unwrap_err();
    assert_eq!(err.code, ErrorCode::SerdeError);
}

#[derive(Debug, Deserialize, PartialEq)]
struct BorrowedSerde<'a> {
    name: &'a str,
    #[serde(borrow)]
    payload: &'a [u8],
}

#[test]
fn serde_deserializes_borrowed_fields() {
    let bytes = [
        0xa2, 0x64, b'n', b'a', b'm', b'e', 0x63, b'a', b'n', b'a', 0x67, b'p', b'a', b'y', b'l',
        b'o', b'a', b'd', 0x42, b'x', b'y',
    ];
    let decoded: BorrowedSerde<'_> =
        from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded.name, "ana");
    assert_eq!(decoded.payload, b"xy");
}
