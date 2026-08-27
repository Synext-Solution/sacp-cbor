use sacp_cbor::bytes::{Bytes, BytesRef};
use sacp_cbor::{CanonicalCbor, CanonicalCborRef, CborError, DecodeLimits, ErrorCode};
use sacp_cbor_abi::{
    decode, AbiDecodeContext, AbiDecodeLocation, AbiDecodeValue, CborAbi, UnknownFields,
};

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "context.Name", version = 1, transparent)]
struct Name(String);

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "context.Entry", version = 1)]
enum Entry {
    #[abi(id = 1)]
    Item {
        #[abi(id = 1)]
        names: Vec<Name>,
        #[abi(id = 2)]
        blob: Bytes,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "context.Envelope", version = 1)]
struct Envelope {
    #[abi(id = 1)]
    entries: Vec<Entry>,
    #[abi(id = 2)]
    title: String,
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(
    type_id = "context.Extensible",
    version = 1,
    unknown_fields = "preserve"
)]
struct Extensible {
    #[abi(unknown_fields)]
    unknown: UnknownFields,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestError {
    Cbor(CborError),
    Budget {
        location: AbiDecodeLocation,
        value: AbiDecodeValue,
        observed: usize,
        limit: usize,
    },
}

impl From<CborError> for TestError {
    fn from(value: CborError) -> Self {
        Self::Cbor(value)
    }
}

#[derive(Default)]
struct RecordingContext {
    events: Vec<(AbiDecodeLocation, AbiDecodeValue)>,
}

impl AbiDecodeContext for RecordingContext {
    type Error = TestError;

    fn admit(
        &mut self,
        location: AbiDecodeLocation,
        value: AbiDecodeValue,
    ) -> Result<(), Self::Error> {
        self.events.push((location, value));
        Ok(())
    }
}

struct UnitBudget {
    observed: usize,
    limit: usize,
}

impl AbiDecodeContext for UnitBudget {
    type Error = TestError;

    fn admit(
        &mut self,
        location: AbiDecodeLocation,
        value: AbiDecodeValue,
    ) -> Result<(), Self::Error> {
        let add = match value {
            AbiDecodeValue::Sequence { items, .. } => items,
            AbiDecodeValue::Text { bytes, .. }
            | AbiDecodeValue::Bytes { bytes, .. }
            | AbiDecodeValue::Canonical { bytes, .. } => bytes,
            AbiDecodeValue::UnknownField { .. } | AbiDecodeValue::UnknownVariant { .. } => 1,
        };
        let observed = self.observed.saturating_add(add);
        if observed > self.limit {
            return Err(TestError::Budget {
                location,
                value,
                observed,
                limit: self.limit,
            });
        }
        self.observed = observed;
        Ok(())
    }
}

fn envelope_bytes() -> Vec<u8> {
    sacp_cbor_abi::encode_to_vec(&Envelope {
        entries: vec![Entry::Item {
            names: vec![Name("a".to_owned()), Name("bc".to_owned())],
            blob: Bytes::new(vec![1, 2, 3]),
        }],
        title: "root".to_owned(),
    })
    .unwrap()
}

#[test]
fn one_context_observes_only_semantic_owned_values_in_recursive_order() {
    let bytes = envelope_bytes();
    let mut context = RecordingContext::default();
    let decoded: Envelope =
        decode(&bytes, DecodeLimits::for_bytes(bytes.len()), &mut context).unwrap();

    assert_eq!(decoded.entries.len(), 1);
    assert_eq!(decoded.title, "root");
    assert_eq!(
        context.events,
        vec![
            (
                AbiDecodeLocation::Field {
                    type_id: "context.Envelope",
                    variant_id: None,
                    field_id: 1,
                },
                AbiDecodeValue::Sequence {
                    offset: 2,
                    items: 1,
                },
            ),
            (
                AbiDecodeLocation::Field {
                    type_id: "context.Entry",
                    variant_id: Some(1),
                    field_id: 1,
                },
                AbiDecodeValue::Sequence {
                    offset: 7,
                    items: 2,
                },
            ),
            (
                AbiDecodeLocation::Field {
                    type_id: "context.Entry",
                    variant_id: Some(1),
                    field_id: 1,
                },
                AbiDecodeValue::Text {
                    offset: 8,
                    bytes: 1,
                },
            ),
            (
                AbiDecodeLocation::Field {
                    type_id: "context.Entry",
                    variant_id: Some(1),
                    field_id: 1,
                },
                AbiDecodeValue::Text {
                    offset: 10,
                    bytes: 2,
                },
            ),
            (
                AbiDecodeLocation::Field {
                    type_id: "context.Entry",
                    variant_id: Some(1),
                    field_id: 2,
                },
                AbiDecodeValue::Bytes {
                    offset: 14,
                    bytes: 3,
                },
            ),
            (
                AbiDecodeLocation::Field {
                    type_id: "context.Envelope",
                    variant_id: None,
                    field_id: 2,
                },
                AbiDecodeValue::Text {
                    offset: 19,
                    bytes: 4,
                },
            ),
        ]
    );
}

#[test]
fn cumulative_budget_accepts_exact_n_and_rejects_n_minus_one_with_typed_boundary() {
    let bytes = envelope_bytes();
    let mut exact = UnitBudget {
        observed: 0,
        limit: 13,
    };
    let _: Envelope = decode(&bytes, DecodeLimits::for_bytes(bytes.len()), &mut exact).unwrap();
    assert_eq!(exact.observed, 13);

    let mut short = UnitBudget {
        observed: 0,
        limit: 12,
    };
    let error = decode::<Envelope, _>(&bytes, DecodeLimits::for_bytes(bytes.len()), &mut short)
        .unwrap_err();
    assert_eq!(
        error,
        TestError::Budget {
            location: AbiDecodeLocation::Field {
                type_id: "context.Envelope",
                variant_id: None,
                field_id: 2,
            },
            value: AbiDecodeValue::Text {
                offset: 19,
                bytes: 4,
            },
            observed: 13,
            limit: 12,
        }
    );
}

#[test]
fn grammar_and_core_limits_refuse_before_context_but_truncation_follows_header_admission() {
    let mut context = RecordingContext::default();
    let error =
        decode::<Vec<u8>, _>(&[0x98, 0x00], DecodeLimits::for_bytes(2), &mut context).unwrap_err();
    assert_eq!(
        error,
        TestError::Cbor(CborError::new(ErrorCode::NonCanonicalEncoding, 0))
    );
    assert!(context.events.is_empty());

    let mut limits = DecodeLimits::for_bytes(3);
    limits.max_text_len = 1;
    let error = decode::<String, _>(&[0x62, b'a', b'b'], limits, &mut context).unwrap_err();
    assert_eq!(
        error,
        TestError::Cbor(CborError::new(ErrorCode::TextLenLimitExceeded, 0))
    );
    assert!(context.events.is_empty());

    let error =
        decode::<String, _>(&[0x62, b'a'], DecodeLimits::for_bytes(2), &mut context).unwrap_err();
    assert_eq!(
        error,
        TestError::Cbor(CborError::new(ErrorCode::UnexpectedEof, 1))
    );
    assert_eq!(
        context.events,
        vec![(
            AbiDecodeLocation::Root,
            AbiDecodeValue::Text {
                offset: 0,
                bytes: 2,
            },
        )]
    );
}

#[test]
fn borrowed_values_do_not_consume_owned_admission_budget() {
    let text = [0x61, b'x'];
    let mut context = RecordingContext::default();
    let decoded: &str = decode(&text, DecodeLimits::for_bytes(text.len()), &mut context).unwrap();
    assert_eq!(decoded.as_ptr(), text[1..].as_ptr());

    let bytes = [0x42, 1, 2];
    let decoded: BytesRef<'_> =
        decode(&bytes, DecodeLimits::for_bytes(bytes.len()), &mut context).unwrap();
    assert_eq!(decoded.as_slice().as_ptr(), bytes[1..].as_ptr());

    let canonical = CanonicalCbor::from_slice(&[0x01], DecodeLimits::for_bytes(1)).unwrap();
    let decoded: CanonicalCborRef<'_> = decode(
        canonical.as_bytes(),
        DecodeLimits::for_bytes(1),
        &mut context,
    )
    .unwrap();
    assert_eq!(decoded.as_bytes().as_ptr(), canonical.as_bytes().as_ptr());
    assert!(context.events.is_empty());
}

#[test]
fn preserved_unknowns_are_admitted_by_actual_count_before_payload_ownership() {
    let bytes = [0x82, 0x09, 0xf6];
    let mut context = RecordingContext::default();
    let decoded: Extensible =
        decode(&bytes, DecodeLimits::for_bytes(bytes.len()), &mut context).unwrap();
    assert_eq!(decoded.unknown.len(), 1);
    assert_eq!(
        context.events,
        vec![
            (
                AbiDecodeLocation::UnknownField {
                    type_id: "context.Extensible",
                    variant_id: None,
                    field_id: 9,
                },
                AbiDecodeValue::UnknownField { offset: 1 },
            ),
            (
                AbiDecodeLocation::UnknownField {
                    type_id: "context.Extensible",
                    variant_id: None,
                    field_id: 9,
                },
                AbiDecodeValue::Canonical {
                    offset: 2,
                    bytes: 1,
                },
            ),
        ]
    );
}
