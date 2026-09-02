use std::cell::RefCell;
use std::rc::Rc;

use sacp_cbor::{
    CanonicalCbor, DecodeLimits, EncodeLimits, Encoder, ErrorCode, WorkCancelled, WorkObserver,
    WorkSession, WORK_CHECKPOINT_INTERVAL,
};
use sacp_cbor_abi::{encode_to_vec, AbiViewField, CborAbi};

const ARRAY_ITEMS: usize = 5_000;
const LAZY_ITEMS: usize = 3_000;
const NESTED_TERMINALS: usize = 1_300;

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "tests.ManifestViewWork", version = 1)]
struct Manifest {
    #[abi(id = 1)]
    first: Vec<u64>,
    #[abi(id = 2)]
    second: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(
    type_id = "tests.OpenManifestViewWork",
    version = 1,
    unknown_fields = "ignore"
)]
struct OpenManifest {
    #[abi(id = 1, optional)]
    anchor: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "tests.RecoverySyncSetViewWork", version = 1)]
struct RecoverySyncSet {
    #[abi(id = 1)]
    terminals: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "tests.RecoveryManifestViewWork", version = 1)]
struct RecoveryManifest {
    #[abi(id = 1)]
    sync_sets: Vec<RecoverySyncSet>,
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "tests.TransparentManifestInnerViewWork", version = 1)]
struct TransparentManifestInner {
    #[abi(id = 1)]
    items: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(
    type_id = "tests.TransparentManifestViewWork",
    version = 1,
    transparent
)]
struct TransparentManifest(TransparentManifestInner);

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "tests.ObservedEnumViewWork", version = 1)]
enum ObservedEnum {
    #[abi(id = 1)]
    Empty,
    #[abi(id = 2)]
    Payload {
        #[abi(id = 1)]
        items: Vec<u64>,
    },
}

#[derive(Clone)]
struct TraceObserver {
    calls: Rc<RefCell<Vec<usize>>>,
    cancel_on_call: Option<usize>,
}

impl TraceObserver {
    fn recording() -> (Self, Rc<RefCell<Vec<usize>>>) {
        let calls = Rc::new(RefCell::new(Vec::new()));
        (
            Self {
                calls: Rc::clone(&calls),
                cancel_on_call: None,
            },
            calls,
        )
    }

    fn cancel_on_second() -> (Self, Rc<RefCell<Vec<usize>>>) {
        let (mut observer, calls) = Self::recording();
        observer.cancel_on_call = Some(2);
        (observer, calls)
    }
}

impl WorkObserver for TraceObserver {
    fn checkpoint(&mut self, completed_units: usize) -> Result<(), WorkCancelled> {
        let mut calls = self.calls.borrow_mut();
        calls.push(completed_units);
        if self.cancel_on_call == Some(calls.len()) {
            Err(WorkCancelled)
        } else {
            Ok(())
        }
    }
}

fn canonical_manifest(first: usize, second: usize) -> CanonicalCbor {
    let value = Manifest {
        first: (0..first as u64).collect(),
        second: (10_000..10_000 + second as u64).collect(),
    };
    let bytes = encode_to_vec(&value, EncodeLimits::for_bytes(1 << 20)).unwrap();
    CanonicalCbor::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap()
}

#[test]
fn generated_manifest_record_scan_cancels_inside_huge_nested_array() {
    let canonical = canonical_manifest(ARRAY_ITEMS, 8);
    let ordinary = ManifestView::from_canonical(canonical.as_canonical_ref()).unwrap();
    let first_raw = ordinary.first_raw().unwrap();
    let (observer, calls) = TraceObserver::cancel_on_second();
    let mut session = WorkSession::new(observer).unwrap();
    let error =
        ManifestView::from_canonical_with_session(canonical.as_canonical_ref(), &mut session)
            .unwrap_err();

    assert_eq!(error.code, ErrorCode::WorkCancelled);
    assert!(
        error.offset > first_raw.offset(),
        "nested boundary walk must have entered the array"
    );
    assert!(
        error.offset < first_raw.offset() + first_raw.byte_len(),
        "nested boundary walk must stop before the array tail"
    );
    assert_eq!(&*calls.borrow(), &[0, WORK_CHECKPOINT_INTERVAL]);
}

#[test]
fn generated_enum_payload_scan_uses_the_callers_session() {
    let value = ObservedEnum::Payload {
        items: (0..ARRAY_ITEMS as u64).collect(),
    };
    let bytes = encode_to_vec(&value, EncodeLimits::for_bytes(1 << 20)).unwrap();
    let canonical =
        CanonicalCbor::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let ordinary = ObservedEnumView::from_canonical(canonical.as_canonical_ref()).unwrap();
    let payload = ordinary.as_payload().unwrap().unwrap();
    let items = payload.items_raw().unwrap();
    let (observer, calls) = TraceObserver::cancel_on_second();
    let mut session = WorkSession::new(observer).unwrap();
    let error =
        ObservedEnumView::from_canonical_with_session(canonical.as_canonical_ref(), &mut session)
            .unwrap_err();

    assert_eq!(error.code, ErrorCode::WorkCancelled);
    assert!(error.offset > items.offset());
    assert!(error.offset < items.offset() + items.byte_len());
    assert_eq!(&*calls.borrow(), &[0, WORK_CHECKPOINT_INTERVAL]);
}

#[test]
fn generated_transparent_root_scan_uses_the_callers_session() {
    let value = TransparentManifest(TransparentManifestInner {
        items: (0..ARRAY_ITEMS as u64).collect(),
    });
    let bytes = encode_to_vec(&value, EncodeLimits::for_bytes(1 << 20)).unwrap();
    let canonical =
        CanonicalCbor::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let (observer, calls) = TraceObserver::cancel_on_second();
    let mut session = WorkSession::new(observer).unwrap();
    let error = TransparentManifestView::from_canonical_with_session(
        canonical.as_canonical_ref(),
        &mut session,
    )
    .unwrap_err();

    assert_eq!(error.code, ErrorCode::WorkCancelled);
    assert!(error.offset > 0);
    assert!(error.offset < bytes.len());
    assert_eq!(&*calls.borrow(), &[0, WORK_CHECKPOINT_INTERVAL]);
}

#[test]
fn transparent_field_and_inner_methods_preserve_observation() {
    let value = TransparentManifest(TransparentManifestInner {
        items: (0..ARRAY_ITEMS as u64).collect(),
    });
    let bytes = encode_to_vec(&value, EncodeLimits::for_bytes(1 << 20)).unwrap();
    let canonical =
        CanonicalCbor::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();

    let (field_observer, field_calls) = TraceObserver::cancel_on_second();
    let mut field_session = WorkSession::new(field_observer).unwrap();
    let field_error = <TransparentManifest as AbiViewField>::view_field_with_session(
        canonical.as_canonical_ref().root(),
        &mut field_session,
    )
    .unwrap_err();
    assert_eq!(field_error.code, ErrorCode::WorkCancelled);
    assert_eq!(&*field_calls.borrow(), &[0, WORK_CHECKPOINT_INTERVAL]);

    let ordinary = TransparentManifestView::from_canonical(canonical.as_canonical_ref()).unwrap();
    let (inner_observer, inner_calls) = TraceObserver::cancel_on_second();
    let mut inner_session = WorkSession::new(inner_observer).unwrap();
    let inner_error = ordinary.inner_with_session(&mut inner_session).unwrap_err();
    assert_eq!(inner_error.code, ErrorCode::WorkCancelled);
    assert_eq!(&*inner_calls.borrow(), &[0, WORK_CHECKPOINT_INTERVAL]);
}

#[test]
fn generated_manifest_array_view_cancels_after_iteration_started() {
    let canonical = canonical_manifest(LAZY_ITEMS, 8);
    let (observer, calls) = TraceObserver::cancel_on_second();
    let mut session = WorkSession::new(observer).unwrap();
    let view =
        ManifestView::from_canonical_with_session(canonical.as_canonical_ref(), &mut session)
            .unwrap();
    let items = view.first_with_session(&mut session).unwrap();
    let mut cursor = items.cursor().unwrap();

    let mut seen = 0usize;
    let error = loop {
        match cursor
            .next_with_session(&mut session)
            .expect("cancellation before array exhaustion")
        {
            Ok(_) => seen += 1,
            Err(error) => break error,
        }
    };

    assert_eq!(error.code, ErrorCode::WorkCancelled);
    assert!(seen > 0, "cancellation must not happen at preflight");
    assert!(seen < LAZY_ITEMS, "cancellation must stop before the tail");
    assert!(error.offset > items.raw_value().offset());
    assert!(
        cursor.next_with_session(&mut session).is_none(),
        "cancelled cursor must stay exhausted"
    );
    assert_eq!(&*calls.borrow(), &[0, WORK_CHECKPOINT_INTERVAL]);
}

#[test]
fn one_session_spans_generated_view_construction_and_two_lazy_fields() {
    let canonical = canonical_manifest(3_000, 3_000);

    let ordinary = ManifestView::from_canonical(canonical.as_canonical_ref()).unwrap();
    let ordinary_first: Vec<_> = ordinary
        .first()
        .unwrap()
        .iter()
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let ordinary_second: Vec<_> = ordinary
        .second()
        .unwrap()
        .iter()
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();

    let (observer, calls) = TraceObserver::recording();
    let mut session = WorkSession::new(observer).unwrap();
    let observed =
        ManifestView::from_canonical_with_session(canonical.as_canonical_ref(), &mut session)
            .unwrap();
    let mut first_cursor = observed
        .first_with_session(&mut session)
        .unwrap()
        .cursor()
        .unwrap();
    let mut observed_first = Vec::new();
    while let Some(item) = first_cursor.next_with_session(&mut session) {
        observed_first.push(item.unwrap());
    }
    let mut second_cursor = observed
        .second_with_session(&mut session)
        .unwrap()
        .cursor()
        .unwrap();
    let mut observed_second = Vec::new();
    while let Some(item) = second_cursor.next_with_session(&mut session) {
        observed_second.push(item.unwrap());
    }
    session.finish().unwrap();

    assert_eq!(observed_first, ordinary_first);
    assert_eq!(observed_second, ordinary_second);
    assert_eq!(
        &*calls.borrow(),
        &[
            0,
            WORK_CHECKPOINT_INTERVAL,
            WORK_CHECKPOINT_INTERVAL,
            WORK_CHECKPOINT_INTERVAL,
            WORK_CHECKPOINT_INTERVAL,
            1_622,
        ],
        "nested boundaries, two field-set entries, and both lazy loops share one cadence"
    );
}

#[test]
fn one_session_enters_a_record_from_an_outer_cursor_then_cancels_in_its_inner_cursor() {
    let value = RecoveryManifest {
        sync_sets: vec![RecoverySyncSet {
            terminals: (0..NESTED_TERMINALS as u64).collect(),
        }],
    };
    let bytes = encode_to_vec(&value, EncodeLimits::for_bytes(1 << 20)).unwrap();
    let canonical =
        CanonicalCbor::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    let (observer, calls) = TraceObserver::cancel_on_second();
    let mut session = WorkSession::new(observer).unwrap();
    let manifest = RecoveryManifestView::from_canonical_with_session(
        canonical.as_canonical_ref(),
        &mut session,
    )
    .unwrap();
    let sync_sets = manifest.sync_sets_with_session(&mut session).unwrap();
    let mut outer = sync_sets.cursor().unwrap();
    let sync_set = outer
        .next_with_session(&mut session)
        .expect("one outer record")
        .unwrap();
    let terminals = sync_set.terminals_with_session(&mut session).unwrap();
    let mut inner = terminals.cursor().unwrap();

    let mut seen = 0usize;
    let error = loop {
        match inner
            .next_with_session(&mut session)
            .expect("cancellation before inner array exhaustion")
        {
            Ok(_) => seen += 1,
            Err(error) => break error,
        }
    };

    assert_eq!(error.code, ErrorCode::WorkCancelled);
    assert_eq!(seen, 91, "the outer and inner cursors share one cadence");
    assert!(error.offset > terminals.raw_value().offset());
    assert!(error.offset < terminals.raw_value().offset() + terminals.raw_value().byte_len());
    assert!(
        inner.next_with_session(&mut session).is_none(),
        "cancelled inner cursor must stay exhausted"
    );
    assert!(
        outer.next_with_session(&mut session).is_none(),
        "the outer cursor remains usable and was already exhausted"
    );
    assert_eq!(&*calls.borrow(), &[0, WORK_CHECKPOINT_INTERVAL]);
}

#[test]
fn generated_record_initial_scan_is_observed_and_interruptible() {
    let _declaration = OpenManifest { anchor: None };
    let field_count = WORK_CHECKPOINT_INTERVAL + 32;
    let mut encoder = Encoder::with_limits(EncodeLimits::for_bytes(1 << 20)).unwrap();
    encoder
        .array(field_count * 2, |array| {
            for id in 2..field_count as u64 + 2 {
                array.value(&id)?;
                array.value(&id)?;
            }
            Ok(())
        })
        .unwrap();
    let bytes = encoder.finish().unwrap();
    let canonical =
        CanonicalCbor::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();

    let (observer, calls) = TraceObserver::cancel_on_second();
    let mut session = WorkSession::new(observer).unwrap();
    let error =
        OpenManifestView::from_canonical_with_session(canonical.as_canonical_ref(), &mut session)
            .unwrap_err();

    assert_eq!(error.code, ErrorCode::WorkCancelled);
    assert!(error.offset > 1, "the field scan must have advanced");
    assert!(error.offset < bytes.len(), "the field scan must stop early");
    assert_eq!(&*calls.borrow(), &[0, WORK_CHECKPOINT_INTERVAL]);
}
