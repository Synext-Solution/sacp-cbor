use core::alloc::{GlobalAlloc, Layout};
use sacp_cbor::bytes::Bytes;
use sacp_cbor::{validate_canonical, CanonicalCbor, CborError, DecodeLimits, ErrorCode};
use sacp_cbor_abi::{
    decode, AbiDecodeContext, AbiDecodeLocation, AbiDecodeValue, CborAbi, UnknownFields,
};
use std::alloc::System;
use std::cell::Cell;

thread_local! {
    static FAIL_NEXT_ALLOCATION: Cell<bool> = const { Cell::new(false) };
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATION_COUNT: Cell<usize> = const { Cell::new(0) };
    static TRANSPARENT_TRY_FROM_CALLS: Cell<usize> = const { Cell::new(0) };
}

struct TestAllocator;

impl TestAllocator {
    fn should_fail() -> bool {
        TRACK_ALLOCATIONS.with(|tracking| {
            if tracking.get() {
                ALLOCATION_COUNT.with(|count| count.set(count.get() + 1));
            }
        });
        FAIL_NEXT_ALLOCATION.with(|flag| flag.replace(false))
    }
}

// SAFETY: successful operations delegate unchanged layouts and pointers to `System`. Returning null
// for the planted failure is permitted by the `GlobalAlloc` contract.
unsafe impl GlobalAlloc for TestAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if Self::should_fail() {
            core::ptr::null_mut()
        } else {
            // SAFETY: the layout is forwarded unchanged to the system allocator.
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if Self::should_fail() {
            core::ptr::null_mut()
        } else {
            // SAFETY: the layout is forwarded unchanged to the system allocator.
            unsafe { System.alloc_zeroed(layout) }
        }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the pointer and layout came from the system allocator.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if Self::should_fail() {
            core::ptr::null_mut()
        } else {
            // SAFETY: the pointer and layout came from the system allocator.
            unsafe { System.realloc(pointer, layout, new_size) }
        }
    }
}

#[global_allocator]
static ALLOCATOR: TestAllocator = TestAllocator;

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(type_id = "allocation.Batch", version = 1)]
struct Batch {
    #[abi(id = 1)]
    values: Vec<u64>,
}

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(type_id = "allocation.CanonicalEnvelope", version = 1)]
struct CanonicalEnvelope {
    #[abi(id = 1)]
    value: CanonicalCbor,
}

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(
    type_id = "allocation.ValidatedText",
    version = 1,
    transparent,
    try_from = "ValidatedText::try_from_inner"
)]
struct ValidatedText(String);

impl ValidatedText {
    fn try_from_inner(value: String) -> Result<Self, ()> {
        TRANSPARENT_TRY_FROM_CALLS.with(|calls| calls.set(calls.get() + 1));
        if value.is_empty() {
            Err(())
        } else {
            Ok(Self(value))
        }
    }
}

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(
    type_id = "allocation.Extensible",
    version = 1,
    unknown_fields = "preserve"
)]
struct Extensible {
    #[abi(id = 1)]
    enabled: bool,
    #[abi(unknown_fields)]
    unknown: UnknownFields,
}

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(
    type_id = "allocation.ExtensibleChoice",
    version = 1,
    unknown_fields = "preserve"
)]
enum ExtensibleChoice {
    #[abi(id = 1)]
    Known {
        #[abi(id = 1)]
        enabled: bool,
        #[abi(unknown_fields)]
        unknown: UnknownFields,
    },
}

fn fail_next_allocation<T>(operation: impl FnOnce() -> T) -> T {
    FAIL_NEXT_ALLOCATION.with(|flag| {
        assert!(!flag.replace(true), "nested planted allocation failure");
    });
    let result = operation();
    let failure_was_consumed = FAIL_NEXT_ALLOCATION.with(|flag| !flag.replace(false));
    assert!(
        failure_was_consumed,
        "the planted allocation failure was not reached"
    );
    result
}

fn count_allocations<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    TRACK_ALLOCATIONS.with(|tracking| {
        assert!(!tracking.replace(true), "nested allocation tracking");
    });
    ALLOCATION_COUNT.with(|count| count.set(0));
    let result = operation();
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    let count = ALLOCATION_COUNT.with(Cell::get);
    (result, count)
}

#[derive(Clone, Copy)]
enum RejectKind {
    Sequence,
    Text,
    Bytes,
    Canonical,
    UnknownField,
}

struct RejectingContext(RejectKind);

impl AbiDecodeContext for RejectingContext {
    type Error = CborError;

    fn admit(
        &mut self,
        _location: AbiDecodeLocation,
        value: AbiDecodeValue,
    ) -> Result<(), Self::Error> {
        let reject = matches!(
            (self.0, value),
            (RejectKind::Sequence, AbiDecodeValue::Sequence { .. })
                | (RejectKind::Text, AbiDecodeValue::Text { .. })
                | (RejectKind::Bytes, AbiDecodeValue::Bytes { .. })
                | (RejectKind::Canonical, AbiDecodeValue::Canonical { .. })
                | (
                    RejectKind::UnknownField,
                    AbiDecodeValue::UnknownField { .. }
                )
        );
        if reject {
            Err(CborError::new(ErrorCode::InvalidAbiValue, 0))
        } else {
            Ok(())
        }
    }
}

fn assert_refusal_precedes_planted_allocation<T>(operation: impl FnOnce() -> Result<T, CborError>) {
    FAIL_NEXT_ALLOCATION.with(|flag| {
        assert!(!flag.replace(true), "nested planted allocation failure");
    });
    let error = operation().err().expect("decode unexpectedly succeeded");
    let failure_remained_planted = FAIL_NEXT_ALLOCATION.with(|flag| flag.replace(false));
    assert!(
        failure_remained_planted,
        "allocation occurred before admission refusal"
    );
    assert_eq!(error.code, ErrorCode::InvalidAbiValue);
}

fn assert_planted_allocation_failure<T>(operation: impl FnOnce() -> Result<T, CborError>) {
    let err = fail_next_allocation(operation)
        .err()
        .expect("decode succeeded");
    assert_eq!(err.code, ErrorCode::AllocationFailed);
    assert_eq!(err.offset, 0);
}

#[test]
fn vec_decode_reports_initial_reservation_failure_at_array_offset() {
    let bytes = [0x82, 0x01, 0x02];
    let err = fail_next_allocation(|| {
        decode::<Vec<u64>, _>(&bytes, DecodeLimits::for_bytes(bytes.len()), &mut ())
    })
    .unwrap_err();

    assert_eq!(err.code, ErrorCode::AllocationFailed);
    assert_eq!(err.offset, 0);
}

#[test]
fn owned_passthrough_decoders_preserve_core_allocation_failures() {
    let text = [0x61, b'a'];
    assert_planted_allocation_failure(|| {
        decode::<String, _>(&text, DecodeLimits::for_bytes(text.len()), &mut ())
    });

    let bytes = [0x41, 0x01];
    assert_planted_allocation_failure(|| {
        decode::<Bytes, _>(&bytes, DecodeLimits::for_bytes(bytes.len()), &mut ())
    });

    let canonical = [0x01];
    assert_planted_allocation_failure(|| {
        decode::<CanonicalCbor, _>(
            &canonical,
            DecodeLimits::for_bytes(canonical.len()),
            &mut (),
        )
    });
}

#[test]
fn context_refusal_precedes_every_owned_reservation_and_copy_boundary() {
    let sequence = [0x81, 0x01];
    assert_refusal_precedes_planted_allocation(|| {
        decode::<Vec<u64>, _>(
            &sequence,
            DecodeLimits::for_bytes(sequence.len()),
            &mut RejectingContext(RejectKind::Sequence),
        )
    });

    let text = [0x61, b'a'];
    assert_refusal_precedes_planted_allocation(|| {
        decode::<String, _>(
            &text,
            DecodeLimits::for_bytes(text.len()),
            &mut RejectingContext(RejectKind::Text),
        )
    });

    let bytes = [0x41, 1];
    assert_refusal_precedes_planted_allocation(|| {
        decode::<Bytes, _>(
            &bytes,
            DecodeLimits::for_bytes(bytes.len()),
            &mut RejectingContext(RejectKind::Bytes),
        )
    });

    let canonical = [0x01];
    assert_refusal_precedes_planted_allocation(|| {
        decode::<CanonicalCbor, _>(
            &canonical,
            DecodeLimits::for_bytes(canonical.len()),
            &mut RejectingContext(RejectKind::Canonical),
        )
    });

    let unknown = [0x82, 0x09, 0xf6];
    assert_refusal_precedes_planted_allocation(|| {
        decode::<Extensible, _>(
            &unknown,
            DecodeLimits::for_bytes(unknown.len()),
            &mut RejectingContext(RejectKind::UnknownField),
        )
    });
}

#[test]
fn nested_vec_decode_reports_reservation_failure_at_nested_array_offset() {
    // [1, [1, 2]]
    let bytes = [0x82, 0x01, 0x82, 0x01, 0x02];
    let err = fail_next_allocation(|| {
        decode::<Batch, _>(&bytes, DecodeLimits::for_bytes(bytes.len()), &mut ())
    })
    .unwrap_err();

    assert_eq!(err.code, ErrorCode::AllocationFailed);
    assert_eq!(err.offset, 2);
}

#[test]
fn nested_canonical_decode_reports_reservation_failure_at_payload_offset() {
    // [1, null]
    let bytes = [0x82, 0x01, 0xf6];
    let err = fail_next_allocation(|| {
        decode::<CanonicalEnvelope, _>(&bytes, DecodeLimits::for_bytes(bytes.len()), &mut ())
    })
    .unwrap_err();

    assert_eq!(err.code, ErrorCode::AllocationFailed);
    assert_eq!(err.offset, 2);
}

#[test]
fn transparent_try_from_view_is_borrowed_and_defers_semantics_without_allocation() {
    let bytes = [0x61, b'x'];
    let canonical = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    TRANSPARENT_TRY_FROM_CALLS.with(|calls| calls.set(0));

    let (view, allocations) = count_allocations(|| {
        ValidatedTextView::from_canonical(canonical).expect("wire-valid transparent view")
    });
    assert_eq!(allocations, 0);
    assert_eq!(view.inner().unwrap(), "x");
    assert_eq!(view.inner().unwrap().as_ptr(), bytes[1..].as_ptr());
    assert_eq!(
        TRANSPARENT_TRY_FROM_CALLS.with(Cell::get),
        0,
        "view construction must not run the owned semantic invariant"
    );
}

#[test]
fn transparent_try_from_invariant_runs_only_for_owned_decode() {
    let bytes = [0x60];
    let canonical = validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    TRANSPARENT_TRY_FROM_CALLS.with(|calls| calls.set(0));

    let view = ValidatedTextView::from_canonical(canonical).expect("wire-valid transparent view");
    assert_eq!(view.inner().unwrap(), "");
    assert_eq!(
        TRANSPARENT_TRY_FROM_CALLS.with(Cell::get),
        0,
        "view construction must not run the owned semantic invariant"
    );

    let error = view.to_owned(&mut ()).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidAbiValue);
    assert_eq!(TRANSPARENT_TRY_FROM_CALLS.with(Cell::get), 1);

    let error = decode::<ValidatedText, _>(&bytes, DecodeLimits::for_bytes(bytes.len()), &mut ())
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidAbiValue);
    assert_eq!(TRANSPARENT_TRY_FROM_CALLS.with(Cell::get), 2);
}

#[test]
fn preserved_unknown_fields_reserve_before_the_first_push() {
    // [1, true, 9, null]
    let bytes = [0x84, 0x01, 0xf5, 0x09, 0xf6];
    let err = fail_next_allocation(|| {
        decode::<Extensible, _>(&bytes, DecodeLimits::for_bytes(bytes.len()), &mut ())
    })
    .unwrap_err();

    assert_eq!(err.code, ErrorCode::AllocationFailed);
    assert_eq!(err.offset, 0);
}

#[test]
fn named_enum_payload_unknown_fields_reserve_before_the_first_push() {
    // [1, [1, true, 9, null]]
    let bytes = [0x82, 0x01, 0x84, 0x01, 0xf5, 0x09, 0xf6];
    let err = fail_next_allocation(|| {
        decode::<ExtensibleChoice, _>(&bytes, DecodeLimits::for_bytes(bytes.len()), &mut ())
    })
    .unwrap_err();

    assert_eq!(err.code, ErrorCode::AllocationFailed);
    assert_eq!(err.offset, 2);
}

#[test]
fn vec_decode_accepts_bounded_arrays_and_rejects_the_first_excess_header() {
    let bytes = [0x83, 0x01, 0x02, 0x03];
    assert_eq!(
        decode::<Vec<u64>, _>(&bytes, DecodeLimits::for_bytes(bytes.len()), &mut ()).unwrap(),
        vec![1, 2, 3]
    );

    let nested = [0x82, 0x01, 0x83, 0x01, 0x02, 0x03];
    let mut limits = DecodeLimits::for_bytes(nested.len());
    limits.max_array_len = 2;
    let err = decode::<Batch, _>(&nested, limits, &mut ()).unwrap_err();
    assert_eq!(err.code, ErrorCode::ArrayLenLimitExceeded);
    assert_eq!(err.offset, 2);
}

#[test]
fn preserved_unknown_fields_still_roundtrip_through_owned_decode() {
    // [1, true, 9, null]
    let bytes = [0x84, 0x01, 0xf5, 0x09, 0xf6];
    let decoded =
        decode::<Extensible, _>(&bytes, DecodeLimits::for_bytes(bytes.len()), &mut ()).unwrap();

    assert!(decoded.enabled);
    assert_eq!(decoded.unknown.len(), 1);
    assert_eq!(decoded.unknown.as_slice()[0].id, 9);
    assert_eq!(decoded.unknown.as_slice()[0].value.as_bytes(), &[0xf6]);
}
