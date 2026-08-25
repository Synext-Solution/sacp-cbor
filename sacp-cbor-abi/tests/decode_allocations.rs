use core::alloc::{GlobalAlloc, Layout};
use sacp_cbor::bytes::Bytes;
use sacp_cbor::{CanonicalCbor, CborError, DecodeLimits, ErrorCode};
use sacp_cbor_abi::{decode, CborAbi, UnknownFields};
use std::alloc::System;
use std::cell::Cell;

thread_local! {
    static FAIL_NEXT_ALLOCATION: Cell<bool> = const { Cell::new(false) };
}

struct TestAllocator;

impl TestAllocator {
    fn should_fail() -> bool {
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
    let err =
        fail_next_allocation(|| decode::<Vec<u64>>(&bytes, DecodeLimits::for_bytes(bytes.len())))
            .unwrap_err();

    assert_eq!(err.code, ErrorCode::AllocationFailed);
    assert_eq!(err.offset, 0);
}

#[test]
fn owned_passthrough_decoders_preserve_core_allocation_failures() {
    let text = [0x61, b'a'];
    assert_planted_allocation_failure(|| {
        decode::<String>(&text, DecodeLimits::for_bytes(text.len()))
    });

    let bytes = [0x41, 0x01];
    assert_planted_allocation_failure(|| {
        decode::<Bytes>(&bytes, DecodeLimits::for_bytes(bytes.len()))
    });

    let canonical = [0x01];
    assert_planted_allocation_failure(|| {
        decode::<CanonicalCbor>(&canonical, DecodeLimits::for_bytes(canonical.len()))
    });
}

#[test]
fn nested_vec_decode_reports_reservation_failure_at_nested_array_offset() {
    // [1, [1, 2]]
    let bytes = [0x82, 0x01, 0x82, 0x01, 0x02];
    let err =
        fail_next_allocation(|| decode::<Batch>(&bytes, DecodeLimits::for_bytes(bytes.len())))
            .unwrap_err();

    assert_eq!(err.code, ErrorCode::AllocationFailed);
    assert_eq!(err.offset, 2);
}

#[test]
fn preserved_unknown_fields_reserve_before_the_first_push() {
    // [1, true, 9, null]
    let bytes = [0x84, 0x01, 0xf5, 0x09, 0xf6];
    let err =
        fail_next_allocation(|| decode::<Extensible>(&bytes, DecodeLimits::for_bytes(bytes.len())))
            .unwrap_err();

    assert_eq!(err.code, ErrorCode::AllocationFailed);
    assert_eq!(err.offset, 0);
}

#[test]
fn named_enum_payload_unknown_fields_reserve_before_the_first_push() {
    // [1, [1, true, 9, null]]
    let bytes = [0x82, 0x01, 0x84, 0x01, 0xf5, 0x09, 0xf6];
    let err = fail_next_allocation(|| {
        decode::<ExtensibleChoice>(&bytes, DecodeLimits::for_bytes(bytes.len()))
    })
    .unwrap_err();

    assert_eq!(err.code, ErrorCode::AllocationFailed);
    assert_eq!(err.offset, 2);
}

#[test]
fn vec_decode_accepts_bounded_arrays_and_rejects_the_first_excess_header() {
    let bytes = [0x83, 0x01, 0x02, 0x03];
    assert_eq!(
        decode::<Vec<u64>>(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap(),
        vec![1, 2, 3]
    );

    let nested = [0x82, 0x01, 0x83, 0x01, 0x02, 0x03];
    let mut limits = DecodeLimits::for_bytes(nested.len());
    limits.max_array_len = 2;
    let err = decode::<Batch>(&nested, limits).unwrap_err();
    assert_eq!(err.code, ErrorCode::ArrayLenLimitExceeded);
    assert_eq!(err.offset, 2);
}

#[test]
fn preserved_unknown_fields_still_roundtrip_through_owned_decode() {
    // [1, true, 9, null]
    let bytes = [0x84, 0x01, 0xf5, 0x09, 0xf6];
    let decoded = decode::<Extensible>(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();

    assert!(decoded.enabled);
    assert_eq!(decoded.unknown.len(), 1);
    assert_eq!(decoded.unknown.as_slice()[0].id, 9);
    assert_eq!(decoded.unknown.as_slice()[0].value.as_bytes(), &[0xf6]);
}
