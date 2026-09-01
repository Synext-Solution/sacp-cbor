#![cfg(feature = "alloc")]

use core::alloc::{GlobalAlloc, Layout};
use core::convert::Infallible;
use std::alloc::System;
use std::cell::RefCell;
use std::rc::Rc;

use sacp_cbor::EncodeLimits;

thread_local! {
    static FAIL_NEXT_ALLOCATION: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

struct TestAllocator;

// SAFETY: every operation delegates to `System`; `alloc` may additionally return null,
// which is permitted by the `GlobalAlloc` contract and is consumed exactly once per thread.
unsafe impl GlobalAlloc for TestAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if FAIL_NEXT_ALLOCATION.with(|flag| flag.replace(false)) {
            core::ptr::null_mut()
        } else {
            // SAFETY: the layout is forwarded unchanged to the system allocator.
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the pointer and layout came from the system allocator.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the pointer and layout came from the system allocator.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: TestAllocator = TestAllocator;
use sacp_cbor::{
    encode_to_vec, ByteSink, CountingSink, EncodeError, Encoder, ErrorCode, FanoutError,
    FanoutSink, VecSink,
};

#[cfg(all(feature = "derive", feature = "sha2"))]
use sacp_cbor::CborEncode;

#[cfg(feature = "serde")]
use serde::ser::SerializeStruct;

#[cfg(feature = "serde")]
use serde::Serialize;

#[derive(Debug, PartialEq, Eq)]
struct OwnedFailure {
    token: Box<str>,
}

impl core::fmt::Display for OwnedFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.token)
    }
}

#[derive(Default)]
struct SharedBytes(Rc<RefCell<Vec<u8>>>);

impl SharedBytes {
    fn snapshot(&self) -> Vec<u8> {
        self.0.borrow().clone()
    }
}

struct FailingSink {
    bytes: SharedBytes,
    fail_write: Option<usize>,
    calls: usize,
    partial: usize,
    fail_finish: bool,
}

impl ByteSink for FailingSink {
    type Error = OwnedFailure;
    type Output = Vec<u8>;

    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let call = self.calls;
        self.calls += 1;
        if self.fail_write == Some(call) {
            let accepted = self.partial.min(bytes.len());
            self.bytes
                .0
                .borrow_mut()
                .extend_from_slice(&bytes[..accepted]);
            return Err(OwnedFailure {
                token: format!("write-{call}").into_boxed_str(),
            });
        }
        self.bytes.0.borrow_mut().extend_from_slice(bytes);
        Ok(())
    }

    fn finish(self) -> Result<Self::Output, Self::Error> {
        if self.fail_finish {
            return Err(OwnedFailure {
                token: "finish".into(),
            });
        }
        Ok(self.bytes.snapshot())
    }
}

#[test]
fn vec_count_custom_and_io_are_byte_identical() {
    let value = "sink conformance";
    let expected = encode_to_vec(&value).unwrap();

    let mut count = Encoder::with_sink(CountingSink::new());
    count.encode(&value).unwrap();
    assert_eq!(count.finish().unwrap(), expected.len());

    let mut custom = Encoder::with_sink(VecSink::new());
    custom.encode(&value).unwrap();
    assert_eq!(custom.finish().unwrap(), expected);

    let mut io = Encoder::with_sink(sacp_cbor::IoSink::new(Vec::new()));
    io.encode(&value).unwrap();
    assert_eq!(io.finish().unwrap(), expected);
}

#[cfg(feature = "sha2")]
#[test]
fn digest_sink_hashes_exact_canonical_bytes() {
    use sha2::{Digest, Sha256};

    let value = vec![1_u8, 2, 3, 4];
    let expected = encode_to_vec(&value).unwrap();
    let mut encoder = Encoder::with_sink(sacp_cbor::DigestSink::new(Sha256::new()));
    encoder.encode(&value).unwrap();
    assert_eq!(
        encoder.finish().unwrap().as_slice(),
        Sha256::digest(expected).as_slice()
    );
}

#[cfg(feature = "sha2")]
#[test]
fn fanout_produces_canonical_bytes_and_digest_in_one_pass() {
    use sha2::{Digest, Sha256};

    let value = "one pass";
    let expected = encode_to_vec(&value).unwrap();
    let sink = FanoutSink::new(VecSink::new(), sacp_cbor::DigestSink::new(Sha256::new()));
    let mut encoder = Encoder::with_sink(sink);
    encoder.encode(&value).unwrap();
    let (bytes, digest) = encoder.finish().unwrap();

    assert_eq!(bytes, expected);
    assert_eq!(digest.as_slice(), Sha256::digest(&bytes).as_slice());
}

#[cfg(all(feature = "derive", feature = "sha2"))]
#[derive(CborEncode)]
struct DerivedLeaf {
    n: u64,
}

#[cfg(all(feature = "derive", feature = "sha2"))]
#[derive(CborEncode)]
struct DerivedTree {
    leaf: DerivedLeaf,
    name: String,
}

#[cfg(all(feature = "derive", feature = "sha2"))]
#[test]
fn nested_derive_uses_the_same_vec_counting_and_digest_path() {
    use sha2::{Digest, Sha256};

    let value = DerivedTree {
        leaf: DerivedLeaf { n: 42 },
        name: String::from("generic"),
    };
    let bytes = encode_to_vec(&value).unwrap();

    let mut counting = Encoder::with_sink(CountingSink::new());
    counting.encode(&value).unwrap();
    assert_eq!(counting.finish().unwrap(), bytes.len());

    let mut digest = Encoder::with_sink(sacp_cbor::DigestSink::new(Sha256::new()));
    digest.encode(&value).unwrap();
    assert_eq!(
        digest.finish().unwrap().as_slice(),
        Sha256::digest(&bytes).as_slice()
    );
}

#[test]
fn first_write_failure_is_owned_and_all_later_calls_are_poisoned() {
    let shared = SharedBytes::default();
    let observer = SharedBytes(Rc::clone(&shared.0));
    let sink = FailingSink {
        bytes: shared,
        fail_write: Some(0),
        calls: 0,
        partial: 1,
        fail_finish: false,
    };
    let mut encoder = Encoder::with_sink(sink);
    let error = encoder.text("abc").unwrap_err();
    assert!(matches!(error, EncodeError::Sink(OwnedFailure { token }) if &*token == "write-0"));
    assert_eq!(observer.snapshot(), [0x63]);
    assert!(matches!(encoder.null(), Err(EncodeError::Poisoned)));
    assert!(matches!(encoder.finish(), Err(EncodeError::Poisoned)));
}

#[test]
fn partial_payload_failure_is_never_rolled_back() {
    let shared = SharedBytes::default();
    let observer = SharedBytes(Rc::clone(&shared.0));
    let sink = FailingSink {
        bytes: shared,
        fail_write: Some(1),
        calls: 0,
        partial: 2,
        fail_finish: false,
    };
    let mut encoder = Encoder::with_sink(sink);
    let error = encoder.bytes(&[10, 11, 12]).unwrap_err();
    assert!(matches!(error, EncodeError::Sink(OwnedFailure { token }) if &*token == "write-1"));
    assert_eq!(observer.snapshot(), [0x43, 10, 11]);
    assert!(matches!(encoder.bool(true), Err(EncodeError::Poisoned)));
}

#[test]
fn fanout_left_failure_short_circuits_right_and_poisons_encoder() {
    let left = SharedBytes::default();
    let left_observer = SharedBytes(Rc::clone(&left.0));
    let right = SharedBytes::default();
    let right_observer = SharedBytes(Rc::clone(&right.0));
    let sink = FanoutSink::new(
        FailingSink {
            bytes: left,
            fail_write: Some(0),
            calls: 0,
            partial: 1,
            fail_finish: false,
        },
        FailingSink {
            bytes: right,
            fail_write: None,
            calls: 0,
            partial: 0,
            fail_finish: false,
        },
    );
    let mut encoder = Encoder::with_sink(sink);

    let error = encoder.text("abc").unwrap_err();
    assert!(matches!(
        error,
        EncodeError::Sink(FanoutError::Left(OwnedFailure { token })) if &*token == "write-0"
    ));
    assert_eq!(left_observer.snapshot(), [0x63]);
    assert!(right_observer.snapshot().is_empty());
    assert_eq!(encoder.len(), 0);
    assert!(matches!(encoder.null(), Err(EncodeError::Poisoned)));
    assert!(matches!(encoder.finish(), Err(EncodeError::Poisoned)));
}

#[test]
fn fanout_right_failure_follows_left_success_and_poisons_encoder() {
    let left = SharedBytes::default();
    let left_observer = SharedBytes(Rc::clone(&left.0));
    let right = SharedBytes::default();
    let right_observer = SharedBytes(Rc::clone(&right.0));
    let sink = FanoutSink::new(
        FailingSink {
            bytes: left,
            fail_write: None,
            calls: 0,
            partial: 0,
            fail_finish: false,
        },
        FailingSink {
            bytes: right,
            fail_write: Some(0),
            calls: 0,
            partial: 0,
            fail_finish: false,
        },
    );
    let mut encoder = Encoder::with_sink(sink);

    let error = encoder.text("abc").unwrap_err();
    assert!(matches!(
        error,
        EncodeError::Sink(FanoutError::Right(OwnedFailure { token })) if &*token == "write-0"
    ));
    assert_eq!(left_observer.snapshot(), [0x63]);
    assert!(right_observer.snapshot().is_empty());
    assert_eq!(encoder.len(), 0);
    assert!(matches!(encoder.null(), Err(EncodeError::Poisoned)));
    assert!(matches!(encoder.finish(), Err(EncodeError::Poisoned)));
}

#[test]
fn fanout_finish_preserves_the_failing_child_error() {
    let mut left_fails = Encoder::with_sink(FanoutSink::new(
        FailingSink {
            bytes: SharedBytes::default(),
            fail_write: None,
            calls: 0,
            partial: 0,
            fail_finish: true,
        },
        FailingSink {
            bytes: SharedBytes::default(),
            fail_write: None,
            calls: 0,
            partial: 0,
            fail_finish: false,
        },
    ));
    left_fails.null().unwrap();
    assert!(matches!(
        left_fails.finish(),
        Err(EncodeError::Sink(FanoutError::Left(OwnedFailure { token })))
            if &*token == "finish"
    ));

    let mut right_fails = Encoder::with_sink(FanoutSink::new(
        FailingSink {
            bytes: SharedBytes::default(),
            fail_write: None,
            calls: 0,
            partial: 0,
            fail_finish: false,
        },
        FailingSink {
            bytes: SharedBytes::default(),
            fail_write: None,
            calls: 0,
            partial: 0,
            fail_finish: true,
        },
    ));
    right_fails.null().unwrap();
    assert!(matches!(
        right_fails.finish(),
        Err(EncodeError::Sink(FanoutError::Right(OwnedFailure { token })))
            if &*token == "finish"
    ));
}

#[test]
fn finish_returns_the_owned_sink_failure() {
    let sink = FailingSink {
        bytes: SharedBytes::default(),
        fail_write: None,
        calls: 0,
        partial: 0,
        fail_finish: true,
    };
    let mut encoder = Encoder::with_sink(sink);
    encoder.null().unwrap();
    let error = encoder.finish().unwrap_err();
    assert!(matches!(error, EncodeError::Sink(OwnedFailure { token }) if &*token == "finish"));
}

struct PointerSink {
    payload_pointer: *const u8,
    payload_len: usize,
    saw_original_payload: bool,
    count: usize,
}

impl ByteSink for PointerSink {
    type Error = Infallible;
    type Output = (usize, bool);

    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        if bytes.as_ptr() == self.payload_pointer && bytes.len() == self.payload_len {
            self.saw_original_payload = true;
        }
        self.count += bytes.len();
        Ok(())
    }

    fn finish(self) -> Result<Self::Output, Self::Error> {
        Ok((self.count, self.saw_original_payload))
    }
}

#[test]
fn streaming_sink_receives_large_payload_without_a_vec_trampoline() {
    let payload = vec![0x5a; 1 << 20];
    let sink = PointerSink {
        payload_pointer: payload.as_ptr(),
        payload_len: payload.len(),
        saw_original_payload: false,
        count: 0,
    };
    let mut encoder = Encoder::with_sink(sink);
    encoder.bytes(&payload).unwrap();
    let (count, saw_original_payload) = encoder.finish().unwrap();
    assert_eq!(count, payload.len() + 5);
    assert!(saw_original_payload);
}

#[cfg(feature = "serde")]
struct SerdeBytes<'a>(&'a [u8]);

#[cfg(feature = "serde")]
impl Serialize for SerdeBytes<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

#[cfg(feature = "serde")]
struct StrictSerdePayload<'a> {
    payload: SerdeBytes<'a>,
}

#[cfg(feature = "serde")]
impl Serialize for StrictSerdePayload<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("StrictSerdePayload", 1)?;
        state.serialize_field("payload", &self.payload)?;
        state.end()
    }
}

#[cfg(feature = "serde")]
#[test]
fn strict_serde_streams_large_payload_to_custom_and_counting_sinks() {
    let payload = vec![0x5a; 1 << 20];
    let value = StrictSerdePayload {
        payload: SerdeBytes(&payload),
    };
    let pointer = PointerSink {
        payload_pointer: payload.as_ptr(),
        payload_len: payload.len(),
        saw_original_payload: false,
        count: 0,
    };
    let (custom_count, saw_original_payload) = sacp_cbor::serde::SerdeOptions::strict()
        .to_sink(&value, pointer)
        .unwrap();
    assert!(saw_original_payload);

    let count = sacp_cbor::serde::SerdeOptions::strict()
        .to_sink(&value, CountingSink::new())
        .unwrap();
    assert_eq!(count, custom_count);
    assert_eq!(count, payload.len() + 14);
}

#[cfg(all(feature = "serde", feature = "sha2"))]
#[test]
fn strict_serde_digest_sink_hashes_large_payload_without_staging() {
    use sha2::{Digest, Sha256};

    let payload = vec![0x5a; 1 << 20];
    let value = StrictSerdePayload {
        payload: SerdeBytes(&payload),
    };
    let actual = sacp_cbor::serde::SerdeOptions::strict()
        .to_sink(&value, sacp_cbor::DigestSink::new(Sha256::new()))
        .unwrap();
    let mut expected = Sha256::new();
    expected.update([0xa1, 0x67]);
    expected.update(b"payload");
    expected.update([0x5a, 0x00, 0x10, 0x00, 0x00]);
    expected.update(&payload);
    assert_eq!(actual.as_slice(), expected.finalize().as_slice());
}

#[cfg(feature = "serde")]
#[test]
fn strict_serde_preserves_owned_sink_error_and_poison_state() {
    let sink = FailingSink {
        bytes: SharedBytes::default(),
        fail_write: Some(1),
        calls: 0,
        partial: 1,
        fail_finish: false,
    };
    let mut encoder = Encoder::with_sink(sink);
    let error = sacp_cbor::serde::SerdeOptions::strict()
        .encode(&SerdeBytes(b"payload"), &mut encoder)
        .unwrap_err();
    assert!(matches!(
        error,
        sacp_cbor::serde::SerdeEncodeError::Encode(EncodeError::Sink(OwnedFailure { token }))
            if &*token == "write-1"
    ));
    assert!(matches!(encoder.null(), Err(EncodeError::Poisoned)));
    assert!(matches!(encoder.finish(), Err(EncodeError::Poisoned)));
}

#[test]
fn offending_map_key_writes_no_bytes_to_the_sink() {
    let shared = SharedBytes::default();
    let observer = SharedBytes(Rc::clone(&shared.0));
    let sink = FailingSink {
        bytes: shared,
        fail_write: None,
        calls: 0,
        partial: 0,
        fail_finish: false,
    };
    let mut encoder = Encoder::with_sink(sink);
    let error = encoder
        .map(2, |map| {
            map.entry("bb", |encoder| encoder.null())?;
            let before = observer.snapshot();
            let error = map.entry("a", |encoder| encoder.null()).unwrap_err();
            assert!(matches!(
                error,
                EncodeError::Cbor(error) if error.code == ErrorCode::NonCanonicalMapOrder
            ));
            assert_eq!(observer.snapshot(), before);
            Err(EncodeError::Poisoned)
        })
        .unwrap_err();
    assert!(matches!(error, EncodeError::Poisoned));
}

#[test]
fn map_accepts_each_source_key_from_a_short_lived_string() {
    let mut encoder = Encoder::new();
    encoder
        .map(3, |map| {
            for source in ["a", "bb", "ccc"] {
                let key = source.to_owned();
                map.entry(&key, |value| value.null())?;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(
        encoder.finish().unwrap(),
        [0xa3, 0x61, b'a', 0xf6, 0x62, b'b', b'b', 0xf6, 0x63, b'c', b'c', b'c', 0xf6,]
    );
}

#[test]
fn map_key_limit_fails_before_key_allocation_or_sink_write() {
    let shared = SharedBytes::default();
    let observer = SharedBytes(Rc::clone(&shared.0));
    let limits = EncodeLimits {
        max_text_len: 1,
        ..EncodeLimits::unbounded()
    };
    let mut encoder = Encoder::with_sink_and_limits(
        FailingSink {
            bytes: shared,
            fail_write: None,
            calls: 0,
            partial: 0,
            fail_finish: false,
        },
        limits,
    )
    .unwrap();
    let error = encoder
        .map(1, |map| map.entry("too-long", |value| value.null()))
        .unwrap_err();
    assert!(matches!(
        error,
        EncodeError::Cbor(error) if error.code == ErrorCode::TextLenLimitExceeded
    ));
    assert_eq!(observer.snapshot(), [0xa1]);
    assert!(matches!(encoder.null(), Err(EncodeError::Poisoned)));
}

#[test]
fn map_previous_key_allocation_failure_is_sticky_and_prewrite() {
    let key = String::from("key-needing-storage");
    let shared = SharedBytes::default();
    let observer = SharedBytes(Rc::clone(&shared.0));
    let mut encoder = Encoder::with_sink(FailingSink {
        bytes: shared,
        fail_write: None,
        calls: 0,
        partial: 0,
        fail_finish: false,
    });
    let error = encoder
        .map(1, |map| {
            FAIL_NEXT_ALLOCATION.with(|flag| flag.set(true));
            map.entry(&key, |value| value.null())
        })
        .unwrap_err();
    assert!(matches!(
        error,
        EncodeError::Cbor(error) if error.code == ErrorCode::AllocationFailed
    ));
    assert_eq!(observer.snapshot(), [0xa1]);
    assert!(matches!(encoder.null(), Err(EncodeError::Poisoned)));
}

#[test]
fn map_key_output_limit_precedes_previous_key_allocation() {
    let key = String::from("allowed-but-too-large-for-output");
    let shared = SharedBytes::default();
    let observer = SharedBytes(Rc::clone(&shared.0));
    let limits = EncodeLimits {
        max_output_bytes: 3,
        ..EncodeLimits::unbounded()
    };
    let mut encoder = Encoder::with_sink_and_limits(
        FailingSink {
            bytes: shared,
            fail_write: None,
            calls: 0,
            partial: 0,
            fail_finish: false,
        },
        limits,
    )
    .unwrap();
    let error = encoder
        .map(1, |map| {
            FAIL_NEXT_ALLOCATION.with(|flag| flag.set(true));
            map.entry(&key, |value| value.null())
        })
        .unwrap_err();
    let allocation_was_not_attempted = FAIL_NEXT_ALLOCATION.with(|flag| flag.replace(false));
    assert!(matches!(
        error,
        EncodeError::Cbor(error) if error.code == ErrorCode::MessageLenLimitExceeded
    ));
    assert_eq!(observer.snapshot(), [0xa1]);
    assert!(allocation_was_not_attempted);
    assert!(matches!(encoder.null(), Err(EncodeError::Poisoned)));
}
