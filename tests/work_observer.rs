#![cfg(feature = "alloc")]

use core::cell::Cell;

use sacp_cbor::{
    decode_with_observer, encode_to_vec_with_observer, validate_canonical,
    validate_canonical_observed, ByteSink, CountingSink, DecodeLimits, Decoder, EncodeError,
    EncodeResult, Encoder, ErrorCode, ScalarKind, VecSink, WorkCancelled, WorkObserver,
    WorkSession, WORK_CHECKPOINT_INTERVAL,
};

const TRACE_CAPACITY: usize = 8;
const UNRECORDED: usize = usize::MAX;

struct Trace {
    calls: Cell<usize>,
    completed: [Cell<usize>; TRACE_CAPACITY],
}

impl Trace {
    fn new() -> Self {
        Self {
            calls: Cell::new(0),
            completed: core::array::from_fn(|_| Cell::new(UNRECORDED)),
        }
    }

    fn record(&self, completed: usize) {
        let call = self.calls.get();
        assert!(call < TRACE_CAPACITY, "test observer trace overflow");
        self.completed[call].set(completed);
        self.calls.set(call + 1);
    }

    fn calls(&self) -> usize {
        self.calls.get()
    }

    fn completed(&self, call: usize) -> usize {
        assert!(call < self.calls());
        self.completed[call].get()
    }

    fn assert_started_then_completed_one_interval(&self) {
        assert_eq!(self.calls(), 2);
        assert_eq!(self.completed(0), 0);
        assert_eq!(self.completed(1), WORK_CHECKPOINT_INTERVAL);
    }

    fn assert_same_as(&self, other: &Self) {
        assert_eq!(self.calls(), other.calls());
        for call in 0..self.calls() {
            assert_eq!(self.completed(call), other.completed(call), "call {call}");
        }
    }
}

#[derive(Clone, Copy)]
struct TestObserver<'a> {
    trace: &'a Trace,
    cancel_on_call: Option<usize>,
}

impl<'a> TestObserver<'a> {
    const fn continuing(trace: &'a Trace) -> Self {
        Self {
            trace,
            cancel_on_call: None,
        }
    }

    const fn cancel_on_second_call(trace: &'a Trace) -> Self {
        Self::cancel_on_call(trace, 2)
    }

    const fn cancel_on_call(trace: &'a Trace, call: usize) -> Self {
        Self {
            trace,
            cancel_on_call: Some(call),
        }
    }
}

impl WorkObserver for TestObserver<'_> {
    fn checkpoint(&mut self, completed_units: usize) -> Result<(), WorkCancelled> {
        self.trace.record(completed_units);
        if self.cancel_on_call == Some(self.trace.calls()) {
            Err(WorkCancelled)
        } else {
            Ok(())
        }
    }
}

struct OversizedCadenceOwner<'a> {
    trace: &'a Trace,
}

impl WorkObserver for OversizedCadenceOwner<'_> {
    const __OWNS_WORK_CADENCE: bool = true;

    fn __next_work_chunk(&self, available: usize) -> usize {
        available
    }

    fn checkpoint(&mut self, completed_units: usize) -> Result<(), WorkCancelled> {
        self.trace.record(completed_units);
        Ok(())
    }
}

#[cfg(feature = "derive")]
#[derive(Debug, PartialEq, Eq, sacp_cbor::CborEncode, sacp_cbor::CborDecode)]
#[cbor(tag = "kind")]
enum ObservedInternalEnum {
    Large { body: String },
}

#[cfg(feature = "derive")]
#[derive(Debug, PartialEq, Eq, sacp_cbor::CborEncode, sacp_cbor::CborDecode)]
#[cbor(tag = "kind", content = "payload")]
enum ObservedAdjacentEnum {
    Large { body: String },
}

fn wide_null_array(elements: usize) -> Vec<u8> {
    let elements = u16::try_from(elements).expect("test fixture fits a two-byte array length");
    let encoded_len = usize::from(elements) + 3;
    let mut bytes = Vec::with_capacity(encoded_len);
    bytes.push(0x99);
    bytes.extend_from_slice(&elements.to_be_bytes());
    bytes.resize(encoded_len, 0xf6);
    bytes
}

fn append_u16_text(bytes: &mut Vec<u8>, payload: &[u8]) {
    let len = u16::try_from(payload.len()).expect("test text fits a two-byte length");
    bytes.push(0x79);
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(payload);
}

fn append_u16_bytes(bytes: &mut Vec<u8>, payload: &[u8]) {
    let len = u16::try_from(payload.len()).expect("test bytes fit a two-byte length");
    bytes.push(0x59);
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(payload);
}

fn encode_null_array<S, O>(encoder: &mut Encoder<S, O>, elements: usize) -> EncodeResult<(), S>
where
    S: ByteSink,
    O: WorkObserver,
{
    encoder.array(elements, |array| {
        for _ in 0..elements {
            array.null()?;
        }
        Ok(())
    })
}

fn unobserved_null_array(elements: usize) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encode_null_array(&mut encoder, elements).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn work_session_consuming_finish_flushes_one_final_remainder() {
    let trace = Trace::new();
    let mut observer = TestObserver::continuing(&trace);
    let mut session = WorkSession::new(&mut observer).unwrap();

    session.complete(WORK_CHECKPOINT_INTERVAL + 7).unwrap();
    session.finish().unwrap();

    assert_eq!(trace.calls(), 3);
    assert_eq!(trace.completed(0), 0);
    assert_eq!(trace.completed(1), WORK_CHECKPOINT_INTERVAL);
    assert_eq!(trace.completed(2), 7);
}

#[test]
fn work_session_cancellation_is_sticky_until_consuming_finish() {
    let trace = Trace::new();
    let mut session = WorkSession::new(TestObserver::cancel_on_second_call(&trace)).unwrap();

    assert_eq!(
        session.complete(WORK_CHECKPOINT_INTERVAL),
        Err(WorkCancelled)
    );
    assert_eq!(session.complete(0), Err(WorkCancelled));
    assert_eq!(trace.calls(), 2, "sticky cancellation must not call again");
    assert_eq!(session.finish(), Err(WorkCancelled));
    assert_eq!(trace.calls(), 2, "terminal finish must not call again");
}

#[test]
fn work_session_borrowed_observer_requires_caller_owned_finish() {
    let trace = Trace::new();
    let mut session = WorkSession::new(TestObserver::continuing(&trace)).unwrap();

    let bytes = encode_to_vec_with_observer(&42_u64, session.observer()).unwrap();
    assert_eq!(bytes, [0x18, 42]);
    assert_eq!(
        trace.calls(),
        1,
        "the eager operation must not finish the session"
    );

    session.finish().unwrap();
    assert_eq!(trace.calls(), 2);
    assert_eq!(trace.completed(0), 0);
    assert!(trace.completed(1) > 0);
    assert!(trace.completed(1) < WORK_CHECKPOINT_INTERVAL);
}

#[test]
fn external_cadence_override_cannot_exceed_the_public_interval() {
    let trace = Trace::new();
    let payload = vec![0_u8; WORK_CHECKPOINT_INTERVAL + 1_000];
    let mut encoder =
        Encoder::with_sink_and_observer(VecSink::new(), OversizedCadenceOwner { trace: &trace })
            .unwrap();
    encoder.bytes(&payload).unwrap();
    encoder.finish().unwrap();

    assert_eq!(trace.completed(0), 0);
    for call in 1..trace.calls() {
        assert!(trace.completed(call) <= WORK_CHECKPOINT_INTERVAL);
    }
}

#[test]
fn canonical_walk_cancels_after_completed_work_not_at_preflight() {
    let bytes = wide_null_array(WORK_CHECKPOINT_INTERVAL + 64);
    let trace = Trace::new();

    let error = validate_canonical_observed(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        TestObserver::cancel_on_second_call(&trace),
    )
    .unwrap_err();

    trace.assert_started_then_completed_one_interval();
    assert_eq!(error.code, ErrorCode::WorkCancelled);
    assert!(
        error.offset > 3,
        "the array walk must have consumed children"
    );
    assert!(
        error.offset < bytes.len(),
        "the walk must stop before the tail"
    );
    validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
}

#[test]
fn decoder_skip_cancellation_is_mid_walk_and_sticky() {
    let bytes = wide_null_array(WORK_CHECKPOINT_INTERVAL + 64);
    let trace = Trace::new();
    let mut decoder = Decoder::<true, _>::new_checked_observed(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        TestObserver::cancel_on_second_call(&trace),
    )
    .unwrap();

    let first = decoder.skip_value().unwrap_err();
    let stopped_at = decoder.position();
    trace.assert_started_then_completed_one_interval();
    assert_eq!(first.code, ErrorCode::WorkCancelled);
    assert_eq!(first.offset, stopped_at);
    assert!(stopped_at > 3, "the decoder must have consumed children");
    assert!(
        stopped_at < bytes.len(),
        "the decoder must stop before the tail"
    );

    let calls = trace.calls();
    assert_eq!(decoder.skip_value().unwrap_err(), first);
    assert_eq!(decoder.position(), stopped_at);
    assert_eq!(trace.calls(), calls, "sticky failure must not call again");
    assert_eq!(decoder.finish().unwrap_err(), first);
    assert_eq!(
        trace.calls(),
        calls,
        "finish must preserve the first failure"
    );
}

#[test]
fn counting_sizing_cancels_mid_array_and_poisons_the_encoder() {
    let elements = WORK_CHECKPOINT_INTERVAL + 64;
    let trace = Trace::new();
    let mut encoder = Encoder::with_sink_and_observer(
        CountingSink::new(),
        TestObserver::cancel_on_second_call(&trace),
    )
    .unwrap();

    let error = encode_null_array(&mut encoder, elements).unwrap_err();
    trace.assert_started_then_completed_one_interval();
    assert!(matches!(
        error,
        EncodeError::Cbor(error)
            if error.code == ErrorCode::WorkCancelled && error.offset == encoder.len()
    ));
    assert!(
        encoder.len() > 3,
        "the sizing sink must have counted children"
    );
    assert!(
        encoder.len() < unobserved_null_array(elements).len(),
        "sizing must stop before the full value"
    );

    let stopped_at = encoder.len();
    let calls = trace.calls();
    assert!(matches!(encoder.null(), Err(EncodeError::Poisoned)));
    assert_eq!(encoder.len(), stopped_at);
    assert_eq!(trace.calls(), calls);
    assert!(matches!(encoder.finish(), Err(EncodeError::Poisoned)));
    assert_eq!(trace.calls(), calls);
}

#[test]
fn counting_and_vector_sinks_observe_the_same_completed_work() {
    let elements = WORK_CHECKPOINT_INTERVAL + 64;

    let counting_trace = Trace::new();
    let mut counting = Encoder::with_sink_and_observer(
        CountingSink::new(),
        TestObserver::continuing(&counting_trace),
    )
    .unwrap();
    encode_null_array(&mut counting, elements).unwrap();
    let counted = counting.finish().unwrap();

    let vector_trace = Trace::new();
    let mut vector =
        Encoder::with_sink_and_observer(VecSink::new(), TestObserver::continuing(&vector_trace))
            .unwrap();
    encode_null_array(&mut vector, elements).unwrap();
    let bytes = vector.finish().unwrap();

    counting_trace.assert_same_as(&vector_trace);
    assert!(counting_trace.calls() >= 3);
    assert_eq!(counting_trace.completed(0), 0);
    for call in 1..counting_trace.calls() - 1 {
        assert_eq!(counting_trace.completed(call), WORK_CHECKPOINT_INTERVAL);
    }
    assert!(counting_trace.completed(counting_trace.calls() - 1) > 0);
    assert!(counting_trace.completed(counting_trace.calls() - 1) <= WORK_CHECKPOINT_INTERVAL);
    assert_eq!(counted, bytes.len());
}

#[test]
fn encoder_cancellation_keeps_a_strict_confirmed_output_prefix() {
    let elements = WORK_CHECKPOINT_INTERVAL + 64;
    let complete = unobserved_null_array(elements);
    let trace = Trace::new();
    let mut encoder = Encoder::with_sink_and_observer(
        VecSink::new(),
        TestObserver::cancel_on_second_call(&trace),
    )
    .unwrap();

    let error = encode_null_array(&mut encoder, elements).unwrap_err();
    trace.assert_started_then_completed_one_interval();
    assert!(matches!(
        error,
        EncodeError::Cbor(error)
            if error.code == ErrorCode::WorkCancelled && error.offset == encoder.len()
    ));
    let prefix = encoder.as_bytes();
    assert!(prefix.len() > 3);
    assert!(prefix.len() < complete.len());
    assert_eq!(prefix, &complete[..prefix.len()]);

    let stopped_at = encoder.len();
    let calls = trace.calls();
    assert!(matches!(encoder.null(), Err(EncodeError::Poisoned)));
    assert_eq!(encoder.len(), stopped_at);
    assert_eq!(trace.calls(), calls);
    assert!(matches!(encoder.finish(), Err(EncodeError::Poisoned)));
}

#[test]
fn canonical_text_cancels_at_a_confirmed_utf8_boundary_after_validation_started() {
    let payload_len = WORK_CHECKPOINT_INTERVAL + 64;
    let mut bytes = Vec::with_capacity(payload_len + 3);
    append_u16_text(&mut bytes, &vec![b'a'; payload_len]);
    let trace = Trace::new();

    let error = validate_canonical_observed(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        TestObserver::cancel_on_second_call(&trace),
    )
    .unwrap_err();

    trace.assert_started_then_completed_one_interval();
    assert_eq!(error.code, ErrorCode::WorkCancelled);
    assert_eq!(error.offset, 3 + WORK_CHECKPOINT_INTERVAL);
    assert!(error.offset > 3, "UTF-8 validation must have started");
    assert!(
        error.offset < bytes.len(),
        "the payload tail must remain unread"
    );
    validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
}

#[test]
fn typed_text_cancellation_offset_is_a_multibyte_code_point_boundary() {
    let payload = "🦀".repeat(WORK_CHECKPOINT_INTERVAL / 4 + 16);
    let mut bytes = Vec::with_capacity(payload.len() + 3);
    append_u16_text(&mut bytes, payload.as_bytes());
    let trace = Trace::new();

    let error = decode_with_observer::<&str, _>(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        TestObserver::cancel_on_second_call(&trace),
    )
    .unwrap_err();

    trace.assert_started_then_completed_one_interval();
    assert_eq!(error.code, ErrorCode::WorkCancelled);
    assert_eq!(error.offset, 3 + WORK_CHECKPOINT_INTERVAL);
    assert!(error.offset < bytes.len());
    assert!(core::str::from_utf8(&bytes[3..error.offset]).is_ok());
}

#[test]
fn canonical_map_cancels_inside_a_long_common_prefix_key_comparison() {
    const KEY_LEN: usize = 1365;
    let first = vec![b'a'; KEY_LEN];
    let mut second = first.clone();
    second[KEY_LEN - 1] = b'b';

    let mut bytes = Vec::with_capacity(1 + 2 * (3 + KEY_LEN + 1));
    bytes.push(0xa2);
    append_u16_text(&mut bytes, &first);
    bytes.push(0xf6);
    append_u16_text(&mut bytes, &second);
    let second_key_end = bytes.len();
    bytes.push(0xf6);

    // Before comparison, the walker has charged the map/item structural work plus both UTF-8
    // payloads, still below one interval. The encoded common prefix crosses that interval, so the
    // second callback can only originate inside the comparison loop.
    let work_before_comparison = 2 * KEY_LEN + 3;
    let encoded_common_prefix = 3 + KEY_LEN - 1;
    assert!(work_before_comparison < WORK_CHECKPOINT_INTERVAL);
    assert!(work_before_comparison + encoded_common_prefix > WORK_CHECKPOINT_INTERVAL);

    let trace = Trace::new();
    let error = validate_canonical_observed(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        TestObserver::cancel_on_second_call(&trace),
    )
    .unwrap_err();

    trace.assert_started_then_completed_one_interval();
    assert_eq!(error.code, ErrorCode::WorkCancelled);
    assert_eq!(error.offset, second_key_end);
    assert_eq!(second_key_end, bytes.len() - 1);
    validate_canonical(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
}

#[test]
fn sorted_scalar_comparison_cancels_after_scanning_a_long_common_prefix() {
    let payload_len = WORK_CHECKPOINT_INTERVAL;
    let first = vec![b'a'; payload_len];
    let mut second = first.clone();
    second[payload_len - 1] = b'b';
    let mut bytes = Vec::with_capacity(1 + 2 * (3 + payload_len));
    bytes.push(0x82);
    append_u16_bytes(&mut bytes, &first);
    append_u16_bytes(&mut bytes, &second);

    // Four structural units precede the comparison; the common prefix is long enough that the
    // interval callback occurs before the differing final payload byte is examined.
    assert!(4 + (3 + payload_len - 1) > WORK_CHECKPOINT_INTERVAL);

    let trace = Trace::new();
    let mut decoder = Decoder::<true, _>::new_checked_observed(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        TestObserver::cancel_on_second_call(&trace),
    )
    .unwrap();
    {
        let mut array = decoder.array().unwrap();
        let error = array.skip_sorted_scalars(ScalarKind::Bytes).unwrap_err();
        trace.assert_started_then_completed_one_interval();
        assert_eq!(error.code, ErrorCode::WorkCancelled);
        assert_eq!(error.offset, bytes.len());
        assert_eq!(array.position(), bytes.len());
    }
    assert_eq!(decoder.finish().unwrap_err().code, ErrorCode::WorkCancelled);
}

#[cfg(feature = "derive")]
fn assert_derived_raw_payload_decode_is_observed<T>(value: &T)
where
    T: core::fmt::Debug + sacp_cbor::CborEncode + for<'de> sacp_cbor::CborDecode<'de>,
{
    let body = "x".repeat(WORK_CHECKPOINT_INTERVAL + 512);
    let bytes = sacp_cbor::encode_to_vec(value).unwrap();
    let payload_start = bytes
        .windows(body.len())
        .position(|window| window == body.as_bytes())
        .expect("derived fixture contains its long text payload");
    let payload_end = payload_start + body.len();
    let trace = Trace::new();

    let error = decode_with_observer::<T, _>(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        TestObserver::cancel_on_call(&trace, 3),
    )
    .unwrap_err();

    assert_eq!(trace.calls(), 3);
    assert_eq!(trace.completed(0), 0);
    assert_eq!(trace.completed(1), WORK_CHECKPOINT_INTERVAL);
    assert_eq!(trace.completed(2), WORK_CHECKPOINT_INTERVAL);
    assert_eq!(error.code, ErrorCode::WorkCancelled);
    assert!(
        error.offset > payload_start && error.offset < payload_end,
        "cancellation must occur while the derived second-pass payload decode is in progress"
    );
}

#[cfg(feature = "derive")]
#[test]
fn internally_tagged_derive_reuses_the_outer_observer_for_raw_fields() {
    let value = ObservedInternalEnum::Large {
        body: "x".repeat(WORK_CHECKPOINT_INTERVAL + 512),
    };
    assert_derived_raw_payload_decode_is_observed(&value);
}

#[cfg(feature = "derive")]
#[test]
fn derived_raw_decode_preserves_the_outer_cadence_across_a_short_payload() {
    let body = "x".repeat(WORK_CHECKPOINT_INTERVAL / 2 + 64);
    let value = ObservedInternalEnum::Large { body: body.clone() };
    let bytes = sacp_cbor::encode_to_vec(&value).unwrap();
    let payload_start = bytes
        .windows(body.len())
        .position(|window| window == body.as_bytes())
        .expect("derived fixture contains its short text payload");
    let payload_end = payload_start + body.len();
    assert!(payload_end < bytes.len(), "the tag follows the body field");
    let trace = Trace::new();

    let error = decode_with_observer::<ObservedInternalEnum, _>(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        TestObserver::cancel_on_second_call(&trace),
    )
    .unwrap_err();

    trace.assert_started_then_completed_one_interval();
    assert_eq!(error.code, ErrorCode::WorkCancelled);
    assert!(
        error.offset > payload_start && error.offset < payload_end,
        "the nested decode must reach the outer cadence before finishing its own short payload"
    );
}

#[cfg(feature = "derive")]
#[test]
fn derived_nested_cancellation_remains_the_parent_decoders_first_error() {
    let value = ObservedInternalEnum::Large {
        body: "x".repeat(WORK_CHECKPOINT_INTERVAL + 512),
    };
    let bytes = {
        let mut encoder = Encoder::new();
        encoder.array(1, |array| array.value(&value)).unwrap();
        encoder.finish().unwrap()
    };
    let trace = Trace::new();
    let mut decoder = Decoder::<true, _>::new_checked_observed(
        &bytes,
        DecodeLimits::for_bytes(bytes.len()),
        TestObserver::cancel_on_call(&trace, 3),
    )
    .unwrap();

    let first = {
        let mut array = decoder.array().unwrap();
        array.next_value::<ObservedInternalEnum>().unwrap_err()
    };
    let later = decoder.finish().unwrap_err();

    assert_eq!(trace.calls(), 3);
    assert_eq!(first.code, ErrorCode::WorkCancelled);
    assert!(first.offset < bytes.len());
    assert_eq!(later, first);
}

#[cfg(feature = "derive")]
#[test]
fn adjacently_tagged_derive_reuses_the_outer_observer_for_raw_content() {
    let value = ObservedAdjacentEnum::Large {
        body: "x".repeat(WORK_CHECKPOINT_INTERVAL + 512),
    };
    assert_derived_raw_payload_decode_is_observed(&value);
}
