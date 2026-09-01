use crate::view::{validate_abi_id_value, validate_sorted_query_ids};
use crate::{
    encode_to_sink, projected_sequence, wire, AbiEncode, AbiEncodeAs, AbiEncodeError,
    SequenceContractError, SequenceEmitter, SequenceProjection, TypeAtom, TypeRef,
};
use core::convert::Infallible;
use sacp_cbor::{ByteSink, CborError, CountingSink, EncodeLimits, ErrorCode, ValueEncoder};

fn assert_err<T>(actual: Result<T, CborError>, expected: ErrorCode) {
    match actual {
        Err(err) => assert!(err.code == expected),
        Ok(_) => unreachable!(),
    }
}

#[kani::proof]
fn abi_id_validator_accepts_exact_nonzero_u32_range() {
    let id: i64 = kani::any();
    let offset: usize = kani::any();
    let actual = validate_abi_id_value(id, offset);

    if id > 0 && id <= u32::MAX as i64 {
        let decoded = actual.unwrap();
        assert!(decoded != 0);
        assert!(i64::from(decoded) == id);
    } else {
        assert_err(actual, ErrorCode::InvalidAbiValue);
    }
}

#[kani::proof]
fn sorted_query_ids_accepts_exact_nonzero_singleton() {
    let id: u32 = kani::any();
    let offset: usize = kani::any();
    let ids = [id];
    let actual = validate_sorted_query_ids(&ids, offset);

    if id == 0 {
        assert_err(actual, ErrorCode::InvalidQuery);
    } else {
        assert!(actual.is_ok());
    }
}

#[kani::proof]
#[kani::unwind(4)]
fn sorted_query_ids_accepts_exact_strict_nonzero_order_for_len3() {
    let ids = [kani::any::<u32>(), kani::any::<u32>(), kani::any::<u32>()];
    let offset: usize = kani::any();
    let actual = validate_sorted_query_ids(&ids, offset);
    let valid = ids[0] != 0 && ids[1] != 0 && ids[2] != 0 && ids[0] < ids[1] && ids[1] < ids[2];

    if valid {
        assert!(actual.is_ok());
    } else {
        assert_err(actual, ErrorCode::InvalidQuery);
    }
}

#[kani::proof]
#[kani::unwind(5)]
fn protocol_sequence_depth_roundtrips_without_a_collection_type() {
    let depth: u32 = kani::any();
    kani::assume(depth <= 3);
    let mut ty = TypeRef::U64;
    let mut wrapped = 0;
    while wrapped < depth {
        ty = TypeRef::sequence(ty);
        wrapped += 1;
    }
    assert!(ty.sequence_depth() == depth);
    assert!(ty.terminal() == TypeAtom::U64);

    let mut peeled = 0;
    while let Some(item) = ty.sequence_item() {
        ty = item;
        peeled += 1;
    }
    assert!(peeled == depth);
    assert!(ty == TypeRef::U64);
}

#[derive(Clone, Copy)]
struct BoundedSequenceSource {
    declared: usize,
    actual: usize,
    swallow_emit_errors: bool,
}

impl SequenceProjection<wire::U8> for BoundedSequenceSource {
    type Error = Infallible;

    fn declared_len(&self) -> Result<usize, Self::Error> {
        Ok(self.declared)
    }

    fn project<S: ByteSink>(
        &self,
        emitter: &mut SequenceEmitter<'_, '_, S, wire::U8, Self::Error>,
    ) -> Result<(), AbiEncodeError<S::Error, Self::Error>> {
        let mut emitted = 0;
        while emitted < self.actual {
            let result = emitter.emit(&0_u8);
            if !self.swallow_emit_errors {
                result?;
            }
            emitted += 1;
        }
        Ok(())
    }
}

struct BoundedSequenceRoot(BoundedSequenceSource);

impl AbiEncode for BoundedSequenceRoot {
    type Error = Infallible;

    fn abi_encode<S: ByteSink>(
        &self,
        encoder: &mut ValueEncoder<'_, S>,
    ) -> Result<(), AbiEncodeError<S::Error, Self::Error>> {
        projected_sequence(self.0).abi_encode_as(encoder)
    }
}

#[kani::proof]
#[kani::unwind(5)]
fn exact_sequence_encoding_succeeds_if_and_only_if_cardinality_matches() {
    let declared: usize = kani::any();
    let actual: usize = kani::any();
    let swallow_emit_errors: bool = kani::any();
    kani::assume(declared <= 3);
    kani::assume(actual <= 3);

    let result = encode_to_sink(
        &BoundedSequenceRoot(BoundedSequenceSource {
            declared,
            actual,
            swallow_emit_errors,
        }),
        CountingSink::new(),
        EncodeLimits::unbounded(),
    );

    if declared == actual {
        assert!(result.is_ok());
    } else {
        assert!(result.is_err());
        if actual < declared {
            assert!(matches!(
                result,
                Err(AbiEncodeError::Sequence(SequenceContractError::Underfill {
                    declared: expected,
                    emitted,
                })) if expected == declared && emitted == actual
            ));
        } else if !swallow_emit_errors {
            assert!(matches!(
                result,
                Err(AbiEncodeError::Sequence(SequenceContractError::Overfill {
                    declared: expected,
                    attempted,
                })) if expected == declared && attempted == declared + 1
            ));
        }
    }
}
