#![no_main]

use core::convert::Infallible;

use libfuzzer_sys::fuzz_target;
use sacp_cbor::{ByteSink, EncodeLimits, ValueEncoder};
use sacp_cbor_abi::{
    projected_sequence, wire, AbiEncode, AbiEncodeAs, AbiEncodeError, SequenceContractError,
    SequenceEmitter, SequenceProjection,
};

struct Source<'a> {
    declared: usize,
    items: &'a [u8],
}

impl SequenceProjection<wire::U8> for Source<'_> {
    type Error = Infallible;

    fn declared_len(&self) -> Result<usize, Self::Error> {
        Ok(self.declared)
    }

    fn project<S: ByteSink>(
        &self,
        emitter: &mut SequenceEmitter<'_, '_, S, wire::U8, Self::Error>,
    ) -> Result<(), AbiEncodeError<S::Error, Self::Error>> {
        for item in self.items {
            emitter.emit(item)?;
        }
        Ok(())
    }
}

struct Root<P>(P);

impl<P> AbiEncode for Root<P>
where
    P: AbiEncodeAs<wire::Sequence<wire::U8>, Infallible>,
{
    type Error = Infallible;

    fn abi_encode<S: ByteSink>(
        &self,
        encoder: &mut ValueEncoder<'_, S>,
    ) -> Result<(), AbiEncodeError<S::Error, Self::Error>> {
        self.0.abi_encode_as(encoder)
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&declared_byte, payload)) = data.split_first() else {
        return;
    };
    let declared = usize::from(declared_byte % 33);
    let actual = payload.len().min(32);
    let items = &payload[..actual];
    let value = Root(projected_sequence(Source { declared, items }));
    let result = sacp_cbor_abi::encode_to_vec(&value, EncodeLimits::for_bytes(128));

    match actual.cmp(&declared) {
        core::cmp::Ordering::Equal => {
            let encoded = result.expect("matching exact source must encode");
            let expected = sacp_cbor::encode_to_vec(&items.to_vec()).unwrap();
            assert_eq!(encoded, expected);
        }
        core::cmp::Ordering::Less => assert!(matches!(
            result,
            Err(AbiEncodeError::Sequence(SequenceContractError::Underfill {
                declared: expected,
                emitted,
            })) if expected == declared && emitted == actual
        )),
        core::cmp::Ordering::Greater => assert!(matches!(
            result,
            Err(AbiEncodeError::Sequence(SequenceContractError::Overfill {
                declared: expected,
                attempted,
            })) if expected == declared && attempted == declared + 1
        )),
    }
});
