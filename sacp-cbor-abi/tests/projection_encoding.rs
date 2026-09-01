use core::cell::Cell;
use core::convert::Infallible;

use sacp_cbor::encode::{CountingSink, Encoder};
use sacp_cbor::{DigestSink, EncodeError, EncodeLimits, ErrorCode, FanoutSink, VecSink};
use sacp_cbor_abi::{
    encode_to_sink, encode_to_vec, exact_indexed_sequence, projected_sequence, wire, AbiEncode,
    AbiEncodeError, AbiType, CborAbi, ExactIndexProjection, ExactIndexedSequence,
    ProjectedSequence, SequenceContractError, SequenceEmitter, SequenceProjection,
};

fn limits() -> EncodeLimits {
    EncodeLimits::unbounded()
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "tests.Batch", version = 1)]
struct Batch {
    #[abi(id = 3, optional)]
    note: Option<String>,
    #[abi(id = 1)]
    topic: String,
    #[abi(id = 2)]
    items: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionFailure {
    Refused,
    MissingIndex,
}

struct SliceBatch<'a> {
    topic: &'a str,
    items: &'a [u64],
    note: Option<&'a str>,
}

impl BatchAbiProjection for SliceBatch<'_> {
    type Error = ProjectionFailure;
    type FieldTopic<'a>
        = &'a str
    where
        Self: 'a;
    type FieldItems<'a>
        = &'a [u64]
    where
        Self: 'a;
    type FieldNote<'a>
        = &'a str
    where
        Self: 'a;

    fn topic(&self) -> Result<Self::FieldTopic<'_>, Self::Error> {
        Ok(self.topic)
    }

    fn items(&self) -> Result<Self::FieldItems<'_>, Self::Error> {
        Ok(self.items)
    }

    fn note(&self) -> Result<Option<Self::FieldNote<'_>>, Self::Error> {
        Ok(self.note)
    }
}

struct IndexSource<'a>(&'a [u64]);

impl<'a> ExactIndexProjection for IndexSource<'a> {
    type Error = ProjectionFailure;
    type Item = &'a u64;

    fn len(&self) -> usize {
        self.0.len()
    }

    fn project(&self, index: usize) -> Result<Self::Item, Self::Error> {
        self.0.get(index).ok_or(ProjectionFailure::MissingIndex)
    }
}

struct IndexedBatch<'a> {
    topic: &'a str,
    items: &'a [u64],
    note: Option<&'a str>,
}

impl BatchAbiProjection for IndexedBatch<'_> {
    type Error = ProjectionFailure;
    type FieldTopic<'a>
        = &'a str
    where
        Self: 'a;
    type FieldItems<'a>
        = ExactIndexedSequence<IndexSource<'a>>
    where
        Self: 'a;
    type FieldNote<'a>
        = &'a str
    where
        Self: 'a;

    fn topic(&self) -> Result<Self::FieldTopic<'_>, Self::Error> {
        Ok(self.topic)
    }

    fn items(&self) -> Result<Self::FieldItems<'_>, Self::Error> {
        Ok(exact_indexed_sequence(IndexSource(self.items)))
    }

    fn note(&self) -> Result<Option<Self::FieldNote<'_>>, Self::Error> {
        Ok(self.note)
    }
}

struct EmittingSource<'a> {
    values: &'a [u64],
    declared: usize,
    swallow_overfill: bool,
}

impl SequenceProjection<wire::U64> for EmittingSource<'_> {
    type Error = ProjectionFailure;

    fn declared_len(&self) -> Result<usize, Self::Error> {
        Ok(self.declared)
    }

    fn project<S: sacp_cbor::ByteSink>(
        &self,
        emitter: &mut SequenceEmitter<'_, '_, S, wire::U64, Self::Error>,
    ) -> Result<(), AbiEncodeError<S::Error, Self::Error>> {
        for value in self.values {
            let result = emitter.emit(value);
            if self.swallow_overfill
                && matches!(
                    result,
                    Err(AbiEncodeError::Sequence(
                        SequenceContractError::Overfill { .. }
                    ))
                )
            {
                continue;
            }
            result?;
        }
        Ok(())
    }
}

struct EmittingBatch<'a> {
    topic: &'a str,
    source: EmittingSource<'a>,
    note: Option<&'a str>,
}

impl BatchAbiProjection for EmittingBatch<'_> {
    type Error = ProjectionFailure;
    type FieldTopic<'a>
        = &'a str
    where
        Self: 'a;
    type FieldItems<'a>
        = ProjectedSequence<EmittingSource<'a>>
    where
        Self: 'a;
    type FieldNote<'a>
        = &'a str
    where
        Self: 'a;

    fn topic(&self) -> Result<Self::FieldTopic<'_>, Self::Error> {
        Ok(self.topic)
    }

    fn items(&self) -> Result<Self::FieldItems<'_>, Self::Error> {
        Ok(projected_sequence(EmittingSource {
            values: self.source.values,
            declared: self.source.declared,
            swallow_overfill: self.source.swallow_overfill,
        }))
    }

    fn note(&self) -> Result<Option<Self::FieldNote<'_>>, Self::Error> {
        Ok(self.note)
    }
}

struct FailingBatch;

impl BatchAbiProjection for FailingBatch {
    type Error = ProjectionFailure;
    type FieldTopic<'a> = &'a str;
    type FieldItems<'a> = &'a [u64];
    type FieldNote<'a> = &'a str;

    fn topic(&self) -> Result<Self::FieldTopic<'_>, Self::Error> {
        Err(ProjectionFailure::Refused)
    }

    fn items(&self) -> Result<Self::FieldItems<'_>, Self::Error> {
        panic!("later projection getter must not run")
    }

    fn note(&self) -> Result<Option<Self::FieldNote<'_>>, Self::Error> {
        panic!("later projection getter must not run")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, CborAbi)]
#[abi(type_id = "tests.Command", version = 1)]
enum Command {
    #[abi(id = 1)]
    Ping,
    #[abi(id = 2)]
    Put {
        #[abi(id = 1)]
        key: String,
        #[abi(id = 2)]
        values: Vec<u64>,
    },
}

enum BusinessCommand<'a> {
    Ping,
    Put { key: &'a str, values: &'a [u64] },
    Refused,
}

impl CommandAbiProjection for BusinessCommand<'_> {
    type Error = ProjectionFailure;

    fn project_variant<V>(&self, visitor: V) -> V::Output
    where
        V: CommandAbiVariantVisitor<Self::Error>,
    {
        match self {
            Self::Ping => visitor.ping(),
            Self::Put { key, values } => visitor.put(*key, *values),
            Self::Refused => visitor.projection_error(ProjectionFailure::Refused),
        }
    }
}

#[test]
fn owned_slice_indexed_and_source_driven_projections_are_byte_identical() {
    let values = [0, 1, 23, 24, 255, 256, u64::MAX];
    let owned = Batch {
        topic: "events".to_owned(),
        items: values.to_vec(),
        note: Some("ready".to_owned()),
    };
    let slice = SliceBatch {
        topic: "events",
        items: &values,
        note: Some("ready"),
    };
    let indexed = IndexedBatch {
        topic: "events",
        items: &values,
        note: Some("ready"),
    };
    let emitted = EmittingBatch {
        topic: "events",
        source: EmittingSource {
            values: &values,
            declared: values.len(),
            swallow_overfill: false,
        },
        note: Some("ready"),
    };

    let expected = encode_to_vec(&owned, limits()).unwrap();
    assert_eq!(
        encode_to_vec(&BatchAbiProjected::new(&slice), limits()).unwrap(),
        expected
    );
    assert_eq!(
        encode_to_vec(&BatchAbiProjected::new(&indexed), limits()).unwrap(),
        expected
    );
    assert_eq!(
        encode_to_vec(&BatchAbiProjected::new(&emitted), limits()).unwrap(),
        expected
    );
    let (fanout_bytes, digest) = encode_to_sink(
        &BatchAbiProjected::new(&slice),
        FanoutSink::new(
            VecSink::new(),
            DigestSink::new(<sha2::Sha256 as sha2::Digest>::new()),
        ),
        limits(),
    )
    .unwrap();
    assert_eq!(fanout_bytes, expected);
    assert_eq!(
        digest.as_slice(),
        <sha2::Sha256 as sha2::Digest>::digest(&expected).as_slice()
    );
    assert_eq!(Batch::schema(), Batch::SCHEMA);
    assert_eq!(
        Batch::SCHEMA.wire_hash(limits()).unwrap(),
        Batch::schema().wire_hash(limits()).unwrap()
    );
}

#[test]
fn semantic_enum_visitor_matches_owned_wire_bytes_and_preserves_typed_errors() {
    let values = [7, 8, 9];
    let owned = Command::Put {
        key: "alpha".to_owned(),
        values: values.to_vec(),
    };
    let projected = BusinessCommand::Put {
        key: "alpha",
        values: &values,
    };
    assert_eq!(
        encode_to_vec(&CommandAbiProjected::new(&projected), limits()).unwrap(),
        encode_to_vec(&owned, limits()).unwrap()
    );
    assert_eq!(
        encode_to_vec(&CommandAbiProjected::new(&BusinessCommand::Ping), limits()).unwrap(),
        encode_to_vec(&Command::Ping, limits()).unwrap()
    );
    assert_eq!(
        encode_to_vec(
            &CommandAbiProjected::new(&BusinessCommand::Refused),
            limits()
        ),
        Err(AbiEncodeError::Projection(ProjectionFailure::Refused))
    );
}

#[test]
fn source_underfill_and_overfill_are_typed_and_sticky() {
    let values = [1, 2, 3];
    let under = EmittingBatch {
        topic: "x",
        source: EmittingSource {
            values: &values[..2],
            declared: 3,
            swallow_overfill: false,
        },
        note: None,
    };
    assert_eq!(
        encode_to_vec(&BatchAbiProjected::new(&under), limits()),
        Err(AbiEncodeError::Sequence(SequenceContractError::Underfill {
            declared: 3,
            emitted: 2,
        }))
    );

    let over = EmittingBatch {
        topic: "x",
        source: EmittingSource {
            values: &values,
            declared: 2,
            swallow_overfill: false,
        },
        note: None,
    };
    assert_eq!(
        encode_to_vec(&BatchAbiProjected::new(&over), limits()),
        Err(AbiEncodeError::Sequence(SequenceContractError::Overfill {
            declared: 2,
            attempted: 3,
        }))
    );

    let swallowed = EmittingBatch {
        topic: "x",
        source: EmittingSource {
            values: &values,
            declared: 2,
            swallow_overfill: true,
        },
        note: None,
    };
    assert_eq!(
        encode_to_vec(&BatchAbiProjected::new(&swallowed), limits()),
        Err(AbiEncodeError::Encode(EncodeError::Poisoned))
    );
}

#[test]
fn projection_failure_is_typed_stops_later_getters_and_poisons_the_encoder() {
    let value = BatchAbiProjected::new(&FailingBatch);
    let mut encoder = Encoder::with_sink_and_limits(CountingSink::new(), limits()).unwrap();
    let error = encoder
        .encode_with_caller_error(|enc| value.abi_encode(enc))
        .unwrap_err();
    assert_eq!(
        error,
        AbiEncodeError::Projection(ProjectionFailure::Refused)
    );
    assert_eq!(
        encoder.encode_with_caller_error::<AbiEncodeError<_, ProjectionFailure>, _>(|enc| {
            enc.null().map_err(AbiEncodeError::Encode)
        }),
        Err(AbiEncodeError::Encode(EncodeError::Poisoned))
    );
}

struct MutatingSource<'a> {
    values: &'a [u64],
    declared: Cell<usize>,
}

impl SequenceProjection<wire::U64> for MutatingSource<'_> {
    type Error = Infallible;

    fn declared_len(&self) -> Result<usize, Self::Error> {
        Ok(self.declared.get())
    }

    fn project<S: sacp_cbor::ByteSink>(
        &self,
        emitter: &mut SequenceEmitter<'_, '_, S, wire::U64, Self::Error>,
    ) -> Result<(), AbiEncodeError<S::Error, Self::Error>> {
        self.declared.set(1);
        for value in self.values.iter().take(self.declared.get()) {
            emitter.emit(value)?;
        }
        Ok(())
    }
}

#[test]
fn interior_length_mutation_cannot_produce_a_successful_value() {
    let source = projected_sequence(MutatingSource {
        values: &[1, 2],
        declared: Cell::new(2),
    });
    let mut encoder = Encoder::with_sink_and_limits(CountingSink::new(), limits()).unwrap();
    let error = encoder
        .encode_with_caller_error(|enc| {
            sacp_cbor_abi::AbiEncodeAs::<wire::Sequence<wire::U64>, Infallible>::abi_encode_as(
                &source, enc,
            )
        })
        .unwrap_err();
    assert_eq!(
        error,
        AbiEncodeError::Sequence(SequenceContractError::Underfill {
            declared: 2,
            emitted: 1,
        })
    );
}

#[test]
fn impossible_sequence_length_fails_before_projection() {
    struct NeverCalled;
    impl ExactIndexProjection for NeverCalled {
        type Error = ProjectionFailure;
        type Item = u64;

        fn len(&self) -> usize {
            usize::MAX
        }

        fn project(&self, _index: usize) -> Result<Self::Item, Self::Error> {
            panic!("array preflight must reject before projection")
        }
    }

    let source = exact_indexed_sequence(NeverCalled);
    let error = encode_to_sink(&DirectSequence(source), CountingSink::new(), limits()).unwrap_err();
    assert_eq!(
        error,
        AbiEncodeError::Encode(EncodeError::Cbor(sacp_cbor::CborError::new(
            ErrorCode::LengthOverflow,
            0,
        )))
    );
}

struct DirectSequence<T>(T);

impl<T> AbiEncode for DirectSequence<T>
where
    T: sacp_cbor_abi::AbiEncodeAs<wire::Sequence<wire::U64>, ProjectionFailure>,
{
    type Error = ProjectionFailure;

    fn abi_encode<S: sacp_cbor::ByteSink>(
        &self,
        enc: &mut sacp_cbor::ValueEncoder<'_, S>,
    ) -> Result<(), AbiEncodeError<S::Error, Self::Error>> {
        sacp_cbor_abi::AbiEncodeAs::<wire::Sequence<wire::U64>, Self::Error>::abi_encode_as(
            &self.0, enc,
        )
    }
}
