//! Storage-independent ABI encoding, semantic projections, and exact protocol sequences.

use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt;
use core::marker::PhantomData;

use sacp_cbor::bytes::{Bytes, BytesRef};
use sacp_cbor::encode::ArrayEncoder;
use sacp_cbor::{
    ByteSink, CanonicalCbor, CanonicalCborRef, CborError, DecodeLimits, EncodeError, EncodeLimits,
    Encoder, NoopWorkObserver, ValueEncoder, VecSink, WorkObserver,
};

use crate::{TypeRef, UnknownFields, UnknownVariant};

/// Marker types for protocol wire shapes.
///
/// They contain no storage and are used only to prove that a Rust carrier encodes the schema-owned
/// wire type selected by a derive-generated semantic driver.
pub mod wire {
    use core::marker::PhantomData;

    /// Unit/null wire type.
    pub struct Unit;
    /// Boolean wire type.
    pub struct Bool;
    /// Unsigned 8-bit integer wire type.
    pub struct U8;
    /// Unsigned 16-bit integer wire type.
    pub struct U16;
    /// Unsigned 32-bit integer wire type.
    pub struct U32;
    /// Unsigned 64-bit integer wire type.
    pub struct U64;
    /// Signed 8-bit integer wire type.
    pub struct I8;
    /// Signed 16-bit integer wire type.
    pub struct I16;
    /// Signed 32-bit integer wire type.
    pub struct I32;
    /// Signed 64-bit integer wire type.
    pub struct I64;
    /// UTF-8 text wire type.
    pub struct Text;
    /// Byte-string wire type.
    pub struct Bytes;
    /// Exact-length byte-string wire type.
    pub struct FixedBytes<const N: usize>;
    /// Canonical CBOR sub-value wire type.
    pub struct CanonicalCbor;
    /// Homogeneous protocol sequence, independent of any Rust collection.
    pub struct Sequence<W>(pub(crate) PhantomData<fn() -> W>);
}

/// A storage-independent wire type with a static schema reference.
pub trait AbiWireType {
    /// Protocol type reference.
    const TYPE_REF: TypeRef;
}

/// Maps a Rust storage representation to its protocol wire type.
pub trait AbiRepresentation {
    /// Wire type encoded by this storage representation.
    type Wire: AbiWireType;
}

/// A declared/observed sequence cardinality mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceContractError {
    /// The source stopped before its declared count.
    Underfill {
        /// Declared number of items.
        declared: usize,
        /// Number emitted before the source returned.
        emitted: usize,
    },
    /// The source attempted to emit more than its declared count.
    Overfill {
        /// Declared number of items.
        declared: usize,
        /// One-based number of the attempted item.
        attempted: usize,
    },
}

impl fmt::Display for SequenceContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Underfill { declared, emitted } => {
                write!(
                    formatter,
                    "ABI sequence declared {declared} items but emitted {emitted}"
                )
            }
            Self::Overfill {
                declared,
                attempted,
            } => write!(
                formatter,
                "ABI sequence declared {declared} items but attempted item {attempted}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SequenceContractError {}

/// Typed failure of one ABI encoding transaction.
#[derive(Debug, PartialEq, Eq)]
pub enum AbiEncodeError<SinkError, ProjectionError> {
    /// Core profile, limit, sticky-poison, or owned sink failure.
    Encode(EncodeError<SinkError>),
    /// Caller-owned business projection failure.
    Projection(ProjectionError),
    /// Exact sequence source violated its declared cardinality.
    Sequence(SequenceContractError),
}

impl<SinkError, ProjectionError> AbiEncodeError<SinkError, ProjectionError> {
    /// Preserve a business projection error without erasing its type.
    #[must_use]
    pub const fn projection(error: ProjectionError) -> Self {
        Self::Projection(error)
    }
}

impl<SinkError, ProjectionError> From<EncodeError<SinkError>>
    for AbiEncodeError<SinkError, ProjectionError>
{
    fn from(error: EncodeError<SinkError>) -> Self {
        Self::Encode(error)
    }
}

impl<SinkError: fmt::Display, ProjectionError: fmt::Display> fmt::Display
    for AbiEncodeError<SinkError, ProjectionError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(error) => error.fmt(formatter),
            Self::Projection(error) => write!(formatter, "ABI projection failed: {error}"),
            Self::Sequence(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl<SinkError, ProjectionError> std::error::Error for AbiEncodeError<SinkError, ProjectionError>
where
    SinkError: std::error::Error + 'static,
    ProjectionError: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encode(error) => Some(error),
            Self::Projection(error) => Some(error),
            Self::Sequence(error) => Some(error),
        }
    }
}

/// Encode one carrier as a particular schema-owned wire type.
///
/// Derive-generated semantic projection traits constrain every associated carrier through this
/// trait, so a business adapter supplies values by field name while numeric field and variant IDs
/// remain private to the generated driver.
pub trait AbiEncodeAs<W: AbiWireType, ProjectionError> {
    /// Emit exactly one wire value.
    fn abi_encode_as<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, ProjectionError>>;
}

impl<W, ProjectionError, T> AbiEncodeAs<W, ProjectionError> for &T
where
    W: AbiWireType,
    T: AbiEncodeAs<W, ProjectionError> + ?Sized,
{
    fn abi_encode_as<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, ProjectionError>> {
        (*self).abi_encode_as(enc)
    }
}

/// A complete ABI value with a caller-visible projection error type.
pub trait AbiEncode {
    /// Business projection failure, or [`Infallible`] for ordinary owned values.
    type Error;

    /// Emit exactly one canonical ABI value.
    fn abi_encode<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, Self::Error>>;
}

impl<T> AbiEncode for T
where
    T: AbiRepresentation + AbiEncodeAs<T::Wire, Infallible> + ?Sized,
{
    type Error = Infallible;

    fn abi_encode<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, Self::Error>> {
        self.abi_encode_as(enc)
    }
}

/// Encode directly into `sink` under caller-supplied limits.
pub fn encode_to_sink<T, S>(
    value: &T,
    sink: S,
    limits: EncodeLimits,
) -> Result<S::Output, AbiEncodeError<S::Error, T::Error>>
where
    T: AbiEncode + ?Sized,
    S: ByteSink,
{
    let mut encoder: Encoder<S, NoopWorkObserver> = Encoder::with_sink_and_limits(sink, limits)
        .map_err(|error| AbiEncodeError::Encode(EncodeError::Cbor(error)))?;
    encoder.encode_with_caller_error(|enc| value.abi_encode(enc))?;
    encoder.finish().map_err(AbiEncodeError::Encode)
}

/// Encode directly into `sink` with cooperative work observation under caller-supplied limits.
pub fn encode_to_sink_with_observer<T, S, O>(
    value: &T,
    sink: S,
    limits: EncodeLimits,
    observer: O,
) -> Result<S::Output, AbiEncodeError<S::Error, T::Error>>
where
    T: AbiEncode + ?Sized,
    S: ByteSink,
    O: WorkObserver,
{
    let mut encoder = Encoder::with_sink_limits_and_observer(sink, limits, observer)
        .map_err(|error| AbiEncodeError::Encode(EncodeError::Cbor(error)))?;
    encoder.encode_with_caller_error(|enc| value.abi_encode(enc))?;
    encoder.finish().map_err(AbiEncodeError::Encode)
}

/// Encode into a vector under caller-supplied limits.
pub fn encode_to_vec<T: AbiEncode + ?Sized>(
    value: &T,
    limits: EncodeLimits,
) -> Result<Vec<u8>, AbiEncodeError<CborError, T::Error>> {
    encode_to_sink(value, VecSink::new(), limits)
}

/// Encode into a vector with cooperative work observation under caller-supplied limits.
pub fn encode_to_vec_with_observer<T, O>(
    value: &T,
    limits: EncodeLimits,
    observer: O,
) -> Result<Vec<u8>, AbiEncodeError<CborError, T::Error>>
where
    T: AbiEncode + ?Sized,
    O: WorkObserver,
{
    encode_to_sink_with_observer(value, VecSink::new(), limits, observer)
}

/// Encode into an owned canonical witness under caller-supplied limits.
pub fn encode_to_canonical<T: AbiEncode + ?Sized>(
    value: &T,
    limits: EncodeLimits,
) -> Result<CanonicalCbor, AbiEncodeError<CborError, T::Error>> {
    let bytes = encode_to_vec(value, limits)?;
    let len = bytes.len();
    CanonicalCbor::from_vec(bytes, DecodeLimits::for_bytes(len))
        .map_err(|error| AbiEncodeError::Encode(EncodeError::Cbor(error)))
}

macro_rules! scalar_wire {
    ($storage:ty, $wire:ty, $type_ref:expr, $method:ident) => {
        impl AbiWireType for $wire {
            const TYPE_REF: TypeRef = $type_ref;
        }

        impl AbiRepresentation for $storage {
            type Wire = $wire;
        }

        impl<E> AbiEncodeAs<$wire, E> for $storage {
            fn abi_encode_as<S: ByteSink, O: WorkObserver>(
                &self,
                enc: &mut ValueEncoder<'_, S, O>,
            ) -> Result<(), AbiEncodeError<S::Error, E>> {
                enc.$method(*self).map_err(AbiEncodeError::Encode)
            }
        }
    };
}

impl AbiWireType for wire::Unit {
    const TYPE_REF: TypeRef = TypeRef::UNIT;
}

impl AbiRepresentation for () {
    type Wire = wire::Unit;
}

impl<E> AbiEncodeAs<wire::Unit, E> for () {
    fn abi_encode_as<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, E>> {
        enc.null().map_err(AbiEncodeError::Encode)
    }
}

scalar_wire!(bool, wire::Bool, TypeRef::BOOL, bool);

macro_rules! integer_wire {
    ($storage:ty, $wire:ty, $type_ref:expr, $convert:expr) => {
        impl AbiWireType for $wire {
            const TYPE_REF: TypeRef = $type_ref;
        }

        impl AbiRepresentation for $storage {
            type Wire = $wire;
        }

        impl<E> AbiEncodeAs<$wire, E> for $storage {
            fn abi_encode_as<S: ByteSink, O: WorkObserver>(
                &self,
                enc: &mut ValueEncoder<'_, S, O>,
            ) -> Result<(), AbiEncodeError<S::Error, E>> {
                ($convert)(enc, *self).map_err(AbiEncodeError::Encode)
            }
        }
    };
}

integer_wire!(
    u8,
    wire::U8,
    TypeRef::U8,
    |enc: &mut ValueEncoder<'_, S, O>, value| enc.int_u128(u128::from(value))
);
integer_wire!(
    u16,
    wire::U16,
    TypeRef::U16,
    |enc: &mut ValueEncoder<'_, S, O>, value| enc.int_u128(u128::from(value))
);
integer_wire!(
    u32,
    wire::U32,
    TypeRef::U32,
    |enc: &mut ValueEncoder<'_, S, O>, value| enc.int_u128(u128::from(value))
);
integer_wire!(
    u64,
    wire::U64,
    TypeRef::U64,
    |enc: &mut ValueEncoder<'_, S, O>, value| enc.int_u128(u128::from(value))
);
integer_wire!(
    i8,
    wire::I8,
    TypeRef::I8,
    |enc: &mut ValueEncoder<'_, S, O>, value| enc.int_i128(i128::from(value))
);
integer_wire!(
    i16,
    wire::I16,
    TypeRef::I16,
    |enc: &mut ValueEncoder<'_, S, O>, value| enc.int_i128(i128::from(value))
);
integer_wire!(
    i32,
    wire::I32,
    TypeRef::I32,
    |enc: &mut ValueEncoder<'_, S, O>, value| enc.int_i128(i128::from(value))
);
integer_wire!(
    i64,
    wire::I64,
    TypeRef::I64,
    |enc: &mut ValueEncoder<'_, S, O>, value| enc.int_i128(i128::from(value))
);

impl AbiWireType for wire::Text {
    const TYPE_REF: TypeRef = TypeRef::TEXT;
}

impl AbiRepresentation for str {
    type Wire = wire::Text;
}

impl AbiRepresentation for String {
    type Wire = wire::Text;
}

impl AbiRepresentation for &str {
    type Wire = wire::Text;
}

impl<E> AbiEncodeAs<wire::Text, E> for str {
    fn abi_encode_as<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, E>> {
        enc.text(self).map_err(AbiEncodeError::Encode)
    }
}

impl<E> AbiEncodeAs<wire::Text, E> for String {
    fn abi_encode_as<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, E>> {
        self.as_str().abi_encode_as(enc)
    }
}

impl AbiWireType for wire::Bytes {
    const TYPE_REF: TypeRef = TypeRef::BYTES;
}

impl AbiRepresentation for Bytes {
    type Wire = wire::Bytes;
}

impl AbiRepresentation for BytesRef<'_> {
    type Wire = wire::Bytes;
}

impl<E> AbiEncodeAs<wire::Bytes, E> for Bytes {
    fn abi_encode_as<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, E>> {
        enc.bytes(self.as_slice()).map_err(AbiEncodeError::Encode)
    }
}

impl<E> AbiEncodeAs<wire::Bytes, E> for BytesRef<'_> {
    fn abi_encode_as<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, E>> {
        enc.bytes(self.as_slice()).map_err(AbiEncodeError::Encode)
    }
}

impl<const N: usize> AbiWireType for wire::FixedBytes<N> {
    const TYPE_REF: TypeRef = TypeRef::fixed_bytes(N as u64);
}

impl<const N: usize> AbiRepresentation for [u8; N] {
    type Wire = wire::FixedBytes<N>;
}

impl<E, const N: usize> AbiEncodeAs<wire::FixedBytes<N>, E> for [u8; N] {
    fn abi_encode_as<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, E>> {
        enc.bytes(self).map_err(AbiEncodeError::Encode)
    }
}

impl AbiWireType for wire::CanonicalCbor {
    const TYPE_REF: TypeRef = TypeRef::CANONICAL_CBOR;
}

impl AbiRepresentation for CanonicalCbor {
    type Wire = wire::CanonicalCbor;
}

impl AbiRepresentation for CanonicalCborRef<'_> {
    type Wire = wire::CanonicalCbor;
}

impl<E> AbiEncodeAs<wire::CanonicalCbor, E> for CanonicalCbor {
    fn abi_encode_as<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, E>> {
        enc.raw_cbor(self.as_canonical_ref())
            .map_err(AbiEncodeError::Encode)
    }
}

impl<E> AbiEncodeAs<wire::CanonicalCbor, E> for CanonicalCborRef<'_> {
    fn abi_encode_as<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, E>> {
        enc.raw_cbor(*self).map_err(AbiEncodeError::Encode)
    }
}

impl<W: AbiWireType> AbiWireType for wire::Sequence<W> {
    const TYPE_REF: TypeRef = TypeRef::sequence(W::TYPE_REF);
}

impl<T: AbiRepresentation> AbiRepresentation for [T] {
    type Wire = wire::Sequence<T::Wire>;
}

impl<T: AbiRepresentation> AbiRepresentation for Vec<T> {
    type Wire = wire::Sequence<T::Wire>;
}

impl<T: AbiRepresentation> AbiRepresentation for &[T] {
    type Wire = wire::Sequence<T::Wire>;
}

impl<T, W, E> AbiEncodeAs<wire::Sequence<W>, E> for [T]
where
    W: AbiWireType,
    T: AbiEncodeAs<W, E>,
{
    fn abi_encode_as<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, E>> {
        enc.array_with_caller_error(self.len(), |array| {
            for value in self {
                array.encode_with_caller_error(|enc| value.abi_encode_as(enc))?;
                array.checkpoint().map_err(AbiEncodeError::Encode)?;
            }
            Ok(())
        })
    }
}

impl<T, W, E> AbiEncodeAs<wire::Sequence<W>, E> for Vec<T>
where
    W: AbiWireType,
    T: AbiEncodeAs<W, E>,
{
    fn abi_encode_as<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, E>> {
        self.as_slice().abi_encode_as(enc)
    }
}

/// Engine-driven exact indexed sequence. The index function is called once for each `0..len`.
pub struct IndexedSequence<F, T> {
    len: usize,
    project: F,
    item: PhantomData<fn() -> T>,
}

/// Admit an engine-driven exact indexed source without trusting an iterator length hint.
#[must_use]
pub const fn indexed_sequence<T, F>(len: usize, project: F) -> IndexedSequence<F, T> {
    IndexedSequence {
        len,
        project,
        item: PhantomData,
    }
}

impl<F, T, W, E> AbiEncodeAs<wire::Sequence<W>, E> for IndexedSequence<F, T>
where
    W: AbiWireType,
    F: Fn(usize) -> Result<T, E>,
    T: AbiEncodeAs<W, E>,
{
    fn abi_encode_as<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, E>> {
        enc.array_with_caller_error(self.len, |array| {
            for index in 0..self.len {
                let value = (self.project)(index).map_err(AbiEncodeError::Projection)?;
                array.encode_with_caller_error(|enc| value.abi_encode_as(enc))?;
                array.checkpoint().map_err(AbiEncodeError::Encode)?;
            }
            Ok(())
        })
    }
}

/// Named exact-index projection suitable for use as a derive-generated carrier.
pub trait ExactIndexProjection {
    /// Caller-owned projection error.
    type Error;
    /// Carrier returned for one index.
    type Item;

    /// Exact count observed before the definite-length header.
    fn len(&self) -> usize;

    /// Whether the projection is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Project one engine-selected index. The engine invokes every index exactly once.
    fn project(&self, index: usize) -> Result<Self::Item, Self::Error>;
}

/// Engine-driven adapter around a named exact-index projection.
pub struct ExactIndexedSequence<P>(P);

/// Admit a named exact-index projection without trusting iterator metadata.
#[must_use]
pub const fn exact_indexed_sequence<P>(projection: P) -> ExactIndexedSequence<P> {
    ExactIndexedSequence(projection)
}

impl<P, W> AbiEncodeAs<wire::Sequence<W>, P::Error> for ExactIndexedSequence<P>
where
    W: AbiWireType,
    P: ExactIndexProjection,
    P::Item: AbiEncodeAs<W, P::Error>,
{
    fn abi_encode_as<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, P::Error>> {
        let len = self.0.len();
        enc.array_with_caller_error(len, |array| {
            for index in 0..len {
                let value = self.0.project(index).map_err(AbiEncodeError::Projection)?;
                array.encode_with_caller_error(|enc| value.abi_encode_as(enc))?;
                array.checkpoint().map_err(AbiEncodeError::Encode)?;
            }
            Ok(())
        })
    }
}

/// Source-driven exact sequence projection.
///
/// There is intentionally no `Iterator` or `ExactSizeIterator` blanket implementation. A source
/// must declare its count and emit through [`SequenceEmitter`], whose runtime accounting is checked
/// against the definite-length array transaction.
pub trait SequenceProjection<W: AbiWireType> {
    /// Caller-owned projection error.
    type Error;

    /// Declare the exact number of items before any array header is emitted.
    fn declared_len(&self) -> Result<usize, Self::Error>;

    /// Emit items in wire order.
    fn project<S: ByteSink, O: WorkObserver>(
        &self,
        emitter: &mut SequenceEmitter<'_, '_, S, O, W, Self::Error>,
    ) -> Result<(), AbiEncodeError<S::Error, Self::Error>>;
}

/// Source-driven sequence adapter.
pub struct ProjectedSequence<P>(P);

/// Admit a source-driven exact sequence projection.
#[must_use]
pub const fn projected_sequence<P>(projection: P) -> ProjectedSequence<P> {
    ProjectedSequence(projection)
}

impl<P, W> AbiEncodeAs<wire::Sequence<W>, P::Error> for ProjectedSequence<P>
where
    W: AbiWireType,
    P: SequenceProjection<W>,
{
    fn abi_encode_as<S: ByteSink, O: WorkObserver>(
        &self,
        enc: &mut ValueEncoder<'_, S, O>,
    ) -> Result<(), AbiEncodeError<S::Error, P::Error>> {
        let declared = self.0.declared_len().map_err(AbiEncodeError::Projection)?;
        enc.array_with_caller_error(declared, |array| {
            let mut emitter = SequenceEmitter {
                array,
                declared,
                emitted: 0,
                wire: PhantomData,
            };
            self.0.project(&mut emitter)?;
            if emitter.emitted != declared {
                return Err(AbiEncodeError::Sequence(SequenceContractError::Underfill {
                    declared,
                    emitted: emitter.emitted,
                }));
            }
            Ok(())
        })
    }
}

/// Count-checking emitter passed to a source-driven projection.
pub struct SequenceEmitter<'a, 'e, S: ByteSink, O: WorkObserver, W: AbiWireType, E> {
    array: &'a mut ArrayEncoder<'e, S, O>,
    declared: usize,
    emitted: usize,
    wire: PhantomData<fn() -> (W, E)>,
}

impl<S: ByteSink, O: WorkObserver, W: AbiWireType, E> SequenceEmitter<'_, '_, S, O, W, E> {
    /// Emit one item and advance the observed count only after successful encoding.
    pub fn emit<T: AbiEncodeAs<W, E> + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), AbiEncodeError<S::Error, E>> {
        let attempted = self.emitted.saturating_add(1);
        if self.emitted >= self.declared {
            let error = AbiEncodeError::Sequence(SequenceContractError::Overfill {
                declared: self.declared,
                attempted,
            });
            return self.array.encode_with_caller_error(|_| Err(error));
        }
        self.array
            .encode_with_caller_error(|enc| value.abi_encode_as(enc))?;
        self.emitted = attempted;
        self.array.checkpoint().map_err(AbiEncodeError::Encode)?;
        Ok(())
    }

    /// Declared item count.
    #[must_use]
    pub const fn declared_len(&self) -> usize {
        self.declared
    }

    /// Successfully emitted item count.
    #[must_use]
    pub const fn emitted_len(&self) -> usize {
        self.emitted
    }
}

/// Encode preserved unknown fields lower than `before_id`.
pub(crate) fn encode_unknown_fields_before<S: ByteSink, O: WorkObserver, E>(
    array: &mut ArrayEncoder<'_, S, O>,
    unknown: &UnknownFields,
    cursor: &mut usize,
    before_id: u32,
) -> Result<(), AbiEncodeError<S::Error, E>> {
    let fields = unknown.as_slice();
    while *cursor < fields.len() && fields[*cursor].id < before_id {
        array
            .value(&fields[*cursor].id)
            .map_err(AbiEncodeError::Encode)?;
        array
            .raw_cbor(fields[*cursor].value.as_canonical_ref())
            .map_err(AbiEncodeError::Encode)?;
        *cursor += 1;
        array.checkpoint().map_err(AbiEncodeError::Encode)?;
    }
    if *cursor < fields.len() && fields[*cursor].id == before_id {
        return Err(AbiEncodeError::Encode(EncodeError::Cbor(CborError::new(
            sacp_cbor::ErrorCode::DuplicateMapKey,
            0,
        ))));
    }
    Ok(())
}

/// Encode remaining preserved unknown fields.
pub(crate) fn encode_remaining_unknown_fields<S: ByteSink, O: WorkObserver, E>(
    array: &mut ArrayEncoder<'_, S, O>,
    unknown: &UnknownFields,
    cursor: &mut usize,
) -> Result<(), AbiEncodeError<S::Error, E>> {
    let fields = unknown.as_slice();
    while *cursor < fields.len() {
        array
            .value(&fields[*cursor].id)
            .map_err(AbiEncodeError::Encode)?;
        array
            .raw_cbor(fields[*cursor].value.as_canonical_ref())
            .map_err(AbiEncodeError::Encode)?;
        *cursor += 1;
        array.checkpoint().map_err(AbiEncodeError::Encode)?;
    }
    Ok(())
}

/// Validate that a preserved unknown variant does not collide with a known semantic variant.
pub(crate) fn validate_unknown_variant<SinkError, E>(
    variant: &UnknownVariant,
    reserved: &[u32],
) -> Result<(), AbiEncodeError<SinkError, E>> {
    if variant.id == 0 || reserved.contains(&variant.id) {
        return Err(AbiEncodeError::Encode(EncodeError::Cbor(CborError::new(
            sacp_cbor::ErrorCode::InvalidAbiValue,
            0,
        ))));
    }
    Ok(())
}
