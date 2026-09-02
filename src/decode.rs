//! Streaming decoder and exact core type implementations.

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use core::marker::PhantomData;
use core::ops::Range;

#[cfg(feature = "alloc")]
use crate::alloc_util;
use crate::bytes::BytesRef;
use crate::canonical::CanonicalCborRef;
use crate::codec::CborDecode;
use crate::profile::{cmp_bytes_observed, validate_f64_bits, MAX_SAFE_INTEGER};
use crate::query::{peek_kind_at, BigIntRef, CborKind, CborValueRef, IntegerRef};
use crate::wire::{self, Cursor};
use crate::work::{NoopWorkObserver, WorkMeter, WorkObserver};
use crate::{CborError, DecodeLimits, ErrorCode, ValidationOptions};

#[cfg(feature = "alloc")]
use crate::bytes::Bytes;
#[cfg(feature = "alloc")]
use crate::value::{BigInt, Integer};
#[cfg(feature = "alloc")]
use crate::CanonicalCbor;

/// A CBOR map represented as ordered key/value entries.
#[cfg(feature = "collections")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapEntries<K, V>(pub Vec<(K, V)>);

#[cfg(feature = "collections")]
impl<K, V> MapEntries<K, V> {
    /// Wrap an existing vector of entries.
    #[must_use]
    pub const fn new(entries: Vec<(K, V)>) -> Self {
        Self(entries)
    }
}

/// Streaming decoder over canonical CBOR bytes.
pub struct Decoder<'de, const CHECKED: bool, O: WorkObserver = NoopWorkObserver> {
    cursor: Cursor<'de>,
    limits: DecodeLimits,
    options: ValidationOptions,
    work: WorkMeter<O>,
    depth: usize,
    items_seen: usize,
    /// Values fully consumed at depth 0 — exactly 1 for a witnessable pass.
    root_values: usize,
    completed_values: usize,
    active_traversal_id: Option<u64>,
    active_traversal_slot: Option<u64>,
    active_traversal_slot_depth: Option<usize>,
    #[cfg(feature = "alloc")]
    next_traversal_id: u64,
    poison: Option<CborError>,
    scratch: wire::SkipScratch,
}

/// Array decoder guard that manages depth and length.
///
/// Dropping the guard before all declared elements are consumed poisons the parent decoder. Later
/// operations on that decoder return the stored malformed-canonical error.
pub struct ArrayDecoder<'a, 'de, const CHECKED: bool, O: WorkObserver = NoopWorkObserver> {
    decoder: &'a mut Decoder<'de, CHECKED, O>,
    header_offset: usize,
    remaining: usize,
    entered: bool,
    admission_open: bool,
}

/// Map decoder guard that manages depth, length, and key ordering.
///
/// Dropping the guard before all declared entries are consumed, or while a key is waiting for its
/// value, poisons the parent decoder. Later operations on that decoder return the stored
/// malformed-canonical error.
pub struct MapDecoder<'a, 'de, const CHECKED: bool, O: WorkObserver = NoopWorkObserver> {
    decoder: &'a mut Decoder<'de, CHECKED, O>,
    remaining: usize,
    entered: bool,
    pending_value: bool,
    prev_key_range: Option<(usize, usize)>,
}

#[derive(Debug)]
#[cfg(feature = "alloc")]
struct ArrayTraversal {
    remaining: usize,
    entered: bool,
    id: u64,
    parent_id: Option<u64>,
    container_depth: usize,
    pending_serial: Option<usize>,
    parent_slot_claimed: bool,
    parent_slot_depth: Option<usize>,
}

/// Non-borrowing state for an explicitly driven map traversal.
///
/// Keys are still consumed by [`Decoder::map_traversal_next_key`], so canonical text-key ordering
/// remains enforced by the core decoder.
#[derive(Debug)]
#[cfg(feature = "alloc")]
struct MapTraversal {
    remaining: usize,
    entered: bool,
    pending_value: bool,
    prev_key_range: Option<(usize, usize)>,
    id: u64,
    parent_id: Option<u64>,
    container_depth: usize,
    pending_serial: Option<usize>,
    parent_slot_claimed: bool,
    parent_slot_depth: Option<usize>,
}

#[derive(Debug)]
#[cfg(feature = "alloc")]
enum TraversalState {
    Array(ArrayTraversal),
    Map(MapTraversal),
}

#[cfg(feature = "alloc")]
struct TraversalIdentity {
    id: u64,
    parent_id: Option<u64>,
    container_depth: usize,
    parent_slot_claimed: bool,
    parent_slot_depth: Option<usize>,
}

/// Caller-owned storage for an explicitly driven, stack-safe decoder traversal.
///
/// Prepare the workspace for the largest permitted open-container depth before calling
/// [`Decoder::with_traversal`]. Successful traversal then performs no allocation.
#[cfg(feature = "alloc")]
#[derive(Debug, Default)]
pub struct TraversalWorkspace {
    states: Vec<TraversalState>,
    prepared_capacity: usize,
}

#[cfg(feature = "alloc")]
impl TraversalWorkspace {
    /// Construct an empty traversal workspace.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            states: Vec::new(),
            prepared_capacity: 0,
        }
    }

    /// Fallibly prepare storage for `container_capacity` simultaneously open containers.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::AllocationFailed`] when storage cannot be reserved.
    pub fn prepare(&mut self, container_capacity: usize) -> Result<(), CborError> {
        self.states.clear();
        if self.states.capacity() < container_capacity {
            self.states
                .try_reserve_exact(container_capacity - self.states.len())
                .map_err(|_| CborError::new(ErrorCode::AllocationFailed, 0))?;
        }
        self.prepared_capacity = container_capacity;
        Ok(())
    }

    fn reset(&mut self) {
        self.states.clear();
    }
}

/// A generatively branded traversal session.
///
/// The session is invariant in its fresh brand and cannot escape or be transferred to another
/// decoder. Container state remains private inside its caller-owned workspace.
#[cfg(feature = "alloc")]
pub struct TraversalSession<
    'decoder,
    'de,
    'brand,
    const CHECKED: bool,
    O: WorkObserver = NoopWorkObserver,
> {
    decoder: &'decoder mut Decoder<'de, CHECKED, O>,
    workspace: &'decoder mut TraversalWorkspace,
    brand: PhantomData<fn(&'brand mut ()) -> &'brand mut ()>,
}

#[cfg(feature = "alloc")]
impl<'de, const CHECKED: bool, O: WorkObserver> core::ops::Deref
    for TraversalSession<'_, 'de, '_, CHECKED, O>
{
    type Target = Decoder<'de, CHECKED, O>;

    fn deref(&self) -> &Self::Target {
        self.decoder
    }
}

#[cfg(feature = "alloc")]
impl<const CHECKED: bool, O: WorkObserver> core::ops::DerefMut
    for TraversalSession<'_, '_, '_, CHECKED, O>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.decoder
    }
}

#[cfg(feature = "alloc")]
impl<'de, const CHECKED: bool, O: WorkObserver> TraversalSession<'_, 'de, '_, CHECKED, O> {
    /// Enter an array in this branded session.
    ///
    /// # Errors
    ///
    /// Returns a sticky grammar, limit, or protocol error.
    pub fn begin_array(&mut self) -> Result<(), CborError> {
        let traversal = self.decoder.begin_array_traversal()?;
        self.push_state(TraversalState::Array(traversal))
    }

    /// Return the number of array elements not yet claimed from the active array.
    ///
    /// # Errors
    ///
    /// Returns a sticky protocol error when the active container is not an array.
    pub fn array_remaining(&mut self) -> Result<usize, CborError> {
        let Some(TraversalState::Array(traversal)) = self.workspace.states.last() else {
            return self.decoder.traversal_protocol_error();
        };
        Ok(traversal.remaining)
    }

    /// Claim the next array element slot.
    ///
    /// # Errors
    ///
    /// Returns a sticky protocol error when the prior child is incomplete.
    pub fn array_next(&mut self) -> Result<bool, CborError> {
        let Some(TraversalState::Array(traversal)) = self.workspace.states.last_mut() else {
            return self.decoder.traversal_protocol_error();
        };
        self.decoder.array_traversal_next(traversal)
    }

    /// Confirm completion of a claimed array child.
    ///
    /// # Errors
    ///
    /// Returns a sticky protocol error when the child is incomplete or nested.
    pub fn array_child_complete(&mut self) -> Result<(), CborError> {
        let Some(TraversalState::Array(traversal)) = self.workspace.states.last_mut() else {
            return self.decoder.traversal_protocol_error();
        };
        self.decoder.array_traversal_child_complete(traversal)
    }

    /// Finish an array traversal.
    ///
    /// # Errors
    ///
    /// Returns a sticky protocol error unless every child completed.
    pub fn finish_array(&mut self) -> Result<(), CborError> {
        let Some(TraversalState::Array(_)) = self.workspace.states.last() else {
            return self.decoder.traversal_protocol_error();
        };
        let Some(TraversalState::Array(traversal)) = self.workspace.states.pop() else {
            unreachable!();
        };
        self.decoder.finish_array_traversal(traversal)
    }

    /// Enter a map in this branded session.
    ///
    /// # Errors
    ///
    /// Returns a sticky grammar, limit, or protocol error.
    pub fn begin_map(&mut self) -> Result<(), CborError> {
        let traversal = self.decoder.begin_map_traversal()?;
        self.push_state(TraversalState::Map(traversal))
    }

    /// Return the number of map entries whose values have not yet been claimed.
    ///
    /// # Errors
    ///
    /// Returns a sticky protocol error when the active container is not a map.
    pub fn map_remaining(&mut self) -> Result<usize, CborError> {
        let Some(TraversalState::Map(traversal)) = self.workspace.states.last() else {
            return self.decoder.traversal_protocol_error();
        };
        Ok(traversal.remaining)
    }

    /// Consume the next canonical map key.
    ///
    /// # Errors
    ///
    /// Returns a sticky grammar or protocol error.
    pub fn map_next_key(&mut self) -> Result<Option<MapKey<'de>>, CborError> {
        let Some(TraversalState::Map(traversal)) = self.workspace.states.last_mut() else {
            return self.decoder.traversal_protocol_error();
        };
        self.decoder.map_traversal_next_key(traversal)
    }

    /// Claim the pending map value slot.
    ///
    /// # Errors
    ///
    /// Returns a sticky protocol error when no key is pending.
    pub fn map_value(&mut self) -> Result<(), CborError> {
        let Some(TraversalState::Map(traversal)) = self.workspace.states.last_mut() else {
            return self.decoder.traversal_protocol_error();
        };
        self.decoder.map_traversal_value(traversal)
    }

    /// Confirm completion of a claimed map value.
    ///
    /// # Errors
    ///
    /// Returns a sticky protocol error when the value is incomplete or nested.
    pub fn map_value_complete(&mut self) -> Result<(), CborError> {
        let Some(TraversalState::Map(traversal)) = self.workspace.states.last_mut() else {
            return self.decoder.traversal_protocol_error();
        };
        self.decoder.map_traversal_value_complete(traversal)
    }

    /// Finish a map traversal.
    ///
    /// # Errors
    ///
    /// Returns a sticky protocol error unless every entry completed.
    pub fn finish_map(&mut self) -> Result<(), CborError> {
        let Some(TraversalState::Map(_)) = self.workspace.states.last() else {
            return self.decoder.traversal_protocol_error();
        };
        let Some(TraversalState::Map(traversal)) = self.workspace.states.pop() else {
            unreachable!();
        };
        self.decoder.finish_map_traversal(traversal)
    }

    /// Consume one arbitrary canonical value using only this session's prepared traversal stack.
    ///
    /// Unlike [`Decoder::skip_value`], this path cannot allocate an internal depth spill. It is
    /// intended for owners that make traversal capacity explicit in a reusable workspace.
    ///
    /// # Errors
    ///
    /// Returns the first grammar, decode-limit, or traversal-workspace error and poisons the
    /// decoder when bytes may have been consumed.
    pub fn skip_value_prepared(&mut self) -> Result<(), CborError> {
        let base = self.workspace.states.len();
        let mut need_value = true;
        loop {
            if need_value {
                match self.decoder.peek_kind()? {
                    CborKind::Integer => self.decoder.skip_scalar(ScalarKind::Integer)?,
                    CborKind::Bytes => self.decoder.skip_scalar(ScalarKind::Bytes)?,
                    CborKind::Text => self.decoder.skip_scalar(ScalarKind::Text)?,
                    CborKind::Bool => self.decoder.skip_scalar(ScalarKind::Bool)?,
                    CborKind::Null => self.decoder.skip_scalar(ScalarKind::Null)?,
                    CborKind::Float => self.decoder.skip_scalar(ScalarKind::Float)?,
                    CborKind::Array => {
                        self.begin_array()?;
                        if self.array_next()? {
                            continue;
                        }
                        self.finish_array()?;
                    }
                    CborKind::Map => {
                        self.begin_map()?;
                        if self.map_next_key()?.is_some() {
                            self.map_value()?;
                            continue;
                        }
                        self.finish_map()?;
                    }
                }
                need_value = false;
            }
            if self.workspace.states.len() == base {
                return Ok(());
            }
            match self.workspace.states.last() {
                Some(TraversalState::Array(_)) => {
                    self.array_child_complete()?;
                    if self.array_next()? {
                        need_value = true;
                    } else {
                        self.finish_array()?;
                    }
                }
                Some(TraversalState::Map(_)) => {
                    self.map_value_complete()?;
                    if self.map_next_key()?.is_some() {
                        self.map_value()?;
                        need_value = true;
                    } else {
                        self.finish_map()?;
                    }
                }
                None => return Ok(()),
            }
        }
    }

    fn push_state(&mut self, state: TraversalState) -> Result<(), CborError> {
        if self.workspace.states.len() == self.workspace.prepared_capacity {
            return self.decoder.traversal_protocol_error();
        }
        self.workspace.states.push(state);
        Ok(())
    }
}

/// Raw parts of one consumed integer-kind value (the single counted
/// funnel behind every integer decode).
#[cfg(feature = "alloc")]
enum IntegerParts<'de> {
    SafePos(u64),
    SafeNeg(u64),
    Big { negative: bool, mag: &'de [u8] },
}

/// A scalar (leaf) kind of the canonical profile.
///
/// The scalar consumption funnels ([`Decoder::skip_scalar`],
/// [`ArrayDecoder::skip_scalars`], [`ArrayDecoder::next_scalar_span`]) take
/// this instead of [`CborKind`] so a container kind cannot be requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarKind {
    /// Safe integer (major 0/1) or bignum (tag 2/3).
    Integer,
    /// Byte string (major 2).
    Bytes,
    /// Text string (major 3).
    Text,
    /// Boolean simple value.
    Bool,
    /// Null simple value.
    Null,
    /// Float64 value.
    Float,
}

/// Declared framing metadata for a text or byte-string payload.
///
/// This is passed to the guarded payload decode APIs after the header and canonical length have
/// been decoded and the decoder's resource limit has been enforced, but before the payload bytes
/// are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadHeader {
    header_offset: usize,
    declared_len: usize,
}

impl PayloadHeader {
    /// Return the byte offset of the text or byte-string header.
    #[must_use]
    pub const fn header_offset(self) -> usize {
        self.header_offset
    }

    /// Return the payload length declared by the header.
    #[must_use]
    pub const fn declared_len(self) -> usize {
        self.declared_len
    }
}

/// Declared framing metadata for a container.
///
/// This is passed to [`ArrayDecoder::admit_with`] after the array header, canonical length, and
/// decoder limits have been checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerHeader {
    header_offset: usize,
    declared_len: usize,
}

/// Framing metadata for one complete canonical encoded value.
///
/// This is passed to [`Decoder::decode_canonical_with_guard`] after the value has been traversed
/// and validated against the decoder's grammar and resource limits, but before a caller can copy
/// the encoded bytes into owned storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedValueHeader {
    header_offset: usize,
    encoded_len: usize,
}

impl EncodedValueHeader {
    /// Return the byte offset of the encoded value's initial byte.
    #[must_use]
    pub const fn header_offset(self) -> usize {
        self.header_offset
    }

    /// Return the complete encoded length of the value.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        self.encoded_len
    }
}

impl ContainerHeader {
    /// Return the byte offset of the container header.
    #[must_use]
    pub const fn header_offset(self) -> usize {
        self.header_offset
    }

    /// Return the number of elements declared by the container header.
    #[must_use]
    pub const fn declared_len(self) -> usize {
        self.declared_len
    }
}

#[derive(Clone, Copy)]
enum PayloadKind {
    Bytes,
    Text,
}

impl PayloadKind {
    const fn major(self) -> u8 {
        match self {
            Self::Bytes => 2,
            Self::Text => 3,
        }
    }

    const fn expected_error(self) -> ErrorCode {
        match self {
            Self::Bytes => ErrorCode::ExpectedBytes,
            Self::Text => ErrorCode::ExpectedText,
        }
    }

    const fn limit(self, limits: &DecodeLimits) -> usize {
        match self {
            Self::Bytes => limits.max_bytes_len,
            Self::Text => limits.max_text_len,
        }
    }

    const fn limit_error(self) -> ErrorCode {
        match self {
            Self::Bytes => ErrorCode::BytesLenLimitExceeded,
            Self::Text => ErrorCode::TextLenLimitExceeded,
        }
    }
}

/// Text key metadata returned by [`MapDecoder::next_key_ref`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapKey<'de> {
    /// Decoded text key.
    pub text: &'de str,
    /// Offset of the encoded text key inside the input.
    pub offset: usize,
    /// Byte range occupied by the encoded text key.
    pub encoded_range: Range<usize>,
}

impl<const CHECKED: bool, O: WorkObserver> Drop for ArrayDecoder<'_, '_, CHECKED, O> {
    fn drop(&mut self) {
        if self.entered {
            self.decoder.exit_container();
            if self.remaining == 0 {
                self.decoder.note_value_end();
            } else {
                let off = self.decoder.position();
                self.decoder.poison(ErrorCode::MalformedCanonical, off);
            }
        }
    }
}

impl<const CHECKED: bool, O: WorkObserver> Drop for MapDecoder<'_, '_, CHECKED, O> {
    fn drop(&mut self) {
        if self.entered {
            self.decoder.exit_container();
            if self.remaining == 0 && !self.pending_value {
                self.decoder.note_value_end();
            } else {
                let off = self.decoder.position();
                self.decoder.poison(ErrorCode::MalformedCanonical, off);
            }
        }
    }
}

impl<'de> Decoder<'de, true, NoopWorkObserver> {
    /// Construct a decoder that enforces canonical constraints while decoding.
    ///
    /// # Errors
    ///
    /// Returns `MessageLenLimitExceeded` if `bytes` exceeds the input limit.
    pub const fn new_checked(bytes: &'de [u8], limits: DecodeLimits) -> Result<Self, CborError> {
        Self::new_noop_with(bytes, limits, ValidationOptions::new())
    }

    /// Construct a checked decoder that additionally enforces the given
    /// restriction modes (e.g. [`ValidationOptions::no_float`]) on every
    /// consumed value, including skipped subtrees.
    ///
    /// # Errors
    ///
    /// Returns `MessageLenLimitExceeded` if `bytes` exceeds the input limit.
    pub const fn new_checked_with(
        bytes: &'de [u8],
        limits: DecodeLimits,
        options: ValidationOptions,
    ) -> Result<Self, CborError> {
        Self::new_noop_with(bytes, limits, options)
    }
}

impl<'de, O: WorkObserver> Decoder<'de, true, O> {
    /// Construct an observed decoder that enforces canonical constraints while decoding.
    ///
    /// The observer is owned by the decoder and receives its initial zero-work checkpoint before
    /// decoding begins.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::WorkCancelled`] when the observer rejects the initial checkpoint,
    /// `MessageLenLimitExceeded` when `bytes` exceeds the input limit, or `InvalidLimits` for an
    /// invalid limit set.
    pub fn new_checked_observed(
        bytes: &'de [u8],
        limits: DecodeLimits,
        observer: O,
    ) -> Result<Self, CborError> {
        Self::new_with(bytes, limits, ValidationOptions::new(), observer)
    }

    /// Construct an observed checked decoder under explicit restriction options.
    ///
    /// The observer is owned by the decoder and receives its initial zero-work checkpoint before
    /// decoding begins.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::WorkCancelled`] when the observer rejects the initial checkpoint,
    /// `MessageLenLimitExceeded` when `bytes` exceeds the input limit, or `InvalidLimits` for an
    /// invalid limit set.
    pub fn new_checked_with_observer(
        bytes: &'de [u8],
        limits: DecodeLimits,
        options: ValidationOptions,
        observer: O,
    ) -> Result<Self, CborError> {
        Self::new_with(bytes, limits, options, observer)
    }
}

impl<'de> Decoder<'de, false, NoopWorkObserver> {
    /// Construct a decoder over canonical bytes with the provided limits.
    ///
    /// This assumes the input is already canonical.
    ///
    /// # Errors
    ///
    /// Returns `MessageLenLimitExceeded` if `bytes` exceeds the input limit.
    pub const fn new_trusted(
        canon: CanonicalCborRef<'de>,
        limits: DecodeLimits,
    ) -> Result<Self, CborError> {
        Self::new_noop_with(canon.as_bytes(), limits, ValidationOptions::new())
    }
}

impl<'de, const CHECKED: bool> Decoder<'de, CHECKED, NoopWorkObserver> {
    const fn new_noop_with(
        bytes: &'de [u8],
        limits: DecodeLimits,
        options: ValidationOptions,
    ) -> Result<Self, CborError> {
        if let Err(error) = limits.validate() {
            return Err(error);
        }
        if bytes.len() > limits.max_input_bytes {
            return Err(CborError::new(ErrorCode::MessageLenLimitExceeded, 0));
        }
        Ok(Self::from_parts(
            bytes,
            limits,
            options,
            WorkMeter::new(NoopWorkObserver),
        ))
    }
}

impl<'de, O: WorkObserver> Decoder<'de, false, O> {
    /// Construct an observed decoder over an existing canonical witness.
    ///
    /// The observer is owned by the decoder and receives its initial zero-work checkpoint before
    /// decoding begins. Canonical grammar checks are omitted, while decode limits and completion
    /// protocol checks remain active.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::WorkCancelled`] when the observer rejects the initial checkpoint,
    /// `MessageLenLimitExceeded` when the witness exceeds the input limit, or `InvalidLimits` for
    /// an invalid limit set.
    pub fn new_trusted_observed(
        canon: CanonicalCborRef<'de>,
        limits: DecodeLimits,
        observer: O,
    ) -> Result<Self, CborError> {
        Self::new_with(canon.as_bytes(), limits, ValidationOptions::new(), observer)
    }
}

impl<'de, const CHECKED: bool, O: WorkObserver> Decoder<'de, CHECKED, O> {
    /// Complete a decode pass and return the canonical witness.
    ///
    /// Succeeds only when this decoder consumed the input as **exactly one canonical item**: no
    /// poisoned container guard, no trailing bytes, and exactly one value completed at the root.
    /// A checked decoder enforces the same canonical grammar as
    /// [`validate_canonical`](crate::validate_canonical) during that single pass. A trusted decoder
    /// preserves the canonical witness supplied to [`new_trusted`](Decoder::new_trusted) while
    /// enforcing the same completion protocol.
    ///
    /// # Errors
    ///
    /// Returns the stored poison, `TrailingBytes` when input remains, or `MalformedCanonical` when
    /// the pass did not consume exactly one root value.
    pub fn finish(mut self) -> Result<CanonicalCborRef<'de>, CborError> {
        self.check_poison()?;
        let pos = self.cursor.position();
        if pos != self.cursor.data().len() {
            return Err(CborError::new(ErrorCode::TrailingBytes, pos));
        }
        if CHECKED && self.root_values != 1 {
            return Err(CborError::new(ErrorCode::MalformedCanonical, pos));
        }
        if self.active_traversal_id.is_some() {
            return Err(CborError::new(ErrorCode::MalformedCanonical, pos));
        }
        self.finish_work()?;
        Ok(CanonicalCborRef::new(self.cursor.data()))
    }

    /// Run an explicitly-driven traversal in a fresh generative brand.
    ///
    /// The branded session cannot escape `f` or be unified with a session for another decoder.
    ///
    /// # Errors
    ///
    /// Returns the closure error, or a sticky traversal-protocol error when the closure returns
    /// successfully without finishing every opened container.
    #[cfg(feature = "alloc")]
    pub fn with_traversal<R, E, F>(
        &mut self,
        workspace: &mut TraversalWorkspace,
        f: F,
    ) -> Result<R, E>
    where
        F: for<'brand> FnOnce(&mut TraversalSession<'_, 'de, 'brand, CHECKED, O>) -> Result<R, E>,
        E: From<CborError>,
    {
        workspace.reset();
        self.check_poison().map_err(E::from)?;
        let mut session = TraversalSession {
            decoder: self,
            workspace,
            brand: PhantomData,
        };
        let result = f(&mut session);
        match result {
            Ok(value) if session.workspace.states.is_empty() => {
                if let Some(error) = session.decoder.poison {
                    if error.code == ErrorCode::WorkCancelled {
                        return Err(E::from(error));
                    }
                }
                Ok(value)
            }
            Ok(_) => {
                let error = session
                    .decoder
                    .traversal_protocol_error::<()>()
                    .unwrap_err();
                session.workspace.reset();
                Err(E::from(error))
            }
            Err(error) => {
                if !session.workspace.states.is_empty() {
                    let _ = session.decoder.traversal_protocol_error::<()>();
                }
                session.workspace.reset();
                Err(error)
            }
        }
    }

    fn new_with(
        bytes: &'de [u8],
        limits: DecodeLimits,
        options: ValidationOptions,
        observer: O,
    ) -> Result<Self, CborError> {
        limits.validate()?;
        if bytes.len() > limits.max_input_bytes {
            return Err(CborError::new(ErrorCode::MessageLenLimitExceeded, 0));
        }
        let mut work = WorkMeter::new(observer);
        work.start()
            .map_err(|_| CborError::new(ErrorCode::WorkCancelled, 0))?;
        Ok(Self::from_parts(bytes, limits, options, work))
    }

    const fn from_parts(
        bytes: &'de [u8],
        limits: DecodeLimits,
        options: ValidationOptions,
        work: WorkMeter<O>,
    ) -> Self {
        Self {
            cursor: Cursor::with_pos(bytes, 0),
            limits,
            options,
            work,
            depth: 0,
            items_seen: 0,
            root_values: 0,
            completed_values: 0,
            active_traversal_id: None,
            active_traversal_slot: None,
            active_traversal_slot_depth: None,
            #[cfg(feature = "alloc")]
            next_traversal_id: 0,
            poison: None,
            scratch: wire::SkipScratch::new(),
        }
    }

    #[inline]
    fn complete_work(&mut self, completed_units: usize) -> Result<(), CborError> {
        if self.work.complete(completed_units).is_err() {
            let error = CborError::new(ErrorCode::WorkCancelled, self.position());
            self.poison_err(error);
            Err(error)
        } else {
            Ok(())
        }
    }

    #[inline]
    fn finish_work(&mut self) -> Result<(), CborError> {
        if self.work.finish().is_err() {
            let error = CborError::new(ErrorCode::WorkCancelled, self.position());
            self.poison_err(error);
            Err(error)
        } else {
            Ok(())
        }
    }

    /// Record the completion of one whole value at the current depth.
    ///
    /// Hot-path note: root counting feeds `finish`, which exists only on
    /// checked decoders — the whole body const-folds away for the trusted
    /// path. On the checked path it is one register compare; in nested
    /// positions (the overwhelmingly common case) the branch is never
    /// taken and predicts perfectly.
    #[inline]
    fn note_value_end(&mut self) {
        let Some(value) = self.completed_values.checked_add(1) else {
            self.poison(ErrorCode::LengthOverflow, self.position());
            return;
        };
        self.completed_values = value;
        if CHECKED && self.depth == 0 {
            self.root_values += 1;
        }
        if self.active_traversal_slot == self.active_traversal_id
            && self.active_traversal_slot_depth == Some(self.depth)
        {
            self.active_traversal_slot = None;
            self.active_traversal_slot_depth = None;
        }
    }

    /// Seal a value-consuming operation: success completes a value,
    /// failure poisons the decoder.
    ///
    /// Errors are sticky by design: a failed consuming operation may have
    /// advanced the cursor past a partial value, so continuing would
    /// traverse an incoherent framing of the input. Poisoning makes every
    /// later operation — `finish` included — return the original error
    /// instead. Cost on the success path: one branch on `Ok` plus the
    /// `note_value_end` compare; the poison store is on the cold error arm.
    #[inline]
    fn seal_value<T>(&mut self, result: Result<T, CborError>) -> Result<T, CborError> {
        match result {
            Ok(value) => {
                if let Some(active) = self.active_traversal_id {
                    if self.active_traversal_slot != Some(active) {
                        return self.traversal_protocol_error();
                    }
                }
                self.note_value_end();
                Ok(value)
            }
            Err(err) => {
                self.poison_err(err);
                Err(err)
            }
        }
    }

    /// Poison a non-completing operation's failure (container entry, key
    /// reads): sticky, but no value completion on success.
    #[inline]
    const fn seal_step<T>(&mut self, result: Result<T, CborError>) -> Result<T, CborError> {
        if let Err(err) = &result {
            self.poison_err(*err);
        }
        result
    }

    #[inline]
    const fn poison_err(&mut self, err: CborError) {
        if self.poison.is_none() {
            self.poison = Some(err);
        }
    }

    /// Return the current byte offset in the input.
    #[must_use]
    #[inline]
    pub const fn position(&self) -> usize {
        self.cursor.position()
    }

    /// Reborrow this decoder's cooperative work state for a derived nested decode.
    ///
    /// This is an implementation detail used by the derive crate when an internally or
    /// adjacently tagged enum must decode a canonical sub-value after its enclosing map has been
    /// scanned. The opaque return type prevents generated code from depending on the meter's
    /// representation while preserving the outer decoder's cadence and sticky cancellation state.
    #[doc(hidden)]
    #[inline]
    pub fn __reborrow_work_observer(&mut self) -> impl WorkObserver + '_ {
        &mut self.work
    }

    /// Construct the checked second-pass decoder used by derived tagged enums.
    ///
    /// The outer decoder already validated `value` against the caller's limits and grammar
    /// options. The checked path is retained because safe text decoding performs real UTF-8 work
    /// during this pass and that work must remain observable. Reusing the caller's limits avoids
    /// introducing an unrelated default cap, while the borrowed work meter preserves the outer
    /// decoder's cadence and sticky cancellation state.
    #[doc(hidden)]
    #[inline]
    pub fn __derived_subvalue_decoder<'value>(
        &mut self,
        value: CborValueRef<'value>,
    ) -> Result<Decoder<'value, true, impl WorkObserver + '_>, CborError> {
        let limits = self.limits;
        Decoder::<true, _>::new_checked_observed(value.as_bytes(), limits, &mut self.work)
    }

    /// Store and return an error from a derived nested decode.
    ///
    /// Derived tagged enums may finish consuming their outer container before interpreting a
    /// retained canonical sub-value. Recording the mapped error here ensures container cleanup and
    /// every later operation preserve that first error, including its original input offset.
    #[doc(hidden)]
    #[inline]
    pub fn __record_nested_decode_error(&mut self, error: CborError) -> CborError {
        self.poison_err(error);
        self.poison.unwrap_or(error)
    }

    #[inline]
    pub(crate) const fn data(&self) -> &'de [u8] {
        self.cursor.data()
    }

    #[inline]
    fn read_header(&mut self) -> Result<(u8, u8, usize), CborError> {
        self.check_poison()?;
        let off = self.cursor.position();
        let ib = self.cursor.read_u8()?;
        self.complete_work(1)?;
        Ok((ib >> 5, ib & 0x1f, off))
    }

    #[inline]
    fn read_uint_arg(&mut self, ai: u8, off: usize) -> Result<u64, CborError> {
        wire::read_uint_arg::<CHECKED>(&mut self.cursor, ai, off)
    }

    #[inline]
    fn read_len(&mut self, ai: u8, off: usize) -> Result<usize, CborError> {
        wire::read_len::<CHECKED>(&mut self.cursor, ai, off)
    }

    #[inline]
    fn bump_items(&mut self, add: usize, off: usize) -> Result<(), CborError> {
        self.items_seen = self
            .items_seen
            .checked_add(add)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
        if self.items_seen > self.limits.max_total_items {
            return Err(CborError::new(ErrorCode::TotalItemsLimitExceeded, off));
        }
        Ok(())
    }

    #[inline]
    fn enter_container(&mut self, len: usize, off: usize) -> Result<bool, CborError> {
        let next_depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
        if next_depth > self.limits.max_depth {
            return Err(CborError::new(ErrorCode::DepthLimitExceeded, off));
        }
        if len == 0 {
            return Ok(false);
        }
        self.depth = next_depth;
        Ok(true)
    }

    #[inline]
    fn exit_container(&mut self) {
        debug_assert!(self.depth > 0);
        self.depth = self.depth.saturating_sub(1);
    }

    #[inline]
    const fn check_poison(&self) -> Result<(), CborError> {
        if let Some(err) = self.poison {
            return Err(err);
        }
        Ok(())
    }

    #[inline]
    const fn poison(&mut self, code: ErrorCode, offset: usize) {
        if self.poison.is_none() {
            self.poison = Some(CborError::new(code, offset));
        }
    }

    #[inline]
    fn parse_text_from_header(&mut self, off: usize, ai: u8) -> Result<&'de str, CborError> {
        wire::parse_text_from_header_observed::<CHECKED, _>(
            &mut self.cursor,
            Some(&self.limits),
            off,
            ai,
            &mut self.work,
        )
    }

    #[inline]
    fn parse_bytes_from_header(&mut self, off: usize, ai: u8) -> Result<&'de [u8], CborError> {
        let len = self.read_len(ai, off)?;
        if len > self.limits.max_bytes_len {
            return Err(CborError::new(ErrorCode::BytesLenLimitExceeded, off));
        }
        self.cursor.read_exact(len)
    }

    /// Decode a text string after giving the caller one opportunity to admit its declared payload
    /// length.
    ///
    /// The guard runs after the text header, canonical length, and [`DecodeLimits::max_text_len`]
    /// have been checked, but before the payload is read or UTF-8 is validated. A guard error is
    /// returned unchanged and poisons the decoder because framing bytes have already been consumed.
    ///
    /// # Errors
    ///
    /// Returns the guard's error, or a converted decode error when the value is not canonical text,
    /// violates the configured limits, is truncated, or contains invalid UTF-8.
    ///
    /// With an enabled observer, checked UTF-8 validation is checkpointed in code-point-aligned
    /// chunks. On safe builds, producing the final whole-slice `&str` then requires one opaque
    /// standard-library conversion. That conversion is not charged twice and cannot itself be
    /// cooperatively interrupted.
    pub fn decode_text_with_guard<E, F>(&mut self, guard: F) -> Result<&'de str, E>
    where
        E: From<CborError>,
        F: FnOnce(PayloadHeader) -> Result<(), E>,
    {
        self.decode_payload_with_guard(
            PayloadKind::Text,
            guard,
            |bytes, off, payload_start, work| {
                if CHECKED {
                    match crate::utf8::validate_utf8_as_str_observed(bytes, work) {
                        Ok(text) => Ok(text),
                        Err(crate::utf8::ObservedUtf8Error::Invalid) => {
                            Err(CborError::new(ErrorCode::Utf8Invalid, off))
                        }
                        Err(crate::utf8::ObservedUtf8Error::Cancelled(completed)) => Err(
                            CborError::new(ErrorCode::WorkCancelled, payload_start + completed),
                        ),
                    }
                } else {
                    crate::utf8::trusted(bytes)
                        .map_err(|()| CborError::new(ErrorCode::Utf8Invalid, off))
                }
            },
        )
    }

    /// Decode a byte string after giving the caller one opportunity to admit its declared payload
    /// length.
    ///
    /// The guard runs after the byte-string header, canonical length, and
    /// [`DecodeLimits::max_bytes_len`] have been checked, but before the payload is read. A guard
    /// error is returned unchanged and poisons the decoder because framing bytes have already been
    /// consumed.
    ///
    /// # Errors
    ///
    /// Returns the guard's error, or a converted decode error when the value is not a canonical byte
    /// string, violates the configured limits, or is truncated.
    pub fn decode_bytes_with_guard<E, F>(&mut self, guard: F) -> Result<&'de [u8], E>
    where
        E: From<CborError>,
        F: FnOnce(PayloadHeader) -> Result<(), E>,
    {
        self.decode_payload_with_guard(PayloadKind::Bytes, guard, |bytes, _, _, _| Ok(bytes))
    }

    fn decode_payload_with_guard<T, E, F, P>(
        &mut self,
        kind: PayloadKind,
        guard: F,
        parse: P,
    ) -> Result<T, E>
    where
        E: From<CborError>,
        F: FnOnce(PayloadHeader) -> Result<(), E>,
        P: FnOnce(&'de [u8], usize, usize, &mut WorkMeter<O>) -> Result<T, CborError>,
    {
        if let Err(err) = self.check_poison() {
            return Err(E::from(err));
        }

        let header = (|| {
            let (major, ai, off) = self.read_header()?;
            if major != kind.major() {
                return Err(CborError::new(kind.expected_error(), off));
            }
            let len = self.read_len(ai, off)?;
            if len > kind.limit(&self.limits) {
                return Err(CborError::new(kind.limit_error(), off));
            }
            Ok(PayloadHeader {
                header_offset: off,
                declared_len: len,
            })
        })();

        let header = match header {
            Ok(header) => header,
            Err(err) => {
                self.poison_err(err);
                return Err(E::from(err));
            }
        };

        if let Err(err) = guard(header) {
            self.poison(ErrorCode::MalformedCanonical, header.header_offset);
            return Err(err);
        }

        let payload_start = self.cursor.position();
        let result = self
            .cursor
            .read_exact(header.declared_len)
            .and_then(|bytes| parse(bytes, header.header_offset, payload_start, &mut self.work));
        if let Err(error) = result {
            if error.code == ErrorCode::WorkCancelled {
                self.cursor.set_position(error.offset);
            }
            return self.seal_value(Err(error)).map_err(E::from);
        }
        self.seal_value(result).map_err(E::from)
    }

    #[inline]
    fn parse_bignum(&mut self, off: usize, ai: u8) -> Result<(bool, &'de [u8]), CborError> {
        wire::parse_bignum::<CHECKED>(&mut self.cursor, Some(&self.limits), off, ai)
    }

    /// Consume one integer-kind value (safe int or bignum) and return its
    /// raw parts plus the header offset. The counted funnel for the
    /// arbitrary-precision decoders (`BigInt`, `Integer`); the primitive
    /// paths below stay direct for hot-loop performance.
    #[cfg(feature = "alloc")]
    fn parse_integer_parts(&mut self) -> Result<(IntegerParts<'de>, usize), CborError> {
        let result = self.parse_integer_parts_raw();
        self.seal_value(result)
    }

    #[cfg(feature = "alloc")]
    fn parse_integer_parts_raw(&mut self) -> Result<(IntegerParts<'de>, usize), CborError> {
        let (major, ai, off) = self.read_header()?;
        match major {
            0 => {
                let v = self.read_uint_arg(ai, off)?;
                if CHECKED && v > MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                Ok((IntegerParts::SafePos(v), off))
            }
            1 => {
                let n = self.read_uint_arg(ai, off)?;
                if CHECKED && n >= MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                Ok((IntegerParts::SafeNeg(n), off))
            }
            6 => {
                let (negative, mag) = self.parse_bignum(off, ai)?;
                Ok((IntegerParts::Big { negative, mag }, off))
            }
            _ => Err(CborError::new(ErrorCode::ExpectedInteger, off)),
        }
    }

    /// Consume one scalar value of the expected kind through the direct
    /// scalar funnel: one header read, no subtree walk, no allocation.
    ///
    /// A value of a different kind is rejected with the kind's
    /// `Expected*` error code at the header offset. All canonical-grammar
    /// checks, decode limits, and restriction modes of this decoder apply.
    ///
    /// # Errors
    ///
    /// Returns an error if the next value is not a scalar of `kind`, is
    /// malformed, or violates limits or validation options.
    pub fn skip_scalar(&mut self, kind: ScalarKind) -> Result<(), CborError> {
        self.check_poison()?;
        let result = self.consume_scalar_raw(kind);
        self.seal_value(result)
    }

    #[inline]
    fn consume_scalar_raw(&mut self, kind: ScalarKind) -> Result<(), CborError> {
        match kind {
            ScalarKind::Integer => self.parse_integer_ref_raw().map(|_| ()),
            ScalarKind::Bytes => self.parse_bytes_raw().map(|_| ()),
            ScalarKind::Text => self.consume_text_raw(),
            ScalarKind::Bool => self.parse_bool_raw().map(|_| ()),
            ScalarKind::Null => self.parse_null_raw(),
            ScalarKind::Float => self.parse_float64_raw().map(|_| ()),
        }
    }

    /// Consume one text value without materializing the `&str`.
    ///
    /// Mirrors the skip path: UTF-8 is validated on the checked decoder and
    /// trusted on the trusted decoder, exactly like [`Decoder::skip_value`].
    /// (`parse_text_raw` must produce a `&str`, so it validates in both
    /// modes; a pure consume has no such obligation.)
    #[inline]
    fn consume_text_raw(&mut self) -> Result<(), CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 3 {
            return Err(CborError::new(ErrorCode::ExpectedText, off));
        }
        let len = self.read_len(ai, off)?;
        if len > self.limits.max_text_len {
            return Err(CborError::new(ErrorCode::TextLenLimitExceeded, off));
        }
        let payload_start = self.cursor.position();
        let bytes = self.cursor.read_exact(len)?;
        if CHECKED {
            match crate::utf8::validate_utf8_observed(bytes, &mut self.work) {
                Ok(()) => {}
                Err(crate::utf8::ObservedUtf8Error::Invalid) => {
                    return Err(CborError::new(ErrorCode::Utf8Invalid, off));
                }
                Err(crate::utf8::ObservedUtf8Error::Cancelled(completed)) => {
                    let position = payload_start + completed;
                    self.cursor.set_position(position);
                    return Err(CborError::new(ErrorCode::WorkCancelled, position));
                }
            }
        }
        Ok(())
    }

    fn parse_integer_ref(&mut self) -> Result<IntegerRef<'de>, CborError> {
        let result = self.parse_integer_ref_raw();
        self.seal_value(result)
    }

    /// Consume one integer-kind value as a zero-copy [`IntegerRef`]: the
    /// direct scalar funnel, no subtree walk and no allocation.
    #[inline]
    fn parse_integer_ref_raw(&mut self) -> Result<IntegerRef<'de>, CborError> {
        let (major, ai, off) = self.read_header()?;
        match major {
            0 => {
                let v = self.read_uint_arg(ai, off)?;
                if CHECKED && v > MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                let v = i64::try_from(v)
                    .map_err(|_| CborError::new(ErrorCode::IntegerOutsideSafeRange, off))?;
                Ok(IntegerRef::Safe(v))
            }
            1 => {
                let n = self.read_uint_arg(ai, off)?;
                if CHECKED && n >= MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                let n = i64::try_from(n)
                    .map_err(|_| CborError::new(ErrorCode::IntegerOutsideSafeRange, off))?;
                Ok(IntegerRef::Safe(-1 - n))
            }
            6 => {
                let (negative, mag) = self.parse_bignum(off, ai)?;
                Ok(IntegerRef::Big(BigIntRef::new(negative, mag)))
            }
            _ => Err(CborError::new(ErrorCode::ExpectedInteger, off)),
        }
    }

    fn parse_integer_i128(&mut self) -> Result<i128, CborError> {
        let result = self.parse_integer_i128_raw();
        self.seal_value(result)
    }

    #[inline]
    fn parse_integer_i128_raw(&mut self) -> Result<i128, CborError> {
        let (major, ai, off) = self.read_header()?;
        match major {
            0 => {
                let v = self.read_uint_arg(ai, off)?;
                if CHECKED && v > MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                Ok(i128::from(v))
            }
            1 => {
                let n = self.read_uint_arg(ai, off)?;
                if CHECKED && n >= MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                Ok(-1 - i128::from(n))
            }
            6 => {
                let (negative, mag) = self.parse_bignum(off, ai)?;
                let n = crate::int::magnitude_to_u128(mag)
                    .ok_or_else(|| CborError::new(ErrorCode::ExpectedInteger, off))?;
                let n = i128::try_from(n)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))?;
                Ok(if negative { -1 - n } else { n })
            }
            _ => Err(CborError::new(ErrorCode::ExpectedInteger, off)),
        }
    }

    fn parse_integer_u128(&mut self) -> Result<u128, CborError> {
        let result = self.parse_integer_u128_raw();
        self.seal_value(result)
    }

    #[inline]
    fn parse_integer_u128_raw(&mut self) -> Result<u128, CborError> {
        let (major, ai, off) = self.read_header()?;
        match major {
            0 => {
                let v = self.read_uint_arg(ai, off)?;
                if CHECKED && v > MAX_SAFE_INTEGER {
                    return Err(CborError::new(ErrorCode::IntegerOutsideSafeRange, off));
                }
                Ok(u128::from(v))
            }
            6 => {
                let (negative, mag) = self.parse_bignum(off, ai)?;
                if negative {
                    return Err(CborError::new(ErrorCode::ExpectedInteger, off));
                }
                crate::int::magnitude_to_u128(mag)
                    .ok_or_else(|| CborError::new(ErrorCode::ExpectedInteger, off))
            }
            _ => Err(CborError::new(ErrorCode::ExpectedInteger, off)),
        }
    }

    fn parse_float64(&mut self) -> Result<f64, CborError> {
        let result = self.parse_float64_raw();
        self.seal_value(result)
    }

    fn parse_float64_raw(&mut self) -> Result<f64, CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 7 {
            return Err(CborError::new(ErrorCode::ExpectedFloat, off));
        }
        if ai != 27 {
            if !CHECKED {
                return Err(CborError::new(ErrorCode::ExpectedFloat, off));
            }
            return match ai {
                24 => {
                    let simple = self.cursor.read_u8()?;
                    if simple < 24 {
                        return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                    }
                    Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off))
                }
                28..=30 => Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
                25 | 26 => Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off)),
                _ => Err(CborError::new(ErrorCode::ExpectedFloat, off)),
            };
        }
        if CHECKED && self.options.forbid_float {
            return Err(CborError::new(ErrorCode::FloatForbidden, off));
        }
        let bits = self.cursor.read_be_u64()?;
        if CHECKED {
            validate_f64_bits(bits).map_err(|code| CborError::new(code, off))?;
        }
        Ok(f64::from_bits(bits))
    }

    fn parse_bool(&mut self) -> Result<bool, CborError> {
        let result = self.parse_bool_raw();
        self.seal_value(result)
    }

    fn parse_bool_raw(&mut self) -> Result<bool, CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 7 {
            return Err(CborError::new(ErrorCode::ExpectedBool, off));
        }
        match ai {
            20 | 21 => {
                if CHECKED && self.options.forbid_simple {
                    return Err(CborError::new(ErrorCode::SimpleForbidden, off));
                }
                Ok(ai == 21)
            }
            22 | 27 => Err(CborError::new(ErrorCode::ExpectedBool, off)),
            _ => self.reject_unexpected_simple(ai, off, ErrorCode::ExpectedBool),
        }
    }

    fn parse_null(&mut self) -> Result<(), CborError> {
        let result = self.parse_null_raw();
        self.seal_value(result)
    }

    fn parse_null_raw(&mut self) -> Result<(), CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 7 {
            return Err(CborError::new(ErrorCode::ExpectedNull, off));
        }
        match ai {
            22 => {
                if CHECKED && self.options.forbid_simple {
                    return Err(CborError::new(ErrorCode::SimpleForbidden, off));
                }
                Ok(())
            }
            20 | 21 | 27 => Err(CborError::new(ErrorCode::ExpectedNull, off)),
            _ => self.reject_unexpected_simple(ai, off, ErrorCode::ExpectedNull),
        }
    }

    fn reject_unexpected_simple<T>(
        &mut self,
        ai: u8,
        off: usize,
        expected: ErrorCode,
    ) -> Result<T, CborError> {
        match ai {
            24 => {
                if !CHECKED {
                    return Err(CborError::new(expected, off));
                }
                let simple = self.cursor.read_u8()?;
                if simple < 24 {
                    return Err(CborError::new(ErrorCode::NonCanonicalEncoding, off));
                }
                Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off))
            }
            28..=30 if CHECKED => Err(CborError::new(ErrorCode::ReservedAdditionalInfo, off)),
            _ if CHECKED => Err(CborError::new(ErrorCode::UnsupportedSimpleValue, off)),
            _ => Err(CborError::new(expected, off)),
        }
    }

    fn parse_bytes(&mut self) -> Result<&'de [u8], CborError> {
        let result = self.parse_bytes_raw();
        self.seal_value(result)
    }

    fn parse_bytes_raw(&mut self) -> Result<&'de [u8], CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 2 {
            return Err(CborError::new(ErrorCode::ExpectedBytes, off));
        }
        self.parse_bytes_from_header(off, ai)
    }

    fn parse_text(&mut self) -> Result<&'de str, CborError> {
        let result = self.parse_text_raw();
        self.seal_value(result)
    }

    fn parse_text_raw(&mut self) -> Result<&'de str, CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 3 {
            return Err(CborError::new(ErrorCode::ExpectedText, off));
        }
        self.parse_text_from_header(off, ai)
    }

    /// Decode an array header and return a guard for its elements.
    ///
    /// # Errors
    ///
    /// Returns `ExpectedArray` if the next value is not an array, or a limit error.
    pub fn array(&mut self) -> Result<ArrayDecoder<'_, 'de, CHECKED, O>, CborError> {
        self.require_claimed_traversal_slot()?;
        let header_offset = self.position();
        let entry = self.array_entry();
        let (len, entered) = self.seal_step(entry)?;
        if !entered {
            // An empty array is already a complete value.
            self.note_value_end();
        }
        Ok(ArrayDecoder {
            decoder: self,
            header_offset,
            remaining: len,
            entered,
            admission_open: true,
        })
    }

    fn array_entry(&mut self) -> Result<(usize, bool), CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 4 {
            return Err(CborError::new(ErrorCode::ExpectedArray, off));
        }
        let len = self.read_len(ai, off)?;
        if len > self.limits.max_array_len {
            return Err(CborError::new(ErrorCode::ArrayLenLimitExceeded, off));
        }
        self.bump_items(len, off)?;
        let entered = self.enter_container(len, off)?;
        Ok((len, entered))
    }

    /// Decode a map header and return a guard for its entries.
    ///
    /// # Errors
    ///
    /// Returns `ExpectedMap` if the next value is not a map, or a limit error.
    pub fn map(&mut self) -> Result<MapDecoder<'_, 'de, CHECKED, O>, CborError> {
        self.require_claimed_traversal_slot()?;
        let entry = self.map_entry();
        let (len, entered) = self.seal_step(entry)?;
        if !entered {
            // An empty map is already a complete value.
            self.note_value_end();
        }
        Ok(MapDecoder {
            decoder: self,
            remaining: len,
            entered,
            pending_value: false,
            prev_key_range: None,
        })
    }

    /// Enter an array without borrowing this decoder for the container lifetime.
    ///
    /// The returned state must be driven to completion with
    /// [`Self::array_traversal_next`] and [`Self::finish_array_traversal`].
    ///
    /// # Errors
    ///
    /// Returns a sticky grammar, resource-limit, or traversal-protocol error.
    #[cfg(feature = "alloc")]
    fn begin_array_traversal(&mut self) -> Result<ArrayTraversal, CborError> {
        self.require_claimed_traversal_slot()?;
        let entry = self.array_entry();
        let (remaining, entered) = self.seal_step(entry)?;
        let identity = self.begin_traversal_identity()?;
        if !entered {
            self.note_value_end();
        }
        Ok(ArrayTraversal {
            remaining,
            entered,
            id: identity.id,
            parent_id: identity.parent_id,
            container_depth: identity.container_depth,
            pending_serial: None,
            parent_slot_claimed: identity.parent_slot_claimed,
            parent_slot_depth: identity.parent_slot_depth,
        })
    }

    /// Return the next array element slot, consuming exactly one declared slot.
    ///
    /// # Errors
    ///
    /// Returns a sticky traversal-protocol error when the prior child is incomplete or stale.
    #[cfg(feature = "alloc")]
    fn array_traversal_next(&mut self, traversal: &mut ArrayTraversal) -> Result<bool, CborError> {
        self.sync_array_traversal(traversal)?;
        if traversal.remaining == 0 {
            return Ok(false);
        }
        traversal.remaining -= 1;
        traversal.pending_serial = Some(self.completed_values);
        self.active_traversal_slot = Some(traversal.id);
        self.active_traversal_slot_depth = Some(traversal.container_depth);
        Ok(true)
    }

    /// Confirm that the claimed array element completed and restore the traversal to its next
    /// element phase.
    ///
    /// # Errors
    ///
    /// Returns a sticky traversal-protocol error when the child is incomplete or nested.
    #[cfg(feature = "alloc")]
    fn array_traversal_child_complete(
        &mut self,
        traversal: &mut ArrayTraversal,
    ) -> Result<(), CborError> {
        self.sync_array_traversal(traversal)
    }

    /// Close a completed explicitly-driven array traversal.
    ///
    /// # Errors
    ///
    /// Returns a sticky traversal-protocol error unless every declared element completed.
    #[cfg(feature = "alloc")]
    fn finish_array_traversal(&mut self, mut traversal: ArrayTraversal) -> Result<(), CborError> {
        self.sync_array_traversal(&mut traversal)?;
        if traversal.remaining != 0 {
            return self.traversal_protocol_error();
        }
        self.active_traversal_id = traversal.parent_id;
        self.active_traversal_slot = traversal
            .parent_id
            .filter(|_| traversal.parent_slot_claimed);
        self.active_traversal_slot_depth = traversal.parent_slot_depth;
        if traversal.entered {
            self.exit_container();
            self.note_value_end();
        }
        self.complete_work(1)
    }

    /// Enter a map without borrowing this decoder for the container lifetime.
    ///
    /// # Errors
    ///
    /// Returns a sticky grammar, resource-limit, or traversal-protocol error.
    #[cfg(feature = "alloc")]
    fn begin_map_traversal(&mut self) -> Result<MapTraversal, CborError> {
        self.require_claimed_traversal_slot()?;
        let entry = self.map_entry();
        let (remaining, entered) = self.seal_step(entry)?;
        let identity = self.begin_traversal_identity()?;
        if !entered {
            self.note_value_end();
        }
        Ok(MapTraversal {
            remaining,
            entered,
            pending_value: false,
            prev_key_range: None,
            id: identity.id,
            parent_id: identity.parent_id,
            container_depth: identity.container_depth,
            pending_serial: None,
            parent_slot_claimed: identity.parent_slot_claimed,
            parent_slot_depth: identity.parent_slot_depth,
        })
    }

    /// Consume the next canonical text key from an explicitly-driven map.
    ///
    /// # Errors
    ///
    /// Returns a sticky grammar or traversal-protocol error.
    #[cfg(feature = "alloc")]
    fn map_traversal_next_key(
        &mut self,
        traversal: &mut MapTraversal,
    ) -> Result<Option<MapKey<'de>>, CborError> {
        self.sync_map_traversal(traversal)?;
        if traversal.pending_value {
            return self.traversal_protocol_error();
        }
        if traversal.remaining == 0 {
            return Ok(None);
        }
        let result = (|| {
            let key_start = self.position();
            let (major, ai, off) = self.read_header()?;
            if major != 3 {
                return Err(CborError::new(ErrorCode::MapKeyMustBeText, off));
            }
            let key = self.parse_text_from_header(off, ai)?;
            let key_end = self.position();
            if CHECKED {
                wire::check_map_key_order_observed(
                    self.data(),
                    &mut traversal.prev_key_range,
                    key_start,
                    key_end,
                    &mut self.work,
                    key_end,
                )?;
            }
            Ok(Some(MapKey {
                text: key,
                offset: key_start,
                encoded_range: key_start..key_end,
            }))
        })();
        match result {
            Ok(key) => {
                traversal.pending_value = true;
                Ok(key)
            }
            Err(error) => {
                self.poison_err(error);
                Err(error)
            }
        }
    }

    /// Consume the pending value slot of an explicitly-driven map.
    ///
    /// # Errors
    ///
    /// Returns a sticky traversal-protocol error when no key is pending.
    #[cfg(feature = "alloc")]
    fn map_traversal_value(&mut self, traversal: &mut MapTraversal) -> Result<(), CborError> {
        self.sync_traversal_identity(traversal.id, traversal.container_depth)?;
        if !traversal.pending_value {
            return self.traversal_protocol_error();
        }
        traversal.pending_value = false;
        traversal.remaining -= 1;
        traversal.pending_serial = Some(self.completed_values);
        self.active_traversal_slot = Some(traversal.id);
        self.active_traversal_slot_depth = Some(traversal.container_depth);
        Ok(())
    }

    /// Confirm that the pending map value completed before the next key is requested.
    ///
    /// # Errors
    ///
    /// Returns a sticky traversal-protocol error when the value is incomplete or nested.
    #[cfg(feature = "alloc")]
    fn map_traversal_value_complete(
        &mut self,
        traversal: &mut MapTraversal,
    ) -> Result<(), CborError> {
        self.sync_map_traversal(traversal)
    }

    /// Close a completed explicitly-driven map traversal.
    ///
    /// # Errors
    ///
    /// Returns a sticky traversal-protocol error unless every entry completed.
    #[cfg(feature = "alloc")]
    fn finish_map_traversal(&mut self, mut traversal: MapTraversal) -> Result<(), CborError> {
        self.sync_map_traversal(&mut traversal)?;
        if traversal.remaining != 0 || traversal.pending_value {
            return self.traversal_protocol_error();
        }
        self.active_traversal_id = traversal.parent_id;
        self.active_traversal_slot = traversal
            .parent_id
            .filter(|_| traversal.parent_slot_claimed);
        self.active_traversal_slot_depth = traversal.parent_slot_depth;
        if traversal.entered {
            self.exit_container();
            self.note_value_end();
        }
        self.complete_work(1)
    }

    #[cfg(feature = "alloc")]
    fn begin_traversal_identity(&mut self) -> Result<TraversalIdentity, CborError> {
        let id = self.next_traversal_id;
        let Some(next) = id.checked_add(1) else {
            let error = CborError::new(ErrorCode::LengthOverflow, self.position());
            self.poison_err(error);
            return Err(error);
        };
        self.next_traversal_id = next;
        let parent_id = self.active_traversal_id;
        let parent_slot_claimed =
            parent_id.is_some_and(|parent| self.active_traversal_slot == Some(parent));
        let parent_slot_depth = self.active_traversal_slot_depth;
        self.active_traversal_id = Some(id);
        self.active_traversal_slot = None;
        self.active_traversal_slot_depth = None;
        Ok(TraversalIdentity {
            id,
            parent_id,
            container_depth: self.depth,
            parent_slot_claimed,
            parent_slot_depth,
        })
    }

    fn require_claimed_traversal_slot(&mut self) -> Result<(), CborError> {
        if let Some(active) = self.active_traversal_id {
            if self.active_traversal_slot != Some(active) {
                return self.traversal_protocol_error();
            }
        }
        Ok(())
    }

    #[cfg(feature = "alloc")]
    fn sync_array_traversal(&mut self, traversal: &mut ArrayTraversal) -> Result<(), CborError> {
        self.sync_traversal_identity(traversal.id, traversal.container_depth)?;
        let had_pending = traversal.pending_serial.is_some();
        self.sync_traversal_child(&mut traversal.pending_serial)?;
        if had_pending {
            self.active_traversal_slot = None;
            self.active_traversal_slot_depth = None;
            self.complete_work(1)?;
        }
        Ok(())
    }

    #[cfg(feature = "alloc")]
    fn sync_map_traversal(&mut self, traversal: &mut MapTraversal) -> Result<(), CborError> {
        self.sync_traversal_identity(traversal.id, traversal.container_depth)?;
        let had_pending = traversal.pending_serial.is_some();
        self.sync_traversal_child(&mut traversal.pending_serial)?;
        if had_pending {
            self.active_traversal_slot = None;
            self.active_traversal_slot_depth = None;
            self.complete_work(1)?;
        }
        Ok(())
    }

    #[cfg(feature = "alloc")]
    fn sync_traversal_identity(&mut self, id: u64, depth: usize) -> Result<(), CborError> {
        self.check_poison()?;
        if self.active_traversal_id != Some(id) || self.depth != depth {
            return self.traversal_protocol_error();
        }
        Ok(())
    }

    #[cfg(feature = "alloc")]
    const fn sync_traversal_child(&mut self, serial: &mut Option<usize>) -> Result<(), CborError> {
        if let Some(before) = *serial {
            if self.completed_values <= before {
                return self.traversal_protocol_error();
            }
            *serial = None;
        }
        Ok(())
    }

    const fn traversal_protocol_error<T>(&mut self) -> Result<T, CborError> {
        let error = CborError::new(ErrorCode::MalformedCanonical, self.position());
        self.poison_err(error);
        Err(error)
    }

    fn map_entry(&mut self) -> Result<(usize, bool), CborError> {
        let (major, ai, off) = self.read_header()?;
        if major != 5 {
            return Err(CborError::new(ErrorCode::ExpectedMap, off));
        }
        let len = self.read_len(ai, off)?;
        if len > self.limits.max_map_len {
            return Err(CborError::new(ErrorCode::MapLenLimitExceeded, off));
        }
        let items = len
            .checked_mul(2)
            .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, off))?;
        self.bump_items(items, off)?;
        let entered = self.enter_container(len, off)?;
        Ok((len, entered))
    }

    /// Skip exactly one CBOR value while enforcing decode limits.
    ///
    /// # Errors
    ///
    /// Returns a decode error if the value is malformed or violates limits.
    pub fn skip_value(&mut self) -> Result<(), CborError> {
        self.check_poison()?;
        let result = wire::skip_one_value_with_scratch_observed::<CHECKED, O>(
            &mut self.cursor,
            wire::WalkPolicy::new(Some(&self.limits), self.options),
            &mut self.items_seen,
            self.depth,
            &mut self.scratch,
            &mut self.work,
        );
        self.seal_value(result)
    }

    /// Decode one complete canonical encoded value after caller admission.
    ///
    /// The decoder traverses the value once, enforcing its grammar and resource limits, then calls
    /// `admit` with the value's offset and encoded length. The callback therefore runs before any
    /// caller-owned copy while retaining the same single traversal used by [`Self::skip_value`]. A
    /// callback rejection is sticky: every later decoder operation returns a protocol error.
    ///
    /// # Errors
    ///
    /// Returns a decode error converted into `E`, or the callback's error unchanged.
    pub fn decode_canonical_with_guard<E, F>(
        &mut self,
        admit: F,
    ) -> Result<CanonicalCborRef<'de>, E>
    where
        E: From<CborError>,
        F: FnOnce(EncodedValueHeader) -> Result<(), E>,
    {
        let start = self.position();
        self.skip_value().map_err(E::from)?;
        let end = self.position();
        let header = EncodedValueHeader {
            header_offset: start,
            encoded_len: end - start,
        };
        if let Err(err) = admit(header) {
            self.poison(ErrorCode::MalformedCanonical, start);
            return Err(err);
        }
        Ok(CanonicalCborRef::new(&self.data()[start..end]))
    }

    /// Peek at the kind of the next CBOR value without consuming it.
    ///
    /// # Errors
    ///
    /// Returns a decode error if the header is malformed.
    pub fn peek_kind(&self) -> Result<CborKind, CborError> {
        self.check_poison()?;
        let mut pos = self.cursor.position();
        peek_kind_at::<CHECKED>(self.data(), &mut pos)
    }
}

impl<'de, const CHECKED: bool, O: WorkObserver> ArrayDecoder<'_, 'de, CHECKED, O> {
    /// Admit this array using its already-decoded header metadata.
    ///
    /// This consumes and returns the guard so admission cannot be accidentally separated from the
    /// array traversal. Admission is allowed exactly once and only before the first element is
    /// consumed. The callback runs after structural and resource-limit checks. Rejecting an empty
    /// array is sticky even though the array has no elements to consume.
    ///
    /// # Errors
    ///
    /// Returns the callback's error unchanged and poisons the underlying decoder. Repeated or late
    /// admission returns a converted protocol error and also poisons the decoder.
    pub fn admit_with<E, F>(mut self, admit: F) -> Result<Self, E>
    where
        E: From<CborError>,
        F: FnOnce(ContainerHeader) -> Result<(), E>,
    {
        self.decoder.check_poison().map_err(E::from)?;
        if !self.admission_open {
            let error = CborError::new(ErrorCode::MalformedCanonical, self.header_offset);
            self.decoder.poison_err(error);
            return Err(E::from(error));
        }
        self.admission_open = false;
        let header = ContainerHeader {
            header_offset: self.header_offset,
            declared_len: self.remaining,
        };
        if let Err(err) = admit(header) {
            self.decoder
                .poison(ErrorCode::MalformedCanonical, self.header_offset);
            return Err(err);
        }
        Ok(self)
    }

    /// Remaining elements in the array.
    #[inline]
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.remaining
    }

    /// Current byte offset of the underlying decoder.
    #[inline]
    #[must_use]
    pub const fn position(&self) -> usize {
        self.decoder.position()
    }

    /// Decode the next array element.
    ///
    /// Returns `Ok(None)` when the array is exhausted.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails.
    pub fn next_value<T: CborDecode<'de>>(&mut self) -> Result<Option<T>, CborError> {
        self.decoder.check_poison()?;
        if self.remaining == 0 {
            return Ok(None);
        }
        self.admission_open = false;
        let value = T::decode(self.decoder)?;
        self.remaining -= 1;
        self.decoder.complete_work(1)?;
        Ok(Some(value))
    }

    /// Decode the next array element using a custom decoder.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails.
    pub fn decode_next<F, T>(&mut self, f: F) -> Result<Option<T>, CborError>
    where
        F: FnOnce(&mut Decoder<'de, CHECKED, O>) -> Result<T, CborError>,
    {
        self.decode_next_with(f)
    }

    /// Decode the next array element using a custom decoder with a
    /// caller-defined error type.
    ///
    /// A caller error aborts the element mid-consumption, so it poisons
    /// the decoder like any decode failure: the pass can no longer reach
    /// [`Decoder::finish`].
    ///
    /// # Errors
    ///
    /// Returns the closure's error, or a decode error if the array is
    /// malformed.
    pub fn decode_next_with<F, T, E>(&mut self, f: F) -> Result<Option<T>, E>
    where
        F: FnOnce(&mut Decoder<'de, CHECKED, O>) -> Result<T, E>,
        E: From<CborError>,
    {
        self.decoder.check_poison().map_err(E::from)?;
        if self.remaining == 0 {
            return Ok(None);
        }
        self.admission_open = false;
        match f(self.decoder) {
            Ok(value) => {
                self.remaining -= 1;
                self.decoder.complete_work(1).map_err(E::from)?;
                Ok(Some(value))
            }
            Err(err) => {
                let off = self.decoder.position();
                self.decoder.poison(ErrorCode::MalformedCanonical, off);
                Err(err)
            }
        }
    }

    /// Skip all remaining elements in the array.
    ///
    /// # Errors
    ///
    /// Returns an error if skipping fails.
    pub fn skip_remaining(&mut self) -> Result<(), CborError> {
        self.decoder.check_poison()?;
        if self.remaining > 0 {
            self.admission_open = false;
        }
        while self.remaining > 0 {
            self.decoder.skip_value()?;
            self.remaining -= 1;
            self.decoder.complete_work(1)?;
        }
        Ok(())
    }

    /// Consume all remaining elements, requiring each to be a scalar of
    /// `kind`.
    ///
    /// This is the batch form of [`Decoder::skip_scalar`]: one tight loop of
    /// direct scalar funnels, with no per-element dispatch. All
    /// canonical-grammar checks, decode limits, and restriction modes apply
    /// to every element.
    ///
    /// # Errors
    ///
    /// Returns an error at the first element that is not a scalar of `kind`
    /// (the kind's `Expected*` code at that element's header offset), is
    /// malformed, or violates limits or validation options.
    pub fn skip_scalars(&mut self, kind: ScalarKind) -> Result<(), CborError> {
        self.decoder.check_poison()?;
        if self.remaining > 0 {
            self.admission_open = false;
        }
        while self.remaining > 0 {
            let result = self.decoder.consume_scalar_raw(kind);
            self.decoder.seal_value(result)?;
            self.remaining -= 1;
            self.decoder.complete_work(1)?;
        }
        Ok(())
    }

    /// Consume the next element, requiring a scalar of `kind`, and return
    /// the byte range of its canonical encoding inside the input.
    ///
    /// Returns `Ok(None)` when the array is exhausted. The returned range is
    /// the element's complete encoding (header and payload), suitable for
    /// canonical byte comparisons.
    ///
    /// # Errors
    ///
    /// Returns an error if the next element is not a scalar of `kind`, is
    /// malformed, or violates limits or validation options.
    pub fn next_scalar_span(
        &mut self,
        kind: ScalarKind,
    ) -> Result<Option<Range<usize>>, CborError> {
        self.decoder.check_poison()?;
        if self.remaining == 0 {
            return Ok(None);
        }
        self.admission_open = false;
        let start = self.decoder.position();
        let result = self.decoder.consume_scalar_raw(kind);
        self.decoder.seal_value(result)?;
        self.remaining -= 1;
        self.decoder.complete_work(1)?;
        Ok(Some(start..self.decoder.position()))
    }

    /// Consume all remaining elements, requiring each to be a scalar of
    /// `kind` and the sequence to be strictly ascending by unsigned
    /// lexicographic (memcmp) order of the elements' canonical encodings.
    ///
    /// This is the sorted-set form of [`skip_scalars`](Self::skip_scalars)
    /// with the order comparison inlined into the batch loop. Canonical
    /// encodings are self-delimiting — no element encoding is a proper
    /// prefix of a different complete encoding — so memcmp order is total,
    /// and equality of encodings is equality of values.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::DuplicateElement`] when an element's encoding
    /// equals its predecessor's and [`ErrorCode::NonAscendingElement`] when
    /// it sorts below it, both at the element's header offset; otherwise as
    /// [`skip_scalars`](Self::skip_scalars). Order failures poison the
    /// decoder like any failed consuming operation.
    pub fn skip_sorted_scalars(&mut self, kind: ScalarKind) -> Result<(), CborError> {
        self.decoder.check_poison()?;
        if self.remaining > 0 {
            self.admission_open = false;
        }
        let data = self.decoder.cursor.data();
        let mut prev: Option<Range<usize>> = None;
        while self.remaining > 0 {
            let start = self.decoder.position();
            let result = self.decoder.consume_scalar_raw(kind);
            self.decoder.seal_value(result)?;
            self.remaining -= 1;
            let end = self.decoder.position();
            if let Some(prev_range) = prev {
                let Ok(order) = cmp_bytes_observed(
                    &data[prev_range],
                    &data[start..end],
                    &mut self.decoder.work,
                ) else {
                    let error = CborError::new(ErrorCode::WorkCancelled, end);
                    self.decoder.poison_err(error);
                    return Err(error);
                };
                if order != core::cmp::Ordering::Less {
                    let code = if order == core::cmp::Ordering::Equal {
                        ErrorCode::DuplicateElement
                    } else {
                        ErrorCode::NonAscendingElement
                    };
                    let err = CborError::new(code, start);
                    self.decoder.poison_err(err);
                    return Err(err);
                }
            }
            prev = Some(start..end);
            self.decoder.complete_work(1)?;
        }
        Ok(())
    }
}

impl<'de, const CHECKED: bool, O: WorkObserver> MapDecoder<'_, 'de, CHECKED, O> {
    /// Remaining entries in the map.
    #[inline]
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.remaining
    }

    /// Current byte offset of the underlying decoder.
    #[inline]
    #[must_use]
    pub const fn position(&self) -> usize {
        self.decoder.position()
    }

    /// Decode the next map key as text with source offsets.
    ///
    /// Returns `Ok(None)` when the map is exhausted.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails or the map is malformed.
    pub fn next_key_ref(&mut self) -> Result<Option<MapKey<'de>>, CborError> {
        self.decoder.check_poison()?;
        // Pending-state misuse is detected before any byte is consumed —
        // recoverable, never sticky.
        if self.pending_value {
            return Err(CborError::new(
                ErrorCode::MalformedCanonical,
                self.decoder.position(),
            ));
        }
        if self.remaining == 0 {
            return Ok(None);
        }
        let result = self.next_key_ref_consume();
        if let Err(err) = &result {
            self.decoder.poison_err(*err);
        }
        result
    }

    fn next_key_ref_consume(&mut self) -> Result<Option<MapKey<'de>>, CborError> {
        let key_start = self.decoder.position();
        let (major, ai, off) = self.decoder.read_header()?;
        if major != 3 {
            return Err(CborError::new(ErrorCode::MapKeyMustBeText, off));
        }
        let key = self.decoder.parse_text_from_header(off, ai)?;
        let key_end = self.decoder.position();
        if CHECKED {
            wire::check_map_key_order_observed(
                self.decoder.data(),
                &mut self.prev_key_range,
                key_start,
                key_end,
                &mut self.decoder.work,
                key_end,
            )?;
        }
        self.pending_value = true;
        Ok(Some(MapKey {
            text: key,
            offset: key_start,
            encoded_range: key_start..key_end,
        }))
    }

    /// Decode the value corresponding to the last returned key.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails or the map is malformed.
    pub fn next_value<T: CborDecode<'de>>(&mut self) -> Result<T, CborError> {
        self.decode_value(T::decode)
    }

    /// Decode the value corresponding to the last returned key using a custom decoder.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails or the map is malformed.
    pub fn decode_value<F, T>(&mut self, f: F) -> Result<T, CborError>
    where
        F: FnOnce(&mut Decoder<'de, CHECKED, O>) -> Result<T, CborError>,
    {
        self.decode_value_with(f)
    }

    /// Decode the value corresponding to the last returned key using a
    /// custom decoder with a caller-defined error type.
    ///
    /// A caller error aborts the value mid-consumption, so it poisons the
    /// decoder like any decode failure: the pass can no longer reach
    /// [`Decoder::finish`].
    ///
    /// # Errors
    ///
    /// Returns the closure's error, or a decode error if the map is
    /// malformed.
    pub fn decode_value_with<F, T, E>(&mut self, f: F) -> Result<T, E>
    where
        F: FnOnce(&mut Decoder<'de, CHECKED, O>) -> Result<T, E>,
        E: From<CborError>,
    {
        self.decoder.check_poison().map_err(E::from)?;
        if !self.pending_value {
            // Detected before any byte is consumed — recoverable.
            let err = CborError::new(ErrorCode::MalformedCanonical, self.decoder.position());
            return Err(E::from(err));
        }
        match f(self.decoder) {
            Ok(value) => {
                self.pending_value = false;
                self.remaining -= 1;
                self.decoder.complete_work(1).map_err(E::from)?;
                Ok(value)
            }
            Err(err) => {
                // The value may be partially consumed; the original decode
                // error (if any) was already stored by the failing funnel
                // and poison_err keeps the first error.
                let off = self.decoder.position();
                self.decoder.poison(ErrorCode::MalformedCanonical, off);
                Err(err)
            }
        }
    }

    /// Skip the value corresponding to the last returned key.
    ///
    /// # Errors
    ///
    /// Returns an error if no key is pending or if skipping fails.
    pub fn skip_value(&mut self) -> Result<(), CborError> {
        self.decoder.check_poison()?;
        if !self.pending_value {
            // Detected before any byte is consumed — recoverable.
            return Err(CborError::new(
                ErrorCode::MalformedCanonical,
                self.decoder.position(),
            ));
        }
        self.decoder.skip_value()?;
        self.pending_value = false;
        self.remaining -= 1;
        self.decoder.complete_work(1)?;
        Ok(())
    }

    /// Decode the next key/value entry in the map.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails or the map is malformed.
    pub fn next_entry<V: CborDecode<'de>>(&mut self) -> Result<Option<(&'de str, V)>, CborError> {
        let Some(key) = self.next_key_ref()? else {
            return Ok(None);
        };
        let value = self.next_value()?;
        Ok(Some((key.text, value)))
    }

    /// Skip all remaining map entries.
    ///
    /// # Errors
    ///
    /// Returns an error if skipping fails or the map is malformed.
    pub fn skip_remaining(&mut self) -> Result<(), CborError> {
        self.decoder.check_poison()?;
        while self.remaining > 0 {
            if !self.pending_value {
                let _ = self.next_key_ref()?;
            }
            self.skip_value()?;
        }
        Ok(())
    }
}

/// Validate canonical CBOR and decode a value using `CborDecode`.
///
/// # Errors
///
/// Returns an error if the input is not canonical CBOR or if decoding fails.
pub fn decode<'de, T: CborDecode<'de>>(
    bytes: &'de [u8],
    limits: DecodeLimits,
) -> Result<T, CborError> {
    decode_with_observer(bytes, limits, NoopWorkObserver)
}

/// Validate canonical CBOR and decode a value through a caller-provided work observer.
///
/// The observer is owned for the duration of the operation. Successful decoding flushes the final
/// completed-work remainder before returning the value.
/// Checked text validation is chunked. When `T` requires a whole borrowed `&str`, safe builds still
/// require one final opaque standard-library slice-to-string conversion; it is not charged twice
/// and cannot itself be cooperatively interrupted.
///
/// # Errors
///
/// Returns an error if the input is not exactly one canonical CBOR value, decoding fails, a limit
/// is exceeded, or the observer requests cancellation.
pub fn decode_with_observer<'de, T, O>(
    bytes: &'de [u8],
    limits: DecodeLimits,
    observer: O,
) -> Result<T, CborError>
where
    T: CborDecode<'de>,
    O: WorkObserver,
{
    let mut decoder = Decoder::<true, O>::new_checked_observed(bytes, limits, observer)?;
    let value = T::decode(&mut decoder)?;
    let _ = decoder.finish()?;
    Ok(value)
}

/// Decode a value from validated canonical bytes.
///
/// # Errors
///
/// Returns an error if decoding fails.
pub fn decode_canonical<'de, T: CborDecode<'de>>(
    canon: CanonicalCborRef<'de>,
    limits: DecodeLimits,
) -> Result<T, CborError> {
    decode_canonical_with_observer(canon, limits, NoopWorkObserver)
}

/// Decode one value from canonical bytes through a caller-provided work observer.
///
/// The observer is owned for the duration of the operation. Successful decoding flushes the final
/// completed-work remainder before returning the value.
/// When `T` requires a whole borrowed `&str`, safe builds perform an opaque standard-library
/// slice-to-string conversion that cannot itself be cooperatively interrupted.
///
/// # Errors
///
/// Returns an error if the witness does not contain exactly one decoded value, decoding fails, a
/// limit is exceeded, or the observer requests cancellation.
pub fn decode_canonical_with_observer<'de, T, O>(
    canon: CanonicalCborRef<'de>,
    limits: DecodeLimits,
    observer: O,
) -> Result<T, CborError>
where
    T: CborDecode<'de>,
    O: WorkObserver,
{
    let mut decoder = Decoder::<false, O>::new_trusted_observed(canon, limits, observer)?;
    let value = T::decode(&mut decoder)?;
    let _ = decoder.finish()?;
    Ok(value)
}

impl<'de> CborDecode<'de> for () {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        decoder.parse_null()
    }
}

#[allow(clippy::use_self)]
impl<'de> CborDecode<'de> for bool {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        decoder.parse_bool()
    }
}

impl<'de> CborDecode<'de> for i64 {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_i128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for i32 {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_i128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for i16 {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_i128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for i8 {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_i128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for isize {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_i128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for i128 {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        decoder.parse_integer_i128()
    }
}

impl<'de> CborDecode<'de> for u64 {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_u128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for u32 {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_u128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for u16 {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_u128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for u8 {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_u128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for usize {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_integer_u128()?;
        Self::try_from(v).map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))
    }
}

impl<'de> CborDecode<'de> for u128 {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        decoder.parse_integer_u128()
    }
}

#[cfg(feature = "alloc")]
impl<'de> CborDecode<'de> for BigInt {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let (parts, off) = decoder.parse_integer_parts()?;
        match parts {
            IntegerParts::Big { negative, mag } => {
                let magnitude = alloc_util::try_vec_from_slice(mag, off)?;
                Self::new(negative, magnitude).map_err(|err| CborError::new(err.code, off))
            }
            IntegerParts::SafePos(_) | IntegerParts::SafeNeg(_) => {
                Err(CborError::new(ErrorCode::ExpectedInteger, off))
            }
        }
    }
}

#[cfg(feature = "alloc")]
impl<'de> CborDecode<'de> for Integer {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let (parts, off) = decoder.parse_integer_parts()?;
        match parts {
            IntegerParts::SafePos(v) => {
                let v_i = i64::try_from(v)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))?;
                Self::safe(v_i).map_err(|err| CborError::new(err.code, off))
            }
            IntegerParts::SafeNeg(n) => {
                let n_i = i64::try_from(n)
                    .map_err(|_| CborError::new(ErrorCode::ExpectedInteger, off))?;
                Self::safe(-1 - n_i).map_err(|err| CborError::new(err.code, off))
            }
            IntegerParts::Big { negative, mag } => {
                let magnitude = alloc_util::try_vec_from_slice(mag, off)?;
                Self::big(negative, magnitude).map_err(|err| CborError::new(err.code, off))
            }
        }
    }
}

impl<'de> CborDecode<'de> for f64 {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        decoder.parse_float64()
    }
}

impl<'de> CborDecode<'de> for f32 {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let v = decoder.parse_float64()?;
        if v.is_nan() {
            return Ok(Self::NAN);
        }
        let bits = v.to_bits();
        let sign = ((bits >> 63) as u32) << 31;
        let exp = ((bits >> 52) & 0x7ff) as i32;
        let mant = bits & 0x000f_ffff_ffff_ffff;
        if exp == 0x7ff {
            if mant != 0 {
                return Ok(Self::NAN);
            }
            return Ok(Self::from_bits(sign | 0x7f80_0000));
        }
        if exp == 0 {
            if mant == 0 {
                return Ok(Self::from_bits(sign));
            }
            return Err(CborError::new(ErrorCode::ExpectedFloat, off));
        }

        let e = exp - 1023;
        let mant_with_hidden = (1u64 << 52) | mant;
        if e > 127 {
            return Err(CborError::new(ErrorCode::ExpectedFloat, off));
        }
        if e >= -126 {
            let lower = mant_with_hidden & ((1u64 << 29) - 1);
            if lower != 0 {
                return Err(CborError::new(ErrorCode::ExpectedFloat, off));
            }
            let mant32 = u32::try_from(mant_with_hidden >> 29)
                .map_err(|_| CborError::new(ErrorCode::ExpectedFloat, off))?
                & 0x7f_ffff;
            let exp32 = u32::try_from(e + 127)
                .map_err(|_| CborError::new(ErrorCode::ExpectedFloat, off))?;
            return Ok(Self::from_bits(sign | (exp32 << 23) | mant32));
        }
        if e >= -149 {
            let shift = u32::try_from(-e - 97)
                .map_err(|_| CborError::new(ErrorCode::ExpectedFloat, off))?;
            let lower = mant_with_hidden & ((1u64 << shift) - 1);
            if lower != 0 {
                return Err(CborError::new(ErrorCode::ExpectedFloat, off));
            }
            let mant32 = u32::try_from(mant_with_hidden >> shift)
                .map_err(|_| CborError::new(ErrorCode::ExpectedFloat, off))?;
            if mant32 == 0 || mant32 > 0x7f_ffff {
                return Err(CborError::new(ErrorCode::ExpectedFloat, off));
            }
            return Ok(Self::from_bits(sign | mant32));
        }
        Err(CborError::new(ErrorCode::ExpectedFloat, off))
    }
}

impl<'de, 'a> CborDecode<'de> for &'a str
where
    'de: 'a,
{
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        decoder.parse_text()
    }
}

impl<'de, 'a> CborDecode<'de> for &'a [u8]
where
    'de: 'a,
{
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        decoder.parse_bytes()
    }
}

impl<'de, 'a> CborDecode<'de> for BytesRef<'a>
where
    'de: 'a,
{
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        decoder.parse_bytes().map(BytesRef::new)
    }
}

impl<'de> CborDecode<'de> for IntegerRef<'de> {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        decoder.parse_integer_ref()
    }
}

impl<'de> CborDecode<'de> for CborValueRef<'de> {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let start = decoder.position();
        decoder.skip_value()?;
        let end = decoder.position();
        Ok(CborValueRef::new(decoder.data(), start, end))
    }
}

#[cfg(feature = "alloc")]
impl<'de, T: CborDecode<'de>> CborDecode<'de> for Option<T> {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let map_off = decoder.position();
        let mut map = decoder.map()?;
        if map.remaining() != 1 {
            return Err(CborError::new(ErrorCode::MapLenMismatch, map_off));
        }
        let Some(key) = map.next_key_ref()? else {
            return Err(CborError::new(ErrorCode::MapLenMismatch, map_off));
        };
        match key.text {
            "none" => {
                let _: () = map.next_value()?;
                Ok(None)
            }
            "some" => map.next_value().map(Some),
            _ => Err(CborError::new(ErrorCode::UnknownEnumVariant, key.offset)),
        }
    }
}

#[cfg(feature = "collections")]
impl<'de, T: CborDecode<'de>> CborDecode<'de> for Vec<T> {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let mut array = decoder.array()?;
        let mut out = alloc_util::try_vec_with_capacity::<T>(array.remaining(), off)?;
        while let Some(item) = array.next_value()? {
            out.push(item);
        }
        Ok(out)
    }
}

#[cfg(feature = "collections")]
impl<'de, V: CborDecode<'de>> CborDecode<'de> for MapEntries<&'de str, V> {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let mut map = decoder.map()?;
        let mut out = alloc_util::try_vec_with_capacity::<(&'de str, V)>(map.remaining(), off)?;
        while let Some((key, value)) = map.next_entry()? {
            out.push((key, value));
        }
        Ok(Self(out))
    }
}

#[cfg(feature = "collections")]
impl<'de, V: CborDecode<'de>> CborDecode<'de> for MapEntries<String, V> {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let mut map = decoder.map()?;
        let mut out = alloc_util::try_vec_with_capacity::<(String, V)>(map.remaining(), off)?;
        while let Some(key) = map.next_key_ref()? {
            let value = map.next_value()?;
            let owned = alloc_util::try_string_from_str(key.text, off)?;
            out.push((owned, value));
        }
        Ok(Self(out))
    }
}

#[cfg(feature = "alloc")]
impl<'de> CborDecode<'de> for String {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let s = decoder.parse_text()?;
        alloc_util::try_string_from_str(s, off)
    }
}

#[cfg(feature = "alloc")]
impl<'de> CborDecode<'de> for Bytes {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let bytes = decoder.parse_bytes()?;
        Ok(Self::new(alloc_util::try_vec_from_slice(bytes, off)?))
    }
}

impl<'de, const N: usize> CborDecode<'de> for [u8; N] {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let bytes = decoder.parse_bytes()?;
        if bytes.len() != N {
            return Err(CborError::new(ErrorCode::ExpectedBytes, off));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }
}

impl<'de> CborDecode<'de> for CanonicalCborRef<'de> {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let start = decoder.position();
        decoder.skip_value()?;
        let end = decoder.position();
        Ok(CanonicalCborRef::new(&decoder.data()[start..end]))
    }
}

#[cfg(feature = "alloc")]
impl<'de> CborDecode<'de> for CanonicalCbor {
    fn decode<const CHECKED: bool, O: WorkObserver>(
        decoder: &mut Decoder<'de, CHECKED, O>,
    ) -> Result<Self, CborError> {
        let off = decoder.position();
        let canon_ref = CanonicalCborRef::decode(decoder)?;
        let bytes = alloc_util::try_vec_from_slice(canon_ref.as_bytes(), off)?;
        Ok(Self::new_unchecked(bytes))
    }
}
