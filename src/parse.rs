use crate::canonical::CanonicalCborRef;
use crate::wire::{self, Cursor, WalkPolicy};
use crate::work::{NoopWorkObserver, WorkMeter, WorkObserver};
use crate::{CborError, DecodeLimits, ErrorCode, ValidationOptions};

/// Validate that `bytes` contain exactly one canonical SACP-CBOR/1 data item and return a wrapper.
///
/// Accepts the full SACP-CBOR/1 grammar. Use [`validate_canonical_with`] to apply restriction
/// modes such as [`ValidationOptions::no_float`].
///
/// # Errors
///
/// Returns an error if decoding fails (EOF, trailing bytes, limit violations) or if validation fails
/// (non-canonical encoding, forbidden tags, map ordering, etc.).
pub fn validate_canonical(
    bytes: &'_ [u8],
    limits: DecodeLimits,
) -> Result<CanonicalCborRef<'_>, CborError> {
    validate_canonical_with(bytes, limits, ValidationOptions::new())
}

/// Validate that `bytes` contain exactly one canonical SACP-CBOR/1 data item under explicit
/// [`ValidationOptions`], and return a wrapper.
///
/// Restriction modes only reject more inputs: every item accepted under a restriction mode is
/// also a valid SACP-CBOR/1 item. The returned witness attests SACP-CBOR/1 canonicality; holding
/// a restriction across later edits requires re-validating the edited output under the same
/// options.
///
/// # Errors
///
/// Returns an error if decoding fails (EOF, trailing bytes, limit violations), if validation fails
/// (non-canonical encoding, forbidden tags, map ordering, etc.), or if a restriction mode rejects
/// the item (e.g. [`ErrorCode::FloatForbidden`] under [`ValidationOptions::no_float`]).
pub fn validate_canonical_with(
    bytes: &'_ [u8],
    limits: DecodeLimits,
    options: ValidationOptions,
) -> Result<CanonicalCborRef<'_>, CborError> {
    let mut meter = WorkMeter::new(NoopWorkObserver);
    validate_canonical_with_meter(bytes, limits, options, &mut meter)
}

/// Validate one canonical SACP-CBOR/1 data item with cooperative work observation.
///
/// The observer receives an initial zero checkpoint before traversal, deterministic completed-work
/// deltas during traversal, and a final non-zero remainder before success. Returning cancellation
/// stops the walk and reports [`ErrorCode::WorkCancelled`] at the current input offset.
///
/// # Errors
///
/// Returns the same grammar and resource-limit errors as [`validate_canonical`], or
/// [`ErrorCode::WorkCancelled`] if `observer` requests cancellation.
pub fn validate_canonical_observed<O: WorkObserver>(
    bytes: &'_ [u8],
    limits: DecodeLimits,
    observer: O,
) -> Result<CanonicalCborRef<'_>, CborError> {
    validate_canonical_with_observer(bytes, limits, ValidationOptions::new(), observer)
}

/// Validate one canonical SACP-CBOR/1 data item under explicit options and cooperative work
/// observation.
///
/// The observer is owned for the duration of this validation transaction. Cancellation is
/// terminal for the transaction, returns no canonical witness, and is reported at the input
/// position reached by completed work.
///
/// # Errors
///
/// Returns the same grammar, restriction, and resource-limit errors as
/// [`validate_canonical_with`], or [`ErrorCode::WorkCancelled`] if `observer` requests
/// cancellation.
pub fn validate_canonical_with_observer<O: WorkObserver>(
    bytes: &'_ [u8],
    limits: DecodeLimits,
    options: ValidationOptions,
    observer: O,
) -> Result<CanonicalCborRef<'_>, CborError> {
    let mut meter = WorkMeter::new(observer);
    validate_canonical_with_meter(bytes, limits, options, &mut meter)
}

fn validate_canonical_with_meter<'a, O: WorkObserver>(
    bytes: &'a [u8],
    limits: DecodeLimits,
    options: ValidationOptions,
    meter: &mut WorkMeter<O>,
) -> Result<CanonicalCborRef<'a>, CborError> {
    limits.validate()?;
    if bytes.len() > limits.max_input_bytes {
        return Err(CborError::new(ErrorCode::MessageLenLimitExceeded, 0));
    }
    meter
        .start()
        .map_err(|_| CborError::new(ErrorCode::WorkCancelled, 0))?;
    let end =
        value_end_internal_observed(bytes, 0, WalkPolicy::new(Some(&limits), options), meter)?;
    if end != bytes.len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, end));
    }
    meter
        .finish()
        .map_err(|_| CborError::new(ErrorCode::WorkCancelled, end))?;
    Ok(CanonicalCborRef::new(bytes))
}

fn value_end_internal_observed<O: WorkObserver>(
    data: &[u8],
    start: usize,
    policy: WalkPolicy<'_>,
    meter: &mut WorkMeter<O>,
) -> Result<usize, CborError> {
    let mut cursor = Cursor::with_pos(data, start);
    let mut items_seen = 0;
    wire::skip_one_value_observed::<true, _>(&mut cursor, policy, &mut items_seen, 0, meter)?;
    Ok(cursor.position())
}
