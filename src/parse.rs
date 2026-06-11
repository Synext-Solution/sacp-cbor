use crate::canonical::CanonicalCborRef;
use crate::wire::{self, Cursor, WalkPolicy};
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
    limits.validate()?;
    if bytes.len() > limits.max_input_bytes {
        return Err(CborError::new(ErrorCode::MessageLenLimitExceeded, 0));
    }
    let end = value_end_internal(bytes, 0, WalkPolicy::new(Some(&limits), options))?;
    if end != bytes.len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, end));
    }
    Ok(CanonicalCborRef::new(bytes))
}

fn value_end_internal(
    data: &[u8],
    start: usize,
    policy: WalkPolicy<'_>,
) -> Result<usize, CborError> {
    let mut cursor = Cursor::with_pos(data, start);
    let mut items_seen = 0;
    wire::skip_one_value::<true>(&mut cursor, policy, &mut items_seen, 0)?;
    Ok(cursor.position())
}
