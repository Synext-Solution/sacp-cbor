use crate::canonical::CanonicalCborRef;
use crate::wire::{self, Cursor};
use crate::{CborError, DecodeLimits, ErrorCode};

/// Validate that `bytes` contain exactly one canonical SACP-CBOR/1 data item.
///
/// This is an allocation-free hot-path validator.
///
/// # Errors
///
/// Returns an error if decoding fails (EOF, trailing bytes, limit violations) or if validation fails
/// (non-canonical encoding, forbidden tags, map ordering, etc.).
pub fn validate(bytes: &[u8], limits: DecodeLimits) -> Result<(), CborError> {
    validate_canonical(bytes, limits).map(|_| ())
}

/// Validate that `bytes` contain exactly one canonical SACP-CBOR/1 data item and return a wrapper.
///
/// # Errors
///
/// Returns an error if decoding fails (EOF, trailing bytes, limit violations) or if validation fails
/// (non-canonical encoding, forbidden tags, map ordering, etc.).
pub fn validate_canonical(
    bytes: &'_ [u8],
    limits: DecodeLimits,
) -> Result<CanonicalCborRef<'_>, CborError> {
    if bytes.len() > limits.max_input_bytes {
        return Err(CborError::new(ErrorCode::MessageLenLimitExceeded, 0));
    }
    let end = value_end_internal(bytes, 0, Some(limits))?;
    if end != bytes.len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, end));
    }
    Ok(CanonicalCborRef::new(bytes))
}

fn value_end_internal(
    data: &[u8],
    start: usize,
    limits: Option<DecodeLimits>,
) -> Result<usize, CborError> {
    let mut cursor = Cursor::<CborError>::with_pos(data, start);
    let mut items_seen = 0;
    wire::skip_one_value::<true, CborError>(&mut cursor, limits.as_ref(), &mut items_seen, 0)?;
    Ok(cursor.position())
}
