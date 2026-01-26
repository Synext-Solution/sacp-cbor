use crate::parse::{decode_value_trusted, validate_canonical};
use crate::{CborError, DecodeLimits, ErrorCode};

#[cfg(feature = "alloc")]
use crate::value::CborValue;

/// Decode SACP-CBOR/1 bytes into an owned [`CborValue`].
///
/// This validates the input before conversion.
///
/// # Errors
///
/// Returns an error if validation fails or allocation fails while building the value.
#[cfg(feature = "alloc")]
pub fn decode_value(bytes: &[u8], limits: DecodeLimits) -> Result<CborValue, CborError> {
    let canon = validate_canonical(bytes, limits)?;
    let (value, end) = decode_value_trusted(canon.as_bytes(), 0)?;
    if end != canon.as_bytes().len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, end));
    }
    Ok(value)
}
