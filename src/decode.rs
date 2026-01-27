use crate::parse::{decode_value_checked_range, decode_value_trusted_range};
use crate::{CborError, DecodeLimits};

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
    decode_value_checked_range(bytes, 0, bytes.len(), limits)
}

/// Decode trusted canonical CBOR bytes into an owned [`CborValue`].
///
/// This does not validate canonical form. It only checks that there is exactly one item.
///
/// # Errors
///
/// Returns an error if decoding fails or allocation fails while building the value.
#[cfg(feature = "alloc")]
pub fn decode_value_trusted(bytes: &[u8]) -> Result<CborValue, CborError> {
    decode_value_trusted_range(bytes, 0, bytes.len())
}
