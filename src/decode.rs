use crate::walk::validate_canonical;
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
    let canon = validate_canonical(bytes, limits)?;
    canon.root().to_owned()
}
