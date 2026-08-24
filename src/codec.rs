//! Native encode/decode traits for SACP-CBOR/1.

#[cfg(feature = "alloc")]
use crate::encode::{ByteSink, EncodeResult, ValueEncoder};
use crate::{CborError, Decoder};

/// Decode a value from a streaming decoder.
pub trait CborDecode<'de>: Sized {
    /// Decode `Self` from a streaming decoder.
    ///
    /// # Errors
    ///
    /// Returns an error if the CBOR value does not match the expected type or violates profile
    /// constraints.
    fn decode<const CHECKED: bool>(decoder: &mut Decoder<'de, CHECKED>) -> Result<Self, CborError>;
}

#[cfg(feature = "alloc")]
/// Encode a value into canonical CBOR bytes using the streaming encoder.
pub trait CborEncode {
    /// Encode `self` into the provided encoder.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    fn encode<S: ByteSink>(&self, enc: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S>;
}
