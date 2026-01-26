use crate::{CborError, ErrorCode};

/// Default maximum nesting depth limit.
pub const DEFAULT_MAX_DEPTH: usize = 256;

/// Default maximum container length limit for arrays/maps.
///
/// This is a safety limit; adjust explicitly for your deployment.
pub const DEFAULT_MAX_CONTAINER_LEN: usize = 1 << 16;

/// Decode-time resource limits for validation and decoding.
///
/// Limits are enforced deterministically and must not depend on background timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Maximum total input length in bytes.
    pub max_input_bytes: usize,
    /// Maximum nesting depth.
    pub max_depth: usize,
    /// Maximum total count of container items:
    /// `sum(array_len) + sum(2 * map_pairs)` across the entire decoded item
    /// (maps count both keys and values).
    pub max_total_items: usize,
    /// Maximum array length.
    pub max_array_len: usize,
    /// Maximum map length (pairs).
    pub max_map_len: usize,
    /// Maximum byte-string length (also applies to bignum magnitudes).
    pub max_bytes_len: usize,
    /// Maximum text-string length in UTF-8 bytes.
    pub max_text_len: usize,
}

impl DecodeLimits {
    /// Construct conservative limits derived from a maximum message size.
    ///
    /// The defaults are:
    /// - `max_input_bytes = max_message_bytes`
    /// - `max_total_items = max_message_bytes`
    /// - `max_bytes_len = max_message_bytes`
    /// - `max_text_len = max_message_bytes`
    /// - `max_array_len` and `max_map_len` are capped by `DEFAULT_MAX_CONTAINER_LEN`
    ///
    /// This is a pragmatic baseline. Production deployments should tune these explicitly.
    #[must_use]
    pub fn for_bytes(max_message_bytes: usize) -> Self {
        let max_container_len = max_message_bytes.min(DEFAULT_MAX_CONTAINER_LEN);
        Self {
            max_input_bytes: max_message_bytes,
            max_depth: DEFAULT_MAX_DEPTH,
            max_total_items: max_message_bytes,
            max_array_len: max_container_len,
            max_map_len: max_container_len,
            max_bytes_len: max_message_bytes,
            max_text_len: max_message_bytes,
        }
    }
}

/// End-to-end limits used by SACP implementations.
///
/// SACP commonly distinguishes between:
/// - maximum message size on the wire, and
/// - maximum size of canonical CBOR stored durably as state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CborLimits {
    /// Maximum bytes per message.
    pub max_message_bytes: usize,
    /// Maximum bytes per state blob (must be <= `max_message_bytes`).
    pub max_state_bytes: usize,
}

impl CborLimits {
    /// Construct new limits.
    ///
    /// # Errors
    ///
    /// Returns `InvalidLimits` if `max_state_bytes > max_message_bytes`.
    pub const fn new(max_message_bytes: usize, max_state_bytes: usize) -> Result<Self, CborError> {
        if max_state_bytes > max_message_bytes {
            return Err(CborError::new(ErrorCode::InvalidLimits, 0));
        }
        Ok(Self {
            max_message_bytes,
            max_state_bytes,
        })
    }

    /// Decode limits appropriate for validating incoming messages.
    #[must_use]
    pub fn message_limits(self) -> DecodeLimits {
        DecodeLimits::for_bytes(self.max_message_bytes)
    }

    /// Decode limits appropriate for validating stored canonical state.
    #[must_use]
    pub fn state_limits(self) -> DecodeLimits {
        DecodeLimits::for_bytes(self.max_state_bytes)
    }
}
