//! Deterministic decode and encode resource limits.

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

/// Encode-time resource limits for canonical byte production.
///
/// The item/depth semantics match [`DecodeLimits`]: arrays count their contained values, maps
/// count both keys and values, and container depth counts the root container as depth 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeLimits {
    /// Maximum total output length in bytes.
    pub max_output_bytes: usize,
    /// Maximum nesting depth for arrays and maps.
    pub max_depth: usize,
    /// Maximum total count of container items:
    /// `sum(array_len) + sum(2 * map_pairs)` across the emitted item.
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

impl EncodeLimits {
    /// Return limits that do not impose semantic bounds beyond platform `usize` capacity.
    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            max_output_bytes: usize::MAX,
            max_depth: usize::MAX,
            max_total_items: usize::MAX,
            max_array_len: usize::MAX,
            max_map_len: usize::MAX / 2,
            max_bytes_len: usize::MAX,
            max_text_len: usize::MAX,
        }
    }

    /// Validate this limit set.
    ///
    /// # Errors
    ///
    /// Returns `InvalidLimits` when item accounting cannot be enforced without overflow.
    pub const fn validate(self) -> Result<(), CborError> {
        if self.max_map_len > usize::MAX / 2 {
            return Err(CborError::new(ErrorCode::InvalidLimits, 0));
        }
        Ok(())
    }

    /// Construct conservative encode limits from an output byte budget.
    #[must_use]
    pub fn for_bytes(max_output_bytes: usize) -> Self {
        let max_container_len = max_output_bytes.min(DEFAULT_MAX_CONTAINER_LEN);
        Self {
            max_output_bytes,
            max_depth: DEFAULT_MAX_DEPTH,
            max_total_items: max_output_bytes,
            max_array_len: max_container_len,
            max_map_len: max_container_len,
            max_bytes_len: max_output_bytes,
            max_text_len: max_output_bytes,
        }
    }

    #[cfg(feature = "alloc")]
    pub(crate) const fn to_decode_limits(self, max_input_bytes: usize) -> DecodeLimits {
        DecodeLimits {
            max_input_bytes,
            max_depth: self.max_depth,
            max_total_items: self.max_total_items,
            max_array_len: self.max_array_len,
            max_map_len: self.max_map_len,
            max_bytes_len: self.max_bytes_len,
            max_text_len: self.max_text_len,
        }
    }
}

impl Default for EncodeLimits {
    fn default() -> Self {
        Self::unbounded()
    }
}

/// Grammar-restriction options for canonical validation.
///
/// [`DecodeLimits`] bounds resources; `ValidationOptions` selects optional *restriction modes* of
/// the SACP-CBOR/1 grammar. The default options accept the full SACP-CBOR/1 grammar. Restriction
/// modes only ever reject more inputs: every item accepted under a restriction mode is also a
/// valid SACP-CBOR/1 item.
///
/// Modes are a property of a validation call, not of the validated bytes: the canonical witness
/// types attest SACP-CBOR/1 canonicality only. Trusted re-traversal of already-validated bytes
/// (queries, editing, trusted decode) ignores restriction modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ValidationOptions {
    /// Reject float64 values anywhere in the item.
    ///
    /// For deployments whose durable data model excludes floating point, this enforces the
    /// no-float restriction at the validation boundary instead of by schema convention. Rejected
    /// values produce [`ErrorCode::FloatForbidden`] at the
    /// float header offset.
    pub forbid_float: bool,
    /// Reject the simple values `false`, `true`, and `null` anywhere in the item.
    ///
    /// For deployments whose durable data model has no boolean or null term — expressing
    /// optionality by key omission and booleans as schema-constrained integers — this enforces
    /// the no-simple restriction at the validation boundary instead of by schema convention.
    /// Rejected values produce [`ErrorCode::SimpleForbidden`] at the simple-value header offset.
    pub forbid_simple: bool,
}

impl ValidationOptions {
    /// Options accepting the full SACP-CBOR/1 grammar.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            forbid_float: false,
            forbid_simple: false,
        }
    }

    /// Return these options with float64 values forbidden.
    #[must_use]
    pub const fn no_float(mut self) -> Self {
        self.forbid_float = true;
        self
    }

    /// Return these options with the simple values `false`, `true`, and `null` forbidden.
    #[must_use]
    pub const fn no_simple(mut self) -> Self {
        self.forbid_simple = true;
        self
    }
}

impl DecodeLimits {
    /// Validate this limit set for the active feature configuration.
    ///
    /// # Errors
    ///
    /// Returns `InvalidLimits` when the configured limits cannot be enforced by this build.
    pub const fn validate(self) -> Result<(), CborError> {
        if self.max_map_len > usize::MAX / 2 {
            return Err(CborError::new(ErrorCode::InvalidLimits, 0));
        }
        #[cfg(not(feature = "alloc"))]
        {
            if self.max_depth > DEFAULT_MAX_DEPTH {
                return Err(CborError::new(ErrorCode::InvalidLimits, 0));
            }
        }
        Ok(())
    }

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
