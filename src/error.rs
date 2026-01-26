use core::fmt;

/// The high-level class of an error.
///
/// SACP-CBOR/1 distinguishes:
/// - **Decode** errors: framing errors such as EOF or trailing bytes.
/// - **Validate** errors: SACP-CBOR/1 rule violations (canonicality, ordering, etc.).
/// - **Encode** errors: attempts to encode values that cannot be represented under SACP-CBOR/1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborErrorKind {
    /// Decode/framing failure.
    Decode,
    /// SACP-CBOR/1 validation failure.
    Validate,
    /// Canonical encoding failure.
    Encode,
}

/// A structured error code identifying the reason a CBOR item was rejected.
///
/// This enum is intentionally stable and string-free to support `no_std` and to remain hot-path friendly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CborErrorCode {
    /// Invalid configured limits.
    InvalidLimits,

    /// Unexpected end-of-input while decoding.
    UnexpectedEof,
    /// Arithmetic overflow while computing a length/offset.
    LengthOverflow,
    /// Input contains trailing bytes after the single CBOR data item.
    TrailingBytes,
    /// Memory allocation failed while decoding into owned structures.
    AllocationFailed,

    /// Nesting depth limit exceeded.
    DepthLimitExceeded,
    /// Total items limit exceeded.
    TotalItemsLimitExceeded,
    /// Array length exceeds limits.
    ArrayLenLimitExceeded,
    /// Map length exceeds limits.
    MapLenLimitExceeded,
    /// Byte string length exceeds limits.
    BytesLenLimitExceeded,
    /// Text string length exceeds limits.
    TextLenLimitExceeded,

    /// Unsupported CBOR major type.
    UnsupportedMajorType,
    /// Reserved additional-info value (28..30) was used.
    ReservedAdditionalInfo,
    /// Indefinite-length encoding was used where forbidden.
    IndefiniteLengthForbidden,
    /// Non-canonical (non-shortest) integer/length encoding was used.
    NonCanonicalEncoding,

    /// Map key was not a CBOR text string.
    MapKeyMustBeText,
    /// Duplicate map key detected.
    DuplicateMapKey,
    /// Map keys are not in canonical order.
    NonCanonicalMapOrder,

    /// A forbidden tag was used, or the tag structure is malformed.
    ForbiddenOrMalformedTag,
    /// Bignum magnitude is not canonical (empty or leading zero).
    BignumNotCanonical,
    /// Bignum was used for a value within the safe integer range.
    BignumMustBeOutsideSafeRange,

    /// Unsupported CBOR simple value.
    UnsupportedSimpleValue,
    /// Integer outside the `int_safe` range.
    IntegerOutsideSafeRange,

    /// Invalid UTF-8 in a text string.
    Utf8Invalid,

    /// Float64 negative zero encoding is forbidden.
    NegativeZeroForbidden,
    /// Float64 NaN encoding is not canonical.
    NonCanonicalNaN,
}

/// An SACP-CBOR/1 error with structured classification, a stable code, and a byte offset.
///
/// Offsets are meaningful for `Decode` and `Validate` errors. For `Encode` errors, `offset` is `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CborError {
    /// The error kind.
    pub kind: CborErrorKind,
    /// The error code.
    pub code: CborErrorCode,
    /// Byte offset into the input where the error was detected (0 for encode errors).
    pub offset: usize,
}

impl CborError {
    /// Construct a decode error at `offset`.
    #[inline]
    #[must_use]
    pub const fn decode(code: CborErrorCode, offset: usize) -> Self {
        Self {
            kind: CborErrorKind::Decode,
            code,
            offset,
        }
    }

    /// Construct a validation error at `offset`.
    #[inline]
    #[must_use]
    pub const fn validate(code: CborErrorCode, offset: usize) -> Self {
        Self {
            kind: CborErrorKind::Validate,
            code,
            offset,
        }
    }

    /// Construct an encoding error.
    #[inline]
    #[must_use]
    pub const fn encode(code: CborErrorCode) -> Self {
        Self {
            kind: CborErrorKind::Encode,
            code,
            offset: 0,
        }
    }

    /// Returns true iff this error is a validation error.
    #[inline]
    #[must_use]
    pub const fn is_validation(self) -> bool {
        matches!(self.kind, CborErrorKind::Validate)
    }
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self.code {
            CborErrorCode::InvalidLimits => "invalid CBOR limits",

            CborErrorCode::UnexpectedEof => "unexpected end of input",
            CborErrorCode::LengthOverflow => "length overflow",
            CborErrorCode::TrailingBytes => "trailing bytes after single CBOR item",
            CborErrorCode::AllocationFailed => "allocation failed",

            CborErrorCode::DepthLimitExceeded => "nesting depth limit exceeded",
            CborErrorCode::TotalItemsLimitExceeded => "total items limit exceeded",
            CborErrorCode::ArrayLenLimitExceeded => "array length exceeds decode limits",
            CborErrorCode::MapLenLimitExceeded => "map length exceeds decode limits",
            CborErrorCode::BytesLenLimitExceeded => "byte string length exceeds decode limits",
            CborErrorCode::TextLenLimitExceeded => "text string length exceeds decode limits",

            CborErrorCode::UnsupportedMajorType => "unsupported CBOR major type",
            CborErrorCode::ReservedAdditionalInfo => "reserved additional info value",
            CborErrorCode::IndefiniteLengthForbidden => "indefinite length forbidden",
            CborErrorCode::NonCanonicalEncoding => "non-canonical integer/length encoding",

            CborErrorCode::MapKeyMustBeText => "map keys must be text strings",
            CborErrorCode::DuplicateMapKey => "duplicate map key",
            CborErrorCode::NonCanonicalMapOrder => "non-canonical map key order",

            CborErrorCode::ForbiddenOrMalformedTag => "forbidden or malformed CBOR tag",
            CborErrorCode::BignumNotCanonical => {
                "bignum magnitude must be canonical (non-empty, no leading zero)"
            }
            CborErrorCode::BignumMustBeOutsideSafeRange => "bignum must be outside int_safe range",

            CborErrorCode::UnsupportedSimpleValue => "unsupported CBOR simple value",
            CborErrorCode::IntegerOutsideSafeRange => "integer outside int_safe range",

            CborErrorCode::Utf8Invalid => "text must be valid UTF-8",

            CborErrorCode::NegativeZeroForbidden => "negative zero forbidden",
            CborErrorCode::NonCanonicalNaN => "non-canonical NaN encoding",
        };

        match self.kind {
            CborErrorKind::Encode => write!(f, "cbor encode failed: {msg}"),
            CborErrorKind::Decode => write!(f, "cbor decode failed at {}: {msg}", self.offset),
            CborErrorKind::Validate => {
                write!(f, "cbor validation failed at {}: {msg}", self.offset)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CborError {}
