use core::fmt;

/// A structured error code identifying the reason a CBOR item was rejected.
///
/// This enum is intentionally stable and string-free to support `no_std` and to remain hot-path friendly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
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
    /// Array builder length mismatch (encoder).
    ArrayLenMismatch,
    /// Map builder length mismatch (encoder).
    MapLenMismatch,

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
    /// Total input length exceeds limits.
    MessageLenLimitExceeded,

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

    /// Serde conversion failed.
    SerdeError,

    /// Expected a map at the current location.
    ExpectedMap,
    /// Expected an array at the current location.
    ExpectedArray,
    /// Expected an integer (safe or bignum) at the current location.
    ExpectedInteger,
    /// Expected a text string at the current location.
    ExpectedText,
    /// Expected a byte string at the current location.
    ExpectedBytes,
    /// Expected a boolean at the current location.
    ExpectedBool,
    /// Expected a null at the current location.
    ExpectedNull,
    /// Expected a float64 at the current location.
    ExpectedFloat,
    /// Expected a CBOR value matching an untagged enum variant.
    ExpectedEnum,
    /// Unknown enum variant key.
    UnknownEnumVariant,

    /// Patch operations overlap or conflict.
    PatchConflict,
    /// Array index is out of bounds.
    IndexOutOfBounds,

    /// Invalid query arguments (e.g., output slice length mismatch).
    InvalidQuery,
    /// Required key missing from map.
    MissingKey,
    /// Malformed canonical CBOR during query traversal.
    MalformedCanonical,
}

/// An SACP-CBOR/1 error with structured classification, a stable code, and a byte offset.
///
/// Offsets refer to the byte position where the error was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CborError {
    /// The error code.
    pub code: ErrorCode,
    /// Byte offset into the input where the error was detected.
    pub offset: usize,
}

impl CborError {
    /// Construct a decode error at `offset`.
    #[inline]
    #[must_use]
    pub const fn new(code: ErrorCode, offset: usize) -> Self {
        Self { code, offset }
    }
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self.code {
            ErrorCode::InvalidLimits => "invalid CBOR limits",

            ErrorCode::UnexpectedEof => "unexpected end of input",
            ErrorCode::LengthOverflow => "length overflow",
            ErrorCode::TrailingBytes => "trailing bytes after single CBOR item",
            ErrorCode::AllocationFailed => "allocation failed",
            ErrorCode::ArrayLenMismatch => "array length mismatch",
            ErrorCode::MapLenMismatch => "map length mismatch",

            ErrorCode::DepthLimitExceeded => "nesting depth limit exceeded",
            ErrorCode::TotalItemsLimitExceeded => "total items limit exceeded",
            ErrorCode::ArrayLenLimitExceeded => "array length exceeds decode limits",
            ErrorCode::MapLenLimitExceeded => "map length exceeds decode limits",
            ErrorCode::BytesLenLimitExceeded => "byte string length exceeds decode limits",
            ErrorCode::TextLenLimitExceeded => "text string length exceeds decode limits",
            ErrorCode::MessageLenLimitExceeded => "input length exceeds decode limits",

            ErrorCode::ReservedAdditionalInfo => "reserved additional info value",
            ErrorCode::IndefiniteLengthForbidden => "indefinite length forbidden",
            ErrorCode::NonCanonicalEncoding => "non-canonical integer/length encoding",

            ErrorCode::MapKeyMustBeText => "map keys must be text strings",
            ErrorCode::DuplicateMapKey => "duplicate map key",
            ErrorCode::NonCanonicalMapOrder => "non-canonical map key order",

            ErrorCode::ForbiddenOrMalformedTag => "forbidden or malformed CBOR tag",
            ErrorCode::BignumNotCanonical => {
                "bignum magnitude must be canonical (non-empty, no leading zero)"
            }
            ErrorCode::BignumMustBeOutsideSafeRange => "bignum must be outside int_safe range",

            ErrorCode::UnsupportedSimpleValue => "unsupported CBOR simple value",
            ErrorCode::IntegerOutsideSafeRange => "integer outside int_safe range",

            ErrorCode::Utf8Invalid => "text must be valid UTF-8",

            ErrorCode::NegativeZeroForbidden => "negative zero forbidden",
            ErrorCode::NonCanonicalNaN => "non-canonical NaN encoding",
            ErrorCode::SerdeError => "serde conversion failed",

            ErrorCode::ExpectedMap => "expected CBOR map",
            ErrorCode::ExpectedArray => "expected CBOR array",
            ErrorCode::ExpectedInteger => "expected CBOR integer",
            ErrorCode::ExpectedText => "expected CBOR text string",
            ErrorCode::ExpectedBytes => "expected CBOR byte string",
            ErrorCode::ExpectedBool => "expected CBOR bool",
            ErrorCode::ExpectedNull => "expected CBOR null",
            ErrorCode::ExpectedFloat => "expected CBOR float64",
            ErrorCode::ExpectedEnum => "expected CBOR enum value",
            ErrorCode::UnknownEnumVariant => "unknown CBOR enum variant",
            ErrorCode::PatchConflict => "patch operations conflict",
            ErrorCode::IndexOutOfBounds => "array index out of bounds",
            ErrorCode::InvalidQuery => "invalid query arguments",
            ErrorCode::MissingKey => "missing required map key",
            ErrorCode::MalformedCanonical => "malformed canonical CBOR",
        };

        write!(f, "cbor error at {}: {msg}", self.offset)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CborError {}
