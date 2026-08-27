//! Stable public ABI schemas and codecs for SACP-CBOR.

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use sacp_cbor::bytes::{Bytes, BytesRef};
use sacp_cbor::{
    ByteSink, CanonicalCbor, CanonicalCborRef, CborDecode, CborEncode, CborError, DecodeLimits,
    Decoder, EncodeResult, ErrorCode, ValueEncoder,
};
use sha2::{Digest, Sha256};

mod edit;
mod runtime;
mod view;

#[cfg(kani)]
#[path = "../../proofs/abi_kani.rs"]
mod proofs;

pub use edit::{AbiDeleteMode, AbiFieldSetEditor, AbiPatchValue, AbiSetMode};
pub use runtime::{
    compile_runtime_schema, AbiSchemaRegistry, NoNamedSchemas, RuntimeAbiError, RuntimeEnumSchema,
    RuntimeEnumView, RuntimeFieldInfo, RuntimeFieldRef, RuntimeFieldSetSchema, RuntimeFieldSetView,
    RuntimeSchema, RuntimeValidationLimits, RuntimeValidationWorkspace, RuntimeVariantInfo,
};
#[cfg(feature = "derive")]
pub use sacp_cbor_abi_derive::CborAbi;
pub use view::{
    AbiArrayView, AbiFieldEntryRef, AbiFieldSetRef, AbiView, AbiViewField, UnknownFieldRef,
    UnknownVariantRef,
};

/// Support items used by generated code.
#[doc(hidden)]
pub mod __private {
    pub use alloc::{boxed::Box, string::String, vec, vec::Vec};
    pub use sacp_cbor;

    use super::{UnknownFields, UnknownVariant};

    /// Convert one core decode failure into the active ABI context's error domain.
    pub fn decode_error<C: super::AbiDecodeContext + ?Sized>(
        code: sacp_cbor::ErrorCode,
        offset: usize,
    ) -> C::Error {
        C::Error::from(sacp_cbor::CborError::new(code, offset))
    }

    /// Decode and validate a nonzero ABI field or variant ID.
    pub fn decode_abi_id(
        value: sacp_cbor::query::CborValueRef<'_>,
    ) -> Result<u32, sacp_cbor::CborError> {
        super::view::abi_field_id(value)
    }

    /// Encode one ABI field ID in a field-set array.
    pub fn encode_field_id<S: sacp_cbor::ByteSink>(
        array: &mut sacp_cbor::encode::ArrayEncoder<'_, S>,
        id: u32,
    ) -> sacp_cbor::EncodeResult<(), S> {
        array.value(&id)
    }

    /// Encode preserved unknown fields whose IDs are lower than `before_id`.
    pub fn encode_unknown_fields_before<S: sacp_cbor::ByteSink>(
        array: &mut sacp_cbor::encode::ArrayEncoder<'_, S>,
        unknown: &UnknownFields,
        cursor: &mut usize,
        before_id: u32,
    ) -> sacp_cbor::EncodeResult<(), S> {
        let fields = unknown.as_slice();
        while *cursor < fields.len() && fields[*cursor].id < before_id {
            encode_unknown_field(array, &fields[*cursor])?;
            *cursor += 1;
        }
        if *cursor < fields.len() && fields[*cursor].id == before_id {
            return Err(sacp_cbor::EncodeError::Cbor(sacp_cbor::CborError::new(
                sacp_cbor::ErrorCode::DuplicateMapKey,
                0,
            )));
        }
        Ok(())
    }

    /// Encode remaining preserved unknown fields.
    pub fn encode_remaining_unknown_fields<S: sacp_cbor::ByteSink>(
        array: &mut sacp_cbor::encode::ArrayEncoder<'_, S>,
        unknown: &UnknownFields,
        cursor: &mut usize,
    ) -> sacp_cbor::EncodeResult<(), S> {
        let fields = unknown.as_slice();
        while *cursor < fields.len() {
            encode_unknown_field(array, &fields[*cursor])?;
            *cursor += 1;
        }
        Ok(())
    }

    /// Validate that an unknown variant does not use a reserved variant ID.
    pub fn validate_unknown_variant(
        variant: &UnknownVariant,
        reserved: &[u32],
    ) -> Result<(), sacp_cbor::CborError> {
        if variant.id == 0 || reserved.contains(&variant.id) {
            return Err(sacp_cbor::CborError::new(
                sacp_cbor::ErrorCode::InvalidAbiValue,
                0,
            ));
        }
        Ok(())
    }

    fn encode_unknown_field<S: sacp_cbor::ByteSink>(
        array: &mut sacp_cbor::encode::ArrayEncoder<'_, S>,
        field: &super::UnknownField,
    ) -> sacp_cbor::EncodeResult<(), S> {
        encode_field_id(array, field.id)?;
        array.raw_cbor(field.value.as_canonical_ref())
    }
}

/// Encode a public ABI value.
pub trait AbiEncode {
    /// Encode `self` into canonical SACP-CBOR bytes.
    fn abi_encode<S: ByteSink>(&self, enc: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S>;
}

/// Identifies the semantic owner of an admitted ABI value.
///
/// ABI field-set and enum framing arrays are deliberately absent: callers budget the values their
/// model owns, not the numeric IDs and arrays used to frame those values on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiDecodeLocation {
    /// A value decoded directly at the root entry point.
    Root,
    /// A declared struct field or named enum-variant field.
    Field {
        /// Stable ABI type ID of the containing declaration.
        type_id: &'static str,
        /// Variant ID for a named enum payload, or `None` for a struct field.
        variant_id: Option<u32>,
        /// Stable numeric field ID.
        field_id: u32,
    },
    /// An unknown field retained by a preserve-policy declaration.
    UnknownField {
        /// Stable ABI type ID of the containing declaration.
        type_id: &'static str,
        /// Variant ID for a named enum payload, or `None` for a struct field.
        variant_id: Option<u32>,
        /// Unknown numeric field ID observed on the wire.
        field_id: u32,
    },
    /// An unknown enum variant retained by a preserve-policy declaration.
    UnknownVariant {
        /// Stable ABI type ID of the enum declaration.
        type_id: &'static str,
        /// Unknown numeric variant ID observed on the wire.
        variant_id: u32,
    },
}

/// A length-bearing semantic value observed before its first owned allocation or payload copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiDecodeValue {
    /// A `Vec<T>` value. `items` is the declared array length.
    Sequence {
        /// Header byte offset.
        offset: usize,
        /// Declared element count.
        items: usize,
    },
    /// A UTF-8 text value. `bytes` is the declared payload length.
    Text {
        /// Header byte offset.
        offset: usize,
        /// Declared UTF-8 byte length.
        bytes: usize,
    },
    /// A byte-string value. `bytes` is the declared payload length.
    Bytes {
        /// Header byte offset.
        offset: usize,
        /// Declared byte length.
        bytes: usize,
    },
    /// A complete canonical value that will be copied into an owned witness.
    Canonical {
        /// Header byte offset.
        offset: usize,
        /// Complete encoded byte length.
        bytes: usize,
    },
    /// One retained unknown field, observed before storage reservation and payload ownership.
    UnknownField {
        /// Field-ID byte offset.
        offset: usize,
    },
    /// One retained unknown variant, observed before payload ownership.
    UnknownVariant {
        /// Variant-ID byte offset.
        offset: usize,
    },
}

/// Caller-owned admission context for ABI decoding.
///
/// One mutable context is threaded through the entire recursive decode. Hooks run after the core
/// canonical grammar and structural limits have admitted a header, but before the corresponding
/// owned reservation or payload copy. A hook error aborts and poisons the single-pass decode.
/// Payload truncation or invalid UTF-8 can still fail after admission, so a stateful context belongs
/// to that decode transaction and must be discarded or rolled back when decoding returns an error.
pub trait AbiDecodeContext {
    /// Error returned by the complete decode transaction.
    type Error: From<CborError>;

    /// Admit one semantic value before ownership is allocated or copied.
    fn admit(
        &mut self,
        location: AbiDecodeLocation,
        value: AbiDecodeValue,
    ) -> Result<(), Self::Error>;
}

impl AbiDecodeContext for () {
    type Error = CborError;

    #[inline]
    fn admit(
        &mut self,
        _location: AbiDecodeLocation,
        _value: AbiDecodeValue,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Decode a public ABI value through one caller-owned admission context.
pub trait AbiDecode<'de, C: AbiDecodeContext + ?Sized>: Sized {
    /// Decode `Self` from a streaming decoder.
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        context: &mut C,
        location: AbiDecodeLocation,
    ) -> Result<Self, C::Error>;
}

/// Exposes the public ABI schema for a type.
pub trait AbiType {
    /// Return this type's schema.
    #[must_use]
    fn schema() -> Schema;
}

/// Exposes the ABI type reference used when this type appears as a field.
pub trait AbiTypeRef {
    /// Return this type's stable ABI reference.
    #[must_use]
    fn abi_type_ref() -> TypeRef;
}

/// Current stable ABI schema profile.
pub const ABI_PROFILE: &str = "SACP_CBOR_ABI/1";

/// Unknown field handling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownFieldPolicy {
    /// Reject unknown fields.
    Reject,
    /// Accept unknown fields without retaining them.
    Ignore,
    /// Accept and retain unknown fields for byte-preserving re-encode.
    Preserve,
}

impl UnknownFieldPolicy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Ignore => "ignore",
            Self::Preserve => "preserve",
        }
    }

    const fn accepts(self) -> bool {
        matches!(self, Self::Ignore | Self::Preserve)
    }

    const fn preserves(self) -> bool {
        matches!(self, Self::Preserve)
    }
}

/// Unknown enum variant handling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownVariantPolicy {
    /// Reject unknown variants.
    Reject,
    /// Accept and retain unknown variants for byte-preserving re-encode.
    Preserve,
}

impl UnknownVariantPolicy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Preserve => "preserve",
        }
    }

    const fn preserves(self) -> bool {
        matches!(self, Self::Preserve)
    }
}

/// A complete public ABI schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schema {
    /// ABI profile.
    pub profile: String,
    /// Stable type identity.
    pub type_id: String,
    /// Governance schema version.
    pub version: u32,
    /// Root type definition.
    pub root: TypeDef,
}

impl Schema {
    /// Construct a schema using the current ABI profile.
    #[must_use]
    pub fn new(type_id: impl Into<String>, version: u32, root: TypeDef) -> Self {
        Self {
            profile: ABI_PROFILE.to_string(),
            type_id: type_id.into(),
            version,
            root,
        }
    }

    /// Canonical SACP-CBOR encoding of the selected schema normal form.
    pub fn canonical_bytes(&self, kind: SchemaHashKind) -> Result<CanonicalCbor, CborError> {
        sacp_cbor::encode_to_canonical(&SchemaNormalForm { schema: self, kind })
    }

    /// SHA-256 over the wire-significant schema normal form.
    pub fn wire_hash(&self) -> Result<SchemaHash, CborError> {
        schema_hash(self, SchemaHashKind::Wire)
    }

    /// SHA-256 over the complete schema normal form.
    pub fn full_hash(&self) -> Result<SchemaHash, CborError> {
        schema_hash(self, SchemaHashKind::Full)
    }
}

/// A public ABI type definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeDef {
    /// Struct field-set.
    Struct(FieldSetDef),
    /// Enum discriminant plus payload.
    Enum(EnumDef),
    /// Named wrapper encoded exactly like its inner type.
    Transparent {
        /// Inner wire type.
        inner: TypeRef,
    },
    /// Primitive or external type definition.
    Primitive {
        /// Primitive type reference.
        ty: TypeRef,
    },
}

/// A reusable ABI field-set definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSetDef {
    /// Public fields.
    pub fields: Vec<FieldDef>,
    /// Unknown field policy.
    pub unknown_fields: UnknownFieldPolicy,
}

/// A public enum definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumDef {
    /// Public variants.
    pub variants: Vec<VariantDef>,
    /// Unknown field policy for named variant payloads.
    pub unknown_fields: UnknownFieldPolicy,
    /// Unknown variant policy.
    pub unknown_variants: UnknownVariantPolicy,
}

/// A public field definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDef {
    /// Stable numeric field ID. Must be nonzero.
    pub id: u32,
    /// Source field name for diagnostics.
    pub name: String,
    /// Field wire type.
    pub ty: TypeRef,
    /// Field presence semantics.
    pub presence: FieldPresence,
}

/// ABI field presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldPresence {
    /// Field must be present.
    Required,
    /// Field is omitted when absent.
    Optional,
}

impl FieldPresence {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
        }
    }

    const fn is_optional(self) -> bool {
        matches!(self, Self::Optional)
    }
}

/// Stable ABI type reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeRef {
    /// Unit/null.
    Unit,
    /// Boolean.
    Bool,
    /// Unsigned 8-bit integer.
    U8,
    /// Unsigned 16-bit integer.
    U16,
    /// Unsigned 32-bit integer.
    U32,
    /// Unsigned 64-bit integer.
    U64,
    /// Signed 8-bit integer.
    I8,
    /// Signed 16-bit integer.
    I16,
    /// Signed 32-bit integer.
    I32,
    /// Signed 64-bit integer.
    I64,
    /// UTF-8 text.
    Text,
    /// CBOR byte string.
    Bytes,
    /// CBOR byte string with exact length.
    FixedBytes {
        /// Required byte length.
        len: u32,
    },
    /// CBOR array of homogeneous items.
    Vec {
        /// Item type.
        item: Box<TypeRef>,
    },
    /// Canonical CBOR sub-value.
    CanonicalCbor,
    /// Stable named ABI type.
    Named {
        /// Stable type identity.
        type_id: String,
        /// Optional referenced schema version.
        version: Option<u32>,
    },
}

/// A public enum variant definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantDef {
    /// Stable numeric variant ID. Must be nonzero.
    pub id: u32,
    /// Source variant name for diagnostics.
    pub name: String,
    /// Struct payload fields. Empty means unit payload.
    pub fields: Vec<FieldDef>,
}

/// Preserved unknown field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownField {
    /// Stable numeric field ID.
    pub id: u32,
    /// Canonical field value bytes.
    pub value: CanonicalCbor,
}

impl UnknownField {
    /// Construct a preserved unknown field.
    pub fn new(id: u32, value: CanonicalCbor) -> Result<Self, CborError> {
        if id == 0 {
            return Err(CborError::new(ErrorCode::InvalidAbiValue, 0));
        }
        Ok(Self { id, value })
    }
}

/// Preserved unknown fields in strict field-ID order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnknownFields(Vec<UnknownField>);

impl UnknownFields {
    /// Construct an empty unknown-field set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Construct an unknown-field set after validating ID order and uniqueness.
    pub fn try_from_vec(fields: Vec<UnknownField>) -> Result<Self, CborError> {
        let mut prev = None;
        for field in &fields {
            if field.id == 0 {
                return Err(CborError::new(ErrorCode::InvalidAbiValue, 0));
            }
            if let Some(prev_id) = prev {
                if field.id <= prev_id {
                    return Err(CborError::new(ErrorCode::InvalidAbiValue, 0));
                }
            }
            prev = Some(field.id);
        }
        Ok(Self(fields))
    }

    /// Return the preserved fields.
    #[must_use]
    pub fn as_slice(&self) -> &[UnknownField] {
        &self.0
    }

    /// Return the number of preserved fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return `true` when no unknown fields are preserved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume and return the preserved fields.
    #[must_use]
    pub fn into_vec(self) -> Vec<UnknownField> {
        self.0
    }
}

/// Preserved unknown enum variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownVariant {
    /// Stable numeric variant ID.
    pub id: u32,
    /// Canonical payload bytes.
    pub payload: CanonicalCbor,
}

impl UnknownVariant {
    /// Construct a preserved unknown variant.
    pub fn new(id: u32, payload: CanonicalCbor) -> Result<Self, CborError> {
        if id == 0 {
            return Err(CborError::new(ErrorCode::InvalidAbiValue, 0));
        }
        Ok(Self { id, payload })
    }
}

/// Schema hash normal form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaHashKind {
    /// Wire-significant schema data.
    Wire,
    /// Complete schema data, including diagnostics.
    Full,
}

/// SHA-256 digest of a schema normal form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaHash(pub [u8; 32]);

impl SchemaHash {
    /// Return the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for SchemaHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Top-level compatibility class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatibilityClass {
    /// The direction is schema-compatible.
    Compatible,
    /// The direction is not schema-compatible.
    Incompatible,
}

impl CompatibilityClass {
    const fn and(self, other: Self) -> Self {
        if matches!(self, Self::Compatible) && matches!(other, Self::Compatible) {
            Self::Compatible
        } else {
            Self::Incompatible
        }
    }
}

/// Schema change severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaChangeClass {
    /// Diagnostic metadata changed.
    MetadataOnly,
    /// Wire schema changed without breaking every direction.
    WireCompatible,
    /// Wire schema changed in a breaking direction.
    WireIncompatible,
}

/// Structured schema change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaChange {
    /// Schema path.
    pub path: String,
    /// Change class.
    pub class: SchemaChangeClass,
    /// Human-readable description.
    pub message: String,
}

/// Directional compatibility report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityReport {
    /// Whether the new decoder can read old bytes.
    pub new_reads_old: CompatibilityClass,
    /// Whether the old decoder can read new bytes.
    pub old_reads_new: CompatibilityClass,
    /// Whether the old decoder can preserve and re-emit new bytes.
    pub old_preserves_new: CompatibilityClass,
    /// Whether both decoders can read each other's bytes.
    pub bidirectional: CompatibilityClass,
    /// Structured schema changes.
    pub changes: Vec<SchemaChange>,
}

impl CompatibilityReport {
    /// Whether both read directions are compatible.
    #[must_use]
    pub const fn is_bidirectional(&self) -> bool {
        matches!(self.bidirectional, CompatibilityClass::Compatible)
    }
}

#[derive(Clone, Copy)]
struct Directional {
    new_reads_old: CompatibilityClass,
    old_reads_new: CompatibilityClass,
    old_preserves_new: CompatibilityClass,
}

impl Directional {
    const fn compatible() -> Self {
        Self {
            new_reads_old: CompatibilityClass::Compatible,
            old_reads_new: CompatibilityClass::Compatible,
            old_preserves_new: CompatibilityClass::Compatible,
        }
    }

    fn all_incompatible(&mut self) {
        self.new_reads_old = CompatibilityClass::Incompatible;
        self.old_reads_new = CompatibilityClass::Incompatible;
        self.old_preserves_new = CompatibilityClass::Incompatible;
    }
}

/// Encode an ABI value to owned canonical CBOR.
pub fn encode_to_canonical<T: AbiEncode>(value: &T) -> Result<CanonicalCbor, CborError> {
    struct AbiValue<'a, T: ?Sized>(&'a T);
    impl<T: AbiEncode + ?Sized> CborEncode for AbiValue<'_, T> {
        fn encode<S: ByteSink>(&self, enc: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
            self.0.abi_encode(enc)
        }
    }
    sacp_cbor::encode_to_canonical(&AbiValue(value))
}

/// Encode an ABI value to a vector of canonical bytes.
pub fn encode_to_vec<T: AbiEncode>(value: &T) -> Result<Vec<u8>, CborError> {
    Ok(encode_to_canonical(value)?.into_bytes())
}

/// Validate and decode an ABI value through one caller-owned context.
pub fn decode<'de, T, C>(
    bytes: &'de [u8],
    limits: DecodeLimits,
    context: &mut C,
) -> Result<T, C::Error>
where
    C: AbiDecodeContext + ?Sized,
    T: AbiDecode<'de, C>,
{
    let mut decoder = Decoder::<true>::new_checked(bytes, limits)?;
    let value = T::abi_decode(&mut decoder, context, AbiDecodeLocation::Root)?;
    let _ = decoder.finish()?;
    Ok(value)
}

/// Decode an ABI value from an already validated canonical witness through one caller-owned context.
pub fn decode_canonical<'de, T, C>(
    cbor: CanonicalCborRef<'de>,
    context: &mut C,
) -> Result<T, C::Error>
where
    C: AbiDecodeContext + ?Sized,
    T: AbiDecode<'de, C>,
{
    let mut decoder =
        Decoder::<false>::new_trusted(cbor, DecodeLimits::for_bytes(cbor.as_bytes().len()))?;
    let value = T::abi_decode(&mut decoder, context, AbiDecodeLocation::Root)?;
    let _ = decoder.finish()?;
    Ok(value)
}

/// SHA-256 over the selected canonical schema normal form.
pub fn schema_hash(schema: &Schema, kind: SchemaHashKind) -> Result<SchemaHash, CborError> {
    let canon = schema.canonical_bytes(kind)?;
    let mut hasher = Sha256::new();
    hasher.update(canon.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(SchemaHash(out))
}

/// Diff two schemas and report directional compatibility.
#[must_use]
pub fn diff(old: &Schema, new: &Schema) -> CompatibilityReport {
    let mut changes = Vec::new();
    let mut dir = Directional::compatible();

    if old.profile != new.profile {
        dir.all_incompatible();
        push_change(
            &mut changes,
            "schema",
            SchemaChangeClass::WireIncompatible,
            "ABI profile changed",
        );
    }
    if old.type_id != new.type_id {
        dir.all_incompatible();
        push_change(
            &mut changes,
            "schema",
            SchemaChangeClass::WireIncompatible,
            "type ID changed",
        );
    }
    if old.version != new.version {
        push_change(
            &mut changes,
            "schema.version",
            SchemaChangeClass::MetadataOnly,
            "version changed",
        );
    }

    compare_type_defs("root", &old.root, &new.root, &mut changes, &mut dir);

    CompatibilityReport {
        new_reads_old: dir.new_reads_old,
        old_reads_new: dir.old_reads_new,
        old_preserves_new: dir.old_preserves_new,
        bidirectional: dir.new_reads_old.and(dir.old_reads_new),
        changes,
    }
}

/// Assert a type's wire schema hash.
pub fn assert_wire_schema_hash<T: AbiType>(expected_hex: &str) {
    let actual = T::schema().wire_hash().expect("schema wire hash");
    assert_eq!(actual.to_string(), expected_hex);
}

/// Assert a type's full schema hash.
pub fn assert_full_schema_hash<T: AbiType>(expected_hex: &str) {
    let actual = T::schema().full_hash().expect("schema full hash");
    assert_eq!(actual.to_string(), expected_hex);
}

/// Assert an ABI encoding golden vector.
pub fn assert_abi_vector<T: AbiEncode>(name: &str, value: &T, expected_hex: &str) {
    let bytes = encode_to_vec(value).unwrap_or_else(|err| panic!("{name}: encode failed: {err}"));
    let actual = hex_bytes(&bytes);
    assert_eq!(actual, expected_hex, "{name}");
}

/// Assert that ABI decoding rejects bytes with the expected core error code.
pub fn assert_abi_rejects<'de, T, C>(bytes: &'de [u8], expected: ErrorCode, context: &mut C)
where
    C: AbiDecodeContext<Error = CborError> + ?Sized,
    T: AbiDecode<'de, C>,
{
    match decode::<T, C>(bytes, DecodeLimits::for_bytes(bytes.len()), context) {
        Ok(_) => panic!("decode unexpectedly succeeded"),
        Err(err) => assert_eq!(err.code, expected),
    }
}

fn push_change(
    changes: &mut Vec<SchemaChange>,
    path: &str,
    class: SchemaChangeClass,
    message: &str,
) {
    changes.push(SchemaChange {
        path: path.to_string(),
        class,
        message: message.to_string(),
    });
}

fn compare_type_defs(
    path: &str,
    old: &TypeDef,
    new: &TypeDef,
    changes: &mut Vec<SchemaChange>,
    dir: &mut Directional,
) {
    match (old, new) {
        (TypeDef::Struct(old), TypeDef::Struct(new)) => {
            compare_field_sets(path, old, new, changes, dir);
        }
        (TypeDef::Enum(old), TypeDef::Enum(new)) => {
            compare_enums(path, old, new, changes, dir);
        }
        (TypeDef::Transparent { inner: old }, TypeDef::Transparent { inner: new }) => {
            compare_type_ref(path, old, new, changes, dir);
        }
        (TypeDef::Primitive { ty: old }, TypeDef::Primitive { ty: new }) => {
            compare_type_ref(path, old, new, changes, dir);
        }
        _ => {
            dir.all_incompatible();
            push_change(
                changes,
                path,
                SchemaChangeClass::WireIncompatible,
                "type kind changed",
            );
        }
    }
}

fn compare_field_sets(
    path: &str,
    old: &FieldSetDef,
    new: &FieldSetDef,
    changes: &mut Vec<SchemaChange>,
    dir: &mut Directional,
) {
    if old.unknown_fields != new.unknown_fields {
        push_change(
            changes,
            &format!("{path}.unknown_fields"),
            SchemaChangeClass::WireCompatible,
            "unknown-field policy changed",
        );
    }
    compare_fields(
        path,
        &old.fields,
        &new.fields,
        old.unknown_fields,
        new.unknown_fields,
        changes,
        dir,
    );
}

fn compare_enums(
    path: &str,
    old: &EnumDef,
    new: &EnumDef,
    changes: &mut Vec<SchemaChange>,
    dir: &mut Directional,
) {
    if old.unknown_fields != new.unknown_fields {
        push_change(
            changes,
            &format!("{path}.unknown_fields"),
            SchemaChangeClass::WireCompatible,
            "variant field-set unknown-field policy changed",
        );
    }
    if old.unknown_variants != new.unknown_variants {
        push_change(
            changes,
            &format!("{path}.unknown_variants"),
            SchemaChangeClass::WireCompatible,
            "unknown-variant policy changed",
        );
    }

    for old_variant in &old.variants {
        match new
            .variants
            .iter()
            .find(|variant| variant.id == old_variant.id)
        {
            Some(new_variant) => {
                let variant_path = format!("{path}.variant.{}", old_variant.id);
                if old_variant.name != new_variant.name {
                    push_change(
                        changes,
                        &format!("{variant_path}.name"),
                        SchemaChangeClass::MetadataOnly,
                        "variant name changed",
                    );
                }
                compare_fields(
                    &variant_path,
                    &old_variant.fields,
                    &new_variant.fields,
                    old.unknown_fields,
                    new.unknown_fields,
                    changes,
                    dir,
                );
            }
            None => {
                push_change(
                    changes,
                    &format!("{path}.variant.{}", old_variant.id),
                    SchemaChangeClass::WireIncompatible,
                    "variant removed",
                );
                if !new.unknown_variants.preserves() {
                    dir.new_reads_old = CompatibilityClass::Incompatible;
                }
            }
        }
    }

    for new_variant in &new.variants {
        if old
            .variants
            .iter()
            .all(|variant| variant.id != new_variant.id)
        {
            push_change(
                changes,
                &format!("{path}.variant.{}", new_variant.id),
                SchemaChangeClass::WireCompatible,
                "variant added",
            );
            if !old.unknown_variants.preserves() {
                dir.old_reads_new = CompatibilityClass::Incompatible;
                dir.old_preserves_new = CompatibilityClass::Incompatible;
            }
        }
    }
}

fn compare_fields(
    path: &str,
    old_fields: &[FieldDef],
    new_fields: &[FieldDef],
    old_unknown: UnknownFieldPolicy,
    new_unknown: UnknownFieldPolicy,
    changes: &mut Vec<SchemaChange>,
    dir: &mut Directional,
) {
    for old in old_fields {
        match new_fields.iter().find(|field| field.id == old.id) {
            Some(new) => {
                let field_path = format!("{path}.field.{}", old.id);
                if old.name != new.name {
                    push_change(
                        changes,
                        &format!("{field_path}.name"),
                        SchemaChangeClass::MetadataOnly,
                        "field name changed",
                    );
                }
                if old.ty != new.ty {
                    dir.all_incompatible();
                    push_change(
                        changes,
                        &format!("{field_path}.type"),
                        SchemaChangeClass::WireIncompatible,
                        "field type changed",
                    );
                }
                if old.presence != new.presence {
                    push_change(
                        changes,
                        &format!("{field_path}.presence"),
                        SchemaChangeClass::WireIncompatible,
                        "field presence changed",
                    );
                    match (old.presence, new.presence) {
                        (FieldPresence::Required, FieldPresence::Optional) => {
                            dir.old_reads_new = CompatibilityClass::Incompatible;
                            dir.old_preserves_new = CompatibilityClass::Incompatible;
                        }
                        (FieldPresence::Optional, FieldPresence::Required) => {
                            dir.new_reads_old = CompatibilityClass::Incompatible;
                        }
                        _ => {}
                    }
                }
            }
            None => {
                push_change(
                    changes,
                    &format!("{path}.field.{}", old.id),
                    SchemaChangeClass::WireIncompatible,
                    "field removed",
                );
                if !new_unknown.accepts() {
                    dir.new_reads_old = CompatibilityClass::Incompatible;
                }
                if matches!(old.presence, FieldPresence::Required) {
                    dir.old_reads_new = CompatibilityClass::Incompatible;
                    dir.old_preserves_new = CompatibilityClass::Incompatible;
                }
            }
        }
    }

    for new in new_fields {
        if old_fields.iter().all(|field| field.id != new.id) {
            push_change(
                changes,
                &format!("{path}.field.{}", new.id),
                if new.presence.is_optional() {
                    SchemaChangeClass::WireCompatible
                } else {
                    SchemaChangeClass::WireIncompatible
                },
                "field added",
            );
            if !new.presence.is_optional() {
                dir.new_reads_old = CompatibilityClass::Incompatible;
            }
            if !old_unknown.accepts() {
                dir.old_reads_new = CompatibilityClass::Incompatible;
            }
            if !old_unknown.preserves() {
                dir.old_preserves_new = CompatibilityClass::Incompatible;
            }
        }
    }
}

fn compare_type_ref(
    path: &str,
    old: &TypeRef,
    new: &TypeRef,
    changes: &mut Vec<SchemaChange>,
    dir: &mut Directional,
) {
    if old != new {
        dir.all_incompatible();
        push_change(
            changes,
            path,
            SchemaChangeClass::WireIncompatible,
            "type reference changed",
        );
    }
}

struct SchemaNormalForm<'a> {
    schema: &'a Schema,
    kind: SchemaHashKind,
}

impl CborEncode for SchemaNormalForm<'_> {
    fn encode<S: ByteSink>(&self, enc: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        encode_schema(self.schema, self.kind, enc)
    }
}

fn encode_schema<S: ByteSink>(
    schema: &Schema,
    kind: SchemaHashKind,
    enc: &mut ValueEncoder<'_, S>,
) -> EncodeResult<(), S> {
    match kind {
        SchemaHashKind::Wire => enc.array(3, |array| {
            encode_item(array, &schema.profile)?;
            encode_item(array, &schema.type_id)?;
            array.encode_with(|enc| encode_type_def(&schema.root, kind, enc))?;
            Ok(())
        }),
        SchemaHashKind::Full => enc.array(4, |array| {
            encode_item(array, &schema.profile)?;
            encode_item(array, &schema.type_id)?;
            encode_item(array, &schema.version)?;
            array.encode_with(|enc| encode_type_def(&schema.root, kind, enc))?;
            Ok(())
        }),
    }
}

fn encode_type_def<S: ByteSink>(
    def: &TypeDef,
    kind: SchemaHashKind,
    enc: &mut ValueEncoder<'_, S>,
) -> EncodeResult<(), S> {
    match def {
        TypeDef::Struct(field_set) => enc.array(3, |array| {
            encode_item(array, &"struct")?;
            encode_item(array, &field_set.unknown_fields.as_str())?;
            encode_fields(array, &field_set.fields, kind)?;
            Ok(())
        }),
        TypeDef::Enum(enum_def) => enc.array(4, |array| {
            encode_item(array, &"enum")?;
            encode_item(array, &enum_def.unknown_fields.as_str())?;
            encode_item(array, &enum_def.unknown_variants.as_str())?;
            array.encode_with(|enc| {
                let mut variants: Vec<&VariantDef> = enum_def.variants.iter().collect();
                variants.sort_unstable_by_key(|variant| variant.id);
                enc.array(variants.len(), |array| {
                    for variant in variants {
                        array.encode_with(|enc| encode_variant(variant, kind, enc))?;
                    }
                    Ok(())
                })
            })?;
            Ok(())
        }),
        TypeDef::Transparent { inner } => enc.array(2, |array| {
            encode_item(array, &"transparent")?;
            array.encode_with(|enc| encode_type_ref(inner, enc))?;
            Ok(())
        }),
        TypeDef::Primitive { ty } => enc.array(2, |array| {
            encode_item(array, &"primitive")?;
            array.encode_with(|enc| encode_type_ref(ty, enc))?;
            Ok(())
        }),
    }
}

fn encode_fields<S: ByteSink>(
    array: &mut sacp_cbor::encode::ArrayEncoder<'_, S>,
    fields: &[FieldDef],
    kind: SchemaHashKind,
) -> EncodeResult<(), S> {
    array.encode_with(|enc| {
        let mut fields: Vec<&FieldDef> = fields.iter().collect();
        fields.sort_unstable_by_key(|field| field.id);
        enc.array(fields.len(), |array| {
            for field in fields {
                array.encode_with(|enc| encode_field(field, kind, enc))?;
            }
            Ok(())
        })
    })
}

fn encode_field<S: ByteSink>(
    field: &FieldDef,
    kind: SchemaHashKind,
    enc: &mut ValueEncoder<'_, S>,
) -> EncodeResult<(), S> {
    match kind {
        SchemaHashKind::Wire => enc.array(3, |array| {
            encode_item(array, &field.id)?;
            array.encode_with(|enc| encode_type_ref(&field.ty, enc))?;
            encode_item(array, &field.presence.as_str())?;
            Ok(())
        }),
        SchemaHashKind::Full => enc.array(4, |array| {
            encode_item(array, &field.id)?;
            encode_item(array, &field.name)?;
            array.encode_with(|enc| encode_type_ref(&field.ty, enc))?;
            encode_item(array, &field.presence.as_str())?;
            Ok(())
        }),
    }
}

fn encode_variant<S: ByteSink>(
    variant: &VariantDef,
    kind: SchemaHashKind,
    enc: &mut ValueEncoder<'_, S>,
) -> EncodeResult<(), S> {
    match kind {
        SchemaHashKind::Wire => enc.array(2, |array| {
            encode_item(array, &variant.id)?;
            encode_fields(array, &variant.fields, kind)?;
            Ok(())
        }),
        SchemaHashKind::Full => enc.array(3, |array| {
            encode_item(array, &variant.id)?;
            encode_item(array, &variant.name)?;
            encode_fields(array, &variant.fields, kind)?;
            Ok(())
        }),
    }
}

fn encode_type_ref<S: ByteSink>(
    ty: &TypeRef,
    enc: &mut ValueEncoder<'_, S>,
) -> EncodeResult<(), S> {
    match ty {
        TypeRef::Unit => enc.text("unit"),
        TypeRef::Bool => enc.text("bool"),
        TypeRef::U8 => enc.text("u8"),
        TypeRef::U16 => enc.text("u16"),
        TypeRef::U32 => enc.text("u32"),
        TypeRef::U64 => enc.text("u64"),
        TypeRef::I8 => enc.text("i8"),
        TypeRef::I16 => enc.text("i16"),
        TypeRef::I32 => enc.text("i32"),
        TypeRef::I64 => enc.text("i64"),
        TypeRef::Text => enc.text("text"),
        TypeRef::Bytes => enc.text("bytes"),
        TypeRef::CanonicalCbor => enc.text("canonical_cbor"),
        TypeRef::FixedBytes { len } => enc.array(2, |array| {
            encode_item(array, &"fixed_bytes")?;
            encode_item(array, len)?;
            Ok(())
        }),
        TypeRef::Vec { item } => enc.array(2, |array| {
            encode_item(array, &"vec")?;
            array.encode_with(|enc| encode_type_ref(item, enc))?;
            Ok(())
        }),
        TypeRef::Named { type_id, version } => enc.array(3, |array| {
            encode_item(array, &"named")?;
            encode_item(array, type_id)?;
            match version {
                Some(version) => encode_item(array, version)?,
                None => array.null()?,
            }
            Ok(())
        }),
    }
}

fn encode_item<S: ByteSink, T: CborEncode + ?Sized>(
    array: &mut sacp_cbor::encode::ArrayEncoder<'_, S>,
    value: &T,
) -> EncodeResult<(), S> {
    array.value(value)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

macro_rules! passthrough_abi {
    ($($ty:ty => $ref:expr),* $(,)?) => {
        $(
            impl AbiEncode for $ty {
                fn abi_encode<S: ByteSink>(
                    &self,
                    enc: &mut ValueEncoder<'_, S>,
                ) -> EncodeResult<(), S> {
                    CborEncode::encode(self, enc)
                }
            }

            impl<'de, C: AbiDecodeContext + ?Sized> AbiDecode<'de, C> for $ty {
                fn abi_decode<const CHECKED: bool>(
                    decoder: &mut Decoder<'de, CHECKED>,
                    _context: &mut C,
                    _location: AbiDecodeLocation,
                ) -> Result<Self, C::Error> {
                    CborDecode::decode(decoder).map_err(C::Error::from)
                }
            }

            impl AbiTypeRef for $ty {
                fn abi_type_ref() -> TypeRef {
                    $ref
                }
            }
        )*
    };
}

passthrough_abi!(
    () => TypeRef::Unit,
    bool => TypeRef::Bool,
    u8 => TypeRef::U8,
    u16 => TypeRef::U16,
    u32 => TypeRef::U32,
    u64 => TypeRef::U64,
    i8 => TypeRef::I8,
    i16 => TypeRef::I16,
    i32 => TypeRef::I32,
    i64 => TypeRef::I64,
);

impl AbiEncode for &str {
    fn abi_encode<S: ByteSink>(&self, enc: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        CborEncode::encode(self, enc)
    }
}

impl<'de, C: AbiDecodeContext + ?Sized> AbiDecode<'de, C> for &'de str {
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        _context: &mut C,
        _location: AbiDecodeLocation,
    ) -> Result<Self, C::Error> {
        CborDecode::decode(decoder).map_err(C::Error::from)
    }
}

impl AbiTypeRef for &str {
    fn abi_type_ref() -> TypeRef {
        TypeRef::Text
    }
}

impl AbiEncode for String {
    fn abi_encode<S: ByteSink>(&self, enc: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        CborEncode::encode(self, enc)
    }
}

impl<'de, C: AbiDecodeContext + ?Sized> AbiDecode<'de, C> for String {
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        context: &mut C,
        location: AbiDecodeLocation,
    ) -> Result<Self, C::Error> {
        let offset = decoder.position();
        let value = decoder.decode_text_with_guard(|header| {
            context.admit(
                location,
                AbiDecodeValue::Text {
                    offset: header.header_offset(),
                    bytes: header.declared_len(),
                },
            )
        })?;
        let mut owned = String::new();
        owned
            .try_reserve_exact(value.len())
            .map_err(|_| C::Error::from(CborError::new(ErrorCode::AllocationFailed, offset)))?;
        owned.push_str(value);
        Ok(owned)
    }
}

impl AbiTypeRef for String {
    fn abi_type_ref() -> TypeRef {
        TypeRef::Text
    }
}

impl AbiEncode for BytesRef<'_> {
    fn abi_encode<S: ByteSink>(&self, enc: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        CborEncode::encode(self, enc)
    }
}

impl<'de, C: AbiDecodeContext + ?Sized> AbiDecode<'de, C> for BytesRef<'de> {
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        _context: &mut C,
        _location: AbiDecodeLocation,
    ) -> Result<Self, C::Error> {
        CborDecode::decode(decoder).map_err(C::Error::from)
    }
}

impl AbiTypeRef for BytesRef<'_> {
    fn abi_type_ref() -> TypeRef {
        TypeRef::Bytes
    }
}

impl AbiEncode for Bytes {
    fn abi_encode<S: ByteSink>(&self, enc: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        CborEncode::encode(self, enc)
    }
}

impl<'de, C: AbiDecodeContext + ?Sized> AbiDecode<'de, C> for Bytes {
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        context: &mut C,
        location: AbiDecodeLocation,
    ) -> Result<Self, C::Error> {
        let offset = decoder.position();
        let value = decoder.decode_bytes_with_guard(|header| {
            context.admit(
                location,
                AbiDecodeValue::Bytes {
                    offset: header.header_offset(),
                    bytes: header.declared_len(),
                },
            )
        })?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(value.len())
            .map_err(|_| C::Error::from(CborError::new(ErrorCode::AllocationFailed, offset)))?;
        owned.extend_from_slice(value);
        Ok(Self::new(owned))
    }
}

impl AbiTypeRef for Bytes {
    fn abi_type_ref() -> TypeRef {
        TypeRef::Bytes
    }
}

impl AbiEncode for CanonicalCborRef<'_> {
    fn abi_encode<S: ByteSink>(&self, enc: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        CborEncode::encode(self, enc)
    }
}

impl<'de, C: AbiDecodeContext + ?Sized> AbiDecode<'de, C> for CanonicalCborRef<'de> {
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        _context: &mut C,
        _location: AbiDecodeLocation,
    ) -> Result<Self, C::Error> {
        CborDecode::decode(decoder).map_err(C::Error::from)
    }
}

impl AbiTypeRef for CanonicalCborRef<'_> {
    fn abi_type_ref() -> TypeRef {
        TypeRef::CanonicalCbor
    }
}

impl AbiEncode for CanonicalCbor {
    fn abi_encode<S: ByteSink>(&self, enc: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        CborEncode::encode(self, enc)
    }
}

impl<'de, C: AbiDecodeContext + ?Sized> AbiDecode<'de, C> for CanonicalCbor {
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        context: &mut C,
        location: AbiDecodeLocation,
    ) -> Result<Self, C::Error> {
        let value_offset = core::cell::Cell::new(0);
        let value = decoder.decode_canonical_with_guard(|header| {
            value_offset.set(header.header_offset());
            context.admit(
                location,
                AbiDecodeValue::Canonical {
                    offset: header.header_offset(),
                    bytes: header.encoded_len(),
                },
            )
        })?;
        value
            .to_owned_with_offset(value_offset.get())
            .map_err(C::Error::from)
    }
}

impl AbiTypeRef for CanonicalCbor {
    fn abi_type_ref() -> TypeRef {
        TypeRef::CanonicalCbor
    }
}

impl<const N: usize> AbiEncode for [u8; N] {
    fn abi_encode<S: ByteSink>(&self, enc: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        CborEncode::encode(self, enc)
    }
}

impl<'de, C: AbiDecodeContext + ?Sized, const N: usize> AbiDecode<'de, C> for [u8; N] {
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        _context: &mut C,
        _location: AbiDecodeLocation,
    ) -> Result<Self, C::Error> {
        CborDecode::decode(decoder).map_err(C::Error::from)
    }
}

impl<const N: usize> AbiTypeRef for [u8; N] {
    fn abi_type_ref() -> TypeRef {
        TypeRef::FixedBytes { len: N as u32 }
    }
}

impl<T: AbiEncode> AbiEncode for Vec<T> {
    fn abi_encode<S: ByteSink>(&self, enc: &mut ValueEncoder<'_, S>) -> EncodeResult<(), S> {
        enc.array(self.len(), |array| {
            for value in self {
                array.encode_with(|enc| value.abi_encode(enc))?;
            }
            Ok(())
        })
    }
}

impl<'de, T, C> AbiDecode<'de, C> for Vec<T>
where
    C: AbiDecodeContext + ?Sized,
    T: AbiDecode<'de, C>,
{
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
        context: &mut C,
        location: AbiDecodeLocation,
    ) -> Result<Self, C::Error> {
        let array_off = decoder.position();
        let array = decoder.array()?;
        let mut array = array.admit_with(|header| {
            context.admit(
                location,
                AbiDecodeValue::Sequence {
                    offset: header.header_offset(),
                    items: header.declared_len(),
                },
            )
        })?;
        let mut out = Vec::new();
        out.try_reserve_exact(array.remaining())
            .map_err(|_| C::Error::from(CborError::new(ErrorCode::AllocationFailed, array_off)))?;
        while let Some(value) =
            array.decode_next_with(|decoder| T::abi_decode(decoder, context, location))?
        {
            out.push(value);
        }
        Ok(out)
    }
}

impl<T: AbiTypeRef> AbiTypeRef for Vec<T> {
    fn abi_type_ref() -> TypeRef {
        TypeRef::Vec {
            item: Box::new(T::abi_type_ref()),
        }
    }
}
