//! Allocation-free static ABI schema descriptors and canonical normal forms.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt;

use sacp_cbor::{
    ByteSink, CanonicalCbor, CborError, DecodeLimits, DigestSink, EncodeError, EncodeLimits,
    EncodeResult, Encoder, ValueEncoder, VecSink, WorkObserver,
};
use sha2::Sha256;

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
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Ignore => "ignore",
            Self::Preserve => "preserve",
        }
    }

    pub(crate) const fn accepts(self) -> bool {
        matches!(self, Self::Ignore | Self::Preserve)
    }

    pub(crate) const fn preserves(self) -> bool {
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
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Preserve => "preserve",
        }
    }

    pub(crate) const fn preserves(self) -> bool {
        matches!(self, Self::Preserve)
    }
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
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
        }
    }

    pub(crate) const fn is_optional(self) -> bool {
        matches!(self, Self::Optional)
    }
}

/// Non-sequence terminal of an ABI type reference.
///
/// Sequence nesting is stored separately in [`TypeRef`]. This value representation makes every
/// statically known type reference `Copy` without recursive `Box` allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeAtom {
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
        len: u64,
    },
    /// Canonical CBOR sub-value.
    CanonicalCbor,
    /// Stable named ABI type.
    Named {
        /// Stable type identity.
        type_id: &'static str,
        /// Optional referenced schema version.
        version: Option<u32>,
    },
}

/// Stable, storage-independent ABI type reference.
///
/// `sequence_depth == 0` denotes the terminal atom. Every positive level denotes one homogeneous
/// protocol `Sequence`; no Rust collection type is part of this model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeRef {
    sequence_depth: u32,
    atom: TypeAtom,
}

impl TypeRef {
    /// Unit/null.
    pub const UNIT: Self = Self::atom(TypeAtom::Unit);
    /// Boolean.
    pub const BOOL: Self = Self::atom(TypeAtom::Bool);
    /// Unsigned 8-bit integer.
    pub const U8: Self = Self::atom(TypeAtom::U8);
    /// Unsigned 16-bit integer.
    pub const U16: Self = Self::atom(TypeAtom::U16);
    /// Unsigned 32-bit integer.
    pub const U32: Self = Self::atom(TypeAtom::U32);
    /// Unsigned 64-bit integer.
    pub const U64: Self = Self::atom(TypeAtom::U64);
    /// Signed 8-bit integer.
    pub const I8: Self = Self::atom(TypeAtom::I8);
    /// Signed 16-bit integer.
    pub const I16: Self = Self::atom(TypeAtom::I16);
    /// Signed 32-bit integer.
    pub const I32: Self = Self::atom(TypeAtom::I32);
    /// Signed 64-bit integer.
    pub const I64: Self = Self::atom(TypeAtom::I64);
    /// UTF-8 text.
    pub const TEXT: Self = Self::atom(TypeAtom::Text);
    /// Byte string.
    pub const BYTES: Self = Self::atom(TypeAtom::Bytes);
    /// Canonical CBOR sub-value.
    pub const CANONICAL_CBOR: Self = Self::atom(TypeAtom::CanonicalCbor);

    /// Construct a terminal type reference.
    #[must_use]
    pub const fn atom(atom: TypeAtom) -> Self {
        Self {
            sequence_depth: 0,
            atom,
        }
    }

    /// Construct a fixed-length byte-string reference.
    #[must_use]
    pub const fn fixed_bytes(len: u64) -> Self {
        Self::atom(TypeAtom::FixedBytes { len })
    }

    /// Construct a named type reference.
    #[must_use]
    pub const fn named(type_id: &'static str, version: Option<u32>) -> Self {
        if type_id.is_empty() {
            panic!("ABI type ID must not be empty");
        }
        Self::atom(TypeAtom::Named { type_id, version })
    }

    /// Wrap `item` in one protocol sequence level.
    #[must_use]
    pub const fn sequence(item: Self) -> Self {
        let Some(sequence_depth) = item.sequence_depth.checked_add(1) else {
            panic!("ABI sequence nesting exceeds u32::MAX");
        };
        Self {
            sequence_depth,
            atom: item.atom,
        }
    }

    /// Return the number of surrounding protocol sequence levels.
    #[must_use]
    pub const fn sequence_depth(self) -> u32 {
        self.sequence_depth
    }

    /// Return the non-sequence terminal.
    #[must_use]
    pub const fn terminal(self) -> TypeAtom {
        self.atom
    }

    /// Remove one surrounding sequence level.
    #[must_use]
    pub const fn sequence_item(self) -> Option<Self> {
        if self.sequence_depth == 0 {
            None
        } else {
            Some(Self {
                sequence_depth: self.sequence_depth - 1,
                atom: self.atom,
            })
        }
    }
}

/// One statically known public field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldDef {
    id: u32,
    name: &'static str,
    ty: TypeRef,
    presence: FieldPresence,
}

impl FieldDef {
    /// Construct a field descriptor.
    #[must_use]
    pub const fn new(id: u32, name: &'static str, ty: TypeRef, presence: FieldPresence) -> Self {
        if id == 0 {
            panic!("ABI field ID must be nonzero");
        }
        if name.is_empty() {
            panic!("ABI field name must not be empty");
        }
        Self {
            id,
            name,
            ty,
            presence,
        }
    }

    /// Stable numeric field ID.
    #[must_use]
    pub const fn id(self) -> u32 {
        self.id
    }

    /// Source field name used for diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Storage-independent wire type.
    #[must_use]
    pub const fn ty(self) -> TypeRef {
        self.ty
    }

    /// Required or optional presence.
    #[must_use]
    pub const fn presence(self) -> FieldPresence {
        self.presence
    }
}

/// A statically known ABI field set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSetDef {
    fields: &'static [FieldDef],
    unknown_fields: UnknownFieldPolicy,
    required_count: usize,
}

impl FieldSetDef {
    /// Construct a field set from strictly increasing, nonzero field IDs.
    #[must_use]
    pub const fn new(fields: &'static [FieldDef], unknown_fields: UnknownFieldPolicy) -> Self {
        let mut index = 0usize;
        let mut required_count = 0usize;
        while index < fields.len() {
            if fields[index].id == 0 {
                panic!("ABI field ID must be nonzero");
            }
            if index != 0 && fields[index - 1].id >= fields[index].id {
                panic!("ABI fields must be in strict numeric ID order");
            }
            if matches!(fields[index].presence, FieldPresence::Required) {
                required_count += 1;
            }
            index += 1;
        }
        Self {
            fields,
            unknown_fields,
            required_count,
        }
    }

    /// Fields in strict numeric ID order.
    #[must_use]
    pub const fn fields(self) -> &'static [FieldDef] {
        self.fields
    }

    /// Unknown-field policy owned by this field set.
    #[must_use]
    pub const fn unknown_fields(self) -> UnknownFieldPolicy {
        self.unknown_fields
    }

    /// Number of required fields.
    #[must_use]
    pub const fn required_count(self) -> usize {
        self.required_count
    }
}

/// Explicit enum payload shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariantPayloadDef {
    /// CBOR null payload.
    Unit,
    /// ABI field-set payload, including an empty-but-non-unit field set.
    Fields(FieldSetDef),
}

/// One statically known public enum variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VariantDef {
    id: u32,
    name: &'static str,
    payload: VariantPayloadDef,
}

impl VariantDef {
    /// Construct a unit variant descriptor.
    #[must_use]
    pub const fn unit(id: u32, name: &'static str) -> Self {
        Self::new(id, name, VariantPayloadDef::Unit)
    }

    /// Construct a field-set variant descriptor.
    #[must_use]
    pub const fn fields(id: u32, name: &'static str, fields: FieldSetDef) -> Self {
        Self::new(id, name, VariantPayloadDef::Fields(fields))
    }

    const fn new(id: u32, name: &'static str, payload: VariantPayloadDef) -> Self {
        if id == 0 {
            panic!("ABI variant ID must be nonzero");
        }
        if name.is_empty() {
            panic!("ABI variant name must not be empty");
        }
        Self { id, name, payload }
    }

    /// Stable numeric variant ID.
    #[must_use]
    pub const fn id(self) -> u32 {
        self.id
    }

    /// Source variant name used for diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Explicit unit or field-set payload shape.
    #[must_use]
    pub const fn payload(self) -> VariantPayloadDef {
        self.payload
    }
}

/// A statically known public enum definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnumDef {
    variants: &'static [VariantDef],
    unknown_variants: UnknownVariantPolicy,
}

impl EnumDef {
    /// Construct an enum from strictly increasing, nonzero variant IDs.
    #[must_use]
    pub const fn new(
        variants: &'static [VariantDef],
        unknown_variants: UnknownVariantPolicy,
    ) -> Self {
        let mut index = 0usize;
        while index < variants.len() {
            if variants[index].id == 0 {
                panic!("ABI variant ID must be nonzero");
            }
            if index != 0 && variants[index - 1].id >= variants[index].id {
                panic!("ABI variants must be in strict numeric ID order");
            }
            index += 1;
        }
        Self {
            variants,
            unknown_variants,
        }
    }

    /// Variants in strict numeric ID order.
    #[must_use]
    pub const fn variants(self) -> &'static [VariantDef] {
        self.variants
    }

    /// Unknown-variant policy owned by this enum.
    #[must_use]
    pub const fn unknown_variants(self) -> UnknownVariantPolicy {
        self.unknown_variants
    }
}

/// A storage-independent public ABI type definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeDef {
    /// Struct field set.
    Struct(FieldSetDef),
    /// Enum discriminant plus explicit payload shape.
    Enum(EnumDef),
    /// Named wrapper encoded exactly like its inner wire type.
    Transparent {
        /// Inner wire type.
        inner: TypeRef,
    },
    /// Primitive or external wire definition.
    Primitive {
        /// Primitive type reference.
        ty: TypeRef,
    },
}

/// A complete allocation-free public ABI schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schema {
    type_id: &'static str,
    version: u32,
    root: TypeDef,
}

impl Schema {
    /// Construct a static schema using the fixed [`ABI_PROFILE`].
    #[must_use]
    pub const fn new(type_id: &'static str, version: u32, root: TypeDef) -> Self {
        if type_id.is_empty() {
            panic!("ABI type ID must not be empty");
        }
        Self {
            type_id,
            version,
            root,
        }
    }

    /// Fixed schema profile.
    #[must_use]
    pub const fn profile(self) -> &'static str {
        ABI_PROFILE
    }

    /// Stable semantic type identity.
    #[must_use]
    pub const fn type_id(self) -> &'static str {
        self.type_id
    }

    /// Governance schema version.
    #[must_use]
    pub const fn version(self) -> u32 {
        self.version
    }

    /// Root wire definition.
    #[must_use]
    pub const fn root(self) -> TypeDef {
        self.root
    }

    /// Canonical bytes of one schema normal form under explicit limits.
    pub fn canonical_bytes(
        &'static self,
        kind: SchemaHashKind,
        limits: EncodeLimits,
    ) -> Result<CanonicalCbor, EncodeError<CborError>> {
        let bytes = encode_schema_to_sink(self, kind, VecSink::new(), limits)?;
        let len = bytes.len();
        CanonicalCbor::from_vec(bytes, DecodeLimits::for_bytes(len)).map_err(EncodeError::Cbor)
    }

    /// SHA-256 over the wire-significant normal form under explicit limits.
    pub fn wire_hash(
        &'static self,
        limits: EncodeLimits,
    ) -> Result<SchemaHash, EncodeError<Infallible>> {
        schema_hash(self, SchemaHashKind::Wire, limits)
    }

    /// SHA-256 over the complete normal form under explicit limits.
    pub fn full_hash(
        &'static self,
        limits: EncodeLimits,
    ) -> Result<SchemaHash, EncodeError<Infallible>> {
        schema_hash(self, SchemaHashKind::Full, limits)
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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Encode a schema normal form directly into an arbitrary sink under explicit limits.
pub fn encode_schema_to_sink<S: ByteSink>(
    schema: &'static Schema,
    kind: SchemaHashKind,
    sink: S,
    limits: EncodeLimits,
) -> Result<S::Output, EncodeError<S::Error>> {
    let mut encoder = Encoder::with_sink_and_limits(sink, limits).map_err(EncodeError::Cbor)?;
    encoder.encode_with(|value| encode_schema(schema, kind, value))?;
    encoder.finish()
}

/// Hash a schema in one encoding pass without materializing its normal-form bytes.
pub fn schema_hash(
    schema: &'static Schema,
    kind: SchemaHashKind,
    limits: EncodeLimits,
) -> Result<SchemaHash, EncodeError<Infallible>> {
    let digest = encode_schema_to_sink(schema, kind, DigestSink::new(Sha256::default()), limits)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(SchemaHash(out))
}

fn encode_schema<S: ByteSink, O: WorkObserver>(
    schema: &Schema,
    kind: SchemaHashKind,
    enc: &mut ValueEncoder<'_, S, O>,
) -> EncodeResult<(), S> {
    match kind {
        SchemaHashKind::Wire => enc.array(3, |array| {
            array.value(&ABI_PROFILE)?;
            array.value(&schema.type_id)?;
            array.encode_with(|value| encode_type_def(schema.root, kind, value))?;
            Ok(())
        }),
        SchemaHashKind::Full => enc.array(4, |array| {
            array.value(&ABI_PROFILE)?;
            array.value(&schema.type_id)?;
            array.value(&schema.version)?;
            array.encode_with(|value| encode_type_def(schema.root, kind, value))?;
            Ok(())
        }),
    }
}

fn encode_type_def<S: ByteSink, O: WorkObserver>(
    def: TypeDef,
    kind: SchemaHashKind,
    enc: &mut ValueEncoder<'_, S, O>,
) -> EncodeResult<(), S> {
    match def {
        TypeDef::Struct(fields) => enc.array(2, |array| {
            array.value(&"struct")?;
            array.encode_with(|value| encode_field_set(fields, kind, value))?;
            Ok(())
        }),
        TypeDef::Enum(def) => enc.array(3, |array| {
            array.value(&"enum")?;
            array.value(&def.unknown_variants.as_str())?;
            array.encode_with(|value| {
                value.array(def.variants.len(), |variants| {
                    for variant in def.variants {
                        variants.encode_with(|value| encode_variant(*variant, kind, value))?;
                    }
                    Ok(())
                })
            })?;
            Ok(())
        }),
        TypeDef::Transparent { inner } => enc.array(2, |array| {
            array.value(&"transparent")?;
            array.encode_with(|value| encode_type_ref(inner, value))?;
            Ok(())
        }),
        TypeDef::Primitive { ty } => enc.array(2, |array| {
            array.value(&"primitive")?;
            array.encode_with(|value| encode_type_ref(ty, value))?;
            Ok(())
        }),
    }
}

fn encode_field_set<S: ByteSink, O: WorkObserver>(
    fields: FieldSetDef,
    kind: SchemaHashKind,
    enc: &mut ValueEncoder<'_, S, O>,
) -> EncodeResult<(), S> {
    enc.array(2, |array| {
        array.value(&fields.unknown_fields.as_str())?;
        array.encode_with(|value| {
            value.array(fields.fields.len(), |items| {
                for field in fields.fields {
                    items.encode_with(|value| encode_field(*field, kind, value))?;
                }
                Ok(())
            })
        })?;
        Ok(())
    })
}

fn encode_field<S: ByteSink, O: WorkObserver>(
    field: FieldDef,
    kind: SchemaHashKind,
    enc: &mut ValueEncoder<'_, S, O>,
) -> EncodeResult<(), S> {
    match kind {
        SchemaHashKind::Wire => enc.array(3, |array| {
            array.value(&field.id)?;
            array.encode_with(|value| encode_type_ref(field.ty, value))?;
            array.value(&field.presence.as_str())?;
            Ok(())
        }),
        SchemaHashKind::Full => enc.array(4, |array| {
            array.value(&field.id)?;
            array.value(&field.name)?;
            array.encode_with(|value| encode_type_ref(field.ty, value))?;
            array.value(&field.presence.as_str())?;
            Ok(())
        }),
    }
}

fn encode_variant<S: ByteSink, O: WorkObserver>(
    variant: VariantDef,
    kind: SchemaHashKind,
    enc: &mut ValueEncoder<'_, S, O>,
) -> EncodeResult<(), S> {
    let len = if matches!(kind, SchemaHashKind::Full) {
        3
    } else {
        2
    };
    enc.array(len, |array| {
        array.value(&variant.id)?;
        if matches!(kind, SchemaHashKind::Full) {
            array.value(&variant.name)?;
        }
        match variant.payload {
            VariantPayloadDef::Unit => array.value(&"unit")?,
            VariantPayloadDef::Fields(fields) => array.encode_with(|value| {
                value.array(2, |payload| {
                    payload.value(&"fields")?;
                    payload.encode_with(|value| encode_field_set(fields, kind, value))?;
                    Ok(())
                })
            })?,
        }
        Ok(())
    })
}

fn encode_type_ref<S: ByteSink, O: WorkObserver>(
    ty: TypeRef,
    enc: &mut ValueEncoder<'_, S, O>,
) -> EncodeResult<(), S> {
    if let Some(item) = ty.sequence_item() {
        return enc.array(2, |array| {
            array.value(&"sequence")?;
            array.encode_with(|value| encode_type_ref(item, value))?;
            Ok(())
        });
    }
    match ty.atom {
        TypeAtom::Unit => enc.text("unit"),
        TypeAtom::Bool => enc.text("bool"),
        TypeAtom::U8 => enc.text("u8"),
        TypeAtom::U16 => enc.text("u16"),
        TypeAtom::U32 => enc.text("u32"),
        TypeAtom::U64 => enc.text("u64"),
        TypeAtom::I8 => enc.text("i8"),
        TypeAtom::I16 => enc.text("i16"),
        TypeAtom::I32 => enc.text("i32"),
        TypeAtom::I64 => enc.text("i64"),
        TypeAtom::Text => enc.text("text"),
        TypeAtom::Bytes => enc.text("bytes"),
        TypeAtom::CanonicalCbor => enc.text("canonical_cbor"),
        TypeAtom::FixedBytes { len } => enc.array(2, |array| {
            array.value(&"fixed_bytes")?;
            array.value(&len)?;
            Ok(())
        }),
        TypeAtom::Named { type_id, version } => enc.array(3, |array| {
            array.value(&"named")?;
            array.value(&type_id)?;
            match version {
                Some(version) => array.value(&version)?,
                None => array.null()?,
            }
            Ok(())
        }),
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

/// Diff two static schemas and report directional compatibility.
#[must_use]
pub fn diff(old: &'static Schema, new: &'static Schema) -> CompatibilityReport {
    let mut changes = Vec::new();
    let mut direction = Directional::compatible();
    if old.type_id != new.type_id {
        direction.all_incompatible();
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
    compare_type_defs("root", old.root, new.root, &mut changes, &mut direction);
    CompatibilityReport {
        new_reads_old: direction.new_reads_old,
        old_reads_new: direction.old_reads_new,
        old_preserves_new: direction.old_preserves_new,
        bidirectional: direction.new_reads_old.and(direction.old_reads_new),
        changes,
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
    old: TypeDef,
    new: TypeDef,
    changes: &mut Vec<SchemaChange>,
    direction: &mut Directional,
) {
    match (old, new) {
        (TypeDef::Struct(old), TypeDef::Struct(new)) => {
            compare_field_sets(path, old, new, changes, direction);
        }
        (TypeDef::Enum(old), TypeDef::Enum(new)) => {
            compare_enums(path, old, new, changes, direction);
        }
        (TypeDef::Transparent { inner: old }, TypeDef::Transparent { inner: new })
        | (TypeDef::Primitive { ty: old }, TypeDef::Primitive { ty: new }) => {
            compare_type_ref(path, old, new, changes, direction);
        }
        _ => {
            direction.all_incompatible();
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
    old: FieldSetDef,
    new: FieldSetDef,
    changes: &mut Vec<SchemaChange>,
    direction: &mut Directional,
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
        old.fields,
        new.fields,
        old.unknown_fields,
        new.unknown_fields,
        changes,
        direction,
    );
}

fn compare_enums(
    path: &str,
    old: EnumDef,
    new: EnumDef,
    changes: &mut Vec<SchemaChange>,
    direction: &mut Directional,
) {
    if old.unknown_variants != new.unknown_variants {
        push_change(
            changes,
            &format!("{path}.unknown_variants"),
            SchemaChangeClass::WireCompatible,
            "unknown-variant policy changed",
        );
    }
    let mut old_index = 0usize;
    let mut new_index = 0usize;
    while old_index < old.variants.len() || new_index < new.variants.len() {
        match (old.variants.get(old_index), new.variants.get(new_index)) {
            (Some(old_variant), Some(new_variant)) if old_variant.id == new_variant.id => {
                let variant_path = format!("{path}.variant.{}", old_variant.id);
                if old_variant.name != new_variant.name {
                    push_change(
                        changes,
                        &format!("{variant_path}.name"),
                        SchemaChangeClass::MetadataOnly,
                        "variant name changed",
                    );
                }
                match (old_variant.payload, new_variant.payload) {
                    (VariantPayloadDef::Unit, VariantPayloadDef::Unit) => {}
                    (
                        VariantPayloadDef::Fields(old_fields),
                        VariantPayloadDef::Fields(new_fields),
                    ) => {
                        compare_field_sets(
                            &variant_path,
                            old_fields,
                            new_fields,
                            changes,
                            direction,
                        );
                    }
                    _ => {
                        direction.all_incompatible();
                        push_change(
                            changes,
                            &format!("{variant_path}.payload"),
                            SchemaChangeClass::WireIncompatible,
                            "variant payload shape changed",
                        );
                    }
                }
                old_index += 1;
                new_index += 1;
            }
            (Some(old_variant), Some(new_variant)) if old_variant.id < new_variant.id => {
                push_change(
                    changes,
                    &format!("{path}.variant.{}", old_variant.id),
                    SchemaChangeClass::WireIncompatible,
                    "variant removed",
                );
                if !new.unknown_variants.preserves() {
                    direction.new_reads_old = CompatibilityClass::Incompatible;
                }
                old_index += 1;
            }
            (Some(old_variant), None) => {
                push_change(
                    changes,
                    &format!("{path}.variant.{}", old_variant.id),
                    SchemaChangeClass::WireIncompatible,
                    "variant removed",
                );
                if !new.unknown_variants.preserves() {
                    direction.new_reads_old = CompatibilityClass::Incompatible;
                }
                old_index += 1;
            }
            (_, Some(new_variant)) => {
                push_change(
                    changes,
                    &format!("{path}.variant.{}", new_variant.id),
                    SchemaChangeClass::WireCompatible,
                    "variant added",
                );
                if !old.unknown_variants.preserves() {
                    direction.old_reads_new = CompatibilityClass::Incompatible;
                    direction.old_preserves_new = CompatibilityClass::Incompatible;
                }
                new_index += 1;
            }
            (None, None) => break,
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
    direction: &mut Directional,
) {
    let mut old_index = 0usize;
    let mut new_index = 0usize;
    while old_index < old_fields.len() || new_index < new_fields.len() {
        match (old_fields.get(old_index), new_fields.get(new_index)) {
            (Some(old), Some(new)) if old.id == new.id => {
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
                    direction.all_incompatible();
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
                            direction.old_reads_new = CompatibilityClass::Incompatible;
                            direction.old_preserves_new = CompatibilityClass::Incompatible;
                        }
                        (FieldPresence::Optional, FieldPresence::Required) => {
                            direction.new_reads_old = CompatibilityClass::Incompatible;
                        }
                        _ => {}
                    }
                }
                old_index += 1;
                new_index += 1;
            }
            (Some(old), Some(new)) if old.id < new.id => {
                push_change(
                    changes,
                    &format!("{path}.field.{}", old.id),
                    SchemaChangeClass::WireIncompatible,
                    "field removed",
                );
                if !new_unknown.accepts() {
                    direction.new_reads_old = CompatibilityClass::Incompatible;
                }
                if matches!(old.presence, FieldPresence::Required) {
                    direction.old_reads_new = CompatibilityClass::Incompatible;
                    direction.old_preserves_new = CompatibilityClass::Incompatible;
                }
                old_index += 1;
            }
            (Some(old), None) => {
                push_change(
                    changes,
                    &format!("{path}.field.{}", old.id),
                    SchemaChangeClass::WireIncompatible,
                    "field removed",
                );
                if !new_unknown.accepts() {
                    direction.new_reads_old = CompatibilityClass::Incompatible;
                }
                if matches!(old.presence, FieldPresence::Required) {
                    direction.old_reads_new = CompatibilityClass::Incompatible;
                    direction.old_preserves_new = CompatibilityClass::Incompatible;
                }
                old_index += 1;
            }
            (_, Some(new)) => {
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
                    direction.new_reads_old = CompatibilityClass::Incompatible;
                }
                if !old_unknown.accepts() {
                    direction.old_reads_new = CompatibilityClass::Incompatible;
                }
                if !old_unknown.preserves() {
                    direction.old_preserves_new = CompatibilityClass::Incompatible;
                }
                new_index += 1;
            }
            (None, None) => break,
        }
    }
}

fn compare_type_ref(
    path: &str,
    old: TypeRef,
    new: TypeRef,
    changes: &mut Vec<SchemaChange>,
    direction: &mut Directional,
) {
    if old != new {
        direction.all_incompatible();
        push_change(
            changes,
            path,
            SchemaChangeClass::WireIncompatible,
            "type reference changed",
        );
    }
}
