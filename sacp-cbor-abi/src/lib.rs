//! Stable ABI schema and codegen support for `sacp-cbor`.
//!
//! This crate is intentionally separate from `CborEncode` / `CborDecode` derives. Normal derives
//! describe Rust shape. `CborAbi` describes a public wire contract with numeric field and variant
//! identities, schema hashes, and mechanical compatibility checks.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use sacp_cbor::{
    CanonicalCbor, CborDecode, CborEncode, CborError, DecodeLimits, Decoder, Encoder, ErrorCode,
};
use sha2::{Digest, Sha256};

#[cfg(feature = "derive")]
pub use sacp_cbor_abi_derive::CborAbi;

/// Private support items used by generated code.
#[doc(hidden)]
pub mod __private {
    pub use alloc::{string::String, vec, vec::Vec};
    pub use sacp_cbor;
}

/// Encode a public ABI value.
pub trait AbiEncode {
    /// Encode `self` into canonical SACP-CBOR bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    fn abi_encode(&self, enc: &mut Encoder) -> Result<(), CborError>;
}

/// Decode a public ABI value.
pub trait AbiDecode<'de>: Sized {
    /// Decode `Self` from a streaming decoder.
    ///
    /// # Errors
    ///
    /// Returns an error if the input does not match the ABI schema.
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
    ) -> Result<Self, CborError>;
}

/// Exposes the public ABI schema for a type.
pub trait AbiType {
    /// Return this type's schema.
    #[must_use]
    fn schema() -> Schema;
}

/// Current stable ABI schema profile.
pub const ABI_PROFILE: &str = "SACP-CBOR-ABI/1";

/// Unknown field handling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownFieldPolicy {
    /// Reject unknown fields.
    Reject,
    /// Ignore unknown fields.
    Ignore,
}

impl UnknownFieldPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Ignore => "ignore",
        }
    }
}

/// A complete public ABI schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schema {
    /// ABI profile.
    pub profile: String,
    /// Stable type identity.
    pub type_id: String,
    /// Schema version.
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

    /// Canonical SACP-CBOR encoding of the schema normal form.
    ///
    /// # Errors
    ///
    /// Returns an error if schema encoding fails.
    pub fn canonical_bytes(&self) -> Result<CanonicalCbor, CborError> {
        let mut enc = Encoder::new();
        encode_schema(self, &mut enc)?;
        enc.finish()
    }

    /// SHA-256 over the canonical schema normal form.
    ///
    /// # Errors
    ///
    /// Returns an error if schema encoding fails.
    pub fn hash(&self) -> Result<SchemaHash, CborError> {
        schema_hash(self)
    }
}

/// A public ABI type definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeDef {
    /// Struct field-set.
    Struct {
        /// Public fields.
        fields: Vec<FieldDef>,
        /// Unknown field policy.
        unknown_fields: UnknownFieldPolicy,
    },
    /// Enum discriminant plus payload.
    Enum {
        /// Public variants.
        variants: Vec<VariantDef>,
        /// Unknown field policy for struct variant payloads.
        unknown_fields: UnknownFieldPolicy,
    },
    /// Primitive or externally-defined field type.
    Primitive {
        /// Stable display name.
        name: String,
    },
}

/// A public field definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDef {
    /// Stable numeric field ID. Must be nonzero.
    pub id: u32,
    /// Rust/source field name for diagnostics.
    pub name: String,
    /// Field type name.
    pub ty: String,
    /// Whether this field is optional and omitted when absent.
    pub optional: bool,
}

/// A public enum variant definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantDef {
    /// Stable numeric variant ID. Must be nonzero.
    pub id: u32,
    /// Rust/source variant name for diagnostics.
    pub name: String,
    /// Struct payload fields. Empty means unit payload.
    pub fields: Vec<FieldDef>,
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

/// Compatibility policy for schema diffs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatibilityPolicy {
    /// Allow adding optional struct fields.
    pub allow_optional_field_additions: bool,
    /// Allow adding enum variants.
    pub allow_variant_additions: bool,
}

impl Default for CompatibilityPolicy {
    fn default() -> Self {
        Self {
            allow_optional_field_additions: true,
            allow_variant_additions: false,
        }
    }
}

/// Top-level compatibility class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatibilityClass {
    /// Existing decoders remain compatible under the policy.
    Compatible,
    /// Existing decoders are not compatible.
    Incompatible,
}

/// Compatibility report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityReport {
    /// Overall class.
    pub class: CompatibilityClass,
    /// Human-readable change descriptions.
    pub changes: Vec<String>,
}

impl CompatibilityReport {
    /// Whether the report is compatible.
    #[must_use]
    pub const fn is_compatible(&self) -> bool {
        matches!(self.class, CompatibilityClass::Compatible)
    }
}

/// Encode an ABI value to owned canonical CBOR.
///
/// # Errors
///
/// Returns an error if encoding fails.
pub fn encode_to_canonical<T: AbiEncode>(value: &T) -> Result<CanonicalCbor, CborError> {
    let mut enc = Encoder::new();
    value.abi_encode(&mut enc)?;
    enc.finish()
}

/// Encode an ABI value to a vector of canonical bytes.
///
/// # Errors
///
/// Returns an error if encoding fails.
pub fn encode_to_vec<T: AbiEncode>(value: &T) -> Result<Vec<u8>, CborError> {
    Ok(encode_to_canonical(value)?.into_bytes())
}

/// Validate and decode an ABI value.
///
/// # Errors
///
/// Returns an error if validation or decoding fails.
pub fn decode<'de, T: AbiDecode<'de>>(
    bytes: &'de [u8],
    limits: DecodeLimits,
) -> Result<T, CborError> {
    let mut decoder = Decoder::<true>::new_checked(bytes, limits)?;
    let value = T::abi_decode(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(CborError::new(ErrorCode::TrailingBytes, decoder.position()));
    }
    Ok(value)
}

/// SHA-256 over the canonical schema normal form.
///
/// # Errors
///
/// Returns an error if schema encoding fails.
pub fn schema_hash(schema: &Schema) -> Result<SchemaHash, CborError> {
    let canon = schema.canonical_bytes()?;
    let mut hasher = Sha256::new();
    hasher.update(canon.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(SchemaHash(out))
}

/// Diff two schemas using the default compatibility policy.
#[must_use]
pub fn diff(old: &Schema, new: &Schema) -> CompatibilityReport {
    diff_with_policy(old, new, CompatibilityPolicy::default())
}

/// Diff two schemas using an explicit compatibility policy.
#[must_use]
pub fn diff_with_policy(
    old: &Schema,
    new: &Schema,
    policy: CompatibilityPolicy,
) -> CompatibilityReport {
    let mut changes = Vec::new();
    let mut incompatible = false;

    if old.profile != new.profile {
        incompatible = true;
        changes.push("ABI profile changed".to_string());
    }
    if old.type_id != new.type_id {
        incompatible = true;
        changes.push("type ID changed".to_string());
    }
    if new.version < old.version {
        incompatible = true;
        changes.push("schema version decreased".to_string());
    }

    compare_type_defs(
        "root",
        &old.root,
        &new.root,
        policy,
        &mut changes,
        &mut incompatible,
    );

    CompatibilityReport {
        class: if incompatible {
            CompatibilityClass::Incompatible
        } else {
            CompatibilityClass::Compatible
        },
        changes,
    }
}

fn compare_type_defs(
    path: &str,
    old: &TypeDef,
    new: &TypeDef,
    policy: CompatibilityPolicy,
    changes: &mut Vec<String>,
    incompatible: &mut bool,
) {
    match (old, new) {
        (
            TypeDef::Struct {
                fields: old_fields,
                unknown_fields: old_unknown,
            },
            TypeDef::Struct {
                fields: new_fields,
                unknown_fields: new_unknown,
            },
        ) => {
            if old_unknown != new_unknown {
                *incompatible = true;
                changes.push(format!("{path} unknown-field policy changed"));
            }
            compare_fields(path, old_fields, new_fields, policy, changes, incompatible);
        }
        (
            TypeDef::Enum {
                variants: old_variants,
                unknown_fields: old_unknown,
            },
            TypeDef::Enum {
                variants: new_variants,
                unknown_fields: new_unknown,
            },
        ) => {
            if old_unknown != new_unknown {
                *incompatible = true;
                changes.push(format!("{path} unknown-field policy changed"));
            }
            compare_variants(
                path,
                old_variants,
                new_variants,
                policy,
                changes,
                incompatible,
            );
        }
        (TypeDef::Primitive { name: old_name }, TypeDef::Primitive { name: new_name }) => {
            if old_name != new_name {
                *incompatible = true;
                changes.push(format!("{path} primitive type changed"));
            }
        }
        _ => {
            *incompatible = true;
            changes.push(format!("{path} kind changed"));
        }
    }
}

fn compare_fields(
    path: &str,
    old_fields: &[FieldDef],
    new_fields: &[FieldDef],
    policy: CompatibilityPolicy,
    changes: &mut Vec<String>,
    incompatible: &mut bool,
) {
    for old in old_fields {
        match new_fields.iter().find(|field| field.id == old.id) {
            Some(new) => {
                if old.ty != new.ty {
                    *incompatible = true;
                    changes.push(format!("{path} field {} type changed", old.id));
                }
                if old.optional != new.optional {
                    *incompatible = true;
                    changes.push(format!("{path} field {} optionality changed", old.id));
                }
            }
            None => {
                *incompatible = true;
                changes.push(format!("{path} field {} removed", old.id));
            }
        }
    }
    for new in new_fields {
        if old_fields.iter().all(|field| field.id != new.id) {
            changes.push(format!("{path} field {} added", new.id));
            if !(new.optional && policy.allow_optional_field_additions) {
                *incompatible = true;
            }
        }
    }
}

fn compare_variants(
    path: &str,
    old_variants: &[VariantDef],
    new_variants: &[VariantDef],
    policy: CompatibilityPolicy,
    changes: &mut Vec<String>,
    incompatible: &mut bool,
) {
    for old in old_variants {
        match new_variants.iter().find(|variant| variant.id == old.id) {
            Some(new) => {
                compare_fields(
                    &format!("{path} variant {}", old.id),
                    &old.fields,
                    &new.fields,
                    policy,
                    changes,
                    incompatible,
                );
            }
            None => {
                *incompatible = true;
                changes.push(format!("{path} variant {} removed", old.id));
            }
        }
    }
    for new in new_variants {
        if old_variants.iter().all(|variant| variant.id != new.id) {
            changes.push(format!("{path} variant {} added", new.id));
            if !policy.allow_variant_additions {
                *incompatible = true;
            }
        }
    }
}

fn encode_schema(schema: &Schema, enc: &mut Encoder) -> Result<(), CborError> {
    enc.array(4, |array| {
        encode_item(array, &schema.profile)?;
        encode_item(array, &schema.type_id)?;
        encode_item(array, &schema.version)?;
        array.value_with(|enc| encode_type_def(&schema.root, enc))?;
        Ok(())
    })
}

fn encode_type_def(def: &TypeDef, enc: &mut Encoder) -> Result<(), CborError> {
    match def {
        TypeDef::Struct {
            fields,
            unknown_fields,
        } => enc.array(3, |array| {
            encode_item(array, &"struct")?;
            encode_item(array, &unknown_fields.as_str())?;
            encode_fields(array, fields)?;
            Ok(())
        }),
        TypeDef::Enum {
            variants,
            unknown_fields,
        } => enc.array(3, |array| {
            encode_item(array, &"enum")?;
            encode_item(array, &unknown_fields.as_str())?;
            array.value_with(|enc| {
                let mut variants: Vec<&VariantDef> = variants.iter().collect();
                variants.sort_by_key(|variant| variant.id);
                enc.array(variants.len(), |array| {
                    for variant in variants {
                        array.value_with(|enc| encode_variant(variant, enc))?;
                    }
                    Ok(())
                })
            })?;
            Ok(())
        }),
        TypeDef::Primitive { name } => enc.array(2, |array| {
            encode_item(array, &"primitive")?;
            encode_item(array, name)?;
            Ok(())
        }),
    }
}

fn encode_fields(
    array: &mut sacp_cbor::encode::ArrayEncoder<'_>,
    fields: &[FieldDef],
) -> Result<(), CborError> {
    array.value_with(|enc| {
        let mut fields: Vec<&FieldDef> = fields.iter().collect();
        fields.sort_by_key(|field| field.id);
        enc.array(fields.len(), |array| {
            for field in fields {
                array.value_with(|enc| encode_field(field, enc))?;
            }
            Ok(())
        })
    })
}

fn encode_field(field: &FieldDef, enc: &mut Encoder) -> Result<(), CborError> {
    enc.array(4, |array| {
        encode_item(array, &field.id)?;
        encode_item(array, &field.name)?;
        encode_item(array, &field.ty)?;
        encode_item(array, &field.optional)?;
        Ok(())
    })
}

fn encode_variant(variant: &VariantDef, enc: &mut Encoder) -> Result<(), CborError> {
    enc.array(3, |array| {
        encode_item(array, &variant.id)?;
        encode_item(array, &variant.name)?;
        encode_fields(array, &variant.fields)?;
        Ok(())
    })
}

fn encode_item<T: CborEncode + ?Sized>(
    array: &mut sacp_cbor::encode::ArrayEncoder<'_>,
    value: &T,
) -> Result<(), CborError> {
    array.value_with(|enc| value.encode(enc))
}

macro_rules! passthrough_abi {
    ($($ty:ty),* $(,)?) => {
        $(
            impl AbiEncode for $ty {
                fn abi_encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
                    CborEncode::encode(self, enc)
                }
            }

            impl<'de> AbiDecode<'de> for $ty {
                fn abi_decode<const CHECKED: bool>(
                    decoder: &mut Decoder<'de, CHECKED>,
                ) -> Result<Self, CborError> {
                    CborDecode::decode(decoder)
                }
            }
        )*
    };
}

passthrough_abi!((), bool, u8, u16, u32, u64, i8, i16, i32, i64, String);

impl AbiEncode for &str {
    fn abi_encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        CborEncode::encode(self, enc)
    }
}

impl<'de> AbiDecode<'de> for &'de str {
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
    ) -> Result<Self, CborError> {
        CborDecode::decode(decoder)
    }
}

impl<T: AbiEncode> AbiEncode for Vec<T> {
    fn abi_encode(&self, enc: &mut Encoder) -> Result<(), CborError> {
        enc.array(self.len(), |array| {
            for value in self {
                array.value_with(|enc| value.abi_encode(enc))?;
            }
            Ok(())
        })
    }
}

impl<'de, T: AbiDecode<'de>> AbiDecode<'de> for Vec<T> {
    fn abi_decode<const CHECKED: bool>(
        decoder: &mut Decoder<'de, CHECKED>,
    ) -> Result<Self, CborError> {
        let mut array = decoder.array()?;
        let mut out = Vec::new();
        while let Some(value) = array.decode_next(AbiDecode::abi_decode)? {
            out.push(value);
        }
        Ok(out)
    }
}
