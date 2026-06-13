use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use sacp_cbor::query::CborValueRef;
use sacp_cbor::{CborError, ErrorCode};

use crate::{
    AbiFieldEntryRef, AbiFieldSetRef, FieldDef, FieldPresence, FieldSetDef, Schema, TypeDef,
    TypeRef, UnknownFieldPolicy, UnknownFieldRef,
};

const DEFAULT_RECURSION_DEPTH: usize = 32;
const SMALL_REQUIRED_BITS: usize = 128;

/// Resolves named ABI schemas for runtime validation.
pub trait AbiSchemaRegistry {
    /// Resolve a named ABI type reference to a schema.
    fn resolve(&self, type_id: &str, version: Option<u32>) -> Option<&Schema>;
}

/// Runtime ABI type-validation policy.
#[derive(Clone, Copy)]
pub enum RuntimeTypeValidation<'r> {
    /// Validate only field-set shell rules, required fields, and unknown-field policy.
    ShellOnly,
    /// Validate inline primitive/container types while treating named types as opaque.
    InlineOnly,
    /// Resolve and recursively validate named types through a caller-provided registry.
    ResolveNamed(&'r dyn AbiSchemaRegistry),
    /// Reject named types during deep validation.
    RejectNamed,
}

/// Options for runtime ABI validation.
#[derive(Clone, Copy)]
pub struct RuntimeAbiOptions<'r> {
    /// Type-validation mode.
    pub type_validation: RuntimeTypeValidation<'r>,
    /// Maximum nested type/schema recursion depth.
    pub max_recursion_depth: usize,
}

impl Default for RuntimeAbiOptions<'_> {
    fn default() -> Self {
        Self {
            type_validation: RuntimeTypeValidation::ShellOnly,
            max_recursion_depth: DEFAULT_RECURSION_DEPTH,
        }
    }
}

/// Runtime ABI validation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeAbiError {
    /// CBOR or ABI value validation failed.
    Cbor(CborError),
    /// Runtime schema is invalid.
    InvalidSchema {
        /// Static reason for the invalid schema.
        reason: &'static str,
    },
    /// Root type is not supported by the v1 runtime validator.
    UnsupportedRoot,
    /// A named type was rejected or could not be resolved.
    UnresolvedNamedType,
    /// Recursive validation exceeded the configured depth.
    RecursionLimit,
}

impl From<CborError> for RuntimeAbiError {
    fn from(err: CborError) -> Self {
        Self::Cbor(err)
    }
}

impl fmt::Display for RuntimeAbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(err) => err.fmt(f),
            Self::InvalidSchema { reason } => write!(f, "invalid runtime ABI schema: {reason}"),
            Self::UnsupportedRoot => write!(f, "unsupported runtime ABI schema root"),
            Self::UnresolvedNamedType => write!(f, "unresolved runtime ABI named type"),
            Self::RecursionLimit => write!(f, "runtime ABI recursion limit exceeded"),
        }
    }
}

/// One compiled runtime field entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFieldInfo<'s> {
    /// Stable numeric field ID.
    pub id: u32,
    /// Source field definition.
    pub def: &'s FieldDef,
    /// Compact required-field bit index, if this field is required.
    pub required_index: Option<usize>,
}

/// Compiled runtime field-set schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeFieldSetSchema<'s> {
    def: &'s FieldSetDef,
    fields: Box<[RuntimeFieldInfo<'s>]>,
    known_ids: Box<[u32]>,
    required_count: usize,
}

/// Borrowed runtime field-set view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFieldSetView<'a, 's> {
    raw: AbiFieldSetRef<'a>,
    schema: &'s RuntimeFieldSetSchema<'s>,
}

/// One borrowed runtime field reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFieldRef<'a, 's> {
    /// Stable numeric field ID.
    pub id: u32,
    /// Known field definition, or `None` for accepted unknown fields.
    pub def: Option<&'s FieldDef>,
    /// Borrowed canonical field value.
    pub value: CborValueRef<'a>,
}

/// Compiled runtime schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeSchema<'s> {
    /// Struct field-set runtime schema.
    Struct(RuntimeFieldSetSchema<'s>),
}

/// Compile a runtime schema root.
///
/// V1 supports only `TypeDef::Struct` roots.
pub fn compile_runtime_schema(schema: &Schema) -> Result<RuntimeSchema<'_>, RuntimeAbiError> {
    match &schema.root {
        TypeDef::Struct(def) => Ok(RuntimeSchema::Struct(RuntimeFieldSetSchema::compile(def)?)),
        TypeDef::Enum(_) | TypeDef::Transparent { .. } | TypeDef::Primitive { .. } => {
            Err(RuntimeAbiError::UnsupportedRoot)
        }
    }
}

impl<'s> RuntimeFieldSetSchema<'s> {
    /// Compile and validate a runtime field-set definition.
    pub fn compile(def: &'s FieldSetDef) -> Result<Self, RuntimeAbiError> {
        let mut fields = Vec::new();
        fields
            .try_reserve_exact(def.fields.len())
            .map_err(|_| RuntimeAbiError::from(CborError::new(ErrorCode::AllocationFailed, 0)))?;

        for field in &def.fields {
            if field.id == 0 {
                return Err(RuntimeAbiError::InvalidSchema {
                    reason: "field ID must be nonzero",
                });
            }
            fields.push(RuntimeFieldInfo {
                id: field.id,
                def: field,
                required_index: None,
            });
        }

        fields.sort_by_key(|field| field.id);
        let mut known_ids = Vec::new();
        known_ids
            .try_reserve_exact(fields.len())
            .map_err(|_| RuntimeAbiError::from(CborError::new(ErrorCode::AllocationFailed, 0)))?;
        known_ids.extend(fields.iter().map(|field| field.id));
        validate_sorted_schema_ids(&known_ids)?;

        let mut required_count = 0usize;
        for field in &mut fields {
            if matches!(field.def.presence, FieldPresence::Required) {
                field.required_index = Some(required_count);
                required_count =
                    required_count
                        .checked_add(1)
                        .ok_or(RuntimeAbiError::InvalidSchema {
                            reason: "too many required fields",
                        })?;
            }
        }

        Ok(Self {
            def,
            fields: fields.into_boxed_slice(),
            known_ids: known_ids.into_boxed_slice(),
            required_count,
        })
    }

    /// Return the source field-set definition.
    #[must_use]
    pub const fn def(&self) -> &'s FieldSetDef {
        self.def
    }

    /// Return compiled field metadata sorted by numeric field ID.
    #[must_use]
    pub fn fields(&self) -> &[RuntimeFieldInfo<'s>] {
        &self.fields
    }

    /// Return sorted known field IDs.
    #[must_use]
    pub fn known_ids(&self) -> &[u32] {
        &self.known_ids
    }

    /// Return the number of required fields.
    #[must_use]
    pub const fn required_count(&self) -> usize {
        self.required_count
    }

    /// Validate only the ABI shell, required fields, and unknown-field policy.
    pub fn view_value<'a>(
        &'s self,
        value: CborValueRef<'a>,
    ) -> Result<RuntimeFieldSetView<'a, 's>, RuntimeAbiError> {
        self.validate_value_inner(value, &RuntimeAbiOptions::default(), 0)
    }

    /// Validate a field-set value using the supplied runtime options.
    pub fn validate_value<'a>(
        &'s self,
        value: CborValueRef<'a>,
        options: &RuntimeAbiOptions<'_>,
    ) -> Result<RuntimeFieldSetView<'a, 's>, RuntimeAbiError> {
        self.validate_value_inner(value, options, 0)
    }

    fn validate_value_inner<'a>(
        &'s self,
        value: CborValueRef<'a>,
        options: &RuntimeAbiOptions<'_>,
        depth: usize,
    ) -> Result<RuntimeFieldSetView<'a, 's>, RuntimeAbiError> {
        let mut required = RequiredSeen::new(self.required_count)?;
        let mut runtime_error = None;
        let mut field_cursor = 0usize;
        let raw = match AbiFieldSetRef::scan(value, |entry| {
            match self.validate_entry(entry, options, depth, &mut required, &mut field_cursor) {
                Ok(()) => Ok(()),
                Err(RuntimeAbiError::Cbor(err)) => Err(err),
                Err(err) => {
                    runtime_error = Some(err);
                    Err(CborError::new(
                        ErrorCode::InvalidAbiValue,
                        entry.value.offset(),
                    ))
                }
            }
        }) {
            Ok(raw) => raw,
            Err(err) => {
                if let Some(err) = runtime_error {
                    return Err(err);
                }
                return Err(err.into());
            }
        };

        if !required.all_seen(self.required_count) {
            return Err(CborError::new(ErrorCode::MissingKey, value.offset()).into());
        }

        Ok(RuntimeFieldSetView { raw, schema: self })
    }

    fn validate_entry<'a>(
        &'s self,
        entry: AbiFieldEntryRef<'a>,
        options: &RuntimeAbiOptions<'_>,
        depth: usize,
        required: &mut RequiredSeen,
        field_cursor: &mut usize,
    ) -> Result<(), RuntimeAbiError> {
        while *field_cursor < self.fields.len() && self.fields[*field_cursor].id < entry.id {
            *field_cursor += 1;
        }

        match self.field_info_at_cursor(entry.id, *field_cursor) {
            Some(info) => {
                if let Some(index) = info.required_index {
                    required.mark(index);
                }
                if !matches!(options.type_validation, RuntimeTypeValidation::ShellOnly) {
                    validate_type_ref(&info.def.ty, entry.value, options, depth)?;
                }
                Ok(())
            }
            None if self.def.unknown_fields == UnknownFieldPolicy::Reject => {
                Err(CborError::new(ErrorCode::UnknownField, entry.id_offset).into())
            }
            None => Ok(()),
        }
    }

    fn field_info(&self, id: u32) -> Option<RuntimeFieldInfo<'s>> {
        self.fields
            .binary_search_by_key(&id, |field| field.id)
            .ok()
            .map(|index| self.fields[index])
    }

    fn field_info_at_cursor(&self, id: u32, cursor: usize) -> Option<RuntimeFieldInfo<'s>> {
        self.fields
            .get(cursor)
            .copied()
            .filter(|field| field.id == id)
    }
}

impl<'a, 's> RuntimeFieldSetView<'a, 's> {
    /// Return the raw field-set array value.
    #[must_use]
    pub fn raw_value(&self) -> CborValueRef<'a> {
        self.raw.raw_value()
    }

    /// Return the validated raw field-set witness.
    #[must_use]
    pub const fn raw_fields(&self) -> AbiFieldSetRef<'a> {
        self.raw
    }

    /// Return the compiled schema backing this view.
    #[must_use]
    pub const fn schema(&self) -> &'s RuntimeFieldSetSchema<'s> {
        self.schema
    }

    /// Return one raw field by numeric ID.
    pub fn get_raw(&self, id: u32) -> Result<Option<CborValueRef<'a>>, CborError> {
        self.raw.get(id)
    }

    /// Return one required raw field by numeric ID.
    pub fn require_raw(&self, id: u32) -> Result<CborValueRef<'a>, CborError> {
        self.raw.require(id)
    }

    /// Fill `out` with raw fields for sorted numeric IDs in one scan.
    pub fn get_many_raw_sorted_into(
        &self,
        ids: &[u32],
        out: &mut [Option<CborValueRef<'a>>],
    ) -> Result<(), CborError> {
        self.raw.get_many_sorted_into(ids, out)
    }

    /// Return one raw field after validating its known runtime type.
    ///
    /// Accepted unknown fields have no type definition and are returned without deep validation.
    pub fn get_checked(
        &self,
        id: u32,
        options: &RuntimeAbiOptions<'_>,
    ) -> Result<Option<CborValueRef<'a>>, RuntimeAbiError> {
        let Some(value) = self.raw.get(id)? else {
            return Ok(None);
        };
        if let Some(info) = self.schema.field_info(id) {
            validate_type_ref(&info.def.ty, value, options, 0)?;
        }
        Ok(Some(value))
    }

    /// Iterate over runtime fields in field-ID order.
    pub fn iter(
        &self,
    ) -> Result<impl Iterator<Item = Result<RuntimeFieldRef<'a, 's>, CborError>> + 'a, CborError>
    where
        's: 'a,
    {
        let schema = self.schema;
        let mut field_cursor = 0usize;
        Ok(self.raw.iter()?.map(move |entry| {
            entry.map(|entry| {
                while field_cursor < schema.fields.len()
                    && schema.fields[field_cursor].id < entry.id
                {
                    field_cursor += 1;
                }
                RuntimeFieldRef {
                    id: entry.id,
                    def: schema
                        .field_info_at_cursor(entry.id, field_cursor)
                        .map(|info| info.def),
                    value: entry.value,
                }
            })
        }))
    }

    /// Iterate over borrowed preserved unknown fields.
    ///
    /// Schemas with `Reject` cannot contain unknown fields after view construction. Schemas with
    /// `Ignore` intentionally expose no unknown preservation view.
    pub fn unknown_fields(
        &self,
    ) -> Result<impl Iterator<Item = Result<UnknownFieldRef<'a>, CborError>> + 'a, CborError>
    where
        's: 'a,
    {
        let schema = self.schema;
        let preserve = schema.def.unknown_fields == UnknownFieldPolicy::Preserve;
        let mut field_cursor = 0usize;
        Ok(self.raw.iter()?.filter_map(move |entry| {
            if !preserve {
                return None;
            }
            match entry {
                Ok(entry) => {
                    while field_cursor < schema.fields.len()
                        && schema.fields[field_cursor].id < entry.id
                    {
                        field_cursor += 1;
                    }
                    if schema
                        .field_info_at_cursor(entry.id, field_cursor)
                        .is_some()
                    {
                        None
                    } else {
                        Some(Ok(UnknownFieldRef {
                            id: entry.id,
                            value: entry.value,
                        }))
                    }
                }
                Err(err) => Some(Err(err)),
            }
        }))
    }
}

fn validate_type_def(
    def: &TypeDef,
    value: CborValueRef<'_>,
    options: &RuntimeAbiOptions<'_>,
    depth: usize,
) -> Result<(), RuntimeAbiError> {
    match def {
        TypeDef::Struct(field_set) => {
            let schema = RuntimeFieldSetSchema::compile(field_set)?;
            schema.validate_value_inner(value, options, depth)?;
            Ok(())
        }
        TypeDef::Transparent { inner } => validate_type_ref(inner, value, options, depth),
        TypeDef::Primitive { ty } => validate_type_ref(ty, value, options, depth),
        TypeDef::Enum(_) => Err(RuntimeAbiError::UnsupportedRoot),
    }
}

fn validate_type_ref(
    ty: &TypeRef,
    value: CborValueRef<'_>,
    options: &RuntimeAbiOptions<'_>,
    depth: usize,
) -> Result<(), RuntimeAbiError> {
    match ty {
        TypeRef::Unit => {
            if value.is_null() {
                Ok(())
            } else {
                Err(CborError::new(ErrorCode::ExpectedNull, value.offset()).into())
            }
        }
        TypeRef::Bool => value.bool().map(|_| ()).map_err(Into::into),
        TypeRef::U8 => validate_unsigned(value, u8::MAX as u128),
        TypeRef::U16 => validate_unsigned(value, u16::MAX as u128),
        TypeRef::U32 => validate_unsigned(value, u32::MAX as u128),
        TypeRef::U64 => validate_unsigned(value, u64::MAX as u128),
        TypeRef::I8 => validate_signed(value, i8::MIN as i128, i8::MAX as i128),
        TypeRef::I16 => validate_signed(value, i16::MIN as i128, i16::MAX as i128),
        TypeRef::I32 => validate_signed(value, i32::MIN as i128, i32::MAX as i128),
        TypeRef::I64 => validate_signed(value, i64::MIN as i128, i64::MAX as i128),
        TypeRef::Text => value.text().map(|_| ()).map_err(Into::into),
        TypeRef::Bytes => value.bytes().map(|_| ()).map_err(Into::into),
        TypeRef::FixedBytes { len } => {
            let bytes = value.bytes()?;
            if bytes.len() == *len as usize {
                Ok(())
            } else {
                Err(CborError::new(ErrorCode::ExpectedBytes, value.offset()).into())
            }
        }
        TypeRef::Vec { item } => {
            let array = value.array()?;
            for item_value in array.iter() {
                validate_type_ref(item, item_value?, options, enter_nested(depth, options)?)?;
            }
            Ok(())
        }
        TypeRef::CanonicalCbor => Ok(()),
        TypeRef::Named { type_id, version } => match options.type_validation {
            RuntimeTypeValidation::ShellOnly | RuntimeTypeValidation::InlineOnly => Ok(()),
            RuntimeTypeValidation::RejectNamed => Err(RuntimeAbiError::UnresolvedNamedType),
            RuntimeTypeValidation::ResolveNamed(registry) => {
                let next_depth = enter_nested(depth, options)?;
                let schema = registry
                    .resolve(type_id, *version)
                    .ok_or(RuntimeAbiError::UnresolvedNamedType)?;
                validate_type_def(&schema.root, value, options, next_depth)
            }
        },
    }
}

fn validate_unsigned(value: CborValueRef<'_>, max: u128) -> Result<(), RuntimeAbiError> {
    let offset = value.offset();
    let value = value
        .integer()?
        .as_u128()
        .ok_or_else(|| CborError::new(ErrorCode::ExpectedInteger, offset))?;
    if value <= max {
        Ok(())
    } else {
        Err(CborError::new(ErrorCode::ExpectedInteger, offset).into())
    }
}

fn validate_signed(value: CborValueRef<'_>, min: i128, max: i128) -> Result<(), RuntimeAbiError> {
    let offset = value.offset();
    let value = value
        .integer()?
        .as_i128()
        .ok_or_else(|| CborError::new(ErrorCode::ExpectedInteger, offset))?;
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(CborError::new(ErrorCode::ExpectedInteger, offset).into())
    }
}

fn enter_nested(depth: usize, options: &RuntimeAbiOptions<'_>) -> Result<usize, RuntimeAbiError> {
    if depth >= options.max_recursion_depth {
        return Err(RuntimeAbiError::RecursionLimit);
    }
    depth.checked_add(1).ok_or(RuntimeAbiError::RecursionLimit)
}

pub(crate) fn validate_sorted_schema_ids(ids: &[u32]) -> Result<(), RuntimeAbiError> {
    let mut prev = None;
    for id in ids {
        if *id == 0 {
            return Err(RuntimeAbiError::InvalidSchema {
                reason: "field ID must be nonzero",
            });
        }
        if prev.is_some_and(|prev_id| *id <= prev_id) {
            return Err(RuntimeAbiError::InvalidSchema {
                reason: "duplicate field ID",
            });
        }
        prev = Some(*id);
    }
    Ok(())
}

pub(crate) enum RequiredSeen {
    Small(u128),
    Large(Vec<u64>),
}

impl RequiredSeen {
    pub(crate) fn new(required_count: usize) -> Result<Self, RuntimeAbiError> {
        if required_count <= SMALL_REQUIRED_BITS {
            Ok(Self::Small(0))
        } else {
            let word_count =
                required_count
                    .checked_add(63)
                    .ok_or(RuntimeAbiError::InvalidSchema {
                        reason: "too many required fields",
                    })?
                    / 64;
            let mut words = Vec::new();
            words.try_reserve_exact(word_count).map_err(|_| {
                RuntimeAbiError::from(CborError::new(ErrorCode::AllocationFailed, 0))
            })?;
            words.resize(word_count, 0);
            Ok(Self::Large(words))
        }
    }

    pub(crate) fn mark(&mut self, index: usize) {
        match self {
            Self::Small(bits) => {
                *bits |= 1u128 << index;
            }
            Self::Large(words) => {
                let word = index / 64;
                let bit = index % 64;
                if let Some(slot) = words.get_mut(word) {
                    *slot |= 1u64 << bit;
                }
            }
        }
    }

    pub(crate) fn all_seen(&self, required_count: usize) -> bool {
        match self {
            Self::Small(bits) => {
                if required_count == 0 {
                    true
                } else if required_count == SMALL_REQUIRED_BITS {
                    *bits == u128::MAX
                } else {
                    let mask = (1u128 << required_count) - 1;
                    (*bits & mask) == mask
                }
            }
            Self::Large(words) => {
                if required_count == 0 {
                    return true;
                }
                let full_words = required_count / 64;
                let remainder = required_count % 64;
                for word in &words[..full_words] {
                    if *word != u64::MAX {
                        return false;
                    }
                }
                if remainder == 0 {
                    true
                } else {
                    let mask = (1u64 << remainder) - 1;
                    words
                        .get(full_words)
                        .is_some_and(|word| (*word & mask) == mask)
                }
            }
        }
    }
}
