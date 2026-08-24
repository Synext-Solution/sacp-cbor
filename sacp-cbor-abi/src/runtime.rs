use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;
use core::mem::MaybeUninit;

use sacp_cbor::query::{ArrayIter, CborValueRef};
use sacp_cbor::{CborError, ErrorCode};

use crate::{
    view::AbiFieldSetIter, AbiFieldEntryRef, AbiFieldSetRef, EnumDef, FieldDef, FieldPresence,
    FieldSetDef, Schema, TypeDef, TypeRef, UnknownFieldPolicy, UnknownFieldRef,
    UnknownVariantPolicy, VariantDef,
};

/// Resolves named ABI schemas for runtime validation.
pub trait AbiSchemaRegistry<'s> {
    /// Resolve a named ABI type reference to a compiled runtime schema.
    ///
    /// Returning a compiled schema keeps named-type recursion allocation-free on the validation
    /// hot path.
    fn resolve(&'s self, type_id: &str, version: Option<u32>) -> Option<&'s RuntimeSchema<'s>>;
}

/// Registry used when a schema contains no named references.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NoNamedSchemas;

impl<'s> AbiSchemaRegistry<'s> for NoNamedSchemas {
    fn resolve(&'s self, _type_id: &str, _version: Option<u32>) -> Option<&'s RuntimeSchema<'s>> {
        None
    }
}

/// Runtime ABI validation limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeValidationLimits {
    /// Maximum nested named/vector/enum-payload depth.
    pub max_depth: usize,
    /// Maximum validation-machine steps.
    pub max_steps: usize,
    /// Maximum field, variant-array, and vector items visited.
    pub max_items: usize,
    /// Maximum simultaneously live validation frames.
    pub max_frames: usize,
}

impl RuntimeValidationLimits {
    /// Construct explicit runtime validation limits.
    #[must_use]
    pub const fn new(
        max_depth: usize,
        max_steps: usize,
        max_items: usize,
        max_frames: usize,
    ) -> Self {
        Self {
            max_depth,
            max_steps,
            max_items,
            max_frames,
        }
    }
}

enum RuntimeValidationFrame<'a, 's> {
    Type {
        ty: &'s TypeRef,
        value: CborValueRef<'a>,
        depth: usize,
    },
    Schema {
        schema: &'s RuntimeSchema<'s>,
        value: CborValueRef<'a>,
        depth: usize,
    },
    FieldSet {
        schema: &'s RuntimeFieldSetSchema<'s>,
        value: CborValueRef<'a>,
        depth: usize,
    },
    Enum {
        schema: &'s RuntimeEnumSchema<'s>,
        value: CborValueRef<'a>,
        depth: usize,
    },
    FieldSetContinue {
        schema: &'s RuntimeFieldSetSchema<'s>,
        entries: AbiFieldSetIter<'a>,
        field_cursor: usize,
        depth: usize,
    },
    VecContinue {
        item: &'s TypeRef,
        items: ArrayIter<'a>,
        depth: usize,
    },
}

/// Reusable caller-prepared storage for stack-safe runtime ABI validation.
pub struct RuntimeValidationWorkspace {
    frames: Vec<MaybeUninit<RuntimeValidationFrame<'static, 'static>>>,
    prepared_frames: usize,
}

impl fmt::Debug for RuntimeValidationWorkspace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeValidationWorkspace")
            .field("prepared_frames", &self.prepared_frames)
            .finish()
    }
}

impl RuntimeValidationWorkspace {
    /// Construct an empty workspace. Call [`Self::prepare`] before validation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            frames: Vec::new(),
            prepared_frames: 0,
        }
    }

    /// Reserve all frame storage needed by the declared limit.
    pub fn prepare(&mut self, limits: RuntimeValidationLimits) -> Result<(), RuntimeAbiError> {
        if self.frames.len() < limits.max_frames {
            let additional = limits.max_frames - self.frames.len();
            self.frames
                .try_reserve_exact(additional)
                .map_err(|_| CborError::new(ErrorCode::AllocationFailed, 0))?;
            self.frames
                .resize_with(limits.max_frames, MaybeUninit::uninit);
        } else {
            self.frames.truncate(limits.max_frames);
        }
        self.prepared_frames = limits.max_frames;
        Ok(())
    }

    /// Return the declared live-frame capacity prepared for validation.
    #[must_use]
    pub const fn prepared_frames(&self) -> usize {
        self.prepared_frames
    }
}

impl Default for RuntimeValidationWorkspace {
    fn default() -> Self {
        Self::new()
    }
}

/// Runtime ABI validation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeAbiError {
    /// CBOR or ABI value validation failed.
    Cbor(CborError),
    /// Runtime schema is invalid.
    InvalidSchema {
        /// Static reason for the invalid schema.
        reason: &'static str,
    },
    /// A named type was rejected or could not be resolved.
    UnresolvedNamedType,
    /// Validation exceeded the explicit nesting depth.
    DepthLimit,
    /// Validation exceeded the explicit machine-step limit.
    StepLimit,
    /// Validation exceeded the explicit visited-item limit.
    ItemLimit,
    /// Validation exceeded the explicit simultaneously live-frame limit.
    FrameLimit,
    /// The prepared workspace cannot hold the declared live-frame limit.
    WorkspaceTooSmall,
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
            Self::UnresolvedNamedType => write!(f, "unresolved runtime ABI named type"),
            Self::DepthLimit => write!(f, "runtime ABI nesting depth limit exceeded"),
            Self::StepLimit => write!(f, "runtime ABI validation step limit exceeded"),
            Self::ItemLimit => write!(f, "runtime ABI validation item limit exceeded"),
            Self::FrameLimit => write!(f, "runtime ABI validation live-frame limit exceeded"),
            Self::WorkspaceTooSmall => write!(f, "runtime ABI validation workspace too small"),
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
}

/// Compiled runtime field-set schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeFieldSetSchema<'s> {
    def: Option<&'s FieldSetDef>,
    unknown_fields: UnknownFieldPolicy,
    fields: Box<[RuntimeFieldInfo<'s>]>,
    known_ids: Box<[u32]>,
    required_count: usize,
}

/// One compiled runtime enum variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeVariantInfo<'s> {
    /// Stable numeric variant ID.
    pub id: u32,
    /// Source variant definition.
    pub def: &'s VariantDef,
    payload: Option<RuntimeFieldSetSchema<'s>>,
}

/// Compiled runtime enum schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEnumSchema<'s> {
    def: &'s EnumDef,
    variants: Box<[RuntimeVariantInfo<'s>]>,
}

/// Borrowed, structurally validated runtime enum view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeEnumView<'a, 's> {
    raw: CborValueRef<'a>,
    schema: &'s RuntimeEnumSchema<'s>,
    variant_id: u32,
    payload: CborValueRef<'a>,
    known_index: Option<usize>,
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
    /// Enum discriminant and payload runtime schema.
    Enum(RuntimeEnumSchema<'s>),
    /// Transparent wrapper runtime schema.
    Transparent {
        /// Inner ABI type reference.
        inner: &'s TypeRef,
    },
    /// Primitive/external runtime schema.
    Primitive {
        /// Primitive ABI type reference.
        ty: &'s TypeRef,
    },
}

/// Compile a runtime schema root.
///
pub fn compile_runtime_schema(schema: &Schema) -> Result<RuntimeSchema<'_>, RuntimeAbiError> {
    match &schema.root {
        TypeDef::Struct(def) => Ok(RuntimeSchema::Struct(RuntimeFieldSetSchema::compile(def)?)),
        TypeDef::Transparent { inner } => Ok(RuntimeSchema::Transparent { inner }),
        TypeDef::Primitive { ty } => Ok(RuntimeSchema::Primitive { ty }),
        TypeDef::Enum(def) => Ok(RuntimeSchema::Enum(RuntimeEnumSchema::compile(def)?)),
    }
}

impl<'s> RuntimeSchema<'s> {
    /// Deeply validate any compiled runtime schema root with explicit resources.
    pub fn validate_value<'a, R: AbiSchemaRegistry<'s>>(
        &'s self,
        value: CborValueRef<'a>,
        registry: &'s R,
        limits: RuntimeValidationLimits,
        workspace: &mut RuntimeValidationWorkspace,
    ) -> Result<(), RuntimeAbiError> {
        let mut validator = RuntimeValidator::new(registry, limits, workspace)?;
        validator.push(RuntimeValidationFrame::Schema {
            schema: self,
            value,
            depth: 0,
        })?;
        validator.run()
    }
}

impl<'s> RuntimeFieldSetSchema<'s> {
    /// Compile and validate a runtime field-set definition.
    pub fn compile(def: &'s FieldSetDef) -> Result<Self, RuntimeAbiError> {
        Self::compile_fields(Some(def), &def.fields, def.unknown_fields)
    }

    fn compile_fields(
        def: Option<&'s FieldSetDef>,
        source_fields: &'s [FieldDef],
        unknown_fields: UnknownFieldPolicy,
    ) -> Result<Self, RuntimeAbiError> {
        let mut fields = Vec::new();
        fields
            .try_reserve_exact(source_fields.len())
            .map_err(|_| RuntimeAbiError::from(CborError::new(ErrorCode::AllocationFailed, 0)))?;

        for field in source_fields {
            if field.id == 0 {
                return Err(RuntimeAbiError::InvalidSchema {
                    reason: "field ID must be nonzero",
                });
            }
            fields.push(RuntimeFieldInfo {
                id: field.id,
                def: field,
            });
        }

        fields.sort_by_key(|field| field.id);
        let mut known_ids = Vec::new();
        known_ids
            .try_reserve_exact(fields.len())
            .map_err(|_| RuntimeAbiError::from(CborError::new(ErrorCode::AllocationFailed, 0)))?;
        known_ids.extend(fields.iter().map(|field| field.id));
        validate_sorted_schema_ids(&known_ids)?;

        let required_count = fields
            .iter()
            .filter(|field| matches!(field.def.presence, FieldPresence::Required))
            .count();

        Ok(Self {
            def,
            unknown_fields,
            fields: fields.into_boxed_slice(),
            known_ids: known_ids.into_boxed_slice(),
            required_count,
        })
    }

    /// Return the source field-set definition.
    #[must_use]
    pub const fn def(&self) -> Option<&'s FieldSetDef> {
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
    #[inline]
    pub fn view_value<'a>(
        &'s self,
        value: CborValueRef<'a>,
    ) -> Result<RuntimeFieldSetView<'a, 's>, RuntimeAbiError> {
        self.validate_shell_value_inner(value)
    }

    /// Deeply validate a field-set value with explicit limits and prepared storage.
    pub fn validate_value<'a, R: AbiSchemaRegistry<'s>>(
        &'s self,
        value: CborValueRef<'a>,
        registry: &'s R,
        limits: RuntimeValidationLimits,
        workspace: &mut RuntimeValidationWorkspace,
    ) -> Result<RuntimeFieldSetView<'a, 's>, RuntimeAbiError> {
        let mut validator = RuntimeValidator::new(registry, limits, workspace)?;
        let raw = validator.push_field_set(self, value, 0)?;
        validator.run()?;
        Ok(RuntimeFieldSetView { raw, schema: self })
    }

    #[inline]
    fn validate_shell_value_inner<'a>(
        &'s self,
        value: CborValueRef<'a>,
    ) -> Result<RuntimeFieldSetView<'a, 's>, RuntimeAbiError> {
        let mut required_seen = 0usize;
        let mut field_cursor = 0usize;
        let raw = AbiFieldSetRef::scan(value, |entry| {
            self.validate_shell_entry(entry, &mut required_seen, &mut field_cursor)
        })?;

        if required_seen != self.required_count {
            return Err(CborError::new(ErrorCode::MissingKey, value.offset()).into());
        }

        Ok(RuntimeFieldSetView { raw, schema: self })
    }

    #[inline]
    fn validate_shell_entry<'a>(
        &'s self,
        entry: AbiFieldEntryRef<'a>,
        required_seen: &mut usize,
        field_cursor: &mut usize,
    ) -> Result<(), CborError> {
        while *field_cursor < self.fields.len() && self.fields[*field_cursor].id < entry.id {
            *field_cursor += 1;
        }

        match self.field_info_at_cursor(entry.id, *field_cursor) {
            Some(info) => {
                if matches!(info.def.presence, FieldPresence::Required) {
                    *required_seen += 1;
                }
                Ok(())
            }
            None if self.unknown_fields == UnknownFieldPolicy::Reject => {
                Err(CborError::new(ErrorCode::UnknownField, entry.id_offset))
            }
            None => Ok(()),
        }
    }

    #[inline]
    fn field_info(&self, id: u32) -> Option<RuntimeFieldInfo<'s>> {
        self.fields
            .binary_search_by_key(&id, |field| field.id)
            .ok()
            .map(|index| self.fields[index])
    }

    #[inline]
    fn field_info_at_cursor(&self, id: u32, cursor: usize) -> Option<RuntimeFieldInfo<'s>> {
        self.fields
            .get(cursor)
            .copied()
            .filter(|field| field.id == id)
    }
}

impl<'s> RuntimeEnumSchema<'s> {
    /// Compile and validate an enum definition, including every variant payload schema.
    pub fn compile(def: &'s EnumDef) -> Result<Self, RuntimeAbiError> {
        let mut variants = Vec::new();
        variants
            .try_reserve_exact(def.variants.len())
            .map_err(|_| RuntimeAbiError::from(CborError::new(ErrorCode::AllocationFailed, 0)))?;
        for variant in &def.variants {
            if variant.id == 0 {
                return Err(RuntimeAbiError::InvalidSchema {
                    reason: "variant ID must be nonzero",
                });
            }
            let payload = if variant.fields.is_empty() {
                None
            } else {
                Some(RuntimeFieldSetSchema::compile_fields(
                    None,
                    &variant.fields,
                    def.unknown_fields,
                )?)
            };
            variants.push(RuntimeVariantInfo {
                id: variant.id,
                def: variant,
                payload,
            });
        }
        variants.sort_unstable_by_key(|variant| variant.id);
        for pair in variants.windows(2) {
            if pair[0].id == pair[1].id {
                return Err(RuntimeAbiError::InvalidSchema {
                    reason: "duplicate variant ID",
                });
            }
        }
        Ok(Self {
            def,
            variants: variants.into_boxed_slice(),
        })
    }

    /// Return the source enum definition.
    #[must_use]
    pub const fn def(&self) -> &'s EnumDef {
        self.def
    }

    /// Return variants sorted by stable numeric ID.
    #[must_use]
    pub fn variants(&self) -> &[RuntimeVariantInfo<'s>] {
        &self.variants
    }

    /// Deeply validate an enum value with explicit limits and prepared storage.
    pub fn validate_value<'a, R: AbiSchemaRegistry<'s>>(
        &'s self,
        value: CborValueRef<'a>,
        registry: &'s R,
        limits: RuntimeValidationLimits,
        workspace: &mut RuntimeValidationWorkspace,
    ) -> Result<RuntimeEnumView<'a, 's>, RuntimeAbiError> {
        let mut validator = RuntimeValidator::new(registry, limits, workspace)?;
        let view = validator.push_enum(self, value, 0)?;
        validator.run()?;
        Ok(view)
    }

    fn view_parts<'a>(
        &'s self,
        value: CborValueRef<'a>,
    ) -> Result<RuntimeEnumView<'a, 's>, RuntimeAbiError> {
        let array = value.array()?;
        if array.len() != 2 {
            return Err(CborError::new(ErrorCode::InvalidAbiValue, value.offset()).into());
        }
        let id_value = array
            .get(0)?
            .ok_or_else(|| CborError::new(ErrorCode::InvalidAbiValue, value.offset()))?;
        let id_offset = id_value.offset();
        let variant_id = id_value
            .integer()?
            .as_u128()
            .filter(|id| (1..=u32::MAX as u128).contains(id))
            .map(|id| id as u32)
            .ok_or_else(|| CborError::new(ErrorCode::InvalidAbiValue, id_offset))?;
        let payload = array
            .get(1)?
            .ok_or_else(|| CborError::new(ErrorCode::InvalidAbiValue, value.offset()))?;
        let known_index = self
            .variants
            .binary_search_by_key(&variant_id, |variant| variant.id)
            .ok();
        if let Some(index) = known_index {
            if self.variants[index].payload.is_none() && !payload.is_null() {
                return Err(CborError::new(ErrorCode::ExpectedNull, payload.offset()).into());
            }
        } else if self.def.unknown_variants == UnknownVariantPolicy::Reject {
            return Err(CborError::new(ErrorCode::InvalidAbiValue, id_offset).into());
        }
        Ok(RuntimeEnumView {
            raw: value,
            schema: self,
            variant_id,
            payload,
            known_index,
        })
    }
}

impl<'a, 's> RuntimeEnumView<'a, 's> {
    /// Return the raw two-element enum array.
    #[must_use]
    pub const fn raw_value(&self) -> CborValueRef<'a> {
        self.raw
    }

    /// Return the compiled enum schema.
    #[must_use]
    pub const fn schema(&self) -> &'s RuntimeEnumSchema<'s> {
        self.schema
    }

    /// Return the stable numeric variant ID.
    #[must_use]
    pub const fn variant_id(&self) -> u32 {
        self.variant_id
    }

    /// Return the borrowed canonical variant payload.
    #[must_use]
    pub const fn payload(&self) -> CborValueRef<'a> {
        self.payload
    }

    /// Return the known variant definition, or `None` for a preserved unknown variant.
    #[must_use]
    pub fn variant(&self) -> Option<&'s VariantDef> {
        self.known_index
            .map(|index| self.schema.variants[index].def)
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
    #[inline]
    pub fn get_raw(&self, id: u32) -> Result<Option<CborValueRef<'a>>, CborError> {
        self.raw.get(id)
    }

    /// Return one required raw field by numeric ID.
    #[inline]
    pub fn require_raw(&self, id: u32) -> Result<CborValueRef<'a>, CborError> {
        self.raw.require(id)
    }

    /// Fill `out` with raw fields for sorted numeric IDs in one scan.
    #[inline]
    pub fn get_many_raw_sorted_into(
        &self,
        ids: &[u32],
        out: &mut [Option<CborValueRef<'a>>],
    ) -> Result<(), CborError> {
        self.raw.get_many_sorted_into(ids, out)
    }

    /// Return one raw field after validating its known runtime type with explicit resources.
    ///
    /// Accepted unknown fields have no type definition and are returned without deep validation.
    #[inline]
    pub fn get_checked<R: AbiSchemaRegistry<'s>>(
        &self,
        id: u32,
        registry: &'s R,
        limits: RuntimeValidationLimits,
        workspace: &mut RuntimeValidationWorkspace,
    ) -> Result<Option<CborValueRef<'a>>, RuntimeAbiError> {
        let Some(value) = self.raw.get(id)? else {
            return Ok(None);
        };
        if let Some(info) = self.schema.field_info(id) {
            let mut validator = RuntimeValidator::new(registry, limits, workspace)?;
            validator.push(RuntimeValidationFrame::Type {
                ty: &info.def.ty,
                value,
                depth: 0,
            })?;
            validator.run()?;
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
        let preserve = schema.unknown_fields == UnknownFieldPolicy::Preserve;
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

struct RuntimeValidator<'w, 'a, 's, R: AbiSchemaRegistry<'s>> {
    registry: &'s R,
    limits: RuntimeValidationLimits,
    workspace: &'w mut RuntimeValidationWorkspace,
    live_frames: usize,
    value_lifetime: PhantomData<&'a [u8]>,
    steps: usize,
    items: usize,
}

impl<'w, 'a, 's, R: AbiSchemaRegistry<'s>> RuntimeValidator<'w, 'a, 's, R> {
    fn new(
        registry: &'s R,
        limits: RuntimeValidationLimits,
        workspace: &'w mut RuntimeValidationWorkspace,
    ) -> Result<Self, RuntimeAbiError> {
        if workspace.prepared_frames < limits.max_frames {
            return Err(RuntimeAbiError::WorkspaceTooSmall);
        }
        Ok(Self {
            registry,
            limits,
            workspace,
            live_frames: 0,
            value_lifetime: PhantomData,
            steps: 0,
            items: 0,
        })
    }

    fn charge_step(&mut self) -> Result<(), RuntimeAbiError> {
        if self.steps >= self.limits.max_steps {
            return Err(RuntimeAbiError::StepLimit);
        }
        self.steps += 1;
        Ok(())
    }

    fn charge_items(&mut self, count: usize) -> Result<(), RuntimeAbiError> {
        self.items = self
            .items
            .checked_add(count)
            .ok_or(RuntimeAbiError::ItemLimit)?;
        if self.items > self.limits.max_items {
            return Err(RuntimeAbiError::ItemLimit);
        }
        Ok(())
    }

    fn nested_depth(&self, depth: usize) -> Result<usize, RuntimeAbiError> {
        if depth >= self.limits.max_depth {
            return Err(RuntimeAbiError::DepthLimit);
        }
        depth.checked_add(1).ok_or(RuntimeAbiError::DepthLimit)
    }

    fn push(&mut self, frame: RuntimeValidationFrame<'a, 's>) -> Result<(), RuntimeAbiError> {
        if self.live_frames >= self.limits.max_frames {
            return Err(RuntimeAbiError::FrameLimit);
        }
        debug_assert!(self.live_frames < self.workspace.frames.len());
        let slot = self.workspace.frames[self.live_frames].as_mut_ptr();
        // SAFETY: every lifetime instantiation of `RuntimeValidationFrame` has the same layout.
        // `live_frames` partitions initialized `[0, live_frames)` from uninitialized remaining
        // slots, and `RuntimeValidator::drop` destroys every still-initialized frame before the
        // call lifetimes can end.
        unsafe {
            slot.cast::<RuntimeValidationFrame<'a, 's>>().write(frame);
        }
        self.live_frames += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<RuntimeValidationFrame<'a, 's>> {
        if self.live_frames == 0 {
            return None;
        }
        self.live_frames -= 1;
        let slot = self.workspace.frames[self.live_frames].as_ptr();
        // SAFETY: the slot immediately below `live_frames` was initialized by `push`, has not
        // previously been read, and becomes uninitialized again after this move.
        Some(unsafe { slot.cast::<RuntimeValidationFrame<'a, 's>>().read() })
    }

    fn push_field_set(
        &mut self,
        schema: &'s RuntimeFieldSetSchema<'s>,
        value: CborValueRef<'a>,
        depth: usize,
    ) -> Result<AbiFieldSetRef<'a>, RuntimeAbiError> {
        self.charge_step()?;
        let array = value.array()?;
        if array.len() % 2 != 0 {
            return Err(CborError::new(ErrorCode::ArrayLenMismatch, value.offset()).into());
        }
        let entry_count = array.len() / 2;
        self.charge_items(entry_count)?;
        let mut required_seen = 0usize;
        let mut field_cursor = 0usize;
        let raw = AbiFieldSetRef::scan(value, |entry| {
            schema.validate_shell_entry(entry, &mut required_seen, &mut field_cursor)
        })?;
        if required_seen != schema.required_count {
            return Err(CborError::new(ErrorCode::MissingKey, value.offset()).into());
        }
        if entry_count != 0 {
            self.push(RuntimeValidationFrame::FieldSetContinue {
                schema,
                entries: raw.iter_internal()?,
                field_cursor: 0,
                depth,
            })?;
        }
        Ok(raw)
    }

    fn push_enum(
        &mut self,
        schema: &'s RuntimeEnumSchema<'s>,
        value: CborValueRef<'a>,
        depth: usize,
    ) -> Result<RuntimeEnumView<'a, 's>, RuntimeAbiError> {
        self.charge_step()?;
        let array = value.array()?;
        if array.len() != 2 {
            return Err(CborError::new(ErrorCode::InvalidAbiValue, value.offset()).into());
        }
        self.charge_items(2)?;
        let view = schema.view_parts(value)?;
        if let Some(index) = view.known_index {
            if let Some(payload_schema) = &schema.variants[index].payload {
                self.push(RuntimeValidationFrame::FieldSet {
                    schema: payload_schema,
                    value: view.payload,
                    depth: self.nested_depth(depth)?,
                })?;
            }
        }
        Ok(view)
    }

    fn run(&mut self) -> Result<(), RuntimeAbiError> {
        while let Some(frame) = self.pop() {
            match frame {
                RuntimeValidationFrame::Type { ty, value, depth } => {
                    self.charge_step()?;
                    self.validate_type(ty, value, depth)?;
                }
                RuntimeValidationFrame::Schema {
                    schema,
                    value,
                    depth,
                } => {
                    self.charge_step()?;
                    match schema {
                        RuntimeSchema::Struct(field_set) => {
                            self.push(RuntimeValidationFrame::FieldSet {
                                schema: field_set,
                                value,
                                depth,
                            })?;
                        }
                        RuntimeSchema::Enum(enum_schema) => {
                            self.push(RuntimeValidationFrame::Enum {
                                schema: enum_schema,
                                value,
                                depth,
                            })?;
                        }
                        RuntimeSchema::Transparent { inner } => {
                            self.push(RuntimeValidationFrame::Type {
                                ty: inner,
                                value,
                                depth,
                            })?;
                        }
                        RuntimeSchema::Primitive { ty } => {
                            self.push(RuntimeValidationFrame::Type { ty, value, depth })?;
                        }
                    }
                }
                RuntimeValidationFrame::FieldSet {
                    schema,
                    value,
                    depth,
                } => {
                    self.push_field_set(schema, value, depth)?;
                }
                RuntimeValidationFrame::Enum {
                    schema,
                    value,
                    depth,
                } => {
                    self.push_enum(schema, value, depth)?;
                }
                RuntimeValidationFrame::FieldSetContinue {
                    schema,
                    mut entries,
                    mut field_cursor,
                    depth,
                } => {
                    self.charge_step()?;
                    let Some(entry) = entries.next() else {
                        continue;
                    };
                    let entry = entry?;
                    while field_cursor < schema.fields.len()
                        && schema.fields[field_cursor].id < entry.id
                    {
                        field_cursor += 1;
                    }
                    let info = schema.field_info_at_cursor(entry.id, field_cursor);
                    self.push(RuntimeValidationFrame::FieldSetContinue {
                        schema,
                        entries,
                        field_cursor,
                        depth,
                    })?;
                    if let Some(info) = info {
                        self.push(RuntimeValidationFrame::Type {
                            ty: &info.def.ty,
                            value: entry.value,
                            depth,
                        })?;
                    }
                }
                RuntimeValidationFrame::VecContinue {
                    item,
                    mut items,
                    depth,
                } => {
                    self.charge_step()?;
                    let Some(item_value) = items.next() else {
                        continue;
                    };
                    self.push(RuntimeValidationFrame::VecContinue { item, items, depth })?;
                    self.push(RuntimeValidationFrame::Type {
                        ty: item,
                        value: item_value?,
                        depth: self.nested_depth(depth)?,
                    })?;
                }
            }
        }
        Ok(())
    }

    fn validate_type(
        &mut self,
        ty: &'s TypeRef,
        value: CborValueRef<'a>,
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
                self.charge_items(array.len())?;
                if !array.is_empty() {
                    self.push(RuntimeValidationFrame::VecContinue {
                        item,
                        items: array.iter(),
                        depth,
                    })?;
                }
                Ok(())
            }
            TypeRef::CanonicalCbor => Ok(()),
            TypeRef::Named { type_id, version } => {
                let schema = self
                    .registry
                    .resolve(type_id, *version)
                    .ok_or(RuntimeAbiError::UnresolvedNamedType)?;
                self.push(RuntimeValidationFrame::Schema {
                    schema,
                    value,
                    depth: self.nested_depth(depth)?,
                })
            }
        }
    }
}

impl<'w, 'a, 's, R: AbiSchemaRegistry<'s>> Drop for RuntimeValidator<'w, 'a, 's, R> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
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

#[inline]
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
