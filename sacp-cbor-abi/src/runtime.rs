//! Allocation-free runtime views over validated static schemas.

use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;
use core::mem::MaybeUninit;

use sacp_cbor::query::{ArrayIter, CborValueRef};
use sacp_cbor::{CborError, ErrorCode};

use crate::view::AbiFieldSetIter;
use crate::{
    AbiFieldEntryRef, AbiFieldSetRef, EnumDef, FieldDef, FieldPresence, FieldSetDef, Schema,
    TypeAtom, TypeDef, TypeRef, UnknownFieldPolicy, UnknownFieldRef, UnknownVariantPolicy,
    VariantDef, VariantPayloadDef,
};

/// Resolves named ABI references to allocation-free runtime schema values.
pub trait AbiSchemaRegistry {
    /// Resolve a named type. Returning by value avoids self-referential compiled-schema storage.
    fn resolve(&self, type_id: &str, version: Option<u32>) -> Option<RuntimeSchema>;
}

/// Registry used when a schema contains no named references.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NoNamedSchemas;

impl AbiSchemaRegistry for NoNamedSchemas {
    fn resolve(&self, _type_id: &str, _version: Option<u32>) -> Option<RuntimeSchema> {
        None
    }
}

/// Runtime ABI validation limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeValidationLimits {
    /// Maximum nested named/sequence/enum-payload depth.
    pub max_depth: usize,
    /// Maximum validation-machine steps.
    pub max_steps: usize,
    /// Maximum field, variant-array, and sequence items visited.
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

enum RuntimeValidationFrame<'a> {
    Type {
        ty: TypeRef,
        value: CborValueRef<'a>,
        depth: usize,
    },
    Schema {
        schema: RuntimeSchema,
        value: CborValueRef<'a>,
        depth: usize,
    },
    FieldSet {
        schema: RuntimeFieldSetSchema,
        value: CborValueRef<'a>,
        depth: usize,
    },
    Enum {
        schema: RuntimeEnumSchema,
        value: CborValueRef<'a>,
        depth: usize,
    },
    FieldSetContinue {
        schema: RuntimeFieldSetSchema,
        entries: AbiFieldSetIter<'a>,
        field_cursor: usize,
        depth: usize,
    },
    SequenceContinue {
        item: TypeRef,
        items: ArrayIter<'a>,
        depth: usize,
    },
}

/// Reusable caller-prepared storage for machine-stack-safe runtime validation.
pub struct RuntimeValidationWorkspace {
    frames: Vec<MaybeUninit<RuntimeValidationFrame<'static>>>,
    prepared_frames: usize,
}

impl fmt::Debug for RuntimeValidationWorkspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeValidationWorkspace")
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

    /// Declared live-frame capacity prepared for validation.
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
    /// A named type could not be resolved.
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
    fn from(error: CborError) -> Self {
        Self::Cbor(error)
    }
}

impl fmt::Display for RuntimeAbiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => error.fmt(formatter),
            Self::UnresolvedNamedType => formatter.write_str("unresolved runtime ABI named type"),
            Self::DepthLimit => formatter.write_str("runtime ABI nesting depth limit exceeded"),
            Self::StepLimit => formatter.write_str("runtime ABI validation step limit exceeded"),
            Self::ItemLimit => formatter.write_str("runtime ABI validation item limit exceeded"),
            Self::FrameLimit => {
                formatter.write_str("runtime ABI validation live-frame limit exceeded")
            }
            Self::WorkspaceTooSmall => {
                formatter.write_str("runtime ABI validation workspace too small")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RuntimeAbiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cbor(error) => Some(error),
            _ => None,
        }
    }
}

/// Zero-allocation runtime field-set schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFieldSetSchema {
    def: FieldSetDef,
}

impl RuntimeFieldSetSchema {
    /// Prepare a static field set. Construction is `const` and performs no sorting or allocation.
    #[must_use]
    pub const fn new(def: FieldSetDef) -> Self {
        Self { def }
    }

    /// Source static field-set definition.
    #[must_use]
    pub const fn def(self) -> FieldSetDef {
        self.def
    }

    /// Fields already in strict numeric ID order.
    #[must_use]
    pub const fn fields(self) -> &'static [FieldDef] {
        self.def.fields()
    }

    /// Number of required fields.
    #[must_use]
    pub const fn required_count(self) -> usize {
        self.def.required_count()
    }

    /// Validate only the ABI shell, required fields, and unknown-field policy.
    pub fn view_value<'a>(
        self,
        value: CborValueRef<'a>,
    ) -> Result<RuntimeFieldSetView<'a>, RuntimeAbiError> {
        let mut required_seen = 0usize;
        let mut field_cursor = 0usize;
        let raw = AbiFieldSetRef::scan(value, |entry| {
            self.validate_shell_entry(entry, &mut required_seen, &mut field_cursor)
        })?;
        if required_seen != self.def.required_count() {
            return Err(CborError::new(ErrorCode::MissingKey, value.offset()).into());
        }
        Ok(RuntimeFieldSetView { raw, schema: self })
    }

    /// Deeply validate a field set with explicit limits and caller-prepared storage.
    pub fn validate_value<'a, R: AbiSchemaRegistry>(
        self,
        value: CborValueRef<'a>,
        registry: &R,
        limits: RuntimeValidationLimits,
        workspace: &mut RuntimeValidationWorkspace,
    ) -> Result<RuntimeFieldSetView<'a>, RuntimeAbiError> {
        let mut validator = RuntimeValidator::new(registry, limits, workspace)?;
        let raw = validator.push_field_set(self, value, 0)?;
        validator.run()?;
        Ok(RuntimeFieldSetView { raw, schema: self })
    }

    fn validate_shell_entry(
        self,
        entry: AbiFieldEntryRef<'_>,
        required_seen: &mut usize,
        field_cursor: &mut usize,
    ) -> Result<(), CborError> {
        let fields = self.def.fields();
        while *field_cursor < fields.len() && fields[*field_cursor].id() < entry.id {
            *field_cursor += 1;
        }
        match self.field_at_cursor(entry.id, *field_cursor) {
            Some(field) => {
                if matches!(field.presence(), FieldPresence::Required) {
                    *required_seen += 1;
                }
                Ok(())
            }
            None if self.def.unknown_fields() == UnknownFieldPolicy::Reject => {
                Err(CborError::new(ErrorCode::UnknownField, entry.id_offset))
            }
            None => Ok(()),
        }
    }

    fn field(self, id: u32) -> Option<&'static FieldDef> {
        self.def
            .fields()
            .binary_search_by_key(&id, |field| field.id())
            .ok()
            .map(|index| &self.def.fields()[index])
    }

    fn field_at_cursor(self, id: u32, cursor: usize) -> Option<&'static FieldDef> {
        self.def
            .fields()
            .get(cursor)
            .filter(|field| field.id() == id)
    }
}

/// Zero-allocation runtime enum schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeEnumSchema {
    def: EnumDef,
}

impl RuntimeEnumSchema {
    /// Prepare a static enum. Construction performs no sorting or allocation.
    #[must_use]
    pub const fn new(def: EnumDef) -> Self {
        Self { def }
    }

    /// Source static enum definition.
    #[must_use]
    pub const fn def(self) -> EnumDef {
        self.def
    }

    /// Variants already in strict numeric ID order.
    #[must_use]
    pub const fn variants(self) -> &'static [VariantDef] {
        self.def.variants()
    }

    /// Deeply validate an enum value with explicit resources.
    pub fn validate_value<'a, R: AbiSchemaRegistry>(
        self,
        value: CborValueRef<'a>,
        registry: &R,
        limits: RuntimeValidationLimits,
        workspace: &mut RuntimeValidationWorkspace,
    ) -> Result<RuntimeEnumView<'a>, RuntimeAbiError> {
        let mut validator = RuntimeValidator::new(registry, limits, workspace)?;
        let view = validator.push_enum(self, value, 0)?;
        validator.run()?;
        Ok(view)
    }

    fn view_parts<'a>(
        self,
        value: CborValueRef<'a>,
    ) -> Result<RuntimeEnumView<'a>, RuntimeAbiError> {
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
            .filter(|id| (1..=u128::from(u32::MAX)).contains(id))
            .map(|id| id as u32)
            .ok_or_else(|| CborError::new(ErrorCode::InvalidAbiValue, id_offset))?;
        let payload = array
            .get(1)?
            .ok_or_else(|| CborError::new(ErrorCode::InvalidAbiValue, value.offset()))?;
        let known = self
            .def
            .variants()
            .binary_search_by_key(&variant_id, |variant| variant.id())
            .ok()
            .map(|index| self.def.variants()[index]);
        if let Some(variant) = known {
            if matches!(variant.payload(), VariantPayloadDef::Unit) && !payload.is_null() {
                return Err(CborError::new(ErrorCode::ExpectedNull, payload.offset()).into());
            }
        } else if self.def.unknown_variants() == UnknownVariantPolicy::Reject {
            return Err(CborError::new(ErrorCode::InvalidAbiValue, id_offset).into());
        }
        Ok(RuntimeEnumView {
            raw: value,
            schema: self,
            variant_id,
            payload,
            known,
        })
    }
}

/// Allocation-free runtime schema value derived directly from one static schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSchema {
    /// Struct field set.
    Struct(RuntimeFieldSetSchema),
    /// Enum discriminant and payload.
    Enum(RuntimeEnumSchema),
    /// Transparent wrapper.
    Transparent {
        /// Inner wire type.
        inner: TypeRef,
    },
    /// Primitive/external root.
    Primitive {
        /// Primitive wire type.
        ty: TypeRef,
    },
}

impl RuntimeSchema {
    /// Prepare a runtime schema by value. This is a constant-time, zero-allocation operation.
    #[must_use]
    pub const fn new(schema: &'static Schema) -> Self {
        match schema.root() {
            TypeDef::Struct(def) => Self::Struct(RuntimeFieldSetSchema::new(def)),
            TypeDef::Enum(def) => Self::Enum(RuntimeEnumSchema::new(def)),
            TypeDef::Transparent { inner } => Self::Transparent { inner },
            TypeDef::Primitive { ty } => Self::Primitive { ty },
        }
    }

    /// Deeply validate any runtime root with explicit resources.
    pub fn validate_value<'a, R: AbiSchemaRegistry>(
        self,
        value: CborValueRef<'a>,
        registry: &R,
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

/// Borrowed, structurally validated runtime enum view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeEnumView<'a> {
    raw: CborValueRef<'a>,
    schema: RuntimeEnumSchema,
    variant_id: u32,
    payload: CborValueRef<'a>,
    known: Option<VariantDef>,
}

impl<'a> RuntimeEnumView<'a> {
    /// Raw two-element enum array.
    #[must_use]
    pub const fn raw_value(self) -> CborValueRef<'a> {
        self.raw
    }

    /// Runtime enum schema.
    #[must_use]
    pub const fn schema(self) -> RuntimeEnumSchema {
        self.schema
    }

    /// Stable numeric variant ID.
    #[must_use]
    pub const fn variant_id(self) -> u32 {
        self.variant_id
    }

    /// Borrowed canonical payload.
    #[must_use]
    pub const fn payload(self) -> CborValueRef<'a> {
        self.payload
    }

    /// Known variant definition, or `None` for a preserved unknown variant.
    #[must_use]
    pub const fn variant(self) -> Option<VariantDef> {
        self.known
    }
}

/// Borrowed runtime field-set view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFieldSetView<'a> {
    raw: AbiFieldSetRef<'a>,
    schema: RuntimeFieldSetSchema,
}

/// One borrowed runtime field reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFieldRef<'a> {
    /// Stable numeric field ID.
    pub id: u32,
    /// Known field definition, or `None` for an accepted unknown field.
    pub def: Option<&'static FieldDef>,
    /// Borrowed canonical field value.
    pub value: CborValueRef<'a>,
}

impl<'a> RuntimeFieldSetView<'a> {
    /// Raw field-set array value.
    #[must_use]
    pub fn raw_value(self) -> CborValueRef<'a> {
        self.raw.raw_value()
    }

    /// Validated raw field-set witness.
    #[must_use]
    pub const fn raw_fields(self) -> AbiFieldSetRef<'a> {
        self.raw
    }

    /// Runtime schema backing this view.
    #[must_use]
    pub const fn schema(self) -> RuntimeFieldSetSchema {
        self.schema
    }

    /// Return one raw field by numeric ID.
    pub fn get_raw(self, id: u32) -> Result<Option<CborValueRef<'a>>, CborError> {
        self.raw.get(id)
    }

    /// Return one required raw field by numeric ID.
    pub fn require_raw(self, id: u32) -> Result<CborValueRef<'a>, CborError> {
        self.raw.require(id)
    }

    /// Fill `out` for sorted numeric IDs in one scan.
    pub fn get_many_raw_sorted_into(
        self,
        ids: &[u32],
        out: &mut [Option<CborValueRef<'a>>],
    ) -> Result<(), CborError> {
        self.raw.get_many_sorted_into(ids, out)
    }

    /// Deeply validate one known field. Accepted unknown fields are returned without a type check.
    pub fn get_checked<R: AbiSchemaRegistry>(
        self,
        id: u32,
        registry: &R,
        limits: RuntimeValidationLimits,
        workspace: &mut RuntimeValidationWorkspace,
    ) -> Result<Option<CborValueRef<'a>>, RuntimeAbiError> {
        let Some(value) = self.raw.get(id)? else {
            return Ok(None);
        };
        if let Some(field) = self.schema.field(id) {
            let mut validator = RuntimeValidator::new(registry, limits, workspace)?;
            validator.push(RuntimeValidationFrame::Type {
                ty: field.ty(),
                value,
                depth: 0,
            })?;
            validator.run()?;
        }
        Ok(Some(value))
    }

    /// Iterate fields in field-ID order.
    pub fn iter(
        self,
    ) -> Result<impl Iterator<Item = Result<RuntimeFieldRef<'a>, CborError>> + 'a, CborError> {
        let schema = self.schema;
        let mut field_cursor = 0usize;
        Ok(self.raw.iter()?.map(move |entry| {
            entry.map(|entry| {
                let fields = schema.fields();
                while field_cursor < fields.len() && fields[field_cursor].id() < entry.id {
                    field_cursor += 1;
                }
                RuntimeFieldRef {
                    id: entry.id,
                    def: schema.field_at_cursor(entry.id, field_cursor),
                    value: entry.value,
                }
            })
        }))
    }

    /// Iterate borrowed preserved unknown fields.
    pub fn unknown_fields(
        self,
    ) -> Result<impl Iterator<Item = Result<UnknownFieldRef<'a>, CborError>> + 'a, CborError> {
        let schema = self.schema;
        let preserve = schema.def.unknown_fields() == UnknownFieldPolicy::Preserve;
        let mut field_cursor = 0usize;
        Ok(self.raw.iter()?.filter_map(move |entry| {
            if !preserve {
                return None;
            }
            match entry {
                Ok(entry) => {
                    let fields = schema.fields();
                    while field_cursor < fields.len() && fields[field_cursor].id() < entry.id {
                        field_cursor += 1;
                    }
                    if schema.field_at_cursor(entry.id, field_cursor).is_some() {
                        None
                    } else {
                        Some(Ok(UnknownFieldRef {
                            id: entry.id,
                            value: entry.value,
                        }))
                    }
                }
                Err(error) => Some(Err(error)),
            }
        }))
    }
}

struct RuntimeValidator<'w, 'a, 'r, R: AbiSchemaRegistry> {
    registry: &'r R,
    limits: RuntimeValidationLimits,
    workspace: &'w mut RuntimeValidationWorkspace,
    live_frames: usize,
    value_lifetime: PhantomData<&'a [u8]>,
    steps: usize,
    items: usize,
}

impl<'w, 'a, 'r, R: AbiSchemaRegistry> RuntimeValidator<'w, 'a, 'r, R> {
    fn new(
        registry: &'r R,
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

    fn push(&mut self, frame: RuntimeValidationFrame<'a>) -> Result<(), RuntimeAbiError> {
        if self.live_frames >= self.limits.max_frames {
            return Err(RuntimeAbiError::FrameLimit);
        }
        debug_assert!(self.live_frames < self.workspace.frames.len());
        let slot = self.workspace.frames[self.live_frames].as_mut_ptr();
        // SAFETY: every lifetime instantiation has the same layout. `live_frames` partitions the
        // initialized prefix, and `Drop` destroys all frames before the borrowed input can expire.
        unsafe {
            slot.cast::<RuntimeValidationFrame<'a>>().write(frame);
        }
        self.live_frames += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<RuntimeValidationFrame<'a>> {
        if self.live_frames == 0 {
            return None;
        }
        self.live_frames -= 1;
        let slot = self.workspace.frames[self.live_frames].as_ptr();
        // SAFETY: the slot was initialized by `push`, has not been read, and is now removed from
        // the initialized prefix.
        Some(unsafe { slot.cast::<RuntimeValidationFrame<'a>>().read() })
    }

    fn push_field_set(
        &mut self,
        schema: RuntimeFieldSetSchema,
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
        if required_seen != schema.required_count() {
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
        schema: RuntimeEnumSchema,
        value: CborValueRef<'a>,
        depth: usize,
    ) -> Result<RuntimeEnumView<'a>, RuntimeAbiError> {
        self.charge_step()?;
        let array = value.array()?;
        if array.len() != 2 {
            return Err(CborError::new(ErrorCode::InvalidAbiValue, value.offset()).into());
        }
        self.charge_items(2)?;
        let view = schema.view_parts(value)?;
        if let Some(variant) = view.known {
            if let VariantPayloadDef::Fields(fields) = variant.payload() {
                self.push(RuntimeValidationFrame::FieldSet {
                    schema: RuntimeFieldSetSchema::new(fields),
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
                        RuntimeSchema::Struct(schema) => {
                            self.push(RuntimeValidationFrame::FieldSet {
                                schema,
                                value,
                                depth,
                            })?;
                        }
                        RuntimeSchema::Enum(schema) => {
                            self.push(RuntimeValidationFrame::Enum {
                                schema,
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
                    let fields = schema.fields();
                    while field_cursor < fields.len() && fields[field_cursor].id() < entry.id {
                        field_cursor += 1;
                    }
                    let field = schema.field_at_cursor(entry.id, field_cursor);
                    self.push(RuntimeValidationFrame::FieldSetContinue {
                        schema,
                        entries,
                        field_cursor,
                        depth,
                    })?;
                    if let Some(field) = field {
                        self.push(RuntimeValidationFrame::Type {
                            ty: field.ty(),
                            value: entry.value,
                            depth,
                        })?;
                    }
                }
                RuntimeValidationFrame::SequenceContinue {
                    item,
                    mut items,
                    depth,
                } => {
                    self.charge_step()?;
                    let Some(value) = items.next() else {
                        continue;
                    };
                    self.push(RuntimeValidationFrame::SequenceContinue { item, items, depth })?;
                    self.push(RuntimeValidationFrame::Type {
                        ty: item,
                        value: value?,
                        depth: self.nested_depth(depth)?,
                    })?;
                }
            }
        }
        Ok(())
    }

    fn validate_type(
        &mut self,
        ty: TypeRef,
        value: CborValueRef<'a>,
        depth: usize,
    ) -> Result<(), RuntimeAbiError> {
        if let Some(item) = ty.sequence_item() {
            let array = value.array()?;
            self.charge_items(array.len())?;
            if !array.is_empty() {
                self.push(RuntimeValidationFrame::SequenceContinue {
                    item,
                    items: array.iter(),
                    depth,
                })?;
            }
            return Ok(());
        }
        match ty.terminal() {
            TypeAtom::Unit => {
                if value.is_null() {
                    Ok(())
                } else {
                    Err(CborError::new(ErrorCode::ExpectedNull, value.offset()).into())
                }
            }
            TypeAtom::Bool => value.bool().map(|_| ()).map_err(Into::into),
            TypeAtom::U8 => validate_unsigned(value, u128::from(u8::MAX)),
            TypeAtom::U16 => validate_unsigned(value, u128::from(u16::MAX)),
            TypeAtom::U32 => validate_unsigned(value, u128::from(u32::MAX)),
            TypeAtom::U64 => validate_unsigned(value, u128::from(u64::MAX)),
            TypeAtom::I8 => validate_signed(value, i128::from(i8::MIN), i128::from(i8::MAX)),
            TypeAtom::I16 => validate_signed(value, i128::from(i16::MIN), i128::from(i16::MAX)),
            TypeAtom::I32 => validate_signed(value, i128::from(i32::MIN), i128::from(i32::MAX)),
            TypeAtom::I64 => validate_signed(value, i128::from(i64::MIN), i128::from(i64::MAX)),
            TypeAtom::Text => value.text().map(|_| ()).map_err(Into::into),
            TypeAtom::Bytes => value.bytes().map(|_| ()).map_err(Into::into),
            TypeAtom::FixedBytes { len } => {
                let bytes = value.bytes()?;
                if u64::try_from(bytes.len()).ok() == Some(len) {
                    Ok(())
                } else {
                    Err(CborError::new(ErrorCode::ExpectedBytes, value.offset()).into())
                }
            }
            TypeAtom::CanonicalCbor => Ok(()),
            TypeAtom::Named { type_id, version } => {
                let schema = self
                    .registry
                    .resolve(type_id, version)
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

impl<'w, 'a, 'r, R: AbiSchemaRegistry> Drop for RuntimeValidator<'w, 'a, 'r, R> {
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
