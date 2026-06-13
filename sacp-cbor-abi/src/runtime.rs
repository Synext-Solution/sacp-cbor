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
    /// Resolve a named ABI type reference to a compiled runtime schema.
    ///
    /// Returning a compiled schema keeps named-type recursion allocation-free on the validation
    /// hot path.
    fn resolve(&self, type_id: &str, version: Option<u32>) -> Option<&RuntimeSchema<'_>>;
}

/// Runtime ABI validation limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeValidationConfig {
    max_recursion_depth: usize,
}

impl RuntimeValidationConfig {
    /// Return the default runtime validation configuration.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_recursion_depth: DEFAULT_RECURSION_DEPTH,
        }
    }

    /// Override the maximum nested type/schema recursion depth.
    #[must_use]
    pub const fn with_max_recursion_depth(self, depth: usize) -> Self {
        Self {
            max_recursion_depth: depth,
        }
    }

    /// Return the configured maximum recursion depth.
    #[must_use]
    pub const fn max_recursion_depth(&self) -> usize {
        self.max_recursion_depth
    }
}

impl Default for RuntimeValidationConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Named-type resolution result for a runtime validation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeNamedResolution<'s> {
    /// Treat named values as structurally opaque after hooks continue.
    Opaque,
    /// Recursively validate against a compiled runtime schema.
    Schema(&'s RuntimeSchema<'s>),
}

/// Static runtime type-validation mode.
pub trait RuntimeTypeMode {
    /// Resolve a named ABI type reference for this validation mode.
    fn resolve_named(
        &self,
        type_id: &str,
        version: Option<u32>,
    ) -> Result<RuntimeNamedResolution<'_>, RuntimeAbiError>;
}

/// Validate inline primitive/container types while treating named types as opaque.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeInline;

impl RuntimeTypeMode for RuntimeInline {
    #[inline]
    fn resolve_named(
        &self,
        _type_id: &str,
        _version: Option<u32>,
    ) -> Result<RuntimeNamedResolution<'_>, RuntimeAbiError> {
        Ok(RuntimeNamedResolution::Opaque)
    }
}

/// Reject named types during deep validation unless hooks accept them.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeRejectNamed;

impl RuntimeTypeMode for RuntimeRejectNamed {
    #[inline]
    fn resolve_named(
        &self,
        _type_id: &str,
        _version: Option<u32>,
    ) -> Result<RuntimeNamedResolution<'_>, RuntimeAbiError> {
        Err(RuntimeAbiError::UnresolvedNamedType)
    }
}

/// Resolve named types through a caller-provided compiled schema registry.
pub struct RuntimeResolveNamed<'r, R: AbiSchemaRegistry> {
    registry: &'r R,
}

impl<R: AbiSchemaRegistry> fmt::Debug for RuntimeResolveNamed<'_, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeResolveNamed")
            .finish_non_exhaustive()
    }
}

impl<R: AbiSchemaRegistry> Clone for RuntimeResolveNamed<'_, R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R: AbiSchemaRegistry> Copy for RuntimeResolveNamed<'_, R> {}

impl<'r, R: AbiSchemaRegistry> RuntimeResolveNamed<'r, R> {
    /// Construct a static-dispatch named-type resolver.
    #[must_use]
    pub const fn new(registry: &'r R) -> Self {
        Self { registry }
    }
}

impl<R: AbiSchemaRegistry> RuntimeTypeMode for RuntimeResolveNamed<'_, R> {
    #[inline]
    fn resolve_named(
        &self,
        type_id: &str,
        version: Option<u32>,
    ) -> Result<RuntimeNamedResolution<'_>, RuntimeAbiError> {
        self.registry
            .resolve(type_id, version)
            .map(RuntimeNamedResolution::Schema)
            .ok_or(RuntimeAbiError::UnresolvedNamedType)
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
    /// Root type is not supported by the runtime validator.
    UnsupportedRoot,
    /// A named type was rejected or could not be resolved.
    UnresolvedNamedType,
    /// Recursive validation exceeded the configured depth.
    RecursionLimit,
    /// Caller-provided runtime validation hook rejected a value.
    HookRejected {
        /// Static rejection reason.
        reason: &'static str,
        /// Offset of the rejected canonical CBOR value, saturated to `u32::MAX`.
        offset: u32,
    },
}

impl From<CborError> for RuntimeAbiError {
    fn from(err: CborError) -> Self {
        Self::Cbor(err)
    }
}

impl RuntimeAbiError {
    /// Construct a hook rejection error.
    ///
    /// The stored offset is saturated to keep the runtime error type compact on validation hot
    /// paths.
    #[must_use]
    pub const fn hook_rejected(reason: &'static str, offset: usize) -> Self {
        Self::HookRejected {
            reason,
            offset: if offset > u32::MAX as usize {
                u32::MAX
            } else {
                offset as u32
            },
        }
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
            Self::HookRejected { reason, offset } => {
                write!(
                    f,
                    "runtime ABI validation hook rejected value at {offset}: {reason}"
                )
            }
        }
    }
}

/// Hook decision for a named ABI type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeNamedDecision {
    /// Continue with the configured built-in named-type policy.
    Continue,
    /// Treat this named node as externally validated by the hook.
    Accepted,
}

/// Outcome passed to exit hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeHookOutcome {
    /// Built-in validation and earlier hooks accepted this node.
    Success,
    /// Built-in validation or an earlier hook rejected this node.
    Error(RuntimeAbiError),
}

/// Field-level hook context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFieldContext<'s> {
    /// Current runtime recursion depth.
    pub depth: usize,
    /// Compiled field-set schema being validated.
    pub schema: &'s RuntimeFieldSetSchema<'s>,
    /// Numeric ABI field ID.
    pub field_id: u32,
}

/// TypeRef-level hook context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeTypeContext<'s> {
    /// Current runtime recursion depth.
    pub depth: usize,
    /// Enclosing field, when validation is currently inside one.
    pub field: Option<&'s FieldDef>,
    /// Enclosing field-set schema, when validation is currently inside one.
    pub field_set: Option<&'s RuntimeFieldSetSchema<'s>>,
}

/// Vec-item hook context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeVecItemContext<'s> {
    /// Current runtime recursion depth of the item.
    pub depth: usize,
    /// Enclosing field, when validation is currently inside one.
    pub field: Option<&'s FieldDef>,
    /// Enclosing field-set schema, when validation is currently inside one.
    pub field_set: Option<&'s RuntimeFieldSetSchema<'s>>,
    /// Zero-based array item index.
    pub index: usize,
}

/// Optional semantic refinements for runtime ABI validation.
///
/// Hooks may reject ABI-valid values, but they cannot make primitive/container ABI-invalid values
/// valid. `TypeRef::Named` is the only node where `RuntimeNamedDecision::Accepted` may replace
/// built-in registry validation.
pub trait RuntimeValidationHooks {
    /// Called before a known field's type is validated.
    #[inline]
    fn enter_field(
        &mut self,
        _ctx: RuntimeFieldContext<'_>,
        _field: &FieldDef,
        _value: CborValueRef<'_>,
    ) -> Result<(), RuntimeAbiError> {
        Ok(())
    }

    /// Called after a known field's type validation completes or fails.
    #[inline]
    fn exit_field(
        &mut self,
        _ctx: RuntimeFieldContext<'_>,
        _field: &FieldDef,
        _value: CborValueRef<'_>,
        _outcome: RuntimeHookOutcome,
    ) -> Result<(), RuntimeAbiError> {
        Ok(())
    }

    /// Called before a `TypeRef` node is validated.
    #[inline]
    fn enter_type_ref(
        &mut self,
        _ctx: RuntimeTypeContext<'_>,
        _ty: &TypeRef,
        _value: CborValueRef<'_>,
    ) -> Result<(), RuntimeAbiError> {
        Ok(())
    }

    /// Called after a `TypeRef` node validation completes or fails.
    #[inline]
    fn exit_type_ref(
        &mut self,
        _ctx: RuntimeTypeContext<'_>,
        _ty: &TypeRef,
        _value: CborValueRef<'_>,
        _outcome: RuntimeHookOutcome,
    ) -> Result<(), RuntimeAbiError> {
        Ok(())
    }

    /// Optionally validate a named type without registry resolution.
    #[inline]
    fn validate_named(
        &mut self,
        _ctx: RuntimeTypeContext<'_>,
        _type_id: &str,
        _version: Option<u32>,
        _value: CborValueRef<'_>,
    ) -> Result<RuntimeNamedDecision, RuntimeAbiError> {
        Ok(RuntimeNamedDecision::Continue)
    }

    /// Called after a `Vec<T>` value's array shape is validated.
    #[inline]
    fn enter_vec(
        &mut self,
        _ctx: RuntimeTypeContext<'_>,
        _item: &TypeRef,
        _value: CborValueRef<'_>,
        _len: usize,
    ) -> Result<(), RuntimeAbiError> {
        Ok(())
    }

    /// Called after a `Vec<T>` validation completes or fails.
    #[inline]
    fn exit_vec(
        &mut self,
        _ctx: RuntimeTypeContext<'_>,
        _item: &TypeRef,
        _value: CborValueRef<'_>,
        _outcome: RuntimeHookOutcome,
    ) -> Result<(), RuntimeAbiError> {
        Ok(())
    }

    /// Called after each `Vec<T>` item validation completes or fails.
    #[inline]
    fn exit_vec_item(
        &mut self,
        _ctx: RuntimeVecItemContext<'_>,
        _item: &TypeRef,
        _value: CborValueRef<'_>,
        _outcome: RuntimeHookOutcome,
    ) -> Result<(), RuntimeAbiError> {
        Ok(())
    }
}

/// No-op runtime validation hooks for the monomorphized no-hook hot path.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NoRuntimeValidationHooks;

impl RuntimeValidationHooks for NoRuntimeValidationHooks {}

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
/// Runtime enum views remain out of scope.
pub fn compile_runtime_schema(schema: &Schema) -> Result<RuntimeSchema<'_>, RuntimeAbiError> {
    match &schema.root {
        TypeDef::Struct(def) => Ok(RuntimeSchema::Struct(RuntimeFieldSetSchema::compile(def)?)),
        TypeDef::Transparent { inner } => Ok(RuntimeSchema::Transparent { inner }),
        TypeDef::Primitive { ty } => Ok(RuntimeSchema::Primitive { ty }),
        TypeDef::Enum(_) => Err(RuntimeAbiError::UnsupportedRoot),
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
    #[inline]
    pub fn view_value<'a>(
        &'s self,
        value: CborValueRef<'a>,
    ) -> Result<RuntimeFieldSetView<'a, 's>, RuntimeAbiError> {
        self.validate_shell_value_inner(value)
    }

    /// Validate a field-set value using a static runtime type-validation mode and no hooks.
    #[inline]
    pub fn validate_value<'a, M: RuntimeTypeMode>(
        &'s self,
        value: CborValueRef<'a>,
        mode: M,
    ) -> Result<RuntimeFieldSetView<'a, 's>, RuntimeAbiError> {
        self.validate_value_with_config(value, mode, RuntimeValidationConfig::default())
    }

    /// Validate a field-set value using a static runtime type-validation mode and config.
    #[inline]
    pub fn validate_value_with_config<'a, M: RuntimeTypeMode>(
        &'s self,
        value: CborValueRef<'a>,
        mode: M,
        config: RuntimeValidationConfig,
    ) -> Result<RuntimeFieldSetView<'a, 's>, RuntimeAbiError> {
        self.validate_value_no_hooks(value, &mode, config, 0)
    }

    /// Validate a field-set value using a static runtime type-validation mode and hooks.
    #[inline]
    pub fn validate_value_with_hooks<'a, M: RuntimeTypeMode, H: RuntimeValidationHooks>(
        &'s self,
        value: CborValueRef<'a>,
        mode: M,
        config: RuntimeValidationConfig,
        hooks: &mut H,
    ) -> Result<RuntimeFieldSetView<'a, 's>, RuntimeAbiError> {
        self.validate_value_inner(value, &mode, config, 0, hooks)
    }

    #[inline]
    fn validate_shell_value_inner<'a>(
        &'s self,
        value: CborValueRef<'a>,
    ) -> Result<RuntimeFieldSetView<'a, 's>, RuntimeAbiError> {
        let mut required = RequiredSeen::new(self.required_count)?;
        let mut field_cursor = 0usize;
        let raw = AbiFieldSetRef::scan(value, |entry| {
            self.validate_shell_entry(entry, &mut required, &mut field_cursor)
        })?;

        if !required.all_seen(self.required_count) {
            return Err(CborError::new(ErrorCode::MissingKey, value.offset()).into());
        }

        Ok(RuntimeFieldSetView { raw, schema: self })
    }

    #[inline]
    fn validate_value_no_hooks<'a, M: RuntimeTypeMode>(
        &'s self,
        value: CborValueRef<'a>,
        mode: &M,
        config: RuntimeValidationConfig,
        depth: usize,
    ) -> Result<RuntimeFieldSetView<'a, 's>, RuntimeAbiError> {
        let mut required = RequiredSeen::new(self.required_count)?;
        let mut runtime_error = None;
        let mut field_cursor = 0usize;
        let raw = match AbiFieldSetRef::scan(value, |entry| {
            match self.validate_entry_no_hooks(
                entry,
                mode,
                config,
                depth,
                &mut required,
                &mut field_cursor,
            ) {
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

    #[inline]
    fn validate_value_inner<'a, M: RuntimeTypeMode, H: RuntimeValidationHooks>(
        &'s self,
        value: CborValueRef<'a>,
        mode: &M,
        config: RuntimeValidationConfig,
        depth: usize,
        hooks: &mut H,
    ) -> Result<RuntimeFieldSetView<'a, 's>, RuntimeAbiError> {
        let mut required = RequiredSeen::new(self.required_count)?;
        let mut runtime_error = None;
        let mut field_cursor = 0usize;
        let scan_result = {
            let mut scan = FieldScanState {
                required: &mut required,
                field_cursor: &mut field_cursor,
            };
            AbiFieldSetRef::scan(value, |entry| {
                match self.validate_entry(entry, mode, config, depth, &mut scan, hooks) {
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
            })
        };
        let raw = match scan_result {
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

    #[inline]
    fn validate_shell_entry<'a>(
        &'s self,
        entry: AbiFieldEntryRef<'a>,
        required: &mut RequiredSeen,
        field_cursor: &mut usize,
    ) -> Result<(), CborError> {
        while *field_cursor < self.fields.len() && self.fields[*field_cursor].id < entry.id {
            *field_cursor += 1;
        }

        match self.field_info_at_cursor(entry.id, *field_cursor) {
            Some(info) => {
                if let Some(index) = info.required_index {
                    required.mark(index);
                }
                Ok(())
            }
            None if self.def.unknown_fields == UnknownFieldPolicy::Reject => {
                Err(CborError::new(ErrorCode::UnknownField, entry.id_offset))
            }
            None => Ok(()),
        }
    }

    #[inline]
    fn validate_entry_no_hooks<'a, M: RuntimeTypeMode>(
        &'s self,
        entry: AbiFieldEntryRef<'a>,
        mode: &M,
        config: RuntimeValidationConfig,
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
                validate_type_ref_no_hooks(&info.def.ty, entry.value, mode, config, depth)
            }
            None if self.def.unknown_fields == UnknownFieldPolicy::Reject => {
                Err(CborError::new(ErrorCode::UnknownField, entry.id_offset).into())
            }
            None => Ok(()),
        }
    }

    #[inline]
    fn validate_entry<'a, M: RuntimeTypeMode, H: RuntimeValidationHooks>(
        &'s self,
        entry: AbiFieldEntryRef<'a>,
        mode: &M,
        config: RuntimeValidationConfig,
        depth: usize,
        scan: &mut FieldScanState<'_>,
        hooks: &mut H,
    ) -> Result<(), RuntimeAbiError> {
        while *scan.field_cursor < self.fields.len()
            && self.fields[*scan.field_cursor].id < entry.id
        {
            *scan.field_cursor += 1;
        }

        match self.field_info_at_cursor(entry.id, *scan.field_cursor) {
            Some(info) => {
                if let Some(index) = info.required_index {
                    scan.required.mark(index);
                }
                self.validate_known_field_value(info, entry.value, mode, config, depth, hooks)?;
                Ok(())
            }
            None if self.def.unknown_fields == UnknownFieldPolicy::Reject => {
                Err(CborError::new(ErrorCode::UnknownField, entry.id_offset).into())
            }
            None => Ok(()),
        }
    }

    #[inline]
    fn validate_known_field_value<'a, M: RuntimeTypeMode, H: RuntimeValidationHooks>(
        &'s self,
        info: RuntimeFieldInfo<'s>,
        value: CborValueRef<'a>,
        mode: &M,
        config: RuntimeValidationConfig,
        depth: usize,
        hooks: &mut H,
    ) -> Result<(), RuntimeAbiError> {
        let field_ctx = RuntimeFieldContext {
            depth,
            schema: self,
            field_id: info.id,
        };
        hooks.enter_field(field_ctx, info.def, value)?;

        let type_ctx = RuntimeTypeContext {
            depth,
            field: Some(info.def),
            field_set: Some(self),
        };
        match validate_type_ref_with_hooks(&info.def.ty, value, mode, config, hooks, type_ctx) {
            Ok(()) => hooks.exit_field(field_ctx, info.def, value, RuntimeHookOutcome::Success),
            Err(err) => {
                let _ =
                    hooks.exit_field(field_ctx, info.def, value, RuntimeHookOutcome::Error(err));
                Err(err)
            }
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

    /// Return one raw field after validating its known runtime type.
    ///
    /// Accepted unknown fields have no type definition and are returned without deep validation.
    #[inline]
    pub fn get_checked<M: RuntimeTypeMode>(
        &self,
        id: u32,
        mode: M,
    ) -> Result<Option<CborValueRef<'a>>, RuntimeAbiError> {
        self.get_checked_with_config(id, mode, RuntimeValidationConfig::default())
    }

    /// Return one raw field after validating its known runtime type with config.
    ///
    /// Accepted unknown fields have no type definition and are returned without deep validation.
    #[inline]
    pub fn get_checked_with_config<M: RuntimeTypeMode>(
        &self,
        id: u32,
        mode: M,
        config: RuntimeValidationConfig,
    ) -> Result<Option<CborValueRef<'a>>, RuntimeAbiError> {
        let Some(value) = self.raw.get(id)? else {
            return Ok(None);
        };
        if let Some(info) = self.schema.field_info(id) {
            validate_type_ref_no_hooks(&info.def.ty, value, &mode, config, 0)?;
        }
        Ok(Some(value))
    }

    /// Return one raw field after validating its known runtime type with hooks.
    ///
    /// Accepted unknown fields have no type definition and are returned without deep validation.
    #[inline]
    pub fn get_checked_with_hooks<M: RuntimeTypeMode, H: RuntimeValidationHooks>(
        &self,
        id: u32,
        mode: M,
        config: RuntimeValidationConfig,
        hooks: &mut H,
    ) -> Result<Option<CborValueRef<'a>>, RuntimeAbiError> {
        let Some(value) = self.raw.get(id)? else {
            return Ok(None);
        };
        if let Some(info) = self.schema.field_info(id) {
            self.schema
                .validate_known_field_value(info, value, &mode, config, 0, hooks)?;
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

#[inline]
fn validate_runtime_schema_no_hooks<M: RuntimeTypeMode>(
    schema: &RuntimeSchema<'_>,
    value: CborValueRef<'_>,
    mode: &M,
    config: RuntimeValidationConfig,
    depth: usize,
) -> Result<(), RuntimeAbiError> {
    match schema {
        RuntimeSchema::Struct(field_set) => {
            field_set.validate_value_no_hooks(value, mode, config, depth)?;
            Ok(())
        }
        RuntimeSchema::Transparent { inner } => {
            validate_type_ref_no_hooks(inner, value, mode, config, depth)
        }
        RuntimeSchema::Primitive { ty } => {
            validate_type_ref_no_hooks(ty, value, mode, config, depth)
        }
    }
}

#[inline]
fn validate_runtime_schema_with_hooks<'ctx, M: RuntimeTypeMode, H: RuntimeValidationHooks>(
    schema: &RuntimeSchema<'_>,
    value: CborValueRef<'_>,
    mode: &M,
    config: RuntimeValidationConfig,
    hooks: &mut H,
    depth: usize,
    parent_ctx: RuntimeTypeContext<'ctx>,
) -> Result<(), RuntimeAbiError> {
    match schema {
        RuntimeSchema::Struct(field_set) => {
            field_set.validate_value_inner(value, mode, config, depth, hooks)?;
            Ok(())
        }
        RuntimeSchema::Transparent { inner } => validate_type_ref_with_hooks(
            inner,
            value,
            mode,
            config,
            hooks,
            RuntimeTypeContext {
                depth,
                field: parent_ctx.field,
                field_set: parent_ctx.field_set,
            },
        ),
        RuntimeSchema::Primitive { ty } => validate_type_ref_with_hooks(
            ty,
            value,
            mode,
            config,
            hooks,
            RuntimeTypeContext {
                depth,
                field: parent_ctx.field,
                field_set: parent_ctx.field_set,
            },
        ),
    }
}

#[inline]
fn validate_type_ref_no_hooks<M: RuntimeTypeMode>(
    ty: &TypeRef,
    value: CborValueRef<'_>,
    mode: &M,
    config: RuntimeValidationConfig,
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
        TypeRef::Vec { item } => validate_vec_no_hooks(item, value, mode, config, depth),
        TypeRef::CanonicalCbor => Ok(()),
        TypeRef::Named { type_id, version } => match mode.resolve_named(type_id, *version)? {
            RuntimeNamedResolution::Opaque => Ok(()),
            RuntimeNamedResolution::Schema(schema) => {
                let next_depth = enter_nested(depth, config)?;
                validate_runtime_schema_no_hooks(schema, value, mode, config, next_depth)
            }
        },
    }
}

#[inline]
fn validate_type_ref_with_hooks<'ctx, M: RuntimeTypeMode, H: RuntimeValidationHooks>(
    ty: &TypeRef,
    value: CborValueRef<'_>,
    mode: &M,
    config: RuntimeValidationConfig,
    hooks: &mut H,
    ctx: RuntimeTypeContext<'ctx>,
) -> Result<(), RuntimeAbiError> {
    hooks.enter_type_ref(ctx, ty, value)?;
    match validate_type_ref_body_with_hooks(ty, value, mode, config, hooks, ctx) {
        Ok(()) => hooks.exit_type_ref(ctx, ty, value, RuntimeHookOutcome::Success),
        Err(err) => {
            let _ = hooks.exit_type_ref(ctx, ty, value, RuntimeHookOutcome::Error(err));
            Err(err)
        }
    }
}

#[inline]
fn validate_type_ref_body_with_hooks<'ctx, M: RuntimeTypeMode, H: RuntimeValidationHooks>(
    ty: &TypeRef,
    value: CborValueRef<'_>,
    mode: &M,
    config: RuntimeValidationConfig,
    hooks: &mut H,
    ctx: RuntimeTypeContext<'ctx>,
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
        TypeRef::Vec { item } => validate_vec_with_hooks(item, value, mode, config, hooks, ctx),
        TypeRef::CanonicalCbor => Ok(()),
        TypeRef::Named { type_id, version } => {
            match hooks.validate_named(ctx, type_id, *version, value)? {
                RuntimeNamedDecision::Accepted => Ok(()),
                RuntimeNamedDecision::Continue => match mode.resolve_named(type_id, *version)? {
                    RuntimeNamedResolution::Opaque => Ok(()),
                    RuntimeNamedResolution::Schema(schema) => {
                        let next_depth = enter_nested(ctx.depth, config)?;
                        validate_runtime_schema_with_hooks(
                            schema, value, mode, config, hooks, next_depth, ctx,
                        )
                    }
                },
            }
        }
    }
}

#[inline]
fn validate_vec_no_hooks<M: RuntimeTypeMode>(
    item: &TypeRef,
    value: CborValueRef<'_>,
    mode: &M,
    config: RuntimeValidationConfig,
    depth: usize,
) -> Result<(), RuntimeAbiError> {
    let array = value.array()?;
    for item_value in array.iter() {
        validate_type_ref_no_hooks(
            item,
            item_value?,
            mode,
            config,
            enter_nested(depth, config)?,
        )?;
    }
    Ok(())
}

#[inline]
fn validate_vec_with_hooks<'ctx, M: RuntimeTypeMode, H: RuntimeValidationHooks>(
    item: &TypeRef,
    value: CborValueRef<'_>,
    mode: &M,
    config: RuntimeValidationConfig,
    hooks: &mut H,
    ctx: RuntimeTypeContext<'ctx>,
) -> Result<(), RuntimeAbiError> {
    let array = value.array()?;
    hooks.enter_vec(ctx, item, value, array.len())?;

    for (index, item_value) in array.iter().enumerate() {
        let item_value = match item_value {
            Ok(item_value) => item_value,
            Err(err) => {
                let err = RuntimeAbiError::Cbor(err);
                let _ = hooks.exit_vec(ctx, item, value, RuntimeHookOutcome::Error(err));
                return Err(err);
            }
        };

        let next_depth = match enter_nested(ctx.depth, config) {
            Ok(depth) => depth,
            Err(err) => {
                let _ = hooks.exit_vec(ctx, item, value, RuntimeHookOutcome::Error(err));
                return Err(err);
            }
        };
        let item_ctx = RuntimeVecItemContext {
            depth: next_depth,
            field: ctx.field,
            field_set: ctx.field_set,
            index,
        };
        let type_ctx = RuntimeTypeContext {
            depth: next_depth,
            field: ctx.field,
            field_set: ctx.field_set,
        };

        match validate_type_ref_with_hooks(item, item_value, mode, config, hooks, type_ctx) {
            Ok(()) => {
                if let Err(err) =
                    hooks.exit_vec_item(item_ctx, item, item_value, RuntimeHookOutcome::Success)
                {
                    let _ = hooks.exit_vec(ctx, item, value, RuntimeHookOutcome::Error(err));
                    return Err(err);
                }
            }
            Err(err) => {
                let _ =
                    hooks.exit_vec_item(item_ctx, item, item_value, RuntimeHookOutcome::Error(err));
                let _ = hooks.exit_vec(ctx, item, value, RuntimeHookOutcome::Error(err));
                return Err(err);
            }
        }
    }

    hooks.exit_vec(ctx, item, value, RuntimeHookOutcome::Success)
}

#[inline]
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

#[inline]
fn enter_nested(depth: usize, config: RuntimeValidationConfig) -> Result<usize, RuntimeAbiError> {
    if depth >= config.max_recursion_depth() {
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

struct FieldScanState<'r> {
    required: &'r mut RequiredSeen,
    field_cursor: &'r mut usize,
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
