//! Fused, stack-safe schema validation.

use alloc::{string::String, vec::Vec};
use core::cmp::Ordering;
use core::fmt::Write as _;
use core::ops::Range;

use sacp_cbor::query::IntegerRef;
use sacp_cbor::{
    CanonicalCborRef, CborDecode, CborError, DecodeLimits, Decoder, ErrorCode, ScalarKind,
    TraversalSession, TraversalWorkspace,
};

use crate::compile::{
    cmp_field_key, CompiledConstraint, CompiledCoupling, RecordIdx, RecordSchema, TypeNode,
};
use crate::error::{ConstraintFault, Fault, RecordError, ShapeFault};
use crate::int::cmp_integer_ref_to_int;
use crate::ir::CountUnit;
use crate::ValidationOptions;

#[derive(Debug)]
enum ValidationFrame {
    RecordStart {
        record_idx: RecordIdx,
        path_base: usize,
    },
    RecordNext {
        record_idx: RecordIdx,
        map_offset: usize,
        field_pos: usize,
        presence_base: usize,
        path_base: usize,
        child_pending: bool,
    },
    Value {
        type_idx: usize,
        constraints: Range<usize>,
    },
    ArrayNext {
        inner: usize,
        set_order: bool,
        previous: Option<Range<usize>>,
        index: usize,
        path_base: usize,
        child_pending: bool,
        child_start: usize,
    },
    MapNext {
        inner: usize,
        path_base: usize,
        child_pending: bool,
    },
    UnionFinish {
        offset: usize,
        path_base: usize,
        child_pending: bool,
    },
    RestorePath(usize),
}

/// Caller-owned reusable scratch space for allocation-free successful validation.
#[derive(Debug, Default)]
pub struct ValidationWorkspace {
    presence: Vec<u64>,
    path: Vec<PathToken>,
    frames: Vec<ValidationFrame>,
    traversal: TraversalWorkspace,
    prepared_presence_words: usize,
    prepared_path_depth: usize,
    prepared_frame_capacity: usize,
    prepared_container_capacity: usize,
}

impl ValidationWorkspace {
    /// Construct an empty workspace.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            presence: Vec::new(),
            path: Vec::new(),
            frames: Vec::new(),
            traversal: TraversalWorkspace::new(),
            prepared_presence_words: 0,
            prepared_path_depth: 0,
            prepared_frame_capacity: 0,
            prepared_container_capacity: 0,
        }
    }

    /// Fallibly reserve all logical scratch capacity required by `schema`.
    ///
    /// # Errors
    ///
    /// Returns an allocation failure when any required arena cannot be reserved.
    pub fn prepare(&mut self, schema: &RecordSchema) -> Result<(), RecordError> {
        self.prepare_capacity(
            schema.workspace_presence_words,
            schema.workspace_path_depth,
            schema.workspace_frame_capacity,
            schema.workspace_container_capacity,
        )
    }

    /// Fallibly prepare for a validation pass with explicit decoder limits.
    ///
    /// Schemas containing `Any` admit container shapes deeper than their own structural graph, so
    /// their traversal workspace is sized from `limits.max_depth`. Other schemas retain their
    /// exact structural requirement.
    ///
    /// # Errors
    ///
    /// Returns an allocation failure when any required arena cannot be reserved.
    pub fn prepare_for_limits(
        &mut self,
        schema: &RecordSchema,
        limits: DecodeLimits,
    ) -> Result<(), RecordError> {
        limits.validate().map_err(RecordError::from)?;
        self.prepare_capacity(
            schema.workspace_presence_words,
            schema.workspace_path_depth,
            schema.workspace_frame_capacity,
            schema.required_container_capacity(limits),
        )
    }

    /// Fallibly reserve explicit logical capacities for reusable validation scratch.
    ///
    /// # Errors
    ///
    /// Returns an allocation failure when any requested arena cannot be reserved.
    pub fn prepare_capacity(
        &mut self,
        presence_words: usize,
        path_depth: usize,
        frame_capacity: usize,
        container_capacity: usize,
    ) -> Result<(), RecordError> {
        self.reset();
        reserve_exact(&mut self.presence, presence_words)?;
        reserve_exact(&mut self.path, path_depth)?;
        reserve_exact(&mut self.frames, frame_capacity)?;
        self.traversal
            .prepare(container_capacity)
            .map_err(RecordError::from)?;
        self.prepared_presence_words = presence_words;
        self.prepared_path_depth = path_depth;
        self.prepared_frame_capacity = frame_capacity;
        self.prepared_container_capacity = container_capacity;
        Ok(())
    }

    fn reset(&mut self) {
        self.presence.clear();
        self.path.clear();
        self.frames.clear();
    }
}

fn reserve_exact<T>(arena: &mut Vec<T>, required: usize) -> Result<(), RecordError> {
    if arena.capacity() < required {
        arena
            .try_reserve_exact(required - arena.len())
            .map_err(|_| allocation_error())?;
    }
    Ok(())
}

const fn allocation_error() -> RecordError {
    plain_error(
        0,
        Fault::Grammar(CborError::new(ErrorCode::AllocationFailed, 0)),
    )
}

const fn workspace_error() -> RecordError {
    plain_error(0, Fault::WorkspaceTooSmall)
}

const fn plain_error(offset: usize, fault: Fault) -> RecordError {
    RecordError {
        offset,
        path: Vec::new(),
        path_complete: true,
        fault,
    }
}

impl RecordSchema {
    /// Validate untrusted bytes as canonical SACP-CBOR/1 and check this schema in one traversal.
    ///
    /// # Errors
    ///
    /// Returns a grammar, schema, workspace, or allocation failure.
    pub fn validate<'de>(
        &self,
        bytes: &'de [u8],
        limits: DecodeLimits,
        options: ValidationOptions,
    ) -> Result<CanonicalCborRef<'de>, RecordError> {
        limits.validate().map_err(RecordError::from)?;
        let mut workspace = ValidationWorkspace::new();
        workspace.prepare_for_limits(self, limits)?;
        self.validate_with_workspace(bytes, limits, options, &mut workspace)
    }

    /// Validate untrusted bytes using caller-prepared reusable scratch space.
    ///
    /// # Errors
    ///
    /// Returns a grammar, schema, workspace, or diagnostic-allocation failure.
    pub fn validate_with_workspace<'de>(
        &self,
        bytes: &'de [u8],
        limits: DecodeLimits,
        options: ValidationOptions,
        workspace: &mut ValidationWorkspace,
    ) -> Result<CanonicalCborRef<'de>, RecordError> {
        limits.validate().map_err(RecordError::from)?;
        self.require_workspace(workspace, limits)?;
        workspace.reset();
        let mut decoder = Decoder::<true>::new_checked_with(bytes, limits, options)?;
        let mut traversal = core::mem::take(&mut workspace.traversal);
        let result = decoder.with_traversal(&mut traversal, |session| {
            CheckContext::new(self, bytes, workspace).run(session)
        });
        workspace.traversal = traversal;
        result?;
        decoder.finish().map_err(RecordError::from)
    }

    /// Check an already-validated canonical item against this schema.
    ///
    /// # Errors
    ///
    /// Returns a schema, workspace, or allocation failure.
    pub fn check(
        &self,
        value: CanonicalCborRef<'_>,
        limits: DecodeLimits,
    ) -> Result<(), RecordError> {
        limits.validate().map_err(RecordError::from)?;
        let mut workspace = ValidationWorkspace::new();
        workspace.prepare_for_limits(self, limits)?;
        self.check_with_workspace(value, limits, &mut workspace)
    }

    /// Check a canonical witness using caller-prepared reusable scratch space.
    ///
    /// # Errors
    ///
    /// Returns a schema, workspace, or diagnostic-allocation failure.
    pub fn check_with_workspace(
        &self,
        value: CanonicalCborRef<'_>,
        limits: DecodeLimits,
        workspace: &mut ValidationWorkspace,
    ) -> Result<(), RecordError> {
        limits.validate().map_err(RecordError::from)?;
        let bytes = value.as_bytes();
        self.require_workspace(workspace, limits)?;
        workspace.reset();
        let mut decoder = Decoder::<false>::new_trusted(value, limits)?;
        let mut traversal = core::mem::take(&mut workspace.traversal);
        let result = decoder.with_traversal(&mut traversal, |session| {
            CheckContext::new(self, bytes, workspace).run(session)
        });
        workspace.traversal = traversal;
        result?;
        if decoder.position() == bytes.len() {
            Ok(())
        } else {
            Err(plain_error(
                decoder.position(),
                Fault::Grammar(CborError::new(ErrorCode::TrailingBytes, decoder.position())),
            ))
        }
    }

    const fn require_workspace(
        &self,
        workspace: &ValidationWorkspace,
        limits: DecodeLimits,
    ) -> Result<(), RecordError> {
        if workspace.prepared_presence_words < self.workspace_presence_words
            || workspace.prepared_path_depth < self.workspace_path_depth
            || workspace.prepared_frame_capacity < self.workspace_frame_capacity
            || workspace.prepared_container_capacity < self.required_container_capacity(limits)
        {
            Err(workspace_error())
        } else {
            Ok(())
        }
    }

    const fn required_container_capacity(&self, limits: DecodeLimits) -> usize {
        if self.contains_any && limits.max_depth > self.workspace_container_capacity {
            limits.max_depth
        } else {
            self.workspace_container_capacity
        }
    }
}

#[derive(Debug)]
struct PendingError {
    offset: usize,
    fault: Fault,
}

struct CheckContext<'schema, 'de> {
    schema: &'schema RecordSchema,
    input: &'de [u8],
    workspace: &'schema mut ValidationWorkspace,
}

struct ConstraintTarget<'a> {
    integer: Option<IntegerRef<'a>>,
    count: Option<(CountUnit, u64)>,
    encoded: Option<&'a [u8]>,
}

impl<'a> ConstraintTarget<'a> {
    const fn int(value: IntegerRef<'a>, encoded: &'a [u8]) -> Self {
        Self {
            integer: Some(value),
            count: None,
            encoded: Some(encoded),
        }
    }

    fn octets(len: usize) -> Self {
        Self {
            integer: None,
            count: Some((CountUnit::Octets, u64::try_from(len).unwrap_or(u64::MAX))),
            encoded: None,
        }
    }

    fn text(len: usize, encoded: &'a [u8]) -> Self {
        Self {
            integer: None,
            count: Some((CountUnit::Octets, u64::try_from(len).unwrap_or(u64::MAX))),
            encoded: Some(encoded),
        }
    }

    fn elements(len: usize) -> Self {
        Self {
            integer: None,
            count: Some((CountUnit::Elements, u64::try_from(len).unwrap_or(u64::MAX))),
            encoded: None,
        }
    }
}

impl<'schema, 'de> CheckContext<'schema, 'de> {
    const fn new(
        schema: &'schema RecordSchema,
        input: &'de [u8],
        workspace: &'schema mut ValidationWorkspace,
    ) -> Self {
        Self {
            schema,
            input,
            workspace,
        }
    }

    fn run<const CHECKED: bool>(
        mut self,
        decoder: &mut TraversalSession<'_, 'de, '_, CHECKED>,
    ) -> Result<(), RecordError> {
        if let Err(error) = self.push_frame(ValidationFrame::RecordStart {
            record_idx: self.schema.root_record,
            path_base: 0,
        }) {
            return Err(self.finish_error(error));
        }
        while let Some(frame) = self.workspace.frames.pop() {
            if let Err(error) = self.step(decoder, frame) {
                return Err(self.finish_error(error));
            }
        }
        self.workspace.reset();
        Ok(())
    }

    fn step<const CHECKED: bool>(
        &mut self,
        decoder: &mut TraversalSession<'_, 'de, '_, CHECKED>,
        frame: ValidationFrame,
    ) -> Result<(), PendingError> {
        match frame {
            ValidationFrame::RestorePath(base) => {
                self.workspace.path.truncate(base);
                Ok(())
            }
            ValidationFrame::RecordStart {
                record_idx,
                path_base,
            } => self.start_record(decoder, record_idx, path_base),
            ValidationFrame::RecordNext {
                record_idx,
                map_offset,
                field_pos,
                presence_base,
                path_base,
                child_pending,
            } => self.next_record(
                decoder,
                record_idx,
                map_offset,
                field_pos,
                presence_base,
                path_base,
                child_pending,
            ),
            ValidationFrame::Value {
                type_idx,
                constraints,
            } => self.check_value(decoder, type_idx, constraints),
            ValidationFrame::ArrayNext {
                inner,
                set_order,
                previous,
                index,
                path_base,
                child_pending,
                child_start,
            } => self.next_array(
                decoder,
                inner,
                set_order,
                previous,
                index,
                path_base,
                child_pending,
                child_start,
            ),
            ValidationFrame::MapNext {
                inner,
                path_base,
                child_pending,
            } => self.next_map(decoder, inner, path_base, child_pending),
            ValidationFrame::UnionFinish {
                offset,
                path_base,
                child_pending,
            } => {
                if child_pending {
                    decoder
                        .array_child_complete()
                        .map_err(|error| self.grammar(error))?;
                }
                if decoder.array_next().map_err(|error| self.grammar(error))? {
                    return Err(self.shape(offset, ShapeFault::UnionArity));
                }
                decoder
                    .finish_array()
                    .map_err(|error| self.grammar(error))?;
                self.workspace.path.truncate(path_base);
                Ok(())
            }
        }
    }

    fn start_record<const CHECKED: bool>(
        &mut self,
        decoder: &mut TraversalSession<'_, 'de, '_, CHECKED>,
        record_idx: RecordIdx,
        path_base: usize,
    ) -> Result<(), PendingError> {
        let map_offset = decoder.position();
        decoder
            .begin_map()
            .map_err(|error| self.value_fault(error))?;
        let record = self.schema.record(record_idx);
        let words = record.fields.len().div_ceil(64);
        let presence_base = self.workspace.presence.len();
        let presence_end = presence_base
            .checked_add(words)
            .ok_or_else(|| self.grammar_code(ErrorCode::LengthOverflow, map_offset))?;
        if presence_end > self.workspace.prepared_presence_words {
            return Err(self.workspace_fault(map_offset));
        }
        self.workspace.presence.resize(presence_end, 0);
        self.push_frame(ValidationFrame::RecordNext {
            record_idx,
            map_offset,
            field_pos: 0,
            presence_base,
            path_base,
            child_pending: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn next_record<const CHECKED: bool>(
        &mut self,
        decoder: &mut TraversalSession<'_, 'de, '_, CHECKED>,
        record_idx: RecordIdx,
        map_offset: usize,
        mut field_pos: usize,
        presence_base: usize,
        path_base: usize,
        child_pending: bool,
    ) -> Result<(), PendingError> {
        if child_pending {
            decoder
                .map_value_complete()
                .map_err(|error| self.grammar(error))?;
        }
        let record = self.schema.record(record_idx);
        let fields = self.schema.fields_for(record);
        let Some(key) = decoder
            .map_next_key()
            .map_err(|error| self.grammar(error))?
        else {
            let presence = &self.workspace.presence[presence_base..];
            if self.schema.required_fields[record.required.clone()]
                .iter()
                .any(|index| !is_present(presence, *index))
            {
                return Err(self.shape(map_offset, ShapeFault::MissingField));
            }
            self.check_couplings(presence, &record.couplings, map_offset)?;
            decoder.finish_map().map_err(|error| self.grammar(error))?;
            self.workspace.presence.truncate(presence_base);
            self.workspace.path.truncate(path_base);
            return Ok(());
        };
        let field = loop {
            let Some(field) = fields.get(field_pos) else {
                return Err(self.shape(key.offset, ShapeFault::UnknownKey));
            };
            match cmp_field_key(key.text, &field.key) {
                Ordering::Less => return Err(self.shape(key.offset, ShapeFault::UnknownKey)),
                Ordering::Greater => {
                    if field.required {
                        return Err(self.shape(map_offset, ShapeFault::MissingField));
                    }
                    field_pos += 1;
                }
                Ordering::Equal => break field,
            }
        };
        mark_present(
            &mut self.workspace.presence[presence_base..],
            field.presence_index,
        );
        decoder.map_value().map_err(|error| self.grammar(error))?;
        self.push_frame(ValidationFrame::RecordNext {
            record_idx,
            map_offset,
            field_pos: field_pos + 1,
            presence_base,
            path_base,
            child_pending: true,
        })?;
        self.push_frame(ValidationFrame::RestorePath(path_base))?;
        self.push_path(
            PathToken::Field(record.fields.start + field_pos),
            key.offset,
        )?;
        self.push_frame(ValidationFrame::Value {
            type_idx: field.type_idx,
            constraints: field.constraints.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn next_array<const CHECKED: bool>(
        &mut self,
        decoder: &mut TraversalSession<'_, 'de, '_, CHECKED>,
        inner: usize,
        set_order: bool,
        mut previous: Option<Range<usize>>,
        index: usize,
        path_base: usize,
        child_pending: bool,
        child_start: usize,
    ) -> Result<(), PendingError> {
        if child_pending {
            decoder
                .array_child_complete()
                .map_err(|error| self.grammar(error))?;
            let end = decoder.position();
            if set_order {
                let current = self.span(child_start..end)?;
                if let Some(previous_range) = previous.clone() {
                    match self.span(previous_range)?.cmp(current) {
                        Ordering::Less => {}
                        Ordering::Equal => {
                            self.push_path(
                                PathToken::Index(index.checked_sub(1).ok_or_else(|| {
                                    self.grammar_code(ErrorCode::LengthOverflow, child_start)
                                })?),
                                child_start,
                            )?;
                            return Err(self.shape(child_start, ShapeFault::SetDuplicate));
                        }
                        Ordering::Greater => {
                            self.push_path(
                                PathToken::Index(index.checked_sub(1).ok_or_else(|| {
                                    self.grammar_code(ErrorCode::LengthOverflow, child_start)
                                })?),
                                child_start,
                            )?;
                            return Err(self.shape(child_start, ShapeFault::SetOrder));
                        }
                    }
                }
                previous = Some(child_start..end);
            }
        }
        if !decoder.array_next().map_err(|error| self.grammar(error))? {
            decoder
                .finish_array()
                .map_err(|error| self.grammar(error))?;
            self.workspace.path.truncate(path_base);
            return Ok(());
        }
        let start = decoder.position();
        self.push_frame(ValidationFrame::ArrayNext {
            inner,
            set_order,
            previous,
            index: index
                .checked_add(1)
                .ok_or_else(|| self.grammar_code(ErrorCode::LengthOverflow, start))?,
            path_base,
            child_pending: true,
            child_start: start,
        })?;
        self.push_frame(ValidationFrame::RestorePath(path_base))?;
        self.push_path(PathToken::Index(index), start)?;
        self.push_frame(ValidationFrame::Value {
            type_idx: inner,
            constraints: 0..0,
        })
    }

    fn next_map<const CHECKED: bool>(
        &mut self,
        decoder: &mut TraversalSession<'_, 'de, '_, CHECKED>,
        inner: usize,
        path_base: usize,
        child_pending: bool,
    ) -> Result<(), PendingError> {
        if child_pending {
            decoder
                .map_value_complete()
                .map_err(|error| self.grammar(error))?;
        }
        let Some(key) = decoder
            .map_next_key()
            .map_err(|error| self.grammar(error))?
        else {
            decoder.finish_map().map_err(|error| self.grammar(error))?;
            self.workspace.path.truncate(path_base);
            return Ok(());
        };
        decoder.map_value().map_err(|error| self.grammar(error))?;
        let start = key.text.as_ptr() as usize - self.input.as_ptr() as usize;
        self.push_frame(ValidationFrame::MapNext {
            inner,
            path_base,
            child_pending: true,
        })?;
        self.push_frame(ValidationFrame::RestorePath(path_base))?;
        self.push_path(
            PathToken::Text {
                start,
                len: key.text.len(),
            },
            key.offset,
        )?;
        self.push_frame(ValidationFrame::Value {
            type_idx: inner,
            constraints: 0..0,
        })
    }

    fn check_value<const CHECKED: bool>(
        &mut self,
        decoder: &mut TraversalSession<'_, 'de, '_, CHECKED>,
        type_idx: usize,
        constraints: Range<usize>,
    ) -> Result<(), PendingError> {
        match self.schema.type_node(type_idx).clone() {
            TypeNode::Int => {
                if constraints.is_empty() {
                    return decoder
                        .skip_scalar(ScalarKind::Integer)
                        .map_err(|error| self.value_fault(error));
                }
                let offset = decoder.position();
                let integer =
                    IntegerRef::decode(decoder).map_err(|error| self.value_fault(error))?;
                let encoded = self.span(offset..decoder.position())?;
                self.apply_constraints(
                    &ConstraintTarget::int(integer, encoded),
                    constraints,
                    offset,
                )
            }
            TypeNode::Bool => decoder
                .skip_scalar(ScalarKind::Bool)
                .map_err(|error| self.value_fault(error)),
            TypeNode::Float64 => decoder
                .skip_scalar(ScalarKind::Float)
                .map_err(|error| self.value_fault(error)),
            TypeNode::Bytes => {
                if constraints.is_empty() {
                    return decoder
                        .skip_scalar(ScalarKind::Bytes)
                        .map_err(|error| self.value_fault(error));
                }
                let offset = decoder.position();
                let value = <&[u8]>::decode(decoder).map_err(|error| self.value_fault(error))?;
                self.apply_constraints(&ConstraintTarget::octets(value.len()), constraints, offset)
            }
            TypeNode::Text => {
                if constraints.is_empty() {
                    return decoder
                        .skip_scalar(ScalarKind::Text)
                        .map_err(|error| self.value_fault(error));
                }
                let offset = decoder.position();
                let value = <&str>::decode(decoder).map_err(|error| self.value_fault(error))?;
                let encoded = self.span(offset..decoder.position())?;
                self.apply_constraints(
                    &ConstraintTarget::text(value.len(), encoded),
                    constraints,
                    offset,
                )
            }
            TypeNode::Array(inner) => self.begin_array(decoder, inner, constraints, false),
            TypeNode::Set(inner) => self.begin_array(decoder, inner, constraints, true),
            TypeNode::Map(inner) => {
                let offset = decoder.position();
                decoder
                    .begin_map()
                    .map_err(|error| self.value_fault(error))?;
                self.apply_constraints(
                    &ConstraintTarget::elements(
                        decoder
                            .map_remaining()
                            .map_err(|error| self.grammar(error))?,
                    ),
                    constraints,
                    offset,
                )?;
                self.push_frame(ValidationFrame::MapNext {
                    inner,
                    path_base: self.workspace.path.len(),
                    child_pending: false,
                })
            }
            TypeNode::Record(record_idx) => self.push_frame(ValidationFrame::RecordStart {
                record_idx,
                path_base: self.workspace.path.len(),
            }),
            TypeNode::Union(alternatives) => self.begin_union(decoder, alternatives),
            TypeNode::Any => decoder
                .skip_value_prepared()
                .map_err(|error| self.grammar(error)),
        }
    }

    fn begin_array<const CHECKED: bool>(
        &mut self,
        decoder: &mut TraversalSession<'_, 'de, '_, CHECKED>,
        inner: usize,
        constraints: Range<usize>,
        set_order: bool,
    ) -> Result<(), PendingError> {
        let offset = decoder.position();
        decoder
            .begin_array()
            .map_err(|error| self.value_fault(error))?;
        self.apply_constraints(
            &ConstraintTarget::elements(
                decoder
                    .array_remaining()
                    .map_err(|error| self.grammar(error))?,
            ),
            constraints,
            offset,
        )?;
        self.push_frame(ValidationFrame::ArrayNext {
            inner,
            set_order,
            previous: None,
            index: 0,
            path_base: self.workspace.path.len(),
            child_pending: false,
            child_start: 0,
        })
    }

    fn begin_union<const CHECKED: bool>(
        &mut self,
        decoder: &mut TraversalSession<'_, 'de, '_, CHECKED>,
        alternatives: Range<usize>,
    ) -> Result<(), PendingError> {
        let offset = decoder.position();
        decoder
            .begin_array()
            .map_err(|error| self.value_fault(error))?;
        let arity = decoder
            .array_remaining()
            .map_err(|error| self.grammar(error))?;
        if arity != 1 && arity != 2 {
            return Err(self.shape(offset, ShapeFault::UnionArity));
        }
        if !decoder.array_next().map_err(|error| self.grammar(error))? {
            return Err(self.shape(offset, ShapeFault::UnionArity));
        }
        let code_offset = decoder.position();
        let path_base = self.workspace.path.len();
        self.push_path(PathToken::Index(0), code_offset)?;
        let integer = IntegerRef::decode(decoder).map_err(|error| self.value_fault(error))?;
        decoder
            .array_child_complete()
            .map_err(|error| self.grammar(error))?;
        let code = integer
            .as_u128()
            .and_then(|raw| u64::try_from(raw).ok())
            .ok_or_else(|| self.shape(code_offset, ShapeFault::WrongKind))?;
        let alternatives = self.schema.union_alts_for(alternatives);
        let alternative = alternatives
            .binary_search_by_key(&code, |alternative| alternative.code)
            .ok()
            .and_then(|index| alternatives.get(index))
            .cloned()
            .ok_or_else(|| self.shape(offset, ShapeFault::UnionCodeUnknown))?;
        self.workspace.path.truncate(path_base);
        match (alternative.payload, arity) {
            (None, 1) => decoder.finish_array().map_err(|error| self.grammar(error)),
            (Some(payload), 2) => {
                if !decoder.array_next().map_err(|error| self.grammar(error))? {
                    return Err(self.shape(offset, ShapeFault::UnionArity));
                }
                if let Some(kind) = alternative.payload_scalar {
                    self.push_path(PathToken::Index(1), decoder.position())?;
                    decoder
                        .skip_scalar(kind)
                        .map_err(|error| self.value_fault(error))?;
                    decoder
                        .array_child_complete()
                        .map_err(|error| self.grammar(error))?;
                    self.workspace.path.truncate(path_base);
                    return decoder.finish_array().map_err(|error| self.grammar(error));
                }
                self.push_frame(ValidationFrame::UnionFinish {
                    offset,
                    path_base,
                    child_pending: true,
                })?;
                self.push_frame(ValidationFrame::RestorePath(path_base))?;
                self.push_path(PathToken::Index(1), decoder.position())?;
                self.push_frame(ValidationFrame::Value {
                    type_idx: payload,
                    constraints: 0..0,
                })
            }
            _ => Err(self.shape(offset, ShapeFault::UnionArity)),
        }
    }

    fn apply_constraints(
        &self,
        target: &ConstraintTarget<'_>,
        constraints: Range<usize>,
        offset: usize,
    ) -> Result<(), PendingError> {
        for constraint in self.schema.constraints_for(constraints) {
            match constraint {
                CompiledConstraint::Range { min, max } => {
                    let Some(value) = target.integer else {
                        continue;
                    };
                    if min
                        .as_ref()
                        .is_some_and(|bound| cmp_integer_ref_to_int(value, bound) == Ordering::Less)
                    {
                        return Err(self.constraint(offset, ConstraintFault::RangeBelow));
                    }
                    if max.as_ref().is_some_and(|bound| {
                        cmp_integer_ref_to_int(value, bound) == Ordering::Greater
                    }) {
                        return Err(self.constraint(offset, ConstraintFault::RangeAbove));
                    }
                }
                CompiledConstraint::Count { unit, min, max } => {
                    let Some((target_unit, count)) = target.count else {
                        continue;
                    };
                    if *unit == target_unit {
                        if min.is_some_and(|value| count < value) {
                            return Err(self.constraint(offset, ConstraintFault::CountBelow));
                        }
                        if max.is_some_and(|value| count > value) {
                            return Err(self.constraint(offset, ConstraintFault::CountAbove));
                        }
                    }
                }
                CompiledConstraint::Enum { members } => {
                    let Some(encoded) = target.encoded else {
                        continue;
                    };
                    if self.schema.enum_members[members.clone()]
                        .binary_search_by(|range| {
                            self.schema.enum_bytes[range.clone()].cmp(encoded)
                        })
                        .is_err()
                    {
                        return Err(self.constraint(offset, ConstraintFault::EnumMismatch));
                    }
                }
            }
        }
        Ok(())
    }

    fn check_couplings(
        &self,
        presence: &[u64],
        couplings: &Range<usize>,
        offset: usize,
    ) -> Result<(), PendingError> {
        for coupling in &self.schema.couplings[couplings.clone()] {
            match coupling {
                CompiledCoupling::Requires {
                    if_index,
                    then_index,
                } if is_present(presence, *if_index) && !is_present(presence, *then_index) => {
                    return Err(self.constraint(offset, ConstraintFault::CouplingRequires));
                }
                CompiledCoupling::ExactlyOne { indices }
                    if self.schema.coupling_indices[indices.clone()]
                        .iter()
                        .filter(|index| is_present(presence, **index))
                        .count()
                        != 1 =>
                {
                    return Err(self.constraint(offset, ConstraintFault::CouplingExactlyOne));
                }
                CompiledCoupling::Together { indices } => {
                    let values = &self.schema.coupling_indices[indices.clone()];
                    let count = values
                        .iter()
                        .filter(|index| is_present(presence, **index))
                        .count();
                    if count != 0 && count != values.len() {
                        return Err(self.constraint(offset, ConstraintFault::CouplingTogether));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn push_frame(&mut self, frame: ValidationFrame) -> Result<(), PendingError> {
        if self.workspace.frames.len() >= self.workspace.prepared_frame_capacity {
            return Err(self.workspace_fault(0));
        }
        self.workspace.frames.push(frame);
        Ok(())
    }

    fn push_path(&mut self, token: PathToken, offset: usize) -> Result<(), PendingError> {
        if self.workspace.path.len() >= self.workspace.prepared_path_depth {
            return Err(self.workspace_fault(offset));
        }
        self.workspace.path.push(token);
        Ok(())
    }

    fn span(&self, range: Range<usize>) -> Result<&'de [u8], PendingError> {
        self.input.get(range.clone()).ok_or_else(|| {
            self.grammar_code(
                ErrorCode::MalformedCanonical,
                range.start.min(self.input.len()),
            )
        })
    }

    const fn value_fault(&self, error: CborError) -> PendingError {
        match error.code {
            ErrorCode::ExpectedInteger
            | ErrorCode::ExpectedBytes
            | ErrorCode::ExpectedText
            | ErrorCode::ExpectedBool
            | ErrorCode::ExpectedFloat
            | ErrorCode::ExpectedNull
            | ErrorCode::ExpectedArray
            | ErrorCode::ExpectedMap => self.shape(error.offset, ShapeFault::WrongKind),
            _ => self.grammar(error),
        }
    }

    #[allow(clippy::unused_self)]
    const fn grammar(&self, error: CborError) -> PendingError {
        PendingError {
            offset: error.offset,
            fault: Fault::Grammar(error),
        }
    }

    const fn grammar_code(&self, code: ErrorCode, offset: usize) -> PendingError {
        self.grammar(CborError::new(code, offset))
    }

    #[allow(clippy::unused_self)]
    const fn shape(&self, offset: usize, fault: ShapeFault) -> PendingError {
        PendingError {
            offset,
            fault: Fault::Shape(fault),
        }
    }

    #[allow(clippy::unused_self)]
    const fn constraint(&self, offset: usize, fault: ConstraintFault) -> PendingError {
        PendingError {
            offset,
            fault: Fault::Constraint(fault),
        }
    }

    #[allow(clippy::unused_self)]
    const fn workspace_fault(&self, offset: usize) -> PendingError {
        PendingError {
            offset,
            fault: Fault::WorkspaceTooSmall,
        }
    }

    fn finish_error(&mut self, pending: PendingError) -> RecordError {
        let (path, path_complete) = self.materialize_path();
        self.workspace.reset();
        RecordError {
            offset: pending.offset,
            path,
            path_complete,
            fault: pending.fault,
        }
    }

    fn materialize_path(&self) -> (Vec<String>, bool) {
        let mut output = Vec::new();
        if output.try_reserve_exact(self.workspace.path.len()).is_err() {
            return (output, false);
        }
        for token in &self.workspace.path {
            let Ok(segment) = self.materialize_token(*token) else {
                return (output, false);
            };
            output.push(segment);
        }
        (output, true)
    }

    fn materialize_token(&self, token: PathToken) -> Result<String, ()> {
        match token {
            PathToken::Field(index) => try_string(&self.schema.fields[index].key),
            PathToken::Text { start, len } => {
                let end = start.checked_add(len).ok_or(())?;
                let text = self
                    .input
                    .get(start..end)
                    .and_then(|bytes| core::str::from_utf8(bytes).ok())
                    .ok_or(())?;
                try_string(text)
            }
            PathToken::Index(index) => {
                let mut output = String::new();
                output.try_reserve_exact(22).map_err(|_| ())?;
                write!(&mut output, "[{index}]").map_err(|_| ())?;
                Ok(output)
            }
        }
    }
}

fn try_string(value: &str) -> Result<String, ()> {
    let mut output = String::new();
    output.try_reserve_exact(value.len()).map_err(|_| ())?;
    output.push_str(value);
    Ok(output)
}

#[derive(Clone, Copy, Debug)]
enum PathToken {
    Field(usize),
    Text { start: usize, len: usize },
    Index(usize),
}

fn mark_present(words: &mut [u64], index: usize) {
    words[index / 64] |= 1u64 << (index % 64);
}

fn is_present(words: &[u64], index: usize) -> bool {
    words
        .get(index / 64)
        .is_some_and(|word| word & (1u64 << (index % 64)) != 0)
}
