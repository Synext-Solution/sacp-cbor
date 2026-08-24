//! Schema compilation into validation arenas.

use alloc::{boxed::Box, string::String, vec::Vec};
use core::cmp::Ordering;
use core::ops::Range;

use sacp_cbor::profile::cmp_text_keys_canonical;
use sacp_cbor::{EncodeError, Encoder, ScalarKind};

use crate::error::SchemaError;
use crate::ir::{Constraint, CountUnit, Coupling, EnumMember, FieldDef, FieldType, RecordDef};
use crate::{Int, SchemaCompileLimits, MIN_COUPLING_KEYS};

pub(crate) type TypeIdx = usize;
pub(crate) type RecordIdx = usize;

/// Compiled closed-record schema.
#[derive(Clone, Debug)]
pub struct RecordSchema {
    pub(crate) types: Vec<TypeNode>,
    pub(crate) records: Vec<CompiledRecord>,
    pub(crate) fields: Vec<CompiledField>,
    pub(crate) required_fields: Vec<usize>,
    pub(crate) constraints: Vec<CompiledConstraint>,
    pub(crate) enum_members: Vec<Range<usize>>,
    pub(crate) enum_bytes: Vec<u8>,
    pub(crate) union_alts: Vec<CompiledUnionAlt>,
    pub(crate) couplings: Vec<CompiledCoupling>,
    pub(crate) coupling_indices: Vec<usize>,
    pub(crate) root_record: RecordIdx,
    pub(crate) workspace_presence_words: usize,
    pub(crate) workspace_path_depth: usize,
    pub(crate) workspace_frame_capacity: usize,
    pub(crate) workspace_container_capacity: usize,
    pub(crate) contains_any: bool,
}

#[derive(Clone, Debug)]
pub(crate) enum TypeNode {
    Int,
    Bool,
    Float64,
    Bytes,
    Text,
    Array(TypeIdx),
    Set(TypeIdx),
    Map(TypeIdx),
    Union(Range<usize>),
    Record(RecordIdx),
    Any,
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledRecord {
    pub(crate) fields: Range<usize>,
    pub(crate) required: Range<usize>,
    pub(crate) couplings: Range<usize>,
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledField {
    pub(crate) key: Box<str>,
    pub(crate) type_idx: TypeIdx,
    pub(crate) required: bool,
    pub(crate) presence_index: usize,
    pub(crate) constraints: Range<usize>,
}

#[derive(Clone, Debug)]
pub(crate) enum CompiledConstraint {
    Range {
        min: Option<Int>,
        max: Option<Int>,
    },
    Count {
        unit: CountUnit,
        min: Option<u64>,
        max: Option<u64>,
    },
    Enum {
        members: Range<usize>,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledUnionAlt {
    pub(crate) code: u64,
    pub(crate) payload: Option<TypeIdx>,
    /// The payload's scalar kind when the payload is a leaf scalar,
    /// resolved at compile time so validation consumes it through the
    /// direct scalar funnel without a per-value dispatch.
    pub(crate) payload_scalar: Option<ScalarKind>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompiledCoupling {
    Requires { if_index: usize, then_index: usize },
    ExactlyOne { indices: Range<usize> },
    Together { indices: Range<usize> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValueKind {
    Int,
    Bool,
    Float64,
    Bytes,
    Text,
    Array,
    Set,
    Map,
    Union,
    Record,
    Any,
}

impl RecordSchema {
    /// Return required presence-word and path-token workspace capacities.
    #[must_use]
    pub const fn workspace_requirements(&self) -> (usize, usize, usize) {
        (
            self.workspace_presence_words,
            self.workspace_path_depth,
            self.workspace_frame_capacity,
        )
    }

    /// Return the number of simultaneously open decoder containers required by this schema's
    /// structural traversal.
    #[must_use]
    pub const fn workspace_container_capacity(&self) -> usize {
        self.workspace_container_capacity
    }

    /// Compile a source-form record schema.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaError`] when the source schema exceeds a fixed cap, contains duplicate
    /// declarations, applies a constraint to the wrong kind, or otherwise violates the model.
    pub fn compile(def: &RecordDef, limits: SchemaCompileLimits) -> Result<Self, SchemaError> {
        let requirements = preflight(def, limits)?;
        let mut compiler = Compiler::new(limits, requirements)?;
        let root_record = compiler.compile_root(def, requirements)?;
        let validation = validation_requirements(&compiler, root_record)?;
        let contains_any = compiler
            .types
            .iter()
            .any(|node| matches!(node, TypeNode::Any));
        Ok(Self {
            types: compiler.types,
            records: compiler.records,
            fields: compiler.fields,
            required_fields: compiler.required_fields,
            constraints: compiler.constraints,
            enum_members: compiler.enum_members,
            enum_bytes: compiler.enum_bytes,
            union_alts: compiler.union_alts,
            couplings: compiler.couplings,
            coupling_indices: compiler.coupling_indices,
            root_record,
            workspace_presence_words: compiler.workspace_presence_words,
            workspace_path_depth: compiler.workspace_path_depth,
            workspace_frame_capacity: validation.frames,
            workspace_container_capacity: validation.containers,
            contains_any,
        })
    }

    pub(crate) fn record(&self, idx: RecordIdx) -> &CompiledRecord {
        &self.records[idx]
    }

    pub(crate) fn type_node(&self, idx: TypeIdx) -> &TypeNode {
        &self.types[idx]
    }

    pub(crate) fn fields_for(&self, record: &CompiledRecord) -> &[CompiledField] {
        &self.fields[record.fields.clone()]
    }

    pub(crate) fn constraints_for(&self, range: Range<usize>) -> &[CompiledConstraint] {
        &self.constraints[range]
    }

    pub(crate) fn union_alts_for(&self, range: Range<usize>) -> &[CompiledUnionAlt] {
        &self.union_alts[range]
    }

    pub(crate) fn couplings_for(&self, record: &CompiledRecord) -> &[CompiledCoupling] {
        &self.couplings[record.couplings.clone()]
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct CompileRequirements {
    types: usize,
    records: usize,
    fields: usize,
    required_fields: usize,
    constraints: usize,
    enum_members: usize,
    enum_bytes: usize,
    union_alts: usize,
    couplings: usize,
    coupling_indices: usize,
    owned_bytes: usize,
    max_path_depth: usize,
    max_sort_width: usize,
}

impl CompileRequirements {
    fn charge_nodes(&self, limits: SchemaCompileLimits) -> Result<(), SchemaError> {
        let counts = [
            self.types,
            self.records,
            self.fields,
            self.required_fields,
            self.constraints,
            self.enum_members,
            self.union_alts,
            self.couplings,
            self.coupling_indices,
        ];
        let mut total = 0usize;
        for count in counts {
            total = total
                .checked_add(count)
                .ok_or(SchemaError::TotalNodeLimitExceeded { count: usize::MAX })?;
        }
        if total > limits.max_total_nodes {
            return Err(SchemaError::TotalNodeLimitExceeded { count: total });
        }
        if self.owned_bytes > limits.max_total_owned_bytes {
            return Err(SchemaError::OwnedByteLimitExceeded {
                count: self.owned_bytes,
            });
        }
        Ok(())
    }

    fn add(slot: &mut usize, count: usize) -> Result<(), SchemaError> {
        *slot = slot
            .checked_add(count)
            .ok_or(SchemaError::TotalNodeLimitExceeded { count: usize::MAX })?;
        Ok(())
    }

    fn add_owned(&mut self, count: usize) -> Result<(), SchemaError> {
        self.owned_bytes = self
            .owned_bytes
            .checked_add(count)
            .ok_or(SchemaError::OwnedByteLimitExceeded { count: usize::MAX })?;
        Ok(())
    }

    const fn check_owned(&self, limits: SchemaCompileLimits) -> Result<(), SchemaError> {
        if self.owned_bytes > limits.max_total_owned_bytes {
            Err(SchemaError::OwnedByteLimitExceeded {
                count: self.owned_bytes,
            })
        } else {
            Ok(())
        }
    }
}

enum PreflightTask<'a> {
    Record(&'a RecordDef, usize),
    Field(&'a FieldDef, usize),
    Type(&'a FieldType, usize),
    PushPath(&'a str),
    PopPath,
}

#[allow(clippy::too_many_lines)]
fn preflight(
    root: &RecordDef,
    limits: SchemaCompileLimits,
) -> Result<CompileRequirements, SchemaError> {
    preflight_root_owned_lower_bound(root, limits)?;
    let mut requirements = CompileRequirements::default();
    let mut tasks = Vec::new();
    let mut path = Vec::new();
    push_preflight_task(&mut tasks, PreflightTask::Record(root, 0), limits)?;
    while let Some(task) = tasks.pop() {
        match task {
            PreflightTask::PushPath(segment) => {
                path.try_reserve(1)
                    .map_err(|_| SchemaError::AllocationFailed)?;
                path.push(segment);
                requirements.max_path_depth = requirements.max_path_depth.max(path.len());
            }
            PreflightTask::PopPath => {
                let _ = path.pop();
            }
            PreflightTask::Record(def, depth) => {
                check_preflight_depth(depth, limits)?;
                requirements.max_sort_width = requirements.max_sort_width.max(def.fields.len());
                if def.fields.len() > limits.max_fields_per_record {
                    return Err(SchemaError::FieldCapExceeded {
                        path: preflight_path_name(&path)?,
                        count: def.fields.len(),
                    });
                }
                if def.couplings.len() > limits.max_couplings_per_record {
                    return Err(SchemaError::CouplingCapExceeded {
                        path: preflight_path_name(&path)?,
                        count: def.couplings.len(),
                    });
                }
                CompileRequirements::add(&mut requirements.records, 1)?;
                CompileRequirements::add(&mut requirements.fields, def.fields.len())?;
                CompileRequirements::add(&mut requirements.couplings, def.couplings.len())?;
                for coupling in &def.couplings {
                    if let Coupling::ExactlyOne(keys) | Coupling::Together(keys) = coupling {
                        CompileRequirements::add(&mut requirements.coupling_indices, keys.len())?;
                    }
                }
                requirements.charge_nodes(limits)?;
                requirements.add_owned(
                    def.fields
                        .iter()
                        .try_fold(0usize, |sum, field| sum.checked_add(field.key.len()))
                        .ok_or(SchemaError::OwnedByteLimitExceeded { count: usize::MAX })?,
                )?;
                requirements.check_owned(limits)?;
                let child_depth = depth
                    .checked_add(1)
                    .ok_or(SchemaError::NestingDepthExceeded { depth: usize::MAX })?;
                for field in def.fields.iter().rev() {
                    push_preflight_task(&mut tasks, PreflightTask::PopPath, limits)?;
                    push_preflight_task(
                        &mut tasks,
                        PreflightTask::Field(field, child_depth),
                        limits,
                    )?;
                    push_preflight_task(&mut tasks, PreflightTask::PushPath(&field.key), limits)?;
                }
            }
            PreflightTask::Field(field, depth) => {
                if field.constraints.len() > limits.max_constraints_per_field {
                    return Err(SchemaError::ConstraintCapExceeded {
                        field: preflight_path_name(&path)?,
                        count: field.constraints.len(),
                    });
                }
                CompileRequirements::add(
                    &mut requirements.required_fields,
                    usize::from(field.required),
                )?;
                CompileRequirements::add(&mut requirements.constraints, field.constraints.len())?;
                requirements.charge_nodes(limits)?;
                for constraint in &field.constraints {
                    match constraint {
                        Constraint::Range { min, max } => {
                            if let Some(value) = min {
                                requirements.add_owned(value.magnitude().len())?;
                                requirements.check_owned(limits)?;
                            }
                            if let Some(value) = max {
                                requirements.add_owned(value.magnitude().len())?;
                                requirements.check_owned(limits)?;
                            }
                        }
                        Constraint::Enum(members) => {
                            CompileRequirements::add(
                                &mut requirements.enum_members,
                                members.len(),
                            )?;
                            requirements.charge_nodes(limits)?;
                            for member in members {
                                let encoded_len = enum_member_encoded_len(member)?;
                                requirements.add_owned(encoded_len)?;
                                CompileRequirements::add(
                                    &mut requirements.enum_bytes,
                                    encoded_len,
                                )?;
                                requirements.check_owned(limits)?;
                            }
                        }
                        Constraint::Count { .. } => {}
                    }
                }
                requirements.charge_nodes(limits)?;
                push_preflight_task(&mut tasks, PreflightTask::Type(&field.ty, depth), limits)?;
            }
            PreflightTask::Type(ty, depth) => {
                check_preflight_depth(depth, limits)?;
                CompileRequirements::add(&mut requirements.types, 1)?;
                requirements.charge_nodes(limits)?;
                let child_depth = depth
                    .checked_add(1)
                    .ok_or(SchemaError::NestingDepthExceeded { depth: usize::MAX })?;
                match ty {
                    FieldType::Array(inner) | FieldType::Set(inner) | FieldType::Map(inner) => {
                        push_preflight_task(
                            &mut tasks,
                            PreflightTask::Type(inner, child_depth),
                            limits,
                        )?;
                    }
                    FieldType::Union(alts) => {
                        requirements.max_sort_width = requirements.max_sort_width.max(alts.len());
                        if alts.len() > limits.max_union_alternatives {
                            return Err(SchemaError::UnionAltCapExceeded {
                                path: preflight_path_name(&path)?,
                                count: alts.len(),
                            });
                        }
                        CompileRequirements::add(&mut requirements.union_alts, alts.len())?;
                        requirements.charge_nodes(limits)?;
                        for alt in alts {
                            if let Some(payload) = &alt.payload {
                                push_preflight_task(
                                    &mut tasks,
                                    PreflightTask::Type(payload, child_depth),
                                    limits,
                                )?;
                            }
                        }
                    }
                    FieldType::Record(record) => {
                        push_preflight_task(
                            &mut tasks,
                            PreflightTask::Record(record, child_depth),
                            limits,
                        )?;
                    }
                    _ => {}
                }
            }
        }
        requirements.charge_nodes(limits)?;
    }
    requirements.charge_nodes(limits)?;
    Ok(requirements)
}

fn preflight_root_owned_lower_bound(
    root: &RecordDef,
    limits: SchemaCompileLimits,
) -> Result<(), SchemaError> {
    let mut owned = 0usize;
    for field in &root.fields {
        owned = owned
            .checked_add(field.key.len())
            .ok_or(SchemaError::OwnedByteLimitExceeded { count: usize::MAX })?;
        for constraint in &field.constraints {
            match constraint {
                Constraint::Range { min, max } => {
                    for value in [min, max].into_iter().flatten() {
                        owned = owned
                            .checked_add(value.magnitude().len())
                            .ok_or(SchemaError::OwnedByteLimitExceeded { count: usize::MAX })?;
                    }
                }
                Constraint::Enum(members) => {
                    for member in members {
                        owned = owned
                            .checked_add(enum_member_encoded_len(member)?)
                            .ok_or(SchemaError::OwnedByteLimitExceeded { count: usize::MAX })?;
                    }
                }
                Constraint::Count { .. } => {}
            }
        }
        if owned > limits.max_total_owned_bytes {
            return Err(SchemaError::OwnedByteLimitExceeded { count: owned });
        }
    }
    Ok(())
}

fn push_preflight_task<'a>(
    tasks: &mut Vec<PreflightTask<'a>>,
    task: PreflightTask<'a>,
    _limits: SchemaCompileLimits,
) -> Result<(), SchemaError> {
    tasks
        .try_reserve(1)
        .map_err(|_| SchemaError::AllocationFailed)?;
    tasks.push(task);
    Ok(())
}

fn preflight_path_name(path: &[&str]) -> Result<String, SchemaError> {
    if path.is_empty() {
        return try_clone_string("$");
    }
    let separators = path
        .len()
        .checked_sub(1)
        .ok_or(SchemaError::AllocationFailed)?;
    let payload = path
        .iter()
        .try_fold(0usize, |sum, segment| sum.checked_add(segment.len()))
        .and_then(|sum| sum.checked_add(separators))
        .ok_or(SchemaError::AllocationFailed)?;
    let mut result = String::new();
    result
        .try_reserve_exact(payload)
        .map_err(|_| SchemaError::AllocationFailed)?;
    for (index, segment) in path.iter().enumerate() {
        if index != 0 {
            result.push('.');
        }
        result.push_str(segment);
    }
    Ok(result)
}

const fn check_preflight_depth(
    depth: usize,
    limits: SchemaCompileLimits,
) -> Result<(), SchemaError> {
    if depth > limits.max_schema_depth {
        Err(SchemaError::NestingDepthExceeded { depth })
    } else {
        Ok(())
    }
}

struct Compiler<'a> {
    limits: SchemaCompileLimits,
    types: Vec<TypeNode>,
    records: Vec<CompiledRecord>,
    fields: Vec<CompiledField>,
    required_fields: Vec<usize>,
    constraints: Vec<CompiledConstraint>,
    enum_members: Vec<Range<usize>>,
    enum_bytes: Vec<u8>,
    union_alts: Vec<CompiledUnionAlt>,
    couplings: Vec<CompiledCoupling>,
    coupling_indices: Vec<usize>,
    path: Vec<&'a str>,
    sort_order: Vec<usize>,
    workspace_presence_words: usize,
    workspace_path_depth: usize,
}

trait FallibleReserve {
    fn reserve_fallible(&mut self, additional: usize) -> Result<(), SchemaError>;
}

impl<T> FallibleReserve for Vec<T> {
    fn reserve_fallible(&mut self, additional: usize) -> Result<(), SchemaError> {
        self.try_reserve_exact(additional)
            .map_err(|_| SchemaError::AllocationFailed)
    }
}

#[derive(Clone, Copy)]
enum ContainerKind {
    Array,
    Set,
    Map,
}

#[derive(Clone, Copy)]
enum TypeTarget {
    Field(usize),
    Container(TypeIdx, ContainerKind),
    UnionAlt(usize),
}

#[derive(Clone, Copy)]
enum RecordTarget {
    Root,
    Type(TypeIdx),
}

enum BuildTask<'a> {
    Record(&'a RecordDef, usize, usize, usize, RecordTarget),
    Type(&'a FieldType, usize, usize, usize, TypeTarget),
    PushPath(&'a str),
    PopPath,
}

#[derive(Clone, Copy, Debug, Default)]
struct ValidationRequirements {
    frames: usize,
    containers: usize,
}

#[derive(Clone, Copy)]
enum ValidationRequirementTask {
    Type(usize, bool),
    Record(usize, bool),
}

#[allow(clippy::too_many_lines)]
fn validation_requirements(
    compiler: &Compiler<'_>,
    root_record: usize,
) -> Result<ValidationRequirements, SchemaError> {
    let mut type_metrics: Vec<Option<ValidationRequirements>> = Vec::new();
    type_metrics
        .try_reserve_exact(compiler.types.len())
        .map_err(|_| SchemaError::AllocationFailed)?;
    type_metrics.resize(compiler.types.len(), None);
    let mut record_metrics: Vec<Option<ValidationRequirements>> = Vec::new();
    record_metrics
        .try_reserve_exact(compiler.records.len())
        .map_err(|_| SchemaError::AllocationFailed)?;
    record_metrics.resize(compiler.records.len(), None);
    let task_capacity = compiler
        .types
        .len()
        .checked_add(compiler.records.len())
        .and_then(|count| count.checked_mul(2))
        .and_then(|count| count.checked_add(1))
        .ok_or(SchemaError::TotalNodeLimitExceeded { count: usize::MAX })?;
    let mut tasks = Vec::new();
    tasks
        .try_reserve_exact(task_capacity)
        .map_err(|_| SchemaError::AllocationFailed)?;
    tasks.push(ValidationRequirementTask::Record(root_record, false));
    while let Some(task) = tasks.pop() {
        match task {
            ValidationRequirementTask::Record(index, false) => {
                if record_metrics[index].is_some() {
                    continue;
                }
                tasks.push(ValidationRequirementTask::Record(index, true));
                let record = &compiler.records[index];
                for field in &compiler.fields[record.fields.clone()] {
                    tasks.push(ValidationRequirementTask::Type(field.type_idx, false));
                }
            }
            ValidationRequirementTask::Type(index, false) => {
                if type_metrics[index].is_some() {
                    continue;
                }
                tasks.push(ValidationRequirementTask::Type(index, true));
                match &compiler.types[index] {
                    TypeNode::Array(inner) | TypeNode::Set(inner) | TypeNode::Map(inner) => {
                        tasks.push(ValidationRequirementTask::Type(*inner, false));
                    }
                    TypeNode::Union(alternatives) => {
                        for alternative in &compiler.union_alts[alternatives.clone()] {
                            if let Some(payload) = alternative.payload {
                                tasks.push(ValidationRequirementTask::Type(payload, false));
                            }
                        }
                    }
                    TypeNode::Record(record) => {
                        tasks.push(ValidationRequirementTask::Record(*record, false));
                    }
                    TypeNode::Int
                    | TypeNode::Bool
                    | TypeNode::Float64
                    | TypeNode::Bytes
                    | TypeNode::Text
                    | TypeNode::Any => {}
                }
            }
            ValidationRequirementTask::Record(index, true) => {
                let record = &compiler.records[index];
                let mut metric = ValidationRequirements {
                    frames: 1,
                    containers: 1,
                };
                for field in &compiler.fields[record.fields.clone()] {
                    let child = type_metrics[field.type_idx]
                        .ok_or(SchemaError::TotalNodeLimitExceeded { count: usize::MAX })?;
                    metric.frames = metric
                        .frames
                        .max(checked_frame_add(child.frames, 2)?)
                        .max(3);
                    metric.containers = metric
                        .containers
                        .max(checked_container_add(child.containers, 1)?);
                }
                record_metrics[index] = Some(metric);
            }
            ValidationRequirementTask::Type(index, true) => {
                let metric = match &compiler.types[index] {
                    TypeNode::Int
                    | TypeNode::Bool
                    | TypeNode::Float64
                    | TypeNode::Bytes
                    | TypeNode::Text
                    | TypeNode::Any => ValidationRequirements::default(),
                    TypeNode::Array(inner) | TypeNode::Set(inner) | TypeNode::Map(inner) => {
                        let child = type_metrics[*inner]
                            .ok_or(SchemaError::TotalNodeLimitExceeded { count: usize::MAX })?;
                        ValidationRequirements {
                            frames: checked_frame_add(child.frames, 2)?.max(3),
                            containers: checked_container_add(child.containers, 1)?,
                        }
                    }
                    TypeNode::Union(alternatives) => {
                        let mut metric = ValidationRequirements {
                            frames: 0,
                            containers: 1,
                        };
                        for alternative in &compiler.union_alts[alternatives.clone()] {
                            // Scalar payloads are consumed synchronously by `begin_union`; unlike
                            // structured payloads, they never place UnionFinish/RestorePath/Value
                            // on the validation-frame arena.
                            if let Some(payload) = alternative
                                .payload
                                .filter(|_| alternative.payload_scalar.is_none())
                            {
                                let child = type_metrics[payload].ok_or(
                                    SchemaError::TotalNodeLimitExceeded { count: usize::MAX },
                                )?;
                                metric.frames = metric
                                    .frames
                                    .max(checked_frame_add(child.frames, 2)?.max(3));
                                metric.containers = metric
                                    .containers
                                    .max(checked_container_add(child.containers, 1)?);
                            }
                        }
                        metric
                    }
                    TypeNode::Record(record) => record_metrics[*record]
                        .ok_or(SchemaError::TotalNodeLimitExceeded { count: usize::MAX })?,
                };
                type_metrics[index] = Some(metric);
            }
        }
    }
    record_metrics[root_record].ok_or(SchemaError::TotalNodeLimitExceeded { count: usize::MAX })
}

const fn checked_frame_add(value: usize, additional: usize) -> Result<usize, SchemaError> {
    match value.checked_add(additional) {
        Some(result) => Ok(result),
        None => Err(SchemaError::TotalNodeLimitExceeded { count: usize::MAX }),
    }
}

const fn checked_container_add(value: usize, additional: usize) -> Result<usize, SchemaError> {
    match value.checked_add(additional) {
        Some(result) => Ok(result),
        None => Err(SchemaError::NestingDepthExceeded { depth: usize::MAX }),
    }
}

impl<'a> Compiler<'a> {
    fn new(
        limits: SchemaCompileLimits,
        requirements: CompileRequirements,
    ) -> Result<Self, SchemaError> {
        let mut compiler = Self {
            limits,
            types: Vec::new(),
            records: Vec::new(),
            fields: Vec::new(),
            required_fields: Vec::new(),
            constraints: Vec::new(),
            enum_members: Vec::new(),
            enum_bytes: Vec::new(),
            union_alts: Vec::new(),
            couplings: Vec::new(),
            coupling_indices: Vec::new(),
            path: Vec::new(),
            sort_order: Vec::new(),
            workspace_presence_words: 0,
            workspace_path_depth: 0,
        };
        compiler.types.reserve_fallible(requirements.types)?;
        compiler.records.reserve_fallible(requirements.records)?;
        compiler.fields.reserve_fallible(requirements.fields)?;
        compiler
            .required_fields
            .reserve_fallible(requirements.required_fields)?;
        compiler
            .constraints
            .reserve_fallible(requirements.constraints)?;
        compiler
            .enum_members
            .reserve_fallible(requirements.enum_members)?;
        compiler
            .enum_bytes
            .reserve_fallible(requirements.enum_bytes)?;
        compiler
            .union_alts
            .reserve_fallible(requirements.union_alts)?;
        compiler
            .couplings
            .reserve_fallible(requirements.couplings)?;
        compiler
            .coupling_indices
            .reserve_fallible(requirements.coupling_indices)?;
        compiler
            .path
            .try_reserve_exact(requirements.max_path_depth)
            .map_err(|_| SchemaError::AllocationFailed)?;
        compiler
            .sort_order
            .try_reserve_exact(requirements.max_sort_width)
            .map_err(|_| SchemaError::AllocationFailed)?;
        Ok(compiler)
    }

    fn compile_root(
        &mut self,
        root: &'a RecordDef,
        requirements: CompileRequirements,
    ) -> Result<RecordIdx, SchemaError> {
        let task_capacity = requirements
            .types
            .checked_add(requirements.records)
            .and_then(|count| {
                requirements
                    .fields
                    .checked_mul(2)
                    .and_then(|paths| count.checked_add(paths))
            })
            .and_then(|count| count.checked_add(1))
            .ok_or(SchemaError::TotalNodeLimitExceeded { count: usize::MAX })?;
        let mut tasks = Vec::new();
        tasks
            .try_reserve_exact(task_capacity)
            .map_err(|_| SchemaError::AllocationFailed)?;
        tasks.push(BuildTask::Record(root, 0, 0, 0, RecordTarget::Root));
        let mut root_record = None;
        while let Some(task) = tasks.pop() {
            match task {
                BuildTask::PushPath(key) => self.path.push(key),
                BuildTask::PopPath => {
                    let _ = self.path.pop();
                }
                BuildTask::Record(def, depth, path_depth, presence_base, target) => {
                    let record_idx = self.compile_record_enter(
                        def,
                        depth,
                        path_depth,
                        presence_base,
                        &mut tasks,
                    )?;
                    match target {
                        RecordTarget::Root => root_record = Some(record_idx),
                        RecordTarget::Type(type_idx) => {
                            self.types[type_idx] = TypeNode::Record(record_idx);
                        }
                    }
                }
                BuildTask::Type(ty, depth, path_depth, presence_base, target) => {
                    self.compile_type_enter(
                        ty,
                        depth,
                        path_depth,
                        presence_base,
                        target,
                        &mut tasks,
                    )?;
                }
            }
        }
        root_record.ok_or(SchemaError::TotalNodeLimitExceeded { count: 0 })
    }

    fn compile_record_enter(
        &mut self,
        def: &'a RecordDef,
        depth: usize,
        path_depth: usize,
        presence_base: usize,
        tasks: &mut Vec<BuildTask<'a>>,
    ) -> Result<RecordIdx, SchemaError> {
        self.check_depth(depth)?;
        let mut order = core::mem::take(&mut self.sort_order);
        fill_sorted_field_indices(&mut order, def);
        for pair in order.windows(2) {
            let left = &def.fields[pair[0]].key;
            let right = &def.fields[pair[1]].key;
            if cmp_text_keys_canonical(left, right).is_eq() {
                return Err(SchemaError::DuplicateFieldKey {
                    key: try_clone_string(right)?,
                });
            }
        }

        let fields_start = self.fields.len();
        let required_start = self.required_fields.len();
        for (rank, source_index) in order.iter().copied().enumerate() {
            let field = &def.fields[source_index];
            self.path.push(&field.key);
            let constraints = self.compile_constraints(field, &field.ty)?;
            let _ = self.path.pop();
            let presence_index = rank;
            if field.required {
                self.required_fields.push(presence_index);
            }
            self.fields.push(CompiledField {
                key: try_boxed_str(&field.key)?,
                type_idx: usize::MAX,
                required: field.required,
                presence_index,
                constraints,
            });
        }
        let fields_end = self.fields.len();
        let couplings_start = self.couplings.len();
        let coupling_indices_start = self.coupling_indices.len();
        self.compile_couplings(&def.couplings, fields_start..fields_end)?;
        self.normalize_couplings(couplings_start, coupling_indices_start)?;
        let record_idx = self.records.len();
        self.records.push(CompiledRecord {
            fields: fields_start..fields_end,
            required: required_start..self.required_fields.len(),
            couplings: couplings_start..self.couplings.len(),
        });
        let words = def.fields.len().div_ceil(64);
        let presence_end = presence_base
            .checked_add(words)
            .ok_or(SchemaError::TotalNodeLimitExceeded { count: usize::MAX })?;
        self.workspace_presence_words = self.workspace_presence_words.max(presence_end);
        self.workspace_path_depth = self.workspace_path_depth.max(path_depth);

        for (rank, source_index) in order.iter().copied().enumerate().rev() {
            let field = &def.fields[source_index];
            tasks.push(BuildTask::PopPath);
            tasks.push(BuildTask::Type(
                &field.ty,
                depth
                    .checked_add(1)
                    .ok_or(SchemaError::NestingDepthExceeded { depth: usize::MAX })?,
                path_depth
                    .checked_add(1)
                    .ok_or(SchemaError::NestingDepthExceeded { depth: usize::MAX })?,
                presence_end,
                TypeTarget::Field(fields_start + rank),
            ));
            tasks.push(BuildTask::PushPath(&field.key));
        }
        self.sort_order = order;
        Ok(record_idx)
    }

    fn compile_type_enter(
        &mut self,
        ty: &'a FieldType,
        depth: usize,
        path_depth: usize,
        presence_base: usize,
        target: TypeTarget,
        tasks: &mut Vec<BuildTask<'a>>,
    ) -> Result<(), SchemaError> {
        self.check_depth(depth)?;
        self.workspace_path_depth = self.workspace_path_depth.max(path_depth);
        let type_idx = self.types.len();
        self.types.push(TypeNode::Any);
        self.assign_type_target(target, type_idx);
        let child_depth = depth
            .checked_add(1)
            .ok_or(SchemaError::NestingDepthExceeded { depth: usize::MAX })?;
        match ty {
            FieldType::Int => self.types[type_idx] = TypeNode::Int,
            FieldType::Bool => self.types[type_idx] = TypeNode::Bool,
            FieldType::Float64 => self.types[type_idx] = TypeNode::Float64,
            FieldType::Bytes => self.types[type_idx] = TypeNode::Bytes,
            FieldType::Text => self.types[type_idx] = TypeNode::Text,
            FieldType::Any => self.types[type_idx] = TypeNode::Any,
            FieldType::Array(inner) => tasks.push(BuildTask::Type(
                inner,
                child_depth,
                checked_increment_depth(path_depth)?,
                presence_base,
                TypeTarget::Container(type_idx, ContainerKind::Array),
            )),
            FieldType::Set(inner) => tasks.push(BuildTask::Type(
                inner,
                child_depth,
                checked_increment_depth(path_depth)?,
                presence_base,
                TypeTarget::Container(type_idx, ContainerKind::Set),
            )),
            FieldType::Map(inner) => tasks.push(BuildTask::Type(
                inner,
                child_depth,
                checked_increment_depth(path_depth)?,
                presence_base,
                TypeTarget::Container(type_idx, ContainerKind::Map),
            )),
            FieldType::Record(record) => tasks.push(BuildTask::Record(
                record,
                child_depth,
                path_depth,
                presence_base,
                RecordTarget::Type(type_idx),
            )),
            FieldType::Union(alts) => {
                self.compile_union_enter(
                    type_idx,
                    alts,
                    child_depth,
                    path_depth,
                    presence_base,
                    tasks,
                )?;
            }
        }
        Ok(())
    }

    fn compile_union_enter(
        &mut self,
        type_idx: TypeIdx,
        alts: &'a [crate::ir::UnionAlt],
        payload_depth: usize,
        path_depth: usize,
        presence_base: usize,
        tasks: &mut Vec<BuildTask<'a>>,
    ) -> Result<(), SchemaError> {
        self.workspace_path_depth = self
            .workspace_path_depth
            .max(checked_increment_depth(path_depth)?);
        if alts.is_empty() {
            return Err(SchemaError::EmptyUnion {
                path: self.path_name()?,
            });
        }
        let start = self.union_alts.len();
        let mut order = core::mem::take(&mut self.sort_order);
        fill_sorted_union_indices(&mut order, alts);
        for pair in order.windows(2) {
            if alts[pair[0]].code == alts[pair[1]].code {
                return Err(SchemaError::DuplicateUnionCode {
                    path: self.path_name()?,
                    code: alts[pair[1]].code,
                });
            }
        }
        for source_index in order.iter().copied() {
            let alt = &alts[source_index];
            self.union_alts.push(CompiledUnionAlt {
                code: alt.code,
                payload: None,
                payload_scalar: alt.payload.as_ref().and_then(scalar_kind_of),
            });
        }
        self.types[type_idx] = TypeNode::Union(start..self.union_alts.len());
        for (rank, source_index) in order.iter().copied().enumerate().rev() {
            let alt = &alts[source_index];
            if let Some(payload) = &alt.payload {
                tasks.push(BuildTask::Type(
                    payload,
                    payload_depth,
                    checked_increment_depth(path_depth)?,
                    presence_base,
                    TypeTarget::UnionAlt(start + rank),
                ));
            }
        }
        self.sort_order = order;
        Ok(())
    }

    fn assign_type_target(&mut self, target: TypeTarget, type_idx: TypeIdx) {
        match target {
            TypeTarget::Field(field_idx) => self.fields[field_idx].type_idx = type_idx,
            TypeTarget::Container(owner, ContainerKind::Array) => {
                self.types[owner] = TypeNode::Array(type_idx);
            }
            TypeTarget::Container(owner, ContainerKind::Set) => {
                self.types[owner] = TypeNode::Set(type_idx);
            }
            TypeTarget::Container(owner, ContainerKind::Map) => {
                self.types[owner] = TypeNode::Map(type_idx);
            }
            TypeTarget::UnionAlt(alt_idx) => self.union_alts[alt_idx].payload = Some(type_idx),
        }
    }

    fn compile_constraints(
        &mut self,
        field: &FieldDef,
        ty: &FieldType,
    ) -> Result<Range<usize>, SchemaError> {
        if field.constraints.len() > self.limits.max_constraints_per_field {
            return Err(SchemaError::ConstraintCapExceeded {
                field: self.path_name()?,
                count: field.constraints.len(),
            });
        }
        let kind = kind_of_type(ty);
        let start = self.constraints.len();
        for constraint in &field.constraints {
            match constraint {
                Constraint::Range { min, max } => {
                    if kind != ValueKind::Int {
                        return Err(SchemaError::ConstraintWrongKind {
                            field: self.path_name()?,
                        });
                    }
                    if matches!((min, max), (Some(lo), Some(hi)) if lo > hi) {
                        return Err(SchemaError::ConstraintBounds {
                            field: self.path_name()?,
                        });
                    }
                    self.constraints.push(CompiledConstraint::Range {
                        min: min.as_ref().map(Int::try_clone).transpose()?,
                        max: max.as_ref().map(Int::try_clone).transpose()?,
                    });
                }
                Constraint::Count { unit, min, max } => {
                    self.check_count_kind(kind, *unit)?;
                    if matches!((min, max), (Some(lo), Some(hi)) if lo > hi) {
                        return Err(SchemaError::ConstraintBounds {
                            field: self.path_name()?,
                        });
                    }
                    self.constraints.push(CompiledConstraint::Count {
                        unit: *unit,
                        min: *min,
                        max: *max,
                    });
                }
                Constraint::Enum(members) => {
                    let members = self.compile_enum_members(kind, members)?;
                    self.constraints.push(CompiledConstraint::Enum { members });
                }
            }
        }
        let enum_members = &self.enum_members;
        let enum_bytes = &self.enum_bytes;
        self.constraints[start..].sort_unstable_by(|left, right| {
            cmp_compiled_constraint(left, right, enum_members, enum_bytes)
        });
        if self.constraints[start..].windows(2).any(|pair| {
            cmp_compiled_constraint(&pair[0], &pair[1], enum_members, enum_bytes).is_eq()
        }) {
            return Err(SchemaError::DuplicateConstraint {
                field: self.path_name()?,
            });
        }
        Ok(start..self.constraints.len())
    }

    fn compile_enum_members(
        &mut self,
        kind: ValueKind,
        members: &[EnumMember],
    ) -> Result<Range<usize>, SchemaError> {
        if kind != ValueKind::Int && kind != ValueKind::Text {
            return Err(SchemaError::ConstraintWrongKind {
                field: self.path_name()?,
            });
        }
        let start = self.enum_members.len();
        for member in members {
            let encoded = match (kind, member) {
                (ValueKind::Int, EnumMember::Int(value)) => value.encode_canonical()?,
                (ValueKind::Text, EnumMember::Text(value)) => encode_text_member(value)?,
                _ => {
                    return Err(SchemaError::EnumMemberWrongKind {
                        field: self.path_name()?,
                    });
                }
            };
            let bytes_start = self.enum_bytes.len();
            self.enum_bytes.extend_from_slice(&encoded);
            self.enum_members.push(bytes_start..self.enum_bytes.len());
        }
        let enum_bytes = &self.enum_bytes;
        self.enum_members[start..].sort_unstable_by(|left, right| {
            enum_bytes[left.clone()].cmp(&enum_bytes[right.clone()])
        });
        for pair in self.enum_members[start..].windows(2) {
            if enum_bytes[pair[0].clone()] == enum_bytes[pair[1].clone()] {
                return Err(SchemaError::DuplicateEnumMember {
                    field: self.path_name()?,
                });
            }
        }
        Ok(start..self.enum_members.len())
    }

    fn compile_couplings(
        &mut self,
        couplings: &[Coupling],
        fields: Range<usize>,
    ) -> Result<(), SchemaError> {
        for coupling in couplings {
            match coupling {
                Coupling::Requires {
                    if_present,
                    then_present,
                } => {
                    if if_present == then_present {
                        return Err(SchemaError::CouplingDuplicateKey {
                            path: self.path_name()?,
                            key: try_clone_string(if_present)?,
                        });
                    }
                    let if_index = self.coupling_key_index(if_present, fields.clone())?;
                    let then_index = self.coupling_key_index(then_present, fields.clone())?;
                    self.couplings.push(CompiledCoupling::Requires {
                        if_index,
                        then_index,
                    });
                }
                Coupling::ExactlyOne(keys) => {
                    let indices = self.coupling_key_indices("ExactlyOne", keys, fields.clone())?;
                    self.couplings
                        .push(CompiledCoupling::ExactlyOne { indices });
                }
                Coupling::Together(keys) => {
                    let indices = self.coupling_key_indices("Together", keys, fields.clone())?;
                    self.couplings.push(CompiledCoupling::Together { indices });
                }
            }
        }
        Ok(())
    }

    fn coupling_key_indices(
        &mut self,
        kind: &'static str,
        keys: &[String],
        fields: Range<usize>,
    ) -> Result<Range<usize>, SchemaError> {
        if keys.len() < MIN_COUPLING_KEYS {
            return Err(SchemaError::CouplingKeyCount {
                path: self.path_name()?,
                kind,
                count: keys.len(),
            });
        }

        let start = self.coupling_indices.len();
        for key in keys {
            let index = self.coupling_key_index(key, fields.clone())?;
            self.coupling_indices.push(index);
        }
        self.coupling_indices[start..].sort_unstable();
        if let Some(pair) = self.coupling_indices[start..]
            .windows(2)
            .find(|pair| pair[0] == pair[1])
        {
            let key = &self.fields[fields.start + pair[1]].key;
            return Err(SchemaError::CouplingDuplicateKey {
                path: self.path_name()?,
                key: try_clone_string(key)?,
            });
        }
        Ok(start..self.coupling_indices.len())
    }

    fn coupling_key_index(&self, key: &str, fields: Range<usize>) -> Result<usize, SchemaError> {
        let fields = &self.fields[fields];
        let found = fields.binary_search_by(|field| cmp_text_keys_canonical(&field.key, key));
        if let Ok(index) = found {
            let field = &fields[index];
            if field.required {
                return Err(SchemaError::CouplingNonOptionalField {
                    path: self.path_name()?,
                    key: try_clone_string(key)?,
                });
            }
            return Ok(field.presence_index);
        }
        Err(SchemaError::CouplingUnknownField {
            path: self.path_name()?,
            key: try_clone_string(key)?,
        })
    }

    fn normalize_couplings(
        &mut self,
        couplings_start: usize,
        indices_start: usize,
    ) -> Result<(), SchemaError> {
        let mut source_indices = Vec::new();
        source_indices
            .try_reserve_exact(self.coupling_indices.len() - indices_start)
            .map_err(|_| SchemaError::AllocationFailed)?;
        source_indices.extend_from_slice(&self.coupling_indices[indices_start..]);
        self.couplings[couplings_start..].sort_unstable_by(|left, right| {
            cmp_compiled_coupling(left, right, &source_indices, indices_start)
        });

        let mut normalized = Vec::new();
        normalized
            .try_reserve_exact(self.couplings.len() - couplings_start)
            .map_err(|_| SchemaError::AllocationFailed)?;
        let mut normalized_indices = Vec::new();
        normalized_indices
            .try_reserve_exact(source_indices.len())
            .map_err(|_| SchemaError::AllocationFailed)?;
        let mut previous_source: Option<CompiledCoupling> = None;
        for coupling in &self.couplings[couplings_start..] {
            if previous_source.as_ref().is_some_and(|previous| {
                cmp_compiled_coupling(previous, coupling, &source_indices, indices_start).is_eq()
            }) {
                continue;
            }
            previous_source = Some(coupling.clone());
            let normalized_coupling = match coupling {
                CompiledCoupling::Requires {
                    if_index,
                    then_index,
                } => CompiledCoupling::Requires {
                    if_index: *if_index,
                    then_index: *then_index,
                },
                CompiledCoupling::ExactlyOne { indices } => {
                    let start = indices_start + normalized_indices.len();
                    normalized_indices.extend_from_slice(coupling_indices_slice(
                        indices,
                        &source_indices,
                        indices_start,
                    ));
                    CompiledCoupling::ExactlyOne {
                        indices: start..indices_start + normalized_indices.len(),
                    }
                }
                CompiledCoupling::Together { indices } => {
                    let start = indices_start + normalized_indices.len();
                    normalized_indices.extend_from_slice(coupling_indices_slice(
                        indices,
                        &source_indices,
                        indices_start,
                    ));
                    CompiledCoupling::Together {
                        indices: start..indices_start + normalized_indices.len(),
                    }
                }
            };
            normalized.push(normalized_coupling);
        }
        self.couplings.truncate(couplings_start);
        self.couplings.extend(normalized);
        self.coupling_indices.truncate(indices_start);
        self.coupling_indices.extend(normalized_indices);
        Ok(())
    }

    fn check_count_kind(&self, kind: ValueKind, unit: CountUnit) -> Result<(), SchemaError> {
        let ok = match unit {
            CountUnit::Elements => {
                matches!(kind, ValueKind::Array | ValueKind::Set | ValueKind::Map)
            }
            CountUnit::Octets => matches!(kind, ValueKind::Bytes | ValueKind::Text),
        };
        if ok {
            Ok(())
        } else {
            Err(SchemaError::ConstraintWrongKind {
                field: self.path_name()?,
            })
        }
    }

    const fn check_depth(&self, depth: usize) -> Result<(), SchemaError> {
        if depth > self.limits.max_schema_depth {
            return Err(SchemaError::NestingDepthExceeded { depth });
        }
        Ok(())
    }

    fn path_name(&self) -> Result<String, SchemaError> {
        if self.path.is_empty() {
            return try_clone_string("$");
        }
        let separators = self.path.len().saturating_sub(1);
        let payload = self
            .path
            .iter()
            .try_fold(0usize, |sum, segment| sum.checked_add(segment.len()))
            .and_then(|sum| sum.checked_add(separators))
            .ok_or(SchemaError::AllocationFailed)?;
        let mut result = String::new();
        result
            .try_reserve_exact(payload)
            .map_err(|_| SchemaError::AllocationFailed)?;
        for (index, segment) in self.path.iter().enumerate() {
            if index != 0 {
                result.push('.');
            }
            result.push_str(segment);
        }
        Ok(result)
    }
}

fn coupling_indices_slice<'a>(
    range: &Range<usize>,
    indices: &'a [usize],
    base: usize,
) -> &'a [usize] {
    &indices[range.start - base..range.end - base]
}

fn cmp_compiled_constraint(
    left: &CompiledConstraint,
    right: &CompiledConstraint,
    enum_members: &[Range<usize>],
    enum_bytes: &[u8],
) -> Ordering {
    let rank = |constraint: &CompiledConstraint| match constraint {
        CompiledConstraint::Range { .. } => 0u8,
        CompiledConstraint::Count { .. } => 1,
        CompiledConstraint::Enum { .. } => 2,
    };
    rank(left)
        .cmp(&rank(right))
        .then_with(|| match (left, right) {
            (
                CompiledConstraint::Range {
                    min: left_min,
                    max: left_max,
                },
                CompiledConstraint::Range {
                    min: right_min,
                    max: right_max,
                },
            ) => (left_min, left_max).cmp(&(right_min, right_max)),
            (
                CompiledConstraint::Count {
                    unit: left_unit,
                    min: left_min,
                    max: left_max,
                },
                CompiledConstraint::Count {
                    unit: right_unit,
                    min: right_min,
                    max: right_max,
                },
            ) => count_unit_rank(*left_unit)
                .cmp(&count_unit_rank(*right_unit))
                .then_with(|| (left_min, left_max).cmp(&(right_min, right_max))),
            (
                CompiledConstraint::Enum {
                    members: left_members,
                },
                CompiledConstraint::Enum {
                    members: right_members,
                },
            ) => cmp_enum_member_tables(
                &enum_members[left_members.clone()],
                &enum_members[right_members.clone()],
                enum_bytes,
            ),
            _ => Ordering::Equal,
        })
}

const fn count_unit_rank(unit: CountUnit) -> u8 {
    match unit {
        CountUnit::Elements => 0,
        CountUnit::Octets => 1,
    }
}

fn cmp_enum_member_tables(
    left: &[Range<usize>],
    right: &[Range<usize>],
    enum_bytes: &[u8],
) -> Ordering {
    for (left, right) in left.iter().zip(right) {
        let ordering = enum_bytes[left.clone()].cmp(&enum_bytes[right.clone()]);
        if !ordering.is_eq() {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

fn cmp_compiled_coupling(
    left: &CompiledCoupling,
    right: &CompiledCoupling,
    indices: &[usize],
    base: usize,
) -> Ordering {
    let rank = |coupling: &CompiledCoupling| match coupling {
        CompiledCoupling::Requires { .. } => 0u8,
        CompiledCoupling::ExactlyOne { .. } => 1,
        CompiledCoupling::Together { .. } => 2,
    };
    rank(left)
        .cmp(&rank(right))
        .then_with(|| match (left, right) {
            (
                CompiledCoupling::Requires {
                    if_index: left_if,
                    then_index: left_then,
                },
                CompiledCoupling::Requires {
                    if_index: right_if,
                    then_index: right_then,
                },
            ) => (*left_if, *left_then).cmp(&(*right_if, *right_then)),
            (
                CompiledCoupling::ExactlyOne { indices: left }
                | CompiledCoupling::Together { indices: left },
                CompiledCoupling::ExactlyOne { indices: right }
                | CompiledCoupling::Together { indices: right },
            ) => coupling_indices_slice(left, indices, base)
                .cmp(coupling_indices_slice(right, indices, base)),
            _ => Ordering::Equal,
        })
}

fn fill_sorted_field_indices(order: &mut Vec<usize>, def: &RecordDef) {
    order.clear();
    order.extend(0..def.fields.len());
    order.sort_unstable_by(|left, right| {
        cmp_text_keys_canonical(&def.fields[*left].key, &def.fields[*right].key)
    });
}

fn fill_sorted_union_indices(order: &mut Vec<usize>, alts: &[crate::ir::UnionAlt]) {
    order.clear();
    order.extend(0..alts.len());
    order.sort_unstable_by_key(|index| alts[*index].code);
}

const fn checked_increment_depth(depth: usize) -> Result<usize, SchemaError> {
    match depth.checked_add(1) {
        Some(value) => Ok(value),
        None => Err(SchemaError::NestingDepthExceeded { depth: usize::MAX }),
    }
}

const fn kind_of_type(ty: &FieldType) -> ValueKind {
    match ty {
        FieldType::Int => ValueKind::Int,
        FieldType::Bool => ValueKind::Bool,
        FieldType::Float64 => ValueKind::Float64,
        FieldType::Bytes => ValueKind::Bytes,
        FieldType::Text => ValueKind::Text,
        FieldType::Array(_) => ValueKind::Array,
        FieldType::Set(_) => ValueKind::Set,
        FieldType::Map(_) => ValueKind::Map,
        FieldType::Union(_) => ValueKind::Union,
        FieldType::Record(_) => ValueKind::Record,
        FieldType::Any => ValueKind::Any,
    }
}

fn encode_text_member(value: &str) -> Result<Vec<u8>, SchemaError> {
    let capacity = encoded_text_len(value.len())?;
    let mut enc =
        Encoder::try_with_capacity(capacity).map_err(SchemaError::CanonicalEncodingFailed)?;
    enc.text(value).map_err(canonical_encoding_failed)?;
    enc.finish().map_err(canonical_encoding_failed)
}

fn enum_member_encoded_len(member: &EnumMember) -> Result<usize, SchemaError> {
    match member {
        EnumMember::Int(value) => value.canonical_encoded_len(),
        EnumMember::Text(value) => encoded_text_len(value.len()),
    }
}

const fn encoded_text_len(payload_len: usize) -> Result<usize, SchemaError> {
    let head = if payload_len <= 23 {
        1
    } else if payload_len <= 0xff {
        2
    } else if payload_len <= 0xffff {
        3
    } else if payload_len <= u32::MAX as usize {
        5
    } else if usize::BITS <= 64 {
        9
    } else {
        return Err(SchemaError::OwnedByteLimitExceeded { count: usize::MAX });
    };
    match payload_len.checked_add(head) {
        Some(len) => Ok(len),
        None => Err(SchemaError::OwnedByteLimitExceeded { count: usize::MAX }),
    }
}

fn try_clone_string(value: &str) -> Result<String, SchemaError> {
    let mut out = String::new();
    out.try_reserve_exact(value.len())
        .map_err(|_| SchemaError::AllocationFailed)?;
    out.push_str(value);
    Ok(out)
}

fn try_boxed_str(value: &str) -> Result<Box<str>, SchemaError> {
    Ok(try_clone_string(value)?.into_boxed_str())
}

#[allow(clippy::needless_pass_by_value)]
const fn canonical_encoding_failed(error: EncodeError<sacp_cbor::CborError>) -> SchemaError {
    let error = match error {
        EncodeError::Cbor(error) | EncodeError::Sink(error) => error,
        EncodeError::Poisoned => {
            sacp_cbor::CborError::new(sacp_cbor::ErrorCode::EncoderPoisoned, 0)
        }
    };
    SchemaError::CanonicalEncodingFailed(error)
}

pub(crate) fn cmp_field_key(a: &str, b: &str) -> Ordering {
    cmp_text_keys_canonical(a, b)
}

const fn scalar_kind_of(ty: &FieldType) -> Option<ScalarKind> {
    match ty {
        FieldType::Int => Some(ScalarKind::Integer),
        FieldType::Bool => Some(ScalarKind::Bool),
        FieldType::Float64 => Some(ScalarKind::Float),
        FieldType::Bytes => Some(ScalarKind::Bytes),
        FieldType::Text => Some(ScalarKind::Text),
        _ => None,
    }
}
