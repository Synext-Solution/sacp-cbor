//! Structural containment derivation between compiled schemas.

use alloc::{string::String, vec::Vec};
use core::cmp::Ordering;
use core::fmt::Write;
use core::ops::Range;

use crate::ValidationWorkspace;
use sacp_cbor::query::IntegerRef;
use sacp_cbor::{
    ByteSink, CanonicalCbor, CborDecode, CborError, DecodeLimits, Decoder, EncodeLimits, Encoder,
    ErrorCode,
};

use crate::compile::{
    cmp_field_key, CompiledConstraint, CompiledCoupling, CompiledRecord, RecordSchema, TypeNode,
};
use crate::int::cmp_integer_ref_to_int;
use crate::ir::CountUnit;
use crate::{Int, RecordError};

/// Structural containment result for both successor directions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inclusion {
    /// Every value admitted by the old schema is admitted by the new schema.
    pub forward: InclusionProof,
    /// Every value admitted by the new schema is admitted by the old schema.
    pub backward: InclusionProof,
}

/// Explicit work and evidence limits for inclusion derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InclusionLimits {
    /// Maximum compiled nodes inspected across both schemas.
    pub max_steps: usize,
    /// Maximum simultaneously live containment continuation frames.
    pub max_frames: usize,
    /// Maximum counterexample and diagnostic path depth.
    pub max_path_depth: usize,
    /// Maximum UTF-8 bytes retained across one diagnostic path.
    pub max_path_bytes: usize,
    /// Maximum canonical counterexample byte length.
    pub max_witness_bytes: usize,
    /// Maximum total container items in a synthesized counterexample.
    pub max_witness_items: usize,
    /// Maximum value nesting depth in a synthesized counterexample.
    pub max_value_depth: usize,
}

impl InclusionLimits {
    /// Construct explicit inclusion limits.
    #[must_use]
    pub const fn new(
        max_steps: usize,
        max_frames: usize,
        max_path_depth: usize,
        max_path_bytes: usize,
        max_witness_bytes: usize,
        max_witness_items: usize,
        max_value_depth: usize,
    ) -> Self {
        Self {
            max_steps,
            max_frames,
            max_path_depth,
            max_path_bytes,
            max_witness_bytes,
            max_witness_items,
            max_value_depth,
        }
    }
}

/// Caller-owned reusable inclusion scratch space.
#[derive(Debug, Default)]
pub struct InclusionWorkspace {
    path_bytes: String,
    path_ranges: Vec<Range<usize>>,
    prepared_path_depth: usize,
    prepared_path_bytes: usize,
    remaining_steps: usize,
    frames: Vec<ContainFrame>,
    prepared_frames: usize,
    witness: Vec<u8>,
    witness_presence: Vec<u64>,
    witness_bytes_scratch: Vec<u8>,
    witness_int_scratch: Vec<u8>,
    witness_frames: Vec<WitnessFrame>,
    source_validation: ValidationWorkspace,
    target_validation: ValidationWorkspace,
}

impl InclusionWorkspace {
    /// Construct an empty inclusion workspace.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            path_bytes: String::new(),
            path_ranges: Vec::new(),
            prepared_path_depth: 0,
            prepared_path_bytes: 0,
            remaining_steps: 0,
            frames: Vec::new(),
            prepared_frames: 0,
            witness: Vec::new(),
            witness_presence: Vec::new(),
            witness_bytes_scratch: Vec::new(),
            witness_int_scratch: Vec::new(),
            witness_frames: Vec::new(),
            source_validation: ValidationWorkspace::new(),
            target_validation: ValidationWorkspace::new(),
        }
    }

    /// Fallibly prepare scratch capacity for `limits`.
    ///
    /// # Errors
    ///
    /// Returns an allocation or resource-limit reason when the requested workspace cannot be
    /// prepared.
    pub fn prepare(
        &mut self,
        source: &RecordSchema,
        target: &RecordSchema,
        limits: InclusionLimits,
    ) -> Result<(), NonDerivationReason> {
        self.clear_path();
        self.frames.clear();
        if self.frames.capacity() < limits.max_frames {
            self.frames
                .try_reserve_exact(limits.max_frames)
                .map_err(|_| NonDerivationReason::AllocationFailed)?;
        }
        if self.path_ranges.capacity() < limits.max_path_depth {
            self.path_ranges
                .try_reserve_exact(limits.max_path_depth)
                .map_err(|_| NonDerivationReason::AllocationFailed)?;
        }
        if self.path_bytes.capacity() < limits.max_path_bytes {
            self.path_bytes
                .try_reserve_exact(limits.max_path_bytes)
                .map_err(|_| NonDerivationReason::AllocationFailed)?;
        }
        self.witness.clear();
        if self.witness.capacity() < limits.max_witness_bytes {
            self.witness
                .try_reserve_exact(limits.max_witness_bytes)
                .map_err(|_| NonDerivationReason::AllocationFailed)?;
        }
        self.witness_bytes_scratch.clear();
        if self.witness_bytes_scratch.capacity() < limits.max_witness_bytes {
            self.witness_bytes_scratch
                .try_reserve_exact(limits.max_witness_bytes)
                .map_err(|_| NonDerivationReason::AllocationFailed)?;
        }
        self.witness_int_scratch.clear();
        if self.witness_int_scratch.capacity() < limits.max_witness_bytes {
            self.witness_int_scratch
                .try_reserve_exact(limits.max_witness_bytes)
                .map_err(|_| NonDerivationReason::AllocationFailed)?;
        }
        self.witness_frames.clear();
        if self.witness_frames.capacity() < limits.max_frames {
            self.witness_frames
                .try_reserve_exact(limits.max_frames)
                .map_err(|_| NonDerivationReason::AllocationFailed)?;
        }
        let presence_words = source
            .workspace_presence_words
            .max(target.workspace_presence_words);
        self.witness_presence.clear();
        if self.witness_presence.capacity() < presence_words {
            self.witness_presence
                .try_reserve_exact(presence_words)
                .map_err(|_| NonDerivationReason::AllocationFailed)?;
        }
        let validation_limits = witness_decode_limits(limits);
        let validation_presence = source
            .workspace_presence_words
            .max(target.workspace_presence_words);
        let validation_path = source.workspace_path_depth.max(target.workspace_path_depth);
        let validation_frames = source
            .workspace_frame_capacity
            .max(target.workspace_frame_capacity);
        let required_containers = |schema: &RecordSchema| {
            if schema.contains_any {
                schema
                    .workspace_container_capacity
                    .max(validation_limits.max_depth)
            } else {
                schema.workspace_container_capacity
            }
        };
        let validation_containers = required_containers(source).max(required_containers(target));
        for validation in [&mut self.source_validation, &mut self.target_validation] {
            validation
                .prepare_capacity(
                    validation_presence,
                    validation_path,
                    validation_frames,
                    validation_containers,
                )
                .map_err(|_| NonDerivationReason::AllocationFailed)?;
        }
        self.prepared_path_depth = limits.max_path_depth;
        self.prepared_path_bytes = limits.max_path_bytes;
        self.prepared_frames = limits.max_frames;
        Ok(())
    }

    fn clear_path(&mut self) {
        self.path_bytes.clear();
        self.path_ranges.clear();
    }
    fn push_path(&mut self, value: &str) -> Result<(), NonDerivationReason> {
        if self.path_ranges.len() >= self.prepared_path_depth
            || self
                .path_bytes
                .len()
                .checked_add(value.len())
                .is_none_or(|len| len > self.prepared_path_bytes)
        {
            return Err(NonDerivationReason::ResourceLimit);
        }
        let start = self.path_bytes.len();
        self.path_bytes.push_str(value);
        self.path_ranges.push(start..self.path_bytes.len());
        Ok(())
    }
    fn push_union_path(&mut self, code: u64) -> Result<(), NonDerivationReason> {
        if self.path_ranges.len() >= self.prepared_path_depth
            || self
                .path_bytes
                .len()
                .checked_add(22)
                .is_none_or(|len| len > self.prepared_path_bytes)
        {
            return Err(NonDerivationReason::ResourceLimit);
        }
        let start = self.path_bytes.len();
        write!(&mut self.path_bytes, "union({code})")
            .map_err(|_| NonDerivationReason::AllocationFailed)?;
        self.path_ranges.push(start..self.path_bytes.len());
        Ok(())
    }
    fn pop_path(&mut self) {
        if let Some(range) = self.path_ranges.pop() {
            self.path_bytes.truncate(range.start);
        }
    }
    fn path_vec(&self) -> Result<Vec<String>, NonDerivationReason> {
        let mut out = Vec::new();
        out.try_reserve_exact(self.path_ranges.len())
            .map_err(|_| NonDerivationReason::AllocationFailed)?;
        for range in &self.path_ranges {
            let value = &self.path_bytes[range.clone()];
            let mut owned = String::new();
            owned
                .try_reserve_exact(value.len())
                .map_err(|_| NonDerivationReason::AllocationFailed)?;
            owned.push_str(value);
            out.push(owned);
        }
        Ok(out)
    }
    fn charge(&mut self, steps: usize) -> Result<(), NonDerivationReason> {
        self.remaining_steps = self
            .remaining_steps
            .checked_sub(steps)
            .ok_or(NonDerivationReason::ResourceLimit)?;
        Ok(())
    }

    fn push_frame(&mut self, frame: ContainFrame) -> Result<(), NonDerivationReason> {
        if self.frames.len() >= self.prepared_frames {
            return Err(NonDerivationReason::ResourceLimit);
        }
        self.frames.push(frame);
        Ok(())
    }
}

struct WitnessSink<'a>(&'a mut Vec<u8>);

impl ByteSink for WitnessSink<'_> {
    type Error = CborError;
    type Output = ();

    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let new_len = self
            .0
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| CborError::new(ErrorCode::MessageLenLimitExceeded, self.0.len()))?;
        if new_len > self.0.capacity() {
            return Err(CborError::new(
                ErrorCode::MessageLenLimitExceeded,
                self.0.len(),
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    fn finish(self) -> Result<Self::Output, Self::Error> {
        Ok(())
    }
}

/// One containment direction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InclusionProof {
    /// The direction is structurally derivable.
    Proven,
    /// A concrete canonical wire value refutes the direction.
    Refuted(WireCounterexample),
    /// The direction is not derivable, with the first failing rule.
    Unknown(NonDerivation),
}

/// Concrete canonical wire counterexample for a refuted inclusion direction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireCounterexample {
    canonical: CanonicalCbor,
    rejection: RecordError,
}

impl WireCounterexample {
    /// Return the validated canonical witness.
    #[must_use]
    pub const fn canonical(&self) -> &CanonicalCbor {
        &self.canonical
    }

    /// Return the replayed target rejection, including rule, path, and offset.
    #[must_use]
    pub const fn target_rejection(&self) -> &RecordError {
        &self.rejection
    }
}

/// First non-derivable containment point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonDerivation {
    /// Schema path to the failing point.
    pub path: Vec<String>,
    /// Rule that failed.
    pub reason: NonDerivationReason,
}

/// Reason a containment direction is not derivable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonDerivationReason {
    /// Caller-supplied inclusion work budget was exhausted.
    ResourceLimit,
    /// Inclusion scratch allocation failed.
    AllocationFailed,
    /// A field was added in the successor schema.
    FieldAdded,
    /// A field was removed in the successor schema.
    FieldRemoved,
    /// A required field was added.
    RequiredAdded,
    /// An optional field became required.
    OptionalToRequired,
    /// A required field became optional.
    RequiredToOptional,
    /// A type changed incompatibly.
    TypeChanged,
    /// A union code was removed from the target admitted set.
    UnionCodeRemoved,
    /// A shared union code changed payload arity or payload type.
    UnionPayloadChanged,
    /// An integer range was narrowed.
    RangeNarrowed,
    /// A count interval was narrowed.
    CountNarrowed,
    /// An enum set was narrowed.
    EnumNarrowed,
    /// An enum constraint was added where the source had no enum constraint.
    EnumAdded,
    /// A coupling was added to the target admitted set.
    CouplingAdded,
    /// An `Any` source was narrowed to a non-`Any` target.
    AnyNarrowed,
}

impl RecordSchema {
    /// Derive structural containment between this schema and `new`.
    ///
    /// `self` is the old schema and `new` is the successor schema.
    #[must_use]
    pub fn inclusion(&self, new: &Self, limits: InclusionLimits) -> Inclusion {
        let mut workspace = InclusionWorkspace::new();
        if let Err(reason) = workspace.prepare(self, new, limits) {
            let unknown = || {
                InclusionProof::Unknown(NonDerivation {
                    path: Vec::new(),
                    reason,
                })
            };
            return Inclusion {
                forward: unknown(),
                backward: unknown(),
            };
        }
        self.inclusion_with_workspace(new, limits, &mut workspace)
    }

    /// Derive inclusion using caller-prepared reusable workspace.
    pub fn inclusion_with_workspace(
        &self,
        new: &Self,
        limits: InclusionLimits,
        workspace: &mut InclusionWorkspace,
    ) -> Inclusion {
        workspace.remaining_steps = limits.max_steps;
        Inclusion {
            forward: derive(self, new, &FORWARD_LABELS, limits, workspace),
            backward: derive(new, self, &BACKWARD_LABELS, limits, workspace),
        }
    }
}

/// Inclusion-specific names for presence-level derivation breaks.
///
/// The walker derives one relation — every value admitted by `from` is
/// admitted by `to` — and both directions run the same walker with swapped
/// arguments. The public reasons name each break from the old-to-new
/// evolution perspective, so the same structural break carries a different
/// name per direction: a key declared only in `from` is a removed field when
/// `from` is the old schema and an added field when `from` is the successor.
struct InclusionLabels {
    /// A key declared only in `from`: `from` admits values carrying it and
    /// `to`'s closed keys reject them.
    source_only_key: NonDerivationReason,
    /// A key declared only in `to` and required there: `from`'s values omit
    /// a key `to` demands.
    target_required_key: NonDerivationReason,
    /// A shared key optional in `from` but required in `to`.
    presence_tightened: NonDerivationReason,
}

const FORWARD_LABELS: InclusionLabels = InclusionLabels {
    source_only_key: NonDerivationReason::FieldRemoved,
    target_required_key: NonDerivationReason::RequiredAdded,
    presence_tightened: NonDerivationReason::OptionalToRequired,
};

const BACKWARD_LABELS: InclusionLabels = InclusionLabels {
    source_only_key: NonDerivationReason::FieldAdded,
    target_required_key: NonDerivationReason::FieldRemoved,
    presence_tightened: NonDerivationReason::RequiredToOptional,
};

fn derive(
    from: &RecordSchema,
    to: &RecordSchema,
    labels: &InclusionLabels,
    limits: InclusionLimits,
    workspace: &mut InclusionWorkspace,
) -> InclusionProof {
    workspace.clear_path();
    let required_depth = from.workspace_path_depth.max(to.workspace_path_depth);
    if required_depth > limits.max_path_depth || workspace.prepared_path_depth < required_depth {
        return InclusionProof::Unknown(NonDerivation {
            path: Vec::new(),
            reason: NonDerivationReason::ResourceLimit,
        });
    }
    match contains_iterative(from, to, workspace, labels) {
        Ok(()) => InclusionProof::Proven,
        Err(
            reason @ (NonDerivationReason::ResourceLimit | NonDerivationReason::AllocationFailed),
        ) => match workspace.path_vec() {
            Ok(path) => InclusionProof::Unknown(NonDerivation { path, reason }),
            Err(path_reason) => InclusionProof::Unknown(NonDerivation {
                path: Vec::new(),
                reason: path_reason,
            }),
        },
        Err(reason) => {
            let path = match workspace.path_vec() {
                Ok(path) => path,
                Err(reason) => {
                    return InclusionProof::Unknown(NonDerivation {
                        path: Vec::new(),
                        reason,
                    })
                }
            };
            match wire_counterexample(from, to, &path, reason, limits, workspace) {
                Ok(Some(counterexample)) => InclusionProof::Refuted(counterexample),
                Ok(None) => InclusionProof::Unknown(NonDerivation { path, reason }),
                Err(resource) => InclusionProof::Unknown(NonDerivation {
                    path,
                    reason: resource,
                }),
            }
        }
    }
}

#[derive(Clone, Debug)]
enum ContainFrame {
    Record {
        from_record: usize,
        to_record: usize,
        from_pos: usize,
        to_pos: usize,
    },
    Type {
        from_type: usize,
        to_type: usize,
        union_payload: bool,
    },
    Constraints {
        from: Range<usize>,
        to: Range<usize>,
    },
    Union {
        from: Range<usize>,
        to: Range<usize>,
        position: usize,
    },
    PopPath,
}

#[derive(Clone, Debug)]
enum WitnessFrame {
    RecordStart {
        record: usize,
        forced_depth: usize,
        depth: usize,
    },
    RecordNext {
        record: usize,
        field: usize,
        presence_base: usize,
        forced_depth: usize,
        depth: usize,
    },
    RecordFinish {
        presence_base: usize,
    },
    Value {
        type_idx: usize,
        constraints: Range<usize>,
        forced_depth: usize,
        depth: usize,
    },
    ArrayNext {
        inner: usize,
        remaining: usize,
        forced_depth: usize,
        depth: usize,
    },
    MapNext {
        inner: usize,
        index: usize,
        remaining: usize,
        forced_depth: usize,
        depth: usize,
    },
}

#[allow(clippy::too_many_lines)]
fn contains_iterative(
    from_schema: &RecordSchema,
    to_schema: &RecordSchema,
    workspace: &mut InclusionWorkspace,
    labels: &InclusionLabels,
) -> Result<(), NonDerivationReason> {
    workspace.frames.clear();
    workspace.push_frame(ContainFrame::Record {
        from_record: from_schema.root_record,
        to_record: to_schema.root_record,
        from_pos: 0,
        to_pos: 0,
    })?;
    while let Some(frame) = workspace.frames.pop() {
        workspace.charge(1)?;
        match frame {
            ContainFrame::PopPath => workspace.pop_path(),
            ContainFrame::Record {
                from_record,
                to_record,
                from_pos,
                mut to_pos,
            } => {
                let from_record_ref = from_schema.record(from_record);
                let to_record_ref = to_schema.record(to_record);
                let from_fields = from_schema.fields_for(from_record_ref);
                let to_fields = to_schema.fields_for(to_record_ref);
                let Some(from_field) = from_fields.get(from_pos) else {
                    while let Some(to_field) = to_fields.get(to_pos) {
                        workspace.charge(1)?;
                        if to_field.required {
                            return fail_field(
                                workspace,
                                &to_field.key,
                                labels.target_required_key,
                            );
                        }
                        to_pos = to_pos
                            .checked_add(1)
                            .ok_or(NonDerivationReason::ResourceLimit)?;
                    }
                    coupling_subset(
                        to_schema,
                        to_record_ref,
                        from_schema,
                        from_record_ref,
                        workspace,
                    )?;
                    continue;
                };
                let Some(to_field) = to_fields.get(to_pos) else {
                    return fail_field(workspace, &from_field.key, labels.source_only_key);
                };
                match cmp_field_key(&from_field.key, &to_field.key) {
                    Ordering::Less => {
                        return fail_field(workspace, &from_field.key, labels.source_only_key);
                    }
                    Ordering::Greater => {
                        if to_field.required {
                            return fail_field(
                                workspace,
                                &to_field.key,
                                labels.target_required_key,
                            );
                        }
                        workspace.push_frame(ContainFrame::Record {
                            from_record,
                            to_record,
                            from_pos,
                            to_pos: to_pos
                                .checked_add(1)
                                .ok_or(NonDerivationReason::ResourceLimit)?,
                        })?;
                    }
                    Ordering::Equal => {
                        workspace.push_path(&from_field.key)?;
                        if !from_field.required && to_field.required {
                            return Err(labels.presence_tightened);
                        }
                        workspace.push_frame(ContainFrame::Record {
                            from_record,
                            to_record,
                            from_pos: from_pos
                                .checked_add(1)
                                .ok_or(NonDerivationReason::ResourceLimit)?,
                            to_pos: to_pos
                                .checked_add(1)
                                .ok_or(NonDerivationReason::ResourceLimit)?,
                        })?;
                        workspace.push_frame(ContainFrame::PopPath)?;
                        workspace.push_frame(ContainFrame::Constraints {
                            from: from_field.constraints.clone(),
                            to: to_field.constraints.clone(),
                        })?;
                        workspace.push_frame(ContainFrame::Type {
                            from_type: from_field.type_idx,
                            to_type: to_field.type_idx,
                            union_payload: false,
                        })?;
                    }
                }
            }
            ContainFrame::Type {
                from_type,
                to_type,
                union_payload,
            } => {
                let from = from_schema.type_node(from_type).clone();
                let to = to_schema.type_node(to_type).clone();
                let mismatch = match (from, to) {
                    (_, TypeNode::Any)
                    | (TypeNode::Int, TypeNode::Int)
                    | (TypeNode::Bool, TypeNode::Bool)
                    | (TypeNode::Float64, TypeNode::Float64)
                    | (TypeNode::Bytes, TypeNode::Bytes)
                    | (TypeNode::Text, TypeNode::Text) => None,
                    (TypeNode::Any, _) => Some(NonDerivationReason::AnyNarrowed),
                    (TypeNode::Array(left), TypeNode::Array(right)) => {
                        workspace.push_path("[*]")?;
                        workspace.push_frame(ContainFrame::PopPath)?;
                        workspace.push_frame(ContainFrame::Type {
                            from_type: left,
                            to_type: right,
                            union_payload,
                        })?;
                        None
                    }
                    (TypeNode::Set(left), TypeNode::Set(right)) => {
                        workspace.push_path("[set]")?;
                        workspace.push_frame(ContainFrame::PopPath)?;
                        workspace.push_frame(ContainFrame::Type {
                            from_type: left,
                            to_type: right,
                            union_payload,
                        })?;
                        None
                    }
                    (TypeNode::Map(left), TypeNode::Map(right)) => {
                        workspace.push_path("{}")?;
                        workspace.push_frame(ContainFrame::PopPath)?;
                        workspace.push_frame(ContainFrame::Type {
                            from_type: left,
                            to_type: right,
                            union_payload,
                        })?;
                        None
                    }
                    (TypeNode::Union(left), TypeNode::Union(right)) => {
                        workspace.push_frame(ContainFrame::Union {
                            from: left,
                            to: right,
                            position: 0,
                        })?;
                        None
                    }
                    (TypeNode::Record(left), TypeNode::Record(right)) => {
                        workspace.push_frame(ContainFrame::Record {
                            from_record: left,
                            to_record: right,
                            from_pos: 0,
                            to_pos: 0,
                        })?;
                        None
                    }
                    _ => Some(NonDerivationReason::TypeChanged),
                };
                if let Some(reason) = mismatch {
                    return Err(if union_payload {
                        NonDerivationReason::UnionPayloadChanged
                    } else {
                        reason
                    });
                }
            }
            ContainFrame::Constraints { from, to } => {
                constraints_contain(from_schema, from, to_schema, to, workspace)?;
            }
            ContainFrame::Union { from, to, position } => {
                let alternatives = from_schema.union_alts_for(from.clone());
                let Some(alternative) = alternatives.get(position) else {
                    continue;
                };
                workspace.push_union_path(alternative.code)?;
                let Some(target) = find_union_alt(
                    to_schema.union_alts_for(to.clone()),
                    alternative.code,
                    workspace,
                )?
                else {
                    return Err(NonDerivationReason::UnionCodeRemoved);
                };
                workspace.push_frame(ContainFrame::Union {
                    from,
                    to,
                    position: position
                        .checked_add(1)
                        .ok_or(NonDerivationReason::ResourceLimit)?,
                })?;
                workspace.push_frame(ContainFrame::PopPath)?;
                match (alternative.payload, target.payload) {
                    (None, None) => {}
                    (Some(left), Some(right)) => {
                        workspace.push_frame(ContainFrame::Type {
                            from_type: left,
                            to_type: right,
                            union_payload: true,
                        })?;
                    }
                    _ => return Err(NonDerivationReason::UnionPayloadChanged),
                }
            }
        }
    }
    Ok(())
}

fn find_union_alt<'a>(
    alternatives: &'a [crate::compile::CompiledUnionAlt],
    code: u64,
    workspace: &mut InclusionWorkspace,
) -> Result<Option<&'a crate::compile::CompiledUnionAlt>, NonDerivationReason> {
    let mut low = 0usize;
    let mut high = alternatives.len();
    while low < high {
        workspace.charge(1)?;
        let middle = low + (high - low) / 2;
        match alternatives[middle].code.cmp(&code) {
            Ordering::Less => low = middle + 1,
            Ordering::Greater => high = middle,
            Ordering::Equal => return Ok(Some(&alternatives[middle])),
        }
    }
    Ok(None)
}

fn constraints_contain(
    from_schema: &RecordSchema,
    from_range: Range<usize>,
    to_schema: &RecordSchema,
    to_range: Range<usize>,
    workspace: &mut InclusionWorkspace,
) -> Result<(), NonDerivationReason> {
    let scans = from_range
        .len()
        .checked_add(to_range.len())
        .and_then(|value| value.checked_mul(4))
        .ok_or(NonDerivationReason::ResourceLimit)?;
    workspace.charge(scans)?;
    ranges_contain(
        from_schema.constraints_for(from_range.clone()),
        to_schema.constraints_for(to_range.clone()),
    )?;
    counts_contain(
        from_schema.constraints_for(from_range.clone()),
        to_schema.constraints_for(to_range.clone()),
    )?;
    enums_contain(from_schema, from_range, to_schema, to_range, workspace)
}

fn ranges_contain(
    from: &[CompiledConstraint],
    to: &[CompiledConstraint],
) -> Result<(), NonDerivationReason> {
    let (from_min, from_max) = int_interval(from);
    let (to_min, to_max) = int_interval(to);
    if let (Some(to_min), Some(from_min)) = (to_min, from_min) {
        if to_min > from_min {
            return Err(NonDerivationReason::RangeNarrowed);
        }
    } else if to_min.is_some() && from_min.is_none() {
        return Err(NonDerivationReason::RangeNarrowed);
    }
    if let (Some(to_max), Some(from_max)) = (to_max, from_max) {
        if to_max < from_max {
            return Err(NonDerivationReason::RangeNarrowed);
        }
    } else if to_max.is_some() && from_max.is_none() {
        return Err(NonDerivationReason::RangeNarrowed);
    }
    Ok(())
}

fn counts_contain(
    from: &[CompiledConstraint],
    to: &[CompiledConstraint],
) -> Result<(), NonDerivationReason> {
    for unit in [CountUnit::Elements, CountUnit::Octets] {
        let (from_min, from_max) = count_interval(from, unit);
        let (to_min, to_max) = count_interval(to, unit);
        if to_min > from_min {
            return Err(NonDerivationReason::CountNarrowed);
        }
        match (from_max, to_max) {
            (Some(from_hi), Some(to_hi)) if to_hi < from_hi => {
                return Err(NonDerivationReason::CountNarrowed);
            }
            (None, Some(_)) => return Err(NonDerivationReason::CountNarrowed),
            _ => {}
        }
    }
    Ok(())
}

fn enums_contain(
    from_schema: &RecordSchema,
    from_range: Range<usize>,
    to_schema: &RecordSchema,
    to_range: Range<usize>,
    workspace: &mut InclusionWorkspace,
) -> Result<(), NonDerivationReason> {
    let from_constraints = from_schema.constraints_for(from_range);
    let to_constraints = to_schema.constraints_for(to_range);
    let Some(first) = from_constraints.iter().find_map(|constraint| {
        if let CompiledConstraint::Enum { members } = constraint {
            Some(members.clone())
        } else {
            None
        }
    }) else {
        return if to_constraints
            .iter()
            .any(|constraint| matches!(constraint, CompiledConstraint::Enum { .. }))
        {
            Err(NonDerivationReason::EnumAdded)
        } else {
            Ok(())
        };
    };
    if !to_constraints
        .iter()
        .any(|constraint| matches!(constraint, CompiledConstraint::Enum { .. }))
    {
        return Ok(());
    }
    for member in &from_schema.enum_members[first] {
        let member = &from_schema.enum_bytes[member.clone()];
        workspace.charge(
            from_constraints
                .len()
                .checked_add(to_constraints.len())
                .ok_or(NonDerivationReason::ResourceLimit)?,
        )?;
        if from_constraints.iter().all(|constraint| match constraint {
            CompiledConstraint::Enum { members } => {
                contains_member(from_schema, members.clone(), member)
            }
            _ => true,
        }) && !to_constraints.iter().all(|constraint| match constraint {
            CompiledConstraint::Enum { members } => {
                contains_member(to_schema, members.clone(), member)
            }
            _ => true,
        }) {
            return Err(NonDerivationReason::EnumNarrowed);
        }
    }
    Ok(())
}

fn contains_member(schema: &RecordSchema, table: Range<usize>, member: &[u8]) -> bool {
    schema.enum_members[table]
        .binary_search_by(|candidate| schema.enum_bytes[candidate.clone()].cmp(member))
        .is_ok()
}

fn int_interval(constraints: &[CompiledConstraint]) -> (Option<&Int>, Option<&Int>) {
    let mut min = None;
    let mut max: Option<&Int> = None;
    for constraint in constraints {
        if let CompiledConstraint::Range { min: lo, max: hi } = constraint {
            if let Some(candidate) = lo {
                if min.is_none_or(|current| candidate > current) {
                    min = Some(candidate);
                }
            }
            if let Some(candidate) = hi {
                if max.is_none_or(|current| candidate < current) {
                    max = Some(candidate);
                }
            }
        }
    }
    (min, max)
}

fn count_interval(constraints: &[CompiledConstraint], unit: CountUnit) -> (u64, Option<u64>) {
    let mut min = 0u64;
    let mut max: Option<u64> = None;
    for constraint in constraints {
        if let CompiledConstraint::Count {
            unit: c_unit,
            min: lo,
            max: hi,
        } = constraint
        {
            if *c_unit == unit {
                if let Some(candidate) = *lo {
                    min = min.max(candidate);
                }
                if let Some(candidate) = *hi {
                    max = Some(max.map_or(candidate, |current: u64| current.min(candidate)));
                }
            }
        }
    }
    (min, max)
}

/// A coupling expressed over field keys, independent of per-record indices.
///
/// Compiled couplings hold presence indices whose positions depend on
/// the record's own sorted field table, so the same coupling over the same
/// keys compiles to different masks when an unrelated field is added or
/// removed. Containment therefore compares couplings by key names, never by
/// masks.
fn coupling_subset(
    required_schema: &RecordSchema,
    required_record: &CompiledRecord,
    available_schema: &RecordSchema,
    available_record: &CompiledRecord,
    workspace: &mut InclusionWorkspace,
) -> Result<(), NonDerivationReason> {
    for coupling in required_schema.couplings_for(required_record) {
        let mut found = false;
        for candidate in available_schema.couplings_for(available_record) {
            workspace.charge(1)?;
            if coupling_equal(
                required_schema,
                required_record,
                coupling,
                available_schema,
                available_record,
                candidate,
            ) {
                found = true;
                break;
            }
        }
        if !found {
            return Err(NonDerivationReason::CouplingAdded);
        }
    }
    Ok(())
}

fn coupling_equal(
    left_schema: &RecordSchema,
    left_record: &CompiledRecord,
    left: &CompiledCoupling,
    right_schema: &RecordSchema,
    right_record: &CompiledRecord,
    right: &CompiledCoupling,
) -> bool {
    let left_fields = left_schema.fields_for(left_record);
    let right_fields = right_schema.fields_for(right_record);
    match (left, right) {
        (
            CompiledCoupling::Requires {
                if_index: a,
                then_index: b,
            },
            CompiledCoupling::Requires {
                if_index: c,
                then_index: d,
            },
        ) => {
            left_fields[*a].key == right_fields[*c].key
                && left_fields[*b].key == right_fields[*d].key
        }
        (
            CompiledCoupling::ExactlyOne { indices: a },
            CompiledCoupling::ExactlyOne { indices: b },
        )
        | (CompiledCoupling::Together { indices: a }, CompiledCoupling::Together { indices: b }) => {
            let a = &left_schema.coupling_indices[a.clone()];
            let b = &right_schema.coupling_indices[b.clone()];
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|(left, right)| left_fields[*left].key == right_fields[*right].key)
        }
        _ => false,
    }
}

fn fail_field(
    path: &mut InclusionWorkspace,
    key: &str,
    reason: NonDerivationReason,
) -> Result<(), NonDerivationReason> {
    path.push_path(key)?;
    Err(reason)
}

#[derive(Clone, Copy)]
enum WitnessPreference {
    Lower,
    Upper,
}

fn wire_counterexample(
    from: &RecordSchema,
    to: &RecordSchema,
    path: &[String],
    reason: NonDerivationReason,
    limits: InclusionLimits,
    workspace: &mut InclusionWorkspace,
) -> Result<Option<WireCounterexample>, NonDerivationReason> {
    let mut synthesis_resource = None;
    for preference in [WitnessPreference::Lower, WitnessPreference::Upper] {
        workspace.witness.clear();
        workspace.witness_presence.clear();
        if let Err(error) = synthesize_witness(from, path, reason, preference, limits, workspace) {
            synthesis_resource = Some(error);
            continue;
        }
        let bytes = &workspace.witness;
        // Replay cost is bounded by the independent witness byte/item/depth limits. Charging a
        // byte-length multiplier here would be an arbitrary proxy rather than a count of schema
        // derivation work, and could turn a valid counterexample into Unknown solely because of
        // scalar payload width.
        let canonical = match CanonicalCbor::from_slice(bytes, witness_decode_limits(limits)) {
            Ok(canonical) => canonical,
            Err(error) if error.code == ErrorCode::AllocationFailed => {
                return Err(NonDerivationReason::AllocationFailed);
            }
            Err(_) => continue,
        };
        if let Err(error) = from.check_with_workspace(
            canonical.as_canonical_ref(),
            witness_decode_limits(limits),
            &mut workspace.source_validation,
        ) {
            if let Some(resource) = validation_resource_reason(&error) {
                return Err(resource);
            }
            continue;
        }
        if let Err(rejection) = to.check_with_workspace(
            canonical.as_canonical_ref(),
            witness_decode_limits(limits),
            &mut workspace.target_validation,
        ) {
            if let Some(resource) = validation_resource_reason(&rejection) {
                return Err(resource);
            }
            return Ok(Some(WireCounterexample {
                canonical,
                rejection,
            }));
        }
    }
    synthesis_resource.map_or(Ok(None), Err)
}

const fn witness_decode_limits(limits: InclusionLimits) -> DecodeLimits {
    DecodeLimits {
        max_input_bytes: limits.max_witness_bytes,
        max_depth: limits.max_value_depth,
        max_total_items: limits.max_witness_items,
        max_array_len: limits.max_witness_items,
        max_map_len: limits.max_witness_items / 2,
        max_bytes_len: limits.max_witness_bytes,
        max_text_len: limits.max_witness_bytes,
    }
}

const fn validation_resource_reason(error: &RecordError) -> Option<NonDerivationReason> {
    match &error.fault {
        crate::Fault::WorkspaceTooSmall => Some(NonDerivationReason::ResourceLimit),
        crate::Fault::Grammar(error) if matches!(error.code, ErrorCode::AllocationFailed) => {
            Some(NonDerivationReason::AllocationFailed)
        }
        crate::Fault::Grammar(error)
            if matches!(
                error.code,
                ErrorCode::DepthLimitExceeded
                    | ErrorCode::TotalItemsLimitExceeded
                    | ErrorCode::ArrayLenLimitExceeded
                    | ErrorCode::MapLenLimitExceeded
                    | ErrorCode::BytesLenLimitExceeded
                    | ErrorCode::TextLenLimitExceeded
                    | ErrorCode::MessageLenLimitExceeded
            ) =>
        {
            Some(NonDerivationReason::ResourceLimit)
        }
        crate::Fault::Grammar(_) | crate::Fault::Shape(_) | crate::Fault::Constraint(_) => None,
    }
}

#[allow(clippy::too_many_lines)]
fn synthesize_witness(
    schema: &RecordSchema,
    forced_path: &[String],
    reason: NonDerivationReason,
    preference: WitnessPreference,
    limits: InclusionLimits,
    workspace: &mut InclusionWorkspace,
) -> Result<(), NonDerivationReason> {
    workspace.witness_frames.clear();
    push_witness_frame(
        &mut workspace.witness_frames,
        limits.max_frames,
        WitnessFrame::RecordStart {
            record: schema.root_record,
            forced_depth: 0,
            depth: 1,
        },
    )?;
    let mut items = 0usize;
    while let Some(frame) = workspace.witness_frames.pop() {
        workspace.charge(1)?;
        match frame {
            WitnessFrame::RecordStart {
                record,
                forced_depth,
                depth,
            } => {
                check_witness_depth(depth, limits)?;
                let record_ref = schema.record(record);
                let fields = schema.fields_for(record_ref);
                let presence_base = workspace.witness_presence.len();
                let words = fields.len().div_ceil(64);
                let presence_end = presence_base
                    .checked_add(words)
                    .ok_or(NonDerivationReason::ResourceLimit)?;
                if presence_end > workspace.witness_presence.capacity() {
                    return Err(NonDerivationReason::AllocationFailed);
                }
                workspace.witness_presence.resize(presence_end, 0);
                for index in &schema.required_fields[record_ref.required.clone()] {
                    workspace.charge(1)?;
                    mark_witness_present(&mut workspace.witness_presence[presence_base..], *index);
                }
                if !matches!(
                    reason,
                    NonDerivationReason::RequiredAdded
                        | NonDerivationReason::OptionalToRequired
                        | NonDerivationReason::RequiredToOptional
                ) {
                    if let Some(forced) = forced_path.get(forced_depth) {
                        workspace.charge(1)?;
                        if let Ok(index) = fields
                            .binary_search_by(|field| cmp_field_key(&field.key, forced.as_str()))
                        {
                            mark_witness_present(
                                &mut workspace.witness_presence[presence_base..],
                                index,
                            );
                        }
                    }
                }
                if matches!(preference, WitnessPreference::Upper)
                    && forced_depth >= forced_path.len()
                {
                    for (index, field) in fields.iter().enumerate() {
                        workspace.charge(1)?;
                        if !field.required {
                            mark_witness_present(
                                &mut workspace.witness_presence[presence_base..],
                                index,
                            );
                            break;
                        }
                    }
                }
                close_witness_couplings(
                    schema,
                    record_ref,
                    &mut workspace.witness_presence[presence_base..],
                    &mut workspace.remaining_steps,
                )?;
                let mut len = 0usize;
                for index in 0..fields.len() {
                    charge_remaining(&mut workspace.remaining_steps, 1)
                        .map_err(|_| NonDerivationReason::ResourceLimit)?;
                    if witness_present(&workspace.witness_presence[presence_base..], index) {
                        len = len
                            .checked_add(1)
                            .ok_or(NonDerivationReason::ResourceLimit)?;
                    }
                }
                charge_witness_items(&mut items, len, true, limits)?;
                write_witness_head(&mut workspace.witness, 5, len, limits.max_witness_bytes)?;
                push_witness_frame(
                    &mut workspace.witness_frames,
                    limits.max_frames,
                    WitnessFrame::RecordFinish { presence_base },
                )?;
                push_witness_frame(
                    &mut workspace.witness_frames,
                    limits.max_frames,
                    WitnessFrame::RecordNext {
                        record,
                        field: 0,
                        presence_base,
                        forced_depth,
                        depth,
                    },
                )?;
            }
            WitnessFrame::RecordNext {
                record,
                field,
                presence_base,
                forced_depth,
                depth,
            } => {
                let record_ref = schema.record(record);
                let fields = schema.fields_for(record_ref);
                let Some(current) = fields.get(field) else {
                    continue;
                };
                let next = field
                    .checked_add(1)
                    .ok_or(NonDerivationReason::ResourceLimit)?;
                push_witness_frame(
                    &mut workspace.witness_frames,
                    limits.max_frames,
                    WitnessFrame::RecordNext {
                        record,
                        field: next,
                        presence_base,
                        forced_depth,
                        depth,
                    },
                )?;
                if !witness_present(&workspace.witness_presence[presence_base..], field) {
                    continue;
                }
                write_witness_text(
                    &mut workspace.witness,
                    &current.key,
                    limits.max_witness_bytes,
                )?;
                let nested_forced = if forced_path
                    .get(forced_depth)
                    .is_some_and(|key| key == current.key.as_ref())
                {
                    forced_depth
                        .checked_add(1)
                        .ok_or(NonDerivationReason::ResourceLimit)?
                } else {
                    forced_path.len()
                };
                push_witness_frame(
                    &mut workspace.witness_frames,
                    limits.max_frames,
                    WitnessFrame::Value {
                        type_idx: current.type_idx,
                        constraints: current.constraints.clone(),
                        forced_depth: nested_forced,
                        depth,
                    },
                )?;
            }
            WitnessFrame::RecordFinish { presence_base } => {
                workspace.witness_presence.truncate(presence_base);
            }
            WitnessFrame::Value {
                type_idx,
                constraints,
                forced_depth,
                depth,
            } => {
                if write_enum_candidate(
                    schema,
                    constraints.clone(),
                    preference,
                    &mut workspace.witness,
                    &mut workspace.remaining_steps,
                    limits.max_witness_bytes,
                )? {
                    continue;
                }
                match schema.type_node(type_idx) {
                    TypeNode::Int => write_int_candidate(
                        schema,
                        constraints,
                        preference,
                        &mut workspace.witness,
                        &mut workspace.witness_bytes_scratch,
                        &mut workspace.witness_int_scratch,
                        limits,
                    )?,
                    TypeNode::Bool => append_witness(&mut workspace.witness, &[0xf4], limits)?,
                    TypeNode::Float64 => append_witness(
                        &mut workspace.witness,
                        &[0xfb, 0, 0, 0, 0, 0, 0, 0, 0],
                        limits,
                    )?,
                    TypeNode::Bytes | TypeNode::Text => {
                        let len =
                            candidate_count(schema, constraints, CountUnit::Octets, preference)
                                .map_err(|_| NonDerivationReason::ResourceLimit)?;
                        if len > limits.max_witness_bytes {
                            return Err(NonDerivationReason::ResourceLimit);
                        }
                        let major = if matches!(schema.type_node(type_idx), TypeNode::Text) {
                            3
                        } else {
                            2
                        };
                        write_witness_head(
                            &mut workspace.witness,
                            major,
                            len,
                            limits.max_witness_bytes,
                        )?;
                        append_witness_fill(
                            &mut workspace.witness,
                            if major == 2 { 0 } else { b'a' },
                            len,
                            limits,
                        )?;
                    }
                    TypeNode::Array(inner) | TypeNode::Set(inner) => {
                        let is_set = matches!(schema.type_node(type_idx), TypeNode::Set(_));
                        let marker = if is_set { "[set]" } else { "[*]" };
                        let force_child = forced_path
                            .get(forced_depth)
                            .is_some_and(|segment| segment == marker);
                        let child_forced = if force_child {
                            forced_depth
                                .checked_add(1)
                                .ok_or(NonDerivationReason::ResourceLimit)?
                        } else {
                            forced_path.len()
                        };
                        let mut len =
                            candidate_count(schema, constraints, CountUnit::Elements, preference)
                                .map_err(|_| NonDerivationReason::ResourceLimit)?;
                        if force_child && len == 0 {
                            len = 1;
                        }
                        let next_depth = depth
                            .checked_add(1)
                            .ok_or(NonDerivationReason::ResourceLimit)?;
                        check_witness_depth(next_depth, limits)?;
                        charge_witness_items(&mut items, len, false, limits)?;
                        write_witness_head(
                            &mut workspace.witness,
                            4,
                            len,
                            limits.max_witness_bytes,
                        )?;
                        if is_set && len > 1 {
                            write_distinct_scalar_set_elements(
                                schema,
                                *inner,
                                len,
                                &mut workspace.witness,
                                &mut workspace.remaining_steps,
                                limits,
                            )?;
                        } else {
                            push_witness_frame(
                                &mut workspace.witness_frames,
                                limits.max_frames,
                                WitnessFrame::ArrayNext {
                                    inner: *inner,
                                    remaining: len,
                                    forced_depth: child_forced,
                                    depth: next_depth,
                                },
                            )?;
                        }
                    }
                    TypeNode::Map(inner) => {
                        let force_child = forced_path
                            .get(forced_depth)
                            .is_some_and(|segment| segment == "{}");
                        let child_forced = if force_child {
                            forced_depth
                                .checked_add(1)
                                .ok_or(NonDerivationReason::ResourceLimit)?
                        } else {
                            forced_path.len()
                        };
                        let mut len =
                            candidate_count(schema, constraints, CountUnit::Elements, preference)
                                .map_err(|_| NonDerivationReason::ResourceLimit)?;
                        if force_child && len == 0 {
                            len = 1;
                        }
                        let next_depth = depth
                            .checked_add(1)
                            .ok_or(NonDerivationReason::ResourceLimit)?;
                        check_witness_depth(next_depth, limits)?;
                        charge_witness_items(&mut items, len, true, limits)?;
                        write_witness_head(
                            &mut workspace.witness,
                            5,
                            len,
                            limits.max_witness_bytes,
                        )?;
                        push_witness_frame(
                            &mut workspace.witness_frames,
                            limits.max_frames,
                            WitnessFrame::MapNext {
                                inner: *inner,
                                index: 0,
                                remaining: len,
                                forced_depth: child_forced,
                                depth: next_depth,
                            },
                        )?;
                    }
                    TypeNode::Union(alternatives) => {
                        let alternatives = schema.union_alts_for(alternatives.clone());
                        let forced_code = forced_path
                            .get(forced_depth)
                            .and_then(|segment| segment.strip_prefix("union("))
                            .and_then(|segment| segment.strip_suffix(')'))
                            .and_then(|segment| segment.parse::<u64>().ok());
                        let alternative = forced_code
                            .and_then(|code| {
                                alternatives
                                    .binary_search_by_key(&code, |alternative| alternative.code)
                                    .ok()
                                    .and_then(|index| alternatives.get(index))
                            })
                            .or_else(|| match preference {
                                WitnessPreference::Lower => alternatives.first(),
                                WitnessPreference::Upper => alternatives.last(),
                            });
                        let Some(alternative) = alternative else {
                            append_witness(&mut workspace.witness, &[0xf6], limits)?;
                            continue;
                        };
                        let next_depth = depth
                            .checked_add(1)
                            .ok_or(NonDerivationReason::ResourceLimit)?;
                        check_witness_depth(next_depth, limits)?;
                        let len = usize::from(alternative.payload.is_some()) + 1;
                        charge_witness_items(&mut items, len, false, limits)?;
                        write_witness_head(
                            &mut workspace.witness,
                            4,
                            len,
                            limits.max_witness_bytes,
                        )?;
                        write_witness_head(
                            &mut workspace.witness,
                            0,
                            usize::try_from(alternative.code)
                                .map_err(|_| NonDerivationReason::ResourceLimit)?,
                            limits.max_witness_bytes,
                        )?;
                        if let Some(payload) = alternative.payload {
                            push_witness_frame(
                                &mut workspace.witness_frames,
                                limits.max_frames,
                                WitnessFrame::Value {
                                    type_idx: payload,
                                    constraints: 0..0,
                                    forced_depth: if forced_code.is_some() {
                                        forced_depth
                                            .checked_add(1)
                                            .ok_or(NonDerivationReason::ResourceLimit)?
                                    } else {
                                        forced_path.len()
                                    },
                                    depth: next_depth,
                                },
                            )?;
                        }
                    }
                    TypeNode::Record(record) => {
                        let next_depth = depth
                            .checked_add(1)
                            .ok_or(NonDerivationReason::ResourceLimit)?;
                        push_witness_frame(
                            &mut workspace.witness_frames,
                            limits.max_frames,
                            WitnessFrame::RecordStart {
                                record: *record,
                                forced_depth,
                                depth: next_depth,
                            },
                        )?;
                    }
                    TypeNode::Any => append_witness(&mut workspace.witness, &[0xf6], limits)?,
                }
            }
            WitnessFrame::ArrayNext {
                inner,
                remaining,
                forced_depth,
                depth,
            } => {
                if remaining == 0 {
                    continue;
                }
                push_witness_frame(
                    &mut workspace.witness_frames,
                    limits.max_frames,
                    WitnessFrame::ArrayNext {
                        inner,
                        remaining: remaining - 1,
                        forced_depth,
                        depth,
                    },
                )?;
                push_witness_frame(
                    &mut workspace.witness_frames,
                    limits.max_frames,
                    WitnessFrame::Value {
                        type_idx: inner,
                        constraints: 0..0,
                        forced_depth,
                        depth,
                    },
                )?;
            }
            WitnessFrame::MapNext {
                inner,
                index,
                remaining,
                forced_depth,
                depth,
            } => {
                if remaining == 0 {
                    continue;
                }
                let key = WitnessMapKey::new(index);
                write_witness_text(
                    &mut workspace.witness,
                    key.as_str(),
                    limits.max_witness_bytes,
                )?;
                push_witness_frame(
                    &mut workspace.witness_frames,
                    limits.max_frames,
                    WitnessFrame::MapNext {
                        inner,
                        index: index
                            .checked_add(1)
                            .ok_or(NonDerivationReason::ResourceLimit)?,
                        remaining: remaining - 1,
                        forced_depth,
                        depth,
                    },
                )?;
                push_witness_frame(
                    &mut workspace.witness_frames,
                    limits.max_frames,
                    WitnessFrame::Value {
                        type_idx: inner,
                        constraints: 0..0,
                        forced_depth,
                        depth,
                    },
                )?;
            }
        }
    }
    Ok(())
}

fn push_witness_frame(
    frames: &mut Vec<WitnessFrame>,
    limit: usize,
    frame: WitnessFrame,
) -> Result<(), NonDerivationReason> {
    if frames.len() >= limit || frames.len() >= frames.capacity() {
        return Err(NonDerivationReason::ResourceLimit);
    }
    frames.push(frame);
    Ok(())
}

const fn check_witness_depth(
    depth: usize,
    limits: InclusionLimits,
) -> Result<(), NonDerivationReason> {
    if depth > limits.max_value_depth {
        Err(NonDerivationReason::ResourceLimit)
    } else {
        Ok(())
    }
}

fn charge_witness_items(
    items: &mut usize,
    len: usize,
    map: bool,
    limits: InclusionLimits,
) -> Result<(), NonDerivationReason> {
    if map && len > limits.max_witness_items / 2 {
        return Err(NonDerivationReason::ResourceLimit);
    }
    let charged = if map {
        len.checked_mul(2)
            .ok_or(NonDerivationReason::ResourceLimit)?
    } else {
        len
    };
    *items = items
        .checked_add(charged)
        .ok_or(NonDerivationReason::ResourceLimit)?;
    if *items > limits.max_witness_items {
        return Err(NonDerivationReason::ResourceLimit);
    }
    Ok(())
}

fn append_witness(
    output: &mut Vec<u8>,
    bytes: &[u8],
    limits: InclusionLimits,
) -> Result<(), NonDerivationReason> {
    let end = output
        .len()
        .checked_add(bytes.len())
        .ok_or(NonDerivationReason::ResourceLimit)?;
    if end > limits.max_witness_bytes || end > output.capacity() {
        return Err(NonDerivationReason::ResourceLimit);
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn append_witness_fill(
    output: &mut Vec<u8>,
    byte: u8,
    len: usize,
    limits: InclusionLimits,
) -> Result<(), NonDerivationReason> {
    let end = output
        .len()
        .checked_add(len)
        .ok_or(NonDerivationReason::ResourceLimit)?;
    if end > limits.max_witness_bytes || end > output.capacity() {
        return Err(NonDerivationReason::ResourceLimit);
    }
    output.resize(end, byte);
    Ok(())
}

fn write_distinct_scalar_set_elements(
    schema: &RecordSchema,
    inner: usize,
    len: usize,
    output: &mut Vec<u8>,
    remaining_steps: &mut usize,
    limits: InclusionLimits,
) -> Result<(), NonDerivationReason> {
    match schema.type_node(inner) {
        TypeNode::Int | TypeNode::Any => {
            for index in 0..len {
                charge_remaining(remaining_steps, 1)
                    .map_err(|_| NonDerivationReason::ResourceLimit)?;
                write_witness_head(output, 0, index, limits.max_witness_bytes)?;
            }
        }
        TypeNode::Bool if len <= 2 => {
            charge_remaining(remaining_steps, len)
                .map_err(|_| NonDerivationReason::ResourceLimit)?;
            append_witness(output, &[0xf4, 0xf5][..len], limits)?;
        }
        TypeNode::Float64 => {
            for index in 0..len {
                charge_remaining(remaining_steps, 1)
                    .map_err(|_| NonDerivationReason::ResourceLimit)?;
                let bits = u64::try_from(index).map_err(|_| NonDerivationReason::ResourceLimit)?;
                let mut encoded = [0u8; 9];
                encoded[0] = 0xfb;
                encoded[1..].copy_from_slice(&bits.to_be_bytes());
                append_witness(output, &encoded, limits)?;
            }
        }
        TypeNode::Bytes | TypeNode::Text => {
            let major = if matches!(schema.type_node(inner), TypeNode::Text) {
                3
            } else {
                2
            };
            for index in 0..len {
                charge_remaining(remaining_steps, 1)
                    .map_err(|_| NonDerivationReason::ResourceLimit)?;
                let candidate = WitnessMapKey::new(index);
                write_witness_head(
                    output,
                    major,
                    candidate.as_str().len(),
                    limits.max_witness_bytes,
                )?;
                append_witness(output, candidate.as_str().as_bytes(), limits)?;
            }
        }
        TypeNode::Bool
        | TypeNode::Array(_)
        | TypeNode::Set(_)
        | TypeNode::Map(_)
        | TypeNode::Union(_)
        | TypeNode::Record(_) => return Err(NonDerivationReason::ResourceLimit),
    }
    Ok(())
}

fn write_witness_head(
    output: &mut Vec<u8>,
    major: u8,
    value: usize,
    max_bytes: usize,
) -> Result<(), NonDerivationReason> {
    let value = u64::try_from(value).map_err(|_| NonDerivationReason::ResourceLimit)?;
    let mut head = [0u8; 9];
    let len = if value <= 23 {
        head[0] = (major << 5) | u8::try_from(value).unwrap_or(0);
        1
    } else if u8::try_from(value).is_ok() {
        head[0] = (major << 5) | 0x18;
        head[1] = u8::try_from(value).unwrap_or(0);
        2
    } else if u16::try_from(value).is_ok() {
        head[0] = (major << 5) | 0x19;
        head[1..3].copy_from_slice(&u16::try_from(value).unwrap_or(0).to_be_bytes());
        3
    } else if u32::try_from(value).is_ok() {
        head[0] = (major << 5) | 0x1a;
        head[1..5].copy_from_slice(&u32::try_from(value).unwrap_or(0).to_be_bytes());
        5
    } else {
        head[0] = (major << 5) | 0x1b;
        head[1..9].copy_from_slice(&value.to_be_bytes());
        9
    };
    append_witness(
        output,
        &head[..len],
        InclusionLimits {
            max_witness_bytes: max_bytes,
            max_steps: usize::MAX,
            max_frames: usize::MAX,
            max_path_depth: usize::MAX,
            max_path_bytes: usize::MAX,
            max_witness_items: usize::MAX,
            max_value_depth: usize::MAX,
        },
    )
}

fn write_witness_text(
    output: &mut Vec<u8>,
    text: &str,
    max_bytes: usize,
) -> Result<(), NonDerivationReason> {
    write_witness_head(output, 3, text.len(), max_bytes)?;
    let limits = InclusionLimits {
        max_witness_bytes: max_bytes,
        max_steps: usize::MAX,
        max_frames: usize::MAX,
        max_path_depth: usize::MAX,
        max_path_bytes: usize::MAX,
        max_witness_items: usize::MAX,
        max_value_depth: usize::MAX,
    };
    append_witness(output, text.as_bytes(), limits)
}

fn write_enum_candidate(
    schema: &RecordSchema,
    constraints: Range<usize>,
    preference: WitnessPreference,
    output: &mut Vec<u8>,
    remaining_steps: &mut usize,
    max_bytes: usize,
) -> Result<bool, NonDerivationReason> {
    let constraints = schema.constraints_for(constraints);
    let mut base: Option<&[Range<usize>]> = None;
    for constraint in constraints {
        charge_remaining(remaining_steps, 1).map_err(|_| NonDerivationReason::ResourceLimit)?;
        if let CompiledConstraint::Enum { members } = constraint {
            let table = &schema.enum_members[members.clone()];
            if base.is_none_or(|current| table.len() < current.len()) {
                base = Some(table);
            }
        }
    }
    let Some(base) = base else {
        return Ok(false);
    };
    for position in 0..base.len() {
        charge_remaining(remaining_steps, 1).map_err(|_| NonDerivationReason::ResourceLimit)?;
        let index = match preference {
            WitnessPreference::Lower => position,
            WitnessPreference::Upper => base.len() - position - 1,
        };
        let range = &base[index];
        let encoded = &schema.enum_bytes[range.clone()];
        let mut accepted = true;
        for constraint in constraints {
            charge_remaining(remaining_steps, 1).map_err(|_| NonDerivationReason::ResourceLimit)?;
            match constraint {
                CompiledConstraint::Enum { members }
                    if !contains_member(schema, members.clone(), encoded) =>
                {
                    accepted = false;
                    break;
                }
                _ => {}
            }
        }
        if accepted
            && enum_candidate_satisfies_non_enum_constraints(encoded, constraints, remaining_steps)?
        {
            let limits = InclusionLimits {
                max_witness_bytes: max_bytes,
                max_steps: usize::MAX,
                max_frames: usize::MAX,
                max_path_depth: usize::MAX,
                max_path_bytes: usize::MAX,
                max_witness_items: usize::MAX,
                max_value_depth: usize::MAX,
            };
            append_witness(output, encoded, limits)?;
            return Ok(true);
        }
    }
    Ok(false)
}

fn enum_candidate_satisfies_non_enum_constraints(
    encoded: &[u8],
    constraints: &[CompiledConstraint],
    remaining_steps: &mut usize,
) -> Result<bool, NonDerivationReason> {
    let limits = DecodeLimits::for_bytes(encoded.len());
    let mut has_range = false;
    let mut has_count = false;
    for constraint in constraints {
        charge_remaining(remaining_steps, 1).map_err(|_| NonDerivationReason::ResourceLimit)?;
        has_range |= matches!(constraint, CompiledConstraint::Range { .. });
        has_count |= matches!(constraint, CompiledConstraint::Count { .. });
    }
    if has_range {
        let Ok(mut decoder) = Decoder::<true>::new_checked(encoded, limits) else {
            return Ok(false);
        };
        let Ok(value) = IntegerRef::decode(&mut decoder) else {
            return Ok(false);
        };
        for constraint in constraints {
            charge_remaining(remaining_steps, 1).map_err(|_| NonDerivationReason::ResourceLimit)?;
            if let CompiledConstraint::Range { min, max } = constraint {
                let accepted = min
                    .as_ref()
                    .is_none_or(|bound| cmp_integer_ref_to_int(value, bound) != Ordering::Less)
                    && max.as_ref().is_none_or(|bound| {
                        cmp_integer_ref_to_int(value, bound) != Ordering::Greater
                    });
                if !accepted {
                    return Ok(false);
                }
            }
        }
        return Ok(true);
    }
    if has_count {
        let Ok(mut decoder) = Decoder::<true>::new_checked(encoded, limits) else {
            return Ok(false);
        };
        let Ok(value) = <&str>::decode(&mut decoder) else {
            return Ok(false);
        };
        let Ok(len) = u64::try_from(value.len()) else {
            return Ok(false);
        };
        for constraint in constraints {
            charge_remaining(remaining_steps, 1).map_err(|_| NonDerivationReason::ResourceLimit)?;
            if let CompiledConstraint::Count {
                unit: CountUnit::Octets,
                min,
                max,
            } = constraint
            {
                if min.is_some_and(|bound| len < bound) || max.is_some_and(|bound| len > bound) {
                    return Ok(false);
                }
            }
        }
        return Ok(true);
    }
    Ok(true)
}

fn write_int_candidate(
    schema: &RecordSchema,
    constraints: Range<usize>,
    preference: WitnessPreference,
    output: &mut Vec<u8>,
    scratch: &mut Vec<u8>,
    int_scratch: &mut Vec<u8>,
    limits: InclusionLimits,
) -> Result<(), NonDerivationReason> {
    let (min, max) = int_interval(schema.constraints_for(constraints));
    let selected = match preference {
        WitnessPreference::Lower => min.or(max),
        WitnessPreference::Upper => max.or(min),
    };
    let Some(value) = selected else {
        return append_witness(output, &[0], limits);
    };
    scratch.clear();
    let encode_limits = EncodeLimits {
        max_output_bytes: scratch.capacity(),
        max_depth: 1,
        max_total_items: 0,
        max_array_len: 0,
        max_map_len: 0,
        max_bytes_len: scratch.capacity(),
        max_text_len: scratch.capacity(),
    };
    let mut encoder = Encoder::with_sink_and_limits(WitnessSink(scratch), encode_limits)
        .map_err(|_| NonDerivationReason::ResourceLimit)?;
    value
        .encode_into(&mut encoder, int_scratch)
        .map_err(|_| NonDerivationReason::ResourceLimit)?;
    encoder
        .finish()
        .map_err(|_| NonDerivationReason::ResourceLimit)?;
    append_witness(output, scratch, limits)
}

fn close_witness_couplings(
    schema: &RecordSchema,
    record: &CompiledRecord,
    presence: &mut [u64],
    remaining_steps: &mut usize,
) -> Result<(), NonDerivationReason> {
    let max_rounds = schema
        .fields_for(record)
        .len()
        .checked_add(1)
        .ok_or(NonDerivationReason::ResourceLimit)?;
    for _ in 0..max_rounds {
        let mut changed = false;
        for coupling in schema.couplings_for(record) {
            charge_remaining(remaining_steps, 1).map_err(|_| NonDerivationReason::ResourceLimit)?;
            match coupling {
                CompiledCoupling::Requires {
                    if_index,
                    then_index,
                } if witness_present(presence, *if_index)
                    && !witness_present(presence, *then_index) =>
                {
                    mark_witness_present(presence, *then_index);
                    changed = true;
                }
                CompiledCoupling::ExactlyOne { indices } => {
                    let mut found = None;
                    for index in schema.coupling_indices[indices.clone()].iter().copied() {
                        charge_remaining(remaining_steps, 1)
                            .map_err(|_| NonDerivationReason::ResourceLimit)?;
                        if witness_present(presence, index) {
                            found = Some(index);
                            break;
                        }
                    }
                    if found.is_none() {
                        mark_witness_present(presence, schema.coupling_indices[indices.start]);
                        changed = true;
                    }
                }
                CompiledCoupling::Together { indices } => {
                    let mut any = false;
                    for index in schema.coupling_indices[indices.clone()].iter().copied() {
                        charge_remaining(remaining_steps, 1)
                            .map_err(|_| NonDerivationReason::ResourceLimit)?;
                        any |= witness_present(presence, index);
                    }
                    if any {
                        for index in schema.coupling_indices[indices.clone()].iter().copied() {
                            charge_remaining(remaining_steps, 1)
                                .map_err(|_| NonDerivationReason::ResourceLimit)?;
                            if !witness_present(presence, index) {
                                mark_witness_present(presence, index);
                                changed = true;
                            }
                        }
                    }
                }
                CompiledCoupling::Requires { .. } => {}
            }
        }
        if !changed {
            return Ok(());
        }
    }
    Err(NonDerivationReason::ResourceLimit)
}

fn charge_remaining(remaining: &mut usize, steps: usize) -> Result<(), CborError> {
    *remaining = remaining
        .checked_sub(steps)
        .ok_or_else(|| CborError::new(ErrorCode::TotalItemsLimitExceeded, 0))?;
    Ok(())
}

const WITNESS_KEY_DIGITS: usize = (usize::BITS as usize * 30_103) / 100_000 + 1;

struct WitnessMapKey {
    bytes: [u8; WITNESS_KEY_DIGITS + 1],
}

impl WitnessMapKey {
    fn new(mut value: usize) -> Self {
        let mut bytes = [b'0'; WITNESS_KEY_DIGITS + 1];
        bytes[0] = b'k';
        let mut index = bytes.len();
        while index > 1 {
            index -= 1;
            bytes[index] = b'0' + u8::try_from(value % 10).unwrap_or(0);
            value /= 10;
        }
        Self { bytes }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes).expect("witness map key contains only ASCII digits")
    }
}

fn mark_witness_present(words: &mut [u64], index: usize) {
    words[index / 64] |= 1u64 << (index % 64);
}
fn witness_present(words: &[u64], index: usize) -> bool {
    words
        .get(index / 64)
        .is_some_and(|word| word & (1u64 << (index % 64)) != 0)
}

fn candidate_count(
    schema: &RecordSchema,
    constraints: Range<usize>,
    unit: CountUnit,
    preference: WitnessPreference,
) -> Result<usize, CborError> {
    let mut min = 0u64;
    let mut max: Option<u64> = None;
    for constraint in schema.constraints_for(constraints) {
        if let CompiledConstraint::Count {
            unit: candidate_unit,
            min: lower,
            max: upper,
        } = constraint
        {
            if *candidate_unit == unit {
                min = min.max(lower.unwrap_or(0));
                max = match (max, upper) {
                    (Some(a), Some(b)) => Some(a.min(*b)),
                    (None, Some(b)) => Some(*b),
                    (value, None) => value,
                };
            }
        }
    }
    let value = match preference {
        WitnessPreference::Lower => min,
        WitnessPreference::Upper => max.unwrap_or(min),
    };
    usize::try_from(value).map_err(|_| CborError::new(ErrorCode::TotalItemsLimitExceeded, 0))
}
