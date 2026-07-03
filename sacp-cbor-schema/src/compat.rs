//! Structural containment derivation between compiled schemas.

use alloc::{string::String, string::ToString, vec::Vec};
use core::cmp::Ordering;
use core::ops::Range;

use crate::compile::{
    cmp_field_key, CompiledConstraint, CompiledCoupling, CompiledField, CompiledRecord,
    RecordSchema, TypeNode,
};
use crate::ir::CountUnit;
use crate::Int;

/// Structural containment result for both successor directions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Containment {
    /// Every value admitted by the old schema is admitted by the new schema.
    pub forward: Direction,
    /// Every value admitted by the new schema is admitted by the old schema.
    pub backward: Direction,
}

/// One containment direction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    /// The direction is structurally derivable.
    Holds,
    /// The direction is not derivable, with the first failing rule.
    NotDerivable(NonDerivation),
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
    pub fn containment(&self, new: &Self) -> Containment {
        Containment {
            forward: derive(self, new, &FORWARD_LABELS),
            backward: derive(new, self, &BACKWARD_LABELS),
        }
    }
}

#[cfg(kani)]
pub(crate) const fn together_holds_for_mask(bits: u64, mask: u64) -> bool {
    bits == 0 || bits == mask
}

/// Direction-specific names for the presence-level containment breaks.
///
/// The walker derives one relation — every value admitted by `from` is
/// admitted by `to` — and both directions run the same walker with swapped
/// arguments. The public reasons name each break from the old-to-new
/// evolution perspective, so the same structural break carries a different
/// name per direction: a key declared only in `from` is a removed field when
/// `from` is the old schema and an added field when `from` is the successor.
struct DirectionLabels {
    /// A key declared only in `from`: `from` admits values carrying it and
    /// `to`'s closed keys reject them.
    source_only_key: NonDerivationReason,
    /// A key declared only in `to` and required there: `from`'s values omit
    /// a key `to` demands.
    target_required_key: NonDerivationReason,
    /// A shared key optional in `from` but required in `to`.
    presence_tightened: NonDerivationReason,
}

const FORWARD_LABELS: DirectionLabels = DirectionLabels {
    source_only_key: NonDerivationReason::FieldRemoved,
    target_required_key: NonDerivationReason::RequiredAdded,
    presence_tightened: NonDerivationReason::OptionalToRequired,
};

const BACKWARD_LABELS: DirectionLabels = DirectionLabels {
    source_only_key: NonDerivationReason::FieldAdded,
    target_required_key: NonDerivationReason::FieldRemoved,
    presence_tightened: NonDerivationReason::RequiredToOptional,
};

fn derive(from: &RecordSchema, to: &RecordSchema, labels: &DirectionLabels) -> Direction {
    let mut path = Vec::new();
    match record_contains(
        from,
        from.record(from.root_record),
        to,
        to.record(to.root_record),
        &mut path,
        labels,
    ) {
        Ok(()) => Direction::Holds,
        Err(reason) => Direction::NotDerivable(NonDerivation { path, reason }),
    }
}

/// Derive that every value admitted by `from_record` is admitted by
/// `to_record`, walking both sorted field tables in one merge join.
fn record_contains(
    from_schema: &RecordSchema,
    from_record: &CompiledRecord,
    to_schema: &RecordSchema,
    to_record: &CompiledRecord,
    path: &mut Vec<String>,
    labels: &DirectionLabels,
) -> Result<(), NonDerivationReason> {
    let from_fields = from_schema.fields_for(from_record);
    let to_fields = to_schema.fields_for(to_record);
    let mut from_pos = 0usize;
    let mut to_pos = 0usize;

    while from_pos < from_fields.len() || to_pos < to_fields.len() {
        match (from_fields.get(from_pos), to_fields.get(to_pos)) {
            (Some(from), Some(to)) => match cmp_field_key(&from.key, &to.key) {
                Ordering::Less => return fail_field(path, &from.key, labels.source_only_key),
                Ordering::Greater => {
                    if to.required {
                        return fail_field(path, &to.key, labels.target_required_key);
                    }
                    to_pos += 1;
                }
                Ordering::Equal => {
                    path.push(from.key.to_string());
                    if !from.required && to.required {
                        return Err(labels.presence_tightened);
                    }
                    field_contains(from_schema, from, to_schema, to, path, labels)?;
                    let _ = path.pop();
                    from_pos += 1;
                    to_pos += 1;
                }
            },
            (Some(from), None) => {
                return fail_field(path, &from.key, labels.source_only_key);
            }
            (None, Some(to)) => {
                if to.required {
                    return fail_field(path, &to.key, labels.target_required_key);
                }
                to_pos += 1;
            }
            (None, None) => break,
        }
    }

    coupling_subset(
        &keyed_couplings(to_schema, to_record),
        &keyed_couplings(from_schema, from_record),
    )
}

fn field_contains(
    from_schema: &RecordSchema,
    from: &CompiledField,
    to_schema: &RecordSchema,
    to: &CompiledField,
    path: &mut Vec<String>,
    labels: &DirectionLabels,
) -> Result<(), NonDerivationReason> {
    type_contains(
        from_schema,
        from.type_idx,
        to_schema,
        to.type_idx,
        path,
        labels,
    )?;
    constraints_contain(
        from_schema,
        from.constraints.clone(),
        to_schema,
        to.constraints.clone(),
    )
}

fn type_contains(
    from_schema: &RecordSchema,
    from_idx: usize,
    to_schema: &RecordSchema,
    to_idx: usize,
    path: &mut Vec<String>,
    labels: &DirectionLabels,
) -> Result<(), NonDerivationReason> {
    let from = from_schema.type_node(from_idx).clone();
    let to = to_schema.type_node(to_idx).clone();
    match (from, to) {
        (_, TypeNode::Any)
        | (TypeNode::Int, TypeNode::Int)
        | (TypeNode::Bool, TypeNode::Bool)
        | (TypeNode::Float64, TypeNode::Float64)
        | (TypeNode::Bytes, TypeNode::Bytes)
        | (TypeNode::Text, TypeNode::Text) => Ok(()),
        (TypeNode::Any, _) => Err(NonDerivationReason::AnyNarrowed),
        (TypeNode::Array(a), TypeNode::Array(b)) => {
            path.push("[*]".to_string());
            let result = type_contains(from_schema, a, to_schema, b, path, labels);
            let _ = path.pop();
            result
        }
        (TypeNode::Set(a), TypeNode::Set(b)) => {
            path.push("[set]".to_string());
            let result = type_contains(from_schema, a, to_schema, b, path, labels);
            let _ = path.pop();
            result
        }
        (TypeNode::Map(a), TypeNode::Map(b)) => {
            path.push("{}".to_string());
            let result = type_contains(from_schema, a, to_schema, b, path, labels);
            let _ = path.pop();
            result
        }
        (TypeNode::Union(a), TypeNode::Union(b)) => union_contains(
            from_schema.union_alts_for(a),
            to_schema.union_alts_for(b),
            from_schema,
            to_schema,
            path,
            labels,
        ),
        (TypeNode::Record(a), TypeNode::Record(b)) => record_contains(
            from_schema,
            from_schema.record(a),
            to_schema,
            to_schema.record(b),
            path,
            labels,
        ),
        _ => Err(NonDerivationReason::TypeChanged),
    }
}

fn union_contains(
    from: &[crate::compile::CompiledUnionAlt],
    to: &[crate::compile::CompiledUnionAlt],
    from_schema: &RecordSchema,
    to_schema: &RecordSchema,
    path: &mut Vec<String>,
    labels: &DirectionLabels,
) -> Result<(), NonDerivationReason> {
    for alt in from {
        let to_alt = to
            .binary_search_by_key(&alt.code, |candidate| candidate.code)
            .ok()
            .and_then(|idx| to.get(idx))
            .ok_or(NonDerivationReason::UnionCodeRemoved)?;
        match (alt.payload, to_alt.payload) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                path.push(format_union_code(alt.code));
                type_contains(from_schema, a, to_schema, b, path, labels)
                    .map_err(|_| NonDerivationReason::UnionPayloadChanged)?;
                let _ = path.pop();
            }
            _ => return Err(NonDerivationReason::UnionPayloadChanged),
        }
    }
    Ok(())
}

fn constraints_contain(
    from_schema: &RecordSchema,
    from_range: Range<usize>,
    to_schema: &RecordSchema,
    to_range: Range<usize>,
) -> Result<(), NonDerivationReason> {
    ranges_contain(
        from_schema.constraints_for(from_range.clone()),
        to_schema.constraints_for(to_range.clone()),
    )?;
    counts_contain(
        from_schema.constraints_for(from_range.clone()),
        to_schema.constraints_for(to_range.clone()),
    )?;
    enums_contain(from_schema, from_range, to_schema, to_range)
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
) -> Result<(), NonDerivationReason> {
    let from_enum = effective_enum(from_schema, from_range);
    let to_enum = effective_enum(to_schema, to_range);
    match (from_enum, to_enum) {
        (_, None) => Ok(()),
        (None, Some(_)) => Err(NonDerivationReason::EnumAdded),
        (Some(from), Some(to)) => {
            for member in from {
                if to
                    .binary_search_by(|candidate| candidate.as_slice().cmp(member.as_slice()))
                    .is_err()
                {
                    return Err(NonDerivationReason::EnumNarrowed);
                }
            }
            Ok(())
        }
    }
}

fn int_interval(constraints: &[CompiledConstraint]) -> (Option<&Int>, Option<&Int>) {
    let mut min = None;
    let mut max: Option<&Int> = None;
    for constraint in constraints {
        if let CompiledConstraint::Range { min: lo, max: hi } = constraint {
            if let Some(candidate) = lo {
                if min.map_or(true, |current| candidate > current) {
                    min = Some(candidate);
                }
            }
            if let Some(candidate) = hi {
                if max.map_or(true, |current| candidate < current) {
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

fn effective_enum(schema: &RecordSchema, range: Range<usize>) -> Option<Vec<Vec<u8>>> {
    let mut tables =
        schema
            .constraints_for(range)
            .iter()
            .filter_map(|constraint| match constraint {
                CompiledConstraint::Enum { members } => Some(members.clone()),
                _ => None,
            });
    let first = tables.next()?;
    let mut current: Vec<Vec<u8>> = schema.enum_members[first]
        .iter()
        .map(|member| member.to_vec())
        .collect();
    for table in tables {
        current.retain(|member| {
            schema.enum_members[table.clone()]
                .binary_search_by(|candidate| candidate.as_ref().cmp(member.as_slice()))
                .is_ok()
        });
    }
    Some(current)
}

/// A coupling expressed over field keys, independent of per-record bit
/// assignment.
///
/// Compiled couplings hold presence-bit masks whose bit positions depend on
/// the record's own sorted field table, so the same coupling over the same
/// keys compiles to different masks when an unrelated field is added or
/// removed. Containment therefore compares couplings by key names, never by
/// masks.
#[derive(Clone, Debug, PartialEq, Eq)]
enum KeyedCoupling<'a> {
    Requires { if_key: &'a str, then_key: &'a str },
    ExactlyOne(Vec<&'a str>),
    Together(Vec<&'a str>),
}

fn keyed_couplings<'a>(
    schema: &'a RecordSchema,
    record: &CompiledRecord,
) -> Vec<KeyedCoupling<'a>> {
    let fields = schema.fields_for(record);
    let keys_for = |mask: u64| -> Vec<&'a str> {
        fields
            .iter()
            .filter(|field| field.bit & mask != 0)
            .map(|field| field.key.as_ref())
            .collect()
    };
    let single_key = |mask: u64| -> &'a str {
        fields
            .iter()
            .find(|field| field.bit & mask != 0)
            .map_or("", |field| field.key.as_ref())
    };
    schema
        .couplings_for(record)
        .iter()
        .map(|coupling| match coupling {
            CompiledCoupling::Requires { if_mask, then_mask } => KeyedCoupling::Requires {
                if_key: single_key(*if_mask),
                then_key: single_key(*then_mask),
            },
            CompiledCoupling::ExactlyOne { mask } => KeyedCoupling::ExactlyOne(keys_for(*mask)),
            CompiledCoupling::Together { mask } => KeyedCoupling::Together(keys_for(*mask)),
        })
        .collect()
}

fn coupling_subset(
    required_subset: &[KeyedCoupling<'_>],
    available_superset: &[KeyedCoupling<'_>],
) -> Result<(), NonDerivationReason> {
    for coupling in required_subset {
        if !available_superset
            .iter()
            .any(|candidate| candidate == coupling)
        {
            return Err(NonDerivationReason::CouplingAdded);
        }
    }
    Ok(())
}

fn fail_field(
    path: &mut Vec<String>,
    key: &str,
    reason: NonDerivationReason,
) -> Result<(), NonDerivationReason> {
    path.push(key.to_string());
    Err(reason)
}

fn format_union_code(code: u64) -> String {
    use alloc::format;

    format!("union:{code}")
}
