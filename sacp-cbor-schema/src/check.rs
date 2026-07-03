//! Fused schema validation.

use alloc::{borrow::ToOwned, format, string::String, vec::Vec};
use core::cmp::Ordering;
use core::ops::Range;

use sacp_cbor::query::IntegerRef;
use sacp_cbor::{
    CanonicalCborRef, CborDecode, CborError, DecodeLimits, Decoder, ErrorCode, ScalarKind,
};

use crate::compile::{
    cmp_field_key, CompiledConstraint, CompiledCoupling, CompiledField, RecordIdx, RecordSchema,
    TypeNode,
};
use crate::error::{ConstraintFault, Fault, RecordError, ShapeFault};
use crate::int::cmp_integer_ref_to_int;
use crate::ir::CountUnit;
use crate::{ValidationOptions, MAX_NESTING_DEPTH};

const MAX_PATH_SEGMENTS: usize = (MAX_NESTING_DEPTH * 3) + 1;

impl RecordSchema {
    /// Validate untrusted bytes as canonical SACP-CBOR/1 and check this schema in one traversal.
    ///
    /// On success, returns the canonical witness for `bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError`] when the bytes fail canonical grammar validation, violate decode
    /// limits or validation options, or do not match the compiled schema.
    pub fn validate<'de>(
        &self,
        bytes: &'de [u8],
        limits: DecodeLimits,
        options: ValidationOptions,
    ) -> Result<CanonicalCborRef<'de>, RecordError> {
        let mut decoder = Decoder::<true>::new_checked_with(bytes, limits, options)?;
        let mut ctx = CheckCtx::new(self, bytes);
        ctx.check_record(&mut decoder, self.root_record)?;
        decoder.finish().map_err(|err| ctx.grammar(err))
    }

    /// Check an already-validated canonical item against this schema.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError`] when the canonical value does not match the compiled schema.
    pub fn check(&self, value: CanonicalCborRef<'_>) -> Result<(), RecordError> {
        let bytes = value.as_bytes();
        let limits = DecodeLimits::for_bytes(bytes.len());
        let mut decoder = Decoder::<false>::new_trusted(value, limits)?;
        let mut ctx = CheckCtx::new(self, bytes);
        ctx.check_record(&mut decoder, self.root_record)?;
        if decoder.position() == bytes.len() {
            Ok(())
        } else {
            Err(ctx.grammar(CborError::new(ErrorCode::TrailingBytes, decoder.position())))
        }
    }
}

struct CheckCtx<'schema, 'de> {
    schema: &'schema RecordSchema,
    input: &'de [u8],
    path: PathStack<'schema, 'de>,
}

/// The constraint-relevant facets of one decoded value.
///
/// Each facet is present only when the value's kind carries it: an integer
/// view for range checks, a counted length for count checks, and the
/// canonical encoded bytes for enum membership.
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
            count: Some((CountUnit::Octets, saturate_u64(len))),
            encoded: None,
        }
    }

    fn text(len: usize, encoded: &'a [u8]) -> Self {
        Self {
            integer: None,
            count: Some((CountUnit::Octets, saturate_u64(len))),
            encoded: Some(encoded),
        }
    }

    fn elements(len: usize) -> Self {
        Self {
            integer: None,
            count: Some((CountUnit::Elements, saturate_u64(len))),
            encoded: None,
        }
    }
}

fn saturate_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// The per-element check of a homogeneous container, resolved once per
/// container rather than re-dispatched per element.
#[derive(Clone, Copy)]
enum ElementCheck {
    /// Kind-checked scalar funnel.
    Scalar(ScalarKind),
    /// Structured element: full schema-directed dispatch.
    Full,
}

impl<'schema, 'de> CheckCtx<'schema, 'de> {
    const fn new(schema: &'schema RecordSchema, input: &'de [u8]) -> Self {
        Self {
            schema,
            input,
            path: PathStack::new(),
        }
    }

    fn check_record<const CHECKED: bool>(
        &mut self,
        decoder: &mut Decoder<'de, CHECKED>,
        record_idx: RecordIdx,
    ) -> Result<(), RecordError> {
        let map_off = decoder.position();
        let mut map = decoder.map().map_err(|err| self.value_fault(err))?;
        let record = self.schema.record(record_idx).clone();
        let fields = self.schema.fields_for(&record);
        let mut field_pos = 0usize;
        let mut presence = 0u64;

        while let Some(key) = map.next_key_ref().map_err(|err| self.grammar(err))? {
            loop {
                let Some(field) = fields.get(field_pos) else {
                    return Err(self.shape(key.offset, ShapeFault::UnknownKey));
                };
                match cmp_field_key(key.text, &field.key) {
                    Ordering::Less => return Err(self.shape(key.offset, ShapeFault::UnknownKey)),
                    Ordering::Greater => {
                        if field.required {
                            return Err(self.shape(map_off, ShapeFault::MissingField));
                        }
                        field_pos += 1;
                    }
                    Ordering::Equal => {
                        presence |= field.bit;
                        self.path.push_field(&field.key, key.offset)?;
                        let result = map.decode_value_with(|d| self.check_field_value(d, field));
                        self.path.pop();
                        result?;
                        field_pos += 1;
                        break;
                    }
                }
            }
        }

        // One presence test covers every missing required field: a required
        // field skipped mid-merge already failed in the Greater arm, and the
        // mask catches required fields past the last map key.
        if presence & record.required_mask != record.required_mask {
            return Err(self.shape(map_off, ShapeFault::MissingField));
        }
        self.check_couplings(presence, &record.couplings, map_off)
    }

    fn check_field_value<const CHECKED: bool>(
        &mut self,
        decoder: &mut Decoder<'de, CHECKED>,
        field: &CompiledField,
    ) -> Result<(), RecordError> {
        self.check_value(decoder, field.type_idx, field.constraints.clone())
    }

    fn check_value<const CHECKED: bool>(
        &mut self,
        decoder: &mut Decoder<'de, CHECKED>,
        type_idx: usize,
        constraints: Range<usize>,
    ) -> Result<(), RecordError> {
        let node = self.schema.type_node(type_idx).clone();
        match node {
            // Scalar kinds parse once: one header read, one payload
            // consumption (text UTF-8 validated exactly once). A value of
            // the wrong kind surfaces as the funnel's `Expected*` error and
            // is classified as a shape fault by `value_fault`.
            TypeNode::Int => {
                if constraints.is_empty() {
                    return self.skip_scalar(decoder, ScalarKind::Integer);
                }
                let off = decoder.position();
                let integer = IntegerRef::decode(decoder).map_err(|err| self.value_fault(err))?;
                let encoded = self.span(off..decoder.position())?;
                let target = ConstraintTarget::int(integer, encoded);
                self.apply_constraints(&target, constraints, off)
            }
            TypeNode::Bool => self.skip_scalar(decoder, ScalarKind::Bool),
            TypeNode::Float64 => self.skip_scalar(decoder, ScalarKind::Float),
            TypeNode::Bytes => {
                if constraints.is_empty() {
                    return self.skip_scalar(decoder, ScalarKind::Bytes);
                }
                let off = decoder.position();
                let bytes = <&[u8]>::decode(decoder).map_err(|err| self.value_fault(err))?;
                let target = ConstraintTarget::octets(bytes.len());
                self.apply_constraints(&target, constraints, off)
            }
            TypeNode::Text => {
                if constraints.is_empty() {
                    return self.skip_scalar(decoder, ScalarKind::Text);
                }
                let off = decoder.position();
                let text = <&str>::decode(decoder).map_err(|err| self.value_fault(err))?;
                let encoded = self.span(off..decoder.position())?;
                let target = ConstraintTarget::text(text.len(), encoded);
                self.apply_constraints(&target, constraints, off)
            }
            TypeNode::Array(inner) => self.check_array(decoder, inner, constraints, false),
            TypeNode::Set(inner) => self.check_array(decoder, inner, constraints, true),
            TypeNode::Map(inner) => self.check_map(decoder, inner, constraints),
            TypeNode::Union(alts) => self.check_union(decoder, alts),
            TypeNode::Record(record) => self.check_record(decoder, record),
            TypeNode::Any => decoder.skip_value().map_err(|err| self.grammar(err)),
        }
    }

    /// Consume one value that must be a scalar of the expected kind, without
    /// materializing any payload view.
    fn skip_scalar<const CHECKED: bool>(
        &self,
        decoder: &mut Decoder<'de, CHECKED>,
        kind: ScalarKind,
    ) -> Result<(), RecordError> {
        decoder
            .skip_scalar(kind)
            .map_err(|err| self.value_fault(err))
    }

    /// Resolve the per-element check once for a homogeneous container.
    ///
    /// Element types carry no constraints (constraints attach to fields), so
    /// a leaf scalar element reduces to a kind-checked scalar funnel,
    /// resolved outside the loop.
    fn element_check(&self, inner: usize) -> ElementCheck {
        match self.schema.type_node(inner) {
            TypeNode::Int => ElementCheck::Scalar(ScalarKind::Integer),
            TypeNode::Bool => ElementCheck::Scalar(ScalarKind::Bool),
            TypeNode::Float64 => ElementCheck::Scalar(ScalarKind::Float),
            TypeNode::Bytes => ElementCheck::Scalar(ScalarKind::Bytes),
            TypeNode::Text => ElementCheck::Scalar(ScalarKind::Text),
            _ => ElementCheck::Full,
        }
    }

    fn check_array<const CHECKED: bool>(
        &mut self,
        decoder: &mut Decoder<'de, CHECKED>,
        inner: usize,
        constraints: Range<usize>,
        set_order: bool,
    ) -> Result<(), RecordError> {
        let off = decoder.position();
        let mut array = decoder.array().map_err(|err| self.value_fault(err))?;
        let target = ConstraintTarget::elements(array.remaining());
        self.apply_constraints(&target, constraints, off)?;

        match self.element_check(inner) {
            // Scalar elements run through the core batch funnels: the
            // element fault (wrong kind, grammar, restriction) carries the
            // exact offset; the path names the container.
            ElementCheck::Scalar(kind) if !set_order => array
                .skip_scalars(kind)
                .map_err(|err| self.value_fault(err)),
            // Sorted scalar sets run through the core batch funnel with the
            // order comparison inlined; its order codes are this family's
            // set faults.
            ElementCheck::Scalar(kind) => array.skip_sorted_scalars(kind).map_err(|err| match err
                .code
            {
                ErrorCode::DuplicateElement => self.shape(err.offset, ShapeFault::SetDuplicate),
                ErrorCode::NonAscendingElement => self.shape(err.offset, ShapeFault::SetOrder),
                _ => self.value_fault(err),
            }),
            ElementCheck::Full => {
                let mut prev: Option<Range<usize>> = None;
                let mut index = 0usize;
                while array.remaining() > 0 {
                    let start = array.position();
                    self.path.push_index(index, start)?;
                    let result: Result<Option<usize>, RecordError> = array.decode_next_with(|d| {
                        self.check_value(d, inner, 0..0)?;
                        Ok(d.position())
                    });
                    self.path.pop();
                    let Some(end) = result? else {
                        return Err(
                            self.grammar(CborError::new(ErrorCode::MalformedCanonical, start))
                        );
                    };
                    if set_order {
                        let curr = self.span(start..end)?;
                        if let Some(prev_range) = prev.clone() {
                            let prev_bytes = self.span(prev_range)?;
                            match prev_bytes.cmp(curr) {
                                Ordering::Less => {}
                                Ordering::Equal => {
                                    return Err(self.shape(start, ShapeFault::SetDuplicate));
                                }
                                Ordering::Greater => {
                                    return Err(self.shape(start, ShapeFault::SetOrder));
                                }
                            }
                        }
                        prev = Some(start..end);
                    }
                    index = index.saturating_add(1);
                }
                Ok(())
            }
        }
    }

    fn check_map<const CHECKED: bool>(
        &mut self,
        decoder: &mut Decoder<'de, CHECKED>,
        inner: usize,
        constraints: Range<usize>,
    ) -> Result<(), RecordError> {
        let off = decoder.position();
        let mut map = decoder.map().map_err(|err| self.value_fault(err))?;
        let target = ConstraintTarget::elements(map.remaining());
        self.apply_constraints(&target, constraints, off)?;

        let check = self.element_check(inner);
        while let Some(key) = map.next_key_ref().map_err(|err| self.grammar(err))? {
            self.path.push_text(key.text, key.offset)?;
            let result = map.decode_value_with(|d| match check {
                ElementCheck::Scalar(kind) => self.skip_scalar(d, kind),
                ElementCheck::Full => self.check_value(d, inner, 0..0),
            });
            self.path.pop();
            result?;
        }
        Ok(())
    }

    fn check_union<const CHECKED: bool>(
        &mut self,
        decoder: &mut Decoder<'de, CHECKED>,
        alts: Range<usize>,
    ) -> Result<(), RecordError> {
        let off = decoder.position();
        let mut array = decoder.array().map_err(|err| self.value_fault(err))?;
        let arity = array.remaining();
        if arity != 1 && arity != 2 {
            return Err(self.shape(off, ShapeFault::UnionArity));
        }

        let code_off = array.position();
        let Some(integer) = array
            .next_value::<IntegerRef<'_>>()
            .map_err(|err| self.value_fault(err))?
        else {
            return Err(self.shape(off, ShapeFault::UnionArity));
        };
        let code = integer
            .as_u128()
            .and_then(|raw| u64::try_from(raw).ok())
            .ok_or_else(|| self.shape(code_off, ShapeFault::WrongKind))?;

        let alt_slice = self.schema.union_alts_for(alts);
        let alt = alt_slice
            .binary_search_by_key(&code, |alt| alt.code)
            .ok()
            .and_then(|idx| alt_slice.get(idx))
            .cloned()
            .ok_or_else(|| self.shape(off, ShapeFault::UnionCodeUnknown))?;

        match (alt.payload, arity) {
            (None, 1) => Ok(()),
            // A scalar payload consumes through the direct funnel, resolved
            // at compile time; a structured payload keeps the full dispatch
            // and its path segment.
            (Some(payload), 2) => {
                if let Some(kind) = alt.payload_scalar {
                    return array
                        .next_scalar_span(kind)
                        .map_err(|err| self.value_fault(err))?
                        .map(|_| ())
                        .ok_or_else(|| self.shape(off, ShapeFault::UnionArity));
                }
                self.path.push_index(1, array.position())?;
                let result = array.decode_next_with(|d| self.check_value(d, payload, 0..0));
                self.path.pop();
                match result? {
                    Some(()) => Ok(()),
                    None => Err(self.shape(off, ShapeFault::UnionArity)),
                }
            }
            _ => Err(self.shape(off, ShapeFault::UnionArity)),
        }
    }

    /// Classify a core error from a kind-expecting consume.
    ///
    /// The core funnels report a value of the wrong kind with that funnel's
    /// `Expected*` code at the value's header offset; those are the schema's
    /// wrong-kind shape faults. Every other code is a grammar fault.
    fn value_fault(&self, err: CborError) -> RecordError {
        match err.code {
            ErrorCode::ExpectedInteger
            | ErrorCode::ExpectedBytes
            | ErrorCode::ExpectedText
            | ErrorCode::ExpectedBool
            | ErrorCode::ExpectedFloat
            | ErrorCode::ExpectedNull
            | ErrorCode::ExpectedArray
            | ErrorCode::ExpectedMap => self.shape(err.offset, ShapeFault::WrongKind),
            _ => self.grammar(err),
        }
    }

    /// Apply every constraint in `constraints` to one decoded value in a
    /// single pass.
    ///
    /// Compilation pairs each constraint with an admitting field kind, so a
    /// constraint whose facet is absent from the target cannot occur; such
    /// arms are inert rather than faults.
    fn apply_constraints(
        &self,
        target: &ConstraintTarget<'_>,
        constraints: Range<usize>,
        offset: usize,
    ) -> Result<(), RecordError> {
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
                    if *unit != target_unit {
                        continue;
                    }
                    if min.is_some_and(|lo| count < lo) {
                        return Err(self.constraint(offset, ConstraintFault::CountBelow));
                    }
                    if max.is_some_and(|hi| count > hi) {
                        return Err(self.constraint(offset, ConstraintFault::CountAbove));
                    }
                }
                CompiledConstraint::Enum { members } => {
                    let Some(encoded) = target.encoded else {
                        continue;
                    };
                    let table = &self.schema.enum_members[members.clone()];
                    if table
                        .binary_search_by(|candidate| candidate.as_ref().cmp(encoded))
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
        presence: u64,
        couplings: &Range<usize>,
        offset: usize,
    ) -> Result<(), RecordError> {
        for coupling in &self.schema.couplings[couplings.clone()] {
            match coupling {
                CompiledCoupling::Requires { if_mask, then_mask } => {
                    if presence & if_mask != 0 && presence & then_mask == 0 {
                        return Err(self.constraint(offset, ConstraintFault::CouplingRequires));
                    }
                }
                CompiledCoupling::ExactlyOne { mask } => {
                    if (presence & mask).count_ones() != 1 {
                        return Err(self.constraint(offset, ConstraintFault::CouplingExactlyOne));
                    }
                }
                CompiledCoupling::Together { mask } => {
                    let bits = presence & mask;
                    if bits != 0 && bits != *mask {
                        return Err(self.constraint(offset, ConstraintFault::CouplingTogether));
                    }
                }
            }
        }
        Ok(())
    }

    fn span(&self, range: Range<usize>) -> Result<&'de [u8], RecordError> {
        self.input.get(range.clone()).ok_or_else(|| {
            self.grammar(CborError::new(
                ErrorCode::MalformedCanonical,
                range.start.min(self.input.len()),
            ))
        })
    }

    fn grammar(&self, err: CborError) -> RecordError {
        RecordError {
            offset: err.offset,
            path: self.path.to_vec(),
            fault: Fault::Grammar(err),
        }
    }

    fn shape(&self, offset: usize, fault: ShapeFault) -> RecordError {
        RecordError {
            offset,
            path: self.path.to_vec(),
            fault: Fault::Shape(fault),
        }
    }

    fn constraint(&self, offset: usize, fault: ConstraintFault) -> RecordError {
        RecordError {
            offset,
            path: self.path.to_vec(),
            fault: Fault::Constraint(fault),
        }
    }
}

#[derive(Clone, Copy)]
enum PathItem<'schema, 'de> {
    Field(&'schema str),
    Text(&'de str),
    Index(usize),
}

struct PathStack<'schema, 'de> {
    items: [PathItem<'schema, 'de>; MAX_PATH_SEGMENTS],
    len: usize,
}

impl<'schema, 'de> PathStack<'schema, 'de> {
    const fn new() -> Self {
        Self {
            items: [PathItem::Field(""); MAX_PATH_SEGMENTS],
            len: 0,
        }
    }

    fn push_field(&mut self, value: &'schema str, offset: usize) -> Result<(), RecordError> {
        self.push(PathItem::Field(value), offset)
    }

    fn push_text(&mut self, value: &'de str, offset: usize) -> Result<(), RecordError> {
        self.push(PathItem::Text(value), offset)
    }

    fn push_index(&mut self, value: usize, offset: usize) -> Result<(), RecordError> {
        self.push(PathItem::Index(value), offset)
    }

    fn push(&mut self, item: PathItem<'schema, 'de>, offset: usize) -> Result<(), RecordError> {
        let Some(slot) = self.items.get_mut(self.len) else {
            return Err(RecordError {
                offset,
                path: self.to_vec(),
                fault: Fault::Grammar(CborError::new(ErrorCode::DepthLimitExceeded, offset)),
            });
        };
        *slot = item;
        self.len += 1;
        Ok(())
    }

    fn pop(&mut self) {
        self.len = self.len.saturating_sub(1);
    }

    fn to_vec(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(self.len);
        for item in self.items.iter().take(self.len) {
            match item {
                PathItem::Field(value) | PathItem::Text(value) => out.push((*value).to_owned()),
                PathItem::Index(index) => out.push(format!("[{index}]")),
            }
        }
        out
    }
}
