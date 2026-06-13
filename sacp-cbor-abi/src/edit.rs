use alloc::vec::Vec;

use sacp_cbor::query::CborValueRef;
use sacp_cbor::{CanonicalCbor, CborError, Encoder, ErrorCode};

use crate::{AbiFieldSetRef, __private};

/// Value inserted by an ABI field-set edit.
#[derive(Debug, Clone)]
pub enum AbiPatchValue<'a> {
    /// Reuse a canonical value from the source document.
    Raw(CborValueRef<'a>),
    /// Insert owned canonical CBOR bytes.
    Encoded(CanonicalCbor),
}

/// ABI field-set set mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiSetMode {
    /// Insert or replace the field.
    Upsert,
    /// Replace an existing field only.
    ReplaceOnly,
    /// Insert a missing field only.
    InsertOnly,
}

/// ABI field-set delete mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiDeleteMode {
    /// Do nothing when the field is absent.
    IgnoreMissing,
    /// Reject absent fields.
    Require,
}

/// Incremental editor for an ABI field-set array.
#[derive(Debug)]
pub struct AbiFieldSetEditor<'a> {
    fields: AbiFieldSetRef<'a>,
    ops: Vec<AbiFieldSetOp<'a>>,
}

#[derive(Debug)]
enum AbiFieldSetOp<'a> {
    Set {
        id: u32,
        mode: AbiSetMode,
        value: AbiPatchValue<'a>,
    },
    Delete {
        id: u32,
        mode: AbiDeleteMode,
    },
}

fn invalid_abi_value(offset: usize) -> CborError {
    CborError::new(ErrorCode::InvalidAbiValue, offset)
}

fn patch_conflict(offset: usize) -> CborError {
    CborError::new(ErrorCode::PatchConflict, offset)
}

impl<'a> AbiFieldSetEditor<'a> {
    pub(crate) fn new(fields: AbiFieldSetRef<'a>) -> Self {
        Self {
            fields,
            ops: Vec::new(),
        }
    }

    /// Set a field value.
    pub fn set(
        &mut self,
        id: u32,
        mode: AbiSetMode,
        value: AbiPatchValue<'a>,
    ) -> Result<(), CborError> {
        if id == 0 {
            return Err(invalid_abi_value(self.fields.raw_value().offset()));
        }
        self.ops.push(AbiFieldSetOp::Set { id, mode, value });
        Ok(())
    }

    /// Delete a field.
    pub fn delete(&mut self, id: u32, mode: AbiDeleteMode) -> Result<(), CborError> {
        if id == 0 {
            return Err(invalid_abi_value(self.fields.raw_value().offset()));
        }
        self.ops.push(AbiFieldSetOp::Delete { id, mode });
        Ok(())
    }

    /// Apply edits and return updated canonical field-set bytes.
    pub fn apply(mut self) -> Result<CanonicalCbor, CborError> {
        self.ops.sort_by_key(AbiFieldSetOp::id);
        for pair in self.ops.windows(2) {
            if pair[0].id() == pair[1].id() {
                return Err(patch_conflict(self.fields.raw_value().offset()));
            }
        }

        let pair_count = self.output_pair_count()?;
        let mut enc = Encoder::new();
        enc.array(pair_count * 2, |array| {
            self.emit_edited_fields(array)?;
            Ok(())
        })?;
        enc.finish()
    }

    fn output_pair_count(&self) -> Result<usize, CborError> {
        let mut count = 0usize;
        let mut op_index = 0usize;
        for entry in self.fields.iter()? {
            let entry = entry?;
            while op_index < self.ops.len() && self.ops[op_index].id() < entry.id {
                count += self.count_missing_op(&self.ops[op_index])?;
                op_index += 1;
            }
            if op_index < self.ops.len() && self.ops[op_index].id() == entry.id {
                count += self.count_existing_op(&self.ops[op_index])?;
                op_index += 1;
            } else {
                count += 1;
            }
        }
        while op_index < self.ops.len() {
            count += self.count_missing_op(&self.ops[op_index])?;
            op_index += 1;
        }
        Ok(count)
    }

    fn count_existing_op(&self, op: &AbiFieldSetOp<'_>) -> Result<usize, CborError> {
        match op {
            AbiFieldSetOp::Set {
                mode: AbiSetMode::InsertOnly,
                ..
            } => Err(patch_conflict(self.fields.raw_value().offset())),
            AbiFieldSetOp::Set { .. } => Ok(1),
            AbiFieldSetOp::Delete { .. } => Ok(0),
        }
    }

    fn count_missing_op(&self, op: &AbiFieldSetOp<'_>) -> Result<usize, CborError> {
        match op {
            AbiFieldSetOp::Set {
                mode: AbiSetMode::ReplaceOnly,
                ..
            }
            | AbiFieldSetOp::Delete {
                mode: AbiDeleteMode::Require,
                ..
            } => Err(CborError::new(
                ErrorCode::MissingKey,
                self.fields.raw_value().offset(),
            )),
            AbiFieldSetOp::Set { .. } => Ok(1),
            AbiFieldSetOp::Delete { .. } => Ok(0),
        }
    }

    fn emit_edited_fields(
        &mut self,
        array: &mut sacp_cbor::encode::ArrayEncoder<'_>,
    ) -> Result<(), CborError> {
        let mut op_index = 0usize;
        for entry in self.fields.iter()? {
            let entry = entry?;
            while op_index < self.ops.len() && self.ops[op_index].id() < entry.id {
                Self::emit_missing_op(array, &self.ops[op_index])?;
                op_index += 1;
            }
            if op_index < self.ops.len() && self.ops[op_index].id() == entry.id {
                Self::emit_existing_op(array, &self.ops[op_index])?;
                op_index += 1;
            } else {
                __private::encode_field_id(array, entry.id)?;
                array.raw_value_ref(entry.value)?;
            }
        }
        while op_index < self.ops.len() {
            Self::emit_missing_op(array, &self.ops[op_index])?;
            op_index += 1;
        }
        Ok(())
    }

    fn emit_existing_op(
        array: &mut sacp_cbor::encode::ArrayEncoder<'_>,
        op: &AbiFieldSetOp<'a>,
    ) -> Result<(), CborError> {
        if let AbiFieldSetOp::Set { id, value, .. } = op {
            __private::encode_field_id(array, *id)?;
            Self::emit_patch_value(array, value)?;
        }
        Ok(())
    }

    fn emit_missing_op(
        array: &mut sacp_cbor::encode::ArrayEncoder<'_>,
        op: &AbiFieldSetOp<'a>,
    ) -> Result<(), CborError> {
        if let AbiFieldSetOp::Set { id, value, .. } = op {
            __private::encode_field_id(array, *id)?;
            Self::emit_patch_value(array, value)?;
        }
        Ok(())
    }

    fn emit_patch_value(
        array: &mut sacp_cbor::encode::ArrayEncoder<'_>,
        value: &AbiPatchValue<'a>,
    ) -> Result<(), CborError> {
        match value {
            AbiPatchValue::Raw(value) => array.raw_value_ref(*value),
            AbiPatchValue::Encoded(value) => array.raw_cbor(value.as_canonical_ref()),
        }
    }
}

impl AbiFieldSetOp<'_> {
    const fn id(&self) -> u32 {
        match self {
            Self::Set { id, .. } | Self::Delete { id, .. } => *id,
        }
    }
}
