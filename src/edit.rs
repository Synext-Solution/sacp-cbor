use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::alloc_util::try_reserve;
use crate::canonical::{CanonicalCbor, CanonicalCborRef, EncodedTextKey};
use crate::encode::{ArrayEncoder, MapEncoder};
use crate::profile::{checked_text_len, cmp_text_keys_canonical};
use crate::query::{CborValueRef, PathElem};
use crate::scalar::F64Bits;
use crate::{CborError, Encoder, ErrorCode};

const fn err(code: ErrorCode, offset: usize) -> CborError {
    CborError::new(code, offset)
}

#[cold]
#[inline(never)]
const fn invalid_query() -> CborError {
    err(ErrorCode::InvalidQuery, 0)
}

#[cold]
#[inline(never)]
const fn patch_conflict() -> CborError {
    err(ErrorCode::PatchConflict, 0)
}

#[cold]
#[inline(never)]
const fn missing_key(offset: usize) -> CborError {
    err(ErrorCode::MissingKey, offset)
}

#[cold]
#[inline(never)]
const fn index_out_of_bounds(offset: usize) -> CborError {
    err(ErrorCode::IndexOutOfBounds, offset)
}

#[cold]
#[inline(never)]
const fn length_overflow(offset: usize) -> CborError {
    err(ErrorCode::LengthOverflow, offset)
}

/// Mode for map set operations.
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetMode {
    /// Insert or replace the target key (default).
    Upsert,
    /// Insert only; error if the key already exists.
    InsertOnly,
    /// Replace only; error if the key is missing.
    ReplaceOnly,
}

/// Mode for delete operations.
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteMode {
    /// Require the key to exist (default).
    Require,
    /// Ignore missing keys.
    IfPresent,
}

/// Array splice position.
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrayPos {
    /// Splice at the given index.
    At(usize),
    /// Splice at the end of the array.
    End,
}

/// Edit behavior options.
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EditOptions {
    /// Allow creating missing map containers when descending into absent keys.
    pub create_missing_maps: bool,
}

/// Incremental editor for canonical CBOR bytes.
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Debug)]
pub struct Editor<'a> {
    root: CborValueRef<'a>,
    options: EditOptions,
    ops: Node<'a>,
}

impl<'a> Editor<'a> {
    pub(crate) const fn new(root: CborValueRef<'a>) -> Self {
        Self {
            root,
            options: EditOptions {
                create_missing_maps: false,
            },
            ops: Node::new(),
        }
    }

    /// Returns mutable access to editor options.
    pub fn options_mut(&mut self) -> &mut EditOptions {
        &mut self.options
    }

    /// Start building an array splice at `array_path`.
    ///
    /// `array_path` must resolve to an array at apply time. Indices are interpreted
    /// against the original array (before edits).
    ///
    /// # Errors
    ///
    /// Returns `CborError` on invalid paths or malformed splice parameters.
    pub fn splice<'p>(
        &'p mut self,
        array_path: &'p [PathElem<'p>],
        pos: ArrayPos,
        delete: usize,
    ) -> Result<ArraySpliceBuilder<'p, 'a, 'p>, CborError> {
        if matches!(pos, ArrayPos::End) && delete != 0 {
            return Err(invalid_query());
        }
        Ok(ArraySpliceBuilder {
            editor: self,
            path: array_path,
            pos,
            delete,
            inserts: Vec::new(),
            bounds: BoundsMode::Require,
        })
    }

    /// Append a value to the end of an array.
    ///
    /// # Errors
    ///
    /// Returns `CborError` for invalid paths or encoding failure.
    pub fn push<T: EditEncode<'a>>(
        &mut self,
        array_path: &[PathElem<'_>],
        value: T,
    ) -> Result<(), CborError> {
        self.splice(array_path, ArrayPos::End, 0)?
            .insert(value)?
            .finish()
    }

    /// Append an encoded value to the end of an array.
    ///
    /// # Errors
    ///
    /// Returns `CborError` for invalid paths or encoding failure.
    pub fn push_encoded<F>(&mut self, array_path: &[PathElem<'_>], f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut Encoder) -> Result<(), CborError>,
    {
        self.splice(array_path, ArrayPos::End, 0)?
            .insert_encoded(f)?
            .finish()
    }

    /// Set or replace the value at `path`.
    ///
    /// For map keys this performs an upsert; for arrays it replaces the element.
    ///
    /// # Errors
    ///
    /// Returns `CborError` on invalid paths, conflicts, or encoding failure.
    pub fn set<T: EditEncode<'a>>(
        &mut self,
        path: &[PathElem<'_>],
        value: T,
    ) -> Result<(), CborError> {
        self.set_with_mode(path, SetMode::Upsert, value)
    }

    /// Insert an entry at `path`.
    ///
    /// For map keys this inserts the key. For arrays this inserts before the index.
    ///
    /// # Errors
    ///
    /// Returns an error if the key already exists or if the path is invalid.
    pub fn insert<T: EditEncode<'a>>(
        &mut self,
        path: &[PathElem<'_>],
        value: T,
    ) -> Result<(), CborError> {
        self.set_with_mode(path, SetMode::InsertOnly, value)
    }

    /// Replace an entry at `path`.
    ///
    /// For map keys this replaces the key. For arrays this replaces the element.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is missing or if the path is invalid.
    pub fn replace<T: EditEncode<'a>>(
        &mut self,
        path: &[PathElem<'_>],
        value: T,
    ) -> Result<(), CborError> {
        self.set_with_mode(path, SetMode::ReplaceOnly, value)
    }

    /// Set a value from an existing canonical value reference without re-encoding.
    ///
    /// # Errors
    ///
    /// Returns `CborError` on invalid paths or conflicts.
    pub fn set_raw(
        &mut self,
        path: &[PathElem<'_>],
        value: CborValueRef<'a>,
    ) -> Result<(), CborError> {
        self.insert_terminal(
            path,
            Terminal::Set {
                mode: SetMode::Upsert,
                value: EditValue::raw(value),
            },
        )
    }

    /// Encode a value using a `Encoder` and set it at `path`.
    ///
    /// # Errors
    ///
    /// Returns `CborError` if encoding fails or if the encoded bytes are not a single CBOR item.
    pub fn set_encoded<F>(&mut self, path: &[PathElem<'_>], f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut Encoder) -> Result<(), CborError>,
    {
        let bytes = encode_with(f)?;
        self.insert_terminal(
            path,
            Terminal::Set {
                mode: SetMode::Upsert,
                value: EditValue::bytes_owned(bytes),
            },
        )
    }

    /// Delete an entry at `path`.
    ///
    /// For map keys this deletes the key. For arrays this deletes the element.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is missing or if the path is invalid.
    pub fn delete(&mut self, path: &[PathElem<'_>]) -> Result<(), CborError> {
        self.insert_terminal(
            path,
            Terminal::Delete {
                mode: DeleteMode::Require,
            },
        )
    }

    /// Delete an entry at `path` if present.
    ///
    /// For map keys this ignores missing keys. For arrays this ignores out-of-bounds indices.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths or conflicts.
    pub fn delete_if_present(&mut self, path: &[PathElem<'_>]) -> Result<(), CborError> {
        self.insert_terminal(
            path,
            Terminal::Delete {
                mode: DeleteMode::IfPresent,
            },
        )
    }

    /// Apply all recorded edits and return updated canonical CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error if any edit is invalid, conflicts, or fails during encoding.
    pub fn apply(self) -> Result<CanonicalCbor, CborError> {
        let mut enc = Encoder::with_capacity(self.root.len());
        emit_value(&mut enc, self.root, &self.ops, self.options)?;
        enc.into_canonical()
    }

    fn set_with_mode<T: EditEncode<'a>>(
        &mut self,
        path: &[PathElem<'_>],
        mode: SetMode,
        value: T,
    ) -> Result<(), CborError> {
        let new_value = value.into_value()?;
        self.insert_terminal(
            path,
            Terminal::Set {
                mode,
                value: new_value,
            },
        )
    }

    fn insert_terminal(
        &mut self,
        path: &[PathElem<'_>],
        terminal: Terminal<'a>,
    ) -> Result<(), CborError> {
        if path.is_empty() {
            return Err(invalid_query());
        }
        if let Some(PathElem::Index(index)) = path.last() {
            let parent = &path[..path.len() - 1];
            let splice = match terminal {
                Terminal::Delete { mode } => ArraySplice {
                    pos: ArrayPos::At(*index),
                    delete: 1,
                    inserts: Vec::new(),
                    bounds: match mode {
                        DeleteMode::Require => BoundsMode::Require,
                        DeleteMode::IfPresent => BoundsMode::IfPresent,
                    },
                },
                Terminal::Set { mode, value } => {
                    let (delete, bounds) = match mode {
                        SetMode::InsertOnly => (0, BoundsMode::Require),
                        SetMode::Upsert | SetMode::ReplaceOnly => (1, BoundsMode::Require),
                    };
                    let mut inserts = crate::alloc_util::try_vec_with_capacity(1, 0)?;
                    inserts.push(value);
                    ArraySplice {
                        pos: ArrayPos::At(*index),
                        delete,
                        inserts,
                        bounds,
                    }
                }
            };
            return self.ops.insert_splice(parent, splice);
        }
        self.ops.insert(path, terminal)
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Encodes a single canonical CBOR value into an `Encoder`.
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub trait EditEncode<'a>: sealed::Sealed {
    /// Encode this value into a canonical CBOR item ready for patching.
    ///
    /// # Errors
    ///
    /// Returns `CborError` if encoding fails or produces invalid canonical CBOR.
    fn into_value(self) -> Result<EditValue<'a>, CborError>;
}

impl sealed::Sealed for bool {}
impl sealed::Sealed for () {}
impl sealed::Sealed for &str {}
impl sealed::Sealed for String {}
impl sealed::Sealed for &[u8] {}
impl sealed::Sealed for Vec<u8> {}
impl sealed::Sealed for F64Bits {}
impl sealed::Sealed for f64 {}
impl sealed::Sealed for f32 {}
impl sealed::Sealed for i64 {}
impl sealed::Sealed for u64 {}
impl sealed::Sealed for i128 {}
impl sealed::Sealed for u128 {}
impl sealed::Sealed for CanonicalCborRef<'_> {}
impl sealed::Sealed for CanonicalCbor {}
impl sealed::Sealed for &CanonicalCbor {}

impl<'a> EditEncode<'a> for bool {
    fn into_value(self) -> Result<EditValue<'a>, CborError> {
        encode_to_vec(|enc| enc.bool(self))
    }
}

impl<'a> EditEncode<'a> for () {
    fn into_value(self) -> Result<EditValue<'a>, CborError> {
        encode_to_vec(Encoder::null)
    }
}

impl<'a> EditEncode<'a> for &str {
    fn into_value(self) -> Result<EditValue<'a>, CborError> {
        encode_to_vec(|enc| enc.text(self))
    }
}

impl<'a> EditEncode<'a> for String {
    fn into_value(self) -> Result<EditValue<'a>, CborError> {
        encode_to_vec(|enc| enc.text(self.as_str()))
    }
}

impl<'a> EditEncode<'a> for &[u8] {
    fn into_value(self) -> Result<EditValue<'a>, CborError> {
        encode_to_vec(|enc| enc.bytes(self))
    }
}

impl<'a> EditEncode<'a> for Vec<u8> {
    fn into_value(self) -> Result<EditValue<'a>, CborError> {
        encode_to_vec(|enc| enc.bytes(self.as_slice()))
    }
}

impl<'a> EditEncode<'a> for F64Bits {
    fn into_value(self) -> Result<EditValue<'a>, CborError> {
        encode_to_vec(|enc| enc.float(self))
    }
}

impl<'a> EditEncode<'a> for f64 {
    fn into_value(self) -> Result<EditValue<'a>, CborError> {
        encode_to_vec(|enc| enc.float(F64Bits::try_from_f64(self)?))
    }
}

impl<'a> EditEncode<'a> for f32 {
    fn into_value(self) -> Result<EditValue<'a>, CborError> {
        encode_to_vec(|enc| enc.float(F64Bits::try_from_f64(f64::from(self))?))
    }
}

impl<'a> EditEncode<'a> for i64 {
    fn into_value(self) -> Result<EditValue<'a>, CborError> {
        encode_to_vec(|enc| enc.int(self))
    }
}

impl<'a> EditEncode<'a> for u64 {
    fn into_value(self) -> Result<EditValue<'a>, CborError> {
        encode_to_vec(|enc| {
            if self > crate::MAX_SAFE_INTEGER {
                return Err(CborError::new(
                    ErrorCode::IntegerOutsideSafeRange,
                    enc.len(),
                ));
            }
            let v = i64::try_from(self)
                .map_err(|_| CborError::new(ErrorCode::LengthOverflow, enc.len()))?;
            enc.int(v)
        })
    }
}

impl<'a> EditEncode<'a> for i128 {
    fn into_value(self) -> Result<EditValue<'a>, CborError> {
        encode_to_vec(|enc| enc.int_i128(self))
    }
}

impl<'a> EditEncode<'a> for u128 {
    fn into_value(self) -> Result<EditValue<'a>, CborError> {
        encode_to_vec(|enc| enc.int_u128(self))
    }
}

impl<'a> EditEncode<'a> for CanonicalCborRef<'a> {
    fn into_value(self) -> Result<EditValue<'a>, CborError> {
        Ok(EditValue::bytes_ref(self))
    }
}

impl<'a> EditEncode<'a> for CanonicalCbor {
    fn into_value(self) -> Result<EditValue<'a>, CborError> {
        Ok(EditValue::bytes_owned(self.into_bytes()))
    }
}

impl<'a> EditEncode<'a> for &'a CanonicalCbor {
    fn into_value(self) -> Result<EditValue<'a>, CborError> {
        Ok(EditValue::bytes_ref(CanonicalCborRef::new(self.as_bytes())))
    }
}

/// Builder for an array splice edit.
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub struct ArraySpliceBuilder<'e, 'a, 'p> {
    editor: &'e mut Editor<'a>,
    path: &'p [PathElem<'p>],
    pos: ArrayPos,
    delete: usize,
    inserts: Vec<EditValue<'a>>,
    bounds: BoundsMode,
}

impl<'a> ArraySpliceBuilder<'_, 'a, '_> {
    /// Insert a value into the splice.
    ///
    /// # Errors
    ///
    /// Returns `CborError` if encoding fails.
    pub fn insert<T: EditEncode<'a>>(mut self, value: T) -> Result<Self, CborError> {
        let value = value.into_value()?;
        try_reserve(&mut self.inserts, 1, 0)?;
        self.inserts.push(value);
        Ok(self)
    }

    /// Insert a raw canonical value reference into the splice.
    ///
    /// # Errors
    ///
    /// Returns `CborError` on allocation failure.
    pub fn insert_raw(mut self, value: CborValueRef<'a>) -> Result<Self, CborError> {
        try_reserve(&mut self.inserts, 1, 0)?;
        self.inserts.push(EditValue::raw(value));
        Ok(self)
    }

    /// Insert a value encoded via `Encoder` into the splice.
    ///
    /// # Errors
    ///
    /// Returns `CborError` if encoding fails.
    pub fn insert_encoded<F>(mut self, f: F) -> Result<Self, CborError>
    where
        F: FnOnce(&mut Encoder) -> Result<(), CborError>,
    {
        let bytes = encode_with(f)?;
        try_reserve(&mut self.inserts, 1, 0)?;
        self.inserts.push(EditValue::bytes_owned(bytes));
        Ok(self)
    }

    /// Finalize and record the splice.
    ///
    /// # Errors
    ///
    /// Returns `CborError` for invalid paths or conflicts.
    pub fn finish(self) -> Result<(), CborError> {
        let splice = ArraySplice {
            pos: self.pos,
            delete: self.delete,
            inserts: self.inserts,
            bounds: self.bounds,
        };
        self.editor.ops.insert_splice(self.path, splice)
    }
}

#[derive(Debug, Clone)]
enum Children<'a> {
    None,
    Keys(Vec<(Box<str>, Node<'a>)>),
    Indices(Vec<(usize, Node<'a>)>),
}

impl Children<'_> {
    fn is_empty(&self) -> bool {
        match self {
            Self::None => true,
            Self::Keys(v) => v.is_empty(),
            Self::Indices(v) => v.is_empty(),
        }
    }
}

#[derive(Debug, Clone)]
enum Terminal<'a> {
    Delete { mode: DeleteMode },
    Set { mode: SetMode, value: EditValue<'a> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundsMode {
    Require,
    IfPresent,
}

#[derive(Debug, Clone)]
struct ArraySplice<'a> {
    pos: ArrayPos,
    delete: usize,
    inserts: Vec<EditValue<'a>>,
    bounds: BoundsMode,
}

fn cmp_array_pos(a: ArrayPos, b: ArrayPos) -> Ordering {
    match (a, b) {
        (ArrayPos::At(x), ArrayPos::At(y)) => x.cmp(&y),
        (ArrayPos::At(_), ArrayPos::End) => Ordering::Less,
        (ArrayPos::End, ArrayPos::At(_)) => Ordering::Greater,
        (ArrayPos::End, ArrayPos::End) => Ordering::Equal,
    }
}

fn splice_end(start: usize, delete: usize, offset: usize) -> Result<usize, CborError> {
    start
        .checked_add(delete)
        .ok_or_else(|| CborError::new(ErrorCode::LengthOverflow, offset))
}

#[derive(Debug, Clone)]
/// Encoded edit value used by the editor.
pub struct EditValue<'a>(EditValueInner<'a>);

#[derive(Debug, Clone)]
enum EditValueInner<'a> {
    /// Splice an existing canonical value reference.
    Raw(CborValueRef<'a>),
    /// Splice canonical bytes by reference.
    BytesRef(CanonicalCborRef<'a>),
    /// Splice owned canonical bytes.
    BytesOwned(Vec<u8>),
}

impl<'a> EditValue<'a> {
    pub(crate) const fn raw(value: CborValueRef<'a>) -> Self {
        Self(EditValueInner::Raw(value))
    }

    pub(crate) const fn bytes_ref(value: CanonicalCborRef<'a>) -> Self {
        Self(EditValueInner::BytesRef(value))
    }

    pub(crate) const fn bytes_owned(value: Vec<u8>) -> Self {
        Self(EditValueInner::BytesOwned(value))
    }
}

#[derive(Debug, Clone)]
struct Node<'a> {
    terminal: Option<Terminal<'a>>,
    children: Children<'a>,
    splices: Vec<ArraySplice<'a>>,
}

impl<'a> Node<'a> {
    const fn new() -> Self {
        Self {
            terminal: None,
            children: Children::None,
            splices: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.terminal.is_none() && self.children.is_empty() && self.splices.is_empty()
    }

    fn insert(&mut self, path: &[PathElem<'_>], terminal: Terminal<'a>) -> Result<(), CborError> {
        let mut cur = self;

        for (idx, pe) in path.iter().enumerate() {
            if cur.terminal.is_some() {
                return Err(patch_conflict());
            }

            let child = cur.child_mut(pe)?;

            if idx + 1 == path.len() {
                if child.terminal.is_some()
                    || !child.children.is_empty()
                    || !child.splices.is_empty()
                {
                    return Err(patch_conflict());
                }
                child.terminal = Some(terminal);
                return Ok(());
            }

            cur = child;
        }

        Err(invalid_query())
    }

    fn insert_splice(
        &mut self,
        path: &[PathElem<'_>],
        splice: ArraySplice<'a>,
    ) -> Result<(), CborError> {
        let mut cur = self;

        for pe in path {
            if cur.terminal.is_some() {
                return Err(patch_conflict());
            }
            cur = cur.child_mut(pe)?;
        }

        if cur.terminal.is_some() {
            return Err(patch_conflict());
        }
        cur.ensure_index_context()?;

        if matches!(splice.pos, ArrayPos::End) && splice.delete != 0 {
            return Err(invalid_query());
        }

        let Err(insert_idx) = cur
            .splices
            .binary_search_by(|s| cmp_array_pos(s.pos, splice.pos))
        else {
            return Err(patch_conflict());
        };

        if let ArrayPos::At(new_pos) = splice.pos {
            if let Some(prev) = insert_idx
                .checked_sub(1)
                .and_then(|idx| cur.splices.get(idx))
            {
                if let ArrayPos::At(prev_pos) = prev.pos {
                    let prev_end = splice_end(prev_pos, prev.delete, 0)?;
                    if new_pos < prev_end {
                        return Err(patch_conflict());
                    }
                }
            }
            if let Some(next) = cur.splices.get(insert_idx) {
                if let ArrayPos::At(next_pos) = next.pos {
                    let new_end = splice_end(new_pos, splice.delete, 0)?;
                    if next_pos < new_end {
                        return Err(patch_conflict());
                    }
                }
            }
        }

        try_reserve(&mut cur.splices, 1, 0)?;
        cur.splices.insert(insert_idx, splice);
        Ok(())
    }

    fn child_mut(&mut self, elem: &PathElem<'_>) -> Result<&mut Self, CborError> {
        match elem {
            PathElem::Key(k) => {
                checked_text_len(k.len()).map_err(|code| CborError::new(code, 0))?;
                if matches!(&self.children, Children::None) {
                    self.children = Children::Keys(Vec::new());
                } else if matches!(&self.children, Children::Indices(_)) {
                    return Err(patch_conflict());
                }

                let Children::Keys(children) = &mut self.children else {
                    return Err(patch_conflict());
                };

                match children
                    .binary_search_by(|(owned, _)| cmp_text_keys_canonical(owned.as_ref(), k))
                {
                    Ok(idx) => Ok(&mut children[idx].1),
                    Err(idx) => {
                        let owned = crate::alloc_util::try_box_str_from_str(k, 0)?;
                        try_reserve(children, 1, 0)?;
                        children.insert(idx, (owned, Node::new()));
                        Ok(&mut children[idx].1)
                    }
                }
            }
            PathElem::Index(i) => {
                if matches!(&self.children, Children::None) {
                    self.children = Children::Indices(Vec::new());
                } else if matches!(&self.children, Children::Keys(_)) {
                    return Err(patch_conflict());
                }

                let Children::Indices(children) = &mut self.children else {
                    return Err(patch_conflict());
                };

                match children.binary_search_by(|(owned, _)| owned.cmp(i)) {
                    Ok(idx) => Ok(&mut children[idx].1),
                    Err(idx) => {
                        try_reserve(children, 1, 0)?;
                        children.insert(idx, (*i, Node::new()));
                        Ok(&mut children[idx].1)
                    }
                }
            }
        }
    }

    fn ensure_index_context(&mut self) -> Result<(), CborError> {
        if matches!(&self.children, Children::None) {
            self.children = Children::Indices(Vec::new());
            return Ok(());
        }
        if matches!(&self.children, Children::Keys(_)) {
            return Err(patch_conflict());
        }
        Ok(())
    }

    fn key_children(&self, offset: usize) -> Result<&[(Box<str>, Self)], CborError> {
        match &self.children {
            Children::None => Ok(&[]),
            Children::Keys(children) => Ok(children.as_slice()),
            Children::Indices(_) => Err(err(ErrorCode::ExpectedMap, offset)),
        }
    }

    fn index_children(&self, offset: usize) -> Result<&[(usize, Self)], CborError> {
        match &self.children {
            Children::None => Ok(&[]),
            Children::Indices(children) => Ok(children.as_slice()),
            Children::Keys(_) => Err(err(ErrorCode::ExpectedArray, offset)),
        }
    }
}

struct ResolvedSplice<'a> {
    start: usize,
    delete: usize,
    inserts: &'a [EditValue<'a>],
}

fn encode_with<F>(f: F) -> Result<Vec<u8>, CborError>
where
    F: FnOnce(&mut Encoder) -> Result<(), CborError>,
{
    let mut enc = Encoder::new();
    f(&mut enc)?;
    Ok(enc.into_canonical()?.into_bytes())
}

fn encode_to_vec<'a, F>(f: F) -> Result<EditValue<'a>, CborError>
where
    F: FnOnce(&mut Encoder) -> Result<(), CborError>,
{
    let bytes = encode_with(f)?;
    Ok(EditValue::bytes_owned(bytes))
}

trait ValueEncoder {
    fn raw_value_ref(&mut self, v: CborValueRef<'_>) -> Result<(), CborError>;
    fn raw_cbor(&mut self, v: CanonicalCborRef<'_>) -> Result<(), CborError>;
    fn map<F>(&mut self, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut MapEncoder<'_>) -> Result<(), CborError>;
    fn array<F>(&mut self, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut ArrayEncoder<'_>) -> Result<(), CborError>;
}

impl ValueEncoder for Encoder {
    fn raw_value_ref(&mut self, v: CborValueRef<'_>) -> Result<(), CborError> {
        Self::raw_value_ref(self, v)
    }

    fn raw_cbor(&mut self, v: CanonicalCborRef<'_>) -> Result<(), CborError> {
        Self::raw_cbor(self, v)
    }

    fn map<F>(&mut self, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut MapEncoder<'_>) -> Result<(), CborError>,
    {
        Self::map(self, len, f)
    }

    fn array<F>(&mut self, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut ArrayEncoder<'_>) -> Result<(), CborError>,
    {
        Self::array(self, len, f)
    }
}

impl ValueEncoder for ArrayEncoder<'_> {
    fn raw_value_ref(&mut self, v: CborValueRef<'_>) -> Result<(), CborError> {
        ArrayEncoder::raw_value_ref(self, v)
    }

    fn raw_cbor(&mut self, v: CanonicalCborRef<'_>) -> Result<(), CborError> {
        ArrayEncoder::raw_cbor(self, v)
    }

    fn map<F>(&mut self, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut MapEncoder<'_>) -> Result<(), CborError>,
    {
        ArrayEncoder::map(self, len, f)
    }

    fn array<F>(&mut self, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut ArrayEncoder<'_>) -> Result<(), CborError>,
    {
        ArrayEncoder::array(self, len, f)
    }
}

fn write_new_value<E: ValueEncoder>(enc: &mut E, value: &EditValue<'_>) -> Result<(), CborError> {
    match &value.0 {
        EditValueInner::Raw(v) => enc.raw_value_ref(*v),
        EditValueInner::BytesRef(b) => enc.raw_cbor(*b),
        EditValueInner::BytesOwned(b) => enc.raw_cbor(CanonicalCborRef::new(b.as_slice())),
    }
}

fn emit_value<'a, E: ValueEncoder>(
    enc: &mut E,
    src: CborValueRef<'a>,
    node: &Node<'a>,
    options: EditOptions,
) -> Result<(), CborError> {
    if node.is_empty() {
        return enc.raw_value_ref(src);
    }

    if let Some(term) = node.terminal.as_ref() {
        return match term {
            Terminal::Set { value, .. } => write_new_value(enc, value),
            Terminal::Delete { .. } => Err(invalid_query()),
        };
    }

    match node.children {
        Children::None => enc.raw_value_ref(src),
        Children::Keys(_) => emit_patched_map(enc, src, node, options),
        Children::Indices(_) => emit_patched_array(enc, src, node, options),
    }
}

fn emit_patched_map<'a, E: ValueEncoder>(
    enc: &mut E,
    src: CborValueRef<'a>,
    node: &Node<'a>,
    options: EditOptions,
) -> Result<(), CborError> {
    let map = src.map()?;
    let map_off = src.offset();
    let mods = node.key_children(map_off)?;

    if mods.is_empty() {
        return enc.raw_value_ref(src);
    }

    let out_len = compute_map_len_and_validate(map, mods, options, map_off)?;
    enc.map(out_len, |menc| {
        emit_map_entries(menc, map, mods, options, map_off)
    })
}

fn emit_patched_array<'a, E: ValueEncoder>(
    enc: &mut E,
    src: CborValueRef<'a>,
    node: &Node<'a>,
    options: EditOptions,
) -> Result<(), CborError> {
    let array = src.array()?;
    let len = array.len();
    let array_off = src.offset();
    let mods = node.index_children(array_off)?;
    let splices = collect_splices(node, len, array_off)?;

    if mods.is_empty() && splices.is_empty() {
        return enc.raw_value_ref(src);
    }

    if let Some(max) = mods.last().map(|m| m.0) {
        if max >= len {
            return Err(index_out_of_bounds(array_off));
        }
    }

    ensure_splice_mod_conflicts(mods, &splices, array_off)?;
    let out_len = compute_array_out_len(len, &splices, array_off)?;

    enc.array(out_len, |aenc| {
        emit_array_items(aenc, array, mods, &splices, options, array_off, len)
    })
}

fn ensure_splice_mod_conflicts<'a>(
    mods: &[(usize, Node<'a>)],
    splices: &[ResolvedSplice<'a>],
    offset: usize,
) -> Result<(), CborError> {
    if mods.is_empty() || splices.is_empty() {
        return Ok(());
    }
    let mut mod_idx = 0usize;
    for splice in splices {
        if splice.delete == 0 {
            continue;
        }
        let end_idx = splice
            .start
            .checked_add(splice.delete)
            .ok_or_else(|| length_overflow(offset))?;
        while mod_idx < mods.len() && mods[mod_idx].0 < splice.start {
            mod_idx += 1;
        }
        if mod_idx < mods.len() && mods[mod_idx].0 < end_idx {
            return Err(patch_conflict());
        }
    }
    Ok(())
}

fn compute_array_out_len(
    len: usize,
    splices: &[ResolvedSplice<'_>],
    offset: usize,
) -> Result<usize, CborError> {
    let mut out_len = len;
    for splice in splices {
        out_len = out_len
            .checked_sub(splice.delete)
            .ok_or_else(|| length_overflow(offset))?;
        out_len = out_len
            .checked_add(splice.inserts.len())
            .ok_or_else(|| length_overflow(offset))?;
    }
    Ok(out_len)
}

fn emit_array_items<'a, E: ValueEncoder>(
    aenc: &mut E,
    array: crate::query::ArrayRef<'a>,
    mods: &[(usize, Node<'a>)],
    splices: &[ResolvedSplice<'a>],
    options: EditOptions,
    array_off: usize,
    len: usize,
) -> Result<(), CborError> {
    let mut splice_iter = splices.iter().peekable();
    let mut mods_iter = mods.iter().peekable();
    let mut iter = array.iter();
    let mut idx = 0usize;

    while idx < len {
        if let Some(splice) = splice_iter.peek() {
            if splice.start == idx {
                for value in splice.inserts {
                    write_new_value(aenc, value)?;
                }
                let delete = splice.delete;
                splice_iter.next();
                if delete > 0 {
                    for _ in 0..delete {
                        let item = iter
                            .next()
                            .ok_or_else(|| err(ErrorCode::MalformedCanonical, array_off))??;
                        let _ = item;
                    }
                    idx = idx
                        .checked_add(delete)
                        .ok_or_else(|| length_overflow(array_off))?;
                    continue;
                }
            }
        }

        let item = iter
            .next()
            .ok_or_else(|| err(ErrorCode::MalformedCanonical, array_off))??;
        match mods_iter.peek() {
            Some((m_idx, _)) if *m_idx == idx => {
                let m_entry = mods_iter.next().ok_or_else(invalid_query)?;
                let m_node = &m_entry.1;
                if let Some(term) = m_node.terminal.as_ref() {
                    match term {
                        Terminal::Delete { .. } => return Err(invalid_query()),
                        Terminal::Set { mode, value } => {
                            if *mode == SetMode::InsertOnly {
                                return Err(invalid_query());
                            }
                            write_new_value(aenc, value)?;
                        }
                    }
                } else {
                    emit_value(aenc, item, m_node, options)?;
                }
            }
            _ => aenc.raw_value_ref(item)?,
        }
        idx += 1;
    }

    for splice in splice_iter {
        if splice.start != len {
            return Err(index_out_of_bounds(array_off));
        }
        for value in splice.inserts {
            write_new_value(aenc, value)?;
        }
    }

    if mods_iter.peek().is_some() {
        return Err(index_out_of_bounds(array_off));
    }

    Ok(())
}

fn collect_splices<'a>(
    node: &'a Node<'a>,
    len: usize,
    offset: usize,
) -> Result<Vec<ResolvedSplice<'a>>, CborError> {
    let mut out = crate::alloc_util::try_vec_with_capacity(node.splices.len(), offset)?;
    let mut last_start: Option<usize> = None;
    for splice in &node.splices {
        if matches!(splice.pos, ArrayPos::End) && splice.delete != 0 {
            return Err(invalid_query());
        }
        let start = match splice.pos {
            ArrayPos::At(i) => i,
            ArrayPos::End => len,
        };

        if start >= len {
            if splice.bounds == BoundsMode::IfPresent {
                continue;
            }
            if start > len || splice.delete != 0 {
                return Err(index_out_of_bounds(offset));
            }
        }

        let remaining = len
            .checked_sub(start)
            .ok_or_else(|| index_out_of_bounds(offset))?;
        if splice.delete > remaining {
            return Err(index_out_of_bounds(offset));
        }

        if let Some(prev) = last_start {
            if start <= prev {
                return Err(patch_conflict());
            }
        }
        last_start = Some(start);

        out.push(ResolvedSplice {
            start,
            delete: splice.delete,
            inserts: splice.inserts.as_slice(),
        });
    }

    Ok(out)
}

fn compute_map_len_and_validate<'a>(
    map: crate::query::MapRef<'a>,
    mods: &[(Box<str>, Node<'a>)],
    options: EditOptions,
    map_off: usize,
) -> Result<usize, CborError> {
    let mut out_len = map.len();
    let mut mod_idx = 0usize;
    let mut iter = map.iter();
    let mut entry = next_map_entry(&mut iter)?;

    while entry.is_some() || mod_idx < mods.len() {
        let cur_mod = mods.get(mod_idx);
        match (entry, cur_mod) {
            (Some((key, _value)), Some((mod_key, mod_node))) => {
                match cmp_text_keys_canonical(key, mod_key.as_ref()) {
                    Ordering::Less => {
                        entry = next_map_entry(&mut iter)?;
                    }
                    Ordering::Equal => {
                        match mod_node.terminal.as_ref() {
                            Some(Terminal::Delete { .. }) => {
                                out_len = out_len
                                    .checked_sub(1)
                                    .ok_or_else(|| length_overflow(map_off))?;
                            }
                            Some(Terminal::Set {
                                mode: SetMode::InsertOnly,
                                ..
                            }) => {
                                return Err(err(ErrorCode::InvalidQuery, map_off));
                            }
                            _ => {}
                        }
                        mod_idx += 1;
                        entry = next_map_entry(&mut iter)?;
                    }
                    Ordering::Greater => {
                        out_len = handle_missing_map_mod(out_len, mod_node, options, map_off)?;
                        mod_idx += 1;
                    }
                }
            }
            (Some((_key, _value)), None) => {
                entry = next_map_entry(&mut iter)?;
            }
            (None, Some((_mod_key, mod_node))) => {
                out_len = handle_missing_map_mod(out_len, mod_node, options, map_off)?;
                mod_idx += 1;
            }
            (None, None) => break,
        }
    }

    Ok(out_len)
}

fn handle_missing_map_mod(
    out_len: usize,
    mod_node: &Node<'_>,
    options: EditOptions,
    map_off: usize,
) -> Result<usize, CborError> {
    match mod_node.terminal.as_ref() {
        Some(Terminal::Delete {
            mode: DeleteMode::IfPresent,
        }) => Ok(out_len),
        Some(
            Terminal::Delete {
                mode: DeleteMode::Require,
            }
            | Terminal::Set {
                mode: SetMode::ReplaceOnly,
                ..
            },
        ) => Err(missing_key(map_off)),
        Some(Terminal::Set { .. }) => out_len
            .checked_add(1)
            .ok_or_else(|| length_overflow(map_off)),
        None => {
            if options.create_missing_maps {
                match mod_node.children {
                    Children::Keys(_) => out_len
                        .checked_add(1)
                        .ok_or_else(|| length_overflow(map_off)),
                    _ => Err(err(ErrorCode::InvalidQuery, map_off)),
                }
            } else {
                Err(missing_key(map_off))
            }
        }
    }
}

fn emit_map_entries<'a>(
    menc: &mut MapEncoder<'_>,
    map: crate::query::MapRef<'a>,
    mods: &[(Box<str>, Node<'a>)],
    options: EditOptions,
    map_off: usize,
) -> Result<(), CborError> {
    let mut mod_idx = 0usize;
    let mut iter = map.iter_encoded();
    let mut entry = next_map_entry_encoded(&mut iter)?;

    while entry.is_some() || mod_idx < mods.len() {
        let cur_mod = mods.get(mod_idx);
        match (entry, cur_mod) {
            (Some((key, key_bytes, value)), Some((mod_key, mod_node))) => {
                match cmp_text_keys_canonical(key, mod_key.as_ref()) {
                    Ordering::Less => {
                        let value_ref = value;
                        menc.entry_raw_key(key_bytes, |venc| venc.raw_value_ref(value_ref))?;
                        entry = next_map_entry_encoded(&mut iter)?;
                    }
                    Ordering::Equal => {
                        match mod_node.terminal.as_ref() {
                            Some(Terminal::Delete { .. }) => {}
                            Some(Terminal::Set {
                                mode: SetMode::InsertOnly,
                                ..
                            }) => {
                                return Err(err(ErrorCode::InvalidQuery, map_off));
                            }
                            Some(Terminal::Set { value, .. }) => {
                                menc.entry_raw_key(key_bytes, |venc| write_new_value(venc, value))?;
                            }
                            None => {
                                let value_ref = value;
                                menc.entry_raw_key(key_bytes, |venc| {
                                    emit_value(venc, value_ref, mod_node, options)
                                })?;
                            }
                        }
                        mod_idx += 1;
                        entry = next_map_entry_encoded(&mut iter)?;
                    }
                    Ordering::Greater => {
                        emit_missing_map_entry(menc, mod_key.as_ref(), mod_node, options, map_off)?;
                        mod_idx += 1;
                    }
                }
            }
            (Some((_key, key_bytes, value)), None) => {
                let value_ref = value;
                menc.entry_raw_key(key_bytes, |venc| venc.raw_value_ref(value_ref))?;
                entry = next_map_entry_encoded(&mut iter)?;
            }
            (None, Some((mod_key, mod_node))) => {
                emit_missing_map_entry(menc, mod_key.as_ref(), mod_node, options, map_off)?;
                mod_idx += 1;
            }
            (None, None) => break,
        }
    }

    Ok(())
}

fn emit_missing_map_entry(
    menc: &mut MapEncoder<'_>,
    mod_key: &str,
    mod_node: &Node<'_>,
    options: EditOptions,
    map_off: usize,
) -> Result<(), CborError> {
    match mod_node.terminal.as_ref() {
        Some(Terminal::Delete {
            mode: DeleteMode::IfPresent,
        }) => Ok(()),
        Some(
            Terminal::Delete {
                mode: DeleteMode::Require,
            }
            | Terminal::Set {
                mode: SetMode::ReplaceOnly,
                ..
            },
        ) => Err(missing_key(map_off)),
        Some(Terminal::Set { value, .. }) => {
            menc.entry(mod_key, |venc| write_new_value(venc, value))
        }
        None => {
            if options.create_missing_maps {
                match mod_node.children {
                    Children::Keys(_) => {
                        menc.entry(mod_key, |venc| emit_created_value(venc, mod_node, options))
                    }
                    _ => Err(err(ErrorCode::InvalidQuery, map_off)),
                }
            } else {
                Err(missing_key(map_off))
            }
        }
    }
}

fn emit_created_value<E: ValueEncoder>(
    enc: &mut E,
    node: &Node<'_>,
    options: EditOptions,
) -> Result<(), CborError> {
    if let Some(term) = node.terminal.as_ref() {
        return match term {
            Terminal::Set { value, .. } => write_new_value(enc, value),
            Terminal::Delete { .. } => Err(invalid_query()),
        };
    }

    match node.children {
        Children::Keys(_) => emit_created_map(enc, node, options),
        _ => Err(invalid_query()),
    }
}

fn emit_created_map<E: ValueEncoder>(
    enc: &mut E,
    node: &Node<'_>,
    options: EditOptions,
) -> Result<(), CborError> {
    let mods = node.key_children(0)?;

    let mut out_len = 0usize;
    for (_key, child) in mods {
        match child.terminal.as_ref() {
            Some(Terminal::Delete { .. }) => return Err(invalid_query()),
            Some(Terminal::Set {
                mode: SetMode::ReplaceOnly,
                ..
            }) => return Err(missing_key(0)),
            Some(Terminal::Set { .. }) => {
                out_len = out_len.checked_add(1).ok_or_else(|| length_overflow(0))?;
            }
            None => match child.children {
                Children::Keys(_) if options.create_missing_maps => {
                    out_len = out_len.checked_add(1).ok_or_else(|| length_overflow(0))?;
                }
                _ => return Err(missing_key(0)),
            },
        }
    }

    enc.map(out_len, |menc| {
        for (key, child) in mods {
            match child.terminal.as_ref() {
                Some(Terminal::Delete { .. }) => return Err(invalid_query()),
                Some(Terminal::Set { value, .. }) => {
                    menc.entry(key.as_ref(), |venc| write_new_value(venc, value))?;
                }
                None => {
                    menc.entry(key.as_ref(), |venc| {
                        emit_created_value(venc, child, options)
                    })?;
                }
            }
        }
        Ok(())
    })
}

fn next_map_entry<'a, I>(iter: &mut I) -> Result<Option<(&'a str, CborValueRef<'a>)>, CborError>
where
    I: Iterator<Item = Result<(&'a str, CborValueRef<'a>), CborError>>,
{
    match iter.next() {
        None => Ok(None),
        Some(Ok(v)) => Ok(Some(v)),
        Some(Err(e)) => Err(e),
    }
}

type EncodedMapEntry<'a> = (&'a str, EncodedTextKey<'a>, CborValueRef<'a>);

fn next_map_entry_encoded<'a, I>(iter: &mut I) -> Result<Option<EncodedMapEntry<'a>>, CborError>
where
    I: Iterator<Item = Result<EncodedMapEntry<'a>, CborError>>,
{
    match iter.next() {
        None => Ok(None),
        Some(Ok(v)) => Ok(Some(v)),
        Some(Err(e)) => Err(e),
    }
}

/// Adds editing methods to `CanonicalCborRef`.
impl<'a> CanonicalCborRef<'a> {
    /// Create a `Editor` for this message.
    #[must_use]
    pub const fn editor(self) -> Editor<'a> {
        Editor::new(self.root())
    }

    /// Apply a sequence of edits atomically.
    ///
    /// # Errors
    ///
    /// Returns `CborError` if any edit fails or the patch is invalid.
    pub fn edit<F>(self, f: F) -> Result<CanonicalCbor, CborError>
    where
        F: FnOnce(&mut Editor<'a>) -> Result<(), CborError>,
    {
        let mut editor = self.editor();
        f(&mut editor)?;
        editor.apply()
    }
}

/// Adds editing methods to `CanonicalCbor`.
impl CanonicalCbor {
    /// Create a `Editor` for this message.
    #[must_use]
    pub fn editor(&self) -> Editor<'_> {
        Editor::new(self.root())
    }

    /// Apply a sequence of edits atomically.
    ///
    /// # Errors
    ///
    /// Returns `CborError` if any edit fails or the patch is invalid.
    pub fn edit<'a, F>(&'a self, f: F) -> Result<Self, CborError>
    where
        F: FnOnce(&mut Editor<'a>) -> Result<(), CborError>,
    {
        let mut editor = self.editor();
        f(&mut editor)?;
        editor.apply()
    }
}
