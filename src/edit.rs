//! Canonical CBOR editing and patch application.
//!
//! The editor records deterministic operations against validated canonical input and emits a new
//! canonical value through the central [`Encoder`] finalizer.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::alloc_util::try_reserve;
use crate::canonical::{CanonicalCbor, CanonicalCborRef, EncodedTextKey};
use crate::encode::{EmitValue, Encoder, MapEncoder};
use crate::profile::{checked_text_len, cmp_text_keys_canonical};
use crate::query::{CborValueRef, PathElem};
use crate::{CborError, ErrorCode};

#[allow(clippy::needless_pass_by_value)]
const fn encoder_error(error: crate::EncodeError<CborError>) -> CborError {
    match error {
        crate::EncodeError::Cbor(error) | crate::EncodeError::Sink(error) => error,
        crate::EncodeError::Poisoned => err(ErrorCode::EncoderPoisoned, 0),
    }
}

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

/// Mode for set operations.
#[cfg_attr(docsrs, doc(cfg(feature = "edit")))]
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
#[cfg_attr(docsrs, doc(cfg(feature = "edit")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteMode {
    /// Require the key to exist (default).
    Require,
    /// Ignore missing keys.
    IfPresent,
}

/// Array splice position.
#[cfg_attr(docsrs, doc(cfg(feature = "edit")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrayPos {
    /// Splice at the given index.
    At(usize),
    /// Splice at the end of the array.
    End,
}

/// Value inserted by an edit operation.
#[cfg_attr(docsrs, doc(cfg(feature = "edit")))]
#[derive(Debug, Clone)]
pub enum PatchValue<'a> {
    /// Reuse a canonical value from the source document.
    Raw(CborValueRef<'a>),
    /// Insert owned canonical CBOR bytes.
    Encoded(CanonicalCbor),
}

/// Array splice operation.
#[cfg_attr(docsrs, doc(cfg(feature = "edit")))]
#[derive(Debug, Clone)]
pub struct Splice<'a> {
    /// Splice position.
    pub pos: ArrayPos,
    /// Number of original array elements to delete at the splice position.
    pub delete: usize,
    /// Values to insert at the splice position.
    pub insert: Vec<PatchValue<'a>>,
}

/// Incremental editor for canonical CBOR bytes.
#[cfg_attr(docsrs, doc(cfg(feature = "edit")))]
#[derive(Debug)]
pub struct Editor<'a> {
    root: CborValueRef<'a>,
    ops: Node<'a>,
}

impl<'a> Editor<'a> {
    pub(crate) const fn new(root: CborValueRef<'a>) -> Self {
        Self {
            root,
            ops: Node::new(),
        }
    }

    /// Set a value at `path`.
    ///
    /// Map-key paths honor all [`SetMode`] variants. Array-index paths replace an existing item;
    /// array insertion is expressed with [`Editor::splice`].
    ///
    /// # Errors
    ///
    /// Returns `CborError` for invalid paths, conflicts, or mode violations.
    pub fn set(
        &mut self,
        path: &[PathElem<'_>],
        mode: SetMode,
        value: PatchValue<'a>,
    ) -> Result<(), CborError> {
        if path.is_empty() {
            return Err(invalid_query());
        }
        if matches!(path.last(), Some(PathElem::Index(_))) && mode == SetMode::InsertOnly {
            return Err(invalid_query());
        }
        self.ops.insert(
            path,
            Terminal::Set {
                mode,
                value: ValueCow::from_patch(value),
            },
        )
    }

    /// Delete a value at `path`.
    ///
    /// # Errors
    ///
    /// Returns `CborError` for invalid paths, conflicts, or missing required targets.
    pub fn delete(&mut self, path: &[PathElem<'_>], mode: DeleteMode) -> Result<(), CborError> {
        if path.is_empty() {
            return Err(invalid_query());
        }
        self.ops.insert(path, Terminal::Delete { mode })
    }

    /// Splice an array at `array_path`.
    ///
    /// Indices are interpreted against the original array before edits.
    ///
    /// # Errors
    ///
    /// Returns `CborError` for invalid paths, conflicts, or malformed splice parameters.
    pub fn splice(
        &mut self,
        array_path: &[PathElem<'_>],
        splice: Splice<'a>,
    ) -> Result<(), CborError> {
        if matches!(splice.pos, ArrayPos::End) && splice.delete != 0 {
            return Err(invalid_query());
        }
        let mut inserts = crate::alloc_util::try_vec_with_capacity(splice.insert.len(), 0)?;
        for value in splice.insert {
            inserts.push(ValueCow::from_patch(value));
        }
        self.ops.insert_splice(
            array_path,
            ArraySplice {
                pos: splice.pos,
                delete: splice.delete,
                inserts,
            },
        )
    }

    /// Apply all recorded edits and return updated canonical CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error if any edit is invalid, conflicts, or fails during encoding.
    pub fn apply(self) -> Result<CanonicalCbor, CborError> {
        let mut enc = Encoder::try_with_capacity(self.root.byte_len())?;
        emit_value(&mut enc, self.root, &self.ops)?;
        Ok(CanonicalCbor::new_unchecked(
            enc.finish().map_err(encoder_error)?,
        ))
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
    Set { mode: SetMode, value: ValueCow<'a> },
}

#[derive(Debug, Clone)]
struct ArraySplice<'a> {
    pos: ArrayPos,
    delete: usize,
    inserts: Vec<ValueCow<'a>>,
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
struct ValueCow<'a>(ValueCowInner<'a>);

#[derive(Debug, Clone)]
enum ValueCowInner<'a> {
    /// Splice an existing canonical value reference.
    Raw(CborValueRef<'a>),
    /// Splice owned canonical bytes.
    BytesOwned(Vec<u8>),
}

impl<'a> ValueCow<'a> {
    fn from_patch(value: PatchValue<'a>) -> Self {
        match value {
            PatchValue::Raw(value) => Self(ValueCowInner::Raw(value)),
            PatchValue::Encoded(value) => Self(ValueCowInner::BytesOwned(value.into_bytes())),
        }
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
    inserts: &'a [ValueCow<'a>],
}

fn write_new_value<E: EmitValue>(enc: &mut E, value: &ValueCow<'_>) -> Result<(), CborError> {
    match &value.0 {
        ValueCowInner::Raw(v) => enc.raw_value_ref(*v),
        ValueCowInner::BytesOwned(b) => enc.raw_cbor(CanonicalCborRef::new(b.as_slice())),
    }
}

fn emit_value<'a, E: EmitValue>(
    enc: &mut E,
    src: CborValueRef<'a>,
    node: &Node<'a>,
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
        Children::Keys(_) => emit_patched_map(enc, src, node),
        Children::Indices(_) => emit_patched_array(enc, src, node),
    }
}

fn emit_patched_map<'a, E: EmitValue>(
    enc: &mut E,
    src: CborValueRef<'a>,
    node: &Node<'a>,
) -> Result<(), CborError> {
    let map = src.map()?;
    let map_off = src.offset();
    let mods = node.key_children(map_off)?;

    if mods.is_empty() {
        return enc.raw_value_ref(src);
    }

    let out_len = compute_map_len_and_validate(map, mods, map_off)?;
    enc.map(out_len, |menc| emit_map_entries(menc, map, mods, map_off))
}

fn emit_patched_array<'a, E: EmitValue>(
    enc: &mut E,
    src: CborValueRef<'a>,
    node: &Node<'a>,
) -> Result<(), CborError> {
    let array = src.array()?;
    let len = array.len();
    let array_off = src.offset();
    let mods = node.index_children(array_off)?;
    let splices = collect_splices(node, len, array_off)?;

    if mods.is_empty() && splices.is_empty() {
        return enc.raw_value_ref(src);
    }

    ensure_splice_mod_conflicts(mods, &splices, array_off)?;
    let out_len = compute_array_out_len(len, &splices, array_off)?
        .checked_sub(deleted_array_item_count(mods, len, array_off)?)
        .ok_or_else(|| length_overflow(array_off))?;

    enc.array(out_len, |aenc| {
        emit_array_items(aenc, array, mods, &splices, array_off, len)
    })
}

fn deleted_array_item_count(
    mods: &[(usize, Node<'_>)],
    len: usize,
    offset: usize,
) -> Result<usize, CborError> {
    let mut count = 0usize;
    for (idx, node) in mods {
        match node.terminal.as_ref() {
            Some(Terminal::Delete {
                mode: DeleteMode::IfPresent,
            }) if *idx >= len => {}
            Some(Terminal::Delete { .. }) if *idx < len => {
                count = count
                    .checked_add(1)
                    .ok_or_else(|| length_overflow(offset))?;
            }
            _ if *idx >= len => return Err(index_out_of_bounds(offset)),
            _ => {}
        }
    }
    Ok(count)
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

fn emit_array_items<'a, E: EmitValue>(
    aenc: &mut E,
    array: crate::query::ArrayRef<'a>,
    mods: &[(usize, Node<'a>)],
    splices: &[ResolvedSplice<'a>],
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
                        Terminal::Delete { .. } => {}
                        Terminal::Set { mode, value } => {
                            if *mode == SetMode::InsertOnly {
                                return Err(invalid_query());
                            }
                            write_new_value(aenc, value)?;
                        }
                    }
                } else {
                    emit_value(aenc, item, m_node)?;
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

    for (_, node) in mods_iter {
        if !matches!(
            node.terminal,
            Some(Terminal::Delete {
                mode: DeleteMode::IfPresent
            })
        ) {
            return Err(index_out_of_bounds(array_off));
        }
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

        if start > len || (start == len && splice.delete != 0) {
            return Err(index_out_of_bounds(offset));
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
                        out_len = handle_missing_map_mod(out_len, mod_node, map_off)?;
                        mod_idx += 1;
                    }
                }
            }
            (Some((_key, _value)), None) => {
                entry = next_map_entry(&mut iter)?;
            }
            (None, Some((_mod_key, mod_node))) => {
                out_len = handle_missing_map_mod(out_len, mod_node, map_off)?;
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
        )
        | None => Err(missing_key(map_off)),
        Some(Terminal::Set { .. }) => out_len
            .checked_add(1)
            .ok_or_else(|| length_overflow(map_off)),
    }
}

fn emit_map_entries<'a>(
    menc: &mut MapEncoder<'_>,
    map: crate::query::MapRef<'a>,
    mods: &[(Box<str>, Node<'a>)],
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
                        menc.entry_raw_key_cbor(key_bytes, |venc| {
                            EmitValue::raw_value_ref(venc, value_ref)
                        })?;
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
                                menc.entry_raw_key_cbor(key_bytes, |venc| {
                                    write_new_value(venc, value)
                                })?;
                            }
                            None => {
                                let value_ref = value;
                                menc.entry_raw_key_cbor(key_bytes, |venc| {
                                    emit_value(venc, value_ref, mod_node)
                                })?;
                            }
                        }
                        mod_idx += 1;
                        entry = next_map_entry_encoded(&mut iter)?;
                    }
                    Ordering::Greater => {
                        emit_missing_map_entry(menc, mod_key.as_ref(), mod_node, map_off)?;
                        mod_idx += 1;
                    }
                }
            }
            (Some((_key, key_bytes, value)), None) => {
                let value_ref = value;
                menc.entry_raw_key_cbor(key_bytes, |venc| {
                    EmitValue::raw_value_ref(venc, value_ref)
                })?;
                entry = next_map_entry_encoded(&mut iter)?;
            }
            (None, Some((mod_key, mod_node))) => {
                emit_missing_map_entry(menc, mod_key.as_ref(), mod_node, map_off)?;
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
        )
        | None => Err(missing_key(map_off)),
        Some(Terminal::Set { value, .. }) => {
            menc.entry_cbor(mod_key, |venc| write_new_value(venc, value))
        }
    }
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
