use alloc::string::String;
use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};
use core::marker::PhantomData;

use sacp_cbor::bytes::{Bytes, BytesRef};
use sacp_cbor::query::{ArrayIter, CborValueRef};
use sacp_cbor::{CanonicalCbor, CanonicalCborRef, CborError, ErrorCode};

use crate::edit::AbiFieldSetEditor;

/// Borrowed zero-copy view over a public ABI value.
pub trait AbiView<'a>: Sized {
    /// Construct a view from a canonical CBOR witness.
    fn view_from_canonical(cbor: CanonicalCborRef<'a>) -> Result<Self, CborError>;

    /// Construct a view from a canonical sub-value.
    fn view_from_value(value: CborValueRef<'a>) -> Result<Self, CborError>;

    /// Return the raw CBOR value backing this view.
    #[must_use]
    fn raw_value(&self) -> CborValueRef<'a>;
}

/// Borrowed view mapping for a type when it appears as an ABI field.
pub trait AbiViewField<'a> {
    /// Zero-copy view type returned by generated accessors.
    type View;

    /// Decode or wrap one raw field value as `Self::View`.
    fn view_field(value: CborValueRef<'a>) -> Result<Self::View, CborError>;
}

/// One borrowed field entry in an ABI field-set array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiFieldEntryRef<'a> {
    /// Stable numeric field ID.
    pub id: u32,
    /// Offset of the encoded field ID.
    pub id_offset: usize,
    /// Borrowed canonical field value.
    pub value: CborValueRef<'a>,
}

/// A fully validated borrowed ABI field-set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiFieldSetRef<'a> {
    raw: CborValueRef<'a>,
}

pub(crate) struct AbiFieldSetIter<'a> {
    items: ArrayIter<'a>,
    pending_id: Option<(u32, usize)>,
}

impl<'a> Iterator for AbiFieldSetIter<'a> {
    type Item = Result<AbiFieldEntryRef<'a>, CborError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let item = match self.items.next()? {
                Ok(item) => item,
                Err(err) => return Some(Err(err)),
            };
            if let Some((id, id_offset)) = self.pending_id.take() {
                return Some(Ok(AbiFieldEntryRef {
                    id,
                    id_offset,
                    value: item,
                }));
            }
            match abi_field_id(item) {
                Ok(id) => self.pending_id = Some((id, item.offset())),
                Err(err) => return Some(Err(err)),
            }
        }
    }
}

/// Borrowed unknown field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownFieldRef<'a> {
    /// Stable numeric field ID.
    pub id: u32,
    /// Borrowed canonical field value.
    pub value: CborValueRef<'a>,
}

/// Borrowed unknown enum variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownVariantRef<'a> {
    /// Stable numeric variant ID.
    pub id: u32,
    /// Borrowed canonical payload.
    pub payload: CborValueRef<'a>,
}

/// Borrowed zero-copy view over a CBOR array field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiArrayView<'a, T> {
    raw: CborValueRef<'a>,
    _marker: PhantomData<fn() -> T>,
}

fn invalid_abi_value(offset: usize) -> CborError {
    CborError::new(ErrorCode::InvalidAbiValue, offset)
}

fn invalid_query(offset: usize) -> CborError {
    CborError::new(ErrorCode::InvalidQuery, offset)
}

#[inline]
pub(crate) fn abi_field_id(value: CborValueRef<'_>) -> Result<u32, CborError> {
    let offset = value.offset();
    let Some(id) = value.integer()?.as_i64() else {
        return Err(invalid_abi_value(offset));
    };
    validate_abi_id_value(id, offset)
}

#[inline]
pub(crate) fn validate_abi_id_value(id: i64, offset: usize) -> Result<u32, CborError> {
    if id <= 0 || id > u32::MAX as i64 {
        return Err(invalid_abi_value(offset));
    }
    Ok(id as u32)
}

#[inline]
pub(crate) fn validate_sorted_query_ids(ids: &[u32], offset: usize) -> Result<(), CborError> {
    let mut prev = None;
    for id in ids {
        if *id == 0 || prev.is_some_and(|prev_id| *id <= prev_id) {
            return Err(invalid_query(offset));
        }
        prev = Some(*id);
    }
    Ok(())
}

fn expected_integer(offset: usize) -> CborError {
    CborError::new(ErrorCode::ExpectedInteger, offset)
}

fn expected_null(offset: usize) -> CborError {
    CborError::new(ErrorCode::ExpectedNull, offset)
}

#[inline]
fn view_signed_integer<'a, T>(value: CborValueRef<'a>) -> Result<T, CborError>
where
    T: TryFrom<i128>,
{
    let offset = value.offset();
    let value = value
        .integer()?
        .as_i128()
        .ok_or_else(|| expected_integer(offset))?;
    T::try_from(value).map_err(|_| expected_integer(offset))
}

#[inline]
fn view_unsigned_integer<'a, T>(value: CborValueRef<'a>) -> Result<T, CborError>
where
    T: TryFrom<u128>,
{
    let offset = value.offset();
    let value = value
        .integer()?
        .as_u128()
        .ok_or_else(|| expected_integer(offset))?;
    T::try_from(value).map_err(|_| expected_integer(offset))
}

impl<'a> AbiFieldSetRef<'a> {
    /// Validate and construct a borrowed ABI field-set witness.
    #[inline]
    pub fn from_value(raw: CborValueRef<'a>) -> Result<Self, CborError> {
        Self::scan(raw, |_| Ok(()))
    }

    /// Validate a field-set and visit each entry exactly once.
    #[inline]
    pub fn scan<F>(raw: CborValueRef<'a>, mut visit: F) -> Result<Self, CborError>
    where
        F: FnMut(AbiFieldEntryRef<'a>) -> Result<(), CborError>,
    {
        let fields = Self { raw };
        let array = raw.array()?;
        if array.len() % 2 != 0 {
            return Err(CborError::new(ErrorCode::ArrayLenMismatch, raw.offset()));
        }

        let mut prev = None;
        let mut iter = array.iter();
        while let Some(id_value) = iter.next() {
            let id_value = id_value?;
            let id = abi_field_id(id_value)?;
            let value = iter
                .next()
                .ok_or_else(|| CborError::new(ErrorCode::ArrayLenMismatch, raw.offset()))??;
            if let Some(prev_id) = prev {
                if id == prev_id {
                    return Err(CborError::new(
                        ErrorCode::DuplicateMapKey,
                        id_value.offset(),
                    ));
                }
                if id < prev_id {
                    return Err(CborError::new(
                        ErrorCode::NonCanonicalMapOrder,
                        id_value.offset(),
                    ));
                }
            }
            prev = Some(id);
            visit(AbiFieldEntryRef {
                id,
                id_offset: id_value.offset(),
                value,
            })?;
        }
        Ok(fields)
    }

    /// Return the raw field-set array value.
    #[must_use]
    pub const fn raw_value(self) -> CborValueRef<'a> {
        self.raw
    }

    /// Iterate over validated ABI field entries in field-ID order.
    #[inline]
    pub(crate) fn iter_internal(self) -> Result<AbiFieldSetIter<'a>, CborError> {
        let array = self.raw.array()?;
        Ok(AbiFieldSetIter {
            items: array.iter(),
            pending_id: None,
        })
    }

    /// Iterate over validated ABI field entries in field-ID order.
    #[inline]
    pub fn iter(
        self,
    ) -> Result<impl Iterator<Item = Result<AbiFieldEntryRef<'a>, CborError>> + 'a, CborError> {
        self.iter_internal()
    }

    /// Return one field by numeric ID.
    #[inline]
    pub fn get(self, id: u32) -> Result<Option<CborValueRef<'a>>, CborError> {
        if id == 0 {
            return Err(invalid_abi_value(self.raw.offset()));
        }
        for entry in self.iter()? {
            let entry = entry?;
            if entry.id == id {
                return Ok(Some(entry.value));
            }
            if entry.id > id {
                return Ok(None);
            }
        }
        Ok(None)
    }

    /// Return one required field by numeric ID.
    #[inline]
    pub fn require(self, id: u32) -> Result<CborValueRef<'a>, CborError> {
        self.get(id)?
            .ok_or_else(|| CborError::new(ErrorCode::MissingKey, self.raw.offset()))
    }

    /// Fill `out` with fields for sorted numeric IDs in one scan.
    #[inline]
    pub fn get_many_sorted_into(
        self,
        ids: &[u32],
        out: &mut [Option<CborValueRef<'a>>],
    ) -> Result<(), CborError> {
        if ids.len() != out.len() {
            return Err(invalid_query(self.raw.offset()));
        }
        validate_sorted_query_ids(ids, self.raw.offset())?;
        for slot in out.iter_mut() {
            *slot = None;
        }

        let mut target = 0usize;
        for entry in self.iter()? {
            let entry = entry?;
            while target < ids.len() && ids[target] < entry.id {
                target += 1;
            }
            if target == ids.len() {
                break;
            }
            if ids[target] == entry.id {
                out[target] = Some(entry.value);
                target += 1;
            }
        }
        Ok(())
    }

    /// Iterate over borrowed unknown fields.
    #[inline]
    pub fn unknown_fields(
        self,
        known_ids: &'static [u32],
    ) -> Result<impl Iterator<Item = Result<UnknownFieldRef<'a>, CborError>> + 'a, CborError> {
        validate_sorted_query_ids(known_ids, self.raw.offset())?;
        Ok(self.iter()?.filter_map(move |entry| match entry {
            Ok(entry) if known_ids.binary_search(&entry.id).is_err() => Some(Ok(UnknownFieldRef {
                id: entry.id,
                value: entry.value,
            })),
            Ok(_) => None,
            Err(err) => Some(Err(err)),
        }))
    }

    /// Create a raw-copy editor for this field-set.
    #[inline]
    #[must_use]
    pub fn edit(self) -> AbiFieldSetEditor<'a> {
        AbiFieldSetEditor::new(self)
    }
}

impl<'a, T> AbiArrayView<'a, T> {
    /// Validate and construct an array view.
    #[inline]
    pub fn from_value(raw: CborValueRef<'a>) -> Result<Self, CborError> {
        let _ = raw.array()?;
        Ok(Self {
            raw,
            _marker: PhantomData,
        })
    }

    /// Return the raw array value.
    #[must_use]
    pub const fn raw_value(self) -> CborValueRef<'a> {
        self.raw
    }

    /// Return the number of elements.
    #[inline]
    pub fn len(self) -> Result<usize, CborError> {
        Ok(self.raw.array()?.len())
    }

    /// Return whether the array is empty.
    #[inline]
    pub fn is_empty(self) -> Result<bool, CborError> {
        Ok(self.raw.array()?.is_empty())
    }
}

impl<'a, T: AbiViewField<'a>> AbiArrayView<'a, T> {
    /// Return one viewed item by index.
    #[inline]
    pub fn get(self, index: usize) -> Result<Option<T::View>, CborError> {
        self.raw.array()?.get(index)?.map(T::view_field).transpose()
    }

    /// Iterate viewed items in order.
    #[inline]
    pub fn iter(self) -> Result<impl Iterator<Item = Result<T::View, CborError>> + 'a, CborError> {
        Ok(self
            .raw
            .array()?
            .iter()
            .map(|item| item.and_then(T::view_field)))
    }
}

impl<'a> AbiViewField<'a> for () {
    type View = ();

    #[inline]
    fn view_field(value: CborValueRef<'a>) -> Result<Self::View, CborError> {
        if value.is_null() {
            Ok(())
        } else {
            Err(expected_null(value.offset()))
        }
    }
}

impl<'a> AbiViewField<'a> for bool {
    type View = bool;

    #[inline]
    fn view_field(value: CborValueRef<'a>) -> Result<Self::View, CborError> {
        value.bool()
    }
}

macro_rules! signed_view_field {
    ($($ty:ty),* $(,)?) => {
        $(
            impl<'a> AbiViewField<'a> for $ty {
                type View = $ty;

                #[inline]
                fn view_field(value: CborValueRef<'a>) -> Result<Self::View, CborError> {
                    view_signed_integer(value)
                }
            }
        )*
    };
}

macro_rules! unsigned_view_field {
    ($($ty:ty),* $(,)?) => {
        $(
            impl<'a> AbiViewField<'a> for $ty {
                type View = $ty;

                #[inline]
                fn view_field(value: CborValueRef<'a>) -> Result<Self::View, CborError> {
                    view_unsigned_integer(value)
                }
            }
        )*
    };
}

signed_view_field!(i8, i16, i32, i64);
unsigned_view_field!(u8, u16, u32, u64);

impl<'a> AbiViewField<'a> for String {
    type View = &'a str;

    #[inline]
    fn view_field(value: CborValueRef<'a>) -> Result<Self::View, CborError> {
        value.text()
    }
}

impl<'a> AbiViewField<'a> for &str {
    type View = &'a str;

    #[inline]
    fn view_field(value: CborValueRef<'a>) -> Result<Self::View, CborError> {
        value.text()
    }
}

impl<'a> AbiViewField<'a> for Bytes {
    type View = BytesRef<'a>;

    #[inline]
    fn view_field(value: CborValueRef<'a>) -> Result<Self::View, CborError> {
        value.bytes().map(BytesRef::new)
    }
}

impl<'a, 'b> AbiViewField<'a> for BytesRef<'b> {
    type View = BytesRef<'a>;

    #[inline]
    fn view_field(value: CborValueRef<'a>) -> Result<Self::View, CborError> {
        value.bytes().map(BytesRef::new)
    }
}

impl<'a> AbiViewField<'a> for CanonicalCbor {
    type View = CanonicalCborRef<'a>;

    #[inline]
    fn view_field(value: CborValueRef<'a>) -> Result<Self::View, CborError> {
        Ok(value.as_canonical_ref())
    }
}

impl<'a, 'b> AbiViewField<'a> for CanonicalCborRef<'b> {
    type View = CanonicalCborRef<'a>;

    #[inline]
    fn view_field(value: CborValueRef<'a>) -> Result<Self::View, CborError> {
        Ok(value.as_canonical_ref())
    }
}

impl<'a, 'b> AbiViewField<'a> for CborValueRef<'b> {
    type View = CborValueRef<'a>;

    #[inline]
    fn view_field(value: CborValueRef<'a>) -> Result<Self::View, CborError> {
        Ok(value)
    }
}

impl<'a, const N: usize> AbiViewField<'a> for [u8; N] {
    type View = &'a [u8; N];

    #[inline]
    fn view_field(value: CborValueRef<'a>) -> Result<Self::View, CborError> {
        value
            .bytes()?
            .try_into()
            .map_err(|_| CborError::new(ErrorCode::ExpectedBytes, value.offset()))
    }
}

impl<'a, T> AbiViewField<'a> for Vec<T>
where
    T: AbiViewField<'a>,
{
    type View = AbiArrayView<'a, T>;

    #[inline]
    fn view_field(value: CborValueRef<'a>) -> Result<Self::View, CborError> {
        AbiArrayView::from_value(value)
    }
}
