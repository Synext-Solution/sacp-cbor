//! Byte-string wrapper types for native CBOR encoding and decoding.

#[cfg(feature = "alloc")]
use crate::alloc_util;
#[cfg(feature = "alloc")]
use crate::CborError;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Borrowed bytes that encode as a CBOR byte string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BytesRef<'a> {
    bytes: &'a [u8],
}

impl<'a> BytesRef<'a> {
    /// Wrap borrowed bytes for CBOR byte-string encoding.
    #[inline]
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Return the borrowed bytes.
    #[inline]
    #[must_use]
    pub const fn as_slice(self) -> &'a [u8] {
        self.bytes
    }

    /// Return the byte length.
    #[inline]
    #[must_use]
    pub const fn len(self) -> usize {
        self.bytes.len()
    }

    /// Return `true` when the byte string is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bytes.is_empty()
    }
}

impl AsRef<[u8]> for BytesRef<'_> {
    fn as_ref(&self) -> &[u8] {
        self.bytes
    }
}

/// Owned bytes that encode as a CBOR byte string.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bytes {
    bytes: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl Bytes {
    /// Wrap owned bytes for CBOR byte-string encoding.
    #[inline]
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Copy borrowed bytes into an owned byte-string wrapper.
    ///
    /// # Errors
    ///
    /// Returns `AllocationFailed` if copying the bytes cannot reserve memory.
    pub fn copy_from_slice(bytes: &[u8]) -> Result<Self, CborError> {
        Ok(Self {
            bytes: alloc_util::try_vec_from_slice(bytes, 0)?,
        })
    }

    /// Return the wrapped bytes.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrow as a byte-string reference.
    #[inline]
    #[must_use]
    pub fn as_ref(&self) -> BytesRef<'_> {
        BytesRef::new(self.as_slice())
    }

    /// Consume and return the wrapped bytes.
    #[inline]
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(feature = "alloc")]
impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
