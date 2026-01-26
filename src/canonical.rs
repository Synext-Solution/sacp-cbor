#[cfg(feature = "alloc")]
use crate::{CborError, DecodeLimits};

/// A validated canonical SACP-CBOR/1 data item borrowed from an input buffer.
///
/// This is the primary "hot-path" product of [`crate::validate_canonical`]. The bytes are guaranteed to:
///
/// - represent exactly one SACP-CBOR/1 CBOR data item, and
/// - already be in canonical form.
///
/// Therefore, for protocol purposes, these bytes can be treated as the stable canonical representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalCborRef<'a> {
    bytes: &'a [u8],
}

impl<'a> CanonicalCborRef<'a> {
    #[inline]
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Return the canonical bytes.
    #[inline]
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Length in bytes of the canonical representation.
    #[inline]
    #[must_use]
    pub const fn len(self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` iff the canonical encoding is empty (this never happens for a valid item).
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bytes.is_empty()
    }

    /// Compute the SHA-256 digest of the canonical bytes.
    #[cfg(feature = "sha2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2")))]
    #[must_use]
    pub fn sha256(self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.bytes);
        let out = h.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(out.as_slice());
        digest
    }

    /// Copy into an owned [`CanonicalCbor`].
    ///
    /// This method is available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[must_use]
    pub fn to_owned(self) -> CanonicalCbor {
        CanonicalCbor {
            bytes: self.bytes.to_vec(),
        }
    }
}

impl AsRef<[u8]> for CanonicalCborRef<'_> {
    fn as_ref(&self) -> &[u8] {
        self.bytes
    }
}

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// An owned canonical SACP-CBOR/1 data item.
///
/// This type is useful for durable storage of canonical CBOR (e.g., protocol state).
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalCbor {
    bytes: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl CanonicalCbor {
    /// Validate and copy `bytes` into an owned canonical representation.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` are not a canonical SACP-CBOR/1 data item.
    pub fn from_slice(bytes: &[u8], limits: DecodeLimits) -> Result<Self, CborError> {
        let canon = crate::validate_canonical(bytes, limits)?;
        Ok(canon.to_owned())
    }

    /// Borrow the canonical bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume and return the canonical bytes.
    #[inline]
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Compute the SHA-256 digest of the canonical bytes.
    #[cfg(feature = "sha2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2")))]
    #[must_use]
    pub fn sha256(&self) -> [u8; 32] {
        CanonicalCborRef::new(&self.bytes).sha256()
    }
}

#[cfg(feature = "alloc")]
impl AsRef<[u8]> for CanonicalCbor {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
