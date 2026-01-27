use crate::{CborError, DecodeLimits, ErrorCode};

/// A validated canonical SACP-CBOR/1 data item borrowed from an input buffer.
///
/// This is the primary "hot-path" product of [`crate::validate_canonical`]. The bytes are guaranteed to:
///
/// - represent exactly one SACP-CBOR/1 CBOR data item, and
/// - already be in canonical form.
///
/// Therefore, for protocol purposes, these bytes can be treated as the stable canonical representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CborBytesRef<'a> {
    bytes: &'a [u8],
}

impl<'a> CborBytesRef<'a> {
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

    /// Copy into an owned [`CborBytes`].
    ///
    /// This method is available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    ///
    /// # Errors
    ///
    /// Returns `CborError` on allocation failure.
    pub fn to_owned(self) -> Result<CborBytes, CborError> {
        use crate::alloc_util::try_vec_from_slice;

        Ok(CborBytes {
            bytes: try_vec_from_slice(self.bytes, 0)?,
        })
    }

    /// Compare canonical bytes for equality.
    #[inline]
    #[must_use]
    pub fn bytes_eq(self, other: Self) -> bool {
        self.bytes == other.bytes
    }
}

impl AsRef<[u8]> for CborBytesRef<'_> {
    fn as_ref(&self) -> &[u8] {
        self.bytes
    }
}

/// A validated canonical CBOR-encoded text-string key.
///
/// This wraps the exact canonical encoding bytes for a CBOR text string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedTextKey<'a> {
    bytes: &'a [u8],
}

impl<'a> EncodedTextKey<'a> {
    #[inline]
    pub(crate) const fn new_unchecked(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Validate and wrap an encoded text key.
    ///
    /// # Errors
    ///
    /// Returns `CborError` if `bytes` are not a canonical CBOR text string.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, CborError> {
        if bytes.is_empty() {
            return Err(CborError::new(ErrorCode::UnexpectedEof, 0));
        }
        let limits = DecodeLimits::for_bytes(bytes.len());
        crate::validate_canonical(bytes, limits)?;
        if bytes[0] >> 5 != 3 {
            return Err(CborError::new(ErrorCode::MapKeyMustBeText, 0));
        }
        Ok(Self { bytes })
    }

    /// Return the canonical encoded bytes.
    #[inline]
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
}

impl AsRef<[u8]> for EncodedTextKey<'_> {
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
pub struct CborBytes {
    bytes: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl CborBytes {
    #[inline]
    pub(crate) const fn new_unchecked(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Compare canonical bytes for equality.
    #[inline]
    #[must_use]
    pub fn bytes_eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }

    /// Validate and copy `bytes` into an owned canonical representation.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` are not a canonical SACP-CBOR/1 data item.
    pub fn from_slice(bytes: &[u8], limits: DecodeLimits) -> Result<Self, CborError> {
        let canon = crate::validate_canonical(bytes, limits)?;
        canon.to_owned()
    }

    /// Validate and wrap an owned canonical CBOR buffer without copying.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` are not a canonical SACP-CBOR/1 data item.
    pub fn from_vec(bytes: Vec<u8>, limits: DecodeLimits) -> Result<Self, CborError> {
        crate::validate_canonical(&bytes, limits)?;
        Ok(Self { bytes })
    }

    /// Validate and wrap an owned canonical CBOR buffer using default limits.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` are not a canonical SACP-CBOR/1 data item.
    pub fn from_vec_default_limits(bytes: Vec<u8>) -> Result<Self, CborError> {
        let limits = DecodeLimits::for_bytes(bytes.len());
        Self::from_vec(bytes, limits)
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
        CborBytesRef::new(&self.bytes).sha256()
    }
}

#[cfg(feature = "alloc")]
impl AsRef<[u8]> for CborBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(feature = "serde")]
mod serde_impls {
    use super::{CborBytes, CborBytesRef};
    use crate::{validate_canonical, DecodeLimits};
    use serde::de::{Error as DeError, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for CborBytesRef<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.as_bytes())
        }
    }

    #[cfg(feature = "alloc")]
    impl Serialize for CborBytes {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.as_bytes())
        }
    }

    /// Deserializes from a CBOR byte string (or any serde bytes source) into an owned canonical
    /// wrapper. Validation uses `DecodeLimits::for_bytes(len)`.
    #[cfg(feature = "alloc")]
    impl<'de> Deserialize<'de> for CborBytes {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct V;

            impl<'de> Visitor<'de> for V {
                type Value = CborBytes;

                fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "canonical CBOR bytes")
                }

                fn visit_byte_buf<E: DeError>(
                    self,
                    v: alloc::vec::Vec<u8>,
                ) -> Result<Self::Value, E> {
                    let limits = DecodeLimits::for_bytes(v.len());
                    validate_canonical(&v, limits).map_err(E::custom)?;
                    Ok(CborBytes::new_unchecked(v))
                }

                fn visit_borrowed_bytes<E: DeError>(self, v: &'de [u8]) -> Result<Self::Value, E> {
                    let limits = DecodeLimits::for_bytes(v.len());
                    validate_canonical(v, limits).map_err(E::custom)?;
                    let out = crate::alloc_util::try_vec_from_slice(v, 0).map_err(E::custom)?;
                    Ok(CborBytes::new_unchecked(out))
                }
            }

            deserializer.deserialize_bytes(V)
        }
    }
}
