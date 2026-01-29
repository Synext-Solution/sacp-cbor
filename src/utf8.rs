#[cfg(feature = "simdutf8")]
use simdutf8::basic as simd_utf8;

/// Validates UTF-8 bytes and returns a borrowed `&str` on success.
#[inline]
pub fn validate(bytes: &[u8]) -> Result<&str, ()> {
    #[cfg(feature = "simdutf8")]
    {
        simd_utf8::from_utf8(bytes).map_err(|_| ())
    }

    #[cfg(not(feature = "simdutf8"))]
    {
        core::str::from_utf8(bytes).map_err(|_| ())
    }
}

/// Returns a `&str` from canonical-trusted bytes.
///
/// In `unsafe` mode this skips validation and relies on the canonical
/// input invariant.
#[cfg(feature = "unsafe")]
#[inline]
#[allow(clippy::unnecessary_wraps)]
#[allow(clippy::missing_const_for_fn)]
pub fn trusted(bytes: &[u8]) -> Result<&str, ()> {
    // Safety: callers only use this for canonical-validated bytes.
    Ok(unsafe { core::str::from_utf8_unchecked(bytes) })
}

/// Returns a `&str` from canonical-trusted bytes.
#[cfg(not(feature = "unsafe"))]
#[inline]
pub fn trusted(bytes: &[u8]) -> Result<&str, ()> {
    validate(bytes)
}
