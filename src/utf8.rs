#[cfg(feature = "simdutf8")]
use simdutf8::basic as simd_utf8;

use crate::work::{WorkMeter, WorkObserver};

/// Failure from an observed UTF-8 validation pass.
pub enum ObservedUtf8Error {
    Invalid,
    /// Cancellation after the contained number of payload bytes were validated.
    Cancelled(usize),
}

/// Validates UTF-8 bytes and returns a borrowed `&str` on success.
#[inline]
pub fn validate_utf8(bytes: &[u8]) -> Result<&str, ()> {
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
    validate_utf8(bytes)
}

#[inline]
const fn is_continuation(byte: u8) -> bool {
    byte & 0b1100_0000 == 0b1000_0000
}

/// Select a chunk end at a UTF-8 code-point boundary when the local bytes permit one.
///
/// Valid UTF-8 needs at most three bytes of adjustment. If the local continuation-byte shape is
/// malformed, returning `suggested` lets the subsequent safe validator reject that chunk instead
/// of letting boundary discovery become an unbounded byte loop of its own.
fn aligned_chunk_end(bytes: &[u8], start: usize, suggested: usize) -> usize {
    debug_assert!(suggested > start);
    if suggested == bytes.len() || !is_continuation(bytes[suggested]) {
        return suggested;
    }

    let ceiling = suggested.saturating_add(3).min(bytes.len());
    let mut candidate = suggested + 1;
    while candidate <= ceiling {
        if candidate == bytes.len() || !is_continuation(bytes[candidate]) {
            return candidate;
        }
        candidate += 1;
    }

    suggested
}

/// Validate UTF-8 through the core fixed-cadence work meter without materializing a whole `&str`.
///
/// The enabled path uses safe, code-point-aligned chunks. Each chunk is charged only after it has
/// validated successfully. The disabled path deliberately retains the existing single SIMD/std
/// validation call.
pub fn validate_utf8_observed<O: WorkObserver>(
    bytes: &[u8],
    meter: &mut WorkMeter<O>,
) -> Result<(), ObservedUtf8Error> {
    if !O::ENABLED {
        return validate_utf8(bytes)
            .map(|_| ())
            .map_err(|()| ObservedUtf8Error::Invalid);
    }

    let mut completed = 0usize;
    while completed < bytes.len() {
        let available = bytes.len() - completed;
        let suggested = completed + meter.next_chunk(available);
        let end = aligned_chunk_end(bytes, completed, suggested);
        if let Err(error) = core::str::from_utf8(&bytes[completed..end]) {
            let valid = error.valid_up_to();
            if valid != 0 && meter.complete(valid).is_err() {
                return Err(ObservedUtf8Error::Cancelled(completed + valid));
            }
            return Err(ObservedUtf8Error::Invalid);
        }
        let chunk_len = end - completed;
        completed = end;
        if meter.complete(chunk_len).is_err() {
            return Err(ObservedUtf8Error::Cancelled(completed));
        }
    }
    Ok(())
}

/// Validate observed UTF-8 and return the complete borrowed string.
///
/// On safe builds, constructing the final whole-slice `&str` requires one opaque standard-library
/// conversion after the chunked validation pass. That conversion is not charged a second time and
/// cannot itself be cooperatively interrupted. Noop observation still performs exactly one
/// validation call in total.
pub fn validate_utf8_as_str_observed<'a, O: WorkObserver>(
    bytes: &'a [u8],
    meter: &mut WorkMeter<O>,
) -> Result<&'a str, ObservedUtf8Error> {
    if !O::ENABLED {
        return validate_utf8(bytes).map_err(|()| ObservedUtf8Error::Invalid);
    }

    validate_utf8_observed(bytes, meter)?;

    #[cfg(feature = "unsafe")]
    {
        trusted(bytes).map_err(|()| ObservedUtf8Error::Invalid)
    }

    #[cfg(not(feature = "unsafe"))]
    {
        core::str::from_utf8(bytes).map_err(|_| ObservedUtf8Error::Invalid)
    }
}
