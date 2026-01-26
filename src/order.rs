use core::cmp::Ordering;

/// Compare two CBOR-encoded map keys by the canonical CBOR ordering rule.
///
/// Canonical ordering is:
/// 1) shorter encoded byte string sorts first, then
/// 2) lexicographic byte comparison.
///
/// This is used by the validator when it already has the encoded key slices.
#[inline]
#[must_use]
pub fn cmp_encoded_key_bytes(a: &[u8], b: &[u8]) -> Ordering {
    match a.len().cmp(&b.len()) {
        Ordering::Equal => a.cmp(b),
        other => other,
    }
}

/// Returns true iff `prev < curr` under canonical CBOR ordering (by encoded bytes).
#[inline]
#[must_use]
pub fn is_strictly_increasing_encoded(prev: &[u8], curr: &[u8]) -> bool {
    cmp_encoded_key_bytes(prev, curr) == Ordering::Less
}

/// Compare two UTF-8 text keys by SACP-CBOR/1 canonical map ordering.
///
/// For SACP-CBOR/1 maps, keys are restricted to CBOR text strings. Canonical map ordering is defined
/// over the *canonical CBOR encoding* of each key:
///
/// 1) shorter encoded key sorts first (this includes the header bytes), then
/// 2) lexicographic ordering of the encoded key bytes.
///
/// For text strings, once encoded length is equal, the header bytes are equal and the lexicographic
/// ordering reduces to lexicographic ordering of UTF-8 bytes.
#[inline]
#[must_use]
#[cfg(feature = "alloc")]
pub fn cmp_text_keys_by_canonical_encoding(a: &str, b: &str) -> Ordering {
    let a_len = encoded_text_len(a.len());
    let b_len = encoded_text_len(b.len());

    match a_len.cmp(&b_len) {
        Ordering::Equal => a.as_bytes().cmp(b.as_bytes()),
        other => other,
    }
}

/// Return the length in bytes of the canonical CBOR encoding of a text string payload of length `n`.
///
/// This is `header_len(n) + n`, where `header_len(n)` depends on the canonical CBOR length encoding:
///
/// - `n < 24`   => 1-byte header
/// - `n <= 255` => 2-byte header
/// - `n <= 65535` => 3-byte header
/// - `n <= 2^32-1` => 5-byte header
/// - otherwise => 9-byte header
#[inline]
#[must_use]
#[cfg(feature = "alloc")]
pub const fn encoded_text_len(n: usize) -> usize {
    const fn add_or_max(a: usize, b: usize) -> usize {
        match a.checked_add(b) {
            Some(v) => v,
            None => usize::MAX,
        }
    }

    if n < 24 {
        add_or_max(1, n)
    } else if n <= 0xff {
        add_or_max(2, n)
    } else if n <= 0xffff {
        add_or_max(3, n)
    } else if n <= 0xffff_ffff {
        add_or_max(5, n)
    } else {
        add_or_max(9, n)
    }
}
