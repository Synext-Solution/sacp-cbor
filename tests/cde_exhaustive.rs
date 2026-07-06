#![cfg(feature = "cde")]

//! Exhaustive and oracle-differential coverage for the CDE float bridge.
//!
//! The bridge's float16 widening/narrowing is pure bit arithmetic; these tests
//! check it against an independent arithmetic oracle (`f64` multiplication by
//! powers of two) over the entire 2^16 float16 space, and cross-check the
//! float32 acceptance decision against the oracle-derived set of
//! float16-representable values.

use std::collections::HashSet;

use proptest::prelude::*;
use sacp_cbor::cde::{from_cde, to_cde};
use sacp_cbor::{DecodeLimits, ErrorCode};

fn limits() -> DecodeLimits {
    DecodeLimits::for_bytes(1 << 12)
}

fn is_f16_nan(half: u16) -> bool {
    half & 0x7c00 == 0x7c00 && half & 0x03ff != 0
}

/// Arithmetic widening oracle: every float16 value is exact in f64, built here
/// from sign/exponent/fraction with float multiplication, independently of the
/// bridge's bit-level path.
fn f16_oracle(half: u16) -> f64 {
    let sign = if half >> 15 == 1 { -1.0 } else { 1.0 };
    let exponent = i32::from((half >> 10) & 0x1f);
    let fraction = f64::from(half & 0x03ff);
    if exponent == 0x1f {
        return sign * f64::INFINITY;
    }
    if exponent == 0 {
        return sign * fraction * 2f64.powi(-24);
    }
    sign * (1024.0 + fraction) * 2f64.powi(exponent - 15 - 10)
}

#[test]
fn every_float16_bit_pattern_round_trips_against_the_oracle() {
    let mut accepted = 0u32;
    for half in 0..=u16::MAX {
        let encoded = [0xf9, (half >> 8) as u8, (half & 0xff) as u8];
        let outcome = from_cde(&encoded, limits());
        if is_f16_nan(half) {
            if half == 0x7e00 {
                let sacp = outcome.expect("preferred NaN accepted");
                assert_eq!(sacp.as_bytes(), [0xfb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0]);
                assert_eq!(
                    to_cde(sacp.as_canonical_ref()).expect("total"),
                    encoded,
                    "NaN returns to the preferred spelling"
                );
            } else {
                assert_eq!(
                    outcome.expect_err("payload NaN rejected").code,
                    ErrorCode::NonCanonicalNaN
                );
            }
            continue;
        }
        if half == 0x8000 {
            assert_eq!(
                outcome.expect_err("negative zero rejected").code,
                ErrorCode::NegativeZeroForbidden
            );
            continue;
        }
        let sacp = outcome.expect("every other float16 value is accepted");
        let widened = u64::from_be_bytes(sacp.as_bytes()[1..9].try_into().expect("f64 payload"));
        assert_eq!(
            widened,
            f16_oracle(half).to_bits(),
            "bit-level widening equals the arithmetic oracle for {half:#06x}"
        );
        assert_eq!(
            to_cde(sacp.as_canonical_ref()).expect("total"),
            encoded,
            "narrowing returns the exact float16 spelling for {half:#06x}"
        );
        accepted += 1;
    }
    // 2^16 patterns minus 2 * 1023 NaNs minus negative zero.
    assert_eq!(accepted, 65_536 - 2 * 1023 - 1);
}

/// Oracle-derived set of f64 bit patterns that have an exact float16 form
/// (excluding NaNs; including both zeros and infinities).
fn f16_exact_bits() -> &'static HashSet<u64> {
    static SET: std::sync::OnceLock<HashSet<u64>> = std::sync::OnceLock::new();
    SET.get_or_init(|| {
        (0..=u16::MAX)
            .filter(|half| !is_f16_nan(*half))
            .map(|half| f16_oracle(half).to_bits())
            .collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// The float32 acceptance decision matches the oracle set: a float32
    /// spelling is canonical CDE exactly when the value has no float16 form,
    /// and accepted values round-trip to the identical spelling.
    #[test]
    fn float32_acceptance_matches_the_oracle_set(single in any::<u32>()) {
        let f16_set = f16_exact_bits();
        let encoded = [
            0xfa,
            (single >> 24) as u8,
            (single >> 16) as u8,
            (single >> 8) as u8,
            (single & 0xff) as u8,
        ];
        let value = f32::from_bits(single);
        let outcome = from_cde(&encoded, limits());
        if value.is_nan() {
            prop_assert_eq!(outcome.unwrap_err().code, ErrorCode::NonCanonicalNaN);
        } else if single == 0x8000_0000 {
            prop_assert_eq!(outcome.unwrap_err().code, ErrorCode::NegativeZeroForbidden);
        } else if f16_set.contains(&f64::from(value).to_bits()) {
            prop_assert_eq!(outcome.unwrap_err().code, ErrorCode::NonCanonicalEncoding);
        } else {
            let sacp = outcome.unwrap();
            let widened =
                u64::from_be_bytes(sacp.as_bytes()[1..9].try_into().expect("f64 payload"));
            prop_assert_eq!(widened, f64::from(value).to_bits());
            prop_assert_eq!(to_cde(sacp.as_canonical_ref()).unwrap(), encoded);
        }
    }

    /// The float64 acceptance decision is the same law one width up: canonical
    /// exactly when the value has no float32 (hence no float16) form.
    #[test]
    fn float64_acceptance_matches_the_narrowing_law(bits in any::<u64>()) {
        let mut encoded = [0u8; 9];
        encoded[0] = 0xfb;
        encoded[1..].copy_from_slice(&bits.to_be_bytes());
        let value = f64::from_bits(bits);
        let outcome = from_cde(&encoded, limits());
        if value.is_nan() {
            prop_assert_eq!(outcome.unwrap_err().code, ErrorCode::NonCanonicalNaN);
        } else if bits == 0x8000_0000_0000_0000 {
            prop_assert_eq!(outcome.unwrap_err().code, ErrorCode::NegativeZeroForbidden);
        } else {
            #[allow(clippy::cast_possible_truncation)] // rounding probe, exactness checked
            let narrowed = value as f32;
            if f64::from(narrowed).to_bits() == bits {
                prop_assert_eq!(outcome.unwrap_err().code, ErrorCode::NonCanonicalEncoding);
            } else {
                let sacp = outcome.unwrap();
                prop_assert_eq!(sacp.as_bytes(), &encoded);
                prop_assert_eq!(to_cde(sacp.as_canonical_ref()).unwrap(), encoded);
            }
        }
    }
}
