// src/macros.rs

//! CBOR construction macro.
//!
//! This module provides [`cbor!`], a convenient macro to build [`crate::CborValue`] trees.
//!
//! Design notes:
//! - The macro is **fallible** and returns `Result<CborValue, CborError>`.
//! - Integers outside the "safe integer" range are automatically encoded as CBOR bignums (tag 2/3).
//! - `NaN` is canonicalized; negative zero is rejected.
//! - Map keys are always text strings and the resulting map is sorted into canonical order via
//!   [`crate::CborMap::new`].
//!
//! Map key rules (same ergonomics as `serde_json::json!`):
//! - `{ a: 1 }` uses the literal key `"a"` (identifier stringized)
//! - `{ "a": 1 }` uses the literal string key `"a"`
//! - `{ (k): 1 }` uses the expression `k` as the key (must be `&str`, `String`, or `char`)
//!
//! ```ignore
//! # use your_crate_name::cbor;
//! # fn demo() -> Result<(), your_crate_name::CborError> {
//! let user_key = "dynamic";
//! let v = cbor!({
//!     a: 1,
//!     (user_key): [true, null, 1.5],
//! })?;
//! # Ok(()) }
//! ```

/// Construct a [`crate::CborValue`] using a JSON-like literal syntax.
///
/// This macro returns `Result<crate::CborValue, crate::CborError>`.
///
/// Supported forms:
/// - `cbor!(null)`
/// - `cbor!(true)` / `cbor!(false)`
/// - `cbor!("text")`
/// - `cbor!(b"bytes")`
/// - `cbor!([ ... ])`
/// - `cbor!({ key: value, "key": value, (expr_key): value, ... })`
/// - `cbor!(expr)` where `expr` implements the internal conversion trait
///   (covers primitives, `String`, `Vec<u8>`, `BigInt`, `F64Bits`, `CborMap`, etc.).
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[macro_export]
macro_rules! cbor {
    (null) => {
        ::core::result::Result::<$crate::CborValue, $crate::CborError>::Ok(
            $crate::CborValue::Null,
        )
    };
    (true) => {
        ::core::result::Result::<$crate::CborValue, $crate::CborError>::Ok(
            $crate::CborValue::Bool(true),
        )
    };
    (false) => {
        ::core::result::Result::<$crate::CborValue, $crate::CborError>::Ok(
            $crate::CborValue::Bool(false),
        )
    };

    // Array literal: cbor!([ ... ])
    ([ $($elem:tt),* $(,)? ]) => {{
        (|| -> ::core::result::Result<$crate::CborValue, $crate::CborError> {
            let mut items = $crate::__cbor_macro::Vec::new();
            $crate::__cbor_macro::try_reserve_exact(
                &mut items,
                0usize $(+ { let _ = stringify!($elem); 1usize })*,
            )?;

            $(
                items.push($crate::cbor!($elem)?);
            )*

            ::core::result::Result::Ok($crate::CborValue::Array(items))
        })()
    }};

    // Map literal: cbor!({ ... })
    ({ $($key:tt : $value:tt),* $(,)? }) => {{
        (|| -> ::core::result::Result<$crate::CborValue, $crate::CborError> {
            let mut entries = $crate::__cbor_macro::Vec::new();
            $crate::__cbor_macro::try_reserve_exact(
                &mut entries,
                0usize $(+ { let _ = stringify!($key); let _ = stringify!($value); 1usize })*,
            )?;

            $(
                let k = $crate::__cbor_key!($key)?;
                let v = $crate::cbor!($value)?;
                entries.push((k, v));
            )*

            let map = $crate::CborMap::new(entries)?;
            ::core::result::Result::Ok($crate::CborValue::Map(map))
        })()
    }};

    // Fallback: convert an expression into CborValue
    ($other:expr) => {{
        $crate::__cbor_macro::IntoCborValue::into_cbor_value($other)
    }};
}

/// Internal helper for map keys.
///
/// - `ident` becomes `"ident"`
/// - `"literal"` must be a string literal
/// - `(expr)` uses the runtime expression as key
#[doc(hidden)]
#[cfg(feature = "alloc")]
#[macro_export]
macro_rules! __cbor_key {
    ($key:ident) => {{
        $crate::__cbor_macro::string_from_str(::core::stringify!($key))
    }};
    (($key:expr)) => {{
        $crate::__cbor_macro::IntoCborKey::into_cbor_key($key)
    }};
    ($key:literal) => {{
        // Intentionally requires a string literal type (`&'static str`).
        // Non-string literals will fail to type-check here.
        $crate::__cbor_macro::string_from_str($key)
    }};
}

/// Hidden support module used by `cbor!` expansions.
///
/// This is re-exported at crate root as `__cbor_macro` (see `lib.rs` change below).
#[doc(hidden)]
#[allow(missing_docs)]
pub mod __cbor_macro {
    use alloc::string::String;
    use core::convert::TryFrom;

    pub use alloc::vec::Vec;

    use crate::{
        BigInt, CborError, CborErrorCode, CborMap, CborValue, F64Bits, MAX_SAFE_INTEGER,
        MAX_SAFE_INTEGER_I64, MIN_SAFE_INTEGER,
    };

    #[inline]
    const fn alloc_failed() -> CborError {
        CborError::encode(CborErrorCode::AllocationFailed)
    }

    #[inline]
    const fn overflow() -> CborError {
        CborError::encode(CborErrorCode::LengthOverflow)
    }

    pub fn try_reserve_exact<T>(v: &mut Vec<T>, additional: usize) -> Result<(), CborError> {
        v.try_reserve_exact(additional)
            .map_err(|_| alloc_failed())?;
        Ok(())
    }

    pub fn string_from_str(s: &str) -> Result<String, CborError> {
        let mut out = String::new();
        out.try_reserve_exact(s.len()).map_err(|_| alloc_failed())?;
        out.push_str(s);
        Ok(out)
    }

    pub fn bytes_from_slice(b: &[u8]) -> Result<Vec<u8>, CborError> {
        let mut out: Vec<u8> = Vec::new();
        out.try_reserve_exact(b.len()).map_err(|_| alloc_failed())?;
        out.extend_from_slice(b);
        Ok(out)
    }

    fn u128_to_min_be_bytes_nonzero(n: u128) -> Result<Vec<u8>, CborError> {
        debug_assert!(n != 0);
        let leading_bytes = (n.leading_zeros() / 8) as usize;
        let raw = n.to_be_bytes();
        // For n != 0, leading_bytes is at most 15, so slice is non-empty.
        bytes_from_slice(&raw[leading_bytes..])
    }

    fn int_from_u128(v: u128) -> Result<CborValue, CborError> {
        let safe_max = u128::from(MAX_SAFE_INTEGER);
        if v <= safe_max {
            let i = i64::try_from(v).map_err(|_| overflow())?;
            return Ok(CborValue::Int(i));
        }

        let magnitude = u128_to_min_be_bytes_nonzero(v)?;
        let big = BigInt::new(false, magnitude)?;
        Ok(CborValue::Bignum(big))
    }

    fn int_from_i128(v: i128) -> Result<CborValue, CborError> {
        let min = i128::from(MIN_SAFE_INTEGER);
        let safe_max = i128::from(MAX_SAFE_INTEGER_I64);

        if v >= min && v <= safe_max {
            let i = i64::try_from(v).map_err(|_| overflow())?;
            return Ok(CborValue::Int(i));
        }

        let negative = v < 0;
        let n_u128 = if negative {
            // CBOR negative integer / bignum semantics: value = -1 - n
            let n_i128 = -1_i128 - v;
            u128::try_from(n_i128).map_err(|_| overflow())?
        } else {
            u128::try_from(v).map_err(|_| overflow())?
        };

        // Outside safe range implies n_u128 != 0.
        let magnitude = u128_to_min_be_bytes_nonzero(n_u128)?;
        let big = BigInt::new(negative, magnitude)?;
        Ok(CborValue::Bignum(big))
    }

    pub trait IntoCborKey {
        fn into_cbor_key(self) -> Result<String, CborError>;
    }

    impl IntoCborKey for String {
        fn into_cbor_key(self) -> Result<String, CborError> {
            Ok(self)
        }
    }

    impl IntoCborKey for &String {
        fn into_cbor_key(self) -> Result<String, CborError> {
            string_from_str(self.as_str())
        }
    }

    impl IntoCborKey for &str {
        fn into_cbor_key(self) -> Result<String, CborError> {
            string_from_str(self)
        }
    }

    impl IntoCborKey for char {
        fn into_cbor_key(self) -> Result<String, CborError> {
            let mut out = String::new();
            out.try_reserve_exact(4).map_err(|_| alloc_failed())?;
            out.push(self);
            Ok(out)
        }
    }

    pub trait IntoCborValue {
        fn into_cbor_value(self) -> Result<CborValue, CborError>;
    }

    impl IntoCborValue for CborValue {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(self)
        }
    }

    impl IntoCborValue for &CborValue {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(self.clone())
        }
    }

    impl IntoCborValue for CborMap {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Map(self))
        }
    }

    impl IntoCborValue for &CborMap {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Map(self.clone()))
        }
    }

    impl IntoCborValue for BigInt {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Bignum(self))
        }
    }

    impl IntoCborValue for &BigInt {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Bignum(self.clone()))
        }
    }

    impl IntoCborValue for F64Bits {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Float(self))
        }
    }

    impl IntoCborValue for bool {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Bool(self))
        }
    }

    impl IntoCborValue for () {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Null)
        }
    }

    impl<T: IntoCborValue> IntoCborValue for Option<T> {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            self.map_or(Ok(CborValue::Null), IntoCborValue::into_cbor_value)
        }
    }

    impl IntoCborValue for String {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Text(self))
        }
    }

    impl IntoCborValue for &String {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Text(string_from_str(self.as_str())?))
        }
    }

    impl IntoCborValue for &str {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Text(string_from_str(self)?))
        }
    }

    impl IntoCborValue for Vec<u8> {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Bytes(self))
        }
    }

    impl IntoCborValue for &Vec<u8> {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Bytes(bytes_from_slice(self.as_slice())?))
        }
    }

    impl IntoCborValue for &[u8] {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Bytes(bytes_from_slice(self)?))
        }
    }

    impl<const N: usize> IntoCborValue for &[u8; N] {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Bytes(bytes_from_slice(&self[..])?))
        }
    }

    impl IntoCborValue for Vec<CborValue> {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Array(self))
        }
    }

    impl IntoCborValue for &[CborValue] {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            // Clone into a new Vec (may allocate).
            Ok(CborValue::Array(self.to_vec()))
        }
    }

    impl IntoCborValue for f64 {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Float(F64Bits::try_from_f64(self)?))
        }
    }

    impl IntoCborValue for f32 {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::Float(F64Bits::try_from_f64(f64::from(self))?))
        }
    }

    macro_rules! impl_into_int_signed {
        ($($t:ty),* $(,)?) => {$(
            impl IntoCborValue for $t {
                fn into_cbor_value(self) -> Result<CborValue, CborError> {
                    int_from_i128(i128::from(self))
                }
            }
        )*};
    }

    macro_rules! impl_into_int_unsigned {
        ($($t:ty),* $(,)?) => {$(
            impl IntoCborValue for $t {
                fn into_cbor_value(self) -> Result<CborValue, CborError> {
                    int_from_u128(u128::from(self))
                }
            }
        )*};
    }

    impl_into_int_signed!(i8, i16, i32, i64, i128);
    impl_into_int_unsigned!(u8, u16, u32, u64, u128);

    impl IntoCborValue for isize {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            int_from_i128(i128::try_from(self).map_err(|_| overflow())?)
        }
    }

    impl IntoCborValue for usize {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            int_from_u128(u128::try_from(self).map_err(|_| overflow())?)
        }
    }
}
