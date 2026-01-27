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
            $crate::CborValue::null(),
        )
    };
    (true) => {
        ::core::result::Result::<$crate::CborValue, $crate::CborError>::Ok(
            $crate::CborValue::bool(true),
        )
    };
    (false) => {
        ::core::result::Result::<$crate::CborValue, $crate::CborError>::Ok(
            $crate::CborValue::bool(false),
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

            ::core::result::Result::Ok($crate::CborValue::array(items))
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
            ::core::result::Result::Ok($crate::CborValue::map(map))
        })()
    }};

    // Fallback: convert an expression into CborValue
    ($other:expr) => {{
        $crate::__cbor_macro::IntoCborValue::into_cbor_value($other)
    }};
}

/// Construct canonical CBOR bytes directly using a JSON-like literal syntax.
///
/// This macro returns `Result<crate::CborBytes, crate::CborError>`.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[macro_export]
macro_rules! cbor_bytes {
    ($($tt:tt)+) => {{
        (|| -> ::core::result::Result<$crate::CborBytes, $crate::CborError> {
            let mut __enc = $crate::Encoder::new();
            $crate::__cbor_bytes_into!(&mut __enc, $($tt)+)?;
            __enc.into_canonical()
        })()
    }};
}

#[doc(hidden)]
#[cfg(feature = "alloc")]
#[macro_export]
macro_rules! __cbor_bytes_into {
    ($enc:expr, null) => { $enc.null() };
    ($enc:expr, true) => { $enc.bool(true) };
    ($enc:expr, false) => { $enc.bool(false) };

    ($enc:expr, [ $($elem:tt),* $(,)? ]) => {{
        let __len = 0usize $(+ { let _ = stringify!($elem); 1usize })*;
        $enc.array(__len, |__arr| {
            $( $crate::__cbor_bytes_into!(__arr, $elem)?; )*
            ::core::result::Result::Ok(())
        })
    }};

    ($enc:expr, { $($key:tt : $value:tt),* $(,)? }) => {{
        let __len = 0usize $(+ { let _ = stringify!($key); let _ = stringify!($value); 1usize })*;
        $enc.map(__len, |__map| {
            $( $crate::__cbor_bytes_map_entry!(__map, $key, $value)?; )*
            ::core::result::Result::Ok(())
        })
    }};

    // fallback: encode arbitrary expression types via IntoCborBytes
    ($enc:expr, $other:expr) => {{
        $enc.__encode_any($other)
    }};
}

#[doc(hidden)]
#[cfg(feature = "alloc")]
#[macro_export]
macro_rules! __cbor_bytes_map_entry {
    ($map:expr, $key:ident, $value:tt) => {{
        $map.entry(::core::stringify!($key), |__enc| {
            $crate::__cbor_bytes_into!(__enc, $value)
        })?;
        ::core::result::Result::Ok(())
    }};
    ($map:expr, $key:literal, $value:tt) => {{
        $map.entry($key, |__enc| $crate::__cbor_bytes_into!(__enc, $value))?;
        ::core::result::Result::Ok(())
    }};
    ($map:expr, (($key:expr)), $value:tt) => {{
        let __k = $crate::__cbor_macro::IntoCborKey::into_cbor_key($key)?;
        $map.entry(__k.as_ref(), |__enc| {
            $crate::__cbor_bytes_into!(__enc, $value)
        })?;
        ::core::result::Result::Ok(())
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
        $crate::__cbor_macro::boxed_str_from_str(::core::stringify!($key))
    }};
    (($key:expr)) => {{
        $crate::__cbor_macro::IntoCborKey::into_cbor_key($key)
    }};
    ($key:literal) => {{
        // Intentionally requires a string literal type (`&'static str`).
        // Non-string literals will fail to type-check here.
        $crate::__cbor_macro::boxed_str_from_str($key)
    }};
}

/// Hidden support module used by `cbor!` expansions.
///
/// This is re-exported at crate root as `__cbor_macro` (see `lib.rs` change below).
#[doc(hidden)]
#[allow(missing_docs)]
pub mod __cbor_macro {
    use alloc::boxed::Box;
    use alloc::string::String;
    use core::convert::TryFrom;

    pub use alloc::vec::Vec;

    use crate::{
        BigInt, CborBytes, CborBytesRef, CborError, CborInteger, CborMap, CborValue, CborValueRef,
        Encoder, ErrorCode, F64Bits, MAX_SAFE_INTEGER, MAX_SAFE_INTEGER_I64, MIN_SAFE_INTEGER,
    };

    #[inline]
    const fn overflow() -> CborError {
        CborError::new(ErrorCode::LengthOverflow, 0)
    }

    pub fn try_reserve_exact<T>(v: &mut Vec<T>, additional: usize) -> Result<(), CborError> {
        crate::alloc_util::try_reserve_exact(v, additional, 0)
    }

    pub fn boxed_str_from_str(s: &str) -> Result<Box<str>, CborError> {
        crate::alloc_util::try_box_str_from_str(s, 0)
    }

    pub fn bytes_from_slice(b: &[u8]) -> Result<Vec<u8>, CborError> {
        crate::alloc_util::try_vec_from_slice(b, 0)
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
            return CborValue::int(i);
        }

        let magnitude = u128_to_min_be_bytes_nonzero(v)?;
        let big = BigInt::new(false, magnitude)?;
        Ok(CborValue::integer(CborInteger::from_bigint(big)))
    }

    fn int_from_i128(v: i128) -> Result<CborValue, CborError> {
        let min = i128::from(MIN_SAFE_INTEGER);
        let safe_max = i128::from(MAX_SAFE_INTEGER_I64);

        if v >= min && v <= safe_max {
            let i = i64::try_from(v).map_err(|_| overflow())?;
            return CborValue::int(i);
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
        Ok(CborValue::integer(CborInteger::from_bigint(big)))
    }

    pub trait IntoCborKey {
        fn into_cbor_key(self) -> Result<Box<str>, CborError>;
    }

    impl IntoCborKey for String {
        fn into_cbor_key(self) -> Result<Box<str>, CborError> {
            Ok(self.into_boxed_str())
        }
    }

    impl IntoCborKey for &String {
        fn into_cbor_key(self) -> Result<Box<str>, CborError> {
            boxed_str_from_str(self.as_str())
        }
    }

    impl IntoCborKey for &str {
        fn into_cbor_key(self) -> Result<Box<str>, CborError> {
            boxed_str_from_str(self)
        }
    }

    impl IntoCborKey for char {
        fn into_cbor_key(self) -> Result<Box<str>, CborError> {
            let mut out = String::new();
            crate::alloc_util::try_reserve_exact_str(&mut out, 4, 0)?;
            out.push(self);
            Ok(out.into_boxed_str())
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
            Ok(CborValue::map(self))
        }
    }

    impl IntoCborValue for &CborMap {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::map(self.clone()))
        }
    }

    impl IntoCborValue for BigInt {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::integer(CborInteger::from_bigint(self)))
        }
    }

    impl IntoCborValue for &BigInt {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::integer(CborInteger::from_bigint(self.clone())))
        }
    }

    impl IntoCborValue for F64Bits {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::float(self))
        }
    }

    impl IntoCborValue for bool {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::bool(self))
        }
    }

    impl IntoCborValue for () {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::null())
        }
    }

    impl<T: IntoCborValue> IntoCborValue for Option<T> {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            self.map_or(Ok(CborValue::null()), IntoCborValue::into_cbor_value)
        }
    }

    impl IntoCborValue for String {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::text(self))
        }
    }

    impl IntoCborValue for &String {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            let boxed = boxed_str_from_str(self.as_str())?;
            Ok(CborValue::text(boxed))
        }
    }

    impl IntoCborValue for &str {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            let boxed = boxed_str_from_str(self)?;
            Ok(CborValue::text(boxed))
        }
    }

    impl IntoCborValue for Vec<u8> {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::bytes(self))
        }
    }

    impl IntoCborValue for &Vec<u8> {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::bytes(bytes_from_slice(self.as_slice())?))
        }
    }

    impl IntoCborValue for &[u8] {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::bytes(bytes_from_slice(self)?))
        }
    }

    impl<const N: usize> IntoCborValue for &[u8; N] {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::bytes(bytes_from_slice(&self[..])?))
        }
    }

    impl IntoCborValue for Vec<CborValue> {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::array(self))
        }
    }

    impl IntoCborValue for &[CborValue] {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            let mut out: Vec<CborValue> = Vec::new();
            crate::alloc_util::try_reserve_exact(&mut out, self.len(), 0)?;
            out.extend_from_slice(self);
            Ok(CborValue::array(out))
        }
    }

    impl IntoCborValue for f64 {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::float(F64Bits::try_from_f64(self)?))
        }
    }

    impl IntoCborValue for f32 {
        fn into_cbor_value(self) -> Result<CborValue, CborError> {
            Ok(CborValue::float(F64Bits::try_from_f64(f64::from(self))?))
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

    pub trait IntoCborBytes {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError>;
    }

    impl IntoCborBytes for CborValue {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.value(&self)
        }
    }

    impl IntoCborBytes for &CborValue {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.value(self)
        }
    }

    impl IntoCborBytes for CborBytesRef<'_> {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.raw_cbor(self)
        }
    }

    impl IntoCborBytes for &CborBytes {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.raw_cbor(CborBytesRef::new(self.as_bytes()))
        }
    }

    impl IntoCborBytes for CborValueRef<'_> {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.raw_value_ref(self)
        }
    }

    impl IntoCborBytes for bool {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.bool(self)
        }
    }

    impl IntoCborBytes for () {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.null()
        }
    }

    impl<T: IntoCborBytes> IntoCborBytes for Option<T> {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            match self {
                None => enc.null(),
                Some(v) => v.into_cbor_bytes(enc),
            }
        }
    }

    impl IntoCborBytes for String {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.text(self.as_str())
        }
    }

    impl IntoCborBytes for &String {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.text(self.as_str())
        }
    }

    impl IntoCborBytes for &str {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.text(self)
        }
    }

    impl IntoCborBytes for Vec<u8> {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.bytes(self.as_slice())
        }
    }

    impl IntoCborBytes for &Vec<u8> {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.bytes(self.as_slice())
        }
    }

    impl IntoCborBytes for &[u8] {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.bytes(self)
        }
    }

    impl<const N: usize> IntoCborBytes for &[u8; N] {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.bytes(&self[..])
        }
    }

    impl IntoCborBytes for F64Bits {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.float(self)
        }
    }

    impl IntoCborBytes for f64 {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.float(F64Bits::try_from_f64(self)?)
        }
    }

    impl IntoCborBytes for f32 {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.float(F64Bits::try_from_f64(f64::from(self))?)
        }
    }

    macro_rules! impl_into_int_signed_bytes {
        ($($t:ty),* $(,)?) => {$(
            impl IntoCborBytes for $t {
                fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
                    enc.int_i128(i128::from(self))
                }
            }
        )*};
    }

    macro_rules! impl_into_int_unsigned_bytes {
        ($($t:ty),* $(,)?) => {$(
            impl IntoCborBytes for $t {
                fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
                    enc.int_u128(u128::from(self))
                }
            }
        )*};
    }

    impl_into_int_signed_bytes!(i8, i16, i32, i64, i128);
    impl_into_int_unsigned_bytes!(u8, u16, u32, u64, u128);

    impl IntoCborBytes for isize {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.int_i128(i128::try_from(self).map_err(|_| overflow())?)
        }
    }

    impl IntoCborBytes for usize {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.int_u128(u128::try_from(self).map_err(|_| overflow())?)
        }
    }
}
