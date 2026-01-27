//! CBOR construction macros.
//!
//! This module provides [`cbor_bytes!`], a convenient macro to build canonical CBOR bytes directly.

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

/// Hidden support module used by `cbor_bytes!` expansions.
///
/// This is re-exported at crate root as `__cbor_macro` (see `lib.rs` change below).
#[doc(hidden)]
#[allow(missing_docs)]
pub mod __cbor_macro {
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::convert::TryFrom;

    use crate::{CborBytes, CborBytesRef, CborError, CborValueRef, Encoder, ErrorCode, F64Bits};

    #[inline]
    const fn overflow() -> CborError {
        CborError::new(ErrorCode::LengthOverflow, 0)
    }

    pub fn boxed_str_from_str(s: &str) -> Result<Box<str>, CborError> {
        crate::alloc_util::try_box_str_from_str(s, 0)
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

    pub trait IntoCborBytes {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError>;
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
