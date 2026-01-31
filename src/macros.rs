//! Internal support for the `cbor_bytes!` macro.

/// Hidden support module used by `cbor_bytes!` expansions.
///
/// This is re-exported at crate root as `__cbor_macro` (see `lib.rs`).
#[doc(hidden)]
#[allow(missing_docs)]
pub mod __cbor_macro {
    use alloc::string::String;
    use alloc::vec::Vec;

    use crate::{CborBytes, CborBytesRef, CborError, CborValueRef, Encoder, F64Bits};

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

    impl IntoCborBytes for i64 {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.int(self)
        }
    }

    impl IntoCborBytes for i32 {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.int(i64::from(self))
        }
    }

    impl IntoCborBytes for i16 {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.int(i64::from(self))
        }
    }

    impl IntoCborBytes for i8 {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.int(i64::from(self))
        }
    }

    impl IntoCborBytes for isize {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            let v = i64::try_from(self)
                .map_err(|_| CborError::new(crate::ErrorCode::LengthOverflow, 0))?;
            enc.int(v)
        }
    }

    impl IntoCborBytes for i128 {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.int_i128(self)
        }
    }

    impl IntoCborBytes for u64 {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            if self <= crate::MAX_SAFE_INTEGER {
                let v = i64::try_from(self)
                    .map_err(|_| CborError::new(crate::ErrorCode::LengthOverflow, 0))?;
                enc.int(v)
            } else {
                enc.int_u128(u128::from(self))
            }
        }
    }

    impl IntoCborBytes for u32 {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.int(i64::from(self))
        }
    }

    impl IntoCborBytes for u16 {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.int(i64::from(self))
        }
    }

    impl IntoCborBytes for u8 {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.int(i64::from(self))
        }
    }

    impl IntoCborBytes for usize {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            let v = u64::try_from(self)
                .map_err(|_| CborError::new(crate::ErrorCode::LengthOverflow, 0))?;
            if v <= crate::MAX_SAFE_INTEGER {
                let v = i64::try_from(v)
                    .map_err(|_| CborError::new(crate::ErrorCode::LengthOverflow, 0))?;
                enc.int(v)
            } else {
                enc.int_u128(u128::from(v))
            }
        }
    }

    impl IntoCborBytes for u128 {
        fn into_cbor_bytes(self, enc: &mut Encoder) -> Result<(), CborError> {
            enc.int_u128(self)
        }
    }
}
