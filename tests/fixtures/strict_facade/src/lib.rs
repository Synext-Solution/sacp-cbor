extern crate alloc;

pub mod codec {
    pub mod cbor {
        extern crate alloc;

        use alloc::string::String;
        use alloc::vec::Vec;

        pub use private_cbor::encode::ArrayEncoder;
        pub use private_cbor::{
            encode_with_to_canonical, ByteSink, CanonicalCbor, CanonicalCborRef, CborError,
            DecodeLimits, Decoder, EncodeResult, Encoder, ErrorCode, NoopWorkObserver,
            ValueEncoder, WorkObserver,
        };

        pub mod query {
            pub use private_cbor::query::{CborKind, CborValueRef};
        }

        pub trait CborEncode {
            fn encode<S: ByteSink, O: WorkObserver>(
                &self,
                enc: &mut ValueEncoder<'_, S, O>,
            ) -> EncodeResult<(), S>;

            fn encode_array_item<S: ByteSink, O: WorkObserver>(
                &self,
                array: &mut ArrayEncoder<'_, S, O>,
            ) -> EncodeResult<(), S> {
                array.encode_with(|enc| self.encode(enc))
            }
        }

        pub trait CborDecode<'de>: Sized {
            fn decode<const CHECKED: bool, O: WorkObserver>(
                decoder: &mut Decoder<'de, CHECKED, O>,
            ) -> Result<Self, CborError>;
        }

        macro_rules! passthrough {
            ($($ty:ty),* $(,)?) => {
                $(
                    impl CborEncode for $ty {
                        fn encode<S: ByteSink, O: WorkObserver>(
                            &self,
                            enc: &mut ValueEncoder<'_, S, O>,
                        ) -> EncodeResult<(), S> {
                            private_cbor::CborEncode::encode(self, enc)
                        }

                        fn encode_array_item<S: ByteSink, O: WorkObserver>(
                            &self,
                            array: &mut ArrayEncoder<'_, S, O>,
                        ) -> EncodeResult<(), S> {
                            array.encode_with(|enc| private_cbor::CborEncode::encode(self, enc))
                        }
                    }

                    impl<'de> CborDecode<'de> for $ty {
                        fn decode<const CHECKED: bool, O: WorkObserver>(
                            decoder: &mut Decoder<'de, CHECKED, O>,
                        ) -> Result<Self, CborError> {
                            private_cbor::CborDecode::decode(decoder)
                        }
                    }
                )*
            };
        }

        passthrough!((), bool, u8, u16, u32, u64, i8, i16, i32, i64, String);

        impl CborEncode for &str {
            fn encode<S: ByteSink, O: WorkObserver>(
                &self,
                enc: &mut ValueEncoder<'_, S, O>,
            ) -> EncodeResult<(), S> {
                private_cbor::CborEncode::encode(self, enc)
            }

            fn encode_array_item<S: ByteSink, O: WorkObserver>(
                &self,
                array: &mut ArrayEncoder<'_, S, O>,
            ) -> EncodeResult<(), S> {
                array.encode_with(|enc| private_cbor::CborEncode::encode(self, enc))
            }
        }

        impl<'de> CborDecode<'de> for &'de str {
            fn decode<const CHECKED: bool, O: WorkObserver>(
                decoder: &mut Decoder<'de, CHECKED, O>,
            ) -> Result<Self, CborError> {
                private_cbor::CborDecode::decode(decoder)
            }
        }

        impl CborEncode for CanonicalCbor {
            fn encode<S: ByteSink, O: WorkObserver>(
                &self,
                enc: &mut ValueEncoder<'_, S, O>,
            ) -> EncodeResult<(), S> {
                private_cbor::CborEncode::encode(self, enc)
            }

            fn encode_array_item<S: ByteSink, O: WorkObserver>(
                &self,
                array: &mut ArrayEncoder<'_, S, O>,
            ) -> EncodeResult<(), S> {
                array.encode_with(|enc| private_cbor::CborEncode::encode(self, enc))
            }
        }

        impl CborEncode for CanonicalCborRef<'_> {
            fn encode<S: ByteSink, O: WorkObserver>(
                &self,
                enc: &mut ValueEncoder<'_, S, O>,
            ) -> EncodeResult<(), S> {
                private_cbor::CborEncode::encode(self, enc)
            }

            fn encode_array_item<S: ByteSink, O: WorkObserver>(
                &self,
                array: &mut ArrayEncoder<'_, S, O>,
            ) -> EncodeResult<(), S> {
                array.encode_with(|enc| private_cbor::CborEncode::encode(self, enc))
            }
        }

        impl<'de> CborDecode<'de> for CanonicalCbor {
            fn decode<const CHECKED: bool, O: WorkObserver>(
                decoder: &mut Decoder<'de, CHECKED, O>,
            ) -> Result<Self, CborError> {
                private_cbor::CborDecode::decode(decoder)
            }
        }

        impl<'de> CborDecode<'de> for CanonicalCborRef<'de> {
            fn decode<const CHECKED: bool, O: WorkObserver>(
                decoder: &mut Decoder<'de, CHECKED, O>,
            ) -> Result<Self, CborError> {
                private_cbor::CborDecode::decode(decoder)
            }
        }

        impl CborEncode for query::CborValueRef<'_> {
            fn encode<S: ByteSink, O: WorkObserver>(
                &self,
                enc: &mut ValueEncoder<'_, S, O>,
            ) -> EncodeResult<(), S> {
                private_cbor::CborEncode::encode(self, enc)
            }

            fn encode_array_item<S: ByteSink, O: WorkObserver>(
                &self,
                array: &mut ArrayEncoder<'_, S, O>,
            ) -> EncodeResult<(), S> {
                array.encode_with(|enc| private_cbor::CborEncode::encode(self, enc))
            }
        }

        impl<'de> CborDecode<'de> for query::CborValueRef<'de> {
            fn decode<const CHECKED: bool, O: WorkObserver>(
                decoder: &mut Decoder<'de, CHECKED, O>,
            ) -> Result<Self, CborError> {
                private_cbor::CborDecode::decode(decoder)
            }
        }

        impl<T: CborEncode> CborEncode for Option<T> {
            fn encode<S: ByteSink, O: WorkObserver>(
                &self,
                enc: &mut ValueEncoder<'_, S, O>,
            ) -> EncodeResult<(), S> {
                enc.map(1, |map| match self {
                    None => map.entry("none", Encoder::null),
                    Some(value) => map.entry("some", |enc| {
                        enc.encode_with(|value_enc| CborEncode::encode(value, value_enc))
                    }),
                })
            }

            fn encode_array_item<S: ByteSink, O: WorkObserver>(
                &self,
                array: &mut ArrayEncoder<'_, S, O>,
            ) -> EncodeResult<(), S> {
                array.encode_with(|enc| self.encode(enc))
            }
        }

        impl<'de, T: CborDecode<'de>> CborDecode<'de> for Option<T> {
            fn decode<const CHECKED: bool, O: WorkObserver>(
                decoder: &mut Decoder<'de, CHECKED, O>,
            ) -> Result<Self, CborError> {
                let map_off = decoder.position();
                let mut map = decoder.map()?;
                if map.remaining() != 1 {
                    return Err(CborError::new(ErrorCode::MapLenMismatch, map_off));
                }
                let Some(key) = map.next_key_ref()? else {
                    return Err(CborError::new(ErrorCode::MapLenMismatch, map_off));
                };
                match key.text {
                    "none" => {
                        let _: () = map.decode_value(CborDecode::decode)?;
                        Ok(None)
                    }
                    "some" => map.decode_value(CborDecode::decode).map(Some),
                    _ => Err(CborError::new(ErrorCode::UnknownEnumVariant, key.offset)),
                }
            }
        }

        impl<T: CborEncode> CborEncode for Vec<T> {
            fn encode<S: ByteSink, O: WorkObserver>(
                &self,
                enc: &mut ValueEncoder<'_, S, O>,
            ) -> EncodeResult<(), S> {
                enc.array(self.len(), |array| {
                    for value in self {
                        CborEncode::encode_array_item(value, array)?;
                    }
                    Ok(())
                })
            }

            fn encode_array_item<S: ByteSink, O: WorkObserver>(
                &self,
                array: &mut ArrayEncoder<'_, S, O>,
            ) -> EncodeResult<(), S> {
                array.encode_with(|enc| self.encode(enc))
            }
        }

        impl<'de, T: CborDecode<'de>> CborDecode<'de> for Vec<T> {
            fn decode<const CHECKED: bool, O: WorkObserver>(
                decoder: &mut Decoder<'de, CHECKED, O>,
            ) -> Result<Self, CborError> {
                let mut array = decoder.array()?;
                let mut out = Vec::new();
                while let Some(value) = array.decode_next(CborDecode::decode)? {
                    out.push(value);
                }
                Ok(out)
            }
        }

        pub fn encode_to_vec<T: CborEncode>(value: &T) -> Result<Vec<u8>, CborError> {
            let mut enc = Encoder::new();
            enc.encode_with(|value_enc| CborEncode::encode(value, value_enc))
                .map_err(collapse)?;
            enc.finish().map_err(collapse)
        }

        fn collapse(error: private_cbor::EncodeError<CborError>) -> CborError {
            match error {
                private_cbor::EncodeError::Cbor(error) | private_cbor::EncodeError::Sink(error) => {
                    error
                }
                private_cbor::EncodeError::Poisoned => {
                    CborError::new(ErrorCode::EncoderPoisoned, 0)
                }
            }
        }

        pub fn decode<'de, T: CborDecode<'de>>(
            bytes: &'de [u8],
            limits: DecodeLimits,
        ) -> Result<T, CborError> {
            let mut decoder = Decoder::<true>::new_checked(bytes, limits)?;
            let value = CborDecode::decode(&mut decoder)?;
            if decoder.position() != bytes.len() {
                return Err(CborError::new(ErrorCode::TrailingBytes, decoder.position()));
            }
            Ok(value)
        }
    }
}

use alloc::string::String;
#[cfg(test)]
use alloc::vec;
#[cfg(test)]
use codec::cbor::{CborDecode, CborEncode};

#[derive(Debug, Clone, PartialEq, Eq, private_cbor::CborEncode, private_cbor::CborDecode)]
#[cbor(crate = crate::codec::cbor)]
pub struct Nested {
    id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, private_cbor::CborEncode, private_cbor::CborDecode)]
#[cbor(crate = crate::codec::cbor)]
pub struct Named {
    nested: Nested,
    values: Vec<Nested>,
    optional: Option<u64>,
    payload: codec::cbor::CanonicalCbor,
}

#[derive(Debug, Clone, PartialEq, Eq, private_cbor::CborEncode, private_cbor::CborDecode)]
#[cbor(crate = crate::codec::cbor)]
pub struct Tuple(pub Nested, pub u64);

#[derive(Debug, Clone, PartialEq, Eq, private_cbor::CborEncode, private_cbor::CborDecode)]
#[cbor(crate = crate::codec::cbor)]
pub enum External {
    Unit,
    One(Nested),
    Pair(Nested, u64),
    Named { nested: Nested },
}

#[derive(Debug, Clone, PartialEq, Eq, private_cbor::CborEncode, private_cbor::CborDecode)]
#[cbor(crate = crate::codec::cbor, tag = "kind")]
#[cbor(rename_all = "snake_case")]
pub enum Internal {
    Ready { label: String, nested: Nested },
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq, private_cbor::CborEncode, private_cbor::CborDecode)]
#[cbor(crate = crate::codec::cbor, tag = "kind", content = "data")]
pub enum Adjacent {
    Unit,
    One(Nested),
    Pair(Nested, u64),
    Named { nested: Nested },
}

#[cfg(test)]
fn roundtrip<T>(value: T) -> T
where
    T: core::fmt::Debug + PartialEq + for<'de> CborDecode<'de> + CborEncode,
{
    let bytes = codec::cbor::encode_to_vec(&value).unwrap();
    codec::cbor::decode(&bytes, codec::cbor::DecodeLimits::for_bytes(bytes.len())).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nested(id: u64) -> Nested {
        Nested { id }
    }

    #[test]
    fn strict_facade_roundtrips_nested_shapes() {
        let payload =
            private_cbor::cbor_bytes!(crate = crate::codec::cbor; [nested(9), 3]).unwrap();
        let value = Named {
            nested: nested(1),
            values: vec![nested(2), nested(3)],
            optional: Some(7),
            payload,
        };
        assert_eq!(roundtrip(value.clone()), value);
        assert_eq!(roundtrip(Tuple(nested(5), 8)), Tuple(nested(5), 8));
    }

    #[test]
    fn strict_facade_roundtrips_external_enums() {
        assert_eq!(roundtrip(External::Unit), External::Unit);
        assert_eq!(
            roundtrip(External::One(nested(1))),
            External::One(nested(1))
        );
        assert_eq!(
            roundtrip(External::Pair(nested(2), 4)),
            External::Pair(nested(2), 4)
        );
        assert_eq!(
            roundtrip(External::Named { nested: nested(3) }),
            External::Named { nested: nested(3) }
        );
    }

    #[test]
    fn strict_facade_roundtrips_tagged_enums() {
        assert_eq!(
            roundtrip(Internal::Ready {
                label: String::from("ready"),
                nested: nested(7),
            }),
            Internal::Ready {
                label: String::from("ready"),
                nested: nested(7),
            }
        );
        assert_eq!(roundtrip(Internal::Done), Internal::Done);
        assert_eq!(roundtrip(Adjacent::Unit), Adjacent::Unit);
        assert_eq!(
            roundtrip(Adjacent::One(nested(8))),
            Adjacent::One(nested(8))
        );
        assert_eq!(
            roundtrip(Adjacent::Pair(nested(9), 10)),
            Adjacent::Pair(nested(9), 10)
        );
        assert_eq!(
            roundtrip(Adjacent::Named { nested: nested(11) }),
            Adjacent::Named { nested: nested(11) }
        );
    }
}
