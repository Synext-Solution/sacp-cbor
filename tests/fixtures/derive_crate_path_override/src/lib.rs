pub mod codec {
    pub mod cbor {
        pub use private_cbor::{
            ByteSink, CborDecode, CborEncode, CborError, DecodeLimits, Decoder, EncodeResult,
            Encoder, ErrorCode, ValueEncoder, encode_with_to_canonical,
        };

        pub mod query {
            pub use private_cbor::query::{CborKind, CborValueRef};
        }
    }
}

use codec::cbor::{CborDecode, CborEncode};

#[derive(Debug, PartialEq, Eq, CborEncode, CborDecode)]
#[cbor(crate = crate::codec::cbor)]
pub struct BorrowedGeneric<'a, T> {
    pub name: &'a str,
    pub value: T,
}

#[derive(Debug, PartialEq, Eq, CborEncode, CborDecode)]
#[cbor(crate = crate::codec::cbor)]
pub struct TupleGeneric<T>(pub T, pub u64);

#[derive(Debug, PartialEq, Eq, CborEncode, CborDecode)]
#[cbor(crate = crate::codec::cbor)]
pub struct Unit;

#[derive(Debug, PartialEq, Eq, CborEncode, CborDecode)]
#[cbor(crate = crate::codec::cbor)]
pub enum External<T> {
    Newtype(T),
    Pair(u64, bool),
    Named { value: T },
}

#[derive(Debug, PartialEq, Eq, CborEncode, CborDecode)]
#[cbor(crate = crate::codec::cbor, tag = "kind")]
#[cbor(rename_all = "snake_case")]
pub enum Internal<'a, T> {
    Ready { name: &'a str, value: T },
    Done,
}

#[derive(Debug, PartialEq, Eq, CborEncode, CborDecode)]
#[cbor(crate = crate::codec::cbor, tag = "kind", content = "data")]
pub enum Adjacent<'a> {
    Unit,
    One(&'a str),
    Pair(u64, bool),
    Named { name: &'a str, ok: bool },
}

#[cfg(test)]
fn roundtrip<T>(value: T) -> T
where
    T: core::fmt::Debug + PartialEq + for<'de> CborDecode<'de> + CborEncode,
{
    let bytes = private_cbor::encode_to_vec(&value).unwrap();
    private_cbor::decode(&bytes, private_cbor::DecodeLimits::for_bytes(bytes.len())).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_path_override_roundtrips_struct_shapes() {
        let value = BorrowedGeneric {
            name: "ana",
            value: 7u64,
        };
        let bytes = private_cbor::encode_to_vec(&value).unwrap();
        let decoded: BorrowedGeneric<'_, u64> =
            private_cbor::decode(&bytes, private_cbor::DecodeLimits::for_bytes(bytes.len()))
                .unwrap();
        assert_eq!(decoded, value);

        assert_eq!(roundtrip(TupleGeneric(9u64, 3)), TupleGeneric(9, 3));
        assert_eq!(roundtrip(Unit), Unit);
    }

    #[test]
    fn crate_path_override_roundtrips_external_enums() {
        assert_eq!(roundtrip(External::Newtype(7u64)), External::Newtype(7));
        assert_eq!(roundtrip(External::<u64>::Pair(3, true)), External::Pair(3, true));
        assert_eq!(
            roundtrip(External::Named { value: 11u64 }),
            External::Named { value: 11 }
        );
    }

    #[test]
    fn crate_path_override_roundtrips_internal_enums() {
        let value = Internal::Ready {
            name: "bor",
            value: 5u64,
        };
        let bytes = private_cbor::encode_to_vec(&value).unwrap();
        let decoded: Internal<'_, u64> =
            private_cbor::decode(&bytes, private_cbor::DecodeLimits::for_bytes(bytes.len()))
                .unwrap();
        assert_eq!(decoded, value);

        let done = Internal::<u64>::Done;
        let bytes = private_cbor::encode_to_vec(&done).unwrap();
        let decoded: Internal<'_, u64> =
            private_cbor::decode(&bytes, private_cbor::DecodeLimits::for_bytes(bytes.len()))
                .unwrap();
        assert_eq!(decoded, done);
    }

    #[test]
    fn crate_path_override_roundtrips_adjacent_enums() {
        let unit = Adjacent::Unit;
        let bytes = private_cbor::encode_to_vec(&unit).unwrap();
        let decoded: Adjacent<'_> =
            private_cbor::decode(&bytes, private_cbor::DecodeLimits::for_bytes(bytes.len()))
                .unwrap();
        assert_eq!(decoded, unit);

        let one = Adjacent::One("payload");
        let bytes = private_cbor::encode_to_vec(&one).unwrap();
        let decoded: Adjacent<'_> =
            private_cbor::decode(&bytes, private_cbor::DecodeLimits::for_bytes(bytes.len()))
                .unwrap();
        assert_eq!(decoded, one);

        let pair = Adjacent::Pair(13, false);
        let bytes = private_cbor::encode_to_vec(&pair).unwrap();
        let decoded: Adjacent<'_> =
            private_cbor::decode(&bytes, private_cbor::DecodeLimits::for_bytes(bytes.len()))
                .unwrap();
        assert_eq!(decoded, pair);

        let named = Adjacent::Named {
            name: "field",
            ok: true,
        };
        let bytes = private_cbor::encode_to_vec(&named).unwrap();
        let decoded: Adjacent<'_> =
            private_cbor::decode(&bytes, private_cbor::DecodeLimits::for_bytes(bytes.len()))
                .unwrap();
        assert_eq!(decoded, named);
    }
}
