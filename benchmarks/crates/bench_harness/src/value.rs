use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize, Serializer};
use sacp_cbor::MapEntries;
use std::fmt;

#[derive(Clone, Debug)]
pub enum BenchValue {
    Null,
    Bool(bool),
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<BenchValue>),
    Map(Vec<(String, BenchValue)>),
}

impl BenchValue {
    pub fn synthetic_map(len: usize, value: BenchValue) -> Self {
        let mut entries = Vec::with_capacity(len);
        for i in 0..len {
            entries.push((format!("k{:04}", i), value.clone()));
        }
        BenchValue::Map(entries)
    }

    pub fn synthetic_array(len: usize, value: BenchValue) -> Self {
        let mut items = Vec::with_capacity(len);
        for _ in 0..len {
            items.push(value.clone());
        }
        BenchValue::Array(items)
    }
}

impl Serialize for BenchValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            BenchValue::Null => serializer.serialize_unit(),
            BenchValue::Bool(b) => serializer.serialize_bool(*b),
            BenchValue::Int(i) => serializer.serialize_i64(*i),
            BenchValue::Bytes(b) => serializer.serialize_bytes(b),
            BenchValue::Text(s) => serializer.serialize_str(s),
            BenchValue::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            BenchValue::Map(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (k, v) in entries {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for BenchValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BenchValueVisitor;

        impl<'de> Visitor<'de> for BenchValueVisitor {
            type Value = BenchValue;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a CBOR-like value")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(BenchValue::Null)
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(BenchValue::Bool(v))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(BenchValue::Int(v))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let i = i64::try_from(v).unwrap_or(i64::MAX);
                Ok(BenchValue::Int(i))
            }

            fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let i = i64::try_from(v).unwrap_or(i64::MIN);
                Ok(BenchValue::Int(i))
            }

            fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let i = i64::try_from(v).unwrap_or(i64::MAX);
                Ok(BenchValue::Int(i))
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(BenchValue::Bytes(v.to_vec()))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(BenchValue::Bytes(v.to_vec()))
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(BenchValue::Text(v.to_string()))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(BenchValue::Text(v.to_string()))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(item) = seq.next_element::<BenchValue>()? {
                    items.push(item);
                }
                Ok(BenchValue::Array(items))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut entries = Vec::with_capacity(map.size_hint().unwrap_or(0));
                while let Some((key, value)) = map.next_entry::<String, BenchValue>()? {
                    entries.push((key, value));
                }
                Ok(BenchValue::Map(entries))
            }

            fn visit_f64<E>(self, _v: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(BenchValue::Null)
            }
        }

        deserializer.deserialize_any(BenchValueVisitor)
    }
}

#[derive(Clone, Debug, sacp_cbor::CborEncode, sacp_cbor::CborDecode)]
#[cbor(untagged)]
pub enum BenchValueNative {
    Null,
    Bool(bool),
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<BenchValueNative>),
    Map(MapEntries<String, BenchValueNative>),
}

#[derive(Clone, Debug, sacp_cbor::CborEncode, sacp_cbor::CborDecode)]
#[cbor(untagged)]
pub enum BenchValueBorrowed<'a> {
    Null,
    Bool(bool),
    Int(i64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<BenchValueBorrowed<'a>>),
    Map(MapEntries<&'a str, BenchValueBorrowed<'a>>),
}

impl BenchValueNative {
    pub fn from_bench(value: &BenchValue) -> Self {
        match value {
            BenchValue::Null => Self::Null,
            BenchValue::Bool(v) => Self::Bool(*v),
            BenchValue::Int(v) => Self::Int(*v),
            BenchValue::Bytes(b) => Self::Bytes(b.clone()),
            BenchValue::Text(s) => Self::Text(s.clone()),
            BenchValue::Array(items) => {
                Self::Array(items.iter().map(Self::from_bench).collect())
            }
            BenchValue::Map(entries) => {
                let mapped = entries
                    .iter()
                    .map(|(k, v)| (k.clone(), Self::from_bench(v)))
                    .collect();
                Self::Map(MapEntries::new(mapped))
            }
        }
    }
}

impl<'a> BenchValueBorrowed<'a> {
    pub fn from_bench(value: &'a BenchValue) -> Self {
        match value {
            BenchValue::Null => Self::Null,
            BenchValue::Bool(v) => Self::Bool(*v),
            BenchValue::Int(v) => Self::Int(*v),
            BenchValue::Bytes(b) => Self::Bytes(b.as_slice()),
            BenchValue::Text(s) => Self::Text(s.as_str()),
            BenchValue::Array(items) => {
                Self::Array(items.iter().map(Self::from_bench).collect())
            }
            BenchValue::Map(entries) => {
                let mapped = entries
                    .iter()
                    .map(|(k, v)| (k.as_str(), Self::from_bench(v)))
                    .collect();
                Self::Map(MapEntries::new(mapped))
            }
        }
    }
}
