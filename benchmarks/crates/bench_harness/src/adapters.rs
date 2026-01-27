use crate::value::BenchValue;
use serde::de::IgnoredAny;

pub struct BenchInput<'a> {
    pub bytes: &'a [u8],
    pub sacp_canon: Option<sacp_cbor::CborBytesRef<'a>>,
}

#[cfg(feature = "adapter-cbor4ii")]
use cbor4ii::core::Value as Cbor4iiValue;

pub trait Adapter {
    fn name(&self) -> &'static str;
    fn validate(&self, bytes: &[u8]) -> Result<(), String>;
    fn decode_discard(&self, bytes: &[u8]) -> Result<(), String>;
    fn decode_discard_trusted(&self, input: &BenchInput<'_>) -> Result<(), String> {
        self.decode_discard(input.bytes)
    }
    fn encode(&self, value: &BenchValue) -> Result<Vec<u8>, String>;
    fn serde_roundtrip(&self, value: &BenchValue) -> Result<(), String>;
}

pub struct SacpCbor;

impl Adapter for SacpCbor {
    fn name(&self) -> &'static str {
        "sacp-cbor"
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), String> {
        sacp_cbor::validate(bytes, sacp_cbor::DecodeLimits::for_bytes(bytes.len()))
            .map_err(|e| format!("{e}"))
    }

    fn decode_discard(&self, bytes: &[u8]) -> Result<(), String> {
        let _: IgnoredAny =
            sacp_cbor::from_slice(bytes, sacp_cbor::DecodeLimits::for_bytes(bytes.len()))
                .map_err(|e| format!("{e}"))?;
        Ok(())
    }

    fn decode_discard_trusted(&self, input: &BenchInput<'_>) -> Result<(), String> {
        let canon = input
            .sacp_canon
            .ok_or_else(|| "missing canonical bytes".to_string())?;
        let _: IgnoredAny = sacp_cbor::from_canonical_bytes_ref(canon)
            .map_err(|e| format!("{e}"))?;
        Ok(())
    }

    fn encode(&self, value: &BenchValue) -> Result<Vec<u8>, String> {
        encode_sacp_stream(value)
    }

    fn serde_roundtrip(&self, value: &BenchValue) -> Result<(), String> {
        let bytes = sacp_cbor::to_vec(value).map_err(|e| format!("{e}"))?;
        let _out: BenchValue = sacp_cbor::from_slice(
            &bytes,
            sacp_cbor::DecodeLimits::for_bytes(bytes.len()),
        )
        .map_err(|e| format!("{e}"))?;
        Ok(())
    }
}

#[cfg(feature = "adapter-serde_cbor")]
pub struct SerdeCbor;

#[cfg(feature = "adapter-serde_cbor")]
impl Adapter for SerdeCbor {
    fn name(&self) -> &'static str {
        "serde_cbor"
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), String> {
        let _: serde_cbor::Value = serde_cbor::from_slice(bytes).map_err(|e| format!("{e}"))?;
        Ok(())
    }

    fn decode_discard(&self, bytes: &[u8]) -> Result<(), String> {
        let _: serde_cbor::Value = serde_cbor::from_slice(bytes).map_err(|e| format!("{e}"))?;
        Ok(())
    }

    fn encode(&self, value: &BenchValue) -> Result<Vec<u8>, String> {
        let v = to_serde_cbor_value(value);
        serde_cbor::to_vec(&v).map_err(|e| format!("{e}"))
    }

    fn serde_roundtrip(&self, value: &BenchValue) -> Result<(), String> {
        let bytes = serde_cbor::to_vec(value).map_err(|e| format!("{e}"))?;
        let _out: BenchValue = serde_cbor::from_slice(&bytes).map_err(|e| format!("{e}"))?;
        Ok(())
    }
}

#[cfg(feature = "adapter-ciborium")]
pub struct Ciborium;

#[cfg(feature = "adapter-ciborium")]
impl Adapter for Ciborium {
    fn name(&self) -> &'static str {
        "ciborium"
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), String> {
        let mut slice = bytes;
        let _: ciborium::value::Value =
            ciborium::de::from_reader(&mut slice).map_err(|e| format!("{e}"))?;
        Ok(())
    }

    fn decode_discard(&self, bytes: &[u8]) -> Result<(), String> {
        let mut slice = bytes;
        let _: ciborium::value::Value =
            ciborium::de::from_reader(&mut slice).map_err(|e| format!("{e}"))?;
        Ok(())
    }

    fn encode(&self, value: &BenchValue) -> Result<Vec<u8>, String> {
        let v = to_ciborium_value(value);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&v, &mut out).map_err(|e| format!("{e}"))?;
        Ok(out)
    }

    fn serde_roundtrip(&self, value: &BenchValue) -> Result<(), String> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(value, &mut out).map_err(|e| format!("{e}"))?;
        let mut slice = out.as_slice();
        let _out: BenchValue = ciborium::de::from_reader(&mut slice).map_err(|e| format!("{e}"))?;
        Ok(())
    }
}

#[cfg(feature = "adapter-minicbor")]
pub struct Minicbor;

#[cfg(feature = "adapter-minicbor")]
impl Adapter for Minicbor {
    fn name(&self) -> &'static str {
        "minicbor"
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), String> {
        let _: BenchValue = minicbor::decode(bytes).map_err(|e| format!("{e}"))?;
        Ok(())
    }

    fn decode_discard(&self, bytes: &[u8]) -> Result<(), String> {
        let _: BenchValue = minicbor::decode(bytes).map_err(|e| format!("{e}"))?;
        Ok(())
    }

    fn encode(&self, value: &BenchValue) -> Result<Vec<u8>, String> {
        minicbor::to_vec(value).map_err(|e| format!("{e}"))
    }

    fn serde_roundtrip(&self, value: &BenchValue) -> Result<(), String> {
        let bytes = minicbor::to_vec(value).map_err(|e| format!("{e}"))?;
        let _out: BenchValue = minicbor::decode(&bytes).map_err(|e| format!("{e}"))?;
        Ok(())
    }
}

#[cfg(feature = "adapter-cbor4ii")]
pub struct Cbor4ii;

#[cfg(feature = "adapter-cbor4ii")]
impl Adapter for Cbor4ii {
    fn name(&self) -> &'static str {
        "cbor4ii"
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), String> {
        let _out: Cbor4iiValue =
            cbor4ii::serde::from_slice(bytes).map_err(|e| format!("{e}"))?;
        Ok(())
    }

    fn decode_discard(&self, bytes: &[u8]) -> Result<(), String> {
        let _out: Cbor4iiValue =
            cbor4ii::serde::from_slice(bytes).map_err(|e| format!("{e}"))?;
        Ok(())
    }

    fn encode(&self, value: &BenchValue) -> Result<Vec<u8>, String> {
        let v = to_cbor4ii_value(value);
        cbor4ii::serde::to_vec(Vec::new(), &v).map_err(|e| format!("{e}"))
    }

    fn serde_roundtrip(&self, value: &BenchValue) -> Result<(), String> {
        let v = to_cbor4ii_value(value);
        let bytes = cbor4ii::serde::to_vec(Vec::new(), &v).map_err(|e| format!("{e}"))?;
        let _out: Cbor4iiValue =
            cbor4ii::serde::from_slice(&bytes).map_err(|e| format!("{e}"))?;
        Ok(())
    }
}

#[cfg(feature = "adapter-serde_cbor")]
fn to_serde_cbor_value(v: &BenchValue) -> serde_cbor::Value {
    match v {
        BenchValue::Null => serde_cbor::Value::Null,
        BenchValue::Bool(b) => serde_cbor::Value::Bool(*b),
        BenchValue::Int(i) => serde_cbor::Value::Integer(i128::from(*i)),
        BenchValue::Bytes(b) => serde_cbor::Value::Bytes(b.clone()),
        BenchValue::Text(s) => serde_cbor::Value::Text(s.clone()),
        BenchValue::Array(items) => {
            serde_cbor::Value::Array(items.iter().map(to_serde_cbor_value).collect())
        }
        BenchValue::Map(entries) => serde_cbor::Value::Map(
            entries
                .iter()
                .map(|(k, v)| (serde_cbor::Value::Text(k.clone()), to_serde_cbor_value(v)))
                .collect(),
        ),
    }
}

#[cfg(feature = "adapter-ciborium")]
fn to_ciborium_value(v: &BenchValue) -> ciborium::value::Value {
    match v {
        BenchValue::Null => ciborium::value::Value::Null,
        BenchValue::Bool(b) => ciborium::value::Value::Bool(*b),
        BenchValue::Int(i) => ciborium::value::Value::Integer((*i).into()),
        BenchValue::Bytes(b) => ciborium::value::Value::Bytes(b.clone()),
        BenchValue::Text(s) => ciborium::value::Value::Text(s.clone()),
        BenchValue::Array(items) => {
            ciborium::value::Value::Array(items.iter().map(to_ciborium_value).collect())
        }
        BenchValue::Map(entries) => ciborium::value::Value::Map(
            entries
                .iter()
                .map(|(k, v)| (ciborium::value::Value::Text(k.clone()), to_ciborium_value(v)))
                .collect(),
        ),
    }
}

#[cfg(feature = "adapter-cbor4ii")]
fn to_cbor4ii_value(v: &BenchValue) -> Cbor4iiValue {
    match v {
        BenchValue::Null => Cbor4iiValue::Null,
        BenchValue::Bool(b) => Cbor4iiValue::Bool(*b),
        BenchValue::Int(i) => Cbor4iiValue::Integer(i128::from(*i)),
        BenchValue::Bytes(b) => Cbor4iiValue::Bytes(b.clone()),
        BenchValue::Text(s) => Cbor4iiValue::Text(s.clone()),
        BenchValue::Array(items) => {
            Cbor4iiValue::Array(items.iter().map(to_cbor4ii_value).collect())
        }
        BenchValue::Map(entries) => Cbor4iiValue::Map(
            entries
                .iter()
                .map(|(k, v)| (Cbor4iiValue::Text(k.clone()), to_cbor4ii_value(v)))
                .collect(),
        ),
    }
}

pub fn encode_sacp_stream(value: &BenchValue) -> Result<Vec<u8>, String> {
    let mut enc = sacp_cbor::Encoder::new();
    encode_bench_value(&mut enc, value).map_err(|e| format!("{e}"))?;
    Ok(enc.into_vec())
}

fn encode_bench_value(
    enc: &mut sacp_cbor::Encoder,
    v: &BenchValue,
) -> Result<(), sacp_cbor::CborError> {
    match v {
        BenchValue::Null => enc.null(),
        BenchValue::Bool(b) => enc.bool(*b),
        BenchValue::Int(i) => enc.int(*i),
        BenchValue::Bytes(b) => enc.bytes(b),
        BenchValue::Text(s) => enc.text(s),
        BenchValue::Array(items) => enc.array(items.len(), |a| encode_bench_array(a, items)),
        BenchValue::Map(entries) => enc.map(entries.len(), |m| {
            for (k, v) in entries {
                m.entry(k.as_str(), |enc| encode_bench_value(enc, v))?;
            }
            Ok(())
        }),
    }
}

fn encode_bench_array(
    a: &mut sacp_cbor::ArrayEncoder<'_>,
    items: &[BenchValue],
) -> Result<(), sacp_cbor::CborError> {
    for item in items {
        encode_bench_value_in_array(a, item)?;
    }
    Ok(())
}

fn encode_bench_value_in_array(
    a: &mut sacp_cbor::ArrayEncoder<'_>,
    v: &BenchValue,
) -> Result<(), sacp_cbor::CborError> {
    match v {
        BenchValue::Null => a.null(),
        BenchValue::Bool(b) => a.bool(*b),
        BenchValue::Int(i) => a.int(*i),
        BenchValue::Bytes(b) => a.bytes(b),
        BenchValue::Text(s) => a.text(s),
        BenchValue::Array(items) => a.array(items.len(), |inner| encode_bench_array(inner, items)),
        BenchValue::Map(entries) => a.map(entries.len(), |m| {
            for (k, v) in entries {
                m.entry(k.as_str(), |enc| encode_bench_value(enc, v))?;
            }
            Ok(())
        }),
    }
}

// (owned value encoding removed)
