use crate::value::BenchValue;
use serde::de::IgnoredAny;

pub struct BenchInput<'a> {
    pub bytes: &'a [u8],
    pub sacp_canon: Option<sacp_cbor::CanonicalCborRef<'a>>,
}

pub trait Adapter {
    fn name(&self) -> &'static str;

    fn decode_ignored(&self, bytes: &[u8]) -> Result<(), String>;

    fn decode_bench_value(&self, bytes: &[u8]) -> Result<BenchValue, String>;

    fn encode_bench_value(&self, value: &BenchValue) -> Result<Vec<u8>, String>;

    fn roundtrip_bench_value(&self, value: &BenchValue) -> Result<(), String> {
        let bytes = self.encode_bench_value(value)?;
        let _ = self.decode_bench_value(&bytes)?;
        Ok(())
    }

    fn validate_only(&self, _bytes: &[u8]) -> Option<Result<(), String>> {
        None
    }

    fn decode_ignored_trusted(&self, _input: &BenchInput<'_>) -> Option<Result<(), String>> {
        None
    }
}

pub struct SacpCbor;

impl Adapter for SacpCbor {
    fn name(&self) -> &'static str {
        "sacp-cbor"
    }

    fn decode_ignored(&self, bytes: &[u8]) -> Result<(), String> {
        let _: IgnoredAny =
            sacp_cbor::from_slice(bytes, sacp_cbor::DecodeLimits::for_bytes(bytes.len()))
                .map_err(|e| format!("{e}"))?;
        Ok(())
    }

    fn decode_bench_value(&self, bytes: &[u8]) -> Result<BenchValue, String> {
        sacp_cbor::from_slice(bytes, sacp_cbor::DecodeLimits::for_bytes(bytes.len()))
            .map_err(|e| format!("{e}"))
    }

    fn encode_bench_value(&self, value: &BenchValue) -> Result<Vec<u8>, String> {
        sacp_cbor::to_vec(value).map_err(|e| format!("{e}"))
    }

    fn validate_only(&self, bytes: &[u8]) -> Option<Result<(), String>> {
        Some(
            sacp_cbor::validate(bytes, sacp_cbor::DecodeLimits::for_bytes(bytes.len()))
                .map_err(|e| format!("{e}")),
        )
    }

    fn decode_ignored_trusted(&self, input: &BenchInput<'_>) -> Option<Result<(), String>> {
        let canon = match input.sacp_canon {
            Some(c) => c,
            None => return Some(Err("missing canonical bytes".to_string())),
        };
        Some(
            sacp_cbor::from_canonical_bytes_ref::<IgnoredAny>(canon)
                .map(|_| ())
                .map_err(|e| format!("{e}")),
        )
    }
}

#[cfg(feature = "adapter-serde_cbor")]
pub struct SerdeCbor;

#[cfg(feature = "adapter-serde_cbor")]
impl Adapter for SerdeCbor {
    fn name(&self) -> &'static str {
        "serde_cbor"
    }

    fn decode_ignored(&self, bytes: &[u8]) -> Result<(), String> {
        let _: IgnoredAny = serde_cbor::from_slice(bytes).map_err(|e| format!("{e}"))?;
        Ok(())
    }

    fn decode_bench_value(&self, bytes: &[u8]) -> Result<BenchValue, String> {
        serde_cbor::from_slice(bytes).map_err(|e| format!("{e}"))
    }

    fn encode_bench_value(&self, value: &BenchValue) -> Result<Vec<u8>, String> {
        serde_cbor::to_vec(value).map_err(|e| format!("{e}"))
    }
}

#[cfg(feature = "adapter-ciborium")]
pub struct Ciborium;

#[cfg(feature = "adapter-ciborium")]
impl Adapter for Ciborium {
    fn name(&self) -> &'static str {
        "ciborium"
    }

    fn decode_ignored(&self, bytes: &[u8]) -> Result<(), String> {
        let mut slice = bytes;
        let _: IgnoredAny = ciborium::de::from_reader(&mut slice).map_err(|e| format!("{e}"))?;
        if !slice.is_empty() {
            return Err(format!("trailing {} bytes", slice.len()));
        }
        Ok(())
    }

    fn decode_bench_value(&self, bytes: &[u8]) -> Result<BenchValue, String> {
        let mut slice = bytes;
        let v: BenchValue = ciborium::de::from_reader(&mut slice).map_err(|e| format!("{e}"))?;
        if !slice.is_empty() {
            return Err(format!("trailing {} bytes", slice.len()));
        }
        Ok(v)
    }

    fn encode_bench_value(&self, value: &BenchValue) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(value, &mut out).map_err(|e| format!("{e}"))?;
        Ok(out)
    }
}

#[cfg(feature = "adapter-minicbor")]
pub struct Minicbor;

#[cfg(feature = "adapter-minicbor")]
impl Adapter for Minicbor {
    fn name(&self) -> &'static str {
        "minicbor"
    }

    fn decode_ignored(&self, bytes: &[u8]) -> Result<(), String> {
        let mut d = minicbor::decode::Decoder::new(bytes);
        d.skip().map_err(|e| format!("{e}"))?;
        if d.position() != bytes.len() {
            return Err(format!("trailing {} bytes", bytes.len() - d.position()));
        }
        Ok(())
    }

    fn decode_bench_value(&self, bytes: &[u8]) -> Result<BenchValue, String> {
        minicbor::decode(bytes).map_err(|e| format!("{e}"))
    }

    fn encode_bench_value(&self, value: &BenchValue) -> Result<Vec<u8>, String> {
        minicbor::to_vec(value).map_err(|e| format!("{e}"))
    }
}

#[cfg(feature = "adapter-cbor4ii")]
pub struct Cbor4ii;

#[cfg(feature = "adapter-cbor4ii")]
impl Adapter for Cbor4ii {
    fn name(&self) -> &'static str {
        "cbor4ii"
    }

    fn decode_ignored(&self, bytes: &[u8]) -> Result<(), String> {
        let _: IgnoredAny = cbor4ii::serde::from_slice(bytes).map_err(|e| format!("{e}"))?;
        Ok(())
    }

    fn decode_bench_value(&self, bytes: &[u8]) -> Result<BenchValue, String> {
        cbor4ii::serde::from_slice(bytes).map_err(|e| format!("{e}"))
    }

    fn encode_bench_value(&self, value: &BenchValue) -> Result<Vec<u8>, String> {
        cbor4ii::serde::to_vec(Vec::new(), value).map_err(|e| format!("{e}"))
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
