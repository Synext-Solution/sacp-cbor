use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;

use crate::value::BenchValue;

#[derive(Debug, Deserialize)]
struct AppendixEntry {
    cbor: String,
    #[allow(dead_code)]
    hex: Option<String>,
}

#[derive(Debug)]
pub struct Dataset {
    pub name: String,
    pub items: Vec<Vec<u8>>,
}

pub fn load_appendix_a(path: &Path) -> Result<Dataset, String> {
    let data = fs::read_to_string(path).map_err(|e| format!("read {path:?}: {e}"))?;
    let entries: Vec<AppendixEntry> = serde_json::from_str(&data)
        .map_err(|e| format!("parse {path:?}: {e}"))?;
    let mut items = Vec::with_capacity(entries.len());
    for entry in entries {
        let bytes = B64
            .decode(entry.cbor.as_bytes())
            .map_err(|e| format!("base64 decode failed: {e}"))?;
        items.push(bytes);
    }
    Ok(Dataset {
        name: "appendix_a".to_string(),
        items,
    })
}

pub fn synthetic_datasets() -> Vec<(String, BenchValue)> {
    vec![
        (
            "map_k16_i64".to_string(),
            BenchValue::synthetic_map(16, BenchValue::Int(7)),
        ),
        (
            "map_k64_i64".to_string(),
            BenchValue::synthetic_map(64, BenchValue::Int(7)),
        ),
        (
            "array_len256_bool".to_string(),
            BenchValue::synthetic_array(256, BenchValue::Bool(true)),
        ),
        (
            "array_len4096_bool".to_string(),
            BenchValue::synthetic_array(4096, BenchValue::Bool(true)),
        ),
    ]
}

pub fn dataset_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("datasets")
}
