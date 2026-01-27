use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
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
