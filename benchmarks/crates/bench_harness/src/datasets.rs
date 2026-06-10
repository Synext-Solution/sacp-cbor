use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sacp_cbor::query::PathElem;
use serde::Deserialize;

use crate::query_edit::sort_map_entries;
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
    let entries: Vec<AppendixEntry> =
        serde_json::from_str(&data).map_err(|e| format!("parse {path:?}: {e}"))?;
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

pub fn dataset_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("datasets")
}

/// A realistic SACP message shape used across all pipeline scenarios.
///
/// Every workload root is a canonical map that contains at least:
/// - `"id"` (text) and `"seq"` (int), so the `patch` scenario can replace
///   `"seq"` uniformly across workloads, and
/// - the fields named by `inspect_paths`, which model the handful of routing /
///   dispatch fields a gateway reads from an incoming message in the `ingest`
///   scenario.
pub struct Workload {
    pub name: &'static str,
    pub value: BenchValue,
    pub inspect_paths: &'static [&'static [PathElem<'static>]],
}

/// Deterministic xorshift64* generator so workloads are identical across
/// runs and machines (no `rand` dependency, no fetched corpora).
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn hex(&mut self, chars: usize) -> String {
        const HEX: &[u8] = b"0123456789abcdef";
        let mut out = String::with_capacity(chars);
        for _ in 0..chars {
            out.push(HEX[self.below(16)] as char);
        }
        out
    }

    fn word(&mut self) -> &'static str {
        const WORDS: &[&str] = &[
            "agent", "buffer", "cancel", "deploy", "editor", "filter", "graph", "handle", "index",
            "journal", "kernel", "lookup", "module", "notify", "output", "policy", "queue",
            "render", "stream", "token", "update", "vector", "worker", "yield",
        ];
        WORDS[self.below(WORDS.len())]
    }

    fn sentence(&mut self, words: usize) -> String {
        let mut out = String::new();
        for i in 0..words {
            if i > 0 {
                out.push(' ');
            }
            out.push_str(self.word());
        }
        out
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let chunk = self.next().to_le_bytes();
            let take = chunk.len().min(len - out.len());
            out.extend_from_slice(&chunk[..take]);
        }
        out
    }
}

fn map(entries: Vec<(String, BenchValue)>) -> BenchValue {
    let mut entries = entries;
    sort_map_entries(&mut entries);
    BenchValue::Map(entries)
}

fn text(s: impl Into<String>) -> BenchValue {
    BenchValue::Text(s.into())
}

fn key(k: &str) -> String {
    k.to_string()
}

const ENVELOPE_PATHS: &[&[PathElem<'static>]] = &[
    &[PathElem::Key("id")],
    &[PathElem::Key("kind")],
    &[PathElem::Key("params"), PathElem::Key("name")],
];

/// ~300 B control-plane message: the most common message on a SACP link.
fn envelope(rng: &mut Rng) -> BenchValue {
    map(vec![
        (key("id"), text(format!("msg-{}", rng.hex(16)))),
        (key("kind"), text("tool_call")),
        (key("seq"), BenchValue::Int(4117)),
        (key("session"), text(format!("sess-{}", rng.hex(12)))),
        (key("ts"), BenchValue::Int(1_780_000_000_000)),
        (
            key("params"),
            map(vec![
                (key("name"), text("files.read")),
                (key("path"), text("/workspace/src/protocol/handler.rs")),
                (key("stream"), BenchValue::Bool(false)),
                (key("timeout_ms"), BenchValue::Int(30_000)),
            ]),
        ),
    ])
}

const TOOL_CALL_PATHS: &[&[PathElem<'static>]] = &[
    &[PathElem::Key("id")],
    &[PathElem::Key("kind")],
    &[PathElem::Key("params"), PathElem::Key("name")],
];

/// ~4 KiB tool invocation: envelope plus text-heavy arguments. The routing
/// reads in `ingest` never touch the large `input` argument.
fn tool_call(rng: &mut Rng) -> BenchValue {
    let files = BenchValue::Array(
        (0..8)
            .map(|_| text(format!("/workspace/{}/{}.rs", rng.word(), rng.word())))
            .collect(),
    );
    let env = map((0..8)
        .map(|i| (format!("VAR_{i:02}"), text(rng.sentence(2))))
        .collect());
    map(vec![
        (key("id"), text(format!("msg-{}", rng.hex(16)))),
        (key("kind"), text("tool_call")),
        (key("seq"), BenchValue::Int(90_210)),
        (key("session"), text(format!("sess-{}", rng.hex(12)))),
        (key("ts"), BenchValue::Int(1_780_000_000_321)),
        (
            key("params"),
            map(vec![
                (key("name"), text("shell.exec")),
                (key("timeout_ms"), BenchValue::Int(120_000)),
                (
                    key("arguments"),
                    map(vec![
                        (key("input"), text(rng.sentence(500))),
                        (key("files"), files),
                        (key("env"), env),
                        (key("cwd"), text("/workspace")),
                    ]),
                ),
            ]),
        ),
    ])
}

const TOOL_RESULT_PATHS: &[&[PathElem<'static>]] = &[
    &[PathElem::Key("id")],
    &[PathElem::Key("ok")],
    &[PathElem::Key("meta"), PathElem::Key("duration_ms")],
];

/// ~64 KiB tool result with a binary payload. The `ingest` reads only the
/// status fields; full decoders must still copy the 60 KiB blob.
fn tool_result_blob(rng: &mut Rng) -> BenchValue {
    map(vec![
        (key("id"), text(format!("msg-{}", rng.hex(16)))),
        (key("kind"), text("tool_result")),
        (key("ok"), BenchValue::Bool(true)),
        (key("seq"), BenchValue::Int(90_211)),
        (
            key("meta"),
            map(vec![
                (key("duration_ms"), BenchValue::Int(842)),
                (key("exit_code"), BenchValue::Int(0)),
                (key("truncated"), BenchValue::Bool(false)),
            ]),
        ),
        (key("payload"), BenchValue::Bytes(rng.bytes(60 * 1024))),
    ])
}

const EVENT_BATCH_PATHS: &[&[PathElem<'static>]] = &[
    &[PathElem::Key("id")],
    &[PathElem::Key("seq")],
    &[
        PathElem::Key("events"),
        PathElem::Index(128),
        PathElem::Key("kind"),
    ],
];

/// ~25 KiB batch of 256 small heterogeneous events.
fn event_batch(rng: &mut Rng) -> BenchValue {
    const KINDS: &[&str] = &["file_changed", "task_started", "task_done", "log", "metric"];
    let events = BenchValue::Array(
        (0..256)
            .map(|i| {
                map(vec![
                    (key("kind"), text(KINDS[rng.below(KINDS.len())])),
                    (
                        key("path"),
                        text(format!("/run/{}/{}", rng.word(), rng.word())),
                    ),
                    (key("seq"), BenchValue::Int(i)),
                    (key("ts"), BenchValue::Int(1_780_000_000_000 + i * 13)),
                ])
            })
            .collect(),
    );
    map(vec![
        (key("id"), text(format!("msg-{}", rng.hex(16)))),
        (key("kind"), text("event_batch")),
        (key("seq"), BenchValue::Int(90_300)),
        (key("events"), events),
    ])
}

const STATE_DOC_PATHS: &[&[PathElem<'static>]] = &[
    &[PathElem::Key("id")],
    &[
        PathElem::Key("agents"),
        PathElem::Key("agent-0008"),
        PathElem::Key("state"),
    ],
    &[PathElem::Key("config"), PathElem::Key("log_level")],
];

/// ~16 KiB nested session/state document with mixed scalar types.
fn state_doc(rng: &mut Rng) -> BenchValue {
    const STATES: &[&str] = &["idle", "running", "blocked", "draining"];
    let agents = map((0..16)
        .map(|i| {
            let caps = BenchValue::Array((0..6).map(|_| text(rng.word())).collect());
            let labels = map((0..4)
                .map(|j| (format!("label{j}"), text(rng.sentence(3))))
                .collect());
            let limits = map(vec![
                (key("max_depth"), BenchValue::Int(64)),
                (key("max_bytes"), BenchValue::Int(1 << 20)),
                (key("max_items"), BenchValue::Int(100_000)),
            ]);
            (
                format!("agent-{i:04}"),
                map(vec![
                    (key("caps"), caps),
                    (key("labels"), labels),
                    (key("limits"), limits),
                    (key("state"), text(STATES[rng.below(STATES.len())])),
                    (key("note"), text(rng.sentence(40))),
                ]),
            )
        })
        .collect());
    map(vec![
        (key("id"), text(format!("doc-{}", rng.hex(16)))),
        (key("seq"), BenchValue::Int(7)),
        (key("version"), BenchValue::Int(3)),
        (key("agents"), agents),
        (
            key("config"),
            map(vec![
                (key("log_level"), text("info")),
                (key("region"), text("eu-west-1")),
                (key("flush_ms"), BenchValue::Int(250)),
                (key("strict"), BenchValue::Bool(true)),
            ]),
        ),
    ])
}

/// All workload messages, deterministic across runs.
pub fn workloads() -> Vec<Workload> {
    let mut rng = Rng::new(0x5acb_c0de_2026_0610);
    vec![
        Workload {
            name: "envelope",
            value: envelope(&mut rng),
            inspect_paths: ENVELOPE_PATHS,
        },
        Workload {
            name: "tool_call",
            value: tool_call(&mut rng),
            inspect_paths: TOOL_CALL_PATHS,
        },
        Workload {
            name: "tool_result_blob",
            value: tool_result_blob(&mut rng),
            inspect_paths: TOOL_RESULT_PATHS,
        },
        Workload {
            name: "event_batch",
            value: event_batch(&mut rng),
            inspect_paths: EVENT_BATCH_PATHS,
        },
        Workload {
            name: "state_doc",
            value: state_doc(&mut rng),
            inspect_paths: STATE_DOC_PATHS,
        },
    ]
}

/// Subset used when `BENCH_FAST=1`: the smallest and the largest message.
pub const FAST_WORKLOADS: &[&str] = &["envelope", "tool_result_blob"];
