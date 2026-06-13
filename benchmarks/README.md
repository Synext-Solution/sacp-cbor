# Benchmarks

Scenario-driven benchmarks comparing sacp-cbor against other Rust CBOR crates
on realistic SACP message shapes, with reports built for two jobs:

1. **Proving real-world impact** — every scenario models something an actual
   SACP endpoint does with a message, and every competitor row is the closest
   thing that crate offers for the same job.
2. **Driving optimization** — uniform `scenario/implementation/workload` IDs,
   per-scenario pivot tables with slowdown ratios, and a baseline-comparison
   mode that flags regressions commit-to-commit.

## Quick start

```bash
cd benchmarks
./scripts/fetch_datasets.sh                 # appendix_a.json (RFC test vectors)
cargo bench
cargo run -p bench_harness --bin report
```

Results are written to:

- `benchmarks/reports/latest/summary.json` — machine-readable, usable as a baseline
- `benchmarks/reports/latest/summary.md` — pivot tables with throughput and ratios

## Scenarios

| Scenario                    | Real-world job                                             | sacp-cbor path                                                                                             | Competitor path                                  |
|-----------------------------|------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|--------------------------------------------------|
| `validate`                  | Accept/reject an untrusted message                         | `validate_canonical` (no decode, no alloc)                                                                 | Full ignored parse (their only structural check) |
| `ingest`                    | Receive a message, read its routing fields                 | validate + zero-copy `at()` queries                                                                        | Decode everything, traverse the value tree       |
| `decode_typed`              | Full decode to an owned value tree                         | serde `from_slice`; plus `sacp-trusted` / `sacp-borrowed` rows decoding from an existing canonical witness | Their decode                                     |
| `encode`                    | Typed value to wire bytes                                  | serde `to_vec`; plus `sacp-stream` (streaming encoder)                                                     | Their encode                                     |
| `roundtrip`                 | encode + decode                                            | as above; plus `sacp-native` (derive-based)                                                                | Their roundtrip                                  |
| `patch`                     | Gateway rewrite: change one field, re-emit canonical bytes | `sacp-editor` structural patch                                                                             | Decode → mutate → re-encode                      |
| `appendix_a`                | RFC 8949 test-vector soup (many tiny items)                | validate / trusted decode                                                                                  | Ignored parse                                    |
| `micro_query`, `micro_edit` | Optimization targets for query/edit hot paths              | sacp-cbor only                                                                                             | —                                                |

## Workloads

ABI-specific scenarios are also part of this suite:
`abi_decode_owned`, `abi_view_access`, `abi_unknown_preserve`, and
`abi_enum_access`. They use `abi_flat4`, `abi_flat16`, `abi_text4k`, and
`abi_blob64k` style messages to compare generated owned ABI decode against
generated zero-copy ABI views.

ABI benchmark implementation IDs distinguish trust boundaries:
`abi-view` / `view` start from an already validated `CanonicalCborRef`,
`abi-view-checked` / `view-checked` include validation from untrusted bytes,
and `abi-owned-trusted` / `owned-trusted` decode owned values from an already
validated canonical witness. Array-specific view costs are tracked separately
with `abi-view-array-get-last`.

Runtime ABI rows measure schema-guided validation without generated Rust
types on the same ABI workloads. `abi-runtime-view` validates only the ABI
field-set shell and uses one sorted multi-field raw lookup, while
`abi-runtime-validate-inline` additionally checks known fields against their
`TypeRef`s. The `*-checked` runtime rows include canonical validation from
untrusted bytes. Runtime hook rows compare the monomorphized no-op hook path,
concrete semantic field hooks, and a vector sorted/unique refinement hook.
`abi_runtime_named` measures compiled-registry
named recursion and named hook acceptance. `abi_runtime_compile` measures the
one-time schema compilation cost that consumers should pay outside hot message
paths.

Deterministically generated SACP message shapes (seeded xorshift, identical on
every machine — see `bench_harness::datasets::workloads`):

| Workload           | Size    | Shape                                                                         |
|--------------------|---------|-------------------------------------------------------------------------------|
| `envelope`         | ~300 B  | Typical control-plane message: id, kind, seq, session, ts, small params       |
| `tool_call`        | ~4 KiB  | Envelope plus text-heavy arguments (large `input`, file list, env map)        |
| `tool_result_blob` | ~64 KiB | Result envelope with a 60 KiB binary payload; ingest reads only status fields |
| `event_batch`      | ~25 KiB | 256 small heterogeneous event maps                                            |
| `state_doc`        | ~16 KiB | Nested session/state document, 16 agents with mixed scalar fields             |

Every workload root carries `id` and `seq`, so `patch` performs the same
edit (`seq` replace) across all workloads, and `ingest` reads each workload's
declared routing paths.

## Optimization workflow

```bash
cargo bench                                          # before
cargo run -p bench_harness --bin report
cp reports/latest/summary.json /tmp/baseline.json

# ... change the code ...

cargo bench                                          # after
cargo run -p bench_harness --bin report -- \
    --baseline /tmp/baseline.json --threshold 5 --fail-on-regress
```

The report prints `REGRESS`/`improve` lines for every bench whose median moved
by more than the threshold, appends a comparison table to `summary.md`, and
(with `--fail-on-regress`) exits non-zero when something got slower — suitable
for scripting.

Flamegraphs per bench (Unix): `cargo bench --features pprof -- --profile-time 10`.

## Adapters

Enabled by default: sacp-cbor, serde_cbor, ciborium, minicbor, cbor4ii.
Disable with feature flags on `bench_harness`. Note the comparison is
intentionally asymmetric in sacp-cbor's favor on guarantees: competitor rows
do **not** validate canonicality and (in `patch`) do not guarantee canonical
output — they are the baseline cost of getting a weaker result.

Workloads avoid floats so all adapters decode the identical value shape
(`BenchValue` maps floats lossily).

## Faster runs

```bash
# Smallest + largest workload only, 10 samples, 1s measurement
BENCH_FAST=1 cargo bench

# Criterion CLI overrides
cargo bench -- --quick
cargo bench -- ingest            # one scenario
cargo bench -- 'ingest/.*/envelope'
```

CI runs `BENCH_FAST=1 cargo bench` as a smoke test so the suite cannot rot;
timing numbers from CI runners are not meaningful — compare baselines on a
quiet local machine.
