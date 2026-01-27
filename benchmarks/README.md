# Benchmarks

This workspace runs cross-crate CBOR benchmarks with common datasets and emits
Markdown + JSON summaries.

## Quick start

```bash
cd benchmarks
./scripts/fetch_datasets.sh
cargo bench
cargo run -p bench_harness --bin report
```

Results are written to:

- `benchmarks/reports/latest/summary.json`
- `benchmarks/reports/latest/summary.md`

## Datasets

- `datasets/appendix_a.json` from the CBOR test-vectors repo.
- Synthetic datasets are generated in-code (see `bench_harness::datasets`).

## Adapters

Enabled by default:

- sacp-cbor
- serde_cbor
- ciborium
- minicbor
- cbor4ii

Disable adapters with feature flags on `bench_harness`.
