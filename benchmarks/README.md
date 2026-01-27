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

## Faster runs

For quick feedback loops you can reduce Criterion's work or trim the synthetic dataset set:

```bash
# Quick mode + smaller synthetic datasets
BENCH_FAST=1 cargo bench

# Use Criterion's CLI overrides
cargo bench -- --quick
cargo bench -- --sample-size 10 --measurement-time 1 --warm-up-time 0.5
```
