# Benchmark datasets

## appendix_a.json
Source: https://github.com/cbor/test-vectors (appendix_a.json, RFC-derived vectors)

SHA256:
```
80e78dc2f53cfdc9836094791d09e84c6818edf380f7cdd4be26a5c2dc4e9f3a
```

## Optional datasets
You may add additional datasets under `benchmarks/datasets/` (e.g., COSE vectors), then wire them
into the harness explicitly with a loader and Criterion scenario so report IDs stay stable.
