# Fast Bench Summary (sacp-cbor)

- Generated: 2026-01-28 16:35:24
- Command: `BENCH_FAST=1 cargo bench --bench bench`
- Scope: sacp-cbor benchmarks only
- Notes: fresh run (no baseline/change data)

## Results

### decode_canonical_trusted/appendix_a/sacp-cbor
| benchmark | mean (ns) | throughput (MiB/s) |
|---|---:|---:|
| decode_canonical_trusted/appendix_a/sacp-cbor/appendix_a_canonical | 904.70 |  |

### decode_ignored/appendix_a/sacp-cbor
| benchmark | mean (ns) | throughput (MiB/s) |
|---|---:|---:|
| decode_ignored/appendix_a/sacp-cbor/appendix_a_canonical | 841.75 | 252.65 |

### decode_ignored/synth/sacp-cbor
| benchmark | mean (ns) | throughput (MiB/s) |
|---|---:|---:|
| decode_ignored/synth/sacp-cbor/synthetic/array_len256_bool | 635.03 | 388.96 |
| decode_ignored/synth/sacp-cbor/synthetic/map_k16_i64 | 199.16 | 541.10 |

### decode_synth_canonical_trusted/sacp-cbor
| benchmark | mean (ns) | throughput (MiB/s) |
|---|---:|---:|
| decode_synth_canonical_trusted/sacp-cbor/synthetic/array_len256_bool | 637.67 |  |
| decode_synth_canonical_trusted/sacp-cbor/synthetic/map_k16_i64 | 110.04 |  |

### decode_value/synth/sacp-cbor
| benchmark | mean (ns) | throughput (MiB/s) |
|---|---:|---:|
| decode_value/synth/sacp-cbor/synthetic/array_len256_bool | 5072.40 | 48.70 |
| decode_value/synth/sacp-cbor/synthetic/map_k16_i64 | 598.04 | 180.20 |

### edit_patch/sacp-cbor
| benchmark | mean (ns) | throughput (MiB/s) |
|---|---:|---:|
| edit_patch/sacp-cbor/array_replace/array_len64 | 1455.56 |  |
| edit_patch/sacp-cbor/array_splice/array_len64 | 1399.33 |  |
| edit_patch/sacp-cbor/map_delete/map_k16 | 831.35 |  |
| edit_patch/sacp-cbor/map_insert/map_k16 | 985.46 |  |
| edit_patch/sacp-cbor/map_set/map_k16 | 934.25 |  |

### encode_stream/sacp-cbor
| benchmark | mean (ns) | throughput (MiB/s) |
|---|---:|---:|
| encode_stream/sacp-cbor/synthetic/array_len256_bool | 705.72 |  |
| encode_stream/sacp-cbor/synthetic/map_k16_i64 | 315.40 |  |

### encode_value/synth/sacp-cbor
| benchmark | mean (ns) | throughput (MiB/s) |
|---|---:|---:|
| encode_value/synth/sacp-cbor/synthetic/array_len256_bool | 775.49 | 318.51 |
| encode_value/synth/sacp-cbor/synthetic/map_k16_i64 | 338.61 | 318.26 |

### native_decode_borrowed/sacp-cbor
| benchmark | mean (ns) | throughput (MiB/s) |
|---|---:|---:|
| native_decode_borrowed/sacp-cbor/synthetic/array_len256_bool | 1760.56 |  |
| native_decode_borrowed/sacp-cbor/synthetic/map_k16_i64 | 205.76 |  |

### native_roundtrip/sacp-cbor
| benchmark | mean (ns) | throughput (MiB/s) |
|---|---:|---:|
| native_roundtrip/sacp-cbor/synthetic/array_len256_bool | 3523.70 |  |
| native_roundtrip/sacp-cbor/synthetic/map_k16_i64 | 906.93 |  |

### query_map_get_many_zero_copy/sacp-cbor
| benchmark | mean (ns) | throughput (MiB/s) |
|---|---:|---:|
| query_map_get_many_zero_copy/sacp-cbor/hits4/map_k16 | 190.18 |  |
| query_map_get_many_zero_copy/sacp-cbor/miss4/map_k16 | 237.93 |  |

### query_path_zero_copy/sacp-cbor
| benchmark | mean (ns) | throughput (MiB/s) |
|---|---:|---:|
| query_path_zero_copy/sacp-cbor/path_items/nested_items32 | 1447.84 |  |
| query_path_zero_copy/sacp-cbor/path_meta/nested_items32 | 74.31 |  |
| query_path_zero_copy/sacp-cbor/path_miss/nested_items32 | 791.61 |  |

### roundtrip_value/synth/sacp-cbor
| benchmark | mean (ns) | throughput (MiB/s) |
|---|---:|---:|
| roundtrip_value/synth/sacp-cbor/synthetic/array_len256_bool | 5925.26 | 41.69 |
| roundtrip_value/synth/sacp-cbor/synthetic/map_k16_i64 | 936.89 | 115.02 |

### validate_only/appendix_a/sacp-cbor
| benchmark | mean (ns) | throughput (MiB/s) |
|---|---:|---:|
| validate_only/appendix_a/sacp-cbor/appendix_a_canonical | 851.58 | 249.74 |

