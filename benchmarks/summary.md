# Fast Bench Summary (sacp-cbor)

- Generated: 2026-01-28 14:55:32
- Command: `BENCH_FAST=1 cargo bench --bench bench`
- Scope: sacp-cbor benchmarks only

## Results

### decode_canonical_trusted/appendix_a/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| decode_canonical_trusted/appendix_a/sacp-cbor/appendix_a_canonical | 907.51 | 2.074 |  |

### decode_canonical_trusted/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| decode_canonical_trusted/sacp-cbor/appendix_a_canonical | 1901.06 | 80.320 |  |

### decode_ignored/appendix_a/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| decode_ignored/appendix_a/sacp-cbor/appendix_a_canonical | 828.19 | -4.219 | 256.79 |

### decode_ignored/synth/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| decode_ignored/synth/sacp-cbor/synthetic/array_len256_bool | 661.13 | 8.917 | 373.60 |
| decode_ignored/synth/sacp-cbor/synthetic/array_len4096_bool | 25071.19 | -2.582 | 155.92 |
| decode_ignored/synth/sacp-cbor/synthetic/map_k16_i64 | 207.17 | 11.498 | 520.18 |
| decode_ignored/synth/sacp-cbor/synthetic/map_k64_i64 | 1105.81 | -10.965 | 388.09 |

### decode_synth_canonical_trusted/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| decode_synth_canonical_trusted/sacp-cbor/synthetic/array_len256_bool | 627.33 | -0.170 |  |
| decode_synth_canonical_trusted/sacp-cbor/synthetic/array_len4096_bool | 26113.20 | 0.976 |  |
| decode_synth_canonical_trusted/sacp-cbor/synthetic/map_k16_i64 | 108.91 | -9.994 |  |
| decode_synth_canonical_trusted/sacp-cbor/synthetic/map_k64_i64 | 926.90 | -1.459 |  |

### decode_synth_validated/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| decode_synth_validated/sacp-cbor/synthetic/array_len256_bool | 485.37 | -72.241 |  |
| decode_synth_validated/sacp-cbor/synthetic/map_k16_i64 | 207.49 | -51.128 |  |

### decode_trusted/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| decode_trusted/sacp-cbor/appendix_a_canonical | 1550.46 | -5.729 |  |

### decode_validated/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| decode_validated/sacp-cbor/appendix_a_canonical | 1463.70 | -3.554 |  |

### decode_value/synth/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| decode_value/synth/sacp-cbor/synthetic/array_len256_bool | 4994.62 | -0.266 | 49.45 |
| decode_value/synth/sacp-cbor/synthetic/array_len4096_bool | 82718.08 | -7.236 | 47.26 |
| decode_value/synth/sacp-cbor/synthetic/map_k16_i64 | 590.04 | -0.958 | 182.64 |
| decode_value/synth/sacp-cbor/synthetic/map_k64_i64 | 2918.58 | -7.348 | 147.04 |

### edit_patch/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| edit_patch/sacp-cbor/array_replace/array_len256 | 8520.78 | 2.780 |  |
| edit_patch/sacp-cbor/array_replace/array_len64 | 1479.93 | -23.338 |  |
| edit_patch/sacp-cbor/array_splice/array_len256 | 8397.04 | 2.953 |  |
| edit_patch/sacp-cbor/array_splice/array_len64 | 1390.87 | -27.752 |  |
| edit_patch/sacp-cbor/map_delete/map_k16 | 841.03 | -17.437 |  |
| edit_patch/sacp-cbor/map_delete/map_k64 | 5055.36 | 0.633 |  |
| edit_patch/sacp-cbor/map_insert/map_k16 | 1001.99 | -11.801 |  |
| edit_patch/sacp-cbor/map_insert/map_k64 | 5377.19 | 1.886 |  |
| edit_patch/sacp-cbor/map_set/map_k16 | 950.96 | -15.313 |  |
| edit_patch/sacp-cbor/map_set/map_k64 | 5172.57 | -1.494 |  |

### encode/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| encode/sacp-cbor/synthetic/array_len256_bool | 647.09 | -4.882 |  |
| encode/sacp-cbor/synthetic/map_k16_i64 | 288.23 | -8.065 |  |

### encode_stream/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| encode_stream/sacp-cbor/synthetic/array_len256_bool | 682.38 | -10.085 |  |
| encode_stream/sacp-cbor/synthetic/array_len4096_bool | 9207.57 | -22.448 |  |
| encode_stream/sacp-cbor/synthetic/map_k16_i64 | 303.82 | 13.023 |  |
| encode_stream/sacp-cbor/synthetic/map_k64_i64 | 871.82 | -1.257 |  |

### encode_value/synth/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| encode_value/synth/sacp-cbor/synthetic/array_len256_bool | 766.35 | -2.377 | 322.31 |
| encode_value/synth/sacp-cbor/synthetic/array_len4096_bool | 12062.94 | -15.306 | 324.06 |
| encode_value/synth/sacp-cbor/synthetic/map_k16_i64 | 340.30 | -3.015 | 316.68 |
| encode_value/synth/sacp-cbor/synthetic/map_k64_i64 | 905.06 | -3.132 | 474.17 |

### native_decode_borrowed/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| native_decode_borrowed/sacp-cbor/synthetic/array_len256_bool | 1755.25 | -2.169 |  |
| native_decode_borrowed/sacp-cbor/synthetic/array_len4096_bool | 28500.75 | 0.819 |  |
| native_decode_borrowed/sacp-cbor/synthetic/map_k16_i64 | 204.66 | -2.068 |  |
| native_decode_borrowed/sacp-cbor/synthetic/map_k64_i64 | 800.54 | -0.014 |  |

### native_roundtrip/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| native_roundtrip/sacp-cbor/synthetic/array_len256_bool | 3383.64 | 0.448 |  |
| native_roundtrip/sacp-cbor/synthetic/array_len4096_bool | 55624.36 | 1.887 |  |
| native_roundtrip/sacp-cbor/synthetic/map_k16_i64 | 879.15 | -0.650 |  |
| native_roundtrip/sacp-cbor/synthetic/map_k64_i64 | 4056.95 | 0.094 |  |

### query_map_get_many_zero_copy/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| query_map_get_many_zero_copy/sacp-cbor/hits4/map_k16 | 196.66 | -44.778 |  |
| query_map_get_many_zero_copy/sacp-cbor/hits4/map_k64 | 464.27 | 2.687 |  |
| query_map_get_many_zero_copy/sacp-cbor/miss4/map_k16 | 246.59 | -44.704 |  |
| query_map_get_many_zero_copy/sacp-cbor/miss4/map_k64 | 2268.16 | -3.475 |  |

### query_path_zero_copy/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| query_path_zero_copy/sacp-cbor/path_items/nested_items128 | 6719.67 | 14.446 |  |
| query_path_zero_copy/sacp-cbor/path_items/nested_items32 | 1444.37 | -12.537 |  |
| query_path_zero_copy/sacp-cbor/path_meta/nested_items128 | 169.94 | 2.944 |  |
| query_path_zero_copy/sacp-cbor/path_meta/nested_items32 | 72.49 | -41.164 |  |
| query_path_zero_copy/sacp-cbor/path_miss/nested_items128 | 5556.05 | 17.339 |  |
| query_path_zero_copy/sacp-cbor/path_miss/nested_items32 | 803.27 | -8.189 |  |

### query_synth_trusted/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| query_synth_trusted/sacp-cbor/synthetic/array_len256_bool | 507.84 | -70.713 |  |
| query_synth_trusted/sacp-cbor/synthetic/map_k16_i64 | 149.20 | -58.386 |  |

### roundtrip_value/synth/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| roundtrip_value/synth/sacp-cbor/synthetic/array_len256_bool | 6017.60 | 5.219 | 41.05 |
| roundtrip_value/synth/sacp-cbor/synthetic/array_len4096_bool | 96225.89 | -2.240 | 40.62 |
| roundtrip_value/synth/sacp-cbor/synthetic/map_k16_i64 | 906.60 | 2.117 | 118.87 |
| roundtrip_value/synth/sacp-cbor/synthetic/map_k64_i64 | 3756.33 | -8.590 | 114.25 |

### serde_roundtrip/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| serde_roundtrip/sacp-cbor/synthetic/array_len256_bool | 5759.97 | -0.810 |  |
| serde_roundtrip/sacp-cbor/synthetic/map_k16_i64 | 912.56 | -2.339 |  |

### validate/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| validate/sacp-cbor/appendix_a_canonical | 1068.16 | 1.946 |  |

### validate_only/appendix_a/sacp-cbor
| benchmark | mean (ns) | change mean % | throughput (MiB/s) |
|---|---:|---:|---:|
| validate_only/appendix_a/sacp-cbor/appendix_a_canonical | 833.30 | -0.361 | 255.21 |

