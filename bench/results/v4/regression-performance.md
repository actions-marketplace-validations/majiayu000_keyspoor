# Secret scanner benchmark

Generated: 2026-10-03T11:39:06Z

Offline, default-rule end-to-end comparison. First-run is a new process, not a cold disk-cache claim. Warm runs start new processes after an unmeasured warmup. No provider validation is enabled. Raw scanner output is discarded.

| Tool | Dataset | Status | Median ms | Input MiB/s | Peak RSS MiB | TP/FP/FN | Unlocalized | Localized P / recall lower bound / F1 |
|---|---|---|---:|---:|---:|---|---:|---|
| secret-scan-before | quality | ok | 47.437 | 0.05 | 24.16 | 34/0/0 | 0 | 1.000/1.000/1.000 |
| secret-scan-before | throughput-16mib | ok | 67.438 | 237.25 | 23.75 | 16/0/0 | 0 | 1.000/1.000/1.000 |
| secret-scan-before | throughput-128mib | ok | 275.258 | 465.02 | 24.55 | 128/0/0 | 0 | 1.000/1.000/1.000 |
| secret-scan-before | real-regex | ok | 101.023 | 79.63 | 30.84 | — | — | — |
| secret-scan | quality | ok | 47.628 | 0.05 | 24.09 | 34/0/0 | 0 | 1.000/1.000/1.000 |
| secret-scan | throughput-16mib | ok | 72.032 | 222.12 | 23.23 | 16/0/0 | 0 | 1.000/1.000/1.000 |
| secret-scan | throughput-128mib | ok | 266.780 | 479.80 | 25.05 | 128/0/0 | 0 | 1.000/1.000/1.000 |
| secret-scan | real-regex | ok | 98.945 | 81.30 | 30.95 | — | — | — |

Schema/scoring v2: precision excludes unlocalized results and is conditional on localized unique findings, not a real-world false-positive estimate. Recall is a confirmed-location lower bound; unlocalized findings do not prove a miss or a hit. Duplicate detections do not increase recall. Exact byte-span, overlapping-span and line-only matches are counted separately in JSON; line-only tools have weaker localization evidence. Tools have different default rules and coverage, so throughput alone does not rank engine efficiency. Unavailable and unsupported entries are not zero scores.

Hardware: `{"cpu": "Apple M2 Max", "logical_cpus": 12, "machine": "arm64", "memory_bytes": "103079215104", "python": "3.14.7", "system": "macOS-26.5.2-arm64-arm-64bit-Mach-O"}`

See the JSON artifact for versions, commands, exits, per-run timings, CPU, RSS, corpus hashes, labels and completeness. RSS is per-child getrusage peak; it is not a simultaneous aggregate for a multiprocess tree.
