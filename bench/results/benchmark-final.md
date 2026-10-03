# Secret scanner benchmark

Generated: 2026-10-02T18:42:49Z

Offline, default-rule end-to-end comparison. First-run is a new process, not a cold disk-cache claim. Warm runs start new processes after an unmeasured warmup. No provider validation is enabled. Raw scanner output is discarded.

| Tool | Dataset | Status | Median ms | Input MiB/s | Peak RSS MiB | TP/FP/FN | P/R/F1 |
|---|---|---|---:|---:|---:|---|---|
| secret-scan | quality | ok | 32.691 | 0.08 | 20.19 | 31/0/3 | 1.000/0.912/0.954 |
| secret-scan | capabilities | ok | 31.342 | 2.02 | 18.72 | 6/0/0 | 1.000/1.000/1.000 |
| secret-scan | throughput-1mib | ok | 31.461 | 31.79 | 19.94 | 1/0/0 | 1.000/1.000/1.000 |
| secret-scan | throughput-16mib | ok | 55.453 | 288.53 | 21.83 | 16/0/0 | 1.000/1.000/1.000 |
| secret-scan | throughput-128mib | ok | 205.855 | 621.80 | 25.17 | 128/0/0 | 1.000/1.000/1.000 |
| secret-scan | git_history | ok | 95.530 | — | 17.16 | 1/0/0 | 1.000/1.000/1.000 |
| secret-scan | staged | ok | 72.747 | — | 17.23 | 1/0/0 | 1.000/1.000/1.000 |
| secret-scan | real-regex | ok | 69.099 | 116.41 | 24.20 | — | — |
| talisman | quality | unsupported | — | — | — | — | — |
| talisman | capabilities | unsupported | — | — | — | — | — |
| talisman | throughput-1mib | unsupported | — | — | — | — | — |
| talisman | throughput-16mib | unsupported | — | — | — | — | — |
| talisman | throughput-128mib | unsupported | — | — | — | — | — |
| talisman | git_history | invalid_adapter | — | — | — | — | — |
| talisman | staged | invalid_adapter | — | — | — | — | — |
| talisman | real-regex | unsupported | — | — | — | — | — |
| rusty-hog | quality | invalid_adapter | — | — | — | — | — |
| rusty-hog | capabilities | invalid_adapter | — | — | — | — | — |
| rusty-hog | throughput-1mib | invalid_adapter | — | — | — | — | — |
| rusty-hog | throughput-16mib | invalid_adapter | — | — | — | — | — |
| rusty-hog | throughput-128mib | invalid_adapter | — | — | — | — | — |
| rusty-hog | git_history | unsupported | — | — | — | — | — |
| rusty-hog | staged | unsupported | — | — | — | — | — |
| rusty-hog | real-regex | invalid_adapter | — | — | — | — | — |
| secretlint | quality | ok | 163.721 | 0.02 | 84.48 | 19/0/15 | 1.000/0.559/0.717 |
| secretlint | capabilities | ok | 146.416 | 0.43 | 83.56 | 2/0/4 | 1.000/0.333/0.500 |
| secretlint | throughput-1mib | ok | 160.458 | 6.23 | 89.55 | 1/0/0 | 1.000/1.000/1.000 |
| secretlint | throughput-16mib | ok | 318.671 | 50.21 | 200.36 | 16/0/0 | 1.000/1.000/1.000 |
| secretlint | throughput-128mib | ok | 1513.439 | 84.58 | 928.33 | 128/0/0 | 1.000/1.000/1.000 |
| secretlint | git_history | unsupported | — | — | — | — | — |
| secretlint | staged | unsupported | — | — | — | — | — |
| secretlint | real-regex | ok | 342.260 | 23.50 | 174.45 | — | — |
| credential-digger | quality | invalid_adapter | — | — | — | — | — |
| credential-digger | capabilities | invalid_adapter | — | — | — | — | — |
| credential-digger | throughput-1mib | invalid_adapter | — | — | — | — | — |
| credential-digger | throughput-16mib | invalid_adapter | — | — | — | — | — |
| credential-digger | throughput-128mib | invalid_adapter | — | — | — | — | — |
| credential-digger | git_history | unsupported | — | — | — | — | — |
| credential-digger | staged | unsupported | — | — | — | — | — |
| credential-digger | real-regex | invalid_adapter | — | — | — | — | — |
| scratch-scanner-rs | quality | invalid_adapter | — | — | — | — | — |
| scratch-scanner-rs | capabilities | invalid_adapter | — | — | — | — | — |
| scratch-scanner-rs | throughput-1mib | invalid_adapter | — | — | — | — | — |
| scratch-scanner-rs | throughput-16mib | invalid_adapter | — | — | — | — | — |
| scratch-scanner-rs | throughput-128mib | invalid_adapter | — | — | — | — | — |
| scratch-scanner-rs | git_history | invalid_adapter | — | — | — | — | — |
| scratch-scanner-rs | staged | unsupported | — | — | — | — | — |
| scratch-scanner-rs | real-regex | invalid_adapter | — | — | — | — | — |
| deepfence-secretscanner | — | build_failed | — | — | — | — | — |

Precision is location-based on the labelled synthetic corpus, not a real-world false-positive estimate. Duplicate detections do not increase recall. Exact byte-span, overlapping-span and line-only matches are counted separately in JSON; line-only tools have weaker localization evidence. Tools have different default rules and coverage, so throughput alone does not rank engine efficiency. Unavailable and unsupported entries are not zero scores.

Hardware: `{"cpu": "Apple M2 Max", "logical_cpus": 12, "machine": "arm64", "memory_bytes": "103079215104", "python": "3.14.7", "system": "macOS-26.5.2-arm64-arm-64bit-Mach-O"}`

See the JSON artifact for versions, commands, exits, per-run timings, CPU, RSS, corpus hashes, labels and completeness. RSS is per-child getrusage peak; it is not a simultaneous aggregate for a multiprocess tree.
