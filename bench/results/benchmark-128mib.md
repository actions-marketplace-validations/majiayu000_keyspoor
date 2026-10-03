# Secret scanner benchmark

Generated: 2026-10-02T18:26:01Z

Offline, default-rule end-to-end comparison. First-run is a new process, not a cold disk-cache claim. Warm runs start new processes after an unmeasured warmup. No provider validation is enabled. Raw scanner output is discarded.

| Tool | Dataset | Status | Median ms | Input MiB/s | Peak RSS MiB | TP/FP/FN | P/R/F1 |
|---|---|---|---:|---:|---:|---|---|
| secret-scan | throughput-128mib | ok | 236.390 | 541.48 | 25.00 | 128/0/0 | 1.000/1.000/1.000 |
| gitleaks | throughput-128mib | ok | 740.251 | 172.91 | 144.44 | 128/0/0 | 1.000/1.000/1.000 |
| kingfisher | throughput-128mib | ok | 504.588 | 253.67 | 150.58 | 128/0/0 | 1.000/1.000/1.000 |
| betterleaks | throughput-128mib | ok | 327.600 | 390.72 | 114.34 | 128/0/0 | 1.000/1.000/1.000 |
| titus | throughput-128mib | ok | 305.810 | 418.56 | 161.11 | 128/0/0 | 1.000/1.000/1.000 |
| trivy | throughput-128mib | ok | 214.665 | 596.28 | 112.41 | 128/0/0 | 1.000/1.000/1.000 |
| keyhog | throughput-128mib | ok | 1937.482 | 66.07 | 99.06 | 0/0/128 | —/0.000/0.000 |

Precision is location-based on the labelled synthetic corpus, not a real-world false-positive estimate. Duplicate detections do not increase recall. Exact byte-span, overlapping-span and line-only matches are counted separately in JSON; line-only tools have weaker localization evidence. Tools have different default rules and coverage, so throughput alone does not rank engine efficiency. Unavailable and unsupported entries are not zero scores.

Hardware: `{"cpu": "Apple M2 Max", "logical_cpus": 12, "machine": "arm64", "memory_bytes": "103079215104", "python": "3.14.7", "system": "macOS-26.5.2-arm64-arm-64bit-Mach-O"}`

See the JSON artifact for versions, commands, exits, per-run timings, CPU, RSS, corpus hashes, labels and completeness. RSS is per-child getrusage peak; it is not a simultaneous aggregate for a multiprocess tree.
