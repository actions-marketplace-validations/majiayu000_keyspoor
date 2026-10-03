# Secret scanner benchmark

Generated: 2026-10-02T17:49:58Z

Offline, default-rule end-to-end comparison. First-run is a new process, not a cold disk-cache claim. Warm runs start new processes after an unmeasured warmup. No provider validation is enabled. Raw scanner output is discarded.

| Tool | Dataset | Status | Median ms | MiB/s | Peak RSS MiB | TP/FP/FN | P/R/F1 |
|---|---|---|---:|---:|---:|---|---|
| gitleaks | quality | ok | 339.374 | 0.01 | 74.39 | 31/0/3 | 1.000/0.912/0.954 |
| trufflehog | quality | ok | 762.615 | 0.00 | 165.11 | 18/0/16 | 1.000/0.529/0.692 |
| kingfisher | quality | failed | — | — | — | — | — |
| betterleaks | quality | ok | 226.954 | 0.01 | 76.30 | 33/1/1 | 0.971/0.971/0.971 |
| titus | quality | ok | 63.801 | 0.04 | 48.36 | 26/2/8 | 0.929/0.765/0.839 |
| ripsecrets | quality | ok | 54.089 | 0.05 | 81.92 | 27/0/7 | 1.000/0.794/0.885 |
| trivy | quality | ok | 109.080 | 0.02 | 101.09 | 24/0/10 | 1.000/0.706/0.828 |
| leakferret | quality | ok | 29.171 | 0.09 | 25.34 | 31/2/3 | 0.939/0.912/0.925 |
| detect-secrets | quality | ok | 421.973 | 0.01 | 35.41 | 34/4/0 | 0.895/1.000/0.944 |
| deepsecrets | quality | ok | 780.386 | 0.00 | 56.09 | 19/0/15 | 1.000/0.559/0.717 |
| secretlint | quality | ok | 222.646 | 0.01 | 82.20 | 19/0/15 | 1.000/0.559/0.717 |

Precision is location-based on the labelled synthetic corpus, not a real-world false-positive estimate. Duplicate detections do not increase recall. Exact byte-span, overlapping-span and line-only matches are counted separately in JSON; line-only tools have weaker localization evidence. Tools have different default rules and coverage, so throughput alone does not rank engine efficiency. Unavailable and unsupported entries are not zero scores.

Hardware: `{"cpu": "Apple M2 Max", "logical_cpus": 12, "machine": "arm64", "memory_bytes": "103079215104", "python": "3.14.7", "system": "macOS-26.5.2-arm64-arm-64bit-Mach-O"}`

See the JSON artifact for versions, commands, exits, per-run timings, CPU, RSS, corpus hashes, labels and completeness. RSS is per-child getrusage peak; it is not a simultaneous aggregate for a multiprocess tree.
