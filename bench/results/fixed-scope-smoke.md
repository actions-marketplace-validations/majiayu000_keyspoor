# Secret scanner benchmark

Generated: 2026-10-02T18:08:20Z

Offline, default-rule end-to-end comparison. First-run is a new process, not a cold disk-cache claim. Warm runs start new processes after an unmeasured warmup. No provider validation is enabled. Raw scanner output is discarded.

| Tool | Dataset | Status | Median ms | MiB/s | Peak RSS MiB | TP/FP/FN | P/R/F1 |
|---|---|---|---:|---:|---:|---|---|
| gitleaks | quality | ok | 293.103 | 0.01 | 73.00 | 31/0/3 | 1.000/0.912/0.954 |
| gitleaks | git_history | ok | 298.107 | — | 67.78 | 1/0/0 | 1.000/1.000/1.000 |
| gitleaks | staged | ok | 289.343 | — | 67.48 | 1/0/0 | 1.000/1.000/1.000 |
| kingfisher | quality | ok | 395.071 | 0.01 | 182.55 | 24/0/10 | 1.000/0.706/0.828 |
| kingfisher | git_history | ok | 442.078 | — | 129.50 | 1/1/0 | 0.500/1.000/0.667 |
| kingfisher | staged | ok | 480.708 | — | 120.97 | 1/0/0 | 1.000/1.000/1.000 |
| betterleaks | quality | ok | 162.361 | 0.02 | 85.06 | 33/1/1 | 0.971/0.971/0.971 |
| betterleaks | git_history | ok | 66.345 | — | 36.41 | 1/0/0 | 1.000/1.000/1.000 |
| betterleaks | staged | ok | 53.404 | — | 35.77 | 1/0/0 | 1.000/1.000/1.000 |
| noseyparker | quality | ok | 408.803 | 0.01 | 247.42 | 26/2/8 | 0.929/0.765/0.839 |
| noseyparker | git_history | ok | 408.994 | — | 245.91 | 1/0/0 | 1.000/1.000/1.000 |
| noseyparker | staged | unsupported | — | — | — | — | — |

Precision is location-based on the labelled synthetic corpus, not a real-world false-positive estimate. Duplicate detections do not increase recall. Exact byte-span, overlapping-span and line-only matches are counted separately in JSON; line-only tools have weaker localization evidence. Tools have different default rules and coverage, so throughput alone does not rank engine efficiency. Unavailable and unsupported entries are not zero scores.

Hardware: `{"cpu": "Apple M2 Max", "logical_cpus": 12, "machine": "arm64", "memory_bytes": "103079215104", "python": "3.14.7", "system": "macOS-26.5.2-arm64-arm-64bit-Mach-O"}`

See the JSON artifact for versions, commands, exits, per-run timings, CPU, RSS, corpus hashes, labels and completeness. RSS is per-child getrusage peak; it is not a simultaneous aggregate for a multiprocess tree.
