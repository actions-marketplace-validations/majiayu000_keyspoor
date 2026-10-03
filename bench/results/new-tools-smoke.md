# Secret scanner benchmark

Generated: 2026-10-02T18:05:41Z

Offline, default-rule end-to-end comparison. First-run is a new process, not a cold disk-cache claim. Warm runs start new processes after an unmeasured warmup. No provider validation is enabled. Raw scanner output is discarded.

| Tool | Dataset | Status | Median ms | MiB/s | Peak RSS MiB | TP/FP/FN | P/R/F1 |
|---|---|---|---:|---:|---:|---|---|
| gitleaks | quality | ok | 286.948 | 0.01 | 70.91 | 31/0/3 | 1.000/0.912/0.954 |
| gitleaks | git_history | ok | 302.107 | — | 71.53 | 1/0/0 | 1.000/1.000/1.000 |
| gitleaks | staged | ok | 287.645 | — | 68.58 | 1/0/0 | 1.000/1.000/1.000 |
| kingfisher | quality | nondeterministic | — | — | — | — | — |
| kingfisher | git_history | ok | 447.703 | — | 127.14 | 1/2/0 | 0.333/1.000/0.500 |
| kingfisher | staged | ok | 484.331 | — | 122.69 | 1/0/0 | 1.000/1.000/1.000 |
| betterleaks | quality | ok | 189.018 | 0.01 | 80.53 | 33/1/1 | 0.971/0.971/0.971 |
| betterleaks | git_history | ok | 67.024 | — | 36.19 | 1/0/0 | 1.000/1.000/1.000 |
| betterleaks | staged | ok | 74.028 | — | 40.44 | 1/0/0 | 1.000/1.000/1.000 |
| noseyparker | quality | ok | 411.328 | 0.01 | 247.56 | 26/2/8 | 0.929/0.765/0.839 |
| noseyparker | git_history | ok | 411.277 | — | 246.27 | 1/3/0 | 0.250/1.000/0.400 |
| noseyparker | staged | unsupported | — | — | — | — | — |
| keyhog | quality | ok | 312.164 | 0.01 | 69.77 | 13/0/21 | 1.000/0.382/0.553 |
| keyhog | git_history | ok | 298.088 | — | 70.80 | 0/0/1 | —/0.000/0.000 |
| keyhog | staged | unsupported | — | — | — | — | — |
| git-secrets | quality | ok | 439.595 | 0.01 | 18.30 | 3/0/31 | 1.000/0.088/0.162 |
| git-secrets | git_history | ok | 452.935 | — | 18.28 | 0/0/1 | —/0.000/0.000 |
| git-secrets | staged | ok | 459.992 | — | 18.33 | 0/0/1 | —/0.000/0.000 |

Precision is location-based on the labelled synthetic corpus, not a real-world false-positive estimate. Duplicate detections do not increase recall. Exact byte-span, overlapping-span and line-only matches are counted separately in JSON; line-only tools have weaker localization evidence. Tools have different default rules and coverage, so throughput alone does not rank engine efficiency. Unavailable and unsupported entries are not zero scores.

Hardware: `{"cpu": "Apple M2 Max", "logical_cpus": 12, "machine": "arm64", "memory_bytes": "103079215104", "python": "3.14.7", "system": "macOS-26.5.2-arm64-arm-64bit-Mach-O"}`

See the JSON artifact for versions, commands, exits, per-run timings, CPU, RSS, corpus hashes, labels and completeness. RSS is per-child getrusage peak; it is not a simultaneous aggregate for a multiprocess tree.
