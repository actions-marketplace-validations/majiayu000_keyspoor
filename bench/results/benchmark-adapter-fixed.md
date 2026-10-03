# Secret scanner benchmark

Generated: 2026-10-02T18:46:12Z

Offline, default-rule end-to-end comparison. First-run is a new process, not a cold disk-cache claim. Warm runs start new processes after an unmeasured warmup. No provider validation is enabled. Raw scanner output is discarded.

| Tool | Dataset | Status | Median ms | Input MiB/s | Peak RSS MiB | TP/FP/FN | P/R/F1 |
|---|---|---|---:|---:|---:|---|---|
| talisman | quality | unsupported | — | — | — | — | — |
| talisman | capabilities | unsupported | — | — | — | — | — |
| talisman | throughput-1mib | unsupported | — | — | — | — | — |
| talisman | throughput-16mib | unsupported | — | — | — | — | — |
| talisman | throughput-128mib | unsupported | — | — | — | — | — |
| talisman | git_history | ok | 120.763 | — | 21.05 | — | — |
| talisman | staged | ok | 162.980 | — | 19.47 | — | — |
| talisman | real-regex | unsupported | — | — | — | — | — |
| rusty-hog | quality | ok | 88.545 | 0.03 | 33.75 | 17/0/17 | 1.000/0.500/0.667 |
| rusty-hog | capabilities | ok | 86.146 | 0.74 | 34.69 | 0/0/6 | —/0.000/0.000 |
| rusty-hog | throughput-1mib | ok | 160.158 | 6.24 | 33.16 | 0/0/1 | —/0.000/0.000 |
| rusty-hog | throughput-16mib | ok | 1000.618 | 15.99 | 35.23 | 0/0/16 | —/0.000/0.000 |
| rusty-hog | throughput-128mib | ok | 7137.801 | 17.93 | 33.52 | 0/0/128 | —/0.000/0.000 |
| rusty-hog | git_history | unsupported | — | — | — | — | — |
| rusty-hog | staged | unsupported | — | — | — | — | — |
| rusty-hog | real-regex | ok | 688.843 | 11.68 | 35.64 | — | — |
| credential-digger | quality | ok | 5620.849 | 0.00 | 643.86 | 6/2/28 | 0.750/0.176/0.286 |
| credential-digger | capabilities | ok | 5518.494 | 0.01 | 642.72 | 0/0/6 | —/0.000/0.000 |
| credential-digger | throughput-1mib | ok | 5676.812 | 0.18 | 643.77 | 0/0/1 | —/0.000/0.000 |
| credential-digger | throughput-16mib | ok | 5780.915 | 2.77 | 642.59 | 0/0/16 | —/0.000/0.000 |
| credential-digger | throughput-128mib | ok | 7005.827 | 18.27 | 643.17 | 0/0/128 | —/0.000/0.000 |
| credential-digger | git_history | unsupported | — | — | — | — | — |
| credential-digger | staged | unsupported | — | — | — | — | — |
| credential-digger | real-regex | ok | 5804.438 | 1.39 | 643.34 | — | — |
| scratch-scanner-rs | quality | ok | 144.510 | 0.02 | 407.53 | 30/1/4 | 0.968/0.882/0.923 |
| scratch-scanner-rs | capabilities | ok | 141.926 | 0.45 | 416.97 | 1/0/5 | 1.000/0.167/0.286 |
| scratch-scanner-rs | throughput-1mib | ok | 143.195 | 6.98 | 431.72 | 1/0/0 | 1.000/1.000/1.000 |
| scratch-scanner-rs | throughput-16mib | ok | 148.817 | 107.51 | 452.47 | 15/0/1 | 1.000/0.938/0.968 |
| scratch-scanner-rs | throughput-128mib | ok | 191.737 | 667.58 | 455.12 | 114/0/14 | 1.000/0.891/0.942 |
| scratch-scanner-rs | git_history | ok | 175.191 | — | 212.53 | 1/0/0 | 1.000/1.000/1.000 |
| scratch-scanner-rs | staged | unsupported | — | — | — | — | — |
| scratch-scanner-rs | real-regex | ok | 147.766 | 54.44 | 452.62 | — | — |

Precision is location-based on the labelled synthetic corpus, not a real-world false-positive estimate. Duplicate detections do not increase recall. Exact byte-span, overlapping-span and line-only matches are counted separately in JSON; line-only tools have weaker localization evidence. Tools have different default rules and coverage, so throughput alone does not rank engine efficiency. Unavailable and unsupported entries are not zero scores.

Hardware: `{"cpu": "Apple M2 Max", "logical_cpus": 12, "machine": "arm64", "memory_bytes": "103079215104", "python": "3.14.7", "system": "macOS-26.5.2-arm64-arm-64bit-Mach-O"}`

See the JSON artifact for versions, commands, exits, per-run timings, CPU, RSS, corpus hashes, labels and completeness. RSS is per-child getrusage peak; it is not a simultaneous aggregate for a multiprocess tree.
