# Secret scanner benchmark

Generated: 2026-10-03T10:30:26Z

Offline, default-rule end-to-end comparison. First-run is a new process, not a cold disk-cache claim. Warm runs start new processes after an unmeasured warmup. No provider validation is enabled. Raw scanner output is discarded.

| Tool | Dataset | Status | Median ms | Input MiB/s | Peak RSS MiB | TP/FP/FN | Unlocalized | Localized P / recall lower bound / F1 |
|---|---|---|---:|---:|---:|---|---:|---|
| secret-scan | throughput-16mib | ok | 59.753 | 267.77 | 22.59 | 16/0/0 | 0 | 1.000/1.000/1.000 |
| secret-scan | throughput-128mib | ok | 225.302 | 568.13 | 23.95 | 128/0/0 | 0 | 1.000/1.000/1.000 |
| secret-scan | real-regex | ok | 84.627 | 95.05 | 30.62 | — | — | — |
| gitleaks | throughput-16mib | ok | 721.102 | 22.19 | 107.28 | 16/0/0 | 0 | 1.000/1.000/1.000 |
| gitleaks | throughput-128mib | ok | 1300.683 | 98.41 | 275.88 | 128/0/0 | 0 | 1.000/1.000/1.000 |
| gitleaks | real-regex | ok | 613.529 | 13.11 | 103.45 | — | — | — |
| kingfisher | throughput-16mib | ok | 617.264 | 25.92 | 149.97 | 16/0/0 | 0 | 1.000/1.000/1.000 |
| kingfisher | throughput-128mib | ok | 766.056 | 167.09 | 151.52 | 128/0/0 | 0 | 1.000/1.000/1.000 |
| kingfisher | real-regex | ok | 647.681 | 12.42 | 121.52 | — | — | — |
| betterleaks | throughput-16mib | ok | 101.876 | 157.05 | 60.09 | 16/0/0 | 0 | 1.000/1.000/1.000 |
| betterleaks | throughput-128mib | ok | 241.527 | 529.96 | 106.23 | 128/0/0 | 0 | 1.000/1.000/1.000 |
| betterleaks | real-regex | ok | 110.599 | 72.73 | 68.97 | — | — | — |
| trivy | throughput-16mib | ok | 95.991 | 166.68 | 100.97 | 16/0/0 | 0 | 1.000/1.000/1.000 |
| trivy | throughput-128mib | ok | 165.228 | 774.69 | 109.78 | 128/0/0 | 0 | 1.000/1.000/1.000 |
| trivy | real-regex | ok | 122.717 | 65.55 | 106.66 | — | — | — |
| scratch-scanner-rs | throughput-16mib | ok | 154.785 | 103.37 | 454.75 | 15/0/1 | 0 | 1.000/0.938/0.968 |
| scratch-scanner-rs | throughput-128mib | ok | 201.354 | 635.70 | 455.41 | 114/0/14 | 0 | 1.000/0.891/0.942 |
| scratch-scanner-rs | real-regex | ok | 154.611 | 52.03 | 453.55 | — | — | — |

Schema/scoring v2: precision excludes unlocalized results and is conditional on localized unique findings, not a real-world false-positive estimate. Recall is a confirmed-location lower bound; unlocalized findings do not prove a miss or a hit. Duplicate detections do not increase recall. Exact byte-span, overlapping-span and line-only matches are counted separately in JSON; line-only tools have weaker localization evidence. Tools have different default rules and coverage, so throughput alone does not rank engine efficiency. Unavailable and unsupported entries are not zero scores.

Hardware: `{"cpu": "Apple M2 Max", "logical_cpus": 12, "machine": "arm64", "memory_bytes": "103079215104", "python": "3.14.7", "system": "macOS-26.5.2-arm64-arm-64bit-Mach-O"}`

See the JSON artifact for versions, commands, exits, per-run timings, CPU, RSS, corpus hashes, labels and completeness. RSS is per-child getrusage peak; it is not a simultaneous aggregate for a multiprocess tree.
