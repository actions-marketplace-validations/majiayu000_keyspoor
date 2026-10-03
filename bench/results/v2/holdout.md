# Secret scanner benchmark

Generated: 2026-10-03T10:29:00Z

Offline, default-rule end-to-end comparison. First-run is a new process, not a cold disk-cache claim. Warm runs start new processes after an unmeasured warmup. No provider validation is enabled. Raw scanner output is discarded.

| Tool | Dataset | Status | Median ms | Input MiB/s | Peak RSS MiB | TP/FP/FN | Unlocalized | Localized P / recall lower bound / F1 |
|---|---|---|---:|---:|---:|---|---:|---|
| secret-scan | quality | ok | 74.007 | 0.98 | 34.95 | 599/25/1 | 0 | 0.960/0.998/0.979 |
| gitleaks | quality | ok | 868.254 | 0.08 | 99.75 | 493/14/107 | 0 | 0.972/0.822/0.891 |
| trufflehog | quality | ok | 927.975 | 0.08 | 192.05 | 342/0/258 | 0 | 1.000/0.570/0.726 |
| kingfisher | quality | ok | 608.842 | 0.12 | 217.44 | 409/0/191 | 0 | 1.000/0.682/0.811 |
| betterleaks | quality | ok | 276.993 | 0.26 | 107.23 | 553/14/47 | 0 | 0.975/0.922/0.948 |
| titus | quality | ok | 149.586 | 0.49 | 56.98 | 433/50/167 | 0 | 0.896/0.722/0.800 |
| ripsecrets | quality | ok | 65.476 | 1.11 | 131.39 | 239/0/361 | 0 | 1.000/0.398/0.570 |
| talisman | quality | unsupported | — | — | — | — | — | — |
| trivy | quality | ok | 147.355 | 0.49 | 113.92 | 376/0/224 | 0 | 1.000/0.627/0.770 |
| leakferret | quality | ok | 102.657 | 0.71 | 54.97 | 532/25/68 | 0 | 0.955/0.887/0.920 |
| noseyparker | quality | ok | 720.804 | 0.10 | 257.78 | 359/28/241 | 0 | 0.928/0.598/0.727 |
| rusty-hog | quality | ok | 168.037 | 0.43 | 34.41 | 111/0/489 | 0 | 1.000/0.185/0.312 |
| detect-secrets | quality | ok | 785.445 | 0.09 | 36.14 | 400/75/200 | 0 | 0.842/0.667/0.744 |
| deepsecrets | quality | ok | 1527.143 | 0.05 | 71.77 | 209/0/391 | 0 | 1.000/0.348/0.517 |
| whispers | quality | ok | 611.260 | 0.12 | 47.05 | 155/0/445 | 120 | 1.000/0.258/0.411 |
| secretlint | quality | ok | 287.784 | 0.25 | 96.94 | 288/0/312 | 0 | 1.000/0.480/0.649 |
| keyhog | quality | ok | 430.303 | 0.17 | 75.97 | 515/0/85 | 0 | 1.000/0.858/0.924 |
| git-secrets | quality | ok | 534.360 | 0.14 | 18.20 | 24/0/576 | 0 | 1.000/0.040/0.077 |
| credential-digger | quality | ok | 6578.581 | 0.01 | 643.00 | 84/25/516 | 0 | 0.771/0.140/0.237 |
| scratch-scanner-rs | quality | ok | 154.521 | 0.47 | 458.16 | 470/25/130 | 0 | 0.949/0.783/0.858 |
| deepfence-secretscanner | — | build_failed | — | — | — | — | — | — |
| ggshield | — | external_service_required | — | — | — | — | — | — |
| secrets-patterns-db | — | not_executable | — | — | — | — | — | — |

Schema/scoring v2: precision excludes unlocalized results and is conditional on localized unique findings, not a real-world false-positive estimate. Recall is a confirmed-location lower bound; unlocalized findings do not prove a miss or a hit. Duplicate detections do not increase recall. Exact byte-span, overlapping-span and line-only matches are counted separately in JSON; line-only tools have weaker localization evidence. Tools have different default rules and coverage, so throughput alone does not rank engine efficiency. Unavailable and unsupported entries are not zero scores.

Hardware: `{"cpu": "Apple M2 Max", "logical_cpus": 12, "machine": "arm64", "memory_bytes": "103079215104", "python": "3.14.7", "system": "macOS-26.5.2-arm64-arm-64bit-Mach-O"}`

See the JSON artifact for versions, commands, exits, per-run timings, CPU, RSS, corpus hashes, labels and completeness. RSS is per-child getrusage peak; it is not a simultaneous aggregate for a multiprocess tree.
