# Secret scanner benchmark

Generated: 2026-10-03T10:27:52Z

Offline, default-rule end-to-end comparison. First-run is a new process, not a cold disk-cache claim. Warm runs start new processes after an unmeasured warmup. No provider validation is enabled. Raw scanner output is discarded.

| Tool | Dataset | Status | Median ms | Input MiB/s | Peak RSS MiB | TP/FP/FN | Unlocalized | Localized P / recall lower bound / F1 |
|---|---|---|---:|---:|---:|---|---:|---|
| secret-scan | quality | ok | 51.497 | 0.05 | 23.30 | 34/0/0 | 0 | 1.000/1.000/1.000 |
| gitleaks | quality | ok | 418.161 | 0.01 | 73.20 | 31/0/3 | 0 | 1.000/0.912/0.954 |
| trufflehog | quality | ok | 832.667 | 0.00 | 163.08 | 18/0/16 | 0 | 1.000/0.529/0.692 |
| kingfisher | quality | ok | 410.104 | 0.01 | 184.14 | 24/0/10 | 0 | 1.000/0.706/0.828 |
| betterleaks | quality | ok | 183.125 | 0.01 | 79.11 | 33/1/1 | 0 | 0.971/0.971/0.971 |
| titus | quality | ok | 52.750 | 0.05 | 50.81 | 26/2/8 | 0 | 0.929/0.765/0.839 |
| ripsecrets | quality | ok | 47.667 | 0.05 | 123.03 | 27/0/7 | 0 | 1.000/0.794/0.885 |
| talisman | quality | unsupported | — | — | — | — | — | — |
| trivy | quality | ok | 109.898 | 0.02 | 99.78 | 24/0/10 | 0 | 1.000/0.706/0.828 |
| leakferret | quality | ok | 37.417 | 0.07 | 25.56 | 31/2/3 | 0 | 0.939/0.912/0.925 |
| noseyparker | quality | ok | 417.309 | 0.01 | 248.98 | 26/2/8 | 0 | 0.929/0.765/0.839 |
| rusty-hog | quality | ok | 96.989 | 0.03 | 34.83 | 17/0/17 | 0 | 1.000/0.500/0.667 |
| detect-secrets | quality | ok | 355.532 | 0.01 | 35.62 | 34/4/0 | 0 | 0.895/1.000/0.944 |
| deepsecrets | quality | ok | 695.789 | 0.00 | 56.86 | 19/0/15 | 0 | 1.000/0.559/0.717 |
| whispers | quality | ok | 145.184 | 0.02 | 35.91 | 21/4/13 | 44 | 0.840/0.618/0.712 |
| secretlint | quality | ok | 170.082 | 0.02 | 79.17 | 19/0/15 | 0 | 1.000/0.559/0.717 |
| keyhog | quality | ok | 317.333 | 0.01 | 72.06 | 13/0/21 | 0 | 1.000/0.382/0.553 |
| git-secrets | quality | ok | 614.755 | 0.00 | 18.25 | 3/0/31 | 0 | 1.000/0.088/0.162 |
| credential-digger | quality | ok | 6323.266 | 0.00 | 643.67 | 6/2/28 | 0 | 0.750/0.176/0.286 |
| scratch-scanner-rs | quality | ok | 173.440 | 0.01 | 416.98 | 30/1/4 | 0 | 0.968/0.882/0.923 |
| deepfence-secretscanner | — | build_failed | — | — | — | — | — | — |
| ggshield | — | external_service_required | — | — | — | — | — | — |
| secrets-patterns-db | — | not_executable | — | — | — | — | — | — |

Schema/scoring v2: precision excludes unlocalized results and is conditional on localized unique findings, not a real-world false-positive estimate. Recall is a confirmed-location lower bound; unlocalized findings do not prove a miss or a hit. Duplicate detections do not increase recall. Exact byte-span, overlapping-span and line-only matches are counted separately in JSON; line-only tools have weaker localization evidence. Tools have different default rules and coverage, so throughput alone does not rank engine efficiency. Unavailable and unsupported entries are not zero scores.

Hardware: `{"cpu": "Apple M2 Max", "logical_cpus": 12, "machine": "arm64", "memory_bytes": "103079215104", "python": "3.14.7", "system": "macOS-26.5.2-arm64-arm-64bit-Mach-O"}`

See the JSON artifact for versions, commands, exits, per-run timings, CPU, RSS, corpus hashes, labels and completeness. RSS is per-child getrusage peak; it is not a simultaneous aggregate for a multiprocess tree.
