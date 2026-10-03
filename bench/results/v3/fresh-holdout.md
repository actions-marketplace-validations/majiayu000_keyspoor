# Secret scanner benchmark

Generated: 2026-10-03T11:01:44Z

Offline, default-rule end-to-end comparison. First-run is a new process, not a cold disk-cache claim. Warm runs start new processes after an unmeasured warmup. No provider validation is enabled. Raw scanner output is discarded.

| Tool | Dataset | Status | Median ms | Input MiB/s | Peak RSS MiB | TP/FP/FN | Unlocalized | Localized P / recall lower bound / F1 |
|---|---|---|---:|---:|---:|---|---:|---|
| secret-scan-before | quality | ok | 84.420 | 1.22 | 34.64 | 595/25/5 | 0 | 0.960/0.992/0.975 |
| secret-scan | quality | ok | 66.724 | 1.55 | 34.33 | 595/25/5 | 0 | 0.960/0.992/0.975 |
| gitleaks | quality | ok | 384.808 | 0.27 | 95.94 | 414/15/186 | 76 | 0.965/0.690/0.805 |
| trufflehog | quality | ok | 1658.062 | 0.06 | 199.28 | 290/0/310 | 39 | 1.000/0.483/0.652 |
| kingfisher | quality | ok | 814.744 | 0.13 | 214.22 | 340/0/260 | 68 | 1.000/0.567/0.723 |
| betterleaks | quality | ok | 332.760 | 0.31 | 105.25 | 484/15/116 | 60 | 0.970/0.807/0.881 |
| titus | quality | ok | 140.518 | 0.74 | 57.14 | 371/50/229 | 45 | 0.881/0.618/0.727 |
| ripsecrets | quality | ok | 79.167 | 1.31 | 129.42 | 206/0/394 | 14 | 1.000/0.343/0.511 |
| talisman | quality | unsupported | — | — | — | — | — | — |
| trivy | quality | ok | 175.267 | 0.59 | 112.47 | 313/0/287 | 60 | 1.000/0.522/0.686 |
| leakferret | quality | ok | 124.840 | 0.83 | 52.77 | 448/25/152 | 76 | 0.947/0.747/0.835 |
| noseyparker | quality | ok | 576.026 | 0.18 | 257.88 | 311/28/289 | 48 | 0.917/0.518/0.662 |
| rusty-hog | quality | ok | 118.201 | 0.87 | 34.58 | 95/0/505 | 10 | 1.000/0.158/0.273 |
| detect-secrets | quality | ok | 643.458 | 0.16 | 36.22 | 377/75/223 | 46 | 0.834/0.628/0.717 |
| deepsecrets | quality | ok | 1695.575 | 0.06 | 72.69 | 190/0/410 | 20 | 1.000/0.317/0.481 |
| whispers | quality | ok | 458.298 | 0.23 | 47.20 | 134/0/466 | 120 | 1.000/0.223/0.365 |
| secretlint | quality | ok | 234.202 | 0.44 | 98.33 | 244/0/356 | 40 | 1.000/0.407/0.578 |
| keyhog | quality | ok | 422.859 | 0.24 | 74.89 | 445/0/155 | 48 | 1.000/0.742/0.852 |
| git-secrets | quality | ok | 578.233 | 0.18 | 18.48 | 20/0/580 | 2 | 1.000/0.033/0.065 |
| credential-digger | quality | ok | 8515.466 | 0.01 | 643.12 | 80/25/520 | 2 | 0.762/0.133/0.227 |
| scratch-scanner-rs | quality | ok | 183.494 | 0.56 | 457.34 | 451/25/149 | 0 | 0.947/0.752/0.838 |
| deepfence-secretscanner | — | build_failed | — | — | — | — | — | — |
| ggshield | — | external_service_required | — | — | — | — | — | — |
| secrets-patterns-db | — | not_executable | — | — | — | — | — | — |

Schema/scoring v2: precision excludes unlocalized results and is conditional on localized unique findings, not a real-world false-positive estimate. Recall is a confirmed-location lower bound; unlocalized findings do not prove a miss or a hit. Duplicate detections do not increase recall. Exact byte-span, overlapping-span and line-only matches are counted separately in JSON; line-only tools have weaker localization evidence. Tools have different default rules and coverage, so throughput alone does not rank engine efficiency. Unavailable and unsupported entries are not zero scores.

Hardware: `{"cpu": "Apple M2 Max", "logical_cpus": 12, "machine": "arm64", "memory_bytes": "103079215104", "python": "3.14.7", "system": "macOS-26.5.2-arm64-arm-64bit-Mach-O"}`

See the JSON artifact for versions, commands, exits, per-run timings, CPU, RSS, corpus hashes, labels and completeness. RSS is per-child getrusage peak; it is not a simultaneous aggregate for a multiprocess tree.
