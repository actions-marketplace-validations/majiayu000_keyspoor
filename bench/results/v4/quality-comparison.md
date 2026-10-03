# Secret scanner benchmark

Generated: 2026-10-03T11:34:49Z

Offline, default-rule end-to-end comparison. First-run is a new process, not a cold disk-cache claim. Warm runs start new processes after an unmeasured warmup. No provider validation is enabled. Raw scanner output is discarded.

| Tool | Dataset | Status | Median ms | Input MiB/s | Peak RSS MiB | TP/FP/FN | Unlocalized | Localized P / recall lower bound / F1 |
|---|---|---|---:|---:|---:|---|---:|---|
| secret-scan-before | quality | ok | 97.194 | 1.06 | 33.56 | 595/25/5 | 0 | 0.960/0.992/0.975 |
| secret-scan | quality | ok | 94.867 | 1.09 | 33.92 | 600/25/0 | 0 | 0.960/1.000/0.980 |
| gitleaks | quality | ok | 431.479 | 0.24 | 93.52 | 414/15/186 | 76 | 0.965/0.690/0.805 |
| trufflehog | quality | ok | 3270.605 | 0.03 | 187.45 | 290/0/310 | 39 | 1.000/0.483/0.652 |
| kingfisher | quality | ok | 536.248 | 0.19 | 216.27 | 340/0/260 | 68 | 1.000/0.567/0.723 |
| betterleaks | quality | ok | 328.904 | 0.31 | 105.55 | 484/15/116 | 60 | 0.970/0.807/0.881 |
| titus | quality | ok | 112.941 | 0.92 | 57.33 | 371/50/229 | 45 | 0.881/0.618/0.727 |
| ripsecrets | quality | ok | 59.302 | 1.74 | 129.20 | 206/0/394 | 14 | 1.000/0.343/0.511 |
| talisman | quality | unsupported | — | — | — | — | — | — |
| trivy | quality | ok | 124.178 | 0.83 | 110.73 | 313/0/287 | 60 | 1.000/0.522/0.686 |
| leakferret | quality | ok | 79.422 | 1.30 | 51.33 | 448/25/152 | 76 | 0.947/0.747/0.835 |
| noseyparker | quality | ok | 492.113 | 0.21 | 256.61 | 311/28/289 | 48 | 0.917/0.518/0.662 |
| rusty-hog | quality | ok | 119.799 | 0.86 | 33.56 | 95/0/505 | 10 | 1.000/0.158/0.273 |
| detect-secrets | quality | ok | 578.619 | 0.18 | 35.97 | 377/75/223 | 46 | 0.834/0.628/0.717 |
| deepsecrets | quality | ok | 1490.412 | 0.07 | 69.56 | 190/0/410 | 20 | 1.000/0.317/0.481 |
| whispers | quality | ok | 421.880 | 0.25 | 47.02 | 134/0/466 | 120 | 1.000/0.223/0.365 |
| secretlint | quality | ok | 210.701 | 0.49 | 97.19 | 244/0/356 | 40 | 1.000/0.407/0.578 |
| keyhog | quality | ok | 416.584 | 0.25 | 74.88 | 445/0/155 | 48 | 1.000/0.742/0.852 |
| git-secrets | quality | ok | 523.312 | 0.20 | 18.23 | 20/0/580 | 2 | 1.000/0.033/0.065 |
| credential-digger | quality | ok | 6075.034 | 0.02 | 643.38 | 80/25/520 | 2 | 0.762/0.133/0.227 |
| scratch-scanner-rs | quality | ok | 163.954 | 0.63 | 457.05 | 451/25/149 | 0 | 0.947/0.752/0.838 |
| deepfence-secretscanner | — | build_failed | — | — | — | — | — | — |
| ggshield | — | external_service_required | — | — | — | — | — | — |
| secrets-patterns-db | — | not_executable | — | — | — | — | — | — |

Schema/scoring v2: precision excludes unlocalized results and is conditional on localized unique findings, not a real-world false-positive estimate. Recall is a confirmed-location lower bound; unlocalized findings do not prove a miss or a hit. Duplicate detections do not increase recall. Exact byte-span, overlapping-span and line-only matches are counted separately in JSON; line-only tools have weaker localization evidence. Tools have different default rules and coverage, so throughput alone does not rank engine efficiency. Unavailable and unsupported entries are not zero scores.

Hardware: `{"cpu": "Apple M2 Max", "logical_cpus": 12, "machine": "arm64", "memory_bytes": "103079215104", "python": "3.14.7", "system": "macOS-26.5.2-arm64-arm-64bit-Mach-O"}`

See the JSON artifact for versions, commands, exits, per-run timings, CPU, RSS, corpus hashes, labels and completeness. RSS is per-child getrusage peak; it is not a simultaneous aggregate for a multiprocess tree.
