# Secret scanner benchmark

Generated: 2026-10-02T18:13:57Z

Offline, default-rule end-to-end comparison. First-run is a new process, not a cold disk-cache claim. Warm runs start new processes after an unmeasured warmup. No provider validation is enabled. Raw scanner output is discarded.

| Tool | Dataset | Status | Median ms | Input MiB/s | Peak RSS MiB | TP/FP/FN | P/R/F1 |
|---|---|---|---:|---:|---:|---|---|
| secret-scan | quality | ok | 31.004 | 0.08 | 19.97 | 29/1/5 | 0.967/0.853/0.906 |
| secret-scan | capabilities | ok | 30.709 | 2.06 | 18.52 | 6/0/0 | 1.000/1.000/1.000 |
| secret-scan | throughput-1mib | ok | 31.265 | 31.98 | 20.05 | 1/0/0 | 1.000/1.000/1.000 |
| secret-scan | throughput-16mib | ok | 51.293 | 311.93 | 22.55 | 16/0/0 | 1.000/1.000/1.000 |
| secret-scan | git_history | ok | 87.654 | — | 17.00 | 1/0/0 | 1.000/1.000/1.000 |
| secret-scan | staged | ok | 68.808 | — | 16.94 | 1/0/0 | 1.000/1.000/1.000 |
| secret-scan | real-regex | ok | 65.413 | 122.97 | 23.88 | — | — |
| gitleaks | quality | ok | 303.446 | 0.01 | 74.39 | 31/0/3 | 1.000/0.912/0.954 |
| gitleaks | capabilities | ok | 278.860 | 0.23 | 70.02 | 5/0/1 | 1.000/0.833/0.909 |
| gitleaks | throughput-1mib | ok | 280.386 | 3.57 | 72.58 | 1/0/0 | 1.000/1.000/1.000 |
| gitleaks | throughput-16mib | ok | 316.463 | 50.56 | 113.34 | 16/0/0 | 1.000/1.000/1.000 |
| gitleaks | git_history | ok | 305.017 | — | 70.27 | 1/0/0 | 1.000/1.000/1.000 |
| gitleaks | staged | ok | 291.309 | — | 69.69 | 1/0/0 | 1.000/1.000/1.000 |
| gitleaks | real-regex | ok | 377.272 | 21.32 | 103.02 | — | — |
| trufflehog | quality | ok | 708.821 | 0.00 | 164.62 | 18/0/16 | 1.000/0.529/0.692 |
| trufflehog | capabilities | ok | 693.357 | 0.09 | 167.36 | 5/0/1 | 1.000/0.833/0.909 |
| trufflehog | throughput-1mib | ok | 732.555 | 1.37 | 161.03 | 1/0/0 | 1.000/1.000/1.000 |
| trufflehog | throughput-16mib | ok | 1057.759 | 15.13 | 196.62 | 16/0/0 | 1.000/1.000/1.000 |
| trufflehog | git_history | ok | 1208.442 | — | 160.66 | 1/0/0 | 1.000/1.000/1.000 |
| trufflehog | staged | unsupported | — | — | — | — | — |
| trufflehog | real-regex | ok | 1209.627 | 6.65 | 250.41 | — | — |
| kingfisher | quality | ok | 555.507 | 0.00 | 185.39 | 24/0/10 | 1.000/0.706/0.828 |
| kingfisher | capabilities | ok | 513.804 | 0.12 | 141.27 | 6/0/0 | 1.000/1.000/1.000 |
| kingfisher | throughput-1mib | ok | 487.605 | 2.05 | 124.80 | 1/0/0 | 1.000/1.000/1.000 |
| kingfisher | throughput-16mib | ok | 575.757 | 27.79 | 152.22 | 16/0/0 | 1.000/1.000/1.000 |
| kingfisher | git_history | ok | 680.857 | — | 129.30 | 1/0/0 | 1.000/1.000/1.000 |
| kingfisher | staged | ok | 725.156 | — | 123.55 | 1/0/0 | 1.000/1.000/1.000 |
| kingfisher | real-regex | ok | 539.427 | 14.91 | 110.02 | — | — |
| betterleaks | quality | ok | 202.764 | 0.01 | 78.62 | 33/1/1 | 0.971/0.971/0.971 |
| betterleaks | capabilities | ok | 71.499 | 0.89 | 41.84 | 5/0/1 | 1.000/0.833/0.909 |
| betterleaks | throughput-1mib | ok | 70.157 | 14.25 | 37.41 | 1/0/0 | 1.000/1.000/1.000 |
| betterleaks | throughput-16mib | ok | 124.604 | 128.41 | 67.94 | 16/0/0 | 1.000/1.000/1.000 |
| betterleaks | git_history | ok | 119.659 | — | 36.50 | 1/0/0 | 1.000/1.000/1.000 |
| betterleaks | staged | ok | 81.923 | — | 36.19 | 1/0/0 | 1.000/1.000/1.000 |
| betterleaks | real-regex | ok | 148.831 | 54.05 | 64.73 | — | — |
| titus | quality | ok | 79.226 | 0.03 | 47.94 | 26/2/8 | 0.929/0.765/0.839 |
| titus | capabilities | ok | 65.126 | 0.97 | 47.28 | 4/0/2 | 1.000/0.667/0.800 |
| titus | throughput-1mib | ok | 80.779 | 12.38 | 53.08 | 1/0/0 | 1.000/1.000/1.000 |
| titus | throughput-16mib | ok | 136.196 | 117.48 | 114.75 | 16/0/0 | 1.000/1.000/1.000 |
| titus | git_history | ok | 146.859 | — | 47.61 | 1/0/0 | 1.000/1.000/1.000 |
| titus | staged | unsupported | — | — | — | — | — |
| titus | real-regex | ok | 140.631 | 57.20 | 72.39 | — | — |
| ripsecrets | quality | ok | 59.521 | 0.04 | 123.05 | 27/0/7 | 1.000/0.794/0.885 |
| ripsecrets | capabilities | ok | 88.778 | 0.71 | 90.05 | 5/0/1 | 1.000/0.833/0.909 |
| ripsecrets | throughput-1mib | ok | 173.091 | 5.78 | 60.88 | 1/0/0 | 1.000/1.000/1.000 |
| ripsecrets | throughput-16mib | ok | 962.642 | 16.62 | 118.89 | 16/0/0 | 1.000/1.000/1.000 |
| ripsecrets | git_history | unsupported | — | — | — | — | — |
| ripsecrets | staged | unsupported | — | — | — | — | — |
| ripsecrets | real-regex | ok | 518.366 | 15.52 | 125.16 | — | — |
| talisman | — | adapter_pending | — | — | — | — | — |
| trivy | quality | ok | 117.373 | 0.02 | 101.66 | 24/0/10 | 1.000/0.706/0.828 |
| trivy | capabilities | ok | 146.354 | 0.43 | 98.66 | 2/1/4 | 0.667/0.333/0.444 |
| trivy | throughput-1mib | ok | 114.942 | 8.70 | 98.47 | 1/0/0 | 1.000/1.000/1.000 |
| trivy | throughput-16mib | ok | 127.783 | 125.21 | 102.36 | 16/0/0 | 1.000/1.000/1.000 |
| trivy | git_history | unsupported | — | — | — | — | — |
| trivy | staged | unsupported | — | — | — | — | — |
| trivy | real-regex | ok | 182.410 | 44.10 | 107.12 | — | — |
| leakferret | quality | ok | 54.689 | 0.05 | 25.41 | 31/2/3 | 0.939/0.912/0.925 |
| leakferret | capabilities | ok | 30.647 | 2.07 | 18.88 | 0/0/6 | —/0.000/0.000 |
| leakferret | throughput-1mib | ok | 36.894 | 27.10 | 21.00 | 1/0/0 | 1.000/1.000/1.000 |
| leakferret | throughput-16mib | ok | 88.251 | 181.30 | 29.67 | 16/0/0 | 1.000/1.000/1.000 |
| leakferret | git_history | ok | 53.141 | — | 18.56 | 1/0/0 | 1.000/1.000/1.000 |
| leakferret | staged | unsupported | — | — | — | — | — |
| leakferret | real-regex | ok | 315.294 | 25.51 | 32.30 | — | — |
| noseyparker | quality | ok | 487.910 | 0.01 | 247.16 | 26/2/8 | 0.929/0.765/0.839 |
| noseyparker | capabilities | ok | 523.144 | 0.12 | 246.81 | 4/0/2 | 1.000/0.667/0.800 |
| noseyparker | throughput-1mib | ok | 497.409 | 2.01 | 248.91 | 1/0/0 | 1.000/1.000/1.000 |
| noseyparker | throughput-16mib | ok | 535.365 | 29.89 | 289.78 | 16/0/0 | 1.000/1.000/1.000 |
| noseyparker | git_history | ok | 534.169 | — | 249.95 | 1/0/0 | 1.000/1.000/1.000 |
| noseyparker | staged | unsupported | — | — | — | — | — |
| noseyparker | real-regex | ok | 503.015 | 15.99 | 261.38 | — | — |
| rusty-hog | — | runtime_failed | — | — | — | — | — |
| detect-secrets | quality | ok | 487.588 | 0.01 | 35.73 | 34/4/0 | 0.895/1.000/0.944 |
| detect-secrets | capabilities | ok | 46505.122 | 0.00 | 35.81 | 4/0/2 | 1.000/0.667/0.800 |
| detect-secrets | throughput-1mib | ok | 945.303 | 1.06 | 38.41 | 1/0/0 | 1.000/1.000/1.000 |
| detect-secrets | throughput-16mib | ok | 5987.141 | 2.67 | 41.02 | 16/0/0 | 1.000/1.000/1.000 |
| detect-secrets | git_history | unsupported | — | — | — | — | — |
| detect-secrets | staged | unsupported | — | — | — | — | — |
| detect-secrets | real-regex | ok | 3883.494 | 2.07 | 48.84 | — | — |
| deepsecrets | quality | ok | 834.757 | 0.00 | 57.03 | 19/0/15 | 1.000/0.559/0.717 |
| deepsecrets | capabilities | ok | 699.622 | 0.09 | 55.58 | 4/0/2 | 1.000/0.667/0.800 |
| deepsecrets | throughput-1mib | ok | 792.814 | 1.26 | 56.98 | 1/0/0 | 1.000/1.000/1.000 |
| deepsecrets | throughput-16mib | ok | 3234.447 | 4.95 | 74.05 | 16/0/0 | 1.000/1.000/1.000 |
| deepsecrets | git_history | unsupported | — | — | — | — | — |
| deepsecrets | staged | unsupported | — | — | — | — | — |
| deepsecrets | real-regex | ok | 7840.447 | 1.03 | 86.81 | — | — |
| whispers | quality | ok | 151.768 | 0.02 | 36.03 | 21/48/13 | 0.304/0.618/0.408 |
| whispers | capabilities | ok | 145.463 | 0.44 | 35.89 | 0/2/6 | 0.000/0.000/0.000 |
| whispers | throughput-1mib | ok | 164.201 | 6.09 | 35.97 | 0/0/1 | —/0.000/0.000 |
| whispers | throughput-16mib | ok | 154.243 | 103.73 | 36.00 | 0/0/16 | —/0.000/0.000 |
| whispers | git_history | unsupported | — | — | — | — | — |
| whispers | staged | unsupported | — | — | — | — | — |
| whispers | real-regex | ok | 267.842 | 30.03 | 35.95 | — | — |
| secretlint | quality | invalid_input_selection | — | — | — | — | — |
| secretlint | capabilities | invalid_input_selection | — | — | — | — | — |
| secretlint | throughput-1mib | invalid_input_selection | — | — | — | — | — |
| secretlint | throughput-16mib | invalid_input_selection | — | — | — | — | — |
| secretlint | git_history | unsupported | — | — | — | — | — |
| secretlint | staged | unsupported | — | — | — | — | — |
| secretlint | real-regex | invalid_input_selection | — | — | — | — | — |
| keyhog | quality | ok | 346.224 | 0.01 | 69.83 | 13/0/21 | 1.000/0.382/0.553 |
| keyhog | capabilities | ok | 457.466 | 0.14 | 81.53 | 1/0/5 | 1.000/0.167/0.286 |
| keyhog | throughput-1mib | ok | 304.591 | 3.28 | 59.11 | 0/0/1 | —/0.000/0.000 |
| keyhog | throughput-16mib | ok | 485.180 | 32.98 | 77.84 | 0/0/16 | —/0.000/0.000 |
| keyhog | git_history | ok | 306.959 | — | 70.52 | 0/0/1 | —/0.000/0.000 |
| keyhog | staged | unsupported | — | — | — | — | — |
| keyhog | real-regex | failed | — | — | — | — | — |
| git-secrets | quality | ok | 492.151 | 0.01 | 18.19 | 3/0/31 | 1.000/0.088/0.162 |
| git-secrets | capabilities | ok | 687.467 | 0.09 | 18.36 | 0/0/6 | —/0.000/0.000 |
| git-secrets | throughput-1mib | ok | 1504.959 | 0.66 | 18.36 | 0/0/1 | —/0.000/0.000 |
| git-secrets | throughput-16mib | ok | 17924.920 | 0.89 | 18.47 | 0/0/16 | —/0.000/0.000 |
| git-secrets | git_history | ok | 482.812 | — | 18.27 | 0/0/1 | —/0.000/0.000 |
| git-secrets | staged | ok | 427.201 | — | 18.25 | 0/0/1 | —/0.000/0.000 |
| git-secrets | real-regex | ok | 7938.901 | 1.01 | 18.45 | — | — |
| credential-digger | — | runtime_failed | — | — | — | — | — |
| scratch-scanner-rs | — | build_failed | — | — | — | — | — |
| deepfence-secretscanner | — | build_failed | — | — | — | — | — |
| ggshield | — | external_service_required | — | — | — | — | — |
| secrets-patterns-db | — | not_executable | — | — | — | — | — |

Precision is location-based on the labelled synthetic corpus, not a real-world false-positive estimate. Duplicate detections do not increase recall. Exact byte-span, overlapping-span and line-only matches are counted separately in JSON; line-only tools have weaker localization evidence. Tools have different default rules and coverage, so throughput alone does not rank engine efficiency. Unavailable and unsupported entries are not zero scores.

Hardware: `{"cpu": "Apple M2 Max", "logical_cpus": 12, "machine": "arm64", "memory_bytes": "103079215104", "python": "3.14.7", "system": "macOS-26.5.2-arm64-arm-64bit-Mach-O"}`

See the JSON artifact for versions, commands, exits, per-run timings, CPU, RSS, corpus hashes, labels and completeness. RSS is per-child getrusage peak; it is not a simultaneous aggregate for a multiprocess tree.
