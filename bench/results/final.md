# Final measured comparison

Development-informed synthetic regression results, not an independent holdout. Real-source results have no accuracy labels. Default rule sets differ; input throughput alone is not an efficiency or accuracy ranking.

Three AWS-labelled synthetic candidates contain 9 in their suffix, outside the imported Gitleaks AWS-specific [A-Z2-7] format. They remain broad configuration-candidate labels, not valid or active AWS credentials. Labels were not removed after observing results; precision/recall is candidate-label performance, not real AWS credential recall.

| Tool | Quality TP / FP / FN | 16 MiB, ms (TP/labels) | 128 MiB, ms (TP/labels) | Real source, ms | Real peak RSS, MiB | Quality status |
|---|---|---:|---:|---:|---:|---|
| secret-scan | 31 / 0 / 3 | 55.5 (16/16) | 205.9 (128/128) | 69.1 | 24.2 | ok |
| gitleaks | 31 / 0 / 3 | 316.5 (16/16) | 740.3 (128/128) | 377.3 | 103.0 | ok |
| trufflehog | 18 / 0 / 16 | 1057.8 (16/16) | — | 1209.6 | 250.4 | ok |
| kingfisher | 24 / 0 / 10 | 575.8 (16/16) | 504.6 (128/128) | 539.4 | 110.0 | ok |
| betterleaks | 33 / 1 / 1 | 124.6 (16/16) | 327.6 (128/128) | 148.8 | 64.7 | ok |
| titus | 26 / 2 / 8 | 136.2 (16/16) | 305.8 (128/128) | 140.6 | 72.4 | ok |
| ripsecrets | 27 / 0 / 7 | 962.6 (16/16) | — | 518.4 | 125.2 | ok |
| talisman | — | unsupported | unsupported | unsupported | — | unsupported |
| trivy | 24 / 0 / 10 | 127.8 (16/16) | 214.7 (128/128) | 182.4 | 107.1 | ok |
| leakferret | 31 / 2 / 3 | 88.3 (16/16) | — | 315.3 | 32.3 | ok |
| noseyparker | 26 / 2 / 8 | 535.4 (16/16) | — | 503.0 | 261.4 | ok |
| rusty-hog | 17 / 0 / 17 | 1000.6 (0/16) | 7137.8 (0/128) | 688.8 | 35.6 | ok |
| detect-secrets | 34 / 4 / 0 | 5987.1 (16/16) | — | 3883.5 | 48.8 | ok |
| deepsecrets | 19 / 0 / 15 | 3234.4 (16/16) | — | 7840.4 | 86.8 | ok |
| whispers | 21 / 48 / 13 | 154.2 (0/16) | — | 267.8 | 36.0 | ok |
| secretlint | 19 / 0 / 15 | 318.7 (16/16) | 1513.4 (128/128) | 342.3 | 174.5 | ok |
| keyhog | 13 / 0 / 21 | 485.2 (0/16) | 1937.5 (0/128) | failed | — | ok |
| git-secrets | 3 / 0 / 31 | 17924.9 (0/16) | — | 7938.9 | 18.5 | ok |
| credential-digger | 6 / 2 / 28 | 5780.9 (0/16) | 7005.8 (0/128) | 5804.4 | 643.3 | ok |
| scratch-scanner-rs | 30 / 1 / 4 | 148.8 (15/16) | 191.7 (114/128) | 147.8 | 452.6 | ok |
| deepfence-secretscanner | — | — | — | — | — | build_failed |
| ggshield | — | — | — | — | — | external_service_required |
| secrets-patterns-db | — | — | — | — | — | not_executable |

Measured capability probes use default commands; a miss does not prove that no optional mode supports the feature. “Unsupported” means this harness has no confirmed command adapter for that input mode.

| Tool | Boundary/encoding probes | ZIP / TAR member location | History target found | Index target found |
|---|---|---|---|---|
| secret-scan | 6/6 | yes / yes | 1/1 | 1/1 |
| gitleaks | 5/6 | no / no | 1/1 | 1/1 |
| trufflehog | 5/6 | archive only / archive only | 1/1 | unsupported |
| kingfisher | 6/6 | yes / yes | 1/1 | 1/1 |
| betterleaks | 5/6 | yes / yes | 1/1 | 1/1 |
| titus | 4/6 | no / no | 1/1 | unsupported |
| ripsecrets | 5/6 | no / no | unsupported | unsupported |
| talisman | unsupported | — | file-level only | file-level only |
| trivy | 2/6 | no / no | unsupported | unsupported |
| leakferret | 0/6 | no / no | 1/1 | unsupported |
| noseyparker | 4/6 | no / no | 1/1 | unsupported |
| rusty-hog | 0/6 | no / no | unsupported | unsupported |
| detect-secrets | 4/6 | no / no | unsupported | unsupported |
| deepsecrets | 4/6 | no / no | unsupported | unsupported |
| whispers | 0/6 | no / no | unsupported | unsupported |
| secretlint | 2/6 | no / no | unsupported | unsupported |
| keyhog | 1/6 | no / no | 0/1 | unsupported |
| git-secrets | 0/6 | no / no | 0/1 | 0/1 |
| credential-digger | 0/6 | no / no | unsupported | unsupported |
| scratch-scanner-rs | 1/6 | yes / yes | 1/1 | unsupported |
| deepfence-secretscanner | — | — | — | — |
| ggshield | — | — | — | — |
| secrets-patterns-db | — | — | — | — |

Actually launched scanners: 20. Failed/incomplete launched scans count as attempts; unsupported commands and unavailable tools do not.

Timing entries include startup and output processing. Rows with zero injected-secret recall must not be presented as equivalent detection throughput. Unavailable, incomplete and unmeasured tools have no numeric zero score. Version/digest, individual repeats, CPU/RSS, locations, scope notes and source artifacts are retained in the merged JSON.
