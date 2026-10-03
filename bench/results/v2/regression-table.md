# Final measured comparison

Development-informed synthetic regression/diagnostic results, not an independent holdout. Precision is conditional on localized unique findings; recall is a confirmed-location lower bound. Unlocalized outputs are separate from false positives and duplicates. Real-source results have no accuracy labels. Default rule sets differ; input throughput alone is not an efficiency or accuracy ranking.


| Tool | Quality TP / FP / FN | Unlocalized | 16 MiB, ms (TP/labels) | 128 MiB, ms (TP/labels) | Real source, ms | Real peak RSS, MiB | Quality status |
|---|---|---:|---:|---:|---:|---:|---|
| secret-scan | 34 / 0 / 0 | 0 | 59.8 (16/16) | 225.3 (128/128) | 84.6 | 30.6 | ok |
| gitleaks | 31 / 0 / 3 | 0 | 721.1 (16/16) | 1300.7 (128/128) | 613.5 | 103.5 | ok |
| trufflehog | 18 / 0 / 16 | 0 | — | — | — | — | ok |
| kingfisher | 24 / 0 / 10 | 0 | 617.3 (16/16) | 766.1 (128/128) | 647.7 | 121.5 | ok |
| betterleaks | 33 / 1 / 1 | 0 | 101.9 (16/16) | 241.5 (128/128) | 110.6 | 69.0 | ok |
| titus | 26 / 2 / 8 | 0 | — | — | — | — | ok |
| ripsecrets | 27 / 0 / 7 | 0 | — | — | — | — | ok |
| talisman | — | — | — | — | — | — | unsupported |
| trivy | 24 / 0 / 10 | 0 | 96.0 (16/16) | 165.2 (128/128) | 122.7 | 106.7 | ok |
| leakferret | 31 / 2 / 3 | 0 | — | — | — | — | ok |
| noseyparker | 26 / 2 / 8 | 0 | — | — | — | — | ok |
| rusty-hog | 17 / 0 / 17 | 0 | — | — | — | — | ok |
| detect-secrets | 34 / 4 / 0 | 0 | — | — | — | — | ok |
| deepsecrets | 19 / 0 / 15 | 0 | — | — | — | — | ok |
| whispers | 21 / 4 / 13 | 44 | — | — | — | — | ok |
| secretlint | 19 / 0 / 15 | 0 | — | — | — | — | ok |
| keyhog | 13 / 0 / 21 | 0 | — | — | — | — | ok |
| git-secrets | 3 / 0 / 31 | 0 | — | — | — | — | ok |
| credential-digger | 6 / 2 / 28 | 0 | — | — | — | — | ok |
| scratch-scanner-rs | 30 / 1 / 4 | 0 | 154.8 (15/16) | 201.4 (114/128) | 154.6 | 453.5 | ok |
| deepfence-secretscanner | — | — | — | — | — | — | build_failed |
| ggshield | — | — | — | — | — | — | external_service_required |
| secrets-patterns-db | — | — | — | — | — | — | not_executable |

Measured capability probes use default commands; a miss does not prove that no optional mode supports the feature. “Unsupported” means this harness has no confirmed command adapter for that input mode.

| Tool | Boundary/encoding probes | ZIP / TAR member location | History target found | Index target found |
|---|---|---|---|---|
| secret-scan | — | — | — | — |
| gitleaks | — | — | — | — |
| trufflehog | — | — | — | — |
| kingfisher | — | — | — | — |
| betterleaks | — | — | — | — |
| titus | — | — | — | — |
| ripsecrets | — | — | — | — |
| talisman | — | — | — | — |
| trivy | — | — | — | — |
| leakferret | — | — | — | — |
| noseyparker | — | — | — | — |
| rusty-hog | — | — | — | — |
| detect-secrets | — | — | — | — |
| deepsecrets | — | — | — | — |
| whispers | — | — | — | — |
| secretlint | — | — | — | — |
| keyhog | — | — | — | — |
| git-secrets | — | — | — | — |
| credential-digger | — | — | — | — |
| scratch-scanner-rs | — | — | — | — |
| deepfence-secretscanner | — | — | — | — |
| ggshield | — | — | — | — |
| secrets-patterns-db | — | — | — | — |

Actually launched scanners: 19. Failed/incomplete launched scans count as attempts; unsupported commands and unavailable tools do not.

Timing entries include startup and output processing. Rows with zero injected-secret recall must not be presented as equivalent detection throughput. Unavailable, incomplete and unmeasured tools have no numeric zero score. Version/digest, individual repeats, CPU/RSS, locations, scope notes and source artifacts are retained in the merged JSON.
