# Final measured comparison

Declared frozen synthetic holdout. Precision is conditional on localized unique findings; recall is a confirmed-location lower bound. Unlocalized outputs are separate from false positives and duplicates. Real-source results have no accuracy labels. Default rule sets differ; input throughput alone is not an efficiency or accuracy ranking.


| Tool | Quality TP / FP / FN | Unlocalized | 16 MiB, ms (TP/labels) | 128 MiB, ms (TP/labels) | Real source, ms | Real peak RSS, MiB | Quality status |
|---|---|---:|---:|---:|---:|---:|---|
| secret-scan | 599 / 25 / 1 | 0 | — | — | — | — | ok |
| gitleaks | 493 / 14 / 107 | 0 | — | — | — | — | ok |
| trufflehog | 342 / 0 / 258 | 0 | — | — | — | — | ok |
| kingfisher | 409 / 0 / 191 | 0 | — | — | — | — | ok |
| betterleaks | 553 / 14 / 47 | 0 | — | — | — | — | ok |
| titus | 433 / 50 / 167 | 0 | — | — | — | — | ok |
| ripsecrets | 239 / 0 / 361 | 0 | — | — | — | — | ok |
| talisman | — | — | — | — | — | — | unsupported |
| trivy | 376 / 0 / 224 | 0 | — | — | — | — | ok |
| leakferret | 532 / 25 / 68 | 0 | — | — | — | — | ok |
| noseyparker | 359 / 28 / 241 | 0 | — | — | — | — | ok |
| rusty-hog | 111 / 0 / 489 | 0 | — | — | — | — | ok |
| detect-secrets | 400 / 75 / 200 | 0 | — | — | — | — | ok |
| deepsecrets | 209 / 0 / 391 | 0 | — | — | — | — | ok |
| whispers | 155 / 0 / 445 | 120 | — | — | — | — | ok |
| secretlint | 288 / 0 / 312 | 0 | — | — | — | — | ok |
| keyhog | 515 / 0 / 85 | 0 | — | — | — | — | ok |
| git-secrets | 24 / 0 / 576 | 0 | — | — | — | — | ok |
| credential-digger | 84 / 25 / 516 | 0 | — | — | — | — | ok |
| scratch-scanner-rs | 470 / 25 / 130 | 0 | — | — | — | — | ok |
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
