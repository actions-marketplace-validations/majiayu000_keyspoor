# Final v3 quality comparison

The 18 competing filesystem scanners below retain their original fresh-holdout measurements from [fresh-holdout.json](fresh-holdout.json). Final local rows come from [fresh-holdout-optimized.json](fresh-holdout-optimized.json), after a performance-only candidate-allocation fast path. That corpus had already been observed, so the final local rerun is explicitly a regression verification, not a new independent holdout. Detection rules and labels were not tuned after the original measurement. Original artifacts remain unchanged. This table combines quality evidence only; it does not compare elapsed times from separate runs.

Baseline is 9da912a; final candidate SHA-256 is `b607dd486f9a62670b0f42bb93e3739346ae4a27f1728f0be8e00851f5590239`.

| Tool | Status | TP | FP | FN | Duplicates | Unlocalized | Localized precision | Confirmed recall lower bound |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| secret-scan-before | ok | 595 | 25 | 5 | 369 | 0 | 0.960 | 0.992 |
| secret-scan | ok | 595 | 25 | 5 | 0 | 0 | 0.960 | 0.992 |
| gitleaks | ok | 414 | 15 | 186 | 0 | 76 | 0.965 | 0.690 |
| trufflehog | ok | 290 | 0 | 310 | 0 | 39 | 1.000 | 0.483 |
| kingfisher | ok | 340 | 0 | 260 | 0 | 68 | 1.000 | 0.567 |
| betterleaks | ok | 484 | 15 | 116 | 0 | 60 | 0.970 | 0.807 |
| titus | ok | 371 | 50 | 229 | 0 | 45 | 0.881 | 0.618 |
| ripsecrets | ok | 206 | 0 | 394 | 0 | 14 | 1.000 | 0.343 |
| talisman | unsupported | — | — | — | — | — | — | — |
| trivy | ok | 313 | 0 | 287 | 0 | 60 | 1.000 | 0.522 |
| leakferret | ok | 448 | 25 | 152 | 272 | 76 | 0.947 | 0.747 |
| noseyparker | ok | 311 | 28 | 289 | 0 | 48 | 0.917 | 0.518 |
| rusty-hog | ok | 95 | 0 | 505 | 20 | 10 | 1.000 | 0.158 |
| detect-secrets | ok | 377 | 75 | 223 | 70 | 46 | 0.834 | 0.628 |
| deepsecrets | ok | 190 | 0 | 410 | 0 | 20 | 1.000 | 0.317 |
| whispers | ok | 134 | 0 | 466 | 0 | 120 | 1.000 | 0.223 |
| secretlint | ok | 244 | 0 | 356 | 0 | 40 | 1.000 | 0.407 |
| keyhog | ok | 445 | 0 | 155 | 0 | 48 | 1.000 | 0.742 |
| git-secrets | ok | 20 | 0 | 580 | 0 | 2 | 1.000 | 0.033 |
| credential-digger | ok | 80 | 25 | 520 | 0 | 2 | 0.762 | 0.133 |
| scratch-scanner-rs | ok | 451 | 25 | 149 | 75 | 0 | 0.947 | 0.752 |
| deepfence-secretscanner | build_failed | — | — | — | — | — | — | — |
| ggshield | external_service_required | — | — | — | — | — | — | — |
| secrets-patterns-db | not_executable | — | — | — | — | — | — | — |

600 positive locations, 580 distinct positive values and 300 negative labels are synthetic. Precision excludes unlocalized and duplicate outputs. Line-only output with multiple labelled candidates on a line remains unlocalized; missing location evidence does not prove either a detection or false positive. Default detector coverage differs. These scores do not establish real-world precision, live credential validity or pure detection-engine superiority. All 25 local false positives remain catalog-description negatives.
