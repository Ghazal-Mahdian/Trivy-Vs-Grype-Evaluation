## Precision against the Debian Security Tracker (OS-package findings)

| Image | Tool | Correct | False pos. | Undecidable | Precision |
|---|---|---|---|---|---|
| app-dependency-cve | trivy | 212 | 0 | 4 | 100.0% |
| app-dependency-cve | grype | 208 | 0 | 0 | 100.0% |
| backport-fix-cve | trivy | 448 | 12 | 3 | 97.4% |
| backport-fix-cve | grype | 443 | 12 | 0 | 97.4% |
| minimal-base-pass | trivy | 0 | 0 | 4 | - |
| updated-base-pass | trivy | 225 | 0 | 1 | 100.0% |
| updated-base-pass | grype | 220 | 0 | 0 | 100.0% |
| go-binary-cve | trivy | 0 | 0 | 4 | - |
| node-transitive-installed | trivy | 0 | 0 | 4 | - |
| node-transitive-lockfile | trivy | 0 | 0 | 4 | - |
| java-shaded-jar-cve | trivy | 0 | 0 | 4 | - |
| **All** | **trivy** | 885 | 12 | 28 | 98.7% |
| **All** | **grype** | 871 | 12 | 0 | 98.6% |

## By who reports it (all images)

| Tool | Reported by | Correct | False pos. | Undecidable | Precision |
|---|---|---|---|---|---|
| trivy | both | 871 | 12 | 0 | 98.6% |
| trivy | only_trivy | 14 | 0 | 28 | 100.0% |
| grype | both | 871 | 12 | 0 | 98.6% |
| grype | only_grype | 0 | 0 | 0 | - |

## Correct findings the other tool did not report (relative misses)

| Tool that missed | Count |
|---|---|
| trivy | 0 |
| grype | 14 |

## Why findings were undecidable

| Tool | Reason | Count |
|---|---|---|
| trivy | not_in_tracker | 28 |
