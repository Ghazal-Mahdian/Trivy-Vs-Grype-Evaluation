## Precision against the Debian Security Tracker (OS-package findings)

| Image | Tool | Correct | False pos. | Undecidable | Precision |
|---|---|---|---|---|---|
| app-dependency-cve | trivy | 241 | 0 | 4 | 100.0% |
| app-dependency-cve | grype | 231 | 0 | 0 | 100.0% |
| backport-fix-cve | trivy | 466 | 0 | 3 | 100.0% |
| backport-fix-cve | grype | 459 | 0 | 0 | 100.0% |
| minimal-base-pass | trivy | 0 | 0 | 4 | - |
| updated-base-pass | trivy | 236 | 0 | 1 | 100.0% |
| updated-base-pass | grype | 231 | 0 | 0 | 100.0% |
| go-binary-cve | trivy | 0 | 0 | 4 | - |
| node-transitive-installed | trivy | 0 | 0 | 4 | - |
| node-transitive-lockfile | trivy | 0 | 0 | 4 | - |
| java-shaded-jar-cve | trivy | 0 | 0 | 4 | - |
| **All** | **trivy** | 943 | 0 | 28 | 100.0% |
| **All** | **grype** | 921 | 0 | 0 | 100.0% |

## By who reports it (all images)

| Tool | Reported by | Correct | False pos. | Undecidable | Precision |
|---|---|---|---|---|---|
| trivy | both | 921 | 0 | 0 | 100.0% |
| trivy | only_trivy | 22 | 0 | 28 | 100.0% |
| grype | both | 921 | 0 | 0 | 100.0% |
| grype | only_grype | 0 | 0 | 0 | - |

## Correct findings the other tool did not report (relative misses)

| Tool that missed | Count |
|---|---|
| trivy | 0 |
| grype | 22 |

## Why findings were undecidable

| Tool | Reason | Count |
|---|---|---|
| trivy | not_in_tracker | 28 |
