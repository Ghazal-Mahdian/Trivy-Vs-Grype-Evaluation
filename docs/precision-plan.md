# Precision check: plan (written before any result is computed)

## Question
Of the findings each scanner reports, how many are correct? The answer keys measure recall on chosen entries only; this adds precision, and recall beyond the keys, on all OS-package findings.

## Population
All OS-package findings (Trivy class `os-pkgs`; Grype Debian matches) in the CI reports (`results/ci-run-2026-11-17`) for the Debian-based images. Language-package findings (Python, Go, Node, Java) are few and already covered by the keys and negative controls, so they are not part of this check.

## Reference
Debian Security Tracker JSON (`security-tracker.debian.org/tracker/data/json`), downloaded once and its date recorded. Caveat: both scanners' databases also use Debian tracker data, so this check is not independent of them. It tests whether each tool reads that data correctly for the installed version, not whether Debian is right.

## Rules, per finding (source package, CVE, installed version, release)
- **CORRECT**: tracker status `open` for that release, or `resolved` with a fixed version that is newer than the installed version.
- **FALSE POSITIVE**: tracker status `resolved` with a fixed version that is the same as or older than the installed version, or marked not affected for that release.
- **UNDECIDABLE**: no tracker entry for that CVE/package/release, status `undetermined`, or a non-CVE ID. Reported as its own count and never counted as correct or wrong.

## Measures
- Precision = CORRECT / (CORRECT + FALSE POSITIVE), per tool, per image and overall. UNDECIDABLE is shown beside it.
- Findings reported by both tools are counted once as "shared". The findings reported by only one tool are scored separately, because that is where the tools actually differ.
- Relative recall: a finding that is CORRECT and reported by one tool but missing from the other counts as a miss for the other tool.

## Not done / limits
- Not a measure of true vulnerabilities: only of agreement with the Debian tracker.
- Undecidable findings are not resolved by hand unless time allows. If sampled, the sample size and seed are recorded here before checking.
- Version comparison uses Debian's rules (`dpkg --compare-versions`).
