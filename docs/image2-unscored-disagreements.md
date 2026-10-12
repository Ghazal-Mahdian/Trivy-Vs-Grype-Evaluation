# Image 2 (app-dependency-cve): findings outside the answer key

Status: UNVERIFIED. Recorded 2026-10-11 from scans of the saved image tarball.
None of these are in ground-truth/app-dependency-cve.json and none count
toward recall or precision.

## Resolved as labeling differences (not real disagreements)
- 5 requests findings: Grype reports GHSA IDs with the CVE as a related ID.
- 6 pip findings (pip 25.0.1): same six CVEs in both tools, Grype as GHSA.

## Grype-only: CPython 3.12.15 interpreter (7 findings, cpe-match on binary)
CVE-2025-12781, CVE-2025-15366, CVE-2025-15367, CVE-2026-3446,
CVE-2026-12345, CVE-2026-6019, CVE-2026-3479.
- All real NVD records. Statuses: Analyzed (2), Deferred (2, no NVD
  affected-version data), Awaiting Analysis (3).
- CVE-2026-3479 is described by NVD as DISPUTED; Grype labels it Negligible.
- Open question: whether the 3.12 branch is actually affected. NVD ranges for
  the analyzed records read "before 3.13.x" with no lower bound, which would
  include 3.12.15 under CPE logic. Needs upstream CPython advisories.
- Trivy did not report any of these.

## Trivy-only: Debian tracker IDs (7 findings)
DSA-6549-1 (liblzma5) and six TEMP-* items (tar, sysvinit-utils, login.defs,
passwd, bash, liblzma5). TEMP-* are Debian tracker entries without a CVE
number. Not confirmed whether Grype reports equivalents under other IDs.
