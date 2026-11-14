# Verified differences between Trivy and Grype

Status as of 2026-11-13. Labels: VERIFIED = seen in both tools' reports and checked against the answer key or an outside source. LIKELY = supported but one link is unchecked. OPEN = cause unknown.
Every comparison is same-image, same-tarball. Database snapshots differ between images (see scanners/reports/versions-*.json). Both tools are pinned (Trivy 0.74.0, Grype 0.120.0; a newer Grype exists).

## D1. Trivy misses CVE-2021-3999 (image 1, end-of-life Debian stretch)
- Answer key: AFFECTED, HIGH. Grype reports it, Trivy does not.
- Status: VERIFIED that Trivy misses it. Cause OPEN (hypothesis: end-of-life OS handling).
- Related: Trivy also omits the disputed CVE-2019-1010022 on image 1 but reports it (LOW) on image 2.

## D2. Opposite Critical findings on the updated image (image 5)
- Trivy Critical: CVE-2023-45853 (zlib1g, no fix). Grype Critical: CVE-2026-5450 (libc6, libc-bin, wont-fix).
- Both tools block P1, but on different findings.
- Status: VERIFIED what each tool labels Critical. How each tool treats the other's CVE (lower severity or absent) is not checked yet.

## D3. Severity labels differ from NVD, in both tools
- Both tools label many findings lower than the NVD reference severity, and a few higher. This is expected: both mainly use distro ratings, which are often lower than NVD's generic score. NVD is a reference, not the truth about risk.
- Pattern (first run, before the disputed CVE was excluded; re-run scripts/gate_compare.py for exact counts): on the Debian 12/13 images (2, 3, 5) Trivy has roughly 2 to 4 times more findings that are High in the reference but below High in its own label than Grype; on image 1 (end-of-life Debian 9) it is the other way round (Grype far more than Trivy).
- CVE-2026-82560 (perl-base, image 2): Trivy has no severity data at all (UNKNOWN), Grype says High, NVD cache says High 7.5 (secondary source, status Deferred). Trivy's database was about 12 hours newer than Grype's that day, so stale data does not explain it.
- CVE-2018-7169 (image 1): both tools say LOW, NVD says MEDIUM.
- Status: VERIFIED as differences. Cause of Trivy's missing severity on CVE-2026-82560: OPEN (likely source selection).

## D4. Trivy reports Debian advisory IDs (DSA, DLA, TEMP) that Grype never reports
- Trivy counts: image 1: 0, image 2: 7, image 3: 7, minimal: 4, updated: 5. Grype: 0 in every report checked.
- Content: 3 distinct tzdata DLAs (timezone data updates, not vulnerabilities), 5 unfixed LOW TEMP entries (bash, login/login.defs, passwd, sysvinit-utils, tar), liblzma5 DSA-6549-1 plus TEMP-1147318 (likely one real fixable issue counted twice; fixed in 5.8.1-1+deb13u2), ca-certificates DLA-4845-1 (not looked up).
- Status: VERIFIED that Grype omits them. liblzma5 is LIKELY a real Grype gap (DSA text not read). The rest are low or non-security.

## D5. Gate verdicts
- Native gates (each tool's own labels): BLOCK vs BLOCK is identical in every pair where both tools block. With the REVIEW rule (unknown severity is never a pass), 5 of 15 image-policy pairs differ, always Trivy REVIEW vs Grype PASS: image 2 P1; minimal P1, P2, P3; updated P3. Causes: D4 (mostly tzdata noise) plus CVE-2026-82560 on image 2.
- Native vs NVD-reference gates (scripts/gate_compare.py, disputed CVEs excluded): no pair changes between block and non-block when the label source switches. The three REVIEW/PASS changes are rule artifacts (unscored CVEs, advisory IDs excluded).
- The REVIEW rule was in the original design but was wired into gate.py only after seeing the minimal image result; the committed prediction for that image was PASS (true under the old gate).
- P2 and P3 are saturated on these images (many findings both tools call High), so severity differences cannot change those verdicts. Cleaner images are needed to test them.
- Status: VERIFIED as outputs.

## D6. Disputed CVE-2019-1010022 (glibc)
- NVD rates it 9.8 CRITICAL; the answer key marks it DISPUTED (upstream treats it as a non-security bug). Grype labels it Negligible, Trivy LOW (image 2), so the NVD number is the outlier.
- A naive NVD-reference gate would wrongly block image 2 on P1 because of it. The reference gate excludes keyed DISPUTED entries.

## Not differences
- Image 2 (requests 2.19.1): both tools 5/5 recall.
- Image 3 (backported fixes): both tools 3/3 recall and 0 of 7 backport false positives.

## Limitations to state in the paper
- Five images so far; two are should-pass images with empty keys.
- NVD reference coverage: about 89 to 100% of CVE findings on images 1, 2 and 5, about 77% on image 3 (96 unscored CVEs).
- Database snapshots differ between images; within-image comparisons are same-day.
- The REVIEW rule and the exclusion of advisory-ID findings and disputed CVEs are design choices, documented above.
