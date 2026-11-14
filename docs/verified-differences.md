# Verified differences between Trivy and Grype

Status as of 2026-11-13. Labels: VERIFIED = seen in both tools' reports and checked against the answer key or an outside source. LIKELY = supported but one link is unchecked. OPEN = cause unknown.
Every comparison is same-image, same-tarball. Database snapshots differ between images (see scanners/reports/versions-*.json).

## D1. Trivy misses CVE-2021-3999 (image 1, end-of-life Debian stretch)
- Answer key: AFFECTED, HIGH. Grype reports it, Trivy does not.
- Status: VERIFIED that Trivy misses it. Cause OPEN (hypothesis: end-of-life OS handling).

## D2. Opposite Critical findings on the updated image (image 5)
- Trivy Critical: CVE-2023-45853 (zlib1g, no fix). Grype Critical: CVE-2026-5450 (libc6, libc-bin, wont-fix).
- Both tools block P1, but on different findings.
- Status: VERIFIED what each tool labels Critical. How each tool treats the other's CVE (lower severity or absent) is not checked yet.

## D3. Severity labels differ
- CVE-2026-82560 (perl-base, image 2): Trivy has no severity data at all (UNKNOWN), Grype says High, NVD cache says High 7.5 (secondary source, status Deferred). Trivy's database was newer than Grype's that day.
- Image 3: Trivy lower than the reference on some perl-base and glibc findings, Grype matches (from earlier analysis).
- Image 5 counts: Trivy 34 High, Grype 49 High.
- CVE-2018-7169 (image 1): both tools say LOW, NVD says MEDIUM.
- Status: VERIFIED as differences. Cause of Trivy's missing severity: OPEN (likely source selection, not stale data).

## D4. Trivy reports Debian advisory IDs (DSA, DLA, TEMP) that Grype never reports
- Trivy counts: image 1: 0, image 2: 7, image 3: 7, minimal: 4, updated: 5. Grype: 0 in every report checked.
- Content: 3 tzdata DLAs (timezone data updates, not vulnerabilities), 5 unfixed LOW TEMP entries (bash, login.defs, passwd, sysvinit-utils, tar), liblzma5 DSA-6549-1 plus TEMP-1147318 (likely one real fixable issue counted twice; fixed in 5.8.1-1+deb13u2), ca-certificates DLA-4845-1 (not looked up).
- Status: VERIFIED that Grype omits them. liblzma5 is LIKELY a real Grype gap (DSA text not read). The rest are low or non-security.

## D5. Gate verdicts
- BLOCK vs BLOCK is identical in every pair where both tools block.
- With the REVIEW rule (unknown severity is never a pass), 5 of 15 image-policy pairs differ, always Trivy REVIEW vs Grype PASS: image 2 P1; minimal P1, P2, P3; updated P3.
- Causes: D4 (mostly tzdata noise) plus D3 on image 2. The REVIEW rule was in the original design but was wired into gate.py only after seeing the minimal image result; the committed prediction for that image was PASS (true under the old gate).
- Status: VERIFIED as outputs. Most of these splits are a rule artifact, not a security difference.

## Not differences
- Image 2 (requests 2.19.1): both tools 5/5 recall.
- Image 3 (backported fixes): both tools 3/3 recall and 0 of 7 backport false positives.
