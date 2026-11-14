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
- Go binary image (image 6): native P2 is BLOCK for Trivy and PASS for Grype, the first BLOCK-vs-PASS split, caused by D7 (a verified miss), not by labeling or advisory-ID noise.
- Status: VERIFIED as outputs.

## D6. Disputed CVE-2019-1010022 (glibc)
- NVD rates it 9.8 CRITICAL; the answer key marks it DISPUTED (upstream treats it as a non-security bug). Grype labels it Negligible, Trivy LOW (image 2), so the NVD number is the outlier.
- A naive NVD-reference gate would wrongly block image 2 on P1 because of it. The reference gate excludes keyed DISPUTED entries.

## D7. Grype misses CVE-2020-26160 in a Go binary (image 6, jwt-go v3.2.0+incompatible)
- Answer key: AFFECTED, HIGH (NVD primary 7.5). Trivy reports it (HIGH, no fix listed); Grype does not.
- Grype catalogued the package correctly (purl pkg:golang/github.com/dgrijalva/jwt-go@v3.2.0%2Bincompatible), and its own database contains the advisory for that exact package: GHSA-w73w-5m7g-f7qc as a go-module record with range >=0.0.0-20150717181359-44718f8a89b0,<=3.2.0, plus an NVD CPE record for CVE-2020-26160 (<= 3.2.0). By semver rules the installed version is inside that range, so the package is catalogued and the data exists.
- Cause OPEN, narrowed. With the same Grype and database: scanning the bare package as a purl (with or without +incompatible) returns GHSA-w73w-5m7g-f7qc; scanning the SBOM that Grype itself generates from the same image returns it too; only the direct image scan (run twice, nothing suppressed) misses it. So Syft's catalogue and the database are fine, and the finding is lost inside the direct image-scan path. Practical consequence: a pipeline that scans an SBOM would catch what `grype <image>` misses, which matters for the CI design.
- Also reproduced with Grype 0.121.3 (the latest release on 2026-11-13, run from the official container with a freshly downloaded database): the direct image scan still reports only the websocket advisory. The main experiment stays pinned to Grype 0.120.0.
- Effect: native P2 gate is BLOCK for Trivy and PASS for Grype, the first BLOCK-vs-PASS split. NVD-reference gates cannot change this: they only re-rate findings a tool reports.
- Predictions scored (committed before any scan): detection 2/2 for both (wrong for Grype, 1/2); P2 BLOCK for both (wrong for Grype); P3 PASS for both on module findings (right: neither tool lists a fix for jwt-go; Trivy's REVIEW on P1 and P3 comes from distroless base advisories); both negative controls correctly unreported by both tools; the GHSA-only websocket advisory caught by both; no Go standard library findings from either tool for go1.26.11.
- Status: VERIFIED miss. Cause OPEN.

## Not differences
- Image 2 (requests 2.19.1): both tools 5/5 recall.
- Image 3 (backported fixes): both tools 3/3 recall and 0 of 7 backport false positives.
- Image 7 (npm transitive dependency, installed): both tools 2/2 recall, severities equal to NVD, no findings on the clean parent package (mkdirp); native and NVD-reference gates both BLOCK for both tools.
- Image 8 (npm lockfile only, packages declared but not installed): neither tool reports the two DISPUTED minimist advisories (0/2 each). Pre-registered prediction that Trivy would report both was WRONG (Grype half was right). Image-scan mode appears not to use the lockfile; not verified, and a filesystem scan of the same files may behave differently (test when building CI). Gate split on this image is REVIEW (Trivy, 4 base-image advisory IDs) vs PASS (Grype), the same D4 pattern.
- Image 9 (Java shaded jar, packages relocated; commons-text 1.9, snakeyaml 1.30, commons-lang3 3.11 transitive, slf4j-api 2.0.9 clean control): both tools 9/9 recall, nothing reported on slf4j-api, native and NVD-reference gates BLOCK on all three policies for both tools. Both tools label CVE-2022-1471 as HIGH while NVD primary is CRITICAL (the GitHub advisory says HIGH), the same label-difference pattern as D3 and not a detection difference. Every pre-registered prediction held. Observation for CI and timing: Trivy downloaded a separate Java database (about 950 MB, 1 min 16 s on this network, cached for 3 days) before scanning the jar; the Grype run showed no equivalent download (not investigated).

## Limitations to state in the paper
- Nine images; two are should-pass images with empty keys.
- NVD reference coverage: about 89 to 100% of CVE findings on images 1, 2 and 5, about 77% on image 3 (96 unscored CVEs).
- Database snapshots differ between images; within-image comparisons are same-day.
- The REVIEW rule and the exclusion of advisory-ID findings and disputed CVEs are design choices, documented above.
- Harness bug found and fixed on image 9: the first scoring run showed Trivy at 0/9 because Trivy names Java packages as Maven coordinates (org.yaml:snakeyaml) while the key and Grype use the artifact name (snakeyaml). Trivy's own scan summary (9 matches) contradicted the 0/9, which is how it was caught. compare_findings.py now compares the artifact part of the name; re-scoring every image changed only this one result (Trivy Java 0/9 to 9/9). The fix concerns name matching only, not which advisory IDs count.
- Earlier harness bug (found on image 7): gate_compare.py shared DISPUTED CVEs between images. Fixed so an image's own key decides, with only the glibc dispute shared explicitly.
