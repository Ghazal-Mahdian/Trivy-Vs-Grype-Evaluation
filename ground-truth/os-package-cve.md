# Ground Truth — os-package-cve

This file is the answer key for the `os-package-cve` test image. It is the
human-readable twin of `ground-truth/os-package-cve.json`; the two must always
say the same thing.

How the key was built: candidate CVEs were discovered from scanner output
(the image is an end-of-life distro, so hand-picking CVEs in advance was not
reliable). Each candidate was then verified independently against vendor or
upstream advisories. Scanner agreement was never treated as proof, and this
file is never adjusted to match a scanner's output. Because candidates came
from scanner output, the key is seeded by the scanners; see the limitations
in the project paper.

Severity reference: NVD primary CVSS base severity (nvd@nist.gov), checked
via the NVD API on 2026-10-10. Scanner-native severities are recorded in
scanner output and comparison results, not in this file.

## Image identity

- Base image: `debian:stretch-slim`
- Base digest: debian:stretch-slim@sha256:abaa313c7e1dfe16069a1a42fa254014780f165d4fd084844602edbe29915e70
- Platform: linux/amd64
- Built: 2026-09-26
- Dockerfile: images/os-package-cve/Dockerfile
- Scanned artifact: saved image tarball; its SHA-256, tool versions, and
  vulnerability DB versions are in `scanners/reports/versions.json`
- OS as detected by both scanners: Debian 9.13 (end of life), 77 packages

## Entry 1

- Package: ncurses-base (also present in libncursesw5, libtinfo5, ncurses-bin)
- Ecosystem: deb (Debian package)
- Installed version: 6.0+20161126-1+deb9u2
- Vulnerability ID: CVE-2022-29458
- Aliases: none found
- Affected status: AFFECTED
- Reference severity: HIGH (NVD CVSS 3.1 base score 7.1). Both scanners also
  report HIGH, so there is no severity disagreement on this finding.
- Fix status: NOT FIXED in the standard Debian archive for stretch.
  Debian's security tracker notes "[stretch] - ncurses <no-dsa> (Minor
  issue)", meaning Debian's security team chose not to issue a backported
  fix through the free archive. A fix exists at 6.0+20161126-1+deb9u5
  through Debian's paid Extended LTS program, which this image does not use.
- Fix status cross-check: Grype independently reports fix state "wont-fix"
  for this CVE in this image.
- Source checked: https://security-tracker.debian.org/tracker/CVE-2022-29458
- Date reviewed: 2026-09-26
- Notes: Good first case: stable (archive is frozen), genuinely unfixed in
  our build, confirmed outside either scanner. Both scanners matched all
  four package names (all derived from source package ncurses).

## Entry 2

- Package: perl-base
- Ecosystem: deb (Debian package)
- Installed version: 5.24.1-3+deb9u7
- Vulnerability ID: CVE-2020-16156
- Aliases: none recorded
- Affected status: AFFECTED
- Reference severity: HIGH (NVD CVSS 3.1 base score 7.8)
- Fix status: NOT FIXED at installed version. A fix exists at
  5.24.1-3+deb9u8 (Freexian Extended LTS advisory ELA-1226-1); the installed
  version is one revision before it.
- Source checked: https://www.freexian.com/lts/extended/updates/ela-1226-1-perl/
- Date reviewed: 2026-10-05
- Notes: Both scanners caught it with HIGH severity. Full agreement.

## Entry 3

- Package: libc6, libc-bin, multiarch-support
- Ecosystem: deb (Debian package)
- Installed version: 2.24-11+deb9u4
- Vulnerability ID: CVE-2021-3999
- Aliases: none found
- Affected status: AFFECTED
- Reference severity: HIGH (NVD CVSS 3.1 base score 7.8, checked 2026-10-10).
  The 2026-10-05 version of this entry took HIGH from Grype; NVD now
  independently confirms it. Issue: glibc getcwd() off-by-one overflow with
  privilege escalation potential.
- Fix status: NOT FIXED. 2.24-11+deb9u4 is the FINAL version stretch's glibc
  ever reached (per Debian's package history), so no later revision exists.
  The advisory Grype cites, DLA-3152-1, covers only buster, not stretch.
- Source checked: https://blueprints.launchpad.net/debian/stretch/+source/glibc
  (version history) and https://security-tracker.debian.org/tracker/DLA-3152-1
  (confirms buster-only scope)
- Date reviewed: 2026-10-05 (severity re-checked against NVD 2026-10-10)
- Notes: FIRST CONFIRMED DETECTION GAP. Trivy did not report this CVE for
  any of the three packages (the CVE ID does not appear anywhere in its
  report), despite it being present and unfixed. Grype caught it. Same
  package, same version, independently verified. Possible link to Trivy's
  warning that detection on an unsupported OS may be insufficient; not
  confirmed.

## Entry 4

- Package: passwd
- Ecosystem: deb (Debian package)
- Installed version: 1:4.4-4.1+deb9u1
- Vulnerability ID: CVE-2018-7169
- Aliases: none found
- Affected status: AFFECTED
- Reference severity: MEDIUM (NVD CVSS 3.0 base score 5.3)
- Fix status: NOT FIXED at installed version. Debian tracker confirms
  1:4.4-4.1+deb9u1 vulnerable, fixed at 1:4.4-4.1+deb9u2.
- Source checked: https://security-tracker.debian.org/tracker/CVE-2018-7169
- Date reviewed: 2026-10-05
- Notes: SEVERITY DISAGREEMENT. Both scanners report LOW while NVD says
  MEDIUM. Working hypothesis (unconfirmed): both inherit Debian's
  distro-specific rating rather than raw CVSS. This is the first non-HIGH
  entry, useful for testing P1 vs P2 gate behavior. Searching for a
  false-positive candidate here turned up a genuine, undisputed
  vulnerability; true false positives likely need a purpose-built case (the
  planned vendor-backported-fix image).

## Entry 5

- Package: libc6, libc-bin, multiarch-support
- Ecosystem: deb (Debian package)
- Installed version: 2.24-11+deb9u4
- Vulnerability ID: CVE-2019-1010022
- Aliases: GHSA-hqfh-jh33-mj7r (UNVERIFIED, re-check against NVD/OSV)
- Affected status: DISPUTED. NVD's description records that upstream glibc
  treats this as a non-security bug with no real threat; the NVD record
  links the upstream bug https://sourceware.org/bugzilla/show_bug.cgi?id=22850
  and the Debian tracker. NVD has no formal "disputed" tag on this record.
  Other trackers reportedly mark it not affected or excluded (Chainguard
  advisory CGA-8m4j-hg3f-5xv5, Yocto CVE exclusion list; both UNVERIFIED,
  re-check before citing).
- Reference severity: CRITICAL (NVD CVSS 3.0 base score 9.8). This is the
  NVD score; the DISPUTED status is what keeps the finding out of
  recall/precision and gate scoring as a confirmed vulnerability.
- Fix status: No fix exists or is planned; upstream considers there is
  nothing to fix.
- Source checked: https://nvd.nist.gov/vuln/detail/CVE-2019-1010022,
  upstream bug above, Debian tracker (not yet read directly)
- Date reviewed: 2026-10-05 (NVD record re-checked 2026-10-10)
- Notes: FIRST DISPUTED CASE. Scoring rule: disputed entries are reported as
  their own category, not counted as true or false positives. Observed:
  Trivy omits this CVE; Grype reports it labeled Negligible. Because Grype
  labels it Negligible, it would not trigger a block under P1 or P2, while
  the NVD score alone (CRITICAL) would. The finding stays in the report
  either way, per the "below-threshold findings retained" rule.

## Entries pending (not verified, do not treat as confirmed)

- CVE-2016-2779 (util-linux), surfaced by the first Trivy scan
- Possible disputed siblings seen in Grype's findings: CVE-2019-1010023,
  CVE-2019-1010024, CVE-2019-1010025, CVE-2010-4756 (glibc)
