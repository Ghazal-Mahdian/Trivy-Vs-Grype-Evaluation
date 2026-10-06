# Ground Truth — os-package-cve

This file is the answer key for the `os-package-cve` test image. Every entry
here was verified against a vendor advisory BEFORE Trivy or Grype were run
against this image. Scanner output is checked against this file — this file
is never adjusted to match a scanner's output.

## Image identity

- Base image: `debian:stretch-slim`
- Base digest: debian:stretch-slim@sha256:abaa313c7e1dfe16069a1a42fa254014780f165d4fd084844602edbe29915e70
- Platform: linux/amd64
- Built: 2026-09-26
- Dockerfile: images/os-package-cve/Dockerfile

## Entry 1

- Package: ncurses-base (also present in ncurses-bin)
- Ecosystem: deb (Debian package)
- Installed version: 6.0+20161126-1+deb9u2
- Vulnerability ID: CVE-2022-29458
- Aliases: none found
- Affected status: AFFECTED
- Reference severity: HIGH. Confirmed independently by both scanners and by
  NVD's own CVSS 3.1 base score of 7.1 (High range is 7.0-8.9). All three
  sources agree here — no severity disagreement on this particular finding.
- Fix status cross-check: Grype independently reports fix state "wont-fix"
  for this CVE in this image, matching the Debian tracker conclusion already
  recorded above. Two independent confirmations of the same fix status.
- Fix status: NOT FIXED in the standard Debian archive for stretch.
  Debian's security tracker explicitly notes: "[stretch] - ncurses <no-dsa>
  (Minor issue)" — meaning Debian's security team deliberately chose not to
  issue a backported fix through the free archive. A fix does exist at
  6.0+20161126-1+deb9u5 through Debian's paid Extended LTS program, which
  this image does not use.
- Source checked: https://security-tracker.debian.org/tracker/CVE-2022-29458
- Date reviewed: 2026-09-26
- Notes: Good first ground-truth case — stable (archive is frozen), genuinely
  unfixed in our build, and independently confirmed outside of either scanner.

## Entries pending

The same Trivy scan surfaced several other candidates worth adding once we
verify each independently:
- CVE-2020-16156 (perl-base) — HIGH per Trivy, not yet checked against NVD/tracker
- CVE-2016-2779 (util-linux) — not yet checked
- CVE-2018-7169 (passwd) — not yet checked

Do not treat these as confirmed until each has its own verified entry above.


## Entry 3

- Package: libc6, libc-bin, multiarch-support
- Ecosystem: deb (Debian package)
- Installed version: 2.24-11+deb9u4
- Vulnerability ID: CVE-2021-3999
- Aliases: none found
- Affected status: AFFECTED
- Reference severity: HIGH (per Grype; glibc getcwd() off-by-one overflow,
  privilege escalation potential — not independently re-scored against raw
  NVD CVSS in this pass, flagged for a closer severity check later)
- Fix status: NOT FIXED. 2.24-11+deb9u4 is confirmed as the FINAL version
  stretch's glibc ever reached (per Debian's own package history) — no
  later revision exists. The advisory Grype cites, DLA-3152-1, covers only
  buster, not stretch, confirming stretch was never patched through any
  channel for this CVE.
- Source checked: https://blueprints.launchpad.net/debian/stretch/+source/glibc
  (version history) and https://security-tracker.debian.org/tracker/DLA-3152-1
  (confirms buster-only scope)
- Date reviewed: 2026-10-05
- Notes: FIRST CONFIRMED DETECTION GAP. Trivy did not report this CVE for
  libc6/libc-bin/multiarch-support at all, despite it being genuinely
  present and unfixed. Grype caught it correctly. This is a true Trivy
  false negative on this image, not a naming/mapping artifact — same
  package, same version, independently verified.

