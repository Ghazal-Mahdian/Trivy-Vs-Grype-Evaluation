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
- Reference severity: HIGH (per Trivy's classification; NVD itself rates this
  MEDIUM — noted here as a first example of the severity disagreements the
  project is designed to surface)
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
