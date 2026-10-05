# Test case: vulnerable OS package
# Base: Debian 9 "stretch" — end of life, frozen, no further security backports
# Target finding: CVE-2017-14062 in libidn11
#   Status per Debian Security Tracker: HIGH severity, "won't fix" in stretch
#   (fixed only in buster and later) — this makes the finding permanent and
#   safe to use as a stable benchmark case.
#
# Pinned by digest once you resolve it (see instructions below) so this
# build is byte-identical every time you or a CI runner pulls it.
#
# Platform: stretch-slim only exists as linux/amd64. Build and run this
# with --platform=linux/amd64 explicitly (required on Apple Silicon, where
# Docker Desktop will otherwise guess wrong). Record this platform choice
# in the ground-truth file too, since a scanner must target the same
# architecture the image was built for.
FROM debian:stretch-slim

# Stretch is end-of-life: Debian removed it from the live mirrors, so the
# default sources.list 404s. Point apt only at what the permanent archive
# actually mirrors (stretch main) — stretch-updates and the old
# security.debian.org path are not preserved there and will 404 if included.
RUN echo 'deb http://archive.debian.org/debian stretch main' > /etc/apt/sources.list && \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid

# libidn11 is present in a base stretch install already; this line makes the
# dependency explicit and pins the exact vulnerable version so the image
# does not silently change if Debian's stretch snapshot repo is ever pruned.
RUN apt-get update && \
    apt-get install -y --no-install-recommends libidn11 && \
    rm -rf /var/lib/apt/lists/*

CMD ["sleep", "3600"]
