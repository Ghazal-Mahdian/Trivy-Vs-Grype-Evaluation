# Test case: vendor-backported fixes (Debian 12 "bookworm", python3-urllib3)
# Debian ships urllib3 1.26.12 and backports security fixes into
# 1.26.12-1+deb12uN while keeping the upstream version number. Upstream
# advisories say 1.26.12 is vulnerable (fixes only in 1.26.17-19 or 2.x), but
# Debian's tracker marks 7 of the 10 applicable CVEs as fixed in this build.
# A scanner that reports those 7 is producing false positives.
# See ground-truth/backport-fix-cve.json for the answer key (written before
# any scan). Debian tracker snapshot: 2026-10-14T13:08Z.
#
# Base pinned by index digest; urllib3 pinned to the exact Debian version.
# Other dependencies resolve at build time; the image tarball SHA-256 in
# scanners/reports/versions-backport-fix-cve.json is the image's identity.
# Build/scan with --platform=linux/amd64. The package is installed, never run.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update && \
    apt-get install -y --no-install-recommends python3-urllib3=1.26.12-1+deb12u4 && \
    rm -rf /var/lib/apt/lists/*

CMD ["sleep", "3600"]
