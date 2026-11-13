# Gate-behavior image: Debian 12 with all available updates applied.
# Same pinned base as images/backport-fix-cve, but every fixable package is
# upgraded at build time, so no fixable HIGH/CRITICAL findings should remain.
# Unfixed findings (e.g. items Debian marks "minor"/"ignored") remain, which is
# where the two scanners' severity labels may lead to different gate verdicts.
# Resolved package versions vary with build date; the image tarball SHA-256 in
# scanners/reports/versions-updated-base-pass.json is the image's identity.
# See ground-truth/updated-base-pass.json (written before any scan).
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update && \
    apt-get dist-upgrade -y --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

CMD ["sleep", "3600"]
