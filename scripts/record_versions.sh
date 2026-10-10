#!/usr/bin/env bash
# Records tool + DB versions and the scanned image's identity, for reproducibility.
# Usage: scripts/record_versions.sh <image-tarball> <output.json>
set -euo pipefail
TAR="$1"; OUT="$2"
jq -n \
  --arg date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg tar "$(basename "$TAR")" \
  --arg sha "$(shasum -a 256 "$TAR" | cut -d' ' -f1)" \
  --argjson trivy "$(trivy version --format json)" \
  --argjson grype "$(grype version -o json)" \
  --argjson grypedb "$(grype db status -o json)" \
  '{recorded_at_utc:$date, image_tarball:$tar, image_tarball_sha256:$sha,
    trivy:$trivy, grype:$grype, grype_db:$grypedb}' > "$OUT"
echo "wrote $OUT"
