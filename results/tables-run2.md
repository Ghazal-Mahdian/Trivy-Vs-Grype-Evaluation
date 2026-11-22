## Detection against the answer keys

| Image | Trivy caught | Grype caught | Trivy severity = NVD | Grype severity = NVD |
|---|---|---|---|---|
| OS packages (EOL Debian) | 4/5 | 5/5 | 3/4 | 4/5 |
| Python app dependency | 5/5 | 5/5 | 5/5 | 5/5 |
| Vendor-backported fixes | 3/3 | 3/3 | 3/3 | 3/3 |
| Clean minimal base | no keyed entries | no keyed entries | - | - |
| Updated base | no keyed entries | no keyed entries | - | - |
| Go binary | 2/2 | 1/2 | 2/2 | 1/1 |
| Node, installed | 2/2 | 2/2 | 2/2 | 2/2 |
| Node, lockfile only | disputed reported 0/2 | disputed reported 0/2 | - | - |
| Java shaded jar | 9/9 | 9/9 | 8/9 | 8/9 |
| **All keyed entries** | **25/26** | **25/26** |  |  |

## Release gate verdicts (Trivy / Grype)

| Image | P1 | P2 | P3 |
|---|---|---|---|
| OS packages (EOL Debian) | BLOCK / BLOCK | BLOCK / BLOCK | BLOCK / BLOCK |
| Python app dependency | REVIEW / BLOCK | BLOCK / BLOCK | BLOCK / BLOCK |
| Vendor-backported fixes | BLOCK / BLOCK | BLOCK / BLOCK | BLOCK / BLOCK |
| Clean minimal base | REVIEW / PASS | REVIEW / PASS | REVIEW / PASS |
| Updated base | BLOCK / BLOCK | BLOCK / BLOCK | REVIEW / PASS |
| Go binary | REVIEW / PASS | BLOCK / PASS | REVIEW / PASS |
| Node, installed | BLOCK / BLOCK | BLOCK / BLOCK | BLOCK / BLOCK |
| Node, lockfile only | REVIEW / PASS | REVIEW / PASS | REVIEW / PASS |
| Java shaded jar | BLOCK / BLOCK | BLOCK / BLOCK | BLOCK / BLOCK |

## Gate agreement tally

| Measure | Count |
|---|---|
| Cells compared (images x 3 policies) | 27 |
| Identical verdict label | 16 |
| Different label | 11 |
| Different release decision (one PASS, the other not) | 10 |
|   of which Trivy is the stricter tool | 10 |
|   of which Grype is the stricter tool | 0 |
|   of which Trivy REVIEW vs Grype PASS | 9 |
| Different release decision if REVIEW were treated as PASS | 2 |

Cells that still differ if REVIEW counts as PASS: app-dependency-cve P1 (Trivy REVIEW, Grype BLOCK); go-binary-cve P2 (Trivy BLOCK, Grype PASS)

## Raw findings reported (all packages, including base image)

| Image | Trivy | Grype |
|---|---|---|
| OS packages (EOL Debian) | 68 | 209 |
| Python app dependency | 256 | 257 |
| Vendor-backported fixes | 469 | 459 |
| Clean minimal base | 4 | 0 |
| Updated base | 237 | 231 |
| Go binary | 6 | 1 |
| Node, installed | 6 | 2 |
| Node, lockfile only | 4 | 0 |
| Java shaded jar | 13 | 9 |

## Timing on cold GitHub-hosted runners (seconds; one run per job)

| Scanner | Database setup, min to max across 9 images | Scan with database local, min to max across 27 runs |
|---|---|---|
| Trivy | 4.6 to 19.5 (median 5.0) | 0.1 to 2.1 (median 0.1) |
| Grype | 48.6 to 81.8 (median 79.9) | 0.9 to 3.4 (median 1.7) |
