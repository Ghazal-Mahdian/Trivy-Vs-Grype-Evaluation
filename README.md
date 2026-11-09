# Trivy vs Grype: Container Vulnerability Detection and CI/CD Release Gating

An empirical evaluation of two open-source container scanners, [Trivy](https://github.com/aquasecurity/trivy) and [Grype](https://github.com/anchore/grype). It asks two questions:

1. **Detection accuracy:** how well does each scanner find the vulnerabilities that are really present in a container image, and avoid reporting ones that aren't?
2. **Release gating:** when each scanner drives a CI/CD "block or ship" decision, do the two tools reach the same verdict, and does a raw finding count predict that verdict?

Each test image is purpose-built and paired with a **ground-truth answer key**. The key is committed before the image is scanned and verified against NVD and vendor security trackers, so scanner output is never treated as its own proof.

**Status:** in progress. Images 1–2 are scanned, scored, and gated. Image 3 (vendor-backported fixes) has its answer key committed and is next in the pipeline.

**Author:** Ghazal Mahdian · MS Cybersecurity, California State University, Dominguez Hills

---

## Results so far

### Detection against the answer key

| Image | What it tests | Key entries | Trivy | Grype |
|---|---|---|---|---|
| `os-package-cve` | Vulnerable OS packages on an end-of-life distro (Debian 9) | 5 scored + 1 disputed | **4 / 5** | **5 / 5** |
| `app-dependency-cve` | Vulnerable Python dependency (`requests 2.19.1`) | 5 | **5 / 5** | **5 / 5** |
| `backport-fix-cve` | Vendor-backported fixes (Debian 12 `python3-urllib3`) | 10 (7 fixed by backport, 3 affected) | pending | pending |

Total findings on `os-package-cve`: **Trivy 68, Grype 209**, for the same image and the same day's databases.

### Release-gate verdicts

| Policy | Rule | `os-package-cve` | `app-dependency-cve` |
|---|---|---|---|
| P1 | Block on any Critical | Both **block** | Both **pass** |
| P2 | Block on High or Critical | Both **block** (Trivy 30 vs Grype 69 blocking findings) | Both **block** |
| P3 | Block on High/Critical **only if a fix exists** | Both **block** | Both **block** (1 blocking finding each) |

**Early finding:** Grype reported about 3× more findings than Trivy on image 1, yet the two tools reached the **same verdict in all six image × policy cells**. Finding volume alone does not predict the release decision. Later images are designed so that verdicts *can* diverge, for example a patched counterpart that should pass P2/P3, and vendor backports where one scanner may raise false positives.

---

## Method

### 1. Purpose-built test images
Each image isolates one scenario, is pinned by base-image digest, and is built for `linux/amd64`. Packages are installed but never run.

| Image | Base | Scenario |
|---|---|---|
| [`os-package-cve`](images/os-package-cve/Dockerfile) | `debian:stretch-slim` (EOL, frozen archive) | Unfixed OS-package CVEs that will never change |
| [`app-dependency-cve`](images/app-dependency-cve/Dockerfile) | `python:3.12-slim` | One vulnerable PyPI package, installed `--no-deps` to isolate it |
| [`backport-fix-cve`](images/backport-fix-cve/Dockerfile) | `debian:bookworm-slim` | Debian keeps upstream version `1.26.12` but backports security fixes. A scanner that trusts the version number alone will report false positives. |

### 2. Ground-truth answer keys
Each image has a JSON key in [`ground-truth/`](ground-truth/) (plus a human-readable twin for image 1). Every entry records the package, installed version, CVE and aliases, affected status, NVD reference severity, fix status, and the source checked.

- **Severity reference:** NVD primary CVSS score. Each scanner's native severity is kept alongside for comparison.
- **Disputed CVEs** are reported in their own category and count toward neither recall nor precision.
- **New status for image 3:** `FIXED_BY_BACKPORT`. Reporting one of these counts as a false positive.
- Supporting evidence, such as Debian tracker snapshots, is stored in [`ground-truth/evidence/`](ground-truth/evidence/).

### 3. Scoring: [`scripts/compare_findings.py`](scripts/compare_findings.py)
- Parses Trivy and Grype JSON reports and matches findings to the key.
- Matching is **alias-aware**: Grype often reports a GHSA ID with the CVE listed as related, and both forms count as a match.
- It is **scoped to the packages named in the key**, so base-image noise doesn't distort scores.
- Prints a per-entry table and summary, with an optional `--csv` export.

### 4. Release gates: [`scripts/gate.py`](scripts/gate.py)
- Applies policies P1–P3 to one scanner's report, using that scanner's native severities.
- A scanner error or a missing report **blocks** the release.
- The two scanners are never merged into a single decision; each is gated on its own.

### 5. Reproducibility: [`scripts/record_versions.sh`](scripts/record_versions.sh)
- Scans run against a saved image tarball, not a live tag.
- The tarball's SHA-256 and the exact scanner and database versions are recorded with each run, in [`scanners/reports/versions*.json`](scanners/reports/).
- Recorded versions: **Trivy 0.74.0**, **Grype 0.120.0** (Syft 1.54.0, DB schema v6).

---

## Repository layout

```
images/            Dockerfiles, one per test scenario
ground-truth/      Answer keys (JSON) + evidence snapshots
scanners/reports/  Raw Trivy and Grype JSON output + recorded tool/DB versions
scripts/           compare_findings.py · gate.py · record_versions.sh
docs/              Analysis notes (e.g. unscored disagreements on image 2)
```

## Reproduce a result

Requires Docker, Trivy, Grype, `jq`, and Python 3. Run from the repo root.

```bash
# 1. Build and save the image (example: app-dependency-cve)
docker build --platform=linux/amd64 -t app-dependency-cve images/app-dependency-cve
docker save app-dependency-cve -o app-dependency-cve.tar

# 2. Scan the saved tarball with both tools
trivy image --input app-dependency-cve.tar --scanners vuln --format json \
  -o scanners/reports/trivy-app-dependency-cve.json
grype docker-archive:app-dependency-cve.tar -o json > scanners/reports/grype-app-dependency-cve.json

# 3. Score against the answer key
python3 scripts/compare_findings.py \
  --ground-truth ground-truth/app-dependency-cve.json \
  --trivy scanners/reports/trivy-app-dependency-cve.json \
  --grype scanners/reports/grype-app-dependency-cve.json

# 4. Apply a release gate
python3 scripts/gate.py --scanner trivy --policy P2 \
  --report scanners/reports/trivy-app-dependency-cve.json
```

Results can shift as the scanners' vulnerability databases update. That's why tool and database versions are recorded with every run.

---

## Roadmap

- [x] Benchmark design, image 1 ground truth, local scans
- [x] Scoring with alias matching and disputed-entry handling
- [x] Image 2 (application dependency) scanned and scored
- [x] Release-gate policies P1–P3 applied to images 1–2
- [x] Image 3 (vendor backports) Dockerfile and answer key committed before scanning
- [ ] Score image 3, including backport false positives
- [ ] Automate scanning, scoring, and gating in GitHub Actions
- [ ] Expand to 6–8 images (transitive dependency, mixed severities, patched counterpart)
- [ ] Measure scan time and resource cost
- [ ] Final write-up

## Known limitations

- **Image 1 key was seeded from scanner output.** Its end-of-life base made pre-selecting CVEs unreliable, so each candidate was then verified independently against Debian and upstream advisories. Images 2 and 3 have keys written before any scan.
- **Small sample size.** Early results describe the images tested so far, not scanners in general.
- **Scope.** Findings outside the packages named in a key are recorded, for example in [`docs/image2-unscored-disagreements.md`](docs/image2-unscored-disagreements.md), but are not yet scored.
