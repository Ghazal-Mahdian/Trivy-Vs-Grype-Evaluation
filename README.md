# Trivy vs Grype: Container Vulnerability Detection and CI/CD Release Gating

An empirical evaluation of two open-source container scanners, [Trivy](https://github.com/aquasecurity/trivy) 0.74.0 and [Grype](https://github.com/anchore/grype) 0.120.0 (Syft 1.54.0). It asks two questions:

1. **Detection:** how well does each scanner find the vulnerabilities that are really present in a container image, and avoid reporting ones that aren't?
2. **Release gating:** when each scanner drives a CI/CD "block or ship" decision, do the two tools reach the same verdict?

Each test image is purpose-built and paired with an **answer key** written from OSV, NVD and vendor trackers, not from scanner output. Keys (and, for later images, predictions about each tool's result) were committed **before** the image was scanned.

**Author:** Ghazal Mahdian · MS Cybersecurity, California State University, Dominguez Hills

**Status:** all nine images are scanned, scored and gated, and a same-day GitHub Actions dataset is collected. The paper is being finished.

---

## Main results

Numbers come from the CI dataset in [`results/ci-run-2026-11-17`](results/ci-run-2026-11-17), turned into tables by [`scripts/make_tables.py`](scripts/make_tables.py). Full tables: [`results/tables.md`](results/tables.md).

- **Detection:** both tools caught **25 of 26** keyed vulnerabilities, but missed different ones. Trivy missed CVE-2021-3999 on the old OS image (D1). Grype missed the jwt-go CVE-2020-26160 in the Go binary (D7).
- **Gate verdicts:** across 27 image × policy cells, the tools matched in **16** and differed in **11**. In 10 of those 11 the release decision changed, and in all 10 Trivy was the stricter one. In 9 of them Trivy returned REVIEW where Grype returned PASS, because Trivy reports Debian advisory IDs with unknown severity (D4).
- **Finding counts don't predict verdicts:** for example the OS image has 68 Trivy findings vs 209 Grype findings, yet both tools block on all three policies.
- **CI timing (single run):** database setup took a median of 5.4 s for Trivy vs 64.8 s for Grype. The scans themselves took a few seconds or less.

Every difference was checked against the raw reports and is logged in [`docs/verified-differences.md`](docs/verified-differences.md), including the ones whose cause is still open.

---

## Method

### 1. Nine purpose-built images
Each image tests one scenario and is pinned by base-image digest, built for `linux/amd64`.

| Image | Scenario |
|---|---|
| [`os-package-cve`](images/os-package-cve/Dockerfile) | Unfixed OS-package CVEs on end-of-life Debian (stretch-slim) |
| [`app-dependency-cve`](images/app-dependency-cve/Dockerfile) | One vulnerable PyPI package (`requests 2.19.1`) |
| [`backport-fix-cve`](images/backport-fix-cve/Dockerfile) | Debian backports fixes without changing the version number; reporting them is a false positive |
| [`minimal-base-pass`](images/minimal-base-pass) | A clean distroless base that should pass |
| [`updated-base-pass`](images/updated-base-pass) | A fully updated Debian base |
| [`go-binary-cve`](images/go-binary-cve) | Vulnerable modules inside a compiled Go binary, plus negative controls |
| [`node-transitive-installed`](images/node-transitive-installed) | A vulnerable transitive npm dependency, installed |
| [`node-transitive-lockfile`](images/node-transitive-lockfile) | The same kind of packages only declared in a lockfile, not installed |
| [`java-shaded-jar-cve`](images/java-shaded-jar-cve) | Libraries relocated inside one fat jar, plus a clean control library |

### 2. Answer keys: [`ground-truth/`](ground-truth/)
Each entry records the package, version, CVE and aliases, a status, the NVD reference severity, and the source checked.
- **Statuses:** `AFFECTED` (should be reported), `FIXED_BY_BACKPORT` (reporting it is a false positive), `DISPUTED` (counted separately, for or against neither tool).
- **Reference severity:** NVD primary CVSS, otherwise a recorded secondary source.
- Evidence snapshots are in [`ground-truth/evidence/`](ground-truth/evidence/).

### 3. Scoring: [`scripts/compare_findings.py`](scripts/compare_findings.py)
Matches each tool's JSON report to the key. Matching is alias-aware (GHSA vs CVE) and compares Maven coordinates by artifact name. It is scoped to the packages named in the key.

### 4. Release gates: [`scripts/gate.py`](scripts/gate.py)
Applied to **one** scanner's report at a time, using that scanner's own severity labels. The two reports are never combined.

| Policy | Rule |
|---|---|
| P1 | Block on any Critical |
| P2 | Block on any High or Critical |
| P3 | Block on High or Critical only if a fix is available |

Exit codes: `0` PASS, `1` BLOCK, `2` error (a missing or invalid report fails closed), `3` REVIEW (a finding has unknown severity and nothing else blocks). [`scripts/gate_compare.py`](scripts/gate_compare.py) also re-rates findings with NVD severities as a side check.

### 5. CI: [`.github/workflows/scan.yml`](.github/workflows/scan.yml)
One job per scanner × image on a fresh runner. It downloads the database (timed separately), scans three times (timed), records the P1–P3 verdicts, and uploads the reports. The dataset from run 44117670618 is in [`results/ci-run-2026-11-17`](results/ci-run-2026-11-17) with its own README (versions, database dates, one job rerun).

---

## Repository layout

```
images/            Dockerfiles, one per scenario
ground-truth/      Answer keys (JSON) + evidence (incl. NVD severity cache)
scanners/reports/  Raw local Trivy and Grype JSON + recorded tool/DB versions
scripts/           compare_findings.py · gate.py · gate_compare.py · fetch_nvd.py · make_tables.py · record_versions.sh
results/           CI dataset (ci-run-2026-11-17) and generated tables.md
docs/              verified-differences.md and analysis notes
.github/workflows/ scan.yml (CI scan, timing and gate)
```

## Reproduce

Requires Docker, Trivy, Grype, `jq` and Python 3. Run from the repo root.

```bash
# 1. Build and save one image (example: app-dependency-cve)
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

# 5. Rebuild the paper tables from the CI dataset
python3 scripts/make_tables.py
```

To rerun the CI scan, use the **Actions** tab, choose the scan workflow, and run it with `workflow_dispatch`.

Results can shift as the vulnerability databases update, so the tool and database versions are recorded with every run.

---

## Known limitations

- **Small test set:** nine images and 26 keyed entries show specific differences, not a general ranking.
- **REVIEW rule added after seeing data:** it was wired into the gate after the clean minimal image, where the earlier prediction had been PASS.
- **Two harness bugs** were found and fixed (Maven package names; disputed CVEs leaking between images). Re-scoring every image changed only Trivy's Java result (0/9 to 9/9).
- **Keys are not fully independent:** OSV and GHSA data is upstream of both scanners' databases, and NVD is a severity reference, not the truth.
- **Precision was not sampled:** findings outside the keys were counted, not checked one by one.
- **Single CI run:** timing is from one run on one day, and the Trivy Java job was rerun with a later database (documented in the dataset README).
- **Open causes:** why Trivy missed CVE-2021-3999 (D1) and why Grype missed the jwt-go CVE (D7), and why Grype reports CVE-2026-115557 on CPython when Trivy does not (D8).
- **CI hardening:** the workflow installs tools with the official install scripts and pins actions by tag, not by commit hash.
