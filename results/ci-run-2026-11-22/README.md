# CI dataset, repeat run (2026-11-22)

Second run of `.github/workflows/scan.yml` (GitHub Actions run 44975331421, triggered with `workflow_dispatch`, policy input P2). Same workflow, same images and same tool versions as the first run in `results/ci-run-2026-11-17`; only the vulnerability databases are newer.

- Trivy 0.74.0, Grype 0.120.0 (Syft v1.54.0).
- Trivy vulnerability DB UpdatedAt 2026-11-22 01:10 UTC; Grype DB built 2026-11-21 06:20 UTC (both read from the `tool-*.txt` files, the same in every job).
- All 18 jobs (2 scanners x 9 images) built, scanned and uploaded on the first try. No job was rerun.
- Every job shows a failed last step ("Enforce the chosen policy"). That is the gate working: exit 1 is BLOCK, exit 3 is REVIEW. It is not a pipeline error.
- 126 files, laid out the same way as the first run.

Compared with 2026-11-17: detection scores and all 27 gate verdicts are identical; raw finding counts are higher; Grype's median database setup was 79.9 s (64.8 s before) and Trivy's 5.0 s (5.4 s before); the 12 shared OS-package false positives seen in the first run are gone (see `results/precision.md`).
- Commit: c92a511fc2e5c693152d38dfac6cd19b65716022
