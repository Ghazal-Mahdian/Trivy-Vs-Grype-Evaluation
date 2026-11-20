# CI dataset: all 9 images, both scanners, one run

Reports, gate verdicts, timings and tool/database info from one GitHub Actions run of
`.github/workflows/scan.yml`. This is the same-day dataset the paper's tables are built from.

- Run: https://github.com/Ghazal-Mahdian/Trivy-Vs-Grype-Evaluation/actions/runs/44117670618
- Workflow commit: fcf833f
- Started: 2026-11-17 (UTC)
- Runner: GitHub-hosted `ubuntu-24.04`, one fresh runner per job (cold start)
- Trivy 0.74.0, Grype 0.120.0 (Syft v1.54.0 inside Grype)
- Trivy vulnerability DB: UpdatedAt 2026-11-17 13:00 UTC. Grype DB: built 2026-11-17 06:20 UTC.
- Scans use the saved image tarball (`docker save`), `linux/amd64`.

## File names (one set per scanner and image)

| File | Content |
|---|---|
| `trivy-<image>.json`, `grype-<image>.json` | the raw scanner report (first of three scan runs) |
| `verdicts-<scanner>-<image>.txt` | gate verdict for P1, P2, P3 (PASS, BLOCK, REVIEW, or ERROR = fail closed) |
| `gate-<scanner>-<image>-P<n>.txt` | gate output for that policy |
| `timing-<scanner>-<image>.txt` | `db_prep_seconds` (database download) and `scan_run_1..3` (scan time, database local) |
| `tool-<scanner>-<image>.txt` | tool version and database dates |

## Exception: trivy on java-shaded-jar-cve

The first attempt of this one job failed at "Build image": Maven could not download its build
plugins from Maven Central (30 second timeouts). The job was rerun on 2026-11-20 (attempt 2).
So its Trivy database is from 2026-11-20 (Trivy DB UpdatedAt 2026-11-20 18:59 UTC, Java DB
UpdatedAt 2026-11-20 01:09 UTC), while Grype's Java job used the 2026-11-17 database.
The image is therefore not a strict same-day comparison. Detection and verdicts for that image
match the earlier local run (both tools 9/9, BLOCK on P1, P2 and P3).

## Notes

- Timing is one run on shared hosted runners; variation between runs is not measured.
- Gate verdicts use each scanner's own severity labels (native), as in the main experiment.
