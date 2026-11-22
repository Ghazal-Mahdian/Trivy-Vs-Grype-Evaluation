#!/usr/bin/env python3
"""make_tables.py - build the paper's tables from the CI dataset folder.

Reads only files (reports, verdicts, timing, answer keys). No number is typed by hand.
Detection scores come from compare_findings.py (single source of truth for scoring).

Usage (from the repo root):
  python3 scripts/make_tables.py [--data results/ci-run-2026-11-17] [--out results/tables.md]
"""
import argparse
import json
import re
import statistics
import subprocess
import sys
from pathlib import Path

IMAGES = [
    ("os-package-cve", "OS packages (EOL Debian)"),
    ("app-dependency-cve", "Python app dependency"),
    ("backport-fix-cve", "Vendor-backported fixes"),
    ("minimal-base-pass", "Clean minimal base"),
    ("updated-base-pass", "Updated base"),
    ("go-binary-cve", "Go binary"),
    ("node-transitive-installed", "Node, installed"),
    ("node-transitive-lockfile", "Node, lockfile only"),
    ("java-shaded-jar-cve", "Java shaded jar"),
]
SCANNERS = ("trivy", "grype")
POLICIES = ("P1", "P2", "P3")
SCORE_RE = re.compile(
    r"^\s+(Trivy|Grype): recall (\d+)/(\d+) \(severity matched on (\d+) of (\d+) caught\); "
    r"disputed reported (\d+)/(\d+)(?:; backported CVEs wrongly reported (\d+)/(\d+))?")


def verdicts(d, s, img):
    p = d / f"verdicts-{s}-{img}.txt"
    out = {}
    if p.exists():
        for line in p.read_text().splitlines():
            pol, _, v = line.partition(" ")
            out[pol] = v.split(" ")[0]
    return out


def timing(d, s, img):
    p = d / f"timing-{s}-{img}.txt"
    out = {}
    if p.exists():
        for line in p.read_text().splitlines():
            k, _, v = line.partition(" ")
            try:
                out[k] = float(v)
            except ValueError:
                pass
    return out


def finding_count(d, s, img):
    p = d / f"{s}-{img}.json"
    if not p.exists():
        return None
    data = json.load(open(p))
    if s == "trivy":
        return sum(len(r.get("Vulnerabilities") or []) for r in data.get("Results") or [])
    return len(data.get("matches") or [])


def score(d, img):
    cmd = [sys.executable, "scripts/compare_findings.py",
           "--ground-truth", f"ground-truth/{img}.json",
           "--trivy", str(d / f"trivy-{img}.json"),
           "--grype", str(d / f"grype-{img}.json")]
    res = subprocess.run(cmd, capture_output=True, text=True)
    out = {}
    for line in res.stdout.splitlines():
        m = SCORE_RE.match(line)
        if m:
            name = m.group(1).lower()
            out[name] = dict(hit=int(m.group(2)), total=int(m.group(3)),
                             sev_ok=int(m.group(4)), sev_of=int(m.group(5)),
                             disp=int(m.group(6)), disp_of=int(m.group(7)),
                             fp=None if m.group(8) is None else int(m.group(8)),
                             fp_of=None if m.group(9) is None else int(m.group(9)))
    return out


def md(rows, header):
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="results/ci-run-2026-11-17")
    ap.add_argument("--out", default="results/tables.md")
    a = ap.parse_args()
    d = Path(a.data)
    out = []

    # ---- Table 1: detection
    rows, tot = [], {"trivy": [0, 0], "grype": [0, 0]}
    for img, label in IMAGES:
        sc = score(d, img)
        t, g = sc.get("trivy"), sc.get("grype")
        if not t or not g:
            rows.append([label, "missing", "missing", "", ""])
            continue
        def cell(x):
            if x["total"] == 0 and x["disp_of"] == 0:
                return "no keyed entries"
            if x["total"] == 0:
                return f"disputed reported {x['disp']}/{x['disp_of']}"
            return f"{x['hit']}/{x['total']}"
        def sev(x):
            return "-" if x["hit"] == 0 else f"{x['sev_ok']}/{x['sev_of']}"
        rows.append([label, cell(t), cell(g), sev(t), sev(g)])
        for n, x in (("trivy", t), ("grype", g)):
            tot[n][0] += x["hit"]
            tot[n][1] += x["total"]
    rows.append(["**All keyed entries**", f"**{tot['trivy'][0]}/{tot['trivy'][1]}**",
                 f"**{tot['grype'][0]}/{tot['grype'][1]}**", "", ""])
    out.append("## Detection against the answer keys\n")
    out.append(md(rows, ["Image", "Trivy caught", "Grype caught", "Trivy severity = NVD", "Grype severity = NVD"]))

    # ---- Table 2: verdict matrix + tally
    vrows, cells = [], []
    for img, label in IMAGES:
        vt, vg = verdicts(d, "trivy", img), verdicts(d, "grype", img)
        r = [label]
        for p in POLICIES:
            t, g = vt.get(p, "?"), vg.get(p, "?")
            r.append(f"{t} / {g}")
            cells.append((img, p, t, g))
        vrows.append(r)
    out.append("\n## Release gate verdicts (Trivy / Grype)\n")
    out.append(md(vrows, ["Image", "P1", "P2", "P3"]))

    n = len(cells)
    same = sum(1 for _, _, t, g in cells if t == g)
    split = [(i, p, t, g) for i, p, t, g in cells if (t == "PASS") != (g == "PASS")]
    t_strict = sum(1 for _, _, t, g in split if t != "PASS")
    g_strict = sum(1 for _, _, t, g in split if g != "PASS")
    t_review = sum(1 for _, _, t, g in split if t == "REVIEW" and g == "PASS")
    lenient = lambda v: "PASS" if v == "REVIEW" else v
    len_split = [(i, p, t, g) for i, p, t, g in cells if (lenient(t) == "PASS") != (lenient(g) == "PASS")]
    out.append("\n## Gate agreement tally\n")
    out.append(md([
        ["Cells compared (images x 3 policies)", n],
        ["Identical verdict label", same],
        ["Different label", n - same],
        ["Different release decision (one PASS, the other not)", len(split)],
        ["  of which Trivy is the stricter tool", t_strict],
        ["  of which Grype is the stricter tool", g_strict],
        ["  of which Trivy REVIEW vs Grype PASS", t_review],
        ["Different release decision if REVIEW were treated as PASS", len(len_split)],
    ], ["Measure", "Count"]))
    if len_split:
        out.append("\nCells that still differ if REVIEW counts as PASS: " +
                   "; ".join(f"{i} {p} (Trivy {t}, Grype {g})" for i, p, t, g in len_split))

    # ---- Table 3: findings counts
    crow = [[label, finding_count(d, "trivy", img), finding_count(d, "grype", img)] for img, label in IMAGES]
    out.append("\n## Raw findings reported (all packages, including base image)\n")
    out.append(md(crow, ["Image", "Trivy", "Grype"]))

    # ---- Table 4: timing
    def collect(s):
        prep, scan = [], []
        for img, _ in IMAGES:
            t = timing(d, s, img)
            if "db_prep_seconds" in t:
                prep.append(t["db_prep_seconds"])
            scan += [t[k] for k in ("scan_run_1", "scan_run_2", "scan_run_3") if k in t]
        return prep, scan
    trow = []
    for s in SCANNERS:
        prep, scan = collect(s)
        trow.append([s.capitalize(),
                     f"{min(prep):.1f} to {max(prep):.1f} (median {statistics.median(prep):.1f})",
                     f"{min(scan):.1f} to {max(scan):.1f} (median {statistics.median(scan):.1f})"])
    out.append("\n## Timing on cold GitHub-hosted runners (seconds; one run per job)\n")
    out.append(md(trow, ["Scanner", "Database setup, min to max across 9 images", "Scan with database local, min to max across 27 runs"]))

    text = "\n".join(out) + "\n"
    Path(a.out).write_text(text)
    print(text)


if __name__ == "__main__":
    main()
