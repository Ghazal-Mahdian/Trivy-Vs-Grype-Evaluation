#!/usr/bin/env python3
"""precision_check.py - score OS-package findings against the Debian Security Tracker.

Rules are in docs/precision-plan.md (written before this ran). Usage, from the repo root:
  python3 scripts/precision_check.py [--data results/ci-run-2026-11-17]
Writes results/precision.md and results/precision-findings.csv.
"""
import argparse, csv, json, re, subprocess, collections
from pathlib import Path

IMAGES = ["app-dependency-cve", "backport-fix-cve", "minimal-base-pass", "updated-base-pass",
          "go-binary-cve", "node-transitive-installed", "node-transitive-lockfile", "java-shaded-jar-cve"]
# os-package-cve (Debian 9 stretch) is out of scope: the tracker has no stretch data.
RELEASES = {"12": "bookworm", "13": "trixie"}
_cmp = {}

def newer(a, b):
    """True if Debian version a < b."""
    k = (a, b)
    if k not in _cmp:
        _cmp[k] = subprocess.run(["dpkg", "--compare-versions", a, "lt", b]).returncode == 0
    return _cmp[k]

def clean(v):  # drop binNMU suffix: tracker versions are source versions
    return re.sub(r"\+b\d+$", "", v or "")

def trivy_findings(path):
    d = json.load(open(path)); rel = RELEASES.get(d["Metadata"]["OS"]["Name"].split(".")[0])
    out = []
    for r in d["Results"]:
        if r.get("Class") != "os-pkgs": continue
        for v in r.get("Vulnerabilities") or []:
            out.append(dict(pkg=v["PkgName"], ver=v["InstalledVersion"], ids=[v["VulnerabilityID"]], src=None))
    return rel, out

def grype_findings(path):
    d = json.load(open(path)); rel = RELEASES.get(str(d["distro"]["version"]).split(".")[0]); out = []
    for m in d["matches"]:
        a = m["artifact"]
        if a["type"] != "deb": continue
        ids = [m["vulnerability"]["id"]] + [x["id"] for x in m.get("relatedVulnerabilities", [])]
        ups = [u["name"] for u in a.get("upstreams") or []]
        out.append(dict(pkg=a["name"], ver=a["version"], ids=ids, src=ups[0] if ups else None))
    return rel, out

def classify(tr, rel, srcs, f):
    """Return (label, reason). srcs: candidate source package names."""
    saw = []
    for i in f["ids"]:
        for s in srcs:
            e = tr.get(s, {}).get(i)
            if not e: continue
            r = e.get("releases", {}).get(rel)
            if not r: saw.append("no_release_entry"); continue
            st = r.get("status")
            if st == "open": return "CORRECT", "tracker open"
            if st == "resolved":
                fv = r.get("fixed_version", "")
                if fv in ("0", ""): return "FALSE_POSITIVE", "tracker: not affected"
                return ("CORRECT", "installed older than fix") if newer(clean(f["ver"]), fv) \
                    else ("FALSE_POSITIVE", f"fixed in {fv} <= installed")
            saw.append(f"status_{st}")
    return "UNDECIDABLE", (saw[0] if saw else "not_in_tracker")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="results/ci-run-2026-11-17")
    ap.add_argument("--tracker", default="ground-truth/evidence/debian-tracker.json")
    a = ap.parse_args()
    tr = json.load(open(a.tracker)); data = Path(a.data); rows = []
    for img in IMAGES:
        rel, tf = trivy_findings(data / f"trivy-{img}.json")
        _, gf = grype_findings(data / f"grype-{img}.json")
        b2s = {f["pkg"]: f["src"] for f in gf if f["src"]}  # binary -> source, from Grype
        seen = {}
        for tool, fs in (("trivy", tf), ("grype", gf)):
            for f in fs:
                srcs = [x for x in (f["src"] or b2s.get(f["pkg"]), f["pkg"]) if x]
                lab, why = classify(tr, rel, srcs, f)
                key = (f["pkg"], f["ids"][0] if f["ids"][0].startswith("CVE") else
                       next((i for i in f["ids"] if i.startswith("CVE")), f["ids"][0]))
                rows.append(dict(image=img, tool=tool, pkg=f["pkg"], id=f["ids"][0], key=key,
                                 label=lab, reason=why, version=f["ver"]))
    # who else reports it
    by = collections.defaultdict(set)
    for r in rows: by[(r["image"], r["key"])].add(r["tool"])
    for r in rows: r["reported_by"] = "both" if len(by[(r["image"], r["key"])]) == 2 else "only_" + r["tool"]
    with open("results/precision-findings.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=[k for k in rows[0] if k != "key"], extrasaction="ignore"); w.writeheader(); w.writerows(rows)

    def tally(rs):
        c = collections.Counter(r["label"] for r in rs); ok, fp, un = c["CORRECT"], c["FALSE_POSITIVE"], c["UNDECIDABLE"]
        p = f"{100*ok/(ok+fp):.1f}%" if ok + fp else "-"
        return ok, fp, un, p
    L = ["## Precision against the Debian Security Tracker (OS-package findings)\n",
         "| Image | Tool | Correct | False pos. | Undecidable | Precision |", "|---|---|---|---|---|---|"]
    for img in IMAGES:
        for tool in ("trivy", "grype"):
            rs = [r for r in rows if r["image"] == img and r["tool"] == tool]
            if rs: L.append(f"| {img} | {tool} | " + " | ".join(map(str, tally(rs))) + " |")
    for tool in ("trivy", "grype"):
        L.append(f"| **All** | **{tool}** | " + " | ".join(map(str, tally([r for r in rows if r["tool"] == tool]))) + " |")
    L += ["\n## By who reports it (all images)\n", "| Tool | Reported by | Correct | False pos. | Undecidable | Precision |", "|---|---|---|---|---|---|"]
    for tool in ("trivy", "grype"):
        for who in ("both", "only_" + tool):
            rs = [r for r in rows if r["tool"] == tool and r["reported_by"] == who]
            L.append(f"| {tool} | {who} | " + " | ".join(map(str, tally(rs))) + " |")
    L += ["\n## Correct findings the other tool did not report (relative misses)\n", "| Tool that missed | Count |", "|---|---|"]
    for tool, other in (("trivy", "grype"), ("grype", "trivy")):
        n = sum(1 for r in rows if r["tool"] == other and r["reported_by"] == "only_" + other and r["label"] == "CORRECT")
        L.append(f"| {tool} | {n} |")
    L += ["\n## Why findings were undecidable\n", "| Tool | Reason | Count |", "|---|---|---|"]
    c = collections.Counter((r["tool"], r["reason"]) for r in rows if r["label"] == "UNDECIDABLE")
    for (tool, why), n in sorted(c.items()): L.append(f"| {tool} | {why} | {n} |")
    Path("results/precision.md").write_text("\n".join(L) + "\n"); print("\n".join(L))

main()
