#!/usr/bin/env python3
"""
compare_findings.py

Scores Trivy and Grype reports against a hand-verified ground-truth file for
one test image.

Matching is alias-aware: a scanner finding matches a ground-truth entry when
the finding's package is named in the entry AND the finding's ID (or any ID
the scanner lists as related, e.g. Grype's GHSA -> CVE link) equals the
entry's cve_id or one of its aliases.

Entry statuses (affected_status):
  AFFECTED           scanner SHOULD report it (counts toward recall)
  FIXED_BY_BACKPORT  vendor already fixed it; scanner should NOT report it.
                     Reporting it is a FALSE POSITIVE (severity is recorded,
                     since a wrongly reported High/Critical can wrongly block
                     a release).
  DISPUTED           counted separately: neither recall nor precision.

Only findings on packages named in the key are examined.

Usage:
    python3 scripts/compare_findings.py \
        --ground-truth ground-truth/app-dependency-cve.json \
        --trivy scanners/reports/trivy-app-dependency-cve.json \
        --grype scanners/reports/grype-app-dependency-cve.json \
        [--csv results/app-dependency-cve.csv]
"""

import argparse
import csv
import json

SERIOUS = {"HIGH", "CRITICAL"}


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def extract_trivy_findings(report):
    findings = []
    for result in report.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID")
            findings.append({
                "id": vid,
                "ids": {vid},
                "package": v.get("PkgName"),
                "version": v.get("InstalledVersion"),
                "severity": (v.get("Severity") or "").upper(),
            })
    return findings


def extract_grype_findings(report):
    findings = []
    for m in report.get("matches") or []:
        vuln = m.get("vulnerability", {})
        art = m.get("artifact", {})
        ids = {vuln.get("id")}
        for rel in m.get("relatedVulnerabilities") or []:
            ids.add(rel.get("id"))
        findings.append({
            "id": vuln.get("id"),
            "ids": ids,
            "package": art.get("name"),
            "version": art.get("version"),
            "severity": (vuln.get("severity") or "").upper(),
        })
    return findings


def wanted_ids(entry):
    return {entry["cve_id"], *entry.get("aliases", [])}


def check_entry(entry, findings):
    pkgs = set(entry["packages"])
    wanted = wanted_ids(entry)
    hits = [f for f in findings if f["package"] in pkgs and f["ids"] & wanted]
    if not hits:
        return {"caught": False}
    sevs = {h["severity"] for h in hits}
    return {
        "caught": True,
        "packages_matched": sorted({h["package"] for h in hits}),
        "packages_missing": sorted(pkgs - {h["package"] for h in hits}),
        "severities": sorted(sevs),
        "severity_agrees": sevs == {entry["reference_severity"]},
        "reported_as": sorted({h["id"] for h in hits}),
    }


def count_unkeyed(entries, findings):
    key_pkgs = {p for e in entries for p in e["packages"]}
    n = 0
    for f in findings:
        if f["package"] not in key_pkgs:
            continue
        keyed = any(
            f["package"] in e["packages"] and f["ids"] & wanted_ids(e)
            for e in entries
        )
        if not keyed:
            n += 1
    return n


def new_tally():
    return {"hit": 0, "total": 0, "sev_ok": 0,
            "disp_rep": 0, "disp_total": 0,
            "bp_rep": 0, "bp_total": 0, "bp_serious": 0}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--trivy", required=True)
    ap.add_argument("--grype", required=True)
    ap.add_argument("--csv", default=None)
    args = ap.parse_args()

    gt = load_json(args.ground_truth)
    entries = gt["entries"]
    scanners = [
        ("Trivy", extract_trivy_findings(load_json(args.trivy))),
        ("Grype", extract_grype_findings(load_json(args.grype))),
    ]

    print(f"Image: {gt['image']}")
    print(f"Ground-truth entries: {len(entries)}")
    for name, findings in scanners:
        print(f"{name} raw findings loaded: {len(findings)}")
    print("-" * 70)

    tally = {name: new_tally() for name, _ in scanners}
    rows = []

    for entry in entries:
        status = entry.get("affected_status")
        disputed = status == "DISPUTED"
        backported = status == "FIXED_BY_BACKPORT"
        print(f"\nCVE: {entry['cve_id']}")
        print(f"  Reference severity (NVD-based): {entry['reference_severity']}")
        print(f"  Expected packages: {', '.join(entry['packages'])}")
        if disputed:
            print("  ** DISPUTED: counted separately, not in recall or precision **")
        if backported:
            print("  ** FIXED BY VENDOR BACKPORT: a scanner should NOT report this **")

        for name, findings in scanners:
            r = check_entry(entry, findings)
            t = tally[name]
            if disputed:
                t["disp_total"] += 1
                if r["caught"]:
                    t["disp_rep"] += 1
                    print(f"  {name:6s}: REPORTED the disputed CVE "
                          f"(native severity {r['severities']})")
                else:
                    print(f"  {name:6s}: did not report the disputed CVE")
            elif backported:
                t["bp_total"] += 1
                if r["caught"]:
                    t["bp_rep"] += 1
                    serious = bool(set(r["severities"]) & SERIOUS)
                    if serious:
                        t["bp_serious"] += 1
                    flag = "  <-- serious: could wrongly block a release" if serious else ""
                    print(f"  {name:6s}: FALSE POSITIVE, reported as {r['reported_as']} "
                          f"(native severity {r['severities']}){flag}")
                else:
                    print(f"  {name:6s}: correctly NOT reported")
            else:
                t["total"] += 1
                if r["caught"]:
                    t["hit"] += 1
                    if r["severity_agrees"]:
                        t["sev_ok"] += 1
                    sev = ("severity matches" if r["severity_agrees"]
                           else f"severity differs, native {r['severities']}")
                    missing = (f", missing packages: {r['packages_missing']}"
                               if r["packages_missing"] else "")
                    print(f"  {name:6s}: CAUGHT as {r['reported_as']} — {sev}{missing}")
                else:
                    print(f"  {name:6s}: MISSED — not reported for any expected package")
            rows.append({
                "image": gt["image"],
                "cve_id": entry["cve_id"],
                "affected_status": status,
                "scanner": name,
                "reported": r["caught"],
                "reported_as": ";".join(r.get("reported_as", [])),
                "native_severity": ";".join(r.get("severities", [])),
                "reference_severity": entry["reference_severity"],
                "severity_agrees": r.get("severity_agrees", ""),
            })

    print("\n" + "-" * 70)
    print("SUMMARY")
    for name, findings in scanners:
        t = tally[name]
        line = (f"  {name}: recall {t['hit']}/{t['total']} "
                f"(severity matched on {t['sev_ok']} of {t['hit']} caught); "
                f"disputed reported {t['disp_rep']}/{t['disp_total']}")
        if t["bp_total"]:
            line += (f"; backported CVEs wrongly reported {t['bp_rep']}/{t['bp_total']} "
                     f"({t['bp_serious']} High/Critical)")
        line += f"; other findings on key packages not in key: {count_unkeyed(entries, findings)}"
        print(line)

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"\nWrote {args.csv}")


if __name__ == "__main__":
    main()
