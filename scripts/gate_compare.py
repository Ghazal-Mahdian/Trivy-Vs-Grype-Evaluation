#!/usr/bin/env python3
"""
gate_compare.py - run the P1/P2/P3 gates twice on every scanner report.

  native = the scanner's own severity label (same logic as gate.py)
  nvd    = reference severity from ground-truth/evidence/nvd-severities.json

Reference rules:
  - finding has a CVE (its own ID, or a related ID for Grype GHSA findings):
    use the cached NVD severity (primary score, else secondary, as fetched)
  - CVE the answer keys mark DISPUTED: excluded from the reference gate
    (neither blocks nor triggers review) and counted separately
  - CVE with no usable score, or missing from the cache: UNSCORED -> REVIEW
  - finding with no CVE ID (DSA/DLA/TEMP): excluded from the reference gate
    and counted separately
Fix availability (P3) always comes from the scanner's own report.
Verdicts: BLOCK, REVIEW (unknown severity, never a pass), PASS.

Usage (from the repo root):
    python3 scripts/gate_compare.py
"""

import argparse
import json
import sys
from pathlib import Path

from gate import POLICY_SEVERITIES

IMAGES = ["os-package-cve", "app-dependency-cve", "backport-fix-cve",
          "minimal-base-pass", "updated-base-pass"]
POLICIES = ["P1", "P2", "P3"]
RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NEGLIGIBLE": 0, "NONE": 0}


def load_keys(gt_dir):
    """Per image key: {"listed": all ids in this key, "disputed": ids this key marks DISPUTED}."""
    keys = {}
    for p in sorted(Path(gt_dir).glob("*.json")):
        try:
            data = json.load(open(p))
        except (OSError, json.JSONDecodeError):
            continue
        entries = data.get("entries") if isinstance(data, dict) else None
        listed, disputed = set(), set()
        for e in entries or []:
            ids = set(a for a in (e.get("aliases") or []) if a)
            if e.get("cve_id"):
                ids.add(e["cve_id"])
            listed |= ids
            if str(e.get("affected_status") or e.get("status") or "").upper() == "DISPUTED":
                disputed |= ids
        keys[p.stem] = {"listed": listed, "disputed": disputed}
    return keys


# Disputes that apply to ANY image sharing the same base OS (glibc CVE-2019-1010022:
# NVD rates it Critical, upstream treats it as a non-security bug). Layout-specific
# disputes (e.g. the lockfile image's declared-but-not-installed npm packages) are
# NOT shared: they apply only to the image whose key lists them.
SHARED_DISPUTED = {"CVE-2019-1010022"}


def disputed_for(keys, img):
    """An image's own key decides for everything it lists. Anything it does not list
    is excluded only if it is in SHARED_DISPUTED."""
    own = keys.get(img, {"listed": set(), "disputed": set()})
    return set(own["disputed"]) | (SHARED_DISPUTED - own["listed"])


def extract(scanner, path):
    with open(path) as f:
        data = json.load(f)
    out = []
    if scanner == "trivy":
        for result in data.get("Results") or []:
            for v in result.get("Vulnerabilities") or []:
                vid = v.get("VulnerabilityID") or ""
                out.append({
                    "id": vid,
                    "package": v.get("PkgName"),
                    "native": (v.get("Severity") or "UNKNOWN").upper(),
                    "fix": bool(v.get("FixedVersion")),
                    "cves": [vid] if vid.startswith("CVE-") else [],
                })
    else:
        for m in data.get("matches") or []:
            vuln = m.get("vulnerability", {})
            vid = vuln.get("id") or ""
            ids = [vid] + [r.get("id") or "" for r in (m.get("relatedVulnerabilities") or [])]
            cves = []
            for i in ids:
                if i.startswith("CVE-") and i not in cves:
                    cves.append(i)
            out.append({
                "id": vid,
                "package": m.get("artifact", {}).get("name"),
                "native": (vuln.get("severity") or "UNKNOWN").upper(),
                "fix": vuln.get("fix", {}).get("state") == "fixed",
                "cves": cves,
            })
    return out


def reference(f, cache, disputed):
    if not f["cves"]:
        return "NO_CVE"
    if any(c in disputed for c in f["cves"]) or f["id"] in disputed:
        return "DISPUTED"
    present = [c for c in f["cves"] if c in cache]
    if not present:
        return "NOT_CACHED"
    for c in present:
        sev = (cache[c] or {}).get("severity")
        if sev in RANK:
            return sev
    return "UNSCORED"


def verdict(findings, key, policy):
    sevs = POLICY_SEVERITIES[policy]
    blocking = [f for f in findings
                if f[key] in sevs and (policy != "P3" or f["fix"])]
    if blocking:
        return "BLOCK"
    if key == "native":
        review = any(f["native"] == "UNKNOWN" for f in findings)
    else:
        review = any(f["ref"] in ("UNSCORED", "NOT_CACHED") for f in findings)
    return "REVIEW" if review else "PASS"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--reports-dir", default="scanners/reports")
    ap.add_argument("--cache", default="ground-truth/evidence/nvd-severities.json")
    ap.add_argument("--ground-truth", default="ground-truth")
    ap.add_argument("--images", nargs="*", default=IMAGES)
    args = ap.parse_args()

    try:
        with open(args.cache) as f:
            cache = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read NVD cache {args.cache}: {e}")
        sys.exit(2)

    keys = load_keys(args.ground_truth)

    for img in args.images:
        disputed = disputed_for(keys, img)
        print(f"Disputed CVEs excluded from the reference gate for {img}:",
              ", ".join(sorted(disputed)) if disputed else "(none)")
        for scanner in ("trivy", "grype"):
            path = Path(args.reports_dir) / f"{scanner}-{img}.json"
            print(f"== {img} {scanner}")
            if not path.exists():
                print(f"  missing report: {path}")
                continue
            findings = extract(scanner, path)
            for f in findings:
                f["ref"] = reference(f, cache, disputed)

            gates = " | ".join(
                f"{p} {verdict(findings, 'native', p)}->{verdict(findings, 'ref', p)}"
                for p in POLICIES)
            print(f"  gates (native -> nvd): {gates}")

            scored = [f for f in findings if f["native"] in RANK and f["ref"] in RANK]
            equal = sum(1 for f in scored if RANK[f["native"]] == RANK[f["ref"]])
            lower = sum(1 for f in scored if RANK[f["native"]] < RANK[f["ref"]])
            higher = sum(1 for f in scored if RANK[f["native"]] > RANK[f["ref"]])
            missed_high = sum(1 for f in scored
                              if RANK[f["ref"]] >= 3 and RANK[f["native"]] < 3)
            extra_high = sum(1 for f in scored
                             if RANK[f["native"]] >= 3 and RANK[f["ref"]] < 3)
            print(f"  labels: equal {equal}/{len(scored)} scored, "
                  f"native lower {lower}, native higher {higher} | "
                  f"High line: reference-High but native below {missed_high}, "
                  f"native-High but reference below {extra_high}")

            no_cve = sum(1 for f in findings if f["ref"] == "NO_CVE")
            dis = sum(1 for f in findings if f["ref"] == "DISPUTED")
            unscored = sum(1 for f in findings if f["ref"] == "UNSCORED")
            not_cached = sum(1 for f in findings if f["ref"] == "NOT_CACHED")
            native_unknown = sum(1 for f in findings if f["native"] == "UNKNOWN")
            print(f"  not scored: {no_cve} without CVE ID (excluded), "
                  f"{dis} disputed (excluded), {unscored} unscored CVEs, "
                  f"{not_cached} not in cache; native UNKNOWN: {native_unknown}")


if __name__ == "__main__":
    main()
