#!/usr/bin/env python3
"""
gate.py - release gate for ONE scanner's JSON report.

Policies (native severity labels of the scanner being gated):
  P1  block if any finding is CRITICAL
  P2  block if any finding is HIGH or CRITICAL
  P3  block if any HIGH or CRITICAL finding has a fix available

Unknown severity is never treated as safe: if nothing blocks but at least
one finding has UNKNOWN severity, the result is REVIEW (a human must look).

Exit codes: 0 = pass, 1 = block, 2 = error (missing/invalid report),
            3 = review needed (unknown severity present, nothing blocking).
Errors fail closed: a scan that did not complete must never look like a pass.
REVIEW also never counts as a pass.

Usage:
    python3 scripts/gate.py --scanner trivy --policy P2 --report scanners/reports/trivy-os-package-cve.json
"""

import argparse
import collections
import json
import sys

ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"]
POLICY_SEVERITIES = {
    "P1": {"CRITICAL"},
    "P2": {"CRITICAL", "HIGH"},
    "P3": {"CRITICAL", "HIGH"},
}


def fail(msg):
    print(f"ERROR: {msg}")
    print("RESULT: BLOCK (error, failing closed)")
    sys.exit(2)


def load_findings(scanner, path):
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        fail(f"cannot read report {path}: {e}")
    if not isinstance(data, dict):
        fail("report is not a JSON object")

    findings = []
    if scanner == "trivy":
        if "SchemaVersion" not in data and "Results" not in data:
            fail("does not look like a Trivy report")
        for result in data.get("Results") or []:
            for v in result.get("Vulnerabilities") or []:
                findings.append({
                    "id": v.get("VulnerabilityID"),
                    "package": v.get("PkgName"),
                    "severity": (v.get("Severity") or "UNKNOWN").upper(),
                    "fix": bool(v.get("FixedVersion")),
                })
    else:
        if not isinstance(data.get("matches"), list):
            fail("does not look like a Grype report")
        for m in data["matches"]:
            vuln = m.get("vulnerability", {})
            findings.append({
                "id": vuln.get("id"),
                "package": m.get("artifact", {}).get("name"),
                "severity": (vuln.get("severity") or "UNKNOWN").upper(),
                "fix": (vuln.get("fix", {}).get("state") == "fixed"),
            })
    return findings


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scanner", required=True, choices=["trivy", "grype"])
    ap.add_argument("--policy", required=True, choices=sorted(POLICY_SEVERITIES))
    ap.add_argument("--report", required=True)
    args = ap.parse_args()

    findings = load_findings(args.scanner, args.report)
    counts = collections.Counter(f["severity"] for f in findings)
    print(f"{args.scanner} report: {len(findings)} findings; by severity: "
          + ", ".join(f"{s}={counts[s]}" for s in ORDER if counts[s]))

    sevs = POLICY_SEVERITIES[args.policy]
    blocking = [f for f in findings if f["severity"] in sevs
                and (args.policy != "P3" or f["fix"])]
    unknown = [f for f in findings if f["severity"] == "UNKNOWN"]

    for f in blocking[:5]:
        print(f"  blocking: {f['id']} {f['package']} {f['severity']} fix={f['fix']}")
    if len(blocking) > 5:
        print(f"  ... and {len(blocking) - 5} more")

    if blocking:
        print(f"RESULT: BLOCK ({args.policy}, {len(blocking)} blocking findings)")
        sys.exit(1)

    if unknown:
        for f in unknown[:5]:
            print(f"  needs review: {f['id']} {f['package']} UNKNOWN fix={f['fix']}")
        if len(unknown) > 5:
            print(f"  ... and {len(unknown) - 5} more")
        print(f"RESULT: REVIEW ({args.policy}, {len(unknown)} findings with unknown severity)")
        sys.exit(3)

    print(f"RESULT: PASS ({args.policy})")
    sys.exit(0)


if __name__ == "__main__":
    main()
