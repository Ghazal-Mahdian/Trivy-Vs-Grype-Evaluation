#!/usr/bin/env python3
"""
compare_findings.py

Loads Trivy's JSON report, Grype's JSON report, and a ground-truth file for
one test image, then reports — for each ground-truth entry — whether each
scanner found it, and whether severity/fix-status agree.

This does NOT yet compute full precision/recall across *every* finding each
scanner reported (that needs every scanner finding checked against ground
truth, including ones we have NOT verified yet — more on that at the bottom
of this file). Right now it answers a narrower, still useful question:
"for the things we KNOW are true, did each scanner catch them correctly?"
That's recall on the verified subset. Precision comes later once more
ground-truth entries exist to check extra scanner findings against.

Usage:
    python3 scripts/compare_findings.py \
        --ground-truth ground-truth/os-package-cve.json \
        --trivy scanners/reports/trivy-os-package-cve.json \
        --grype scanners/reports/grype-os-package-cve.json
"""

import argparse
import json
import sys


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def extract_trivy_findings(trivy_report):
    """
    Trivy's JSON nests vulnerabilities under Results[].Vulnerabilities[].
    Each finding becomes a simple dict: cve_id, package, version, severity.
    """
    findings = []
    for result in trivy_report.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({
                "cve_id": vuln.get("VulnerabilityID"),
                "package": vuln.get("PkgName"),
                "version": vuln.get("InstalledVersion"),
                "severity": (vuln.get("Severity") or "").upper(),
                "fixed_version": vuln.get("FixedVersion", ""),
            })
    return findings


def extract_grype_findings(grype_report):
    """
    Grype's JSON lists matches[], each with a vulnerability{} block and an
    artifact{} block. Same normalization target as Trivy's output above.
    """
    findings = []
    for match in grype_report.get("matches", []) or []:
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        fix = vuln.get("fix", {})
        findings.append({
            "cve_id": vuln.get("id"),
            "package": artifact.get("name"),
            "version": artifact.get("version"),
            "severity": (vuln.get("severity") or "").upper(),
            "fix_state": fix.get("state", ""),
        })
    return findings


def check_entry_against_scanner(entry, scanner_findings, scanner_name):
    """
    For one ground-truth entry (which may cover multiple package names, as
    CVE-2022-29458 does), find any matching scanner finding and report
    whether it was caught, and whether severity matches.
    """
    cve_id = entry["cve_id"]
    expected_packages = set(entry["packages"])
    expected_severity = entry["reference_severity"]

    matches = [
        f for f in scanner_findings
        if f["cve_id"] == cve_id and f["package"] in expected_packages
    ]

    if not matches:
        return {
            "scanner": scanner_name,
            "cve_id": cve_id,
            "caught": False,
            "packages_matched": [],
            "severity_agrees": None,
        }

    packages_matched = sorted(set(m["package"] for m in matches))
    severities_found = set(m["severity"] for m in matches)
    severity_agrees = severities_found == {expected_severity}

    return {
        "scanner": scanner_name,
        "cve_id": cve_id,
        "caught": True,
        "packages_matched": packages_matched,
        "packages_missing": sorted(expected_packages - set(packages_matched)),
        "severity_agrees": severity_agrees,
        "severities_found": sorted(severities_found),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--trivy", required=True)
    parser.add_argument("--grype", required=True)
    args = parser.parse_args()

    ground_truth = load_json(args.ground_truth)
    trivy_report = load_json(args.trivy)
    grype_report = load_json(args.grype)

    trivy_findings = extract_trivy_findings(trivy_report)
    grype_findings = extract_grype_findings(grype_report)

    print(f"Image: {ground_truth['image']}")
    print(f"Ground-truth entries: {len(ground_truth['entries'])}")
    print(f"Trivy raw findings loaded: {len(trivy_findings)}")
    print(f"Grype raw findings loaded: {len(grype_findings)}")
    print("-" * 70)

    for entry in ground_truth["entries"]:
        print(f"\nCVE: {entry['cve_id']}")
        print(f"  Expected severity: {entry['reference_severity']}")
        print(f"  Expected packages: {', '.join(entry['packages'])}")

        for scanner_name, findings in [("Trivy", trivy_findings), ("Grype", grype_findings)]:
            result = check_entry_against_scanner(entry, findings, scanner_name)
            if result["caught"]:
                status = "CAUGHT"
                sev_note = "severity matches" if result["severity_agrees"] else f"severity MISMATCH ({result['severities_found']})"
                missing = f", missing packages: {result['packages_missing']}" if result["packages_missing"] else ""
                print(f"  {scanner_name:6s}: {status} — {sev_note}{missing}")
            else:
                print(f"  {scanner_name:6s}: MISSED — not reported for any expected package")

    print("\n" + "-" * 70)
    print("NOTE: this run only checks recall on verified ground-truth entries.")
    print("Precision (false positives) requires checking the scanners' OTHER")
    print("findings — the ones not yet in ground-truth — which is the next")
    print("piece of work: expanding ground-truth/os-package-cve.json to cover")
    print("more of what each scanner reported, verifying each against an")
    print("advisory, the same way CVE-2022-29458 was verified.")


if __name__ == "__main__":
    main()
