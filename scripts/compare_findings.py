#!/usr/bin/env python3
"""
compare_findings.py

Loads Trivy's JSON report, Grype's JSON report, and a ground-truth file for
one test image, then reports — for each ground-truth entry — whether each
scanner found it, and whether severity/fix-status agree.

Ground-truth entries with "affected_status": "DISPUTED" are handled
differently: for those, NOT reporting the CVE is the correct behavior, and
reporting it is logged as a note toward precision rather than toward recall.

Usage:
    python3 scripts/compare_findings.py \
        --ground-truth ground-truth/os-package-cve.json \
        --trivy scanners/reports/trivy-os-package-cve.json \
        --grype scanners/reports/grype-os-package-cve.json
"""

import argparse
import json


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def extract_trivy_findings(trivy_report):
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


def check_entry_against_scanner(entry, scanner_findings):
    cve_id = entry["cve_id"]
    expected_packages = set(entry["packages"])
    expected_severity = entry["reference_severity"]

    matches = [
        f for f in scanner_findings
        if f["cve_id"] == cve_id and f["package"] in expected_packages
    ]

    if not matches:
        return {"caught": False}

    packages_matched = sorted(set(m["package"] for m in matches))
    severities_found = set(m["severity"] for m in matches)
    severity_agrees = severities_found == {expected_severity}

    return {
        "caught": True,
        "packages_matched": packages_matched,
        "packages_missing": sorted(expected_packages - set(packages_matched)),
        "severity_agrees": severity_agrees,
        "severities_found": sorted(severities_found),
    }


def report_disputed_entry(entry, scanner_name, findings):
    cve_id = entry["cve_id"]
    expected_packages = set(entry["packages"])
    reported = [
        f for f in findings
        if f["cve_id"] == cve_id and f["package"] in expected_packages
    ]
    if reported:
        severities = sorted(set(r["severity"] for r in reported))
        print(f"  {scanner_name:6s}: REPORTED a disputed CVE "
              f"(severity labeled: {severities}) — arguably a "
              f"precision ding under a strict scoring rule")
    else:
        print(f"  {scanner_name:6s}: CORRECTLY EXCLUDED the disputed CVE")


def report_normal_entry(scanner_name, result):
    if result["caught"]:
        sev_note = "severity matches" if result["severity_agrees"] else f"severity MISMATCH ({result['severities_found']})"
        missing = f", missing packages: {result['packages_missing']}" if result["packages_missing"] else ""
        print(f"  {scanner_name:6s}: CAUGHT — {sev_note}{missing}")
    else:
        print(f"  {scanner_name:6s}: MISSED — not reported for any expected package")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--trivy", required=True)
    parser.add_argument("--grype", required=True)
    args = parser.parse_args()

    ground_truth = load_json(args.ground_truth)
    trivy_findings = extract_trivy_findings(load_json(args.trivy))
    grype_findings = extract_grype_findings(load_json(args.grype))

    print(f"Image: {ground_truth['image']}")
    print(f"Ground-truth entries: {len(ground_truth['entries'])}")
    print(f"Trivy raw findings loaded: {len(trivy_findings)}")
    print(f"Grype raw findings loaded: {len(grype_findings)}")
    print("-" * 70)

    for entry in ground_truth["entries"]:
        is_disputed = entry.get("affected_status") == "DISPUTED"
        print(f"\nCVE: {entry['cve_id']}")
        print(f"  Expected severity: {entry['reference_severity']}")
        print(f"  Expected packages: {', '.join(entry['packages'])}")
        if is_disputed:
            print("  ** DISPUTED by upstream — not a confirmed real vulnerability **")

        for scanner_name, findings in [("Trivy", trivy_findings), ("Grype", grype_findings)]:
            if is_disputed:
                report_disputed_entry(entry, scanner_name, findings)
            else:
                result = check_entry_against_scanner(entry, findings)
                report_normal_entry(scanner_name, result)

    print("\n" + "-" * 70)
    print("NOTE: non-disputed entries measure recall against verified ground")
    print("truth. Disputed entries measure something different: whether each")
    print("scanner includes CVEs that upstream maintainers say are not real")
    print("vulnerabilities. Full precision (false positives among ALL scanner")
    print("findings, not just the ones we've checked) still requires growing")
    print("ground truth further.")


if __name__ == "__main__":
    main()
