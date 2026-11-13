#!/usr/bin/env python3
"""
fetch_nvd.py - build a cache of NVD severities for every CVE in the scanner reports.

For each CVE: the NVD primary CVSS (v3.1, then v3.0) severity if present,
otherwise a secondary source's score; the source and type are recorded.
Resumable: results are cached in ground-truth/evidence/nvd-severities.json.
Set NVD_API_KEY for the faster rate limit (free key from nvd.nist.gov).

Usage:
    python3 scripts/fetch_nvd.py --dry-run     # count only
    python3 scripts/fetch_nvd.py               # fetch missing CVEs
"""
import argparse, glob, json, os, time, urllib.error, urllib.request
from datetime import datetime, timezone

API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="


def ids_from_reports(paths):
    ids = set()
    for p in paths:
        try:
            d = json.load(open(p))
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        if isinstance(d.get("matches"), list):  # Grype
            for m in d["matches"]:
                cands = [m.get("vulnerability", {}).get("id")]
                cands += [x.get("id") for x in m.get("relatedVulnerabilities") or []]
                ids.update(i for i in cands if i and i.startswith("CVE-"))
        elif "SchemaVersion" in d or "Results" in d:  # Trivy
            for r in d.get("Results") or []:
                for v in r.get("Vulnerabilities") or []:
                    i = v.get("VulnerabilityID")
                    if i and i.startswith("CVE-"):
                        ids.add(i)
    return ids


def pick(cve):
    metrics = cve.get("metrics") or {}
    best = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key, []):
            cd = m.get("cvssData", {})
            cand = {"severity": (cd.get("baseSeverity") or "").upper(),
                    "score": cd.get("baseScore"), "cvss_version": cd.get("version"),
                    "source": m.get("source"), "type": m.get("type")}
            if m.get("type") == "Primary":
                return cand
            if best is None:
                best = cand
    return best


def fetch(cve_id, key):
    req = urllib.request.Request(API + cve_id)
    if key:
        req.add_header("apiKey", key)
    for attempt in range(6):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503):
                time.sleep(10 * (attempt + 1))
                continue
            return None
        except urllib.error.URLError:
            time.sleep(5)
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cache", default="ground-truth/evidence/nvd-severities.json")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    paths = [p for p in glob.glob("scanners/reports/*.json")
             if not os.path.basename(p).startswith("versions")]
    ids = ids_from_reports(paths)
    cache = json.load(open(args.cache)) if os.path.exists(args.cache) else {}
    todo = sorted(ids - cache.keys())
    key = os.environ.get("NVD_API_KEY")
    delay = 0.7 if key else 6.5
    print(f"Reports read: {len(paths)}")
    print(f"Unique CVE IDs: {len(ids)}; already cached: {len(ids & cache.keys())}; to fetch: {len(todo)}")
    print(f"Estimated time: {len(todo) * delay / 60:.0f} minutes "
          f"({'with' if key else 'without'} an API key)")
    if args.dry_run or not todo:
        return

    def save():
        os.makedirs(os.path.dirname(args.cache), exist_ok=True)
        with open(args.cache, "w") as f:
            json.dump(cache, f, indent=1, sort_keys=True)

    try:
        for n, cid in enumerate(todo, 1):
            data = fetch(cid, key)
            if data is None:
                print(f"  {cid}: fetch failed, will retry on next run")
            else:
                vulns = data.get("vulnerabilities") or []
                if not vulns:
                    rec = {"severity": "NOT_FOUND"}
                else:
                    cve = vulns[0]["cve"]
                    rec = pick(cve) or {"severity": "UNSCORED"}
                    rec["vulnStatus"] = cve.get("vulnStatus")
                rec["fetched_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
                cache[cid] = rec
            if n % 10 == 0:
                save()
                print(f"  {n}/{len(todo)} done")
            time.sleep(delay)
    except KeyboardInterrupt:
        print("Interrupted; progress saved. Re-run to resume.")
    save()
    print(f"Saved {len(cache)} entries to {args.cache}")


if __name__ == "__main__":
    main()
