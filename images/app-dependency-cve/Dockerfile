# Test case: vulnerable application dependency (Python / PyPI)
# Target package: requests 2.19.1, the last release affected by CVE-2018-18074
# (fixed in 2.20.0). Also affected by four later advisories; see
# ground-truth/app-dependency-cve.json for the answer key.
#
# Base: python:3.12-slim, pinned by the multi-platform index digest below so
# the build is reproducible. Build and scan with --platform=linux/amd64
# (same platform pin as images/os-package-cve).
#
# --no-deps is deliberate: requests 2.19.1 would otherwise pull in old
# urllib3/idna/chardet/certifi, whose advisories would bury the one package
# this image is meant to isolate. Transitive dependencies get their own image.
#
# The package is installed but never run, so nothing here is exploitable.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --no-deps -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

CMD ["sleep", "3600"]
