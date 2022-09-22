#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter, Retry

# Utilities

def build_session(headers: List[str], timeout: int) -> requests.Session:
    s = requests.Session()

    retries = Retry(
        total=3,
        backoff_factor=0.4,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
        raise_on_status=False,
    )
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.mount("https://", HTTPAdapter(max_retries=retries))

    default_headers = {
        "User-Agent": "Jira-Scanner/1.0 (+safe read-only checks)",
        "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
    }

    for h in headers:
        if ":" not in h:
            continue
        k, v = h.split(":", 1)
        default_headers[k.strip()] = v.strip()
    s.headers.update(default_headers)


    s.request_timeout = timeout  
    return s


def norm_url(base: str, path: str) -> str:
    base = base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path



# Fingerprinting & Checks
@dataclass
class Finding:
    check: str
    url: str
    severity: str  # INFO/LOW/MEDIUM/HIGH
    description: str
    evidence: Optional[str] = None


@dataclass
class TargetReport:
    base_url: str
    http_ok: bool = False
    jira_version: Optional[str] = None
    product: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)

    def add(self, f: Finding):
        self.findings.append(f)


COMMON_PATHS = [
    "/robots.txt",
    "/.well-known/security.txt",
    "/status",
    "/login.jsp",
    "/secure/ContactAdministrators!default.jspa",
    "/secure/QueryComponent!Default.jspa",
    "/rest/api/2/serverInfo",
    "/rest/api/3/serverInfo",
    "/rest/api/2/project",
    "/rest/api/3/project",
    "/rest/api/2/search?jql=order%20by%20created%20desc&maxResults=1",
    "/rest/api/2/filter",
    "/rest/api/2/dashboard",
    "/s/",
]


HEADER_KEYS_OF_INTEREST = [
    "Server",
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "X-Seraph-LoginReason",
    "X-Atlassian-Token",
    "X-AREQUESTID",
]


VERSION_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)*)\b")


def get(s: requests.Session, url: str) -> Tuple[Optional[requests.Response], Optional[str]]:
    try:
        r = s.get(url, timeout=s.request_timeout, allow_redirects=True)
        body = None

        if r is not None:
            body = r.text[:20000]
        return r, body
    except requests.RequestException as e:
        return None, str(e)


# Individual check helpers

def check_basic_http(report: TargetReport, s: requests.Session):
    r, body = get(s, report.base_url)
    if r is None:
        report.add(Finding(
            check="base_http",
            url=report.base_url,
            severity="INFO",
            description="Base URL not reachable",
            evidence=body or "connection error",
        ))
        return

    report.http_ok = True

    for k in HEADER_KEYS_OF_INTEREST:
        if k in r.headers:
            report.headers[k] = r.headers.get(k, "")


    server_h = r.headers.get("Server", "")
    if "AtlassianProxy" in server_h or "Atlassian" in server_h:
        report.product = "Atlassian (proxy)"
    if body:
        if "Atlassian" in body or "Jira" in body or "JIRA" in body:
            report.product = (report.product or "").strip() or "Jira (suspected)"


    missing = []
    must = ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"]
    for m in must:
        if m not in r.headers:
            missing.append(m)
    if missing:
        report.add(Finding(
            check="security_headers",
            url=report.base_url,
            severity="LOW",
            description=f"Missing common security headers: {', '.join(missing)}",
        ))


def check_server_info(report: TargetReport, s: requests.Session):
    for path in ("/rest/api/3/serverInfo", "/rest/api/2/serverInfo"):
        url = norm_url(report.base_url, path)
        r, body = get(s, url)
        if r is None:
            continue
        if r.status_code == 200 and r.headers.get("Content-Type", "").startswith("application/json"):
            try:
                data = r.json()
                ver = data.get("version") or data.get("versionNumber")
                if isinstance(ver, list):
                    ver = ".".join(map(str, ver))
                if isinstance(ver, str):
                    report.jira_version = ver
                report.product = data.get("deploymentType") or report.product or "Jira"
                report.add(Finding(
                    check="serverInfo_exposed",
                    url=url,
                    severity="MEDIUM",
                    description="Server information endpoint is publicly accessible (may enable fingerprinting)",
                    evidence=json.dumps({k: data.get(k) for k in ("version", "deploymentType", "buildNumber")}, ensure_ascii=False),
                ))
                return
            except Exception:
                pass
        elif r.status_code in (401, 403):
            report.add(Finding(
                check="serverInfo_protected",
                url=url,
                severity="INFO",
                description=f"{path} requires auth ({r.status_code})",
            ))
            return


def check_common_paths(report: TargetReport, s: requests.Session):
    for path in COMMON_PATHS:
        url = norm_url(report.base_url, path)
        r, body = get(s, url)
        if r is None:
            continue


        if path.endswith("robots.txt") and r.status_code == 200 and body:
            dis = []
            for line in body.splitlines():
                if line.lower().startswith("disallow"):
                    dis.append(line.strip())
            if dis:
                report.add(Finding(
                    check="robots",
                    url=url,
                    severity="INFO",
                    description="robots.txt present",
                    evidence="; ".join(dis)[:3000],
                ))
        if path.endswith("security.txt") and r.status_code == 200:
            report.add(Finding(
                check="security_txt",
                url=url,
                severity="INFO",
                description=".well-known/security.txt is present",
            ))


        if r.status_code == 200 and body and re.search(r"<title>Index of /", body, re.I):
            report.add(Finding(
                check="dir_listing",
                url=url,
                severity="MEDIUM",
                description="Directory listing exposed",
            ))


        if path.startswith("/rest/api/2/search"):
            if r.status_code == 200:
                report.add(Finding(
                    check="anonymous_issue_search",
                    url=url,
                    severity="MEDIUM",
                    description="Anonymous users can query issues (information disclosure)",
                ))
            elif r.status_code in (401, 403):
                report.add(Finding(
                    check="search_protected",
                    url=url,
                    severity="INFO",
                    description=f"Search endpoint requires auth ({r.status_code})",
                ))


        if path.startswith("/secure/ContactAdministrators"):
            if r.status_code == 200:
                report.add(Finding(
                    check="contact_admins_exposed",
                    url=url,
                    severity="LOW",
                    description="ContactAdministrators page is publicly accessible (fingerprinting, spam risk)",
                ))


        if body and ("at com.atlassian" in body or "java.lang." in body) and r.status_code >= 500:
            report.add(Finding(
                check="stack_trace",
                url=url,
                severity="LOW",
                description="Stack trace or verbose Java error leaked in response",
            ))


def check_headers_for_hints(report: TargetReport):

    if report.headers and "Strict-Transport-Security" not in report.headers:
        report.add(Finding(
            check="hsts_missing",
            url=report.base_url,
            severity="LOW",
            description="HSTS header is missing (consider enabling to enforce HTTPS)",
        ))


    if report.headers.get("X-Seraph-LoginReason"):
        report.add(Finding(
            check="seraph_header",
            url=report.base_url,
            severity="INFO",
            description="Seraph login header present (Jira authentication layer)",
            evidence=f"X-Seraph-LoginReason: {report.headers.get('X-Seraph-LoginReason')}",
        ))


def assess_version_against_known(report: TargetReport):

    if not report.jira_version:
        return
    try:
        parts = [int(x) for x in report.jira_version.split(".")[:2]]
        major_minor = tuple(parts + [0] * (2 - len(parts)))
    except Exception:
        return

    if major_minor[0] < 8:
        report.add(Finding(
            check="outdated_version",
            url=norm_url(report.base_url, "/rest/api/2/serverInfo"),
            severity="MEDIUM",
            description=(
                f"Jira version appears to be {report.jira_version}. Older major versions are more likely to carry known CVEs. "
                "Consider upgrading to a currently supported release."
            ),
        ))


# Engine

def scan_target(base_url: str, session: requests.Session) -> TargetReport:
    report = TargetReport(base_url=base_url.rstrip("/"))
    check_basic_http(report, session)
    if not report.http_ok:
        return report

    check_server_info(report, session)
    check_common_paths(report, session)
    check_headers_for_hints(report)
    assess_version_against_known(report)
    return report


def load_targets(arg: str, from_file: bool) -> List[str]:
    if not from_file:
        return [arg]
    with open(arg, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    return lines


def parse_auth(auth: Optional[str]) -> Tuple[Optional[Tuple[str, str]], Optional[str]]:
    if not auth:
        return None, None
    if auth.startswith("basic:"):
        try:
            _, user, pwd = auth.split(":", 2)
            return (user, pwd), None
        except ValueError:
            return None, None
    if auth.startswith("bearer:"):
        token = auth.split(":", 1)[1]
        return None, f"Authorization: Bearer {token}"
    return None, None


def to_json(report: TargetReport) -> Dict:
    return {
        "base_url": report.base_url,
        "http_ok": report.http_ok,
        "product": report.product,
        "jira_version": report.jira_version,
        "headers": report.headers,
        "findings": [f.__dict__ for f in report.findings],
    }


def print_report(report: TargetReport):
    print(f"\n=== {report.base_url} ===")
    if not report.http_ok:
        print("  - Unreachable")
        return
    if report.product:
        print(f"  Product: {report.product}")
    if report.jira_version:
        print(f"  Version: {report.jira_version}")
    if report.headers:
        for k, v in report.headers.items():
            print(f"  Header[{k}]: {v}")
    if not report.findings:
        print("  Findings: none")
    else:
        print("  Findings:")
        for f in report.findings:
            ev = f" | Evidence: {f.evidence}" if f.evidence else ""
            print(f"    - [{f.severity}] {f.check}: {f.description} ({f.url}){ev}")


# ------------------------------
# Main
# ------------------------------

def main():
    ap = argparse.ArgumentParser(description="Jira vulnerability & info disclosure scanner (safe)")
    ap.add_argument("target", help="Base URL (e.g., https://jira.example.com) or a file if --from-file")
    ap.add_argument("--from-file", action="store_true", help="Treat 'target' as a file containing base URLs")
    ap.add_argument("--threads", type=int, default=4, help="Concurrent worker threads (for multiple targets)")
    ap.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds")
    ap.add_argument("--auth", type=str, help="Auth helper, e.g. 'basic:user:pass' or 'bearer:TOKEN'")
    ap.add_argument("--header", action="append", default=[], help="Extra header, e.g. 'Cookie: JSESSIONID=...' (repeatable)")
    ap.add_argument("--output", type=str, help="Write JSON report to this file")

    args = ap.parse_args()

    basic, bearer_hdr = parse_auth(args.auth)
    headers = list(args.header)
    if bearer_hdr:
        headers.append(bearer_hdr)

    session = build_session(headers, args.timeout)
    if basic:
        session.auth = basic

    targets = load_targets(args.target, args.from_file)

    results: List[TargetReport] = []
    if len(targets) == 1:
        rep = scan_target(targets[0], session)
        results.append(rep)
        print_report(rep)
    else:
        with cf.ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
            futs = {ex.submit(scan_target, t, session): t for t in targets}
            for fut in cf.as_completed(futs):
                rep = fut.result()
                results.append(rep)
                print_report(rep)

    if args.output:
        data = [to_json(r) for r in results]
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"\nSaved JSON report to {args.output}")


if __name__ == "__main__":
    main()
