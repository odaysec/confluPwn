#!/usr/bin/env python3
import sys
import requests
import concurrent.futures
from urllib.parse import urljoin

TIMEOUT = 5
ENDPOINTS = [
    "/rest/api/2/serverInfo",
    "/rest/api/3/serverInfo",
    "/rest/api/2/project",
    "/rest/api/3/project",
    "/rest/api/2/search?jql=order%20by%20created%20desc&maxResults=1",
    "/secure/ContactAdministrators!default.jspa",
    "/.well-known/security.txt",
    "/robots.txt"
]

def check_endpoint(base_url, path):
    url = urljoin(base_url, path)
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False)
        return {
            "url": url,
            "status": r.status_code,
            "content_type": r.headers.get("Content-Type", ""),
            "length": len(r.content)
        }
    except requests.RequestException:
        return None

def scan_domain(domain):
    base_urls = [f"https://{domain}", f"http://{domain}"]
    results = []
    for base in base_urls:
        for path in ENDPOINTS:
            res = check_endpoint(base, path)
            if res:
                results.append(res)
    return domain, results

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} domains.txt")
        sys.exit(1)

    input_file = sys.argv[1]
    with open(input_file, "r") as f:
        domains = [line.strip() for line in f if line.strip()]

    all_results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_domain, d): d for d in domains}
        for future in concurrent.futures.as_completed(futures):
            domain, res = future.result()
            all_results[domain] = res
            print(f"[+] Scanned {domain}, {len(res)} endpoints checked.")

    with open("jira_endpoints_report.txt", "w") as out:
        for domain, endpoints in all_results.items():
            out.write(f"# {domain}\n")
            for e in endpoints:
                out.write(f"{e['url']} | {e['status']} | {e['content_type']} | {e['length']} bytes\n")
            out.write("\n")

    print("[✓] Report saved to jira_endpoints_report.txt")

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()
