#!/usr/bin/env python3
import sys
import requests
import concurrent.futures
import re

TIMEOUT = 5


JIRA_KEYWORDS = [
    "Atlassian", "JIRA", "Jira Software", "jiraServiceDesk"
]
JIRA_HEADER_KEYS = [
    "X-Atlassian-Token", "X-Seraph-LoginReason"
]

def is_jira(url):
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
        body = r.text[:20000]  

        if any(k.lower() in body.lower() for k in JIRA_KEYWORDS):
            return True

        if any(h in r.headers for h in JIRA_HEADER_KEYS):
            return True

        if "Server" in r.headers and "atlassian" in r.headers["Server"].lower():
            return True
    except requests.RequestException:
        pass
    return False

def scan_subdomain(sub):
    url_http = f"http://{sub}"
    url_https = f"https://{sub}"
    if is_jira(url_https):
        return sub
    elif is_jira(url_http):
        return sub
    return None

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} subdomains.txt")
        sys.exit(1)

    input_file = sys.argv[1]
    with open(input_file, "r") as f:
        subs = [line.strip() for line in f if line.strip()]

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_subdomain, sub): sub for sub in subs}
        for future in concurrent.futures.as_completed(futures):
            sub = futures[future]
            try:
                result = future.result()
                if result:
                    print(f"[+] Jira detected: {result}")
                    found.append(result)
            except Exception:
                pass


    with open("result.txt", "w") as out:
        for sub in found:
            out.write(sub + "\n")

    print(f"[✓] Done! {len(found)} Jira domains saved to result.txt")

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()  
    main()
