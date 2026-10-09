#!/usr/bin/env python3

import re
import sys
import argparse
from urllib.parse import urljoin
from __future__ import annotations

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
