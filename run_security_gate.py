#!/usr/bin/env python3
"""
Unified DVWA security regression gate runner.

Runs every test in registry.py against a target DVWA instance, captures
each test's output to its own log file, prints a summary, and exits
non-zero if ANY test confirms a vulnerability or errors.

Used by both run-security-gate-local.sh and the GitHub Actions workflow,
so there is exactly one place that knows how to run "all the tests."
"""

import argparse
import subprocess
import sys
from pathlib import Path
from sarif_utils import build_sarif
import json

from registry import TESTS


def run_one(test: dict, base_url: str, security_level: str, log_dir: Path) -> dict:
    label = test["label"]
    log_path = log_dir / f"{test['id']}_output.log"
    finding_path = log_dir / f"{test['id']}_finding.json"

    print(f"\n[*] Running {label} security regression test...")

    cmd = [
        sys.executable, test["script"],
        "--base-url", base_url,
        "--security-level", security_level,
        "--finding-out", str(finding_path),
    ]

    with open(log_path, "w") as log_file:
        proc = subprocess.run(cmd, stdout=log_file, stderr=subprocess.STDOUT)

    # Echo to stdout too, so it's visible inline in CI/terminal output,
    # not just buried in the uploaded log artifact.
    print(log_path.read_text())

    exit_code = proc.returncode
    if exit_code == 0:
        status = "PASS"
        print(f"[PASS] No {label} leak/exploit detected.")
    elif exit_code == 1:
        status = "FAIL"
        print(f"[FAIL] {label} vulnerability confirmed.")
    else:
        status = "ERROR"
        print(f"[ERROR] {label} test script errored (exit {exit_code}).")

    return {"id": test["id"], "label": label, "exit_code": exit_code, "status": status, "finding_path": finding_path}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--security-level", default="low",
                         choices=["low", "medium", "high", "impossible"])
    parser.add_argument("--log-dir", default=".", help="Directory to write per-test log files into")
    parser.add_argument("--only", default=None,
                         help="Run only the test with this id (e.g. 'lfi'), instead of all registered tests")
    parser.add_argument("--report-only", action="store_true",
                         help="Always exit 0 regardless of findings. Use this for SARIF reporting runs "
                              "where you want results recorded but never want to fail the workflow itself.")
    args = parser.parse_args()

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    tests_to_run = TESTS
    if args.only:
        tests_to_run = [t for t in TESTS if t["id"] == args.only]
        if not tests_to_run:
            print(f"::error::No registered test with id '{args.only}'")
            return 2

    results = [run_one(t, args.base_url, args.security_level, log_dir) for t in tests_to_run]

    print("\n======================================")
    print(" Security Gate Summary")
    print("======================================")
    overall_failed = False
    for r in results:
        print(f"  {r['label']:<6} {r['status']:<6} (exit={r['exit_code']})")
        if r["exit_code"] != 0:
            overall_failed = True
    print("======================================")

    sarif_doc = build_sarif([r["finding_path"] for r in results])
    sarif_path = log_dir / "dvwa-gate-results.sarif"
    sarif_path.write_text(json.dumps(sarif_doc, indent=2))
    print(f"\n[*] SARIF report written: {sarif_path}")

    if args.report_only:
        print("[*] --report-only set: exiting 0 regardless of findings (SARIF has the real results).")
        return 0

    return 1 if overall_failed else 0


if __name__ == "__main__":
    sys.exit(main())
