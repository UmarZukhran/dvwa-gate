"""
Minimal SARIF 2.1.0 report builder for the DVWA security gate.

Each test script writes a small "finding" JSON (via write_finding below)
describing what it found. run_security_gate.py then collects all finding
files and calls build_sarif() once, producing a single combined SARIF
report that GitHub's Security tab can ingest directly.
"""

import json
from pathlib import Path

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def write_finding(
    path: Path,
    rule_id: str,
    rule_name: str,
    message: str,
    uri: str,
    confirmed: bool,
    security_level: str,
) -> None:
    """
    Called by a test script at the end of its run. Always writes a finding
    file (even on a clean result) so the gate can tell "ran and passed"
    apart from "never ran" -- useful for debugging a missing SARIF entry.
    """
    finding = {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "message": message,
        "uri": uri,
        "confirmed": confirmed,
        "security_level": security_level,
    }
    path.write_text(json.dumps(finding, indent=2))


def build_sarif(finding_paths: list[Path], tool_name: str = "dvwa-security-gate") -> dict:
    """
    Reads every finding file that exists among finding_paths and produces
    one SARIF 2.1.0 document. Only CONFIRMED findings become SARIF results
    -- a clean/not-confirmed test contributes no result, same as a linter
    that found nothing to flag.
    """
    rules_seen: dict[str, dict] = {}
    results = []

    for p in finding_paths:
        if not p.exists():
            continue  # test errored before writing its finding -- skip, don't crash the report
        finding = json.loads(p.read_text())

        rules_seen.setdefault(finding["rule_id"], {
            "id": finding["rule_id"],
            "name": finding["rule_name"],
            "shortDescription": {"text": finding["rule_name"]},
        })

        if finding["confirmed"]:
            results.append({
                "ruleId": finding["rule_id"],
                "level": "error",
                "message": {"text": f"{finding['message']} (security level: {finding['security_level']})"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding["uri"]},
                        "region": {"startLine": 1},
                    }
                }],
            })

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "informationUri": "https://github.com/UmarZukhran/dvwa-gate",
                    "rules": list(rules_seen.values()),
                }
            },
            "results": results,
        }],
    }
