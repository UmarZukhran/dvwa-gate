# DVWA Security Regression Pipeline

> ⚠️ Learning/portfolio project. Not production-ready. Built to practice DevSecOps/CI-CD security automation concepts firsthand — automated DAST testing, CI gating, and security reporting against an intentionally vulnerable target.

Automated regression testing against [DVWA](https://github.com/digininja/DVWA) (Damn Vulnerable Web App), with results gated in GitHub Actions and reported to GitHub's Security tab via SARIF.

## What this does

- Spins up a local DVWA instance via Docker
- Runs DAST regression tests against known DVWA vulnerability classes, confirming each is exploitable at `security=low` and blocked at `security=high`
- **Gates** merges to `main` on all tests passing, enforced via a GitHub branch ruleset
- **Reports** findings to GitHub's Security tab as SARIF, independent of gate pass/fail
- Scans the full repo history for secrets on every push/PR via Gitleaks

## Architecture

Adding a new vulnerability class only requires writing one test script and adding one line to `registry.py` — nothing else needs manual wiring (no workflow edits, no shell script edits).

**Two separate GitHub Actions workflows, by design:**

| Workflow | Purpose | Fails the build on a finding? |
|---|---|---|
| `dvwa-security-gate.yml` | Merge-blocking gate (matrix: one parallel job per test) | Yes |
| `sarif-report.yml` | Reports findings to the Security tab | No — always green |

They're intentionally split. A single workflow that both fails on findings *and* uploads SARIF confuses GitHub's code-scanning status page — it interprets "workflow failed" as "scanning is misconfigured," even when the failure is the gate correctly doing its job. Real security pipelines separate **gating** (should this merge be blocked?) from **reporting** (what did we find, tracked over time?) for the same reason.

## Running locally

```bash
docker run -d --name dvwa-security-gate -p 8080:80 vulnerables/web-dvwa
./run-security-gate-local.sh
```

## A note on the open Security tab alerts

This repo's Security tab shows open "Error" alerts for LFI, SQLi, and Command Injection. **That's expected, not a problem to fix** — DVWA is deliberately vulnerable at `security=low`, and these alerts are proof the SARIF reporting pipeline correctly detects and reports real findings. They're left open intentionally to demonstrate the tooling works end-to-end, not because anything here is meant to be "fixed."

## Status

- [x] Regression tests for three vuln classes (LFI, SQLi, Command Injection), sharing a common helper module
- [x] CI gate wired up as a matrix strategy — per-test pass/fail visibility, confirmed red at `low` / green at `high`
- [x] Branch ruleset + required status checks (public repo, GitHub Rulesets)
- [x] Gitleaks secrets scan on every push/PR
- [x] SARIF reporting to GitHub's Security tab, decoupled from the merge gate
- [ ] Full README (this is still evolving as the project grows)
- [ ] Severity-based gating (fail only above a threshold, rather than on any finding)
- [ ] Baseline/suppression handling for known, accepted findings

---
*Scope note: all testing here is against a local, intentionally-vulnerable Docker instance I own. Not a general-purpose scanning tool, and not authorized for use against systems I don't own or have explicit permission to test.*
