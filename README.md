# DVWA Security Regression Pipeline

> ⚠️ Learning project. Not production-ready. Built to practice DevSecOps/CI-CD security automation concepts firsthand.

Automated DAST regression testing against [DVWA](https://github.com/digininja/DVWA) (Damn Vulnerable Web App), gated in GitHub Actions.

## What this does

- Spins up a local DVWA instance via Docker
- Runs regression tests against known DVWA vulnerability classes, confirming each is exploitable at `security=low` and blocked at `security=high`
- Gates merges to `main` on all vuln tests passing and a **Gitleaks** secrets scan

## Structure

- `dvwa_common.py` — shared login/CSRF/security-level helpers, reused across all vuln tests
- `dvwa_*_regression_test.py` — one regression test per vulnerability class
- `run-security-gate-local.sh` — local test runner (spin up → init → test → teardown)
- `.github/workflows/dvwa-lfi-security-gate.yml` — CI gate running the vuln regression tests (`workflow_dispatch` with a security-level dropdown)
- `.github/workflows/gitleaks-scan.yml` — secrets scan on every push/PR

## Running locally

```bash
docker run -d --name dvwa-security-gate -p 8080:80 vulnerables/web-dvwa
./run-security-gate-local.sh
```

## Status

- [x] Regression tests for two vuln classes — confirmed working
- [x] CI gate wired up, confirmed red at `low` / green at `high`
- [x] Branch ruleset + required status checks (gated via GitHub Rulesets, public repo)
- [x] Gitleaks secrets scan integrated
- [ ] Full README (this is a placeholder)
- [ ] Additional vuln class(es) using the same shared-helper pattern

---
*Scope note: all testing here is against a local, intentionally-vulnerable Docker instance I own. Not a general-purpose scanning tool.*
