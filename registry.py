"""
Central registry of DVWA security regression tests.

To add a new vulnerability class:
    1. Write dvwa_<name>_regression_test.py following the existing CLI
       contract: --base-url, --security-level, exits 0 (not confirmed),
       1 (confirmed), 2 (script/environment error).
    2. Add one line below.

That's it -- the local runner and the GitHub Actions workflow both pick
it up automatically, no other file needs to change.
"""

TESTS = [
    {"id": "lfi",  "label": "LFI",  "script": "dvwa_lfi_regression_test.py"},
    {"id": "sqli", "label": "SQLi", "script": "dvwa_sqli_regression_test.py"},
    {"id": "cmdi", "label": "CMDi", "script": "dvwa_cmdi_regression_test.py"},
]
