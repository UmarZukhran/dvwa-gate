#!/usr/bin/env bash
#
# run-security-gate-local.sh
#
# Local equivalent of the GitHub Actions "DVWA LFI Security Gate" job.
# Same four stages as the CI workflow, just run by hand on your machine
# instead of by a GitHub-hosted runner:
#
#   1. Start DVWA as a disposable Docker container
#   2. Wait for it to be ready + initialize its database
#   3. Run the Python regression test against it
#   4. Tear the container down and exit with the test's result
#
# Usage:
#   chmod +x run-security-gate-local.sh
#   ./run-security-gate-local.sh
#
# Exit code mirrors the Python script: 0 = no leak, 1 = leak confirmed,
# 2 = something about the test itself failed (env/auth/setup problem).

set -uo pipefail   # (not -e: we want to reach cleanup even on failure)

CONTAINER_NAME="dvwa-security-gate"
IMAGE="vulnerables/web-dvwa"
PORT=8080
BASE_URL="http://localhost:${PORT}"

cleanup() {
  echo "[*] Tearing down ${CONTAINER_NAME}..."
  docker rm -f "${CONTAINER_NAME}" > /dev/null 2>&1
}
trap cleanup EXIT   # always runs, even if a step below fails or you Ctrl+C

echo "[*] Starting ${IMAGE} as ${CONTAINER_NAME} on port ${PORT}..."
docker run -d --name "${CONTAINER_NAME}" -p "${PORT}:80" "${IMAGE}" > /dev/null

echo "[*] Waiting for DVWA to respond..."
for i in $(seq 1 30); do
  if curl -sf "${BASE_URL}/login.php" > /dev/null; then
    echo "[*] DVWA is up after ${i}s"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "[!] DVWA did not become ready in time" >&2
    exit 2
  fi
  sleep 2
done

echo "[*] Initializing DVWA database..."
COOKIE_JAR=$(mktemp)
SETUP_PAGE=$(mktemp)
curl -s -c "${COOKIE_JAR}" "${BASE_URL}/setup.php" -o "${SETUP_PAGE}"
TOKEN=$(grep -oP "name='user_token' value='\K[a-f0-9]+" "${SETUP_PAGE}")
curl -s -b "${COOKIE_JAR}" -X POST "${BASE_URL}/setup.php" \
  --data-urlencode "create_db=Create / Reset Database" \
  --data-urlencode "user_token=${TOKEN}" > /dev/null
rm -f "${COOKIE_JAR}" "${SETUP_PAGE}"
echo "[*] Database initialized."

echo "[*] Running LFI security regression test..."
python3 dvwa_lfi_regression_test.py --base-url "${BASE_URL}"
TEST_EXIT_CODE=$?

echo ""
case $TEST_EXIT_CODE in
  0) echo "[PASS] No LFI leak detected." ;;
  1) echo "[FAIL] LFI vulnerability confirmed." ;;
  *) echo "[ERROR] Test script errored (exit ${TEST_EXIT_CODE})." ;;
esac

exit $TEST_EXIT_CODE
