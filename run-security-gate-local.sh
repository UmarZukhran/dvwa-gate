#!/usr/bin/env bash
set -uo pipefail

IMAGE="vulnerables/web-dvwa"
CONTAINER_NAME="dvwa-security-gate"
PORT="8080"
BASE_URL="http://127.0.0.1:${PORT}"

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

# --- Run each regression test, track results independently ---
declare -A RESULTS

run_test() {
  local label="$1"
  local script="$2"

  echo ""
  echo "[*] Running ${label} security regression test..."
  python3 "${script}" --base-url "${BASE_URL}"
  local exit_code=$?
  RESULTS["${label}"]=$exit_code

  case $exit_code in
    0) echo "[PASS] No ${label} leak/exploit detected." ;;
    1) echo "[FAIL] ${label} vulnerability confirmed." ;;
    *) echo "[ERROR] ${label} test script errored (exit ${exit_code})." ;;
  esac
}

run_test "LFI"  "dvwa_lfi_regression_test.py"
run_test "SQLi" "dvwa_sqli_regression_test.py"
run_test "CMDi" "dvwa_cmdi_regression_test.py"

# --- Summary ---
echo ""
echo "======================================"
echo " Security Gate Summary"
echo "======================================"
OVERALL_EXIT=0
for label in "${!RESULTS[@]}"; do
  code=${RESULTS[$label]}
  if [ "$code" -ne 0 ]; then
    OVERALL_EXIT=1
  fi
  printf "  %-6s exit=%s\n" "$label" "$code"
done
echo "======================================"

