#!/bin/bash

set -eo pipefail

sleep $(awk 'BEGIN{srand(); printf "%.1f", rand()*10}')

SHARED_CORPUS="/home/fuzzer/corpus_shared"
BUILTIN_CORPUS="/home/fuzzer/corpus"

echo "[entrypoint] Seeding shared corpus from built-in seeds..."
cp "${BUILTIN_CORPUS}/"* "${SHARED_CORPUS}/" 2>/dev/null || true
SEED_COUNT=$(ls "${SHARED_CORPUS}" | wc -l)
echo "[entrypoint] Corpus: ${SEED_COUNT} files in ${SHARED_CORPUS}"

echo "[entrypoint] Starting fuzzer: fork=${FUZZER_JOBS:-1}, max_time=${FUZZER_MAX_TIME:-0}, max_len=${FUZZER_MAX_LEN:-4096}"

DICT_FLAG=""
if [ -f "./fuzzer.dict" ]; then
    DICT_FLAG="-dict=./fuzzer.dict"
    echo "[entrypoint] Dictionary: fuzzer.dict"
fi
LOG_DIR="/home/fuzzer/logs"
LOG_FILE="${LOG_DIR}/findings.log"
CRASH_DIR="${LOG_DIR}/crashes"
mkdir -p "${CRASH_DIR}"
CID=$(hostname | cut -c1-12)

log_finding() {
    local msg="$1"
    (
        flock -x 9
        printf '[%s][%s] %s\n' "$(date -u +%H:%M:%SZ)" "${CID}" "${msg}" >&9
    ) 9>>"${LOG_FILE}"
}

log_finding "=== START pid=$$ max_len=${FUZZER_MAX_LEN:-4096} ==="

ARTIFACT_FLAG="-artifact_prefix=${CRASH_DIR}/"
TMPLOG=$(mktemp /tmp/fuzzer.XXXXXX)
set +e
if [ "${FUZZER_JOBS:-1}" -le 1 ]; then
    ./fuzzer_bin \
        -max_total_time="${FUZZER_MAX_TIME:-0}" \
        -max_len="${FUZZER_MAX_LEN:-4096}" \
        ${ARTIFACT_FLAG} \
        ${DICT_FLAG} \
        "${SHARED_CORPUS}/" 2>&1 | tee "${TMPLOG}"
else
    ./fuzzer_bin \
        -fork="${FUZZER_JOBS}" \
        -max_total_time="${FUZZER_MAX_TIME:-0}" \
        -max_len="${FUZZER_MAX_LEN:-4096}" \
        ${ARTIFACT_FLAG} \
        ${DICT_FLAG} \
        "${SHARED_CORPUS}/" 2>&1 | tee "${TMPLOG}"
fi
FUZZER_EXIT=${PIPESTATUS[0]}
set -e

CRASH_PATHS=$(grep "Test unit written to" "${TMPLOG}" | awk '{print $NF}' | tr -d ' ' || true)
if [ -n "${CRASH_PATHS}" ]; then
    while IFS= read -r crash_path; do
        [ -n "${crash_path}" ] || continue
        log_finding "CRASH artifact=$(basename "${crash_path}") exit=${FUZZER_EXIT}"
    done <<< "${CRASH_PATHS}"
else
    log_finding "EXIT exit=${FUZZER_EXIT} (no new crashes)"
fi
rm -f "${TMPLOG}"
exit ${FUZZER_EXIT}
