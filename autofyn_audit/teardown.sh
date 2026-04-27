#!/usr/bin/env bash
set -euo pipefail

NETWORK="ragflow-audit"
CONTAINERS=(
    "ragflow-audit-mysql"
    "ragflow-audit-redis"
    "ragflow-audit-minio"
    "ragflow-audit-es"
    "ragflow-audit-server"
)

echo "=== RAGFlow Audit Environment Teardown ==="
echo ""

for container in "${CONTAINERS[@]}"; do
    if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
        docker stop "$container" 2>/dev/null || true
        docker rm "$container" 2>/dev/null || true
        echo "[+] Removed container: $container"
    else
        echo "[*] Container not found (skipping): $container"
    fi
done

# Remove docker network
if docker network inspect "$NETWORK" >/dev/null 2>&1; then
    docker network rm "$NETWORK"
    echo "[+] Removed network: $NETWORK"
else
    echo "[*] Network not found (skipping): $NETWORK"
fi

# Clean up temp files created by exploits
if [ -f /tmp/pickle_rce_proof.txt ]; then
    rm -f /tmp/pickle_rce_proof.txt
    echo "[+] Removed /tmp/pickle_rce_proof.txt"
fi

echo ""
echo "[+] Teardown complete."
