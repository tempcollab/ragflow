#!/usr/bin/env bash
set -euo pipefail

NETWORK="ragflow-audit"
CONTAINERS=(
    "ragflow-audit-server"
    "ragflow-audit-mysql"
    "ragflow-audit-redis"
    "ragflow-audit-minio"
    "ragflow-audit-es"
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

if docker network inspect "$NETWORK" >/dev/null 2>&1; then
    docker network rm "$NETWORK"
    echo "[+] Removed network: $NETWORK"
else
    echo "[*] Network not found (skipping): $NETWORK"
fi

# Clean up temp files created by exploits
for f in /tmp/pickle_rce_proof.txt /tmp/from_dict_hook_proof.txt; do
    if [ -f "$f" ]; then
        rm -f "$f"
        echo "[+] Removed $f"
    fi
done

echo ""
echo "[+] Teardown complete."
