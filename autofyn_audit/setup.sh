#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# RAGFlow Security Audit — Environment Setup
#
# Audited commit: c81081f8e (Refactor: Doc change parser #14327)
# Docker image:   infiniflow/ragflow:nightly (v0.25.0, contains restful_apis/)
#
# This script brings up all required services and the RAGFlow server, then
# waits until the API is healthy before returning. After this script succeeds,
# run_all.sh can execute all exploit scripts with full live confirmation.
# ==============================================================================

NETWORK="ragflow-audit"
MYSQL_CONTAINER="ragflow-audit-mysql"
REDIS_CONTAINER="ragflow-audit-redis"
MINIO_CONTAINER="ragflow-audit-minio"
ES_CONTAINER="ragflow-audit-es"
SERVER_CONTAINER="ragflow-audit-server"

MYSQL_PORT=3307
REDIS_PORT=6380
MINIO_PORT=9100
ES_PORT=1200
API_PORT=9381

DB_PASSWORD="infini_rag_flow"
DB_NAME="rag_flow"
MINIO_USER="rag_flow"

# Pinned nightly image (v0.25.0-91-gc5116b90e) — matches audited codebase.
# 2 commits behind audit base c81081f8e; diff only touches document update
# logic, not any audited endpoints. Verified safe for all 17 findings.
RAGFLOW_IMAGE="infiniflow/ragflow@sha256:0698a8733efd267527b20835793e3db48416f8b8a2de3bc1c83f3c5924b4e05a"

echo "============================================================"
echo "  RAGFlow Security Audit — Environment Setup"
echo "  Audited commit : c81081f8e"
echo "  Docker image   : ${RAGFLOW_IMAGE}"
echo "============================================================"
echo ""

# -------------------------------------------------------------------
# Network
# -------------------------------------------------------------------
if docker network inspect "$NETWORK" >/dev/null 2>&1; then
    echo "[*] Network $NETWORK already exists"
else
    docker network create "$NETWORK"
    echo "[+] Created network $NETWORK"
fi

# -------------------------------------------------------------------
# MySQL
# -------------------------------------------------------------------
if docker ps -a --format '{{.Names}}' | grep -q "^${MYSQL_CONTAINER}$"; then
    echo "[*] $MYSQL_CONTAINER already exists, starting if stopped..."
    docker start "$MYSQL_CONTAINER" 2>/dev/null || true
else
    docker run -d \
        --name "$MYSQL_CONTAINER" \
        --network "$NETWORK" \
        -p "${MYSQL_PORT}:3306" \
        -e MYSQL_ROOT_PASSWORD="$DB_PASSWORD" \
        -e MYSQL_DATABASE="$DB_NAME" \
        mysql:8.0
    echo "[+] Started $MYSQL_CONTAINER on port $MYSQL_PORT"
fi

# -------------------------------------------------------------------
# Redis
# -------------------------------------------------------------------
if docker ps -a --format '{{.Names}}' | grep -q "^${REDIS_CONTAINER}$"; then
    echo "[*] $REDIS_CONTAINER already exists, starting if stopped..."
    docker start "$REDIS_CONTAINER" 2>/dev/null || true
else
    docker run -d \
        --name "$REDIS_CONTAINER" \
        --network "$NETWORK" \
        -p "${REDIS_PORT}:6379" \
        redis:7 \
        redis-server --requirepass "$DB_PASSWORD"
    echo "[+] Started $REDIS_CONTAINER on port $REDIS_PORT"
fi

# -------------------------------------------------------------------
# MinIO
# -------------------------------------------------------------------
if docker ps -a --format '{{.Names}}' | grep -q "^${MINIO_CONTAINER}$"; then
    echo "[*] $MINIO_CONTAINER already exists, starting if stopped..."
    docker start "$MINIO_CONTAINER" 2>/dev/null || true
else
    docker run -d \
        --name "$MINIO_CONTAINER" \
        --network "$NETWORK" \
        -p "${MINIO_PORT}:9000" \
        -e MINIO_ROOT_USER="$MINIO_USER" \
        -e MINIO_ROOT_PASSWORD="$DB_PASSWORD" \
        minio/minio:latest \
        server /data
    echo "[+] Started $MINIO_CONTAINER on port $MINIO_PORT"
fi

# -------------------------------------------------------------------
# Elasticsearch
# -------------------------------------------------------------------
if docker ps -a --format '{{.Names}}' | grep -q "^${ES_CONTAINER}$"; then
    echo "[*] $ES_CONTAINER already exists, starting if stopped..."
    docker start "$ES_CONTAINER" 2>/dev/null || true
else
    docker run -d \
        --name "$ES_CONTAINER" \
        --network "$NETWORK" \
        -p "${ES_PORT}:9200" \
        -e discovery.type=single-node \
        -e ELASTIC_PASSWORD="$DB_PASSWORD" \
        -e xpack.security.enabled=true \
        elasticsearch:8.11.3
    echo "[+] Started $ES_CONTAINER on port $ES_PORT"
fi

# -------------------------------------------------------------------
# Wait for MySQL
# -------------------------------------------------------------------
echo ""
echo "[*] Waiting for MySQL to be ready..."
for i in $(seq 1 30); do
    if docker exec "$MYSQL_CONTAINER" mysqladmin ping -u root -p"$DB_PASSWORD" --silent 2>/dev/null; then
        echo "[+] MySQL is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "[!] MySQL did not become ready in time"
        exit 1
    fi
    sleep 2
done

# -------------------------------------------------------------------
# Wait for Redis
# -------------------------------------------------------------------
echo "[*] Waiting for Redis to be ready..."
for i in $(seq 1 15); do
    if docker exec "$REDIS_CONTAINER" redis-cli -a "$DB_PASSWORD" ping 2>/dev/null | grep -q PONG; then
        echo "[+] Redis is ready"
        break
    fi
    if [ "$i" -eq 15 ]; then
        echo "[!] Redis did not become ready in time"
        exit 1
    fi
    sleep 2
done

# -------------------------------------------------------------------
# Wait for Elasticsearch
# -------------------------------------------------------------------
echo "[*] Waiting for Elasticsearch to be ready..."
for i in $(seq 1 60); do
    if docker exec "$ES_CONTAINER" curl -s -u "elastic:${DB_PASSWORD}" "http://localhost:9200/_cluster/health" 2>/dev/null | grep -q '"status"'; then
        echo "[+] Elasticsearch is ready"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "[!] Elasticsearch did not become ready in time"
        exit 1
    fi
    sleep 3
done

# -------------------------------------------------------------------
# RAGFlow Server
# -------------------------------------------------------------------
echo ""
echo "[*] Starting RAGFlow server..."
if docker ps -a --format '{{.Names}}' | grep -q "^${SERVER_CONTAINER}$"; then
    echo "[*] $SERVER_CONTAINER already exists, removing for clean start..."
    docker rm -f "$SERVER_CONTAINER" 2>/dev/null || true
fi

docker run -d \
    --platform linux/amd64 \
    --name "$SERVER_CONTAINER" \
    --network "$NETWORK" \
    -e MYSQL_HOST="$MYSQL_CONTAINER" \
    -e MYSQL_PORT=3306 \
    -e MYSQL_PASSWORD="$DB_PASSWORD" \
    -e MYSQL_DBNAME="$DB_NAME" \
    -e REDIS_HOST="$REDIS_CONTAINER" \
    -e REDIS_PORT=6379 \
    -e REDIS_PASSWORD="$DB_PASSWORD" \
    -e ES_HOST="$ES_CONTAINER" \
    -e ELASTIC_PASSWORD="$DB_PASSWORD" \
    -e MINIO_HOST="$MINIO_CONTAINER" \
    -e MINIO_USER="$MINIO_USER" \
    -e MINIO_PASSWORD="$DB_PASSWORD" \
    -e DOC_ENGINE=elasticsearch \
    -e USE_DOCLING=false \
    -e API_PROXY_SCHEME=python \
    -p "${API_PORT}:9380" \
    -p 9380:80 \
    "$RAGFLOW_IMAGE" \
    --disable-taskexecutor --disable-datasync
echo "[+] Started $SERVER_CONTAINER"

# -------------------------------------------------------------------
# Wait for RAGFlow API
# -------------------------------------------------------------------
# The entrypoint starts nginx (port 80) proxying to ragflow_server (port 9380).
# We mapped container:9380 -> host:API_PORT and container:80 -> host:9380.
# API requests go to host:API_PORT which hits the Python server directly,
# or host:9380 which goes through nginx.
echo "[*] Waiting for RAGFlow API to be ready (may take 2-5 minutes on ARM)..."
for i in $(seq 1 90); do
    RESP=$(curl -s "http://localhost:${API_PORT}/api/v1/documents" 2>/dev/null || echo "")
    if echo "$RESP" | grep -q '"code"'; then
        echo "[+] RAGFlow API is ready at http://localhost:${API_PORT}"
        break
    fi
    if [ "$i" -eq 90 ]; then
        echo "[!] RAGFlow API did not become ready in ~7 minutes."
        echo "    Check logs: docker logs $SERVER_CONTAINER"
        exit 1
    fi
    sleep 5
done

echo ""
echo "============================================================"
echo "  Services Running"
echo "============================================================"
echo "  MySQL   : localhost:${MYSQL_PORT}  (root / ${DB_PASSWORD})"
echo "  Redis   : localhost:${REDIS_PORT}  (password: ${DB_PASSWORD})"
echo "  MinIO   : localhost:${MINIO_PORT}  (${MINIO_USER} / ${DB_PASSWORD})"
echo "  ES      : localhost:${ES_PORT}     (elastic / ${DB_PASSWORD})"
echo "  RAGFlow : localhost:${API_PORT}    (API on container port 9380)"
echo ""
echo "  API base URL: http://localhost:${API_PORT}/api/v1"
echo ""
echo "[+] Setup complete. Run: bash autofyn_audit/run_all.sh"
