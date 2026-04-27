#!/usr/bin/env bash
set -euo pipefail

NETWORK="ragflow-audit"
MYSQL_CONTAINER="ragflow-audit-mysql"
REDIS_CONTAINER="ragflow-audit-redis"
MINIO_CONTAINER="ragflow-audit-minio"
ES_CONTAINER="ragflow-audit-es"

MYSQL_PORT=3307
REDIS_PORT=6380
MINIO_PORT=9100
ES_PORT=1200

DB_PASSWORD="infini_rag_flow"
DB_NAME="rag_flow"
MINIO_USER="rag_flow"

echo "=== RAGFlow Audit Environment Setup ==="
echo ""

# Create docker network
if docker network inspect "$NETWORK" >/dev/null 2>&1; then
    echo "[*] Network $NETWORK already exists"
else
    docker network create "$NETWORK"
    echo "[+] Created network $NETWORK"
fi

# Start MySQL
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

# Start Redis
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

# Start MinIO
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

# Start Elasticsearch
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

# Wait for MySQL to be healthy
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

# Wait for Redis to be healthy
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

echo ""
echo "=== Services Running ==="
echo "  MySQL   : localhost:${MYSQL_PORT}  (root / ${DB_PASSWORD}, db: ${DB_NAME})"
echo "  Redis   : localhost:${REDIS_PORT}  (password: ${DB_PASSWORD})"
echo "  MinIO   : localhost:${MINIO_PORT}  (${MINIO_USER} / ${DB_PASSWORD})"
echo "  ES      : localhost:${ES_PORT}     (elastic / ${DB_PASSWORD})"
SERVER_CONTAINER="ragflow-audit-server"

# Start RAGFlow Server (for exploit 05 — live endpoint testing)
echo ""
echo "[*] Starting RAGFlow server (for exploit 05)..."
if docker ps -a --format '{{.Names}}' | grep -q "^${SERVER_CONTAINER}$"; then
    echo "[*] $SERVER_CONTAINER already exists, starting if stopped..."
    docker start "$SERVER_CONTAINER" 2>/dev/null || true
else
    docker run -d \
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
        -p 9380:80 \
        -p 9381:9380 \
        infiniflow/ragflow:v0.18.0-slim
    echo "[+] Started $SERVER_CONTAINER"
fi

# Wait for RAGFlow server
echo "[*] Waiting for RAGFlow API to be ready (this may take 2-3 minutes)..."
for i in $(seq 1 30); do
    if docker exec "$SERVER_CONTAINER" curl -s http://localhost:9380/v1/document/list 2>/dev/null | grep -q '"code"'; then
        echo "[+] RAGFlow API is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "[!] RAGFlow API did not become ready in time (may still be starting)"
    fi
    sleep 10
done

echo ""
echo "=== Services Running ==="
echo "  MySQL   : localhost:${MYSQL_PORT}  (root / ${DB_PASSWORD}, db: ${DB_NAME})"
echo "  Redis   : localhost:${REDIS_PORT}  (password: ${DB_PASSWORD})"
echo "  MinIO   : localhost:${MINIO_PORT}  (${MINIO_USER} / ${DB_PASSWORD})"
echo "  ES      : localhost:${ES_PORT}     (elastic / ${DB_PASSWORD})"
echo "  RAGFlow : ragflow-audit-server:9380 (API inside container)"
echo ""
echo "[+] Setup complete."
