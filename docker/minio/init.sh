#!/bin/sh
# Sentio OSS quickstart - one-shot MinIO bootstrap.
# Runs via the minio/mc image, creates the sentio-attachments bucket, sets
# a reasonable default lifecycle. Idempotent (ignores "already exists").

set -eu

MINIO_URL="${MINIO_URL:-http://minio:9000}"
MINIO_ROOT_USER="${MINIO_ROOT_USER:-sentio-dev}"
MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:-sentio-dev-secret-CHANGE_ME}"
BUCKET="${SENTIO_BUCKET:-sentio-attachments}"

echo "waiting for MinIO at ${MINIO_URL}..."
until mc alias set local "${MINIO_URL}" "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}" 2>/dev/null; do
    sleep 1
done

echo "creating bucket ${BUCKET} (ignore 'already exists')"
mc mb --ignore-existing "local/${BUCKET}"

echo "MinIO bootstrap done."
