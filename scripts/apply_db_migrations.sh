#!/usr/bin/env bash
# Applies the versioned SQL migrations in db/migrations/ to Cloud SQL (cymbal-health-pg-main).
#
# Why gcloud sql import: the instance has no public IP, so neither a workstation nor
# Cloud Build can open a direct PostgreSQL session. `gcloud sql import sql` runs the
# script inside the Cloud SQL control plane, reading it from a private bucket that only
# the Cloud SQL instance service agent can read. No database password is used by the
# caller; the import runs as the built-in admin user managed by Cloud SQL.
#
# Migrations are idempotent and must always be applied in order (V001, V002, ...).
#
# Usage: scripts/apply_db_migrations.sh <project_id> [region]
set -euo pipefail

PROJECT_ID="${1:?project_id required}"
REGION="${2:-us-central1}"
INSTANCE="cymbal-health-pg-main"
DATABASE="cymbal_health_db"
PROJECT_NUM="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
BUCKET="gs://cymbal-health-db-migrations-${PROJECT_NUM}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIGRATIONS_DIR="${SCRIPT_DIR}/../db/migrations"

if ! gcloud storage buckets describe "${BUCKET}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud storage buckets create "${BUCKET}" --project="${PROJECT_ID}" --location="${REGION}" \
    --uniform-bucket-level-access --public-access-prevention
  SQL_SA="$(gcloud sql instances describe "${INSTANCE}" --project="${PROJECT_ID}" --format='value(serviceAccountEmailAddress)')"
  gcloud storage buckets add-iam-policy-binding "${BUCKET}" \
    --member="serviceAccount:${SQL_SA}" --role="roles/storage.objectViewer" >/dev/null
fi

for migration in $(ls "${MIGRATIONS_DIR}"/V*.sql | sort); do
  name="$(basename "${migration}")"
  echo "Applying ${name}"
  gcloud storage cp "${migration}" "${BUCKET}/${name}" --project="${PROJECT_ID}" >/dev/null
  # gcloud can exit 0 even when PostgreSQL reports an error, so inspect the output.
  output="$(gcloud sql import sql "${INSTANCE}" "${BUCKET}/${name}" \
    --project="${PROJECT_ID}" --database="${DATABASE}" --user=postgres --quiet 2>&1)" || true
  if grep -q "ERROR" <<<"${output}"; then
    echo "${output}" >&2
    echo "Migration ${name} failed; the transaction was rolled back. Stopping." >&2
    exit 1
  fi
done
echo "All migrations applied to ${INSTANCE}/${DATABASE}"
