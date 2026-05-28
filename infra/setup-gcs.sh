#!/usr/bin/env bash
#
# setup-gcs.sh — provision the Context Bridge store. IDEMPOTENT: safe to re-run.
#
# Creates (or confirms) a PRIVATE GCS bucket with:
#   - uniform bucket-level access (no per-object ACLs)
#   - public access prevention = enforced (cannot be made public)
#   - a lifecycle rule that auto-deletes objects after LIFECYCLE_DAYS
#   - a read-only service account granted objectViewer on THIS bucket only
#
# It does NOT touch object contents and does NOT make anything public. After
# running, verify with ./verify.sh (configured != enforcing — prove it).
#
# Config comes from infra/.env (gitignored). See infra/.env.example.
#
# USAGE
#   cd infra && cp .env.example .env   # fill in real values
#   ./setup-gcs.sh                     # provision (idempotent)
#   ./setup-gcs.sh --dry-run           # print intended actions, change nothing

set -euo pipefail

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

if [ ! -f "$ENV_FILE" ]; then
  echo "setup-gcs: missing ${ENV_FILE}" >&2
  echo "copy infra/.env.example to infra/.env and fill in values." >&2
  exit 2
fi
# shellcheck disable=SC1090
. "$ENV_FILE"

: "${PROJECT:?set PROJECT in infra/.env}"
: "${BUCKET:?set BUCKET in infra/.env}"
: "${REGION:?set REGION in infra/.env}"
: "${READER_SA_NAME:?set READER_SA_NAME in infra/.env}"
: "${LIFECYCLE_DAYS:?set LIFECYCLE_DAYS in infra/.env}"

READER_SA_EMAIL="${READER_SA_NAME}@${PROJECT}.iam.gserviceaccount.com"
BUCKET_URI="gs://${BUCKET}"

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  DRY-RUN: $*"
  else
    echo "  + $*"
    "$@"
  fi
}

echo "[setup-gcs] project=${PROJECT} bucket=${BUCKET} region=${REGION}"
echo "[setup-gcs] reader SA=${READER_SA_EMAIL} lifecycle=${LIFECYCLE_DAYS}d"
[ "$DRY_RUN" -eq 1 ] && echo "[setup-gcs] DRY RUN — no changes will be made"

# ── 1. Bucket ──────────────────────────────────────────────────────────────
# Create with uniform bucket-level access (--uniform-bucket-level-access) and
# public access prevention. If it already exists, creation is skipped.
echo "[1/4] bucket"
if gcloud storage buckets describe "$BUCKET_URI" --project "$PROJECT" >/dev/null 2>&1; then
  echo "  bucket exists — skipping create"
else
  run gcloud storage buckets create "$BUCKET_URI" \
    --project "$PROJECT" \
    --location "$REGION" \
    --uniform-bucket-level-access \
    --public-access-prevention
fi

# ── 2. Harden access settings (idempotent; safe to re-apply) ────────────────
# Ensure public access prevention is enforced even if the bucket pre-existed
# with a looser setting.
echo "[2/4] harden access settings"
run gcloud storage buckets update "$BUCKET_URI" \
  --project "$PROJECT" \
  --public-access-prevention \
  --uniform-bucket-level-access

# ── 3. Lifecycle rule (auto-delete after LIFECYCLE_DAYS) ─────────────────────
echo "[3/4] lifecycle rule (${LIFECYCLE_DAYS}d)"
LIFECYCLE_JSON="$(mktemp)"
trap 'rm -f "$LIFECYCLE_JSON"' EXIT
cat > "$LIFECYCLE_JSON" <<JSON
{
  "rule": [
    {
      "action": { "type": "Delete" },
      "condition": { "age": ${LIFECYCLE_DAYS} }
    }
  ]
}
JSON
run gcloud storage buckets update "$BUCKET_URI" \
  --project "$PROJECT" \
  --lifecycle-file "$LIFECYCLE_JSON"

# ── 4. Read-only service account + bucket-scoped objectViewer ───────────────
echo "[4/4] reader service account"
if gcloud iam service-accounts describe "$READER_SA_EMAIL" --project "$PROJECT" >/dev/null 2>&1; then
  echo "  SA exists — skipping create"
else
  run gcloud iam service-accounts create "$READER_SA_NAME" \
    --project "$PROJECT" \
    --display-name "Context Bridge read-only reader"
fi

# Grant objectViewer on THE BUCKET ONLY (not project-wide). add-iam-policy-
# binding is idempotent — re-running just confirms the binding.
run gcloud storage buckets add-iam-policy-binding "$BUCKET_URI" \
  --project "$PROJECT" \
  --member "serviceAccount:${READER_SA_EMAIL}" \
  --role "roles/storage.objectViewer"

echo
echo "[setup-gcs] done. NEXT: ./verify.sh — prove private + lifecycle + read-only."
echo "[setup-gcs] then sync staged output with:"
echo "  gcloud storage rsync -r -d ~/.context-bridge/staged ${BUCKET_URI}"
