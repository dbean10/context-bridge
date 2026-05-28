#!/usr/bin/env bash
#
# verify.sh — prove the Context Bridge bucket is actually safe.
#
# "Configured != enforcing." setup-gcs.sh sets values; this script asserts the
# DANGEROUS states are actually impossible and the protective ones are actually
# in force. It reads live GCP state and checks, rather than trusting that the
# setup script's flags took effect.
#
# Checks (each must pass; any failure -> exit 1):
#   1. Bucket exists.
#   2. Public access prevention = enforced.
#   3. Uniform bucket-level access = enabled.
#   4. NO allUsers / allAuthenticatedUsers in the bucket IAM policy.
#   5. Lifecycle rule present with age == LIFECYCLE_DAYS, action Delete.
#   6. Reader SA exists and holds roles/storage.objectViewer on the bucket.
#
# USAGE
#   cd infra && ./verify.sh

set -uo pipefail   # NOTE: no -e; we want to run all checks and tally failures.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

if [ ! -f "$ENV_FILE" ]; then
  echo "verify: missing ${ENV_FILE}" >&2
  exit 2
fi
# shellcheck disable=SC1090
. "$ENV_FILE"

: "${PROJECT:?set PROJECT in infra/.env}"
: "${BUCKET:?set BUCKET in infra/.env}"
: "${READER_SA_NAME:?set READER_SA_NAME in infra/.env}"
: "${LIFECYCLE_DAYS:?set LIFECYCLE_DAYS in infra/.env}"

READER_SA_EMAIL="${READER_SA_NAME}@${PROJECT}.iam.gserviceaccount.com"
BUCKET_URI="gs://${BUCKET}"

PASS=0
FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1" >&2; FAIL=$((FAIL+1)); }

echo "[verify] ${BUCKET_URI} in ${PROJECT}"

# Pull bucket metadata once as JSON.
META="$(gcloud storage buckets describe "$BUCKET_URI" --project "$PROJECT" --format json 2>/dev/null)"
if [ -z "$META" ]; then
  echo "  FAIL: bucket not found or not accessible: ${BUCKET_URI}" >&2
  echo "[verify] 0 passed, 1 failed"
  exit 1
fi
ok "bucket exists"

# 2. Public access prevention enforced.
PAP="$(printf '%s' "$META" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("public_access_prevention") or d.get("publicAccessPrevention",""))' 2>/dev/null)"
if [ "$PAP" = "enforced" ]; then
  ok "public access prevention = enforced"
else
  bad "public access prevention is '${PAP:-unset}', expected 'enforced'"
fi

# 3. Uniform bucket-level access enabled.
UBLA="$(printf '%s' "$META" | python3 -c 'import sys,json; d=json.load(sys.stdin); u=d.get("uniform_bucket_level_access") or d.get("uniformBucketLevelAccess") or (d.get("iamConfiguration",{}).get("uniformBucketLevelAccess",{})); print(str(u.get("enabled") if isinstance(u,dict) else u).lower())' 2>/dev/null)"
if [ "$UBLA" = "true" ]; then
  ok "uniform bucket-level access = enabled"
else
  bad "uniform bucket-level access is '${UBLA:-unset}', expected true"
fi

# 4. No public members in the bucket IAM policy. This is the real safety
#    assertion — run the failing case: look for allUsers / allAuthenticatedUsers.
POLICY="$(gcloud storage buckets get-iam-policy "$BUCKET_URI" --project "$PROJECT" --format json 2>/dev/null)"
PUBLIC_MEMBERS="$(printf '%s' "$POLICY" | python3 -c '
import sys, json
d = json.load(sys.stdin)
bad = []
for b in d.get("bindings", []):
    role = b.get("role", "")
    for m in b.get("members", []):
        if m in ("allUsers", "allAuthenticatedUsers"):
            bad.append(m + " -> " + role)
print("\n".join(bad))
' 2>/dev/null)"
if [ -z "$PUBLIC_MEMBERS" ]; then
  ok "no allUsers / allAuthenticatedUsers in bucket IAM"
else
  bad "PUBLIC IAM members present: ${PUBLIC_MEMBERS}"
fi

# 5. Lifecycle rule present, Delete action, age == LIFECYCLE_DAYS.
LC_OK="$(gcloud storage buckets describe "$BUCKET_URI" --project "$PROJECT" --format json 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
lc = d.get('lifecycle_config') or d.get('lifecycle') or {}
rules = lc.get('rule', []) if isinstance(lc, dict) else []
want = ${LIFECYCLE_DAYS}
for r in rules:
    act = r.get('action', {})
    cond = r.get('condition', {})
    if act.get('type') == 'Delete' and int(cond.get('age', -1)) == want:
        print('ok'); break
else:
    print('no')
" 2>/dev/null)"
if [ "$LC_OK" = "ok" ]; then
  ok "lifecycle Delete @ ${LIFECYCLE_DAYS}d present"
else
  bad "no lifecycle Delete rule with age=${LIFECYCLE_DAYS} found"
fi

# 6. Reader SA exists and holds objectViewer on the bucket.
if gcloud iam service-accounts describe "$READER_SA_EMAIL" --project "$PROJECT" >/dev/null 2>&1; then
  ok "reader SA exists (${READER_SA_EMAIL})"
else
  bad "reader SA missing: ${READER_SA_EMAIL}"
fi
HAS_VIEWER="$(printf '%s' "$POLICY" | python3 -c "
import sys, json
d = json.load(sys.stdin)
want_m = 'serviceAccount:${READER_SA_EMAIL}'
for b in d.get('bindings', []):
    if b.get('role') == 'roles/storage.objectViewer' and want_m in b.get('members', []):
        print('ok'); break
else:
    print('no')
" 2>/dev/null)"
if [ "$HAS_VIEWER" = "ok" ]; then
  ok "reader SA has objectViewer on bucket"
else
  bad "reader SA lacks objectViewer on bucket"
fi

echo
echo "[verify] ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "[verify] bucket is private, scoped, and expiring. Safe to sync."
