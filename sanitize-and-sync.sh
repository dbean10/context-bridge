#!/usr/bin/env bash
#
# sanitize-and-sync.sh — the outbound pipeline, with safety gates.
#
# Pipeline:
#   1. sanitize.py        regenerate ~/.context-bridge/staged from local state
#   2. inspect.sh   GATE  if it exits non-zero, ABORT — never sync a leak
#   3. non-empty    GATE  refuse to sync if staged is suspiciously empty
#                         (a broken sanitize must not mirror-delete the bucket)
#   4. rsync (mirror)     outbound MIRROR to gs://$BUCKET (private)
#
# The bucket is a PROJECTION of current local state: mirror-delete removes bucket
# objects with no local counterpart so the chat never sees stale/ghost files.
# That delete power is exactly why gates 2+3 exist — they ensure we never
# mirror an empty or unsafe staged dir over a good bucket.
#
# Nothing here reads the bucket or runs on a server. Outbound only.
#
# USAGE
#   ./sanitize-and-sync.sh              # sanitize -> inspect -> guard -> sync
#   ./sanitize-and-sync.sh --dry-run    # do everything EXCEPT the real rsync
#   ./sanitize-and-sync.sh --skip-sanitize   # use existing staged/ (still gated)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ROOT}/infra/.env"
STAGED="${HOME}/.context-bridge/staged"

DRY_RUN=0
SKIP_SANITIZE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)       DRY_RUN=1; shift ;;
    --skip-sanitize) SKIP_SANITIZE=1; shift ;;
    -h|--help)       sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

if [ ! -f "$ENV_FILE" ]; then
  echo "sync: missing ${ENV_FILE} (copy infra/.env.example to infra/.env)" >&2
  exit 2
fi
# shellcheck disable=SC1090
. "$ENV_FILE"
: "${BUCKET:?set BUCKET in infra/.env}"
: "${PROJECT:?set PROJECT in infra/.env}"
BUCKET_URI="gs://${BUCKET}"

# Minimum artifacts a healthy staged dir must contain. Tune if your layout
# changes; the point is "obviously broken / empty" detection, not exactness.
MIN_REPO_FILES=1
MIN_SESSION_FILES=1

echo "[sync] root=${ROOT}"
echo "[sync] staged=${STAGED}"
echo "[sync] bucket=${BUCKET_URI} (project ${PROJECT})"
[ "$DRY_RUN" -eq 1 ] && echo "[sync] DRY RUN — sanitize + gates run for real, rsync is simulated"

# ── 1. Sanitize ─────────────────────────────────────────────────────────────
if [ "$SKIP_SANITIZE" -eq 1 ]; then
  echo "[1/4] sanitize — SKIPPED (--skip-sanitize); using existing staged/"
else
  echo "[1/4] sanitize"
  ( cd "$ROOT" && uv run python3 sanitize.py )
fi

# ── 2. Inspect GATE (hard) ──────────────────────────────────────────────────
# This is the load-bearing line: a leak scan failure ABORTS the sync. The only
# path to the bucket is through a passing inspect.
echo "[2/4] inspect (leak-scan gate)"
if ! "${ROOT}/inspect.sh" "$STAGED"; then
  echo "[sync] ABORT: inspect.sh flagged potential secrets. Nothing synced." >&2
  echo "[sync] investigate the lines above; sync is blocked until inspect is clean." >&2
  exit 1
fi

# ── 3. Non-empty GATE (guards -d against wiping the bucket) ─────────────────
echo "[3/4] non-empty guard"
if [ ! -d "$STAGED" ]; then
  echo "[sync] ABORT: staged dir does not exist: ${STAGED}" >&2
  exit 1
fi
# Count real artifacts. -maxdepth keeps it to the expected layout.
repo_count="$(find "${STAGED}/repos" -maxdepth 1 -name '*.md' 2>/dev/null | wc -l | tr -d ' ')"
session_count="$(find "${STAGED}/sessions" -maxdepth 1 -name '*.md' 2>/dev/null | wc -l | tr -d ' ')"
echo "  repos: ${repo_count}, sessions: ${session_count}"
if [ "${repo_count:-0}" -lt "$MIN_REPO_FILES" ] && [ "${session_count:-0}" -lt "$MIN_SESSION_FILES" ]; then
  echo "[sync] ABORT: staged output looks empty (repos=${repo_count}, sessions=${session_count})." >&2
  echo "[sync] refusing to mirror an empty dir over the bucket. Check sanitize.py output." >&2
  exit 1
fi

# ── 4. Outbound MIRROR ──────────────────────────────────────────────────────
echo "[4/4] mirror -> ${BUCKET_URI}"
# NOTE: `gcloud storage rsync` uses the long flag
# --delete-unmatched-destination-objects for mirror/delete behavior. The short
# `-d` form is from the older `gsutil rsync` and is NOT recognized here.
RSYNC=(gcloud storage rsync -r --delete-unmatched-destination-objects "$STAGED" "$BUCKET_URI" --project "$PROJECT")
if [ "$DRY_RUN" -eq 1 ]; then
  echo "  DRY-RUN: ${RSYNC[*]} --dry-run"
  "${RSYNC[@]}" --dry-run
else
  echo "  + ${RSYNC[*]}"
  "${RSYNC[@]}"
fi

echo
echo "[sync] done. Bucket now mirrors current staged state."
[ "$DRY_RUN" -eq 1 ] && echo "[sync] (dry run — no objects were actually changed)"
