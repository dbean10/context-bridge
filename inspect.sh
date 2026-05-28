#!/usr/bin/env bash
#
# inspect.sh — trustworthy leak scan over the sanitized staging directory.
#
# WHY THIS EXISTS
# A raw `grep` over the staged output is noisy: context-bridge snapshots its
# own source (which literally contains the secret regexes and test fixtures),
# and real repos contain placeholders, redaction markers, and code that just
# *mentions* secret prefixes. That noise trains you to skim past hits — exactly
# how a real leak slips through. This script suppresses ONLY structurally
# benign lines so that a clean run prints "clean" and ANY output is a real hit
# worth investigating.
#
# SAFETY STANCE
# - Exclusions are by LINE SHAPE, never by filename. We never blind the scan to
#   a whole file. A real secret in sanitize.py would still be caught.
# - An exclusion only fires when the line carries positive evidence of being
#   benign: it contains a [REDACTED...] marker, an obvious placeholder ellipsis,
#   or it is a regex-definition line. Everything else is reported.
# - Exit code: 0 = clean, 1 = potential leak found, 2 = usage/setup error.
#
# USAGE
#   ./inspect.sh                       # scan ~/.context-bridge/staged
#   ./inspect.sh /path/to/staged       # scan a specific dir
#   ./inspect.sh --raw                 # no benign filtering (the old noisy grep)
#   ./inspect.sh --verbose             # also print how many benign lines were filtered

set -euo pipefail

STAGED_DEFAULT="${HOME}/.context-bridge/staged"
RAW=0
VERBOSE=0
TARGET=""

while [ $# -gt 0 ]; do
  case "$1" in
    --raw)     RAW=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    -h|--help)
      sed -n '2,30p' "$0"; exit 0 ;;
    -*)
      echo "unknown flag: $1" >&2; exit 2 ;;
    *)
      TARGET="$1"; shift ;;
  esac
done

STAGED="${TARGET:-$STAGED_DEFAULT}"

if [ ! -d "$STAGED" ]; then
  echo "inspect: staged dir not found: $STAGED" >&2
  echo "run sanitize.py first, or pass the path explicitly." >&2
  exit 2
fi

# The secret shapes we scan for. Keep in sync with sanitize.py's high-confidence
# patterns. A hit on any of these is a candidate leak until proven benign.
SECRET_RE='sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|libsql://[A-Za-z0-9._-]+|eyJ[A-Za-z0-9._-]{30,}|-----BEGIN .*PRIVATE KEY-----'

# Raw mode: just the candidate hits, no filtering.
if [ "$RAW" -eq 1 ]; then
  if grep -rInE "$SECRET_RE" "$STAGED"; then
    exit 1
  else
    echo "clean (raw)"
    exit 0
  fi
fi

# Benign-line filter. A candidate hit is suppressed ONLY if the SAME line also
# carries positive evidence of being benign. Each branch is deliberately narrow.
#
#  1. Redaction marker present  -> the secret was already neutralized on this
#                                   line; the match is the surrounding context
#                                   (e.g. `TURSO_URL=[REDACTED:TURSO_URL]`), or
#                                   it's our own [REDACTED:...] format string.
#  2. Placeholder ellipsis      -> e.g. `sk-ant-...` / `sk-...` — not a real key.
#  3. Regex-source line         -> a line defining one of the detection patterns
#                                   (contains `re.compile(` or the grep pattern
#                                   string), i.e. the scanner describing itself.
#  4. Prefix-mention in code    -> `startswith("libsql://")` / `"libsql://"` used
#                                   as a literal prefix in a comparison, not a URL
#                                   with a host. We require the libsql match to be
#                                   immediately followed by a quote/paren/space.
BENIGN_RE='\[REDACTED|sk-ant-\.\.\.|sk-\.\.\.|re\.compile\(|github_pat_\[A-Za-z|startswith\("libsql://"\)|"libsql://"[,)[:space:]]|libsql:// \(remote\)|grep -rInE|\[A-Za-z0-9|END\[\^'

candidates="$(grep -rInE "$SECRET_RE" "$STAGED" || true)"

if [ -z "$candidates" ]; then
  echo "clean"
  exit 0
fi

# Split candidates into real hits vs benign-filtered.
real_hits="$(printf '%s\n' "$candidates" | grep -vE "$BENIGN_RE" || true)"
benign_count="$(printf '%s\n' "$candidates" | grep -cE "$BENIGN_RE" || true)"

if [ "$VERBOSE" -eq 1 ]; then
  echo "inspect: $(printf '%s\n' "$candidates" | grep -c . ) candidate lines, ${benign_count} filtered as benign" >&2
fi

if [ -n "$real_hits" ]; then
  echo "POTENTIAL LEAK — lines below are NOT recognized as benign:" >&2
  printf '%s\n' "$real_hits"
  echo >&2
  echo "If these are genuinely safe, confirm by hand and (if appropriate) widen" >&2
  echo "the BENIGN_RE filter in inspect.sh — but verify the secret is fake first." >&2
  exit 1
fi

echo "clean (${benign_count} benign self-references filtered; run --raw to see them)"
exit 0
