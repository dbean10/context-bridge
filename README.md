# Context Bridge

Give the **claude.ai chat** (the "strategy" Claude, no local access) the ability to
(a) sanity-check files in `~/Projects/` and (b) see what **Claude Code's agents
actually did**, by syncing **pre-sanitized** snapshots and transcripts to a store
the chat can read.

## Core architectural decision

**Outbound sync of pre-sanitized data, not inbound live access.**

Nothing on the Mac is ever reachable from the internet. Sanitization happens
locally, once, and is inspectable before anything leaves the machine. The worst
case is "one bad sync I can inspect and delete," not "a live exfiltration
endpoint."

```
~/Projects/<repo>/                  ~/.claude/projects/<proj>/<session>.jsonl
        │                                        │
        ▼                                        ▼
   ┌─────────────────────────────────────────────────┐
   │  sanitize.py  (local, offline)                   │
   │  - repo: tree + selected file contents            │
   │          (denylist: skip .env, *.pem, .git/, …)   │
   │  - transcripts: parse JSONL → event skeleton      │
   │          (tool name, ts, file touched, subagent   │
   │           spawn, status — NO raw output bodies)   │
   │  + regex redaction net on any retained text       │
   │  → writes clean .md/.json to ~/.context-bridge/   │
   └─────────────────────────────────────────────────┘
        │  inspect locally (`cat` + grep) — confirm clean
        ▼
   gcloud storage cp   (outbound only, private bucket)
        ▼
   Private GCS bucket  (doc-qa-learn for now)
        ▼
   Cloud Run FastMCP server (read-only)  → registered connector → claude.ai chat
```

## Three defense layers

1. **Denylist (primary for repos).** Secret files (`.env`, `*.pem`, `*.key`,
   service-account JSONs, …) are never read — name listed only. `.git/`,
   `node_modules/`, `.venv/`, caches, build dirs are never descended.
   `.env.example` is explicitly allowed.
2. **Structured extraction (primary for transcripts).** JSONL is parsed into an
   event skeleton: role, timestamp, tool name, path-like inputs, subagent spawn
   type, result status + length. **Raw tool-output bodies, full command args, and
   subagent prompts are dropped entirely** — they do not exist in the output.
3. **Regex redaction (safety net).** Applied to the thin text that survives both
   layers (repo file contents, one retained line per turn). Catches known secret
   shapes: `sk-ant-`, `ghp_`/`github_pat_`, Slack, AWS, GCP SA keys, PEM blocks,
   `libsql://`, JWT shapes, generic `key=value` assignments.

## Usage

```bash
python3 sanitize.py --dry-run                 # report only, write nothing
python3 sanitize.py                            # stage to ~/.context-bridge/staged/
python3 sanitize.py --repos-only
python3 sanitize.py --sessions-only
python3 sanitize.py --projects-root ~/Projects --cc-root ~/.claude/projects
```

### Inspect before you trust it (non-negotiable)

```bash
cat ~/.context-bridge/staged/sessions/*.md
grep -rInE "sk-ant-|ghp_|github_pat_|libsql://|BEGIN .*PRIVATE KEY|eyJ" \
  ~/.context-bridge/staged || echo clean
```

**Automating an unproven sanitizer is automating a leak.** Do not wire up the
watcher or the sync until the sanitizer is proven correct by manual inspection on
real data.

## Build order

1. ✅ `sanitize.py` — the gate. Stdlib-only, offline. Built and tested.
2. ⬜ `sanitize-and-sync.sh` — wraps sanitize.py + `gcloud storage cp` to GCS.
3. ⬜ `infra/setup-gcs.sh` — private bucket, uniform access, lifecycle expiry, IAM.
4. ⬜ `mcp-server/` — FastMCP read-only server on Cloud Run; register as connector.
5. ⬜ `fswatch` + `launchd` — near-real-time, only after the sanitizer is proven.

## Tests

```bash
uv run pytest
```

`tests/test_sanitize.py` plants known secrets in adversarial positions (source
files, `.env`, `.git/config`, command args, tool_result bodies, subagent prompts)
and asserts none survive sanitization. This is a **required CI check** — a red
here means a potential leak and blocks merge.

## Security model

| Property | How enforced |
|---|---|
| No inbound access to Mac | Sync is outbound-only; nothing listens on the Mac |
| Secrets never leave | Denylist + structured extraction + regex redaction, all local, inspectable |
| Store not world-readable | Private GCS bucket (uniform bucket-level access) |
| Bounded worst case | Read-only, pre-sanitized data only |
| Auto-expiry | GCS lifecycle rule matches Claude Code's ~30-day transcript retention |

## What this is NOT

Not part of `cto-compass` (the product) or `claude-agents` (the subagent kit).
This is separate tooling with its own deploy target (the Cloud Run MCP server) and
its own threat model.
