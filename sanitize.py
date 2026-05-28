#!/usr/bin/env python3
"""
sanitize.py — Context Bridge sanitizer (the gate).

Produces pre-sanitized snapshots of local Claude Code state for outbound sync.
NOTHING here ever opens a network connection. It only reads local files and
writes clean artifacts to a staging directory you inspect by hand.

Two inputs, two strategies:
  - Repo files (~/Projects/<repo>/): tree + selected file CONTENTS, with a
    hard denylist of secret-bearing files and a regex redaction net on what
    survives.
  - Transcripts (~/.claude/projects/<proj>/<session>.jsonl): STRUCTURED
    EXTRACTION ONLY. Parse each JSONL line into an event skeleton (role, ts,
    tool name, file path touched, subagent spawn, status). Raw tool-output
    bodies are NEVER copied. This is safe-by-construction: the secret-bearing
    payloads do not exist in the output at all.

Output layout (default ~/.context-bridge/staged/):
  staged/
    repos/<repo>.md            one markdown file per repo (tree + contents)
    sessions/<session>.md      human-readable event timeline per session
    sessions/<session>.json    machine-readable event skeleton per session
    manifest.json              what was produced, counts, redaction stats

USAGE
  python3 sanitize.py                      # sanitize everything, default roots
  python3 sanitize.py --dry-run            # report what WOULD be done, write nothing
  python3 sanitize.py --repos-only
  python3 sanitize.py --sessions-only
  python3 sanitize.py --projects-root ~/Projects --cc-root ~/.claude/projects
  python3 sanitize.py --out ~/.context-bridge/staged

After running: `cat` the output, confirm zero secrets, THEN wire up sync.
Automating an unproven sanitizer is automating a leak.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ----------------------------------------------------------------------------
# Configuration: denylists and redaction patterns
# ----------------------------------------------------------------------------

# Files/dirs whose CONTENTS are never read or copied. Matched on the basename
# (for files) or any path component (for dirs). Glob-style via fnmatch.
SECRET_FILE_GLOBS = [
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx",
    "id_rsa", "id_rsa.*", "id_ed25519", "id_ed25519.*",
    "*.keystore", "*.jks", "credentials.json", "service-account*.json",
    ".npmrc", ".pypirc", ".netrc",
]

# Directory names never descended into. Some hold secrets (.git config can hold
# tokens); others are pure noise that pointlessly bloats the sync.
SKIP_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules", ".venv", "venv", "env", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "dist", "build", ".next", ".turbo", "coverage",
    ".terraform", ".gradle", ".idea", ".vscode",
}

# Only these extensions have their contents copied. Everything else gets a
# tree entry but no body (keeps binaries and surprises out of the snapshot).
TEXT_EXTENSIONS = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".md", ".txt", ".rst", ".json", ".jsonl", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".conf", ".sh", ".bash", ".zsh", ".fish",
    ".html", ".css", ".scss", ".sql", ".dockerfile", ".tf", ".tfvars",
    ".env.example", ".gitignore", ".dockerignore",
}
# Filenames (no extension) whose contents are still worth copying.
TEXT_FILENAMES = {
    "Dockerfile", "Makefile", "README", "LICENSE", "CLAUDE.md",
    ".gitignore", ".dockerignore", "requirements.txt", "pyproject.toml",
    ".env.example",
}

# Skip copying contents of files larger than this (still listed in the tree).
MAX_FILE_BYTES = 256 * 1024  # 256 KB

# Per-repo ignore file, gitignore-style (very small subset: exact + prefix + suffix).
REPO_IGNORE_FILENAME = ".context-bridge-ignore"

# Regex redaction net: the safety layer applied to ALL surviving text (repo
# file contents AND the thin strings retained from transcripts). These catch
# KNOWN secret shapes. They are a net, not the primary defense — the primary
# defenses are the file denylist and structured-only transcript extraction.
REDACTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ANTHROPIC_KEY", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OPENAI_KEY", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("GITHUB_PAT", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("GITHUB_FINEGRAINED", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("SLACK_TOKEN", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GCP_SA_KEY", re.compile(r'"private_key"\s*:\s*"-----BEGIN[^"]+"')),
    ("PRIVATE_KEY_BLOCK", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END[^\n]*-----")),
    ("BEARER", re.compile(r"[Bb]earer\s+[A-Za-z0-9._\-]{20,}")),
    ("TURSO_URL", re.compile(r"libsql://[A-Za-z0-9._\-]+")),
    ("AUTH_TOKEN_TURSO", re.compile(r"eyJ[A-Za-z0-9._\-]{30,}")),  # JWT shape (Turso auth tokens, etc.)
    # GENERIC_ASSIGN fires ONLY on a QUOTED string literal assigned to a
    # secret-named identifier — i.e. an embedded value, not code that reads a
    # secret. `token = os.getenv("X")`, `--secret=name`, and `key = ""` do NOT
    # match (no quoted opaque RHS). The opacity check lives in redact().
    ("GENERIC_ASSIGN", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|auth[_-]?token|access[_-]?token)\b"
        r"\s*[:=]\s*(['\"])([^'\"]{12,})\1"
    )),
]


# Values that are clearly a CODE REFERENCE (env lookup / interpolation) rather
# than an embedded secret. Name-like values (e.g. `anthropic-key`) are handled
# by the opacity gate instead, which requires letters AND digits.
_NOT_A_SECRET_VALUE = re.compile(
    r"""(?xi)
    ^(?:
        os\. | getenv | environ | process\.env | deno\.env |   # env lookups
        \$\{? | \#\{                                            # shell / interpolation
    )
    """
)

# A real opaque secret value has entropy: a mix of letters AND digits (or
# symbols) and no spaces. Pure words, dotted paths, and prose don't qualify.
_LOOKS_OPAQUE = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9._\-+/=]{12,}$")


# ----------------------------------------------------------------------------
# Redaction
# ----------------------------------------------------------------------------

@dataclass
class RedactionStats:
    counts: dict[str, int] = field(default_factory=dict)

    def bump(self, label: str, n: int = 1) -> None:
        if n:
            self.counts[label] = self.counts.get(label, 0) + n

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def redact(text: str, stats: RedactionStats) -> str:
    """Apply every redaction pattern. For GENERIC_ASSIGN, redact only the
    quoted value (and only if it actually looks like an opaque secret, not a
    code reference or a bare name); for the rest, redact the whole match."""
    for label, pat in REDACTION_PATTERNS:
        if label == "GENERIC_ASSIGN":
            def _sub(m: re.Match[str], _label: str = label) -> str:
                value = m.group(2)
                # Skip code references / env lookups / bare names, and anything
                # that doesn't look opaque (real secrets mix letters + digits).
                if _NOT_A_SECRET_VALUE.match(value) or not _LOOKS_OPAQUE.match(value):
                    return m.group(0)
                stats.bump(_label)
                return m.group(0).replace(value, f"[REDACTED:{_label}]")
            text = pat.sub(_sub, text)
        else:
            def _sub2(m: re.Match[str], _label: str = label) -> str:
                stats.bump(_label)
                return f"[REDACTED:{_label}]"
            text = pat.sub(_sub2, text)
    return text


# ----------------------------------------------------------------------------
# Repo snapshot
# ----------------------------------------------------------------------------

def _glob_match(name: str, globs: Iterable[str]) -> bool:
    from fnmatch import fnmatch
    return any(fnmatch(name, g) for g in globs)


def _is_secret_file(name: str) -> bool:
    if name == ".env.example":  # explicitly safe; example file, no real values
        return False
    return _glob_match(name, SECRET_FILE_GLOBS)


def _wants_contents(path: Path) -> bool:
    if path.name in TEXT_FILENAMES:
        return True
    return path.suffix.lower() in TEXT_EXTENSIONS


def _load_repo_ignore(repo_root: Path) -> list[str]:
    f = repo_root / REPO_IGNORE_FILENAME
    if not f.exists():
        return []
    out: list[str] = []
    for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _ignored_by_repo(rel: str, patterns: list[str]) -> bool:
    for p in patterns:
        if p.endswith("/") and (rel == p[:-1] or rel.startswith(p)):
            return True
        if p.startswith("*") and rel.endswith(p[1:]):
            return True
        if rel == p or rel.startswith(p + "/"):
            return True
    return False


@dataclass
class RepoResult:
    repo: str
    markdown: str
    file_count: int
    content_count: int
    skipped_secret: list[str]
    redactions: int


def sanitize_repo(repo_root: Path, stats: RedactionStats) -> RepoResult:
    repo_name = repo_root.name
    ignore = _load_repo_ignore(repo_root)
    tree_lines: list[str] = []
    content_blocks: list[str] = []
    file_count = 0
    content_count = 0
    skipped_secret: list[str] = []
    start_redactions = stats.total

    for dirpath, dirnames, filenames in os.walk(repo_root):
        # prune skip dirs in place
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        rel_dir = os.path.relpath(dirpath, repo_root)
        rel_dir = "" if rel_dir == "." else rel_dir

        for fname in sorted(filenames):
            rel = os.path.join(rel_dir, fname) if rel_dir else fname
            if _ignored_by_repo(rel, ignore):
                continue

            file_count += 1
            full = Path(dirpath) / fname

            if _is_secret_file(fname):
                skipped_secret.append(rel)
                tree_lines.append(f"  {rel}    [SECRET FILE — name listed, contents NOT read]")
                continue

            try:
                size = full.stat().st_size
            except OSError:
                continue

            if not _wants_contents(full):
                tree_lines.append(f"  {rel}    ({size} B, contents omitted: not a tracked text type)")
                continue
            if size > MAX_FILE_BYTES:
                tree_lines.append(f"  {rel}    ({size} B, contents omitted: exceeds {MAX_FILE_BYTES} B)")
                continue

            try:
                raw = full.read_text(encoding="utf-8", errors="replace")
            except OSError:
                tree_lines.append(f"  {rel}    (unreadable)")
                continue

            clean = redact(raw, stats)
            content_count += 1
            tree_lines.append(f"  {rel}    ({size} B)")
            lang = full.suffix.lstrip(".") or "text"
            content_blocks.append(f"### `{rel}`\n\n```{lang}\n{clean}\n```\n")

    md = [f"# Repo snapshot: `{repo_name}`\n"]
    md.append(f"_Sanitized {datetime.now(UTC).isoformat()} · source: `{repo_root}`_\n")
    md.append("## Tree\n\n```")
    md.extend(tree_lines if tree_lines else ["  (empty)"])
    md.append("```\n")
    if skipped_secret:
        md.append("## Secret files skipped (names only)\n")
        md.extend(f"- `{s}`" for s in skipped_secret)
        md.append("")
    md.append("## File contents\n")
    md.extend(content_blocks if content_blocks else ["_(no copyable text files)_"])

    return RepoResult(
        repo=repo_name,
        markdown="\n".join(md),
        file_count=file_count,
        content_count=content_count,
        skipped_secret=skipped_secret,
        redactions=stats.total - start_redactions,
    )


# ----------------------------------------------------------------------------
# Transcript structured extraction (NO raw bodies)
# ----------------------------------------------------------------------------

# Tool-input fields that are safe-ish to retain in redacted summary form.
# We keep only the file path / command name shape — never full arg strings.
PATH_LIKE_KEYS = ("path", "file_path", "filename", "file", "notebook_path")
COMMAND_KEYS = ("command", "cmd")


def _summarize_tool_input(name: str, tool_input: Any, stats: RedactionStats) -> str:
    """Return a thin, redacted, one-line summary of a tool_use input.
    Never returns full argument bodies — only path-like fields and the head
    token of a command. Everything that survives is run through redact()."""
    if not isinstance(tool_input, dict):
        return ""
    bits: list[str] = []
    for k in PATH_LIKE_KEYS:
        if k in tool_input and isinstance(tool_input[k], str):
            bits.append(f"{k}={tool_input[k]}")
    for k in COMMAND_KEYS:
        if k in tool_input and isinstance(tool_input[k], str):
            head = tool_input[k].strip().split()
            # keep only the program name + first subcommand-ish token
            keep = " ".join(head[:2]) if head else ""
            bits.append(f"{k}~={keep} [args dropped]")
    # subagent spawn (Task tool) — keep the subagent type, drop the prompt body
    if name in ("Task", "task") and isinstance(tool_input, dict):
        sub = tool_input.get("subagent_type") or tool_input.get("description")
        if isinstance(sub, str):
            bits.append(f"subagent={sub} [prompt dropped]")
    summary = "; ".join(bits)
    return redact(summary, stats)


@dataclass
class SessionEvent:
    ts: str | None
    role: str
    kind: str            # "text" | "tool_use" | "tool_result" | "system"
    tool: str | None
    summary: str         # thin, redacted; never a raw body
    status: str | None   # for tool_result: ok/error
    body_len: int | None  # length only — proves we saw a body without copying it


def _extract_text_blocks(content: Any) -> list[dict[str, Any]]:
    if isinstance(content, list):
        return [b for b in content if isinstance(b, dict)]
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    return []


def _result_body_len(rc: Any) -> int:
    """Length of a tool_result body, without retaining the body itself."""
    if isinstance(rc, str):
        return len(rc)
    if isinstance(rc, list):
        return sum(len(x.get("text", "")) for x in rc if isinstance(x, dict))
    return 0


def sanitize_session(jsonl_path: Path, stats: RedactionStats) -> tuple[list[SessionEvent], dict[str, int]]:
    events: list[SessionEvent] = []
    tallies = {"text": 0, "tool_use": 0, "tool_result": 0, "system": 0, "lines": 0, "tools_by_name": {}}

    with jsonl_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            tallies["lines"] += 1
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts = obj.get("timestamp") or obj.get("ts")
            msg = obj.get("message") if isinstance(obj.get("message"), dict) else obj
            role = (msg.get("role") if isinstance(msg, dict) else None) or obj.get("type") or "unknown"
            content = msg.get("content") if isinstance(msg, dict) else None

            for block in _extract_text_blocks(content):
                btype = block.get("type")

                if btype == "text":
                    # We keep ONLY a length + a heavily-redacted first line, not the body.
                    raw = block.get("text", "") or ""
                    first = redact(raw.strip().splitlines()[0] if raw.strip() else "", stats)
                    first = (first[:120] + "…") if len(first) > 120 else first
                    events.append(SessionEvent(ts, role, "text", None, first, None, len(raw)))
                    tallies["text"] += 1

                elif btype == "tool_use":
                    name = block.get("name", "?")
                    summ = _summarize_tool_input(name, block.get("input"), stats)
                    events.append(SessionEvent(ts, role, "tool_use", name, summ, None, None))
                    tallies["tool_use"] += 1
                    tallies["tools_by_name"][name] = tallies["tools_by_name"].get(name, 0) + 1

                elif btype == "tool_result":
                    # CRITICAL: never copy the result body. Record status + length only.
                    is_err = bool(block.get("is_error"))
                    blen = _result_body_len(block.get("content"))
                    events.append(SessionEvent(
                        ts, role, "tool_result", None, "", "error" if is_err else "ok", blen
                    ))
                    tallies["tool_result"] += 1

    return events, tallies


def session_markdown(session_id: str, src: Path, events: list[SessionEvent], tallies: dict[str, int]) -> str:
    md = [f"# Session timeline: `{session_id}`\n"]
    md.append(f"_Sanitized {datetime.now(UTC).isoformat()} · source: `{src}`_\n")
    md.append("> Structured extraction only. No raw tool-output bodies are present in this file.\n")
    md.append("## Summary\n")
    md.append(f"- Lines parsed: {tallies['lines']}")
    md.append(
        f"- Text turns: {tallies['text']} · tool_use: {tallies['tool_use']}"
        f" · tool_result: {tallies['tool_result']}"
    )
    if tallies["tools_by_name"]:
        by = ", ".join(f"{k}×{v}" for k, v in sorted(tallies["tools_by_name"].items(), key=lambda x: -x[1]))
        md.append(f"- Tools used: {by}")
    md.append("\n## Event sequence\n")
    for e in events:
        ts = (e.ts or "")[:19]
        if e.kind == "tool_use":
            md.append(f"- `{ts}` **{e.role}** → tool_use **{e.tool}** · {e.summary or '(no path/cmd)'}")
        elif e.kind == "tool_result":
            tag = "✗ error" if e.status == "error" else "✓ ok"
            md.append(f"- `{ts}`   ↳ tool_result {tag} · body {e.body_len} chars [dropped]")
        elif e.kind == "text":
            md.append(f"- `{ts}` **{e.role}**: {e.summary} _(len {e.body_len} [dropped])_")
        else:
            md.append(f"- `{ts}` **{e.role}** · {e.kind}")
    return "\n".join(md) + "\n"


def events_to_json(events: list[SessionEvent]) -> list[dict[str, Any]]:
    return [
        {
            "ts": e.ts, "role": e.role, "kind": e.kind, "tool": e.tool,
            "summary": e.summary, "status": e.status, "body_len": e.body_len,
        }
        for e in events
    ]


# ----------------------------------------------------------------------------
# Driver
# ----------------------------------------------------------------------------

def discover_sessions(cc_root: Path) -> list[Path]:
    if not cc_root.exists():
        return []
    return sorted(cc_root.rglob("*.jsonl"))


def discover_repos(projects_root: Path) -> list[Path]:
    if not projects_root.exists():
        return []
    return sorted(p for p in projects_root.iterdir() if p.is_dir() and p.name not in SKIP_DIRS)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Context Bridge sanitizer (the gate).")
    ap.add_argument("--projects-root", default=str(Path.home() / "Projects"))
    ap.add_argument("--cc-root", default=str(Path.home() / ".claude" / "projects"))
    ap.add_argument("--out", default=str(Path.home() / ".context-bridge" / "staged"))
    ap.add_argument("--repos-only", action="store_true")
    ap.add_argument("--sessions-only", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="report only; write nothing")
    args = ap.parse_args(argv)

    projects_root = Path(args.projects_root).expanduser()
    cc_root = Path(args.cc_root).expanduser()
    out = Path(args.out).expanduser()
    do_repos = not args.sessions_only
    do_sessions = not args.repos_only

    stats = RedactionStats()
    manifest: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "projects_root": str(projects_root),
        "cc_root": str(cc_root),
        "dry_run": args.dry_run,
        "repos": [],
        "sessions": [],
    }

    if not args.dry_run:
        (out / "repos").mkdir(parents=True, exist_ok=True)
        (out / "sessions").mkdir(parents=True, exist_ok=True)

    if do_repos:
        repos = discover_repos(projects_root)
        print(f"[repos] {len(repos)} found under {projects_root}", file=sys.stderr)
        for repo in repos:
            res = sanitize_repo(repo, stats)
            entry = {
                "repo": res.repo, "files": res.file_count, "contents_copied": res.content_count,
                "secret_files_skipped": res.skipped_secret, "redactions": res.redactions,
            }
            manifest["repos"].append(entry)
            print(f"  - {res.repo}: {res.content_count}/{res.file_count} files copied, "
                  f"{len(res.skipped_secret)} secret files skipped, {res.redactions} redactions",
                  file=sys.stderr)
            if not args.dry_run:
                (out / "repos" / f"{res.repo}.md").write_text(res.markdown, encoding="utf-8")

    if do_sessions:
        sessions = discover_sessions(cc_root)
        print(f"[sessions] {len(sessions)} jsonl files under {cc_root}", file=sys.stderr)
        for jsonl in sessions:
            sid = jsonl.stem
            events, tallies = sanitize_session(jsonl, stats)
            manifest["sessions"].append({
                "session": sid, "source": str(jsonl), "lines": tallies["lines"],
                "events": len(events), "tools_by_name": tallies["tools_by_name"],
            })
            print(f"  - {sid}: {len(events)} events from {tallies['lines']} lines", file=sys.stderr)
            if not args.dry_run:
                (out / "sessions" / f"{sid}.md").write_text(
                    session_markdown(sid, jsonl, events, tallies), encoding="utf-8")
                (out / "sessions" / f"{sid}.json").write_text(
                    json.dumps(events_to_json(events), indent=2), encoding="utf-8")

    manifest["redaction_stats"] = stats.counts
    manifest["redaction_total"] = stats.total
    print(f"\n[redaction] {stats.total} total: {stats.counts}", file=sys.stderr)

    if not args.dry_run:
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"\n[done] staged to {out}", file=sys.stderr)
        print("NEXT: inspect before trusting. Recommended:", file=sys.stderr)
        _pat = r"sk-ant-|ghp_|github_pat_|libsql://|BEGIN .*PRIVATE KEY|eyJ"
        print(f'  grep -rInE "{_pat}" {out} || echo "clean"', file=sys.stderr)
    else:
        print("\n[dry-run] nothing written.", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
