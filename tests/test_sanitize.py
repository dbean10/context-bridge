"""
test_sanitize.py — the load-bearing regression guard.

Plants known secrets in every position the sanitizer must defend, runs
sanitize.py end-to-end as a subprocess, and asserts:
  1. NO planted secret appears anywhere in the staged output (the leak scan).
  2. Secret files are skipped by name, contents never read.
  3. tool_result bodies, command args, and subagent prompts are dropped.
  4. .env.example IS copied (safe example, no real values).
  5. Known-shape secrets committed in source files ARE redacted in place.

If any of these fail, the sanitizer has regressed into a potential leak.
This test is a required CI check; a red here blocks merge.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SANITIZE = REPO_ROOT / "sanitize.py"

sys.path.insert(0, str(REPO_ROOT))
from sanitize import RedactionStats, redact  # noqa: E402

# Every distinct secret string we plant. None may appear in staged output.
PLANTED = [
    "sk-ant-api03-THISshouldNEVERappear1234567890",   # real .env value
    "sk-ant-api03-LEAKEDinsourcefileABCDEFGHIJ12345",  # key in a .py file
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",        # PAT in a .py file
    "ghp_SHOULDbeSKIPPEDcompletely12345",              # token in .git/config
    "sk-ant-api03-INCOMMANDargs999",                   # key in a gcloud arg
    "sk-ant-api03-INPROMPT123",                        # key in a subagent prompt
    "eyJhbGciOiJIUzI1NiJ9.SECRETjwtbody.signature",    # JWT in a tool_result body
    "libsql://demo-db.turso.io",                       # turso url in .env
]


def _build_fixtures(root: Path) -> tuple[Path, Path]:
    projects = root / "Projects"
    cc = root / ".claude" / "projects" / "demo"
    repo = projects / "demo-repo"
    (repo / "backend" / "app").mkdir(parents=True)
    (repo / ".git").mkdir(parents=True)
    cc.mkdir(parents=True)

    (repo / ".env").write_text(
        "ANTHROPIC_API_KEY=sk-ant-api03-THISshouldNEVERappear1234567890\n"
        "TURSO_URL=libsql://demo-db.turso.io\n"
    )
    (repo / ".env.example").write_text("ANTHROPIC_API_KEY=your-key-here\n")
    (repo / "backend" / "app" / "main.py").write_text(
        'GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"\n'
        'api_key = "sk-ant-api03-LEAKEDinsourcefileABCDEFGHIJ12345"\n'
        "def health(): return {'ok': True}\n"
    )
    (repo / "README.md").write_text("# Demo\nNormal text, nothing secret.\n")
    (repo / ".git" / "config").write_text(
        "token=ghp_SHOULDbeSKIPPEDcompletely12345\n"
    )

    lines = [
        {"timestamp": "2026-05-28T05:00:01Z", "message": {"role": "user",
         "content": [{"type": "text", "text": "deploy the api"}]}},
        {"timestamp": "2026-05-28T05:00:02Z", "message": {"role": "assistant",
         "content": [{"type": "tool_use", "name": "Bash", "input": {
             "command": "gcloud run deploy api --set-env-vars KEY=sk-ant-api03-INCOMMANDargs999"}}]}},
        {"timestamp": "2026-05-28T05:00:05Z", "message": {"role": "user",
         "content": [{"type": "tool_result", "is_error": False,
                      "content": "Service deployed. Token: eyJhbGciOiJIUzI1NiJ9.SECRETjwtbody.signature"}]}},
        {"timestamp": "2026-05-28T05:00:06Z", "message": {"role": "assistant",
         "content": [{"type": "tool_use", "name": "Task", "input": {
             "subagent_type": "engineer", "description": "impl",
             "prompt": "secret sk-ant-api03-INPROMPT123 do the work"}}]}},
        {"timestamp": "2026-05-28T05:00:09Z", "message": {"role": "assistant",
         "content": [{"type": "tool_use", "name": "Read", "input": {
             "file_path": "/Users/d/Projects/demo-repo/backend/app/db.py"}}]}},
        {"timestamp": "2026-05-28T05:00:10Z", "message": {"role": "user",
         "content": [{"type": "tool_result", "is_error": True, "content": "Permission denied"}]}},
    ]
    (cc.parent / "demo" / "sess-001.jsonl").write_text(
        "\n".join(json.dumps(x) for x in lines) + "\n"
    )
    return projects, cc.parent


def _run(projects: Path, cc_root: Path, out: Path) -> None:
    res = subprocess.run(
        [sys.executable, str(SANITIZE),
         "--projects-root", str(projects),
         "--cc-root", str(cc_root),
         "--out", str(out)],
        capture_output=True, text=True,
    )
    assert res.returncode == 0, f"sanitize.py failed: {res.stderr}"


def _all_staged_text(out: Path) -> str:
    return "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in out.rglob("*") if p.is_file()
    )


def test_no_planted_secret_leaks(tmp_path: Path) -> None:
    projects, cc_root = _build_fixtures(tmp_path / "home")
    out = tmp_path / "staged"
    _run(projects, cc_root, out)
    blob = _all_staged_text(out)
    leaked = [s for s in PLANTED if s in blob]
    assert not leaked, f"LEAK: these planted secrets appear in staged output: {leaked}"


def test_env_skipped_by_name(tmp_path: Path) -> None:
    projects, cc_root = _build_fixtures(tmp_path / "home")
    out = tmp_path / "staged"
    _run(projects, cc_root, out)
    repo_md = (out / "repos" / "demo-repo.md").read_text()
    assert ".env" in repo_md, "the .env name should be listed in the tree"
    assert "SECRET FILE" in repo_md, ".env should be flagged as a skipped secret file"


def test_env_example_is_copied(tmp_path: Path) -> None:
    projects, cc_root = _build_fixtures(tmp_path / "home")
    out = tmp_path / "staged"
    _run(projects, cc_root, out)
    repo_md = (out / "repos" / "demo-repo.md").read_text()
    assert "your-key-here" in repo_md, ".env.example is safe and should be copied"


def test_source_secrets_redacted_in_place(tmp_path: Path) -> None:
    projects, cc_root = _build_fixtures(tmp_path / "home")
    out = tmp_path / "staged"
    _run(projects, cc_root, out)
    repo_md = (out / "repos" / "demo-repo.md").read_text()
    assert "[REDACTED:GITHUB_PAT]" in repo_md
    assert "[REDACTED:ANTHROPIC_KEY]" in repo_md
    # structure preserved around the redaction
    assert "GITHUB_TOKEN =" in repo_md


def test_tool_result_bodies_dropped(tmp_path: Path) -> None:
    projects, cc_root = _build_fixtures(tmp_path / "home")
    out = tmp_path / "staged"
    _run(projects, cc_root, out)
    sess_md = (out / "sessions" / "sess-001.md").read_text()
    assert "body 84 chars [dropped]" in sess_md or "[dropped]" in sess_md
    # the subagent type survives (signal) but the prompt does not
    assert "subagent=engineer" in sess_md
    assert "prompt dropped" in sess_md
    # the read path survives (this is the signal we actually want)
    assert "db.py" in sess_md


def test_manifest_written(tmp_path: Path) -> None:
    projects, cc_root = _build_fixtures(tmp_path / "home")
    out = tmp_path / "staged"
    _run(projects, cc_root, out)
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["redaction_total"] >= 2
    assert any(r["repo"] == "demo-repo" for r in manifest["repos"])
    assert any(s["session"] == "sess-001" for s in manifest["sessions"])


# --- GENERIC_ASSIGN precision: real false positives from the live run -------
# These are code that READS secrets, env-var NAMES, and empty/placeholder
# values. None is an embedded secret; none may be redacted.
NO_REDACT_CASES = [
    'api_key = os.environ.get("OPENAI_API_KEY")',
    'auth_token=os.getenv("TURSO_TOKEN", "")',
    'secret = os.environ["INTERNAL_AUTH_TOKEN"]',
    'client = anthropic.AsyncAnthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))',
    'token = os.getenv("GITHUB_TOKEN", "")',
    "export ANTHROPIC_API_KEY=$(gcloud secrets versions access latest --secret=anthropic-key)",
    'apiKey: process.env.OPENAI_API_KEY,',
    'SECRET = ""',
    'password = ""',
    "auth_token: Deno.env.get('TURSO_TOKEN'),",
]

# These ARE embedded opaque values and MUST be redacted.
REDACT_CASES = [
    'SECRET = "a1b2c3d4e5f6g7h8i9j0"',
    'api_key = "Xk29fLp03qWZ8aB7cD4e"',
    "password = 'P4ssw0rdWithEntropy99'",
    'auth_token: "tok_9fA2bC7dE1gH4jK6mN8p"',
]


def test_generic_assign_skips_code_references() -> None:
    for case in NO_REDACT_CASES:
        stats = RedactionStats()
        out = redact(case, stats)
        assert "GENERIC_ASSIGN" not in stats.counts, f"false positive on: {case!r} -> {out!r}"
        assert out == case, f"should be unchanged: {case!r} -> {out!r}"


def test_generic_assign_catches_embedded_values() -> None:
    for case in REDACT_CASES:
        stats = RedactionStats()
        out = redact(case, stats)
        assert stats.counts.get("GENERIC_ASSIGN", 0) == 1, f"missed embedded secret: {case!r}"
        assert "[REDACTED:GENERIC_ASSIGN]" in out
        # the identifier and quotes survive; only the value is replaced
        assert "=" in out or ":" in out


def test_high_confidence_patterns_still_fire() -> None:
    # Tightening GENERIC_ASSIGN must not weaken the precise provider patterns.
    stats = RedactionStats()
    sample = (
        "key=sk-ant-api03-REALshapedKEY1234567890\n"
        "pat=ghp_REALshapedPAT1234567890abcdef\n"
        "url=libsql://prod-db-12345.turso.io\n"
    )
    out = redact(sample, stats)
    assert "sk-ant-api03-REALshapedKEY1234567890" not in out
    assert "ghp_REALshapedPAT1234567890abcdef" not in out
    assert "libsql://prod-db-12345.turso.io" not in out

