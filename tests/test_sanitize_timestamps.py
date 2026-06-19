"""Tests for step-0 manifest v2: per-session first_event_at / last_event_at
extraction, the _parse_ts helper, and the manifest_version bump.

Each case mirrors something verified against real Claude Code transcripts:

  - Primary sessions interleave timestamped conversation events with ts-less
    metadata records (ai-title, file-history-snapshot, last-prompt,
    permission-mode). The metadata must not affect first/last.
  - Subagent transcripts are all events, no metadata, no nulls.
  - Timestamps arrive as ISO-8601 with a 'Z' suffix and millisecond precision;
    the manifest must normalise them to the canonical '+00:00' / microsecond
    rendering (same form as generated_at), never lexical string compare.
  - A session with zero timestamped events yields null for both fields and
    must sort last downstream — it must not raise.

Run from the context-bridge repo root: `pytest`. Tests are hermetic (local
tmp files only, no network, no API), so they need no markers.
"""

from __future__ import annotations

import json

import pytest

from sanitize import RedactionStats, _parse_ts, main, sanitize_session

# ----------------------------------------------------------------------------
# Helpers: build minimal transcript lines in the shape sanitize_session parses
# ----------------------------------------------------------------------------

def _event_line(ts: str | None, text: str = "hello", role: str = "user") -> dict:
    """A conversation event: a message with a text content block. Produces one
    SessionEvent. `ts` may be None to simulate an event line with no stamp."""
    line: dict = {"type": role, "message": {"role": role, "content": [{"type": "text", "text": text}]}}
    if ts is not None:
        line["timestamp"] = ts
    return line


def _meta_line(record_type: str) -> dict:
    """A metadata record: a top-level type, no timestamp, no content blocks.
    Produces NO SessionEvent — matches ai-title / file-history-snapshot /
    last-prompt / permission-mode in real transcripts."""
    return {"type": record_type}


def _write(tmp_path, lines: list[dict], name: str = "session.jsonl"):
    p = tmp_path / name
    p.write_text("\n".join(json.dumps(o) for o in lines) + "\n", encoding="utf-8")
    return p


def _run(jsonl_path) -> dict:
    _events, tallies = sanitize_session(jsonl_path, RedactionStats())
    return tallies


# ----------------------------------------------------------------------------
# _parse_ts — the normalisation primitive
# ----------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw, expected_iso",
    [
        # 'Z' suffix, ms precision -> canonical '+00:00', µs precision
        ("2026-05-27T17:39:33.827Z", "2026-05-27T17:39:33.827000+00:00"),
        # already-offset form passes through
        ("2026-05-27T17:39:33.827000+00:00", "2026-05-27T17:39:33.827000+00:00"),
        # whole-second stamp: isoformat drops a zero fractional part
        ("2026-05-27T18:00:00Z", "2026-05-27T18:00:00+00:00"),
    ],
)
def test_parse_ts_canonicalises(raw, expected_iso):
    parsed = _parse_ts(raw)
    assert parsed is not None
    assert parsed.isoformat() == expected_iso


@pytest.mark.parametrize("raw", [None, "", "not-a-timestamp", 1716831573, {"t": 1}, []])
def test_parse_ts_returns_none_on_garbage(raw):
    # Anything non-string or unparseable yields None so callers skip it,
    # rather than raising and aborting a whole manifest regeneration.
    assert _parse_ts(raw) is None


# ----------------------------------------------------------------------------
# sanitize_session — the five boundary cases
# ----------------------------------------------------------------------------

def test_mixed_metadata_and_events(tmp_path):
    """Primary-session shape: ts-less metadata interleaved with events.
    Metadata must not poison min/max; only event timestamps count."""
    lines = [
        _meta_line("file-history-snapshot"),
        _event_line("2026-05-27T17:39:33.827Z"),
        _meta_line("permission-mode"),
        _event_line("2026-05-27T17:00:00.100Z"),   # earliest
        _meta_line("ai-title"),
        _event_line("2026-05-27T18:00:00.900Z"),    # latest
        _meta_line("last-prompt"),
    ]
    t = _run(_write(tmp_path, lines))
    assert t["first_event_at"] == "2026-05-27T17:00:00.100000+00:00"
    assert t["last_event_at"] == "2026-05-27T18:00:00.900000+00:00"


def test_subagent_all_events_no_nulls(tmp_path):
    """Subagent shape: every line an event, no metadata, no nulls.
    Real subagent transcripts were exactly this (e.g. 2 events)."""
    lines = [
        _event_line("2026-05-20T12:30:09.049Z", role="user"),
        _event_line("2026-05-20T12:30:11.500Z", role="assistant"),
    ]
    t = _run(_write(tmp_path, lines))
    assert t["first_event_at"] == "2026-05-20T12:30:09.049000+00:00"
    assert t["last_event_at"] == "2026-05-20T12:30:11.500000+00:00"


def test_all_metadata_yields_null(tmp_path):
    """A transcript with no timestamped events -> both fields null, no raise.
    Sorts last downstream; never masquerades as recent."""
    lines = [
        _meta_line("file-history-snapshot"),
        _meta_line("permission-mode"),
        _meta_line("ai-title"),
    ]
    t = _run(_write(tmp_path, lines))
    assert t["first_event_at"] is None
    assert t["last_event_at"] is None


def test_single_event_min_equals_max(tmp_path):
    """One event -> first_event_at == last_event_at."""
    t = _run(_write(tmp_path, [_event_line("2026-05-27T17:39:33.827Z")]))
    assert t["first_event_at"] == "2026-05-27T17:39:33.827000+00:00"
    assert t["last_event_at"] == t["first_event_at"]


def test_malformed_timestamp_is_skipped_not_fatal(tmp_path):
    """An event with an unparseable timestamp is still counted as an event,
    but excluded from the min/max. The valid events drive the result."""
    lines = [
        _event_line("2026-05-27T17:00:00.100Z"),
        _event_line("not-a-timestamp"),             # event recorded, ts ignored
        _event_line("2026-05-27T18:00:00.900Z"),
    ]
    events, tallies = sanitize_session(_write(tmp_path, lines), RedactionStats())
    assert tallies["text"] == 3                      # all three are real events
    assert tallies["first_event_at"] == "2026-05-27T17:00:00.100000+00:00"
    assert tallies["last_event_at"] == "2026-05-27T18:00:00.900000+00:00"


def test_empty_transcript_yields_null(tmp_path):
    """Zero lines -> both null, no raise."""
    t = _run(_write(tmp_path, []))
    assert t["first_event_at"] is None
    assert t["last_event_at"] is None


# ----------------------------------------------------------------------------
# Documented edge of deriving from events rather than re-scanning lines
# ----------------------------------------------------------------------------

def test_timestamped_line_without_event_block_does_not_count(tmp_path):
    """KNOWN, ACCEPTED tradeoff: first/last are derived from SessionEvents, so
    a line that carries a timestamp but produces no text/tool_use/tool_result
    event (e.g. empty content) contributes nothing. On real transcripts this
    does not occur — timestamped lines are exactly the conversation events. If
    a future transcript shape violates that, switch to tracking min/max in the
    line loop off the raw `ts` instead. This test pins current behaviour so the
    change is deliberate, not accidental."""
    line = {"type": "user", "timestamp": "2026-05-27T17:39:33.827Z",
            "message": {"role": "user", "content": []}}   # no blocks -> no event
    t = _run(_write(tmp_path, [line]))
    assert t["first_event_at"] is None
    assert t["last_event_at"] is None


def test_first_never_after_last(tmp_path):
    """Invariant across any timestamped session: first_event_at <= last_event_at."""
    lines = [_event_line(f"2026-05-27T1{i}:00:00.000Z") for i in range(5)]
    t = _run(_write(tmp_path, lines))
    assert t["first_event_at"] <= t["last_event_at"]


# ----------------------------------------------------------------------------
# main() — manifest_version bump and fields land on the entry, end to end
# ----------------------------------------------------------------------------

def test_main_writes_manifest_version_2_and_session_fields(tmp_path):
    cc = tmp_path / "cc" / "proj"
    cc.mkdir(parents=True)
    _write(cc, [
        _event_line("2026-05-27T17:00:00.100Z"),
        _event_line("2026-05-27T18:00:00.900Z"),
    ], name="abc123.jsonl")

    proj = tmp_path / "projects"   # empty; --sessions-only skips repo walk anyway
    proj.mkdir()
    out = tmp_path / "out"

    rc = main([
        "--sessions-only",
        "--cc-root", str(cc.parent),
        "--projects-root", str(proj),
        "--out", str(out),
    ])
    assert rc == 0

    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["manifest_version"] == 2

    entry = next(s for s in manifest["sessions"] if s["session"] == "abc123")
    assert entry["first_event_at"] == "2026-05-27T17:00:00.100000+00:00"
    assert entry["last_event_at"] == "2026-05-27T18:00:00.900000+00:00"
