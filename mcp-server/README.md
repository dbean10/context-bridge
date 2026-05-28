# mcp-server/

FastMCP read-only server, deployed to Cloud Run. Reads the private GCS bucket
and exposes structured tools to the claude.ai chat (registered as a connector):

- list_repo_snapshots() / read_repo_snapshot(repo, path)
- list_sessions() / read_session_summary(session_id)
- git_state(repo)

Runs on Cloud Run, NOT on the Mac — no local exposure. Serves only
pre-sanitized data, so its blast radius is bounded even if auth were weak.
Built after the sanitizer is proven on real data and the GCS store exists.
