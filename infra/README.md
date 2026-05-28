# infra/

GCS bucket + IAM setup for the context bridge store. Built in the next pass.

Planned (`setup-gcs.sh`, idempotent, in project `doc-qa-learn`):
- Private bucket, uniform bucket-level access (no per-object ACLs)
- Lifecycle rule: auto-delete objects after ~30 days (matches CC retention)
- Service account for the Cloud Run MCP server with read-only access
- `verify.sh` — configured = enforcing gate (run the failing case)
