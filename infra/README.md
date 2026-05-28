# infra/

GCS store provisioning for the context bridge. Config lives in `infra/.env`
(gitignored); copy `infra/.env.example` and fill in real values first.

## Scripts

- **`setup-gcs.sh`** — idempotent. Creates a private bucket (uniform
  bucket-level access + public access prevention enforced), attaches a
  lifecycle rule (auto-delete after `LIFECYCLE_DAYS`), and creates a read-only
  service account with `objectViewer` scoped to the bucket only. Safe to re-run.
  `--dry-run` prints intended actions without changing anything.

- **`verify.sh`** — the configured≠enforcing gate. Reads live GCP state and
  asserts the dangerous states are impossible: public access prevention
  enforced, uniform access on, NO `allUsers`/`allAuthenticatedUsers` in the
  bucket IAM, lifecycle Delete rule present at the right age, reader SA holds
  objectViewer. Exits non-zero on any failure. Run after every `setup-gcs.sh`.

## Order

```bash
cd infra
cp .env.example .env        # fill in PROJECT, BUCKET, REGION, etc.
./setup-gcs.sh              # provision (idempotent)
./verify.sh                 # prove private + scoped + expiring

# then sync sanitized output (outbound only):
gcloud storage rsync -r -d ~/.context-bridge/staged gs://$BUCKET
```

The bucket is multi-project by design — it holds sanitized snapshots for every
project under `~/Projects`, not one bucket per product.
