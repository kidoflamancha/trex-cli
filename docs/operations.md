# trex-cli operations

## Database upgrades and recovery

The Agent owns one SQLite database and supports schema version 1. `PRAGMA user_version` is the
machine-readable version; `schema_migrations` records the applied version, timestamp, and Agent
version. A healthy `/readyz` response includes `databaseSchemaVersion`.

Startup upgrades an unversioned 0.x database as follows:

1. Open the database with foreign keys and WAL enabled.
2. Create an online SQLite backup beside the database, named
   `<database>.backup-v0-<UTC timestamp>`.
3. Apply the migration and validate every required table and key column in one transaction.
4. Record the migration and set `PRAGMA user_version=1` only after validation succeeds.

New empty databases do not need a backup. A database created by a newer schema is never
downgraded. Migration failure rolls back the transaction and preserves both the original database
and backup. The process stays alive for diagnostics: `/healthz` returns 200, `/readyz` returns 503
with `DATABASE_MIGRATION_FAILED` and the backup path, and authenticated work endpoints return
`AGENT_NOT_READY`.

### Recovery procedure

Stop the Agent before replacing a database. Keep the failed database rather than deleting it, then
validate the backup:

```bash
sqlite3 /path/to/jobs.sqlite3.backup-v0-<timestamp> 'PRAGMA quick_check; PRAGMA user_version;'
```

`quick_check` must return `ok`. Move the failed database and its `-wal`/`-shm` sidecars to an
incident directory. Restore through SQLite rather than copying a live WAL database:

```bash
sqlite3 /path/to/jobs.sqlite3.backup-v0-<timestamp> \
  '.backup /path/to/restored-jobs.sqlite3'
```

Point `databasePath` at the restored file. Start the previous known-good wheel if the migration
code itself is under investigation; otherwise restart the new wheel and confirm `/readyz` reports
`databaseSchemaVersion: 1`. Preserve the incident directory until Job and Artifact counts have
been reconciled.

## Artifact retention and cleanup

Artifacts are content-addressed files below `artifactRoot`. `artifactRetentionDays` controls the
default retention period from the most recent write of a digest; reusing identical content extends
the existing deadline and never shortens it. The Agent does not run cleanup automatically. Schedule
the operator command only after its dry-run output has been reviewed:

```bash
trex-cli artifact cleanup --output json
trex-cli artifact cleanup --apply --yes --output json
```

The first command is always non-destructive. The apply command deletes an expired file before
removing its database registration. If filesystem deletion fails, the registration remains and the
CLI exits with status 3 so an operator can correct permissions or storage health and retry. A
`missingFiles` count means an expired registration pointed at an already absent file; it is removed
without adding its declared size to `reclaimedBytes`.

Normal cleanup never deletes unregistered files. To inspect and then delete orphans, use:

```bash
trex-cli artifact cleanup --delete-orphans --output json
trex-cli artifact cleanup --apply --delete-orphans --yes --output json
```

Only files in the exact `<artifactRoot>/<first two hex>/<64 hex digest>` layout are candidates.
They must also be older than `artifactOrphanGracePeriod` (24 hours by default), which protects an
in-progress atomic write. Files outside that layout are left untouched. All cleanup requests require
an operator token; read-only tokens receive `PERMISSION_DENIED`.

For unattended operation, capture every JSON report in the scheduler log and alert when `failures`
is non-empty. Run a dry-run first, then an apply using the same deployment window. Concurrent
Artifact writes and cleanup are serialized inside one Agent process, consistent with the supported
single-process deployment model.

## Structured logs and runtime metrics

`trex-agent` writes one JSON object per line to stderr. Configure the minimum severity with
`logLevel` (`DEBUG`, `INFO`, `WARNING`, or `ERROR`; default `INFO`). Normal responses and handled API
errors include an `X-Request-ID`. A caller-supplied ID is retained only when it contains at most 128
ASCII letters, digits, dots, underscores, colons, or hyphens; otherwise the Agent generates one.
HTTP log records carry that `requestId`, the matched route template, status code and duration. Job
records carry the `jobId`, kind, previous/current state, event type and revision. Logs never include
Bearer Tokens, submitted documents or packet payloads.

The authenticated Prometheus text endpoint accepts either a reader or operator token:

```bash
curl -fsS -H "Authorization: Bearer $TREX_READER_TOKEN" \
  http://127.0.0.1:8080/metrics
```

Metrics include current persistent Jobs by state, logical ports by status, registered Artifact count
and declared bytes, last engine availability, process start time, HTTP request count/latency, Job
state transitions, and Artifact cleanup outcomes. Process counters reset on Agent restart; Job,
port, and Artifact gauges are rebuilt from SQLite on every scrape. Labels deliberately use bounded
route templates and enum-like states—never request paths, Job IDs, digests, principals, or errors.

Recommended initial alerts are:

- `/readyz` is non-200 or `trex_agent_engine_available` is 0 for two consecutive probes;
- `trex_agent_logical_ports{status="QUARANTINED"}` is greater than 0;
- the increase of failed terminal Job transitions is nonzero;
- `trex_agent_artifact_cleanup_runs_total{outcome="failed"}` increases;
- Artifact bytes approach the filesystem capacity or no successful cleanup occurs in the expected
  maintenance interval.

Keep `/metrics` behind the same private network or TLS reverse proxy as the API. A Prometheus scrape
configuration must send a reader token through an authorization header; use a dedicated read-only
principal so it can be rotated independently from operator credentials.

## TLS deployment

For native TLS, configure certificate paths and start the Agent normally:

```yaml
bindHost: 10.0.0.10
bindPort: 8443
tls:
  certFile: /etc/trex-agent/tls/server.crt
  keyFile: /etc/trex-agent/tls/server.key
  # Optional mutual TLS:
  clientCaFile: /etc/trex-agent/tls/clients-ca.crt
  requireClientCertificate: true
```

When `requireClientCertificate` is true, `clientCaFile` is mandatory. `/readyz` and `/version`
report `transportSecurity: tls`. Protect the private key with filesystem permissions and run the
service as a dedicated account. Certificate issuance, renewal, and trust policy remain deployment
responsibilities.

The recommended alternative is to bind the Agent to `127.0.0.1`, terminate TLS at a maintained
reverse proxy, and firewall the clear-text loopback port. An Nginx starting point is provided at
`deploy/nginx/trex-agent.conf`; it preserves authorization and request correlation headers and
disables buffering for SSE and large capture uploads. The Agent correctly continues to describe its
own hop as `insecure-http`; do not interpret that field as the proxy's external transport status.

## File tokens and online rotation

Environment-backed tokens remain supported for simple deployments. For online rotation, configure
two operator slots backed by private files:

```yaml
auth:
  tokens:
    - {name: operator-a, role: operator, file: /etc/trex-agent/secrets/operator-a}
    - {name: operator-b, role: operator, file: /etc/trex-agent/secrets/operator-b}
    - {name: metrics, role: read-only, file: /etc/trex-agent/secrets/metrics}
```

Each file must be a regular file accessible only by its owner (`0600`) and contain exactly one
non-empty token line. The Agent immediately hashes the value and retains only its SHA-256 digest in
memory. File paths are fixed by the loaded configuration; credential reload rereads their contents,
not the YAML structure.

Rotate without interrupting active tests:

1. Generate a strong value into a `0600` temporary file without placing it in shell history.
2. Atomically replace the inactive slot file with that temporary file.
3. While authenticated with the active slot, run `trex-cli auth reload`.
4. Verify `/version` and `/metrics` using the new inactive-slot token.
5. Replace the former active slot with a new random value and reload using the newly verified slot.
6. Confirm the retired token returns `UNAUTHENTICATED`, then update secret escrow and automation.

Reload constructs the complete credential set before swapping it into service. A missing,
world/group-readable, empty, or invalid UTF-8 file returns `CREDENTIAL_RELOAD_FAILED`, leaves every
previous credential active, and emits an audit record. Adding or removing credential slots requires
a controlled Agent restart because it changes the configuration structure.

## systemd installation

The template at `deploy/systemd/trex-agent.service` assumes a wheel virtual environment at
`/opt/trex-agent/venv`, configuration under `/etc/trex-agent`, and writable state under
`/var/lib/trex-agent`. Copy it to `/etc/systemd/system`, adjust read-only paths needed by the TRex
client installation, then enable it. The unit fixes one worker, applies a private umask, removes
capabilities, restricts writable paths, and grants five minutes for graceful shutdown. Always test
stop/restart reconciliation against the actual remote TRex timeout before production rollout.

The version and migration rules used for upgrades and rollback are documented in
`docs/compatibility.md`.
