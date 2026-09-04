from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from trex_cli import __version__
from trex_cli.async_compat import to_thread
from trex_cli.engine import ExecutionMarker
from trex_cli.errors import (
    DatabaseMigrationError,
    IdempotencyConflict,
    NotFound,
    RevisionConflict,
    TrexCliError,
)
from trex_cli.models import JobSnapshot, JobState, snapshot_json, utc_now

LATEST_SCHEMA_VERSION = 1

_SCHEMA_V1_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS jobs (
        job_id TEXT PRIMARY KEY, principal TEXT NOT NULL, idempotency_key TEXT NOT NULL,
        spec_digest TEXT NOT NULL, document_json TEXT NOT NULL, resolved_spec_json TEXT,
        kind TEXT NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL,
        snapshot_json TEXT NOT NULL, retry_of TEXT, accepted_at TEXT NOT NULL,
        retain_until TEXT NOT NULL, UNIQUE(principal, idempotency_key),
        FOREIGN KEY(retry_of) REFERENCES jobs(job_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS job_events (
        job_id TEXT NOT NULL, revision INTEGER NOT NULL, event_type TEXT NOT NULL,
        snapshot_json TEXT NOT NULL, details_json TEXT NOT NULL, created_at TEXT NOT NULL,
        PRIMARY KEY(job_id, revision), FOREIGN KEY(job_id) REFERENCES jobs(job_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS cancel_requests (
        job_id TEXT NOT NULL, request_id TEXT NOT NULL, principal TEXT NOT NULL,
        reason TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(job_id, request_id),
        FOREIGN KEY(job_id) REFERENCES jobs(job_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS port_leases (
        port_id TEXT PRIMARY KEY, job_id TEXT, generation INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'AVAILABLE', FOREIGN KEY(job_id) REFERENCES jobs(job_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS artifacts (
        digest TEXT PRIMARY KEY, media_type TEXT NOT NULL, size INTEGER NOT NULL,
        path TEXT NOT NULL, retain_until TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS execution_markers (
        marker_id TEXT PRIMARY KEY, job_id TEXT NOT NULL UNIQUE, session_id TEXT NOT NULL,
        logical_ports_json TEXT NOT NULL, fence_json TEXT NOT NULL,
        hard_deadline TEXT NOT NULL, created_at TEXT NOT NULL,
        FOREIGN KEY(job_id) REFERENCES jobs(job_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS calibrations (
        environment_key TEXT NOT NULL, tx_port TEXT NOT NULL, rx_port TEXT NOT NULL,
        direction TEXT NOT NULL, frame_size INTEGER NOT NULL,
        ceiling_percent_l1 REAL NOT NULL, counter_mode TEXT NOT NULL,
        source_job_id TEXT NOT NULL, observed_at TEXT NOT NULL,
        PRIMARY KEY(environment_key, tx_port, rx_port, direction, frame_size),
        FOREIGN KEY(source_job_id) REFERENCES jobs(job_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL, agent_version TEXT NOT NULL
    )
    """,
)

_REQUIRED_SCHEMA = {
    "jobs": {"job_id", "document_json", "snapshot_json", "retain_until"},
    "job_events": {"job_id", "revision", "snapshot_json"},
    "cancel_requests": {"job_id", "request_id"},
    "port_leases": {"port_id", "job_id", "generation", "status"},
    "artifacts": {"digest", "path", "retain_until"},
    "execution_markers": {"marker_id", "job_id", "hard_deadline"},
    "calibrations": {"environment_key", "frame_size", "source_job_id"},
    "schema_migrations": {"version", "applied_at", "agent_version"},
}


class SqliteStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._connection: sqlite3.Connection | None = None
        self._lock = threading.RLock()

    async def initialize(self, logical_ports: list[str]) -> None:
        await to_thread(self._initialize_sync, logical_ports)

    def _initialize_sync(self, logical_ports: list[str]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        existed = self._path.is_file() and self._path.stat().st_size > 0
        connection = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        backup_path: Path | None = None
        try:
            current_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current_version > LATEST_SCHEMA_VERSION:
                raise DatabaseMigrationError(
                    f"database schema v{current_version} is newer than supported "
                    f"v{LATEST_SCHEMA_VERSION}",
                    details={"currentVersion": current_version, "supportedVersion": 1},
                )
            if current_version < LATEST_SCHEMA_VERSION:
                if existed:
                    backup_path = self._backup(connection, current_version)
                self._migrate_to_v1(connection)
            self._validate_schema(connection)
        except DatabaseMigrationError as error:
            if backup_path is not None:
                error.details.setdefault("backupPath", str(backup_path))
            connection.close()
            raise
        except Exception as error:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            connection.close()
            details = {"cause": str(error)}
            if backup_path is not None:
                details["backupPath"] = str(backup_path)
            raise DatabaseMigrationError(
                "database migration failed; the pre-migration backup was preserved",
                details=details,
            ) from error
        for port in logical_ports:
            connection.execute("INSERT OR IGNORE INTO port_leases(port_id) VALUES (?)", (port,))
        configured = set(logical_ports)
        existing = {
            str(row["port_id"])
            for row in connection.execute("SELECT port_id FROM port_leases").fetchall()
        }
        stale_query = (
            "SELECT port_id FROM port_leases WHERE port_id NOT IN ({}) AND job_id IS NOT NULL"
        ).format(",".join("?" for _ in configured) or "NULL")
        stale_busy = connection.execute(
            stale_query,
            tuple(configured),
        ).fetchall()
        if stale_busy:
            ports = ", ".join(str(row["port_id"]) for row in stale_busy)
            connection.close()
            raise RuntimeError(f"removed logical ports still have leases: {ports}")
        for stale in existing - configured:
            connection.execute("DELETE FROM port_leases WHERE port_id = ?", (stale,))
        self._connection = connection

    def _backup(self, source: sqlite3.Connection, current_version: int) -> Path:
        timestamp = utc_now().strftime("%Y%m%dT%H%M%S%fZ")
        path = self._path.with_name(f"{self._path.name}.backup-v{current_version}-{timestamp}")
        backup = sqlite3.connect(path)
        try:
            source.backup(backup)
        finally:
            backup.close()
        return path

    @staticmethod
    def _migrate_to_v1(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")
        try:
            for statement in _SCHEMA_V1_STATEMENTS:
                connection.execute(statement)
            SqliteStore._validate_schema(connection)
            connection.execute(
                "INSERT OR REPLACE INTO schema_migrations VALUES (?, ?, ?)",
                (1, utc_now().isoformat(), __version__),
            )
            connection.execute(f"PRAGMA user_version = {LATEST_SCHEMA_VERSION}")
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        for table, required_columns in _REQUIRED_SCHEMA.items():
            columns = {
                str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            }
            missing = required_columns - columns
            if missing:
                raise DatabaseMigrationError(
                    f"database table {table} is incompatible; missing columns: "
                    + ", ".join(sorted(missing))
                )

    async def close(self) -> None:
        await to_thread(self._close_sync)

    def _close_sync(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    @property
    def connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("store is not initialized")
        return self._connection

    async def schema_version(self) -> int:
        return await to_thread(self._schema_version_sync)

    def _schema_version_sync(self) -> int:
        with self._lock:
            return int(self.connection.execute("PRAGMA user_version").fetchone()[0])

    async def observation_counts(self) -> tuple[dict[str, int], int, int]:
        return await to_thread(self._observation_counts_sync)

    def _observation_counts_sync(self) -> tuple[dict[str, int], int, int]:
        with self._lock:
            states = {
                str(row["state"]): int(row["count"])
                for row in self.connection.execute(
                    "SELECT state, COUNT(*) AS count FROM jobs GROUP BY state"
                ).fetchall()
            }
            artifact = self.connection.execute(
                "SELECT COUNT(*) AS count, COALESCE(SUM(size), 0) AS bytes FROM artifacts"
            ).fetchone()
            return states, int(artifact["count"]), int(artifact["bytes"])

    async def create_job(
        self,
        *,
        snapshot: JobSnapshot,
        principal: str,
        idempotency_key: str,
        document_json: str,
        retry_of: str | None,
    ) -> tuple[JobSnapshot, bool]:
        return await to_thread(
            self._create_job_sync,
            snapshot,
            principal,
            idempotency_key,
            document_json,
            retry_of,
        )

    def _create_job_sync(
        self,
        snapshot: JobSnapshot,
        principal: str,
        idempotency_key: str,
        document_json: str,
        retry_of: str | None,
    ) -> tuple[JobSnapshot, bool]:
        with self._lock:
            connection = self.connection
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "SELECT spec_digest, snapshot_json FROM jobs "
                    "WHERE principal = ? AND idempotency_key = ?",
                    (principal, idempotency_key),
                ).fetchone()
                if existing is not None:
                    if str(existing["spec_digest"]) != snapshot.submitted_spec_digest:
                        raise IdempotencyConflict()
                    connection.execute("COMMIT")
                    return JobSnapshot.model_validate_json(existing["snapshot_json"]), False

                if retry_of is not None:
                    retried = connection.execute(
                        "SELECT state, spec_digest FROM jobs WHERE job_id = ?", (retry_of,)
                    ).fetchone()
                    if retried is None:
                        raise NotFound(f"retry Job {retry_of}")
                    if not JobState(str(retried["state"])).terminal:
                        raise TrexCliError(
                            code="INVALID_DOCUMENT",
                            message="retryOf must reference a terminal Job",
                            category="INPUT",
                        )
                    if str(retried["spec_digest"]) != snapshot.submitted_spec_digest:
                        raise TrexCliError(
                            code="INVALID_DOCUMENT",
                            message="retryOf must reference a Job with the same spec digest",
                            category="INPUT",
                        )

                now = utc_now()
                retain_until = now + timedelta(days=30)
                encoded = snapshot_json(snapshot)
                connection.execute(
                    """
                    INSERT INTO jobs(
                        job_id, principal, idempotency_key, spec_digest, document_json,
                        kind, state, revision, snapshot_json, retry_of, accepted_at, retain_until
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot.job_id,
                        principal,
                        idempotency_key,
                        snapshot.submitted_spec_digest,
                        document_json,
                        snapshot.kind,
                        snapshot.state,
                        snapshot.revision,
                        encoded,
                        retry_of,
                        snapshot.submitted_at.isoformat(),
                        retain_until.isoformat(),
                    ),
                )
                connection.execute(
                    "INSERT INTO job_events VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        snapshot.job_id,
                        snapshot.revision,
                        "JOB_ACCEPTED",
                        encoded,
                        "{}",
                        now.isoformat(),
                    ),
                )
                connection.execute("COMMIT")
                return snapshot, True
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    async def get_snapshot(self, job_id: str) -> JobSnapshot:
        return await to_thread(self._get_snapshot_sync, job_id)

    def _get_snapshot_sync(self, job_id: str) -> JobSnapshot:
        with self._lock:
            row = self.connection.execute(
                "SELECT snapshot_json FROM jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            if row is None:
                raise NotFound(f"Job {job_id}")
            return JobSnapshot.model_validate_json(row["snapshot_json"])

    async def get_document_json(self, job_id: str) -> str:
        return await to_thread(self._get_document_json_sync, job_id)

    def _get_document_json_sync(self, job_id: str) -> str:
        with self._lock:
            row = self.connection.execute(
                "SELECT document_json FROM jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            if row is None:
                raise NotFound(f"Job {job_id}")
            return str(row["document_json"])

    async def save_execution_marker(self, marker: ExecutionMarker) -> None:
        await to_thread(self._save_execution_marker_sync, marker)

    def _save_execution_marker_sync(self, marker: ExecutionMarker) -> None:
        with self._lock:
            self.connection.execute(
                """
                INSERT INTO execution_markers(
                    marker_id, job_id, session_id, logical_ports_json, fence_json,
                    hard_deadline, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    marker_id = excluded.marker_id,
                    session_id = excluded.session_id,
                    logical_ports_json = excluded.logical_ports_json,
                    fence_json = excluded.fence_json,
                    hard_deadline = excluded.hard_deadline,
                    created_at = excluded.created_at
                """,
                (
                    marker.marker_id,
                    marker.job_id,
                    marker.session_id,
                    json.dumps(marker.logical_ports),
                    json.dumps(marker.fence, sort_keys=True),
                    marker.hard_deadline.isoformat(),
                    utc_now().isoformat(),
                ),
            )

    async def get_execution_marker(self, job_id: str) -> ExecutionMarker | None:
        return await to_thread(self._get_execution_marker_sync, job_id)

    def _get_execution_marker_sync(self, job_id: str) -> ExecutionMarker | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT * FROM execution_markers WHERE job_id = ?", (job_id,)
            ).fetchone()
            if row is None:
                return None
            return self._execution_marker(row)

    async def list_execution_markers(self) -> list[ExecutionMarker]:
        return await to_thread(self._list_execution_markers_sync)

    def _list_execution_markers_sync(self) -> list[ExecutionMarker]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT * FROM execution_markers ORDER BY created_at, marker_id"
            ).fetchall()
            return [self._execution_marker(row) for row in rows]

    @staticmethod
    def _execution_marker(row: sqlite3.Row) -> ExecutionMarker:
        return ExecutionMarker(
            marker_id=str(row["marker_id"]),
            job_id=str(row["job_id"]),
            session_id=str(row["session_id"]),
            logical_ports=tuple(json.loads(row["logical_ports_json"])),
            fence={str(key): int(value) for key, value in json.loads(row["fence_json"]).items()},
            hard_deadline=datetime.fromisoformat(str(row["hard_deadline"])),
        )

    async def delete_execution_marker(self, job_id: str) -> None:
        await to_thread(self._delete_execution_marker_sync, job_id)

    def _delete_execution_marker_sync(self, job_id: str) -> None:
        with self._lock:
            self.connection.execute("DELETE FROM execution_markers WHERE job_id = ?", (job_id,))

    async def update_snapshot(
        self,
        snapshot: JobSnapshot,
        *,
        expected_revision: int,
        event_type: str,
        details: dict[str, Any] | None = None,
        resolved_spec_json: str | None = None,
    ) -> None:
        await to_thread(
            self._update_snapshot_sync,
            snapshot,
            expected_revision,
            event_type,
            details or {},
            resolved_spec_json,
        )

    def _update_snapshot_sync(
        self,
        snapshot: JobSnapshot,
        expected_revision: int,
        event_type: str,
        details: dict[str, Any],
        resolved_spec_json: str | None,
    ) -> None:
        with self._lock:
            connection = self.connection
            connection.execute("BEGIN IMMEDIATE")
            try:
                encoded = snapshot_json(snapshot)
                result = connection.execute(
                    """
                    UPDATE jobs
                    SET state = ?, revision = ?, snapshot_json = ?,
                        resolved_spec_json = COALESCE(?, resolved_spec_json)
                    WHERE job_id = ? AND revision = ?
                    """,
                    (
                        snapshot.state,
                        snapshot.revision,
                        encoded,
                        resolved_spec_json,
                        snapshot.job_id,
                        expected_revision,
                    ),
                )
                if result.rowcount != 1:
                    raise RevisionConflict()
                connection.execute(
                    "INSERT INTO job_events VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        snapshot.job_id,
                        snapshot.revision,
                        event_type,
                        encoded,
                        json.dumps(details, sort_keys=True, separators=(",", ":")),
                        utc_now().isoformat(),
                    ),
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    async def request_cancel(
        self,
        job_id: str,
        request_id: str,
        principal: str,
        reason: str,
    ) -> JobSnapshot:
        return await to_thread(self._request_cancel_sync, job_id, request_id, principal, reason)

    def _request_cancel_sync(
        self, job_id: str, request_id: str, principal: str, reason: str
    ) -> JobSnapshot:
        with self._lock:
            connection = self.connection
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT snapshot_json FROM jobs WHERE job_id = ?", (job_id,)
                ).fetchone()
                if row is None:
                    raise NotFound(f"Job {job_id}")
                snapshot = JobSnapshot.model_validate_json(row["snapshot_json"])
                existing = connection.execute(
                    "SELECT 1 FROM cancel_requests WHERE job_id = ? AND request_id = ?",
                    (job_id, request_id),
                ).fetchone()
                if existing is not None or snapshot.state.terminal:
                    connection.execute("COMMIT")
                    return snapshot
                connection.execute(
                    "INSERT INTO cancel_requests VALUES (?, ?, ?, ?, ?)",
                    (job_id, request_id, principal, reason, utc_now().isoformat()),
                )
                updated = snapshot.model_copy(
                    update={"revision": snapshot.revision + 1, "cancel_requested": True}
                )
                encoded = snapshot_json(updated)
                connection.execute(
                    "UPDATE jobs SET revision = ?, snapshot_json = ? WHERE job_id = ?",
                    (updated.revision, encoded, job_id),
                )
                connection.execute(
                    "INSERT INTO job_events VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        job_id,
                        updated.revision,
                        "CANCEL_REQUESTED",
                        encoded,
                        json.dumps({"principal": principal, "reason": reason}),
                        utc_now().isoformat(),
                    ),
                )
                connection.execute("COMMIT")
                return updated
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    async def events_after(self, job_id: str, revision: int) -> list[JobSnapshot]:
        return await to_thread(self._events_after_sync, job_id, revision)

    def _events_after_sync(self, job_id: str, revision: int) -> list[JobSnapshot]:
        with self._lock:
            exists = self.connection.execute(
                "SELECT 1 FROM jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            if exists is None:
                raise NotFound(f"Job {job_id}")
            rows = self.connection.execute(
                "SELECT snapshot_json FROM job_events "
                "WHERE job_id = ? AND revision > ? ORDER BY revision",
                (job_id, revision),
            ).fetchall()
            return [JobSnapshot.model_validate_json(row["snapshot_json"]) for row in rows]

    async def list_nonterminal(self) -> list[JobSnapshot]:
        return await to_thread(self._list_nonterminal_sync)

    def _list_nonterminal_sync(self) -> list[JobSnapshot]:
        terminal = (JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED)
        with self._lock:
            query = (
                "SELECT snapshot_json FROM jobs "
                "WHERE state NOT IN (?, ?, ?) ORDER BY accepted_at, job_id"
            )
            rows = self.connection.execute(query, terminal).fetchall()
            return [JobSnapshot.model_validate_json(row["snapshot_json"]) for row in rows]

    async def acquire_ports(self, job_id: str, ports: Iterable[str]) -> dict[str, int] | None:
        return await to_thread(self._acquire_ports_sync, job_id, tuple(sorted(set(ports))))

    def _acquire_ports_sync(self, job_id: str, ports: tuple[str, ...]) -> dict[str, int] | None:
        with self._lock:
            connection = self.connection
            connection.execute("BEGIN IMMEDIATE")
            try:
                placeholders = ",".join("?" for _ in ports)
                rows = connection.execute(
                    f"SELECT * FROM port_leases WHERE port_id IN ({placeholders})",
                    ports,
                ).fetchall()
                if len(rows) != len(ports):
                    raise TrexCliError(
                        code="CAPABILITY_MISMATCH",
                        message="one or more logical ports are not configured",
                        category="RESOURCE",
                    )
                if any(row["status"] == "QUARANTINED" for row in rows):
                    raise TrexCliError(
                        code="CAPABILITY_MISMATCH",
                        message="one or more logical ports are quarantined",
                        category="RESOURCE",
                    )
                if any(row["job_id"] not in (None, job_id) for row in rows):
                    connection.execute("COMMIT")
                    return None
                generations: dict[str, int] = {}
                for row in rows:
                    generation = int(row["generation"])
                    if row["job_id"] is None:
                        generation += 1
                        connection.execute(
                            "UPDATE port_leases SET job_id = ?, generation = ?, status = 'LEASED' "
                            "WHERE port_id = ?",
                            (job_id, generation, row["port_id"]),
                        )
                    generations[str(row["port_id"])] = generation
                connection.execute("COMMIT")
                return generations
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    async def release_ports(self, job_id: str, *, quarantine: bool = False) -> None:
        await to_thread(self._release_ports_sync, job_id, quarantine)

    def _release_ports_sync(self, job_id: str, quarantine: bool) -> None:
        with self._lock:
            status = "QUARANTINED" if quarantine else "AVAILABLE"
            self.connection.execute(
                "UPDATE port_leases SET job_id = NULL, status = ? WHERE job_id = ?",
                (status, job_id),
            )

    async def confirm_ports_available(self, ports: Iterable[str]) -> None:
        await to_thread(self._confirm_ports_available_sync, tuple(sorted(set(ports))))

    def _confirm_ports_available_sync(self, ports: tuple[str, ...]) -> None:
        if not ports:
            return
        with self._lock:
            placeholders = ",".join("?" for _ in ports)
            self.connection.execute(
                f"UPDATE port_leases SET job_id = NULL, status = 'AVAILABLE' "
                f"WHERE port_id IN ({placeholders})",
                ports,
            )

    async def port_statuses(self) -> dict[str, dict[str, Any]]:
        return await to_thread(self._port_statuses_sync)

    def _port_statuses_sync(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT port_id, job_id, generation, status FROM port_leases ORDER BY port_id"
            ).fetchall()
            return {
                str(row["port_id"]): {
                    "status": str(row["status"]),
                    "generation": int(row["generation"]),
                    "jobId": row["job_id"],
                }
                for row in rows
            }

    async def record_artifact(
        self, digest: str, media_type: str, size: int, path: Path, retain_until: str
    ) -> None:
        await to_thread(self._record_artifact_sync, digest, media_type, size, path, retain_until)

    def _record_artifact_sync(
        self, digest: str, media_type: str, size: int, path: Path, retain_until: str
    ) -> None:
        with self._lock:
            connection = self.connection
            existing = connection.execute(
                "SELECT media_type, size, path FROM artifacts WHERE digest = ?", (digest,)
            ).fetchone()
            if existing is not None and (
                str(existing["media_type"]) != media_type
                or int(existing["size"]) != size
                or str(existing["path"]) != str(path)
            ):
                raise RuntimeError("Artifact metadata does not match its existing digest")
            connection.execute(
                """
                INSERT INTO artifacts VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(digest) DO UPDATE SET
                    retain_until = MAX(artifacts.retain_until, excluded.retain_until)
                """,
                (digest, media_type, size, str(path), retain_until),
            )

    async def record_calibration(
        self,
        *,
        environment_key: str,
        tx_port: str,
        rx_port: str,
        direction: str,
        frame_size: int,
        ceiling_percent_l1: float,
        counter_mode: str,
        source_job_id: str,
        observed_at: str,
    ) -> None:
        await to_thread(
            self._record_calibration_sync,
            environment_key,
            tx_port,
            rx_port,
            direction,
            frame_size,
            ceiling_percent_l1,
            counter_mode,
            source_job_id,
            observed_at,
        )

    def _record_calibration_sync(
        self,
        environment_key: str,
        tx_port: str,
        rx_port: str,
        direction: str,
        frame_size: int,
        ceiling_percent_l1: float,
        counter_mode: str,
        source_job_id: str,
        observed_at: str,
    ) -> None:
        with self._lock:
            self.connection.execute(
                """
                INSERT INTO calibrations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(environment_key, tx_port, rx_port, direction, frame_size)
                DO UPDATE SET
                    ceiling_percent_l1 = excluded.ceiling_percent_l1,
                    counter_mode = excluded.counter_mode,
                    source_job_id = excluded.source_job_id,
                    observed_at = excluded.observed_at
                WHERE excluded.ceiling_percent_l1 > calibrations.ceiling_percent_l1
                """,
                (
                    environment_key,
                    tx_port,
                    rx_port,
                    direction,
                    frame_size,
                    ceiling_percent_l1,
                    counter_mode,
                    source_job_id,
                    observed_at,
                ),
            )

    async def get_calibrations(
        self,
        *,
        environment_key: str,
        tx_port: str,
        rx_port: str,
        direction: str,
    ) -> dict[int, dict[str, Any]]:
        return await to_thread(
            self._get_calibrations_sync,
            environment_key,
            tx_port,
            rx_port,
            direction,
        )

    def _get_calibrations_sync(
        self, environment_key: str, tx_port: str, rx_port: str, direction: str
    ) -> dict[int, dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute(
                """
                SELECT frame_size, ceiling_percent_l1, counter_mode,
                       source_job_id, observed_at
                FROM calibrations
                WHERE environment_key = ? AND tx_port = ? AND rx_port = ? AND direction = ?
                """,
                (environment_key, tx_port, rx_port, direction),
            ).fetchall()
            return {
                int(row["frame_size"]): {
                    "ceilingPercentL1": float(row["ceiling_percent_l1"]),
                    "counterMode": str(row["counter_mode"]),
                    "sourceJobId": str(row["source_job_id"]),
                    "observedAt": str(row["observed_at"]),
                }
                for row in rows
            }

    async def list_calibrations(self) -> list[dict[str, Any]]:
        return await to_thread(self._list_calibrations_sync)

    def _list_calibrations_sync(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute(
                """
                SELECT environment_key, tx_port, rx_port, direction, frame_size,
                       ceiling_percent_l1, counter_mode, source_job_id, observed_at
                FROM calibrations
                ORDER BY environment_key, tx_port, rx_port, direction, frame_size
                """
            ).fetchall()
            return [
                {
                    "environmentKey": str(row["environment_key"]),
                    "txPort": str(row["tx_port"]),
                    "rxPort": str(row["rx_port"]),
                    "direction": str(row["direction"]),
                    "frameSize": int(row["frame_size"]),
                    "ceilingPercentL1": float(row["ceiling_percent_l1"]),
                    "counterMode": str(row["counter_mode"]),
                    "sourceJobId": str(row["source_job_id"]),
                    "observedAt": str(row["observed_at"]),
                }
                for row in rows
            ]

    async def artifact_path(self, digest: str) -> tuple[Path, str, int]:
        return await to_thread(self._artifact_path_sync, digest)

    def _artifact_path_sync(self, digest: str) -> tuple[Path, str, int]:
        with self._lock:
            row = self.connection.execute(
                "SELECT path, media_type, size FROM artifacts WHERE digest = ?", (digest,)
            ).fetchone()
            if row is None:
                raise NotFound(f"Artifact {digest}")
            return Path(str(row["path"])), str(row["media_type"]), int(row["size"])

    async def expired_artifacts(self, now_iso: str) -> list[tuple[str, Path, int]]:
        return await to_thread(self._expired_artifacts_sync, now_iso)

    def _expired_artifacts_sync(self, now_iso: str) -> list[tuple[str, Path, int]]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT digest, path, size FROM artifacts WHERE retain_until < ? "
                "ORDER BY digest",
                (now_iso,),
            ).fetchall()
            return [
                (str(row["digest"]), Path(str(row["path"])), int(row["size"])) for row in rows
            ]

    async def forget_expired_artifact(self, digest: str, now_iso: str) -> bool:
        return await to_thread(self._forget_expired_artifact_sync, digest, now_iso)

    def _forget_expired_artifact_sync(self, digest: str, now_iso: str) -> bool:
        with self._lock:
            result = self.connection.execute(
                "DELETE FROM artifacts WHERE digest = ? AND retain_until < ?",
                (digest, now_iso),
            )
            return result.rowcount == 1

    async def registered_artifact_paths(self) -> set[Path]:
        return await to_thread(self._registered_artifact_paths_sync)

    def _registered_artifact_paths_sync(self) -> set[Path]:
        with self._lock:
            rows = self.connection.execute("SELECT path FROM artifacts").fetchall()
            return {Path(str(row["path"])) for row in rows}
