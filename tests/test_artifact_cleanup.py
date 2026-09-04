from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trex_cli.artifacts import ArtifactStore
from trex_cli.errors import NotFound
from trex_cli.storage import SqliteStore


async def _store(
    tmp_path: Path, *, orphan_grace_period_ms: int = 86_400_000
) -> tuple[SqliteStore, ArtifactStore]:
    database = SqliteStore(tmp_path / "jobs.sqlite3")
    await database.initialize([])
    artifacts = ArtifactStore(
        tmp_path / "artifacts",
        database,
        orphan_grace_period_ms=orphan_grace_period_ms,
    )
    await artifacts.initialize()
    return database, artifacts


@pytest.mark.asyncio
async def test_cleanup_defaults_to_dry_run_and_accounts_for_missing_files(tmp_path: Path) -> None:
    database, artifacts = await _store(tmp_path)
    try:
        first = await artifacts.write("first", b"first", "text/plain")
        second = await artifacts.write("second", b"second", "text/plain")
        retained = await artifacts.write("retained", b"retained", "text/plain")
        now = datetime.now(UTC)
        database.connection.execute(
            "UPDATE artifacts SET retain_until = ? WHERE digest IN (?, ?)",
            ((now - timedelta(seconds=1)).isoformat(), first.digest, second.digest),
        )
        missing_path, _, _ = await artifacts.locate(second.digest)
        missing_path.unlink()

        preview = await artifacts.cleanup(now=now)
        assert preview.payload() == {
            "dryRun": True,
            "expiredRecords": 2,
            "deletedRecords": 0,
            "missingFiles": 0,
            "orphanFiles": 0,
            "deletedOrphans": 0,
            "reclaimedBytes": 0,
            "failures": [],
        }
        assert (await artifacts.locate(first.digest))[0].is_file()

        applied = await artifacts.cleanup(now=now, dry_run=False)
        assert applied.deleted_records == 2
        assert applied.missing_files == 1
        assert applied.reclaimed_bytes == len(b"first")
        with pytest.raises(NotFound, match="Artifact"):
            await artifacts.locate(first.digest)
        assert (await artifacts.locate(retained.digest))[0].is_file()
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_reusing_a_digest_extends_retention(tmp_path: Path) -> None:
    database, artifacts = await _store(tmp_path)
    try:
        reference = await artifacts.write("short", b"shared", "text/plain", retain_days=1)
        await artifacts.write("long", b"shared", "text/plain", retain_days=30)

        report = await artifacts.cleanup(now=datetime.now(UTC) + timedelta(days=2))

        assert report.expired_records == 0
        assert (await artifacts.locate(reference.digest))[0].is_file()
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_cleanup_keeps_registration_when_file_deletion_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, artifacts = await _store(tmp_path)
    try:
        reference = await artifacts.write("blocked", b"blocked", "text/plain")
        now = datetime.now(UTC)
        database.connection.execute(
            "UPDATE artifacts SET retain_until = ? WHERE digest = ?",
            ((now - timedelta(seconds=1)).isoformat(), reference.digest),
        )
        artifact_path, _, _ = await artifacts.locate(reference.digest)
        original_unlink = Path.unlink

        def fail_target(path: Path, *args: object, **kwargs: object) -> None:
            if path == artifact_path:
                raise OSError("injected deletion failure")
            original_unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", fail_target)
        report = await artifacts.cleanup(now=now, dry_run=False)

        assert report.deleted_records == 0
        assert report.failures and "injected deletion failure" in report.failures[0]
        assert await artifacts.locate(reference.digest)
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_orphan_cleanup_requires_explicit_apply_and_grace(tmp_path: Path) -> None:
    database, artifacts = await _store(tmp_path, orphan_grace_period_ms=1_000)
    try:
        content = b"orphan"
        digest = hashlib.sha256(content).hexdigest()
        orphan = tmp_path / "artifacts" / digest[:2] / digest
        orphan.parent.mkdir(parents=True)
        orphan.write_bytes(content)
        now = datetime.now(UTC)
        old_timestamp = (now - timedelta(seconds=2)).timestamp()
        os.utime(orphan, (old_timestamp, old_timestamp))

        preview = await artifacts.cleanup(now=now, delete_orphans=True)
        assert preview.orphan_files == 1
        assert orphan.is_file()

        retained = await artifacts.cleanup(now=now, dry_run=False)
        assert retained.deleted_orphans == 0
        assert orphan.is_file()

        applied = await artifacts.cleanup(now=now, dry_run=False, delete_orphans=True)
        assert applied.deleted_orphans == 1
        assert applied.reclaimed_bytes == len(content)
        assert not orphan.exists()
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_cleanup_never_deletes_a_registered_path_outside_artifact_root(
    tmp_path: Path,
) -> None:
    database, artifacts = await _store(tmp_path)
    try:
        content = b"outside"
        digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
        outside = tmp_path / "outside"
        outside.write_bytes(content)
        now = datetime.now(UTC)
        await database.record_artifact(
            digest,
            "text/plain",
            len(content),
            outside,
            (now - timedelta(seconds=1)).isoformat(),
        )

        report = await artifacts.cleanup(now=now, dry_run=False)

        assert report.deleted_records == 0
        assert report.failures == [f"unsafe registered path: {outside}"]
        assert outside.read_bytes() == content
        assert await artifacts.locate(digest)
    finally:
        await database.close()
