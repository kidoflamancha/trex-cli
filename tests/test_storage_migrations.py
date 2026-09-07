import sqlite3
from pathlib import Path

import pytest

from trex_cli.errors import DatabaseMigrationError
from trex_cli.storage import LATEST_SCHEMA_VERSION, SqliteStore


@pytest.mark.asyncio
async def test_unversioned_database_is_backed_up_and_migrated_without_data_loss(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "jobs.sqlite3"
    original = SqliteStore(database_path)
    await original.initialize(["lab-west", "lab-east"])
    original.connection.execute(
        "UPDATE port_leases SET generation = 7 WHERE port_id = 'lab-west'"
    )
    await original.close()
    legacy = sqlite3.connect(database_path)
    legacy.execute("DROP TABLE schema_migrations")
    legacy.execute("PRAGMA user_version = 0")
    legacy.close()

    upgraded = SqliteStore(database_path)
    await upgraded.initialize(["lab-west", "lab-east"])
    try:
        assert upgraded.connection.execute("PRAGMA user_version").fetchone()[0] == 1
        migration = upgraded.connection.execute(
            "SELECT version, agent_version FROM schema_migrations"
        ).fetchone()
        assert tuple(migration) == (LATEST_SCHEMA_VERSION, "1.0.1")
        assert (await upgraded.port_statuses())["lab-west"]["generation"] == 7
    finally:
        await upgraded.close()

    backups = list(tmp_path.glob("jobs.sqlite3.backup-v0-*"))  # noqa: ASYNC240
    assert len(backups) == 1
    backup = sqlite3.connect(backups[0])
    try:
        assert backup.execute("PRAGMA user_version").fetchone()[0] == 0
        assert backup.execute(
            "SELECT generation FROM port_leases WHERE port_id = 'lab-west'"
        ).fetchone()[0] == 7
    finally:
        backup.close()


@pytest.mark.asyncio
async def test_incompatible_legacy_database_rolls_back_and_preserves_backup(tmp_path: Path) -> None:
    database_path = tmp_path / "jobs.sqlite3"
    legacy = sqlite3.connect(database_path)
    legacy.execute("CREATE TABLE jobs (job_id TEXT PRIMARY KEY)")
    legacy.execute("INSERT INTO jobs VALUES ('legacy-job')")
    legacy.commit()
    legacy.close()

    store = SqliteStore(database_path)
    with pytest.raises(DatabaseMigrationError, match="missing columns") as raised:
        await store.initialize(["lab-west", "lab-east"])

    unchanged = sqlite3.connect(database_path)
    try:
        assert unchanged.execute("PRAGMA user_version").fetchone()[0] == 0
        assert unchanged.execute("SELECT job_id FROM jobs").fetchone()[0] == "legacy-job"
        tables = {
            row[0]
            for row in unchanged.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert tables == {"jobs"}
    finally:
        unchanged.close()
    backups = list(tmp_path.glob("jobs.sqlite3.backup-v0-*"))  # noqa: ASYNC240
    assert len(backups) == 1
    assert raised.value.details["backupPath"] == str(backups[0])


@pytest.mark.asyncio
async def test_database_from_a_future_release_is_rejected(tmp_path: Path) -> None:
    database_path = tmp_path / "jobs.sqlite3"
    future = sqlite3.connect(database_path)
    future.execute(f"PRAGMA user_version = {LATEST_SCHEMA_VERSION + 1}")
    future.close()

    with pytest.raises(DatabaseMigrationError, match="newer than supported"):
        await SqliteStore(database_path).initialize(["lab-west", "lab-east"])
