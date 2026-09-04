from __future__ import annotations

import asyncio
from pathlib import Path
from typing import ClassVar

import pytest

from trex_cli.artifacts import ArtifactStore
from trex_cli.engine import (
    EngineStatus,
    ExecutionMarker,
    ReconcileResult,
    RunHandle,
    SimulatedEngine,
)
from trex_cli.errors import IdempotencyConflict, TrexCliError
from trex_cli.jobs import TestJobs as JobsModule
from trex_cli.models import JobDocument, JobState, Verdict, utc_now
from trex_cli.storage import SqliteStore

from .conftest import (
    build_jobs,
    make_config,
    rfc_document,
    stateless_document,
    submit_body,
    wait_terminal,
)


@pytest.mark.asyncio
async def test_submit_runs_to_terminal_and_writes_bundle(jobs, operator) -> None:
    accepted = await jobs.submit(
        submit_body(stateless_document()), principal=operator, idempotency_key="same"
    )
    terminal = await asyncio.wait_for(wait_terminal(jobs, accepted.job_id), timeout=2)

    assert terminal.state == JobState.SUCCEEDED
    assert terminal.result is not None
    assert terminal.result.verdict == Verdict.PASS
    assert terminal.result.provenance.simulated is True
    names = {artifact.name for artifact in terminal.result.artifacts}
    assert {
        "manifest.json",
        "result.json",
        "report.md",
        "publication.json",
        "measurements.csv",
        "checksums.sha256",
    } <= names
    for artifact in terminal.result.artifacts:
        path, media_type, size = await jobs.artifact(artifact.digest)
        assert path.exists()
        assert media_type == artifact.media_type
        assert size == artifact.size


@pytest.mark.asyncio
async def test_calibration_does_not_replace_a_higher_verified_ceiling(
    jobs,
    operator,
) -> None:
    high = await jobs.submit(
        submit_body(stateless_document()), principal=operator, idempotency_key="calibration-high"
    )
    low = await jobs.submit(
        submit_body(stateless_document()), principal=operator, idempotency_key="calibration-low"
    )
    database = jobs._database
    fields = {
        "environment_key": "test-environment",
        "tx_port": "lab-west",
        "rx_port": "lab-east",
        "direction": "unidirectional",
        "frame_size": 64,
        "counter_mode": "flow-stats",
    }
    await database.record_calibration(
        **fields,
        ceiling_percent_l1=10,
        source_job_id=high.job_id,
        observed_at="2026-08-14T00:00:00+00:00",
    )
    await database.record_calibration(
        **fields,
        ceiling_percent_l1=0,
        source_job_id=low.job_id,
        observed_at="2026-08-14T01:00:00+00:00",
    )

    records = await database.get_calibrations(
        environment_key="test-environment",
        tx_port="lab-west",
        rx_port="lab-east",
        direction="unidirectional",
    )
    assert records[64]["ceilingPercentL1"] == 10
    assert records[64]["sourceJobId"] == high.job_id


@pytest.mark.asyncio
async def test_idempotency_returns_original_and_rejects_conflict(jobs, operator) -> None:
    first = await jobs.submit(
        submit_body(stateless_document()), principal=operator, idempotency_key="stable-key"
    )
    second = await jobs.submit(
        submit_body(stateless_document()), principal=operator, idempotency_key="stable-key"
    )
    assert second.job_id == first.job_id

    with pytest.raises(IdempotencyConflict):
        await jobs.submit(
            submit_body(rfc_document()), principal=operator, idempotency_key="stable-key"
        )


@pytest.mark.asyncio
async def test_retry_requires_terminal_job_with_same_spec(jobs, operator) -> None:
    original = await jobs.submit(
        submit_body(stateless_document()), principal=operator, idempotency_key="original"
    )
    await asyncio.wait_for(wait_terminal(jobs, original.job_id), timeout=2)

    retried = await jobs.submit(
        submit_body(stateless_document(), retry_of=original.job_id),
        principal=operator,
        idempotency_key="retry",
    )
    assert retried.job_id != original.job_id
    assert retried.retry_of == original.job_id

    with pytest.raises(TrexCliError, match="same spec digest"):
        await jobs.submit(
            submit_body(rfc_document(), retry_of=original.job_id),
            principal=operator,
            idempotency_key="bad-retry",
        )


@pytest.mark.asyncio
async def test_rfc_assertion_uses_simulated_ceiling(jobs, operator) -> None:
    accepted = await jobs.submit(
        submit_body(rfc_document(threshold=98)), principal=operator, idempotency_key="rfc"
    )
    terminal = await asyncio.wait_for(wait_terminal(jobs, accepted.job_id), timeout=2)
    assert terminal.result is not None
    assert terminal.result.verdict == Verdict.FAIL
    assert terminal.result.methodology == "simulated-rfc2544-throughput-strict/v1"


@pytest.mark.asyncio
async def test_rfc_suite_is_one_job_with_method_scoped_results(jobs, operator) -> None:
    raw = rfc_document()
    raw["kind"] = "Rfc2544Suite"
    raw["spec"]["tests"] = ["throughput", "frame-loss"]
    accepted = await jobs.submit(submit_body(raw), principal=operator, idempotency_key="rfc-suite")

    terminal = await asyncio.wait_for(wait_terminal(jobs, accepted.job_id), timeout=2)

    assert terminal.kind == "Rfc2544Suite"
    assert terminal.result is not None
    assert terminal.result.methodology == "simulated-rfc2544-suite-strict/v1"
    assert list(terminal.result.summary["tests"]) == ["throughput", "frame-loss"]
    assert (
        terminal.result.summary["tests"]["frame-loss"]["frames"]["64"][
            "stoppedAfterTwoZeroLossTrials"
        ]
        is True
    )


@pytest.mark.asyncio
async def test_simulated_complete_rfc_suite_is_never_publishable(jobs, operator) -> None:
    raw = rfc_document()
    raw["kind"] = "Rfc2544Suite"
    raw["spec"]["tests"] = [
        "throughput",
        "latency",
        "frame-loss",
        "back-to-back",
    ]
    raw["spec"]["latency"] = {
        "definition": "store-and-forward",
        "scenarios": ["same-destination", "new-destination"],
    }
    raw["spec"]["backToBack"] = {"maximumBurstFrames": 1000000}
    accepted = await jobs.submit(
        submit_body(raw), principal=operator, idempotency_key="complete-rfc-suite"
    )

    terminal = await asyncio.wait_for(wait_terminal(jobs, accepted.job_id), timeout=2)

    assert terminal.result is not None
    assert terminal.result.summary["publicationStatus"] == "PARTIAL"
    assert "measurement is simulated" in terminal.result.summary["publicationIssues"]
    assert terminal.result.summary["standardConformance"] == "rfc2544-suite-partial"
    assert list(terminal.result.summary["tests"]) == [
        "throughput",
        "latency",
        "frame-loss",
        "back-to-back",
    ]


@pytest.mark.asyncio
async def test_cancel_is_persisted_and_wins_over_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operator
) -> None:
    jobs = await build_jobs(make_config(tmp_path, monkeypatch, step_delay_ms=50))
    try:
        accepted = await jobs.submit(
            submit_body(stateless_document()), principal=operator, idempotency_key="cancel"
        )
        await jobs.cancel(accepted.job_id, "cancel-1", "test", principal=operator)
        terminal = await asyncio.wait_for(wait_terminal(jobs, accepted.job_id), timeout=2)
        assert terminal.state == JobState.CANCELLED
        assert terminal.result is None
    finally:
        await jobs.stop()


@pytest.mark.asyncio
async def test_cancel_interrupts_a_running_engine_and_releases_ports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operator
) -> None:
    class BlockingRunEngine(SimulatedEngine):
        def __init__(self, config) -> None:
            super().__init__(config.safety, 0)
            self.run_started = asyncio.Event()
            self.force_stopped = asyncio.Event()
            self.cleaned = asyncio.Event()

        async def run(self, handle, *, report_progress=None):
            del handle, report_progress
            self.run_started.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        async def stop(self, handle: RunHandle, *, force: bool = False) -> None:
            del handle
            if force:
                self.force_stopped.set()

        async def cleanup(self, handle: RunHandle) -> None:
            await super().cleanup(handle)
            self.cleaned.set()

    config = make_config(tmp_path, monkeypatch)
    database = SqliteStore(config.database_path)
    engine = BlockingRunEngine(config)
    instance = JobsModule(
        config,
        database,
        ArtifactStore(config.artifact_root, database),
        engine,
    )
    await instance.start()
    try:
        accepted = await instance.submit(
            submit_body(stateless_document()), principal=operator, idempotency_key="cancel-running"
        )
        await asyncio.wait_for(engine.run_started.wait(), timeout=2)

        await instance.cancel(accepted.job_id, "cancel-running-1", "test", principal=operator)

        terminal = await asyncio.wait_for(wait_terminal(instance, accepted.job_id), timeout=2)
        assert terminal.state == JobState.CANCELLED
        assert engine.force_stopped.is_set()
        assert engine.cleaned.is_set()
        assert await database.get_execution_marker(accepted.job_id) is None
        assert all(
            value["status"] == "AVAILABLE" for value in (await database.port_statuses()).values()
        )
    finally:
        await instance.stop()


@pytest.mark.asyncio
async def test_cancel_quarantines_ports_when_remote_cleanup_cannot_be_confirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operator
) -> None:
    class UnconfirmedCancelEngine(SimulatedEngine):
        def __init__(self, config) -> None:
            super().__init__(config.safety, 0)
            self.run_started = asyncio.Event()

        async def run(self, handle, *, report_progress=None):
            del handle, report_progress
            self.run_started.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        async def stop(self, handle: RunHandle, *, force: bool = False) -> None:
            del handle, force
            raise TrexCliError(
                code="TREX_TIMEOUT", category="ENGINE", message="remote stop was not confirmed"
            )

        async def cleanup(self, handle: RunHandle) -> None:
            del handle
            raise TrexCliError(
                code="TREX_TIMEOUT", category="ENGINE", message="remote cleanup was not confirmed"
            )

    config = make_config(tmp_path, monkeypatch)
    database = SqliteStore(config.database_path)
    engine = UnconfirmedCancelEngine(config)
    instance = JobsModule(
        config,
        database,
        ArtifactStore(config.artifact_root, database),
        engine,
    )
    await instance.start()
    try:
        accepted = await instance.submit(
            submit_body(stateless_document()),
            principal=operator,
            idempotency_key="cancel-unconfirmed",
        )
        await asyncio.wait_for(engine.run_started.wait(), timeout=2)

        await instance.cancel(accepted.job_id, "cancel-unconfirmed-1", "test", principal=operator)

        terminal = await asyncio.wait_for(wait_terminal(instance, accepted.job_id), timeout=2)
        assert terminal.state == JobState.CANCELLED
        assert await database.get_execution_marker(accepted.job_id) is not None
        statuses = await database.port_statuses()
        assert statuses["lab-west"]["status"] == "QUARANTINED"
        assert statuses["lab-east"]["status"] == "QUARANTINED"
    finally:
        await instance.stop()


@pytest.mark.asyncio
async def test_restart_fails_job_after_execution_begins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operator
) -> None:
    config = make_config(tmp_path, monkeypatch, step_delay_ms=1_000)
    first = await build_jobs(config)
    accepted = await first.submit(
        submit_body(stateless_document()), principal=operator, idempotency_key="restart"
    )
    for _ in range(100):
        current = await first.get(accepted.job_id)
        if current.state in {JobState.PREPARING, JobState.WARMING_UP, JobState.RUNNING}:
            break
        await asyncio.sleep(0.01)
    assert current.state in {JobState.PREPARING, JobState.WARMING_UP, JobState.RUNNING}
    await first.stop()

    second = await build_jobs(config)
    try:
        recovered = await second.get(accepted.job_id)
        assert recovered.state == JobState.FAILED
        assert recovered.problem is not None
        assert recovered.problem.code == "RECOVERY_ABORTED"
    finally:
        await second.stop()


@pytest.mark.asyncio
async def test_address_outside_policy_fails_asynchronously(jobs, operator) -> None:
    document = stateless_document()
    document["spec"]["packet"]["ipv4"]["dst"] = "203.0.113.1"
    accepted = await jobs.submit(
        submit_body(document), principal=operator, idempotency_key="unsafe"
    )
    terminal = await asyncio.wait_for(wait_terminal(jobs, accepted.job_id), timeout=2)
    assert terminal.state == JobState.FAILED
    assert terminal.problem is not None
    assert terminal.problem.code == "UNSAFE_REQUEST"


@pytest.mark.asyncio
async def test_mac_range_outside_policy_fails_asynchronously(jobs, operator) -> None:
    document = stateless_document()
    document["spec"]["packet"]["ethernet"]["src"] = {
        "start": "02:00:00:00:00:01",
        "end": "02:00:00:00:00:04",
        "mode": "increment",
    }
    accepted = await jobs.submit(
        submit_body(document), principal=operator, idempotency_key="unsafe-mac"
    )
    terminal = await asyncio.wait_for(wait_terminal(jobs, accepted.job_id), timeout=2)
    assert terminal.state == JobState.FAILED
    assert terminal.problem is not None
    assert terminal.problem.code == "UNSAFE_REQUEST"


@pytest.mark.asyncio
async def test_disjoint_ports_run_concurrently_while_conflicting_job_waits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operator
) -> None:
    jobs = await build_jobs(make_config(tmp_path, monkeypatch, step_delay_ms=75))
    try:
        first = await jobs.submit(
            submit_body(stateless_document()), principal=operator, idempotency_key="first"
        )
        second = await jobs.submit(
            submit_body(stateless_document()), principal=operator, idempotency_key="second"
        )
        disjoint_document = stateless_document()
        disjoint_document["spec"]["ports"] = {"tx": "lab-north", "rx": "lab-south"}
        disjoint = await jobs.submit(
            submit_body(disjoint_document), principal=operator, idempotency_key="disjoint"
        )

        observed_parallel = False
        for _ in range(100):
            states = {
                first.job_id: (await jobs.get(first.job_id)).state,
                second.job_id: (await jobs.get(second.job_id)).state,
                disjoint.job_id: (await jobs.get(disjoint.job_id)).state,
            }
            active_states = {
                JobState.PREPARING,
                JobState.WARMING_UP,
                JobState.RUNNING,
                JobState.DRAINING,
                JobState.COLLECTING,
            }
            if (
                states[first.job_id] in active_states
                and states[disjoint.job_id] in active_states
                and states[second.job_id] == JobState.WAITING_FOR_PORTS
            ):
                observed_parallel = True
                break
            await asyncio.sleep(0.01)
        assert observed_parallel

        terminals = await asyncio.gather(
            wait_terminal(jobs, first.job_id),
            wait_terminal(jobs, second.job_id),
            wait_terminal(jobs, disjoint.job_id),
        )
        assert all(snapshot.state == JobState.SUCCEEDED for snapshot in terminals)
        assert terminals[0].finished_at is not None
        assert terminals[1].started_at is not None
        assert terminals[0].finished_at <= terminals[1].started_at
    finally:
        await jobs.stop()


@pytest.mark.asyncio
async def test_safety_policy_rejects_excessive_duration(jobs, operator) -> None:
    document = stateless_document()
    document["spec"]["duration"] = "121s"
    accepted = await jobs.submit(
        submit_body(document), principal=operator, idempotency_key="too-long"
    )
    terminal = await asyncio.wait_for(wait_terminal(jobs, accepted.job_id), timeout=2)
    assert terminal.state == JobState.FAILED
    assert terminal.problem is not None
    assert terminal.problem.code == "UNSAFE_REQUEST"


@pytest.mark.asyncio
async def test_atomic_prepare_failure_does_not_quarantine_ports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operator
) -> None:
    class FailingPrepareEngine(SimulatedEngine):
        async def prepare(self, marker: ExecutionMarker, document: JobDocument) -> RunHandle:
            del marker, document
            raise TrexCliError(
                code="TREX_UNAVAILABLE",
                category="ENGINE",
                message="atomic prepare rolled back",
            )

    config = make_config(tmp_path, monkeypatch)
    database = SqliteStore(config.database_path)
    instance = JobsModule(
        config,
        database,
        ArtifactStore(config.artifact_root, database),
        FailingPrepareEngine(config.safety, 0),
    )
    await instance.start()
    try:
        first = await instance.submit(
            submit_body(stateless_document()), principal=operator, idempotency_key="prepare-fails"
        )
        terminal = await asyncio.wait_for(wait_terminal(instance, first.job_id), timeout=2)
        assert terminal.state == JobState.FAILED
        assert await database.get_execution_marker(first.job_id) is None
        assert all(
            value["status"] == "AVAILABLE" for value in (await database.port_statuses()).values()
        )
    finally:
        await instance.stop()


@pytest.mark.asyncio
async def test_unconfirmed_engine_cleanup_quarantines_ports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operator
) -> None:
    class FailingCleanupEngine(SimulatedEngine):
        async def cleanup(self, handle: RunHandle) -> None:
            raise RuntimeError("release could not be confirmed")

    config = make_config(tmp_path, monkeypatch)
    database = SqliteStore(config.database_path)
    artifacts = ArtifactStore(config.artifact_root, database)
    engine = FailingCleanupEngine(config.safety, 0)
    instance = JobsModule(config, database, artifacts, engine)
    await instance.start()
    try:
        first = await instance.submit(
            submit_body(stateless_document()), principal=operator, idempotency_key="cleanup-fails"
        )
        first_terminal = await asyncio.wait_for(wait_terminal(instance, first.job_id), timeout=2)
        assert first_terminal.state == JobState.FAILED

        second = await instance.submit(
            submit_body(stateless_document()), principal=operator, idempotency_key="quarantined"
        )
        second_terminal = await asyncio.wait_for(wait_terminal(instance, second.job_id), timeout=2)
        assert second_terminal.state == JobState.FAILED
        assert second_terminal.problem is not None
        assert second_terminal.problem.code == "CAPABILITY_MISMATCH"
        assert "quarantined" in second_terminal.problem.message
    finally:
        await instance.stop()

    recovery_database = SqliteStore(config.database_path)
    recovered_instance = JobsModule(
        config,
        recovery_database,
        ArtifactStore(config.artifact_root, recovery_database),
        SimulatedEngine(config.safety, 0),
    )
    await recovered_instance.start()
    try:
        assert await recovery_database.get_execution_marker(first.job_id) is None
        after_reconcile = await recovered_instance.submit(
            submit_body(stateless_document()),
            principal=operator,
            idempotency_key="cleanup-reconciled",
        )
        terminal = await asyncio.wait_for(
            wait_terminal(recovered_instance, after_reconcile.job_id), timeout=2
        )
        assert terminal.state == JobState.SUCCEEDED
    finally:
        await recovered_instance.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("confirmed_idle", [True, False])
async def test_startup_reconciliation_controls_quarantine_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operator,
    confirmed_idle: bool,
) -> None:
    class HangingPrepareEngine(SimulatedEngine):
        async def prepare(self, marker: ExecutionMarker, document: JobDocument) -> RunHandle:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    class RecoveringEngine(SimulatedEngine):
        mode = "recovering-test"
        simulated = False

        async def reconcile(
            self, marker: ExecutionMarker, document: JobDocument
        ) -> ReconcileResult:
            return ReconcileResult(
                confirmed_idle=confirmed_idle,
                details={"reason": "test-reconciliation"},
            )

    config = make_config(tmp_path, monkeypatch)
    first_database = SqliteStore(config.database_path)
    first = JobsModule(
        config,
        first_database,
        ArtifactStore(config.artifact_root, first_database),
        HangingPrepareEngine(config.safety, 0),
    )
    await first.start()
    stranded = await first.submit(
        submit_body(stateless_document()), principal=operator, idempotency_key="stranded"
    )
    for _ in range(100):
        if await first_database.get_execution_marker(stranded.job_id) is not None:
            break
        await asyncio.sleep(0.01)
    assert await first_database.get_execution_marker(stranded.job_id) is not None
    await first.stop()

    second_database = SqliteStore(config.database_path)
    second = JobsModule(
        config,
        second_database,
        ArtifactStore(config.artifact_root, second_database),
        RecoveringEngine(config.safety, 0),
    )
    await second.start()
    try:
        recovered = await second.get(stranded.job_id)
        assert recovered.state == JobState.FAILED
        assert recovered.problem is not None
        assert recovered.problem.details["reconciliation"]["reason"] == "test-reconciliation"

        follow_up = await second.submit(
            submit_body(stateless_document()),
            principal=operator,
            idempotency_key="after-recovery",
        )
        terminal = await asyncio.wait_for(wait_terminal(second, follow_up.job_id), timeout=2)
        if confirmed_idle:
            assert terminal.state == JobState.SUCCEEDED
        else:
            assert terminal.state == JobState.FAILED
            assert terminal.problem is not None
            assert "quarantined" in terminal.problem.message
    finally:
        await second.stop()


@pytest.mark.asyncio
async def test_strict_remote_rfc_requires_calibration_above_bootstrap_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operator
) -> None:
    class RemoteLikeEngine(SimulatedEngine):
        mode = "remote-trex"
        simulated = False
        port_speeds_gbps: ClassVar[dict[str, float]] = {
            "0": 10.0,
            "1": 10.0,
            "2": 10.0,
            "3": 10.0,
        }

        async def probe(self) -> EngineStatus:
            return EngineStatus(
                available=True,
                details={
                    "mode": self.mode,
                    "trexVersion": "v3.08-test",
                    "portSpeedsGbps": self.port_speeds_gbps,
                },
            )

    data = make_config(tmp_path, monkeypatch).model_dump(mode="json", by_alias=True)
    data["engine"] = {
        "mode": "remote-trex",
        "server": "127.0.0.1",
        "clientPath": str(tmp_path),
        "externalLibsPath": str(tmp_path),
        "portMapping": {
            "lab-west": 0,
            "lab-east": 1,
            "lab-north": 2,
            "lab-south": 3,
        },
    }
    data["safety"]["maxPercentL1"] = 1
    config = type(make_config(tmp_path, monkeypatch)).model_validate(data)
    config.resolve_secrets()
    database = SqliteStore(config.database_path)
    engine = RemoteLikeEngine(config.safety, 0)
    instance = JobsModule(
        config,
        database,
        ArtifactStore(config.artifact_root, database),
        engine,
    )
    await instance.start()
    try:
        accepted = await instance.submit(
            submit_body(rfc_document()), principal=operator, idempotency_key="needs-calibration"
        )
        terminal = await asyncio.wait_for(wait_terminal(instance, accepted.job_id), timeout=2)
        assert terminal.state == JobState.FAILED
        assert terminal.problem is not None
        assert terminal.problem.code == "CALIBRATION_REQUIRED"
        assert terminal.problem.details["missingFrameSizes"] == [
            64,
            128,
            256,
            512,
            1024,
            1280,
            1518,
        ]

        environment_key = await instance._environment_key()
        engine.port_speeds_gbps = {"0": 1.0, "1": 1.0, "2": 10.0, "3": 10.0}
        assert await instance._environment_key() != environment_key
        engine.port_speeds_gbps = {"0": 10.0, "1": 10.0, "2": 10.0, "3": 10.0}
        frame_sizes = [64, 128, 256, 512, 1024, 1280, 1518]
        for frame_size in frame_sizes:
            await database.record_calibration(
                environment_key=environment_key,
                tx_port="lab-west",
                rx_port="lab-east",
                direction="bidirectional",
                frame_size=frame_size,
                ceiling_percent_l1=0.5,
                counter_mode="flow-stats",
                source_job_id=accepted.job_id,
                observed_at=utc_now().isoformat(),
            )

        accepted_again = await instance.submit(
            submit_body(rfc_document()),
            principal=operator,
            idempotency_key="calibration-ceiling-too-low",
        )
        terminal_again = await asyncio.wait_for(
            wait_terminal(instance, accepted_again.job_id), timeout=2
        )
        assert terminal_again.problem is not None
        assert terminal_again.problem.code == "CALIBRATION_REQUIRED"
        assert terminal_again.problem.details["insufficientCeilingFrameSizes"] == frame_sizes
        assert terminal_again.problem.details["requiredCeilingPercentL1"] == 1
        assert terminal_again.problem.details["minimumPriorCeilingPercentL1"] == 1
        assert terminal_again.problem.details["maxCalibrationGrowthFactor"] == 1

        config.safety.max_calibration_growth_factor = 2
        accepted_ramp = await instance.submit(
            submit_body(rfc_document()),
            principal=operator,
            idempotency_key="calibration-bounded-ramp",
        )
        terminal_ramp = await asyncio.wait_for(
            wait_terminal(instance, accepted_ramp.job_id), timeout=2
        )
        assert terminal_ramp.state == JobState.SUCCEEDED
    finally:
        await instance.stop()
