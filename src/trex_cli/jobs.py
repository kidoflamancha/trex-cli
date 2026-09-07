from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from typing import Any

from trex_cli import __version__
from trex_cli.address_policy import ipv4_range_allowed, mac_range_allowed
from trex_cli.artifacts import ArtifactStore
from trex_cli.config import AgentConfig, RemoteTrexEngineConfig
from trex_cli.engine import ExecutionMarker, RunHandle, TrafficEngine
from trex_cli.errors import RevisionConflict, TrexCliError
from trex_cli.models import (
    JOB_DOCUMENT_ADAPTER,
    ArpStormSpec,
    DhcpStormSpec,
    DnsStormSpec,
    JobDocument,
    JobResult,
    JobSnapshot,
    JobState,
    PacketStormDocument,
    PcapReplayDocument,
    Phase,
    Principal,
    Problem,
    Progress,
    Provenance,
    ReplayCaptureTiming,
    ReplayFixedRateTiming,
    ReplayPreserveAddress,
    ReplayRewriteAddress,
    Rfc2544SuiteDocument,
    Rfc2544ThroughputDocument,
    StatefulReplayDocument,
    StatelessTrafficDocument,
    SubmitBody,
    UdpWorkloadDocument,
    canonical_document,
    sha256_text,
    utc_now,
)
from trex_cli.observability import RuntimeMetrics
from trex_cli.storage import SqliteStore

_LOGGER = logging.getLogger(__name__)


class TestJobs:
    def __init__(
        self,
        config: AgentConfig,
        database: SqliteStore,
        artifacts: ArtifactStore,
        engine: TrafficEngine,
        metrics: RuntimeMetrics | None = None,
    ) -> None:
        self._config = config
        self._database = database
        self._artifacts = artifacts
        self._engine = engine
        self._metrics = metrics
        self._changed = asyncio.Condition()
        self._stop = asyncio.Event()
        self._scheduler_task: asyncio.Task[None] | None = None
        self._active: dict[str, asyncio.Task[None]] = {}
        self._session_id = uuid.uuid4().hex

    async def start(self) -> None:
        await self._database.initialize(self._config.logical_ports)
        await self._artifacts.initialize()
        await self._recover()
        self._scheduler_task = asyncio.create_task(self._scheduler_loop(), name="job-scheduler")
        _LOGGER.info(
            "agent_started",
            extra={"sessionId": self._session_id, "engine": self._engine.mode},
        )

    async def stop(self) -> None:
        self._stop.set()
        await self._notify()
        if self._scheduler_task is not None:
            await self._scheduler_task
        active = list(self._active.values())
        for task in active:
            task.cancel()
        if active:
            await asyncio.gather(*active, return_exceptions=True)
        await self._database.close()
        _LOGGER.info("agent_stopped", extra={"sessionId": self._session_id})

    async def submit(
        self, request: SubmitBody, *, principal: Principal, idempotency_key: str
    ) -> JobSnapshot:
        canonical = canonical_document(request.document)
        digest = sha256_text(canonical)
        now = utc_now()
        snapshot = JobSnapshot(
            jobId=_new_job_id(),
            revision=1,
            state=JobState.ACCEPTED,
            kind=request.document.kind,
            submittedSpecDigest=digest,
            retryOf=request.retry_of,
            submittedAt=now,
            phase=Phase(name="accepted"),
            progress=Progress(completed=0, total=None),
        )
        stored, created = await self._database.create_job(
            snapshot=snapshot,
            principal=principal.name,
            idempotency_key=idempotency_key,
            document_json=canonical,
            retry_of=request.retry_of,
        )
        if created:
            _LOGGER.info(
                "job_submitted",
                extra={
                    "jobId": stored.job_id,
                    "kind": stored.kind,
                    "principal": principal.name,
                    "revision": stored.revision,
                },
            )
            await self._notify()
        return stored

    async def get(self, job_id: str) -> JobSnapshot:
        return await self._database.get_snapshot(job_id)

    async def observe(
        self, job_id: str, after_revision: int | None = None
    ) -> AsyncIterator[JobSnapshot]:
        cursor = after_revision
        if cursor is None:
            current = await self._database.get_snapshot(job_id)
            yield current
            cursor = current.revision
            if current.state.terminal:
                return

        while True:
            events = await self._database.events_after(job_id, cursor)
            if events:
                for snapshot in events:
                    yield snapshot
                    cursor = snapshot.revision
                    if snapshot.state.terminal:
                        return
                continue

            current = await self._database.get_snapshot(job_id)
            if current.state.terminal and current.revision <= cursor:
                return
            async with self._changed:
                try:
                    await asyncio.wait_for(self._changed.wait(), timeout=0.1)
                except TimeoutError:
                    pass

    async def cancel(
        self, job_id: str, request_id: str, reason: str, *, principal: Principal
    ) -> JobSnapshot:
        snapshot = await self._database.request_cancel(job_id, request_id, principal.name, reason)
        _LOGGER.info(
            "job_cancel_requested",
            extra={
                "jobId": snapshot.job_id,
                "principal": principal.name,
                "cancelRequestId": request_id,
                "revision": snapshot.revision,
            },
        )
        task = self._active.get(job_id)
        if task is not None and not task.done():
            task.cancel()
        await self._notify()
        return snapshot

    async def artifact(self, digest: str) -> tuple[Any, str, int]:
        return await self._artifacts.locate(digest)

    async def _notify(self) -> None:
        async with self._changed:
            self._changed.notify_all()

    async def _recover(self) -> None:
        snapshots = await self._database.list_nonterminal()
        processed_markers: set[str] = set()
        recoverable = {
            JobState.ACCEPTED,
            JobState.VALIDATING,
            JobState.WAITING_FOR_PORTS,
        }
        for snapshot in snapshots:
            if snapshot.state in recoverable:
                continue
            marker = await self._database.get_execution_marker(snapshot.job_id)
            confirmed_idle = marker is None
            reconciliation: dict[str, Any] = {"reason": "no-execution-marker"}
            if marker is not None:
                processed_markers.add(marker.marker_id)
                document = await self._document(snapshot.job_id)
                result = await self._engine.reconcile(marker, document)
                confirmed_idle = result.confirmed_idle
                reconciliation = result.details
                if confirmed_idle:
                    await self._database.delete_execution_marker(snapshot.job_id)
                    await self._database.confirm_ports_available(marker.logical_ports)
            problem = Problem(
                code="RECOVERY_ABORTED",
                category="ENGINE",
                retryable=False,
                message="the Agent restarted after execution had begun",
                details={
                    "previousState": snapshot.state,
                    "reconciliation": reconciliation,
                },
            )
            await self._fail(snapshot.job_id, problem, expected_states={snapshot.state})
            await self._database.release_ports(snapshot.job_id, quarantine=not confirmed_idle)

        for marker in await self._database.list_execution_markers():
            if marker.marker_id in processed_markers:
                continue
            document = await self._document(marker.job_id)
            result = await self._engine.reconcile(marker, document)
            if result.confirmed_idle:
                await self._database.delete_execution_marker(marker.job_id)
                await self._database.confirm_ports_available(marker.logical_ports)

    async def _scheduler_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self._tick()
            except Exception:
                # A scheduler-level error must not terminate future scheduling. Individual Jobs
                # are failed by their own paths and the next tick retries database discovery.
                _LOGGER.exception("scheduler_tick_failed")
                await asyncio.sleep(0.05)
            async with self._changed:
                try:
                    await asyncio.wait_for(self._changed.wait(), timeout=0.05)
                except TimeoutError:
                    pass

    async def _tick(self) -> None:
        self._active = {job_id: task for job_id, task in self._active.items() if not task.done()}
        snapshots = await self._database.list_nonterminal()
        for snapshot in snapshots:
            if snapshot.job_id in self._active:
                continue
            if snapshot.cancel_requested:
                self._spawn(snapshot.job_id, self._finish_cancel(snapshot.job_id))
                continue
            document = await self._document(snapshot.job_id)
            elapsed_ms = (utc_now() - snapshot.submitted_at).total_seconds() * 1_000
            if elapsed_ms > document.spec.limits.job_timeout:
                await self._fail(
                    snapshot.job_id,
                    Problem(
                        code="JOB_TIMEOUT",
                        category="RESOURCE",
                        retryable=True,
                        message="the Job exceeded its resolved jobTimeout",
                    ),
                )
                await self._database.release_ports(snapshot.job_id)
                continue
            if snapshot.state in {JobState.ACCEPTED, JobState.VALIDATING}:
                await self._validate_job(snapshot.job_id)

        if len(self._active) >= self._config.safety.max_concurrent_jobs:
            return
        snapshots = await self._database.list_nonterminal()
        for snapshot in snapshots:
            if len(self._active) >= self._config.safety.max_concurrent_jobs:
                break
            if snapshot.job_id in self._active or snapshot.state != JobState.WAITING_FOR_PORTS:
                continue
            if snapshot.cancel_requested:
                self._spawn(snapshot.job_id, self._finish_cancel(snapshot.job_id))
                continue
            document = await self._document(snapshot.job_id)
            wait_ms = (utc_now() - snapshot.submitted_at).total_seconds() * 1_000
            if wait_ms > document.spec.limits.port_wait_timeout:
                await self._fail(
                    snapshot.job_id,
                    Problem(
                        code="PORT_WAIT_TIMEOUT",
                        category="RESOURCE",
                        retryable=True,
                        message="the Job did not acquire all logical ports before its deadline",
                    ),
                    expected_states={JobState.WAITING_FOR_PORTS},
                )
                continue
            ports = (
                sorted(document.spec.logical_ports())
                if isinstance(
                    document,
                    (
                        StatelessTrafficDocument,
                        PcapReplayDocument,
                        StatefulReplayDocument,
                        UdpWorkloadDocument,
                        PacketStormDocument,
                    ),
                )
                else [document.spec.ports.tx, document.spec.ports.rx]
            )
            try:
                fence = await self._database.acquire_ports(snapshot.job_id, ports)
            except TrexCliError as error:
                await self._fail(snapshot.job_id, _problem(error), expected_states={snapshot.state})
                continue
            if fence is None:
                continue
            prepared = await self._transition(
                snapshot.job_id,
                JobState.PREPARING,
                "PORTS_ACQUIRED",
                expected_states={JobState.WAITING_FOR_PORTS},
                phase=Phase(name="preparing", detail={"fence": fence}),
            )
            if prepared is None:
                await self._database.release_ports(snapshot.job_id)
                continue
            remaining_seconds = max(
                0.001,
                (
                    document.spec.limits.job_timeout
                    - (utc_now() - snapshot.submitted_at).total_seconds() * 1_000
                )
                / 1_000,
            )
            self._spawn(
                snapshot.job_id,
                self._execute_with_deadline(snapshot.job_id, remaining_seconds, fence),
            )

    def _spawn(self, job_id: str, coroutine: Any) -> None:
        task = asyncio.create_task(coroutine, name=f"job-{job_id}")
        self._active[job_id] = task

    async def _validate_job(self, job_id: str) -> None:
        snapshot = await self._database.get_snapshot(job_id)
        if snapshot.state == JobState.ACCEPTED:
            transitioned = await self._transition(
                job_id,
                JobState.VALIDATING,
                "VALIDATION_STARTED",
                expected_states={JobState.ACCEPTED},
                phase=Phase(name="validating"),
            )
            if transitioned is None:
                return
        try:
            document = await self._document(job_id)
            self._validate_policy(document)
            await self._engine.validate(document)
            await self._validate_calibration(document)
            resolved = {
                "document": document.model_dump(mode="json", by_alias=True, exclude_none=True),
                "policyVersion": self._config.safety.version,
                "engine": {"mode": self._engine.mode, "simulated": self._engine.simulated},
            }
            resolved_json = json.dumps(
                resolved, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            await self._transition(
                job_id,
                JobState.WAITING_FOR_PORTS,
                "VALIDATION_SUCCEEDED",
                expected_states={JobState.VALIDATING},
                phase=Phase(name="waiting-for-ports"),
                resolved_spec_digest=sha256_text(resolved_json),
                resolved_spec_json=resolved_json,
            )
        except TrexCliError as error:
            await self._fail(job_id, _problem(error), expected_states={JobState.VALIDATING})
        except Exception as error:
            await self._fail(
                job_id,
                Problem(
                    code="UNSAFE_REQUEST",
                    category="POLICY",
                    message=str(error),
                    retryable=False,
                ),
                expected_states={JobState.VALIDATING},
            )

    async def _validate_calibration(self, document: JobDocument) -> None:
        if not isinstance(document, (Rfc2544ThroughputDocument, Rfc2544SuiteDocument)):
            return
        if document.spec.mode != "strict" or self._engine.simulated:
            return
        policy = self._config.safety
        if policy.max_percent_l1 <= policy.calibration_bootstrap_max_percent_l1:
            return
        environment_key = await self._environment_key()
        records = await self._database.get_calibrations(
            environment_key=environment_key,
            tx_port=document.spec.ports.tx,
            rx_port=document.spec.ports.rx,
            direction=document.spec.ports.direction,
        )
        required = {64, 128, 256, 512, 1024, 1280, 1518}
        now = utc_now()
        missing: list[int] = []
        unreliable: list[int] = []
        stale: list[int] = []
        insufficient: list[int] = []
        minimum_prior_ceiling = policy.max_percent_l1 / policy.max_calibration_growth_factor
        for frame_size in sorted(required):
            record = records.get(frame_size)
            if record is None:
                missing.append(frame_size)
                continue
            if record["counterMode"] != "flow-stats":
                unreliable.append(frame_size)
            if float(record["ceilingPercentL1"]) < minimum_prior_ceiling:
                insufficient.append(frame_size)
            observed = datetime.fromisoformat(str(record["observedAt"]))
            age_ms = (now - observed).total_seconds() * 1_000
            if age_ms > policy.max_calibration_age:
                stale.append(frame_size)
        if missing or unreliable or stale or insufficient:
            raise TrexCliError(
                code="CALIBRATION_REQUIRED",
                category="ENGINE",
                message="strict RFC2544 requires fresh, marker-isolated calibration",
                details={
                    "missingFrameSizes": missing,
                    "unreliableFrameSizes": unreliable,
                    "staleFrameSizes": stale,
                    "insufficientCeilingFrameSizes": insufficient,
                    "requiredCeilingPercentL1": policy.max_percent_l1,
                    "minimumPriorCeilingPercentL1": minimum_prior_ceiling,
                    "maxCalibrationGrowthFactor": policy.max_calibration_growth_factor,
                    "environmentKey": environment_key,
                },
            )

    async def _environment_key(self, trex_version: str | None = None) -> str:
        engine = self._config.engine
        if not isinstance(engine, RemoteTrexEngineConfig):
            return "simulated"
        status = await self._engine.probe()
        if trex_version is None:
            trex_version = str(status.details.get("trexVersion", "unavailable"))
        physical_speeds = status.details.get("portSpeedsGbps", {})
        logical_speeds = {
            logical_port: (
                physical_speeds.get(str(physical_port), "unavailable")
                if isinstance(physical_speeds, dict)
                else "unavailable"
            )
            for logical_port, physical_port in engine.port_mapping.items()
        }
        value = {
            "mode": engine.mode,
            "server": engine.server,
            "syncPort": engine.sync_port,
            "asyncPort": engine.async_port,
            "portMapping": engine.port_mapping,
            "logicalPortSpeedsGbps": logical_speeds,
            "trexVersion": trex_version,
        }
        return sha256_text(json.dumps(value, sort_keys=True, separators=(",", ":")))

    async def _record_calibrations(
        self, job_id: str, document: JobDocument, result: JobResult
    ) -> None:
        if not isinstance(document, (Rfc2544ThroughputDocument, Rfc2544SuiteDocument)):
            return
        if result.verdict == "INVALID" or self._engine.simulated:
            return
        summary = result.summary
        if isinstance(document, Rfc2544SuiteDocument):
            suite_tests = summary.get("tests")
            if not isinstance(suite_tests, dict):
                return
            throughput = suite_tests.get("throughput")
            if not isinstance(throughput, dict):
                return
            summary = throughput
        rates = summary.get("rates")
        trials = summary.get("trials")
        if not isinstance(rates, dict) or not isinstance(trials, dict):
            return
        environment_key = await self._environment_key(result.provenance.trex_version)
        for frame_text, values in rates.items():
            if not isinstance(values, dict):
                continue
            ceiling = values.get("percentL1")
            frame_trials = trials.get(frame_text)
            if not isinstance(ceiling, (int, float)) or not isinstance(frame_trials, list):
                continue
            counter_modes: set[str] = set()
            for trial in frame_trials:
                if not isinstance(trial, dict):
                    continue
                details = trial.get("details")
                if not isinstance(details, dict):
                    continue
                directions = details.get("directions")
                if isinstance(directions, list):
                    for direction in directions:
                        if isinstance(direction, dict):
                            counter_modes.add(str(direction.get("counterSource", "unknown")))
            counter_mode = (
                "flow-stats" if counter_modes == {"flow-stats"} else "exclusive-port-fallback"
            )
            await self._database.record_calibration(
                environment_key=environment_key,
                tx_port=document.spec.ports.tx,
                rx_port=document.spec.ports.rx,
                direction=document.spec.ports.direction,
                frame_size=int(frame_text),
                ceiling_percent_l1=float(ceiling),
                counter_mode=counter_mode,
                source_job_id=job_id,
                observed_at=utc_now().isoformat(),
            )

    def _validate_policy(self, document: JobDocument) -> None:
        limits = document.spec.limits
        policy = self._config.safety
        if limits.job_timeout > policy.max_job_timeout:
            raise TrexCliError(
                code="UNSAFE_REQUEST",
                category="POLICY",
                message="jobTimeout exceeds the configured SafetyPolicy maximum",
            )
        if limits.port_wait_timeout > policy.max_port_wait_timeout:
            raise TrexCliError(
                code="UNSAFE_REQUEST",
                category="POLICY",
                message="portWaitTimeout exceeds the configured SafetyPolicy maximum",
            )
        if document.kind == "StatelessTraffic":
            if document.spec.duration is not None:
                if document.spec.duration > policy.max_run_duration:
                    raise TrexCliError(
                        code="UNSAFE_REQUEST",
                        category="POLICY",
                        message="duration exceeds the configured SafetyPolicy maximum",
                    )
                if document.spec.duration > limits.job_timeout:
                    raise TrexCliError(
                        code="UNSAFE_REQUEST",
                        category="POLICY",
                        message="duration cannot exceed jobTimeout",
                    )
            if (
                document.spec.burst_packets is not None
                and document.spec.burst_packets > policy.max_burst_packets
            ):
                raise TrexCliError(
                    code="UNSAFE_REQUEST",
                    category="POLICY",
                    message="burstPackets exceeds the configured SafetyPolicy maximum",
                )
            rates_by_egress: dict[tuple[str, str], float] = {}
            if document.spec.streams:
                for stream in document.spec.streams:
                    key = (stream.tx, stream.rate.unit)
                    rates_by_egress[key] = rates_by_egress.get(key, 0.0) + stream.rate.value
            else:
                rates_by_egress[(document.spec.ports.tx, document.spec.rate.unit)] = (
                    document.spec.rate.value
                )
                if document.spec.ports.direction == "bidirectional":
                    rates_by_egress[(document.spec.ports.rx, document.spec.rate.unit)] = (
                        document.spec.rate.value
                    )
            for (egress, unit), value in rates_by_egress.items():
                if value > policy.rate_ceiling(unit):
                    raise TrexCliError(
                        code="UNSAFE_REQUEST",
                        category="POLICY",
                        message=f"{unit} exceeds the configured per-egress SafetyPolicy maximum",
                        details={"egress": egress, "resolvedValue": value},
                    )
        if isinstance(document, PcapReplayDocument):
            timing = document.spec.timing
            if isinstance(timing, ReplayFixedRateTiming):
                if timing.rate.value > policy.rate_ceiling(timing.rate.unit):
                    raise TrexCliError(
                        code="UNSAFE_REQUEST",
                        category="POLICY",
                        message="PCAP replay rate exceeds the configured SafetyPolicy maximum",
                    )
                if timing.rate.unit == "pps":
                    estimated_seconds = document.spec.capture.packet_count / timing.rate.value
                elif timing.rate.unit == "bps_l2":
                    estimated_seconds = document.spec.capture.size * 8 / timing.rate.value
                elif timing.rate.unit == "bps_l1":
                    estimated_seconds = (
                        (document.spec.capture.size + 24 * document.spec.capture.packet_count)
                        * 8
                        / timing.rate.value
                    )
                else:
                    raise TrexCliError(
                        code="UNSAFE_REQUEST",
                        category="POLICY",
                        message="fixed-rate PCAP replay does not support percent_l1",
                    )
            elif isinstance(timing, ReplayCaptureTiming):
                if policy.max_percent_l1 < 100:
                    raise TrexCliError(
                        code="UNSAFE_REQUEST",
                        category="POLICY",
                        message=(
                            "capture timing requires maxPercentL1 100 because its peak rate "
                            "is unbounded"
                        ),
                    )
                estimated_seconds = (
                    document.spec.capture.normalized_duration_seconds / timing.multiplier
                )
            else:
                if policy.max_percent_l1 < 100:
                    raise TrexCliError(
                        code="UNSAFE_REQUEST",
                        category="POLICY",
                        message="top-speed replay requires maxPercentL1 100",
                    )
                estimated_seconds = 0.0
            if estimated_seconds * 1_000 > policy.max_run_duration:
                raise TrexCliError(
                    code="UNSAFE_REQUEST",
                    category="POLICY",
                    message="estimated PCAP replay duration exceeds maxRunDuration",
                    details={"estimatedDurationSeconds": estimated_seconds},
                )
            address = document.spec.address
            if isinstance(address, ReplayPreserveAddress):
                if address.policy_version != policy.version:
                    raise TrexCliError(
                        code="UNSAFE_REQUEST",
                        category="POLICY",
                        message=(
                            "preserve Replay Plan was frozen under a different SafetyPolicy version"
                        ),
                    )
                if document.spec.capture.has_broadcast or document.spec.capture.has_multicast:
                    raise TrexCliError(
                        code="UNSAFE_REQUEST",
                        category="POLICY",
                        message="preserve replay cannot contain broadcast or multicast packets",
                    )
        configured = set(self._config.logical_ports)
        requested = (
            document.spec.logical_ports()
            if isinstance(
                document,
                (
                    StatelessTrafficDocument,
                    PcapReplayDocument,
                    StatefulReplayDocument,
                    UdpWorkloadDocument,
                    PacketStormDocument,
                ),
            )
            else {document.spec.ports.tx, document.spec.ports.rx}
        )
        if not requested <= configured:
            missing = sorted(requested - configured)
            raise TrexCliError(
                code="CAPABILITY_MISMATCH",
                category="RESOURCE",
                message="the Job references unknown logical ports",
                details={"ports": missing},
            )

        allowed = [ipaddress.ip_network(cidr, strict=False) for cidr in policy.allowed_cidrs]
        if isinstance(document, StatefulReplayDocument):
            run = document.spec.run
            if run.duration > policy.max_run_duration:
                raise TrexCliError(
                    code="UNSAFE_REQUEST",
                    category="POLICY",
                    message="stateful replay duration exceeds maxRunDuration",
                )
            if run.cps > policy.max_cps:
                raise TrexCliError(
                    code="UNSAFE_REQUEST",
                    category="POLICY",
                    message="stateful replay CPS exceeds maxCps",
                )
            if run.max_active_connections > policy.max_active_connections:
                raise TrexCliError(
                    code="UNSAFE_REQUEST",
                    category="POLICY",
                    message="stateful replay active connection limit exceeds SafetyPolicy",
                )
            client_pool = document.spec.client.ipv4_pool
            server_pool = document.spec.server.ipv4_pool
            for label, pool in (("client", client_pool), ("server", server_pool)):
                if pool.cardinality > policy.max_address_pool_size:
                    raise TrexCliError(
                        code="ADDRESS_POOL_EXHAUSTED",
                        category="POLICY",
                        message=f"{label} IPv4 pool exceeds maxAddressPoolSize",
                    )
                if not ipv4_range_allowed(pool.start, pool.end, policy.allowed_cidrs):
                    raise TrexCliError(
                        code="UNSAFE_REQUEST",
                        category="POLICY",
                        message=f"{label} IPv4 pool is outside allowedCidrs",
                    )
            capacity = (
                client_pool.cardinality * document.spec.client.transport_port_pool.cardinality
            )
            if run.max_active_connections > capacity:
                raise TrexCliError(
                    code="PORT_POOL_EXHAUSTED",
                    category="RESOURCE",
                    message="maxActiveConnections exceeds client address/port capacity",
                )
        if isinstance(document, UdpWorkloadDocument):
            if document.spec.run.duration > policy.max_run_duration:
                raise TrexCliError(
                    code="UNSAFE_REQUEST",
                    category="POLICY",
                    message="UDP workload duration exceeds maxRunDuration",
                )
            if document.spec.run.estimated_pps > policy.max_pps:
                raise TrexCliError(
                    code="UNSAFE_REQUEST",
                    category="POLICY",
                    message="UDP workload estimatedPps exceeds maxPps",
                )
            if document.spec.run.estimated_bps_l1 > policy.max_bps_l1:
                raise TrexCliError(
                    code="UNSAFE_REQUEST",
                    category="POLICY",
                    message="UDP workload estimatedBpsL1 exceeds maxBpsL1",
                )
            mac_values = [document.spec.initiator.mac, document.spec.responder.mac]
            ip_values = [document.spec.initiator.ipv4, document.spec.responder.ipv4]
            if not policy.allow_arbitrary_unicast_mac:
                prefixes = [prefix.lower() for prefix in policy.allowed_mac_prefixes]
                if any(
                    not any(value.lower().startswith(prefix) for prefix in prefixes)
                    for value in mac_values
                ):
                    raise TrexCliError(
                        code="UNSAFE_REQUEST",
                        category="POLICY",
                        message="UDP workload MAC endpoint is outside allowedMacPrefixes",
                    )
            if any(
                not any(ipaddress.ip_address(value) in subnet for subnet in allowed)
                for value in ip_values
            ):
                raise TrexCliError(
                    code="UNSAFE_REQUEST",
                    category="POLICY",
                    message="UDP workload IPv4 endpoint is outside allowedCidrs",
                )
        if isinstance(document, PacketStormDocument):
            storm_run = document.spec.run
            if not document.spec.safety.isolated_lab:
                raise TrexCliError(
                    code="UNSAFE_REQUEST",
                    category="POLICY",
                    message="Packet Storm requires isolatedLab",
                )
            if (
                storm_run.duration > policy.max_run_duration
                or storm_run.duration > limits.job_timeout
            ):
                raise TrexCliError(
                    code="UNSAFE_REQUEST",
                    category="POLICY",
                    message="Packet Storm duration exceeds a configured limit",
                )
            if storm_run.pps > policy.max_pps:
                raise TrexCliError(
                    code="UNSAFE_REQUEST",
                    category="POLICY",
                    message="Packet Storm pps exceeds maxPps",
                )
            derived_bps_l1 = storm_run.pps * (storm_run.wire_size + 20) * 8
            if derived_bps_l1 > policy.max_bps_l1:
                raise TrexCliError(
                    code="UNSAFE_REQUEST",
                    category="POLICY",
                    message="Packet Storm estimatedBpsL1 exceeds maxBpsL1",
                )
            if isinstance(document.spec, DnsStormSpec):
                if document.spec.client.source_port_count > policy.max_address_pool_size:
                    raise TrexCliError(
                        code="PORT_POOL_EXHAUSTED",
                        category="POLICY",
                        message="DNS source port range exceeds maxAddressPoolSize",
                    )
                mac_values = [document.spec.client.mac, document.spec.server.mac]
                ip_values = [document.spec.client.ipv4, document.spec.server.ipv4]
                if not policy.allow_arbitrary_unicast_mac:
                    prefixes = [prefix.lower() for prefix in policy.allowed_mac_prefixes]
                    if any(
                        not any(value.lower().startswith(prefix) for prefix in prefixes)
                        for value in mac_values
                    ):
                        raise TrexCliError(
                            code="UNSAFE_REQUEST",
                            category="POLICY",
                            message="DNS storm MAC endpoint is outside allowedMacPrefixes",
                        )
                if any(
                    not any(ipaddress.ip_address(value) in subnet for subnet in allowed)
                    for value in ip_values
                ):
                    raise TrexCliError(
                        code="UNSAFE_REQUEST",
                        category="POLICY",
                        message="DNS storm IPv4 endpoint is outside allowedCidrs",
                    )
            elif isinstance(document.spec, DhcpStormSpec):
                if not policy.allow_broadcast_storms:
                    raise TrexCliError(
                        code="UNSAFE_REQUEST",
                        category="POLICY",
                        message="DHCP storm requires allowBroadcastStorms",
                    )
                if document.spec.clients.count > policy.max_address_pool_size:
                    raise TrexCliError(
                        code="ADDRESS_POOL_EXHAUSTED",
                        category="POLICY",
                        message="DHCP client identity pool exceeds maxAddressPoolSize",
                    )
                if not policy.allow_arbitrary_unicast_mac:
                    prefixes = [prefix.lower() for prefix in policy.allowed_mac_prefixes]
                    if not mac_range_allowed(
                        document.spec.clients.mac_start,
                        document.spec.clients.mac_end,
                        prefixes,
                    ):
                        raise TrexCliError(
                            code="UNSAFE_REQUEST",
                            category="POLICY",
                            message=("DHCP client identity pool is outside allowedMacPrefixes"),
                        )
            else:
                assert isinstance(document.spec, ArpStormSpec)
                if not policy.allow_broadcast_storms:
                    raise TrexCliError(
                        code="UNSAFE_REQUEST",
                        category="POLICY",
                        message="ARP storm requires allowBroadcastStorms",
                    )
                if document.spec.senders.count > policy.max_address_pool_size:
                    raise TrexCliError(
                        code="ADDRESS_POOL_EXHAUSTED",
                        category="POLICY",
                        message="ARP sender identity pool exceeds maxAddressPoolSize",
                    )
                if not policy.allow_arbitrary_unicast_mac:
                    prefixes = [prefix.lower() for prefix in policy.allowed_mac_prefixes]
                    if not mac_range_allowed(
                        document.spec.senders.mac_start,
                        document.spec.senders.mac_end,
                        prefixes,
                    ):
                        raise TrexCliError(
                            code="UNSAFE_REQUEST",
                            category="POLICY",
                            message="ARP sender identity pool is outside allowedMacPrefixes",
                        )
                sender_range_allowed = any(
                    ipaddress.ip_address(document.spec.senders.ipv4_start) in subnet
                    and ipaddress.ip_address(document.spec.senders.ipv4_end) in subnet
                    for subnet in allowed
                )
                if not sender_range_allowed or not any(
                    ipaddress.ip_address(document.spec.target.ipv4) in subnet
                    for subnet in allowed
                ):
                    raise TrexCliError(
                        code="UNSAFE_REQUEST",
                        category="POLICY",
                        message="ARP IPv4 endpoint is outside allowedCidrs",
                    )
        if isinstance(document, PcapReplayDocument):
            address = document.spec.address
            mac_values = (
                [address.source_mac, address.destination_mac]
                if isinstance(address, ReplayRewriteAddress)
                else document.spec.capture.mac_endpoints
            )
            ip_values = (
                [address.source_ipv4, address.destination_ipv4]
                if isinstance(address, ReplayRewriteAddress)
                else document.spec.capture.ipv4_endpoints
            )
            if not policy.allow_arbitrary_unicast_mac:
                prefixes = [prefix.lower() for prefix in policy.allowed_mac_prefixes]
                outside_macs = [
                    value
                    for value in mac_values
                    if not any(value.lower().startswith(prefix) for prefix in prefixes)
                ]
                if outside_macs:
                    raise TrexCliError(
                        code="UNSAFE_REQUEST",
                        category="POLICY",
                        message="PCAP replay MAC endpoint is outside allowedMacPrefixes",
                        details={"addresses": outside_macs},
                    )
            outside_ips = [
                value
                for value in ip_values
                if not any(ipaddress.ip_address(value) in subnet for subnet in allowed)
            ]
            if outside_ips:
                raise TrexCliError(
                    code="UNSAFE_REQUEST",
                    category="POLICY",
                    message="PCAP replay IPv4 endpoint is outside allowedCidrs",
                    details={"addresses": outside_ips},
                )
        packets = (
            []
            if isinstance(
                document,
                (
                    PcapReplayDocument,
                    StatefulReplayDocument,
                    UdpWorkloadDocument,
                    PacketStormDocument,
                ),
            )
            else (
                [stream.packet for stream in document.spec.streams]
                if isinstance(document, StatelessTrafficDocument) and document.spec.streams
                else [
                    document.spec.packet,
                    *(
                        [document.spec.reverse_packet]
                        if isinstance(document, (Rfc2544ThroughputDocument, Rfc2544SuiteDocument))
                        and document.spec.reverse_packet is not None
                        else []
                    ),
                ]
            )
        )
        for packet in packets:
            if not policy.allow_arbitrary_unicast_mac:
                prefixes = [prefix.lower() for prefix in policy.allowed_mac_prefixes]
                for mac_value in (packet.ethernet.src, packet.ethernet.dst):
                    macs = (
                        [mac_value]
                        if isinstance(mac_value, str)
                        else [mac_value.start, mac_value.end]
                    )
                    if not any(
                        all(mac.lower().startswith(prefix) for mac in macs) for prefix in prefixes
                    ):
                        raise TrexCliError(
                            code="UNSAFE_REQUEST",
                            category="POLICY",
                            message="MAC address range is outside configured allowedMacPrefixes",
                            details={"addresses": macs},
                        )
            network = packet.ipv4 or packet.ipv6
            if network is not None:
                for address_value in (network.src, network.dst):
                    addresses = (
                        [address_value]
                        if isinstance(address_value, str)
                        else [address_value.start, address_value.end]
                    )
                    for address_text in addresses:
                        parsed_address = ipaddress.ip_address(address_text)
                        if not any(parsed_address in subnet for subnet in allowed):
                            raise TrexCliError(
                                code="UNSAFE_REQUEST",
                                category="POLICY",
                                message=(
                                    f"address {parsed_address} is outside configured allowedCidrs"
                                ),
                            )

    async def _execute_with_deadline(
        self, job_id: str, remaining_seconds: float, fence: dict[str, int]
    ) -> None:
        try:
            await asyncio.wait_for(
                self._execute(job_id, remaining_seconds, fence), timeout=remaining_seconds
            )
        except TimeoutError:
            await self._fail(
                job_id,
                Problem(
                    code="JOB_TIMEOUT",
                    category="RESOURCE",
                    retryable=True,
                    message="the Job exceeded its resolved jobTimeout",
                ),
            )
            await self._database.release_ports(job_id)

    async def _execute(self, job_id: str, remaining_seconds: float, fence: dict[str, int]) -> None:
        handle: RunHandle | None = None
        cleanup_confirmed = True
        try:
            document = await self._document(job_id)
            marker = ExecutionMarker(
                marker_id="marker_" + uuid.uuid4().hex,
                job_id=job_id,
                session_id=self._session_id,
                logical_ports=tuple(sorted(fence)),
                fence=fence,
                hard_deadline=utc_now()
                + timedelta(seconds=_remote_hard_duration(document, remaining_seconds)),
            )
            await self._database.save_execution_marker(marker)
            cleanup_confirmed = False
            try:
                handle = await self._engine.prepare(marker, document)
            except Exception:
                # A returned error is the engine's atomic confirmation that prepare rolled back.
                # Cancellation is a BaseException: its remote side effects are uncertain, so the
                # marker remains for startup reconciliation.
                cleanup_confirmed = True
                raise
            cleanup_confirmed = False
            await self._phase(job_id, JobState.WARMING_UP, "warming-up", "WARMUP_STARTED", True)
            await self._engine.warmup(handle)
            if await self._cancelled(job_id, handle):
                return
            await self._phase(job_id, JobState.RUNNING, "run", "RUN_STARTED")

            async def report_progress(update: dict[str, Any]) -> None:
                completed = int(update.get("completedFrames", 0))
                total_value = update.get("totalFrames")
                total = int(total_value) if total_value is not None else None
                await self._transition(
                    job_id,
                    JobState.RUNNING,
                    "RUN_PROGRESS",
                    expected_states={JobState.RUNNING},
                    phase=Phase(name="run", detail=update),
                    progress=Progress(completed=completed, total=total),
                )

            measurement = await self._engine.run(handle, report_progress=report_progress)
            if await self._cancelled(job_id, handle):
                return
            await self._phase(job_id, JobState.DRAINING, "draining", "DRAIN_STARTED")
            await self._engine.stop(handle)
            await self._phase(job_id, JobState.COLLECTING, "collecting", "COLLECTION_STARTED")
            await self._engine.cleanup(handle)
            cleanup_confirmed = True
            await self._database.delete_execution_marker(job_id)
            handle = None
            current = await self._database.get_snapshot(job_id)
            resolved_json = await self._resolved_json(job_id)
            result = JobResult(
                verdict=measurement.verdict,
                methodology=measurement.methodology,
                summary=measurement.summary,
                provenance=Provenance(
                    submittedSpecDigest=current.submitted_spec_digest,
                    resolvedSpecDigest=current.resolved_spec_digest or "",
                    policyVersion=self._config.safety.version,
                    agentVersion=__version__,
                    simulated=self._engine.simulated,
                    engine=measurement.provenance.get("engine", self._engine.mode),
                    trexVersion=measurement.provenance.get("trexVersion"),
                ),
            )
            await self._record_calibrations(job_id, document, result)
            refs = await self._artifacts.build_result_bundle(
                snapshot=current,
                submitted_document=document.model_dump(
                    mode="json", by_alias=True, exclude_none=True
                ),
                resolved_document=json.loads(resolved_json),
                result=result,
            )
            result = result.model_copy(update={"artifacts": refs})
            latest = await self._database.get_snapshot(job_id)
            if latest.cancel_requested:
                await self._finish_cancel(job_id)
                return
            await self._transition(
                job_id,
                JobState.SUCCEEDED,
                "JOB_SUCCEEDED",
                expected_states={JobState.COLLECTING},
                phase=Phase(name="completed"),
                progress=Progress(completed=1, total=1),
                result=result,
                finished_at=utc_now(),
            )
        except asyncio.CancelledError:
            raise
        except TrexCliError as error:
            await self._fail(job_id, _problem(error))
        except Exception as error:
            await self._fail(
                job_id,
                Problem(
                    code="INTERNAL",
                    category="INTERNAL",
                    retryable=False,
                    message=str(error),
                ),
            )
        finally:
            if handle is not None:
                stopped = False
                cleaned = False
                try:
                    await self._engine.stop(handle, force=True)
                    stopped = True
                except Exception:
                    pass
                try:
                    await self._engine.cleanup(handle)
                    cleaned = True
                except Exception:
                    pass
                cleanup_confirmed = stopped and cleaned
            if cleanup_confirmed:
                await self._database.delete_execution_marker(job_id)
            await self._database.release_ports(job_id, quarantine=not cleanup_confirmed)

    async def _phase(
        self,
        job_id: str,
        state: JobState,
        name: str,
        event: str,
        started: bool = False,
    ) -> None:
        current = await self._database.get_snapshot(job_id)
        updated = await self._transition(
            job_id,
            state,
            event,
            expected_states={current.state},
            phase=Phase(name=name),
            started_at=utc_now() if started else None,
        )
        if updated is None:
            raise TrexCliError(
                code="LEASE_LOST",
                category="RESOURCE",
                message="the Job state changed while the engine was executing",
            )

    async def _cancelled(self, job_id: str, handle: RunHandle) -> bool:
        if not (await self._database.get_snapshot(job_id)).cancel_requested:
            return False
        await self._finish_cancel(job_id, handle)
        return True

    async def _finish_cancel(self, job_id: str, handle: RunHandle | None = None) -> None:
        try:
            current = await self._database.get_snapshot(job_id)
            if current.state.terminal:
                return
            if current.state != JobState.DRAINING:
                await self._transition(
                    job_id,
                    JobState.DRAINING,
                    "CANCEL_DRAIN_STARTED",
                    expected_states={current.state},
                    phase=Phase(name="cancelling-drain"),
                )
                if handle is not None:
                    await self._engine.stop(handle, force=True)
            current = await self._database.get_snapshot(job_id)
            if current.state != JobState.COLLECTING:
                await self._transition(
                    job_id,
                    JobState.COLLECTING,
                    "CANCEL_COLLECTION_STARTED",
                    expected_states={current.state},
                    phase=Phase(name="cancelling-collect"),
                )
                if handle is not None:
                    await self._engine.cleanup(handle)
            await self._transition(
                job_id,
                JobState.CANCELLED,
                "JOB_CANCELLED",
                expected_states={JobState.COLLECTING},
                phase=Phase(name="cancelled"),
                finished_at=utc_now(),
            )
        finally:
            if handle is None:
                await self._database.release_ports(job_id)

    async def _fail(
        self,
        job_id: str,
        problem: Problem,
        *,
        expected_states: set[JobState] | None = None,
    ) -> JobSnapshot | None:
        return await self._transition(
            job_id,
            JobState.FAILED,
            "JOB_FAILED",
            expected_states=expected_states,
            phase=Phase(name="failed"),
            problem=problem,
            finished_at=utc_now(),
        )

    async def _transition(
        self,
        job_id: str,
        state: JobState,
        event_type: str,
        *,
        expected_states: set[JobState] | None = None,
        phase: Phase | None = None,
        progress: Progress | None = None,
        result: JobResult | None = None,
        problem: Problem | None = None,
        resolved_spec_digest: str | None = None,
        resolved_spec_json: str | None = None,
        started_at: Any = None,
        finished_at: Any = None,
    ) -> JobSnapshot | None:
        for _ in range(3):
            current = await self._database.get_snapshot(job_id)
            if current.state.terminal:
                return current
            if expected_states is not None and current.state not in expected_states:
                return None
            if state == JobState.SUCCEEDED and current.cancel_requested:
                return None
            updates: dict[str, Any] = {
                "revision": current.revision + 1,
                "state": state,
            }
            if phase is not None:
                updates["phase"] = phase
            if progress is not None:
                updates["progress"] = progress
            if result is not None:
                updates["result"] = result
            if problem is not None:
                updates["problem"] = problem
            if resolved_spec_digest is not None:
                updates["resolved_spec_digest"] = resolved_spec_digest
            if started_at is not None and current.started_at is None:
                updates["started_at"] = started_at
            if finished_at is not None:
                updates["finished_at"] = finished_at
            updated = current.model_copy(update=updates)
            try:
                await self._database.update_snapshot(
                    updated,
                    expected_revision=current.revision,
                    event_type=event_type,
                    resolved_spec_json=resolved_spec_json,
                )
                if self._metrics is not None:
                    self._metrics.observe_job_transition(
                        kind=updated.kind,
                        previous=current.state,
                        current=updated.state,
                        event=event_type,
                    )
                log_fields: dict[str, Any] = {
                    "jobId": updated.job_id,
                    "kind": updated.kind,
                    "previousState": current.state,
                    "state": updated.state,
                    "eventType": event_type,
                    "revision": updated.revision,
                }
                if problem is not None:
                    log_fields["problemCode"] = problem.code
                _LOGGER.info("job_state_transition", extra=log_fields)
                await self._notify()
                return updated
            except RevisionConflict:
                continue
        return None

    async def _document(self, job_id: str) -> JobDocument:
        return JOB_DOCUMENT_ADAPTER.validate_json(await self._database.get_document_json(job_id))

    async def _resolved_json(self, job_id: str) -> str:
        document = await self._document(job_id)
        resolved = {
            "document": document.model_dump(mode="json", by_alias=True, exclude_none=True),
            "policyVersion": self._config.safety.version,
            "engine": {"mode": self._engine.mode, "simulated": self._engine.simulated},
        }
        return json.dumps(resolved, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _new_job_id() -> str:
    return "job_" + uuid.uuid4().hex.upper()


def _remote_hard_duration(document: JobDocument, remaining_seconds: float) -> float:
    if isinstance(document, StatelessTrafficDocument) and document.spec.duration is not None:
        return min(remaining_seconds, document.spec.duration / 1_000 + 5)
    if isinstance(document, StatefulReplayDocument):
        return min(remaining_seconds, document.spec.run.duration / 1_000 + 30)
    if isinstance(document, UdpWorkloadDocument):
        return min(remaining_seconds, document.spec.run.duration / 1_000 + 5)
    if isinstance(document, PacketStormDocument):
        return min(remaining_seconds, document.spec.run.duration / 1_000 + 5)
    return remaining_seconds


def _problem(error: TrexCliError) -> Problem:
    category = error.category
    if category not in {"INPUT", "POLICY", "RESOURCE", "ENGINE", "OBSERVATION", "INTERNAL"}:
        category = "INTERNAL"
    return Problem(
        code=error.code,
        category=category,  # type: ignore[arg-type]
        retryable=error.retryable,
        message=error.message,
        details=error.details,
    )
