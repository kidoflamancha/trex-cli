from __future__ import annotations

import asyncio
import importlib
import ipaddress
import os
import sys
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trex_cli.async_compat import to_thread
from trex_cli.config import RemoteTrexAstfEngineConfig
from trex_cli.engine import (
    EngineMeasurement,
    EngineStatus,
    ExecutionMarker,
    ReconcileResult,
    RunHandle,
)
from trex_cli.errors import TrexCliError
from trex_cli.models import (
    JobDocument,
    StatefulReplayDocument,
    StatefulWorkloadTemplateBinding,
    Verdict,
)
from trex_cli.pcap_catalog import CaptureCatalog
from trex_cli.session_analysis import SessionTemplate, extract_session_template


@dataclass(slots=True)
class _PreparedTemplate:
    id: str
    capture: SessionTemplate
    server_port: int
    cps: float
    max_active_connections: int
    occurrence_count: int
    weight: float
    traffic_group: str | None
    server_ip_start: str = ""
    server_ip_end: str = ""


@dataclass(slots=True)
class _AstfSession:
    client: Any
    document: StatefulReplayDocument
    templates: tuple[_PreparedTemplate, ...]
    version: str
    stopped: bool = False
    control_lost: bool = False


class RemoteTrexAstfEngine:
    mode = "remote-astf"
    simulated = False

    def __init__(
        self,
        config: RemoteTrexAstfEngineConfig,
        *,
        capture_root: Path | None,
        client_factory: Callable[..., Any] | None = None,
        client_api: Any | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._config = config
        self._capture_root = capture_root
        self._client_factory = client_factory
        self._api = client_api
        self._sleep = sleep
        self._sessions: dict[str, _AstfSession] = {}

    async def probe(self) -> EngineStatus:
        try:
            return await to_thread(self._probe_sync)
        except Exception as error:
            return EngineStatus(
                available=False,
                details={"mode": self.mode, "error": str(error)},
            )

    async def validate(self, document: JobDocument) -> None:
        if not isinstance(document, StatefulReplayDocument):
            raise TrexCliError(
                code="CAPABILITY_MISMATCH",
                category="ENGINE",
                message="remote-astf only accepts StatefulReplay Jobs",
            )
        await to_thread(self._validate_sync, document)

    async def prepare(self, marker: ExecutionMarker, document: JobDocument) -> RunHandle:
        if not isinstance(document, StatefulReplayDocument):
            raise TrexCliError(
                code="CAPABILITY_MISMATCH",
                category="ENGINE",
                message="remote-astf only accepts StatefulReplay Jobs",
            )
        try:
            session = await to_thread(self._prepare_sync, marker, document)
        except TrexCliError:
            raise
        except Exception as error:
            raise self._client_error("could not prepare ASTF execution", error) from error
        handle = RunHandle(f"{marker.job_id}:{uuid.uuid4().hex}")
        self._sessions[handle.id] = session
        return handle

    async def warmup(self, handle: RunHandle) -> None:
        self._session(handle)

    async def run(
        self,
        handle: RunHandle,
        *,
        report_progress: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> EngineMeasurement:
        session = self._session(handle)
        try:
            await to_thread(self._start_sync, session)
        except Exception as error:
            raise self._client_error("could not start ASTF execution", error) from error
        await self._sleep(session.document.spec.run.duration / 1_000 + 0.25)
        try:
            measurement = await to_thread(self._finish_sync, session)
        except Exception as error:
            raise self._client_error("could not collect ASTF execution", error) from error
        if report_progress is not None:
            await report_progress(
                {
                    "completedConnections": measurement.summary["attemptedConnections"],
                    "totalConnections": measurement.summary["attemptedConnections"],
                }
            )
        return measurement

    async def stop(self, handle: RunHandle, *, force: bool = False) -> None:
        del force
        session = self._session(handle)
        if not session.stopped:
            try:
                await asyncio.wait_for(
                    to_thread(session.client.stop, True),
                    timeout=self._config.timeout_seconds,
                )
            except TimeoutError as error:
                session.control_lost = True
                timeout = TimeoutError(
                    f"ASTF stop timed out after {self._config.timeout_seconds} seconds"
                )
                raise self._client_error("could not stop ASTF execution", timeout) from error
            except Exception as error:
                raise self._client_error("could not stop ASTF execution", error) from error
            session.stopped = True

    async def cleanup(self, handle: RunHandle) -> None:
        session = self._sessions.get(handle.id)
        if session is None:
            return
        try:
            if session.control_lost:
                raise TrexCliError(
                    code="TREX_TIMEOUT",
                    category="ENGINE",
                    retryable=True,
                    message="ASTF cleanup was skipped after control of the client session was lost",
                )
            try:
                await asyncio.wait_for(
                    to_thread(self._cleanup_sync, session),
                    timeout=self._config.timeout_seconds,
                )
            except TimeoutError as error:
                session.control_lost = True
                timeout = TimeoutError(
                    f"ASTF cleanup timed out after {self._config.timeout_seconds} seconds"
                )
                raise self._client_error("could not clean up ASTF execution", timeout) from error
        finally:
            self._sessions.pop(handle.id, None)

    def _cleanup_sync(self, session: _AstfSession) -> None:
        errors: list[Exception] = []
        try:
            session.client.clear_profile(True)
        except Exception as error:
            errors.append(error)
        try:
            session.client.release(False)
        except Exception as error:
            errors.append(error)
        try:
            session.client.disconnect()
        except Exception as error:
            errors.append(error)
        if errors:
            raise self._client_error("could not clean up ASTF execution", errors[0])

    async def reconcile(self, marker: ExecutionMarker, document: JobDocument) -> ReconcileResult:
        del marker, document
        return ReconcileResult(
            confirmed_idle=False,
            details={
                "mode": self.mode,
                "reason": "ASTF ownership cannot be proven after client session loss",
            },
        )

    def _validate_sync(self, document: StatefulReplayDocument) -> tuple[_PreparedTemplate, ...]:
        if self._capture_root is None:
            raise TrexCliError(
                code="CAPABILITY_MISMATCH",
                category="RESOURCE",
                message="stateful replay requires an Agent captureRoot",
            )
        capture_path = CaptureCatalog(self._capture_root).object_path(document.spec.capture.digest)
        if not capture_path.is_file() or capture_path.stat().st_size != document.spec.capture.size:
            raise TrexCliError(
                code="CAPABILITY_MISMATCH",
                category="RESOURCE",
                message="the frozen Capture Resource object is unavailable or changed",
            )
        prepared: list[_PreparedTemplate] = []
        workload = document.spec.workload
        if workload is None:
            session = document.spec.session
            assert session is not None
            template = extract_session_template(capture_path, session.id)
            if template.digest != session.digest:
                raise TrexCliError(
                    code="RESOURCE_CHANGED",
                    category="RESOURCE",
                    message="the extracted Session Template digest does not match the Plan",
                )
            prepared.append(
                _PreparedTemplate(
                    id="template_" + template.template_digest.removeprefix("sha256:")[:24],
                    capture=template,
                    server_port=session.server_port,
                    cps=document.spec.run.cps,
                    max_active_connections=document.spec.run.max_active_connections,
                    occurrence_count=1,
                    weight=1,
                    traffic_group=None,
                )
            )
        else:
            for binding in workload.templates:
                template = extract_session_template(
                    capture_path,
                    binding.representative_session.id,
                )
                if template.digest != binding.representative_session.digest:
                    raise TrexCliError(
                        code="RESOURCE_CHANGED",
                        category="RESOURCE",
                        message="a representative Session digest does not match the Plan",
                        details={"templateId": binding.id},
                    )
                if template.template_digest != binding.digest:
                    raise TrexCliError(
                        code="RESOURCE_CHANGED",
                        category="RESOURCE",
                        message="an extracted workload template digest does not match the Plan",
                        details={"templateId": binding.id},
                    )
                prepared.append(self._prepared_workload_template(binding, template))
        client_port = self._physical_port(document.spec.client.port)
        server_port = self._physical_port(document.spec.server.port)
        if client_port % 2 or server_port != client_port + 1:
            raise TrexCliError(
                code="CAPABILITY_MISMATCH",
                category="RESOURCE",
                message="ASTF requires client/server roles on an even/odd adjacent TRex port pair",
            )
        transport_pool = document.spec.client.transport_port_pool
        if transport_pool.start != 1024 or transport_pool.end != 65_535:
            raise TrexCliError(
                code="CAPABILITY_MISMATCH",
                category="ENGINE",
                message="TRex ASTF v3.08 only supports its managed 1024-65535 client port pool",
            )
        return tuple(prepared)

    @staticmethod
    def _prepared_workload_template(
        binding: StatefulWorkloadTemplateBinding,
        template: SessionTemplate,
    ) -> _PreparedTemplate:
        return _PreparedTemplate(
            id=binding.id,
            capture=template,
            server_port=binding.representative_session.server_port,
            cps=binding.cps,
            max_active_connections=binding.max_active_connections,
            occurrence_count=binding.occurrence_count,
            weight=binding.weight,
            traffic_group="tg_" + binding.id.removeprefix("template_")[:16],
        )

    def _prepare_sync(
        self, marker: ExecutionMarker, document: StatefulReplayDocument
    ) -> _AstfSession:
        templates = self._validate_sync(document)
        api = self._load_api()
        client = self._new_client(api, username=self._owner(marker))
        acquired = False
        try:
            client.connect()
            expected_ports = max(self._config.port_mapping.values()) + 1
            if client.get_port_count() < expected_ports:
                raise TrexCliError(
                    code="CAPABILITY_MISMATCH",
                    category="RESOURCE",
                    message="engine.portMapping references a TRex port that does not exist",
                )
            port_info = client.get_port_info()
            client_port = self._physical_port(document.spec.client.port)
            server_port = self._physical_port(document.spec.server.port)
            data_path_threads = max(
                len(port_info[client_port].get("cores", [])),
                len(port_info[server_port].get("cores", [])),
            )
            if (
                document.spec.client.ipv4_pool.cardinality <= data_path_threads
                or document.spec.server.ipv4_pool.cardinality <= data_path_threads
            ):
                raise TrexCliError(
                    code="ADDRESS_POOL_EXHAUSTED",
                    category="RESOURCE",
                    message=(
                        "each ASTF IPv4 pool must contain more addresses than data-path threads"
                    ),
                    details={"dataPathThreads": data_path_threads},
                )
            self._assign_server_ranges(document, templates, data_path_threads)
            client.acquire(force=False)
            acquired = True
            profile = self._build_profile(api, document, templates)
            client.load_profile(profile)
            version_data = client.get_server_version()
            version = str(version_data.get("Version", version_data.get("version", "unknown")))
            return _AstfSession(
                client=client,
                document=document,
                templates=templates,
                version=version,
            )
        except Exception:
            if acquired:
                try:
                    client.release(False)
                except Exception:
                    pass
            try:
                client.disconnect()
            except Exception:
                pass
            raise

    @staticmethod
    def _assign_server_ranges(
        document: StatefulReplayDocument,
        templates: tuple[_PreparedTemplate, ...],
        data_path_threads: int,
    ) -> None:
        chunk_size = data_path_threads + 1
        pool_start = int(ipaddress.IPv4Address(document.spec.server.ipv4_pool.start))
        pool_size = document.spec.server.ipv4_pool.cardinality
        groups: dict[int, list[_PreparedTemplate]] = {}
        for template in templates:
            groups.setdefault(template.server_port, []).append(template)
        required = max(len(group) * chunk_size for group in groups.values())
        if required > pool_size:
            raise TrexCliError(
                code="ADDRESS_POOL_EXHAUSTED",
                category="RESOURCE",
                message=("server IPv4 pool cannot disambiguate workload templates sharing a port"),
                details={
                    "requiredAddresses": required,
                    "availableAddresses": pool_size,
                    "dataPathThreads": data_path_threads,
                },
            )
        for group in groups.values():
            for index, template in enumerate(sorted(group, key=lambda item: item.id)):
                start = pool_start + index * chunk_size
                template.server_ip_start = str(ipaddress.IPv4Address(start))
                template.server_ip_end = str(ipaddress.IPv4Address(start + chunk_size - 1))

    @staticmethod
    def _build_profile(
        api: Any,
        document: StatefulReplayDocument,
        templates: tuple[_PreparedTemplate, ...],
    ) -> Any:
        client_distribution = api.ASTFIPGenDist(
            ip_range=[
                document.spec.client.ipv4_pool.start,
                document.spec.client.ipv4_pool.end,
            ],
            distribution="seq",
        )
        profile_templates = []
        ip_generators = []
        for template in templates:
            client_program = api.ASTFProgram()
            server_program = api.ASTFProgram()
            for direction, payload in template.capture.exchanges:
                if direction == "client":
                    client_program.send(payload)
                    server_program.recv(len(payload))
                else:
                    client_program.recv(len(payload))
                    server_program.send(payload)
            server_distribution = api.ASTFIPGenDist(
                ip_range=[template.server_ip_start, template.server_ip_end],
                distribution="seq",
            )
            ip_generator = api.ASTFIPGen(
                glob=api.ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                dist_client=client_distribution,
                dist_server=server_distribution,
            )
            ip_generators.append(ip_generator)
            client_template = api.ASTFTCPClientTemplate(
                program=client_program,
                ip_gen=ip_generator,
                port=template.server_port,
                cps=template.cps,
                limit=template.max_active_connections,
                cont=True,
            )
            server_template = api.ASTFTCPServerTemplate(
                program=server_program,
                assoc=api.ASTFAssociationRule(
                    port=template.server_port,
                    ip_start=template.server_ip_start,
                    ip_end=template.server_ip_end,
                ),
            )
            profile_templates.append(
                api.ASTFTemplate(
                    client_template=client_template,
                    server_template=server_template,
                    tg_name=template.traffic_group,
                )
            )
        return api.ASTFProfile(
            default_ip_gen=ip_generators[0],
            templates=profile_templates,
        )

    @staticmethod
    def _start_sync(session: _AstfSession) -> None:
        client = session.client
        document = session.document
        duration = document.spec.run.duration / 1_000
        client.clear_stats()
        client.start(
            mult=1,
            duration=duration,
            nc=False,
            e_duration=20.0,
            t_duration=20.0,
            block=False,
        )

    @staticmethod
    def _finish_sync(session: _AstfSession) -> EngineMeasurement:
        client = session.client
        document = session.document
        duration = document.spec.run.duration / 1_000
        if not session.stopped:
            client.stop(True)
            session.stopped = True
        stats = client.get_stats()
        traffic = stats.get("traffic", {})
        values = RemoteTrexAstfEngine._traffic_values(
            traffic.get("client", {}),
            traffic.get("server", {}),
            duration,
        )
        warnings = [str(item) for item in client.get_warnings()]
        workload = document.spec.workload
        if workload is not None:
            traffic_groups = [
                template.traffic_group
                for template in session.templates
                if template.traffic_group is not None
            ]
            group_stats = client.get_traffic_tg_stats(traffic_groups)
            template_results = []
            for template in session.templates:
                assert template.traffic_group is not None
                template_stats = group_stats.get(template.traffic_group, {})
                template_values = RemoteTrexAstfEngine._traffic_values(
                    template_stats.get("client", {}),
                    template_stats.get("server", {}),
                    duration,
                )
                template_results.append(
                    {
                        "id": template.id,
                        "digest": template.capture.template_digest,
                        "trafficGroup": template.traffic_group,
                        "occurrenceCount": template.occurrence_count,
                        "weight": template.weight,
                        "cps": template.cps,
                        "maxActiveConnections": template.max_active_connections,
                        **template_values,
                    }
                )
            return EngineMeasurement(
                verdict=Verdict.NO_ASSERTION,
                methodology="trex-astf-capture-workload/v1",
                summary={
                    "simulated": False,
                    "selection": workload.selection,
                    "sourceSessionCount": workload.source_session_count,
                    "templateCount": workload.template_count,
                    **values,
                    "templates": template_results,
                    "semanticDifferences": document.spec.semantic_differences,
                    "warnings": warnings,
                },
                provenance={"engine": "remote-astf", "trexVersion": session.version},
            )
        selected = document.spec.session
        assert selected is not None
        return EngineMeasurement(
            verdict=Verdict.NO_ASSERTION,
            methodology="trex-astf-stateful-replay/v1",
            summary={
                "simulated": False,
                "sessionId": selected.id,
                **values,
                "semanticDifferences": document.spec.semantic_differences,
                "warnings": warnings,
            },
            provenance={"engine": "remote-astf", "trexVersion": session.version},
        )

    @staticmethod
    def _traffic_values(
        client_stats: dict[str, Any],
        server_stats: dict[str, Any],
        duration: float,
    ) -> dict[str, int | float]:
        attempted = int(client_stats.get("tcps_connattempt", 0))
        established = int(client_stats.get("tcps_connects", 0))
        tx_bytes = int(client_stats.get("tcps_sndbyte", 0))
        rx_bytes = int(client_stats.get("tcps_rcvbyte", 0))
        return {
            "attemptedConnections": attempted,
            "establishedConnections": established,
            "failedConnections": max(0, attempted - established),
            "closedConnections": int(client_stats.get("tcps_closed", 0)),
            "applicationTxBytes": tx_bytes,
            "applicationRxBytes": rx_bytes,
            "serverApplicationRxBytes": int(server_stats.get("tcps_rcvbyte", 0)),
            "serverApplicationTxBytes": int(server_stats.get("tcps_sndbyte", 0)),
            "throughputBps": (tx_bytes + rx_bytes) * 8 / duration,
        }

    def _probe_sync(self) -> EngineStatus:
        api = self._load_api()
        client = self._new_client(api)
        try:
            client.connect()
            version_data = client.get_server_version()
            return EngineStatus(
                available=True,
                details={
                    "mode": self.mode,
                    "trexVersion": str(
                        version_data.get("Version", version_data.get("version", "unknown"))
                    ),
                    "portCount": client.get_port_count(),
                },
            )
        finally:
            client.disconnect()

    def _new_client(self, api: Any, *, username: str | None = None) -> Any:
        factory = self._client_factory or api.ASTFClient
        return factory(
            server=self._config.server,
            sync_port=self._config.sync_port,
            async_port=self._config.async_port,
            username=username or f"{self._config.username[:24]}-probe",
            verbose_level="error",
            sync_timeout=self._config.timeout_seconds,
        )

    def _load_api(self) -> Any:
        if self._api is not None:
            return self._api
        if not self._config.client_path.is_dir():
            raise TrexCliError(
                code="TREX_UNAVAILABLE",
                category="ENGINE",
                message=f"TRex clientPath does not exist: {self._config.client_path}",
            )
        os.environ["TREX_EXT_LIBS"] = str(self._config.external_libs_path)
        client_path = str(self._config.client_path)
        if client_path not in sys.path:
            sys.path.insert(0, client_path)
        self._api = importlib.import_module("trex.astf.api")
        return self._api

    def _physical_port(self, logical_port: str) -> int:
        try:
            return self._config.port_mapping[logical_port]
        except KeyError as error:
            raise TrexCliError(
                code="CAPABILITY_MISMATCH",
                category="RESOURCE",
                message=f"engine.portMapping has no logical port {logical_port}",
            ) from error

    def _session(self, handle: RunHandle) -> _AstfSession:
        try:
            return self._sessions[handle.id]
        except KeyError as error:
            raise TrexCliError(
                code="LEASE_LOST",
                category="ENGINE",
                message="the ASTF run handle is no longer active",
            ) from error

    @staticmethod
    def _owner(marker: ExecutionMarker) -> str:
        return f"trex-cli:{marker.session_id[:12]}:{marker.job_id[-12:]}"

    @staticmethod
    def _client_error(message: str, error: Exception) -> TrexCliError:
        cause = str(error)
        lowered = cause.lower()
        if "acquir" in lowered or "owned" in lowered:
            code, category, retryable = "PORT_BUSY", "RESOURCE", True
        elif "timeout" in lowered or "timed out" in lowered:
            code, category, retryable = "TREX_TIMEOUT", "ENGINE", True
        else:
            code, category, retryable = "TREX_ERROR", "ENGINE", False
        return TrexCliError(
            code=code,
            category=category,
            retryable=retryable,
            message=message,
            details={"cause": cause},
        )
