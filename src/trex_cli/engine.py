from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from trex_cli.config import SafetyPolicy
from trex_cli.models import (
    ArpStormSpec,
    DhcpStormSpec,
    DnsStormSpec,
    JobDocument,
    PacketStormDocument,
    PcapReplayDocument,
    Rfc2544SuiteDocument,
    Rfc2544ThroughputDocument,
    StatefulReplayDocument,
    StatelessTrafficDocument,
    UdpWorkloadDocument,
    Verdict,
)
from trex_cli.publication import assess_rfc2544_publication


class Clock(Protocol):
    async def sleep(self, seconds: float) -> None: ...


class RealClock:
    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


@dataclass(frozen=True, slots=True)
class EngineMeasurement:
    verdict: Verdict
    methodology: str
    summary: dict[str, Any]
    provenance: dict[str, str]


@dataclass(frozen=True, slots=True)
class EngineStatus:
    available: bool
    details: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ExecutionMarker:
    marker_id: str
    job_id: str
    session_id: str
    logical_ports: tuple[str, ...]
    fence: dict[str, int]
    hard_deadline: datetime


@dataclass(frozen=True, slots=True)
class ReconcileResult:
    confirmed_idle: bool
    details: dict[str, Any]


@dataclass(frozen=True, slots=True)
class RunHandle:
    id: str


class TrafficEngine(Protocol):
    mode: str
    simulated: bool

    async def probe(self) -> EngineStatus: ...
    async def validate(self, document: JobDocument) -> None: ...
    async def prepare(self, marker: ExecutionMarker, document: JobDocument) -> RunHandle: ...
    async def warmup(self, handle: RunHandle) -> None: ...
    async def run(
        self,
        handle: RunHandle,
        *,
        report_progress: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> EngineMeasurement: ...
    async def stop(self, handle: RunHandle, *, force: bool = False) -> None: ...
    async def cleanup(self, handle: RunHandle) -> None: ...
    async def reconcile(
        self, marker: ExecutionMarker, document: JobDocument
    ) -> ReconcileResult: ...


class SimulatedEngine:
    mode = "simulated"
    simulated = True

    def __init__(
        self, policy: SafetyPolicy, step_delay_ms: int, clock: Clock | None = None
    ) -> None:
        self._policy = policy
        self._step_delay = step_delay_ms / 1_000
        self._clock = clock or RealClock()
        self._documents: dict[str, JobDocument] = {}

    async def _step(self) -> None:
        await self._clock.sleep(self._step_delay)

    async def probe(self) -> EngineStatus:
        return EngineStatus(available=True, details={"mode": self.mode})

    async def validate(self, document: JobDocument) -> None:
        del document

    async def prepare(self, marker: ExecutionMarker, document: JobDocument) -> RunHandle:
        handle = RunHandle(f"{marker.job_id}:{uuid.uuid4().hex}")
        self._documents[handle.id] = document
        await self._step()
        return handle

    async def warmup(self, handle: RunHandle) -> None:
        await self._step()

    async def run(
        self,
        handle: RunHandle,
        *,
        report_progress: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> EngineMeasurement:
        del report_progress
        await self._step()
        return self._measure(self._documents[handle.id])

    async def stop(self, handle: RunHandle, *, force: bool = False) -> None:
        del handle, force
        await self._step()

    async def cleanup(self, handle: RunHandle) -> None:
        self._documents.pop(handle.id, None)
        await self._step()

    async def reconcile(self, marker: ExecutionMarker, document: JobDocument) -> ReconcileResult:
        del marker, document
        return ReconcileResult(confirmed_idle=True, details={"mode": self.mode})

    def _measure(self, document: JobDocument) -> EngineMeasurement:
        if isinstance(document, StatelessTrafficDocument):
            verdict = Verdict.PASS if document.spec.assertions is not None else Verdict.NO_ASSERTION
            return EngineMeasurement(
                verdict=verdict,
                methodology="simulated-stateless/v1",
                summary={
                    "simulated": True,
                    "targetRateReached": True,
                    "txFrames": 100_000,
                    "rxFrames": 100_000,
                    "lossFrames": 0,
                    "lossPercent": 0,
                },
                provenance={},
            )

        if isinstance(document, PcapReplayDocument):
            timing = document.spec.timing.model_dump(mode="json", by_alias=True, exclude_none=True)
            address = document.spec.address.model_dump(
                mode="json", by_alias=True, exclude_none=True
            )
            return EngineMeasurement(
                verdict=Verdict.NO_ASSERTION,
                methodology="simulated-pcap-replay/v1",
                summary={
                    "simulated": True,
                    "capture": {
                        "name": document.spec.capture.name,
                        "revision": document.spec.capture.revision,
                        "digest": document.spec.capture.digest,
                    },
                    "address": address,
                    "timing": timing,
                    "txFrames": document.spec.capture.packet_count,
                    "rxFrames": document.spec.capture.packet_count,
                    "lossFrames": 0,
                    "lossPercent": 0.0,
                },
                provenance={},
            )

        if isinstance(document, UdpWorkloadDocument):
            duration_seconds = document.spec.run.duration / 1_000
            templates = []
            initiator_datagrams = 0
            responder_datagrams = 0
            flow_instances = 0
            for udp_template in document.spec.workload.templates:
                instances = int(udp_template.fps * duration_seconds)
                flow = udp_template.representative_flow
                initiator_count = instances * flow.initiator_datagram_count
                responder_count = instances * flow.responder_datagram_count
                flow_instances += instances
                initiator_datagrams += initiator_count
                responder_datagrams += responder_count
                templates.append(
                    {
                        "id": udp_template.id,
                        "digest": udp_template.digest,
                        "occurrenceCount": udp_template.occurrence_count,
                        "weight": udp_template.weight,
                        "fps": udp_template.fps,
                        "flowInstances": instances,
                        "txDatagrams": initiator_count + responder_count,
                        "rxDatagrams": initiator_count + responder_count,
                        "initiatorPayloadBytes": (instances * flow.initiator_payload_bytes),
                        "responderPayloadBytes": (instances * flow.responder_payload_bytes),
                    }
                )
            return EngineMeasurement(
                verdict=Verdict.NO_ASSERTION,
                methodology="simulated-stl-datagram-workload/v1",
                summary={
                    "simulated": True,
                    "selection": document.spec.workload.selection,
                    "sourceFlowCount": document.spec.workload.source_flow_count,
                    "templateCount": document.spec.workload.template_count,
                    "flowInstances": flow_instances,
                    "txDatagrams": initiator_datagrams + responder_datagrams,
                    "rxDatagrams": initiator_datagrams + responder_datagrams,
                    "directions": {
                        "initiator-to-responder": {
                            "txDatagrams": initiator_datagrams,
                            "rxDatagrams": initiator_datagrams,
                        },
                        "responder-to-initiator": {
                            "txDatagrams": responder_datagrams,
                            "rxDatagrams": responder_datagrams,
                        },
                    },
                    "templates": templates,
                    "semanticDifferences": document.spec.semantic_differences,
                },
                provenance={},
            )

        if isinstance(document, PacketStormDocument):
            frames = int(document.spec.run.pps * document.spec.run.duration / 1_000)
            if isinstance(document.spec, ArpStormSpec):
                return EngineMeasurement(
                    verdict=Verdict.NO_ASSERTION,
                    methodology="simulated-arp-request-storm/v1",
                    summary={
                        "simulated": True,
                        "protocol": document.spec.protocol,
                        "messageType": document.spec.message.operation,
                        "senderIdentities": document.spec.senders.count,
                        "requestsTx": frames,
                        "transmissionValid": True,
                        "counterSource": document.spec.observation.request_transmission,
                        "requestDeliveryObservation": document.spec.observation.request_delivery,
                        "replyObservation": document.spec.observation.replies,
                        "limitation": document.spec.observation.limitation,
                    },
                    provenance={},
                )
            if isinstance(document.spec, DhcpStormSpec):
                return EngineMeasurement(
                    verdict=Verdict.NO_ASSERTION,
                    methodology="simulated-dhcp-discover-storm/v1",
                    summary={
                        "simulated": True,
                        "protocol": document.spec.protocol,
                        "messageType": document.spec.message.type,
                        "clientIdentities": document.spec.clients.count,
                        "discoversTx": frames,
                        "discoversRx": frames,
                        "lostDiscovers": 0,
                        "lossPercent": 0.0,
                        "observationValid": True,
                        "counterSource": document.spec.observation.discover_delivery,
                        "offerObservation": document.spec.observation.offers,
                    },
                    provenance={},
                )
            assert isinstance(document.spec, DnsStormSpec)
            question = document.spec.question
            return EngineMeasurement(
                verdict=Verdict.NO_ASSERTION,
                methodology="simulated-dns-query-storm/v1",
                summary={
                    "simulated": True,
                    "protocol": document.spec.protocol,
                    "question": {
                        "name": question.name,
                        "type": question.type,
                        "class": question.dns_class,
                    },
                    "queriesTx": frames,
                    "queriesRx": frames,
                    "lostQueries": 0,
                    "lossPercent": 0.0,
                    "observationValid": True,
                    "counterSource": document.spec.observation.query_delivery,
                    "responseObservation": document.spec.observation.responses,
                },
                provenance={},
            )

        if isinstance(document, StatefulReplayDocument):
            duration_seconds = document.spec.run.duration / 1_000
            workload = document.spec.workload
            if workload is not None:
                templates = []
                for template in workload.templates:
                    attempted = int(template.cps * duration_seconds)
                    representative = template.representative_session
                    templates.append(
                        {
                            "id": template.id,
                            "digest": template.digest,
                            "occurrenceCount": template.occurrence_count,
                            "weight": template.weight,
                            "cps": template.cps,
                            "maxActiveConnections": template.max_active_connections,
                            "attemptedConnections": attempted,
                            "establishedConnections": attempted,
                            "failedConnections": 0,
                            "closedConnections": attempted,
                            "applicationTxBytes": attempted * representative.client_payload_bytes,
                            "applicationRxBytes": attempted * representative.server_payload_bytes,
                        }
                    )
                return EngineMeasurement(
                    verdict=Verdict.NO_ASSERTION,
                    methodology="simulated-astf-capture-workload/v1",
                    summary={
                        "simulated": True,
                        "selection": workload.selection,
                        "sourceSessionCount": workload.source_session_count,
                        "templateCount": workload.template_count,
                        "attemptedConnections": sum(
                            item["attemptedConnections"] for item in templates
                        ),
                        "establishedConnections": sum(
                            item["establishedConnections"] for item in templates
                        ),
                        "failedConnections": 0,
                        "closedConnections": sum(item["closedConnections"] for item in templates),
                        "applicationTxBytes": sum(item["applicationTxBytes"] for item in templates),
                        "applicationRxBytes": sum(item["applicationRxBytes"] for item in templates),
                        "templates": templates,
                        "semanticDifferences": document.spec.semantic_differences,
                    },
                    provenance={},
                )
            session = document.spec.session
            assert session is not None
            attempted = int(document.spec.run.cps * duration_seconds)
            return EngineMeasurement(
                verdict=Verdict.NO_ASSERTION,
                methodology="simulated-astf-stateful-replay/v1",
                summary={
                    "simulated": True,
                    "sessionId": session.id,
                    "attemptedConnections": attempted,
                    "establishedConnections": attempted,
                    "failedConnections": 0,
                    "closedConnections": attempted,
                    "peakActiveConnections": min(
                        attempted, document.spec.run.max_active_connections
                    ),
                    "applicationTxBytes": attempted * session.client_payload_bytes,
                    "applicationRxBytes": attempted * session.server_payload_bytes,
                    "semanticDifferences": document.spec.semantic_differences,
                },
                provenance={},
            )

        if isinstance(document, Rfc2544SuiteDocument):
            return self._measure_rfc2544_suite(document)

        assert isinstance(document, Rfc2544ThroughputDocument)
        frame_sizes = (
            [64, 128, 256, 512, 1024, 1280, 1518]
            if document.spec.mode == "strict"
            else (document.spec.frame_sizes or [64, 512, 1518])
        )
        measured = self._policy.simulated_throughput_percent
        assertion = document.spec.assertion
        if assertion is None:
            verdict = Verdict.NO_ASSERTION
        else:
            passed = all(
                measured >= threshold
                for frame, threshold in assertion.minimum_percent_line_rate.items()
                if int(frame) in frame_sizes
            )
            verdict = Verdict.PASS if passed else Verdict.FAIL
        methodology = (
            "simulated-rfc2544-throughput-strict/v1"
            if document.spec.mode == "strict"
            else "simulated-engineering-throughput-estimate/v1"
        )
        summary: dict[str, Any] = {
            "simulated": True,
            "directionMode": document.spec.direction_mode or document.spec.ports.direction,
            "frameSizes": frame_sizes,
            "throughputPercentL1": {str(size): measured for size in frame_sizes},
            "lossFrames": {str(size): 0 for size in frame_sizes},
        }
        if document.spec.direction_mode == "unidirectional-each":
            summary["directions"] = {
                direction: {
                    "throughputPercentL1": {str(size): measured for size in frame_sizes},
                    "lossFrames": {str(size): 0 for size in frame_sizes},
                }
                for direction in ("forward", "reverse")
            }
        return EngineMeasurement(
            verdict=verdict,
            methodology=methodology,
            summary=summary,
            provenance={},
        )

    def _measure_rfc2544_suite(self, document: Rfc2544SuiteDocument) -> EngineMeasurement:
        frame_sizes = (
            [64, 128, 256, 512, 1024, 1280, 1518]
            if document.spec.mode == "strict"
            else (document.spec.frame_sizes or [64, 512, 1518])
        )
        measured = self._policy.simulated_throughput_percent
        tests: dict[str, Any] = {}
        verdict = Verdict.NO_ASSERTION
        if "throughput" in document.spec.tests:
            assertion = document.spec.assertion
            if assertion is not None:
                passed = all(
                    measured >= threshold
                    for frame, threshold in assertion.minimum_percent_line_rate.items()
                    if int(frame) in frame_sizes
                )
                verdict = Verdict.PASS if passed else Verdict.FAIL
            tests["throughput"] = {
                "methodology": (
                    "simulated-rfc2544-throughput-strict/v1"
                    if document.spec.mode == "strict"
                    else "simulated-engineering-throughput-estimate/v1"
                ),
                "verdict": verdict,
                "frameSizes": frame_sizes,
                "throughputPercentL1": {str(size): measured for size in frame_sizes},
                "lossFrames": {str(size): 0 for size in frame_sizes},
            }
        if "frame-loss" in document.spec.tests:
            points = [100.0, 90.0]
            tests["frame-loss"] = {
                "methodology": (
                    "simulated-rfc2544-frame-loss-strict/v1"
                    if document.spec.mode == "strict"
                    else "simulated-engineering-frame-loss-curve/v1"
                ),
                "verdict": Verdict.NO_ASSERTION,
                "frameSizes": frame_sizes,
                "frames": {
                    str(size): {
                        "valid": True,
                        "stoppedAfterTwoZeroLossTrials": True,
                        "points": [
                            {
                                "ratePercentL1": rate,
                                "lossFrames": 0,
                                "lossPercent": 0.0,
                            }
                            for rate in points
                        ],
                    }
                    for size in frame_sizes
                },
            }
        if "latency" in document.spec.tests:
            tests["latency"] = {
                "methodology": "simulated-rfc2544-latency-strict/v1",
                "verdict": Verdict.NO_ASSERTION,
                "definition": "store-and-forward",
                "trialDurationSeconds": 120,
                "repetitions": 20,
                "frames": {
                    str(size): {
                        "valid": True,
                        "samplesMicroseconds": [10.0] * 20,
                        "averageMicroseconds": 10.0,
                    }
                    for size in frame_sizes
                },
            }
        if "back-to-back" in document.spec.tests:
            tests["back-to-back"] = {
                "methodology": "simulated-rfc9004-back-to-back/v1",
                "verdict": Verdict.NO_ASSERTION,
                "searchAlgorithm": "binary-search-with-loss-verification",
                "repetitions": 20,
                "frames": {
                    str(size): {
                        "valid": True,
                        "averageFrames": 1000.0,
                        "minimumFrames": 1000,
                        "maximumFrames": 1000,
                        "standardDeviationFrames": 0.0,
                    }
                    for size in frame_sizes
                },
            }
        tests = {name: tests[name] for name in document.spec.tests}
        summary: dict[str, Any] = {
            "simulated": True,
            "mode": document.spec.mode,
            "directionMode": document.spec.direction_mode or document.spec.ports.direction,
            "reportContext": (
                document.spec.report_context.model_dump(
                    mode="json", by_alias=True, exclude_none=True
                )
                if document.spec.report_context is not None
                else None
            ),
            "tests": tests,
        }
        assessment = assess_rfc2544_publication(summary)
        summary.update(
            {
                "publicationStatus": assessment.status,
                "standardConformance": assessment.conformance,
                "publicationIssues": list(assessment.issues),
            }
        )
        return EngineMeasurement(
            verdict=verdict,
            methodology=(
                "simulated-rfc2544-suite-strict/v1"
                if document.spec.mode == "strict"
                else "simulated-engineering-rfc2544-suite/v1"
            ),
            summary=summary,
            provenance={},
        )
