from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import dpkt  # type: ignore[import-untyped]
from pydantic import Field

from trex_cli.models import StrictModel


class DatagramEndpoint(StrictModel):
    ipv4: str
    port: int = Field(ge=1, le=65_535)


class CapturedDatagramFlowAnalysis(StrictModel):
    id: str = Field(pattern=r"^udpflow_[0-9a-f]{24}$")
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    initiator: DatagramEndpoint
    responder: DatagramEndpoint
    datagram_count: int = Field(alias="datagramCount", ge=1)
    initiator_datagram_count: int = Field(alias="initiatorDatagramCount", ge=0)
    responder_datagram_count: int = Field(alias="responderDatagramCount", ge=0)
    initiator_payload_bytes: int = Field(alias="initiatorPayloadBytes", ge=0)
    responder_payload_bytes: int = Field(alias="responderPayloadBytes", ge=0)
    duration_microseconds: int = Field(alias="durationMicroseconds", ge=0)
    l1_bytes_per_flow: int = Field(alias="l1BytesPerFlow", ge=1)
    replayable: bool
    issues: list[str]


class DatagramWorkloadTemplateAnalysis(StrictModel):
    id: str = Field(pattern=r"^udptemplate_[0-9a-f]{24}$")
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    representative_flow_id: str = Field(
        alias="representativeFlowId", pattern=r"^udpflow_[0-9a-f]{24}$"
    )
    representative_flow_digest: str = Field(
        alias="representativeFlowDigest", pattern=r"^sha256:[0-9a-f]{64}$"
    )
    responder_port: int = Field(alias="responderPort", ge=1, le=65_535)
    datagram_count: int = Field(alias="datagramCount", ge=1)
    initiator_datagram_count: int = Field(alias="initiatorDatagramCount", ge=0)
    responder_datagram_count: int = Field(alias="responderDatagramCount", ge=0)
    initiator_payload_bytes: int = Field(alias="initiatorPayloadBytes", ge=0)
    responder_payload_bytes: int = Field(alias="responderPayloadBytes", ge=0)
    duration_microseconds: int = Field(alias="durationMicroseconds", ge=0)
    l1_bytes_per_flow: int = Field(alias="l1BytesPerFlow", ge=1)
    occurrence_count: int = Field(alias="occurrenceCount", ge=1)


class DatagramCaptureAnalysis(StrictModel):
    udp_flow_count: int = Field(alias="udpFlowCount", ge=0)
    replayable_flow_count: int = Field(alias="replayableFlowCount", ge=0)
    reported_flow_count: int = Field(alias="reportedFlowCount", ge=0)
    idle_timeout_seconds: float = Field(alias="idleTimeoutSeconds", gt=0)
    analysis_truncated: bool = Field(default=False, alias="analysisTruncated")
    omitted_udp_packet_count: int = Field(default=0, alias="omittedUdpPacketCount", ge=0)
    workload_complete: bool = Field(default=True, alias="workloadComplete")
    workload_template_count: int = Field(default=0, alias="workloadTemplateCount", ge=0)
    workload_datagram_count: int = Field(default=0, alias="workloadDatagramCount", ge=0)
    workload_templates: list[DatagramWorkloadTemplateAnalysis] = Field(
        default_factory=list, alias="workloadTemplates"
    )
    flows: list[CapturedDatagramFlowAnalysis]
    semantic_differences: list[str] = Field(alias="semanticDifferences")


@dataclass(frozen=True, slots=True)
class Datagram:
    direction: Literal["initiator", "responder"]
    offset_microseconds: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class DatagramTemplate:
    id: str
    digest: str
    template_digest: str
    initiator_port: int
    responder_port: int
    datagrams: tuple[Datagram, ...]


@dataclass(slots=True)
class _DatagramFlow:
    initiator_ip: bytes
    initiator_port: int
    responder_ip: bytes
    responder_port: int
    first_timestamp: float
    last_timestamp: float
    elapsed_microseconds: int = 0
    datagrams: list[Datagram] = field(default_factory=list)
    stored_payload_bytes: int = 0
    issues: list[str] = field(default_factory=list)

    def issue(self, value: str) -> None:
        if value not in self.issues:
            self.issues.append(value)


class DatagramFlowAnalyzer:
    """Derive bounded UDP flow facts while Capture Analysis scans packets once."""

    def __init__(
        self,
        *,
        idle_timeout_seconds: float = 30,
        maximum_reported_flows: int = 256,
        maximum_workload_templates: int = 256,
        maximum_workload_datagrams: int = 512,
        maximum_tracked_flows: int = 4_096,
        maximum_datagrams_per_flow: int = 256,
        maximum_payload_bytes_per_flow: int = 4 * 1024 * 1024,
        maximum_total_payload_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self._idle_timeout_seconds = idle_timeout_seconds
        self._maximum_reported_flows = maximum_reported_flows
        self._maximum_workload_templates = maximum_workload_templates
        self._maximum_workload_datagrams = maximum_workload_datagrams
        self._maximum_tracked_flows = maximum_tracked_flows
        self._maximum_datagrams_per_flow = maximum_datagrams_per_flow
        self._maximum_payload_bytes_per_flow = maximum_payload_bytes_per_flow
        self._maximum_total_payload_bytes = maximum_total_payload_bytes
        self._active: dict[tuple[tuple[bytes, int], tuple[bytes, int]], _DatagramFlow] = {}
        self._flows: list[_DatagramFlow] = []
        self._stored_payload_bytes = 0
        self._omitted_udp_packet_count = 0

    def observe(self, timestamp: float, ethernet: dpkt.ethernet.Ethernet) -> None:
        ip = ethernet.data
        if not isinstance(ip, dpkt.ip.IP) or int(ip.p) != dpkt.ip.IP_PROTO_UDP:
            return
        if (
            ethernet.dst == b"\xff" * 6
            or ethernet.dst[0] & 1
            or ipaddress.IPv4Address(ip.dst).is_multicast
            or not isinstance(ip.data, dpkt.udp.UDP)
        ):
            self._omitted_udp_packet_count += 1
            return
        udp = ip.data
        if not udp.sport or not udp.dport:
            self._omitted_udp_packet_count += 1
            return
        source = (bytes(ip.src), int(udp.sport))
        destination = (bytes(ip.dst), int(udp.dport))
        ordered = sorted((source, destination))
        key = (ordered[0], ordered[1])
        flow = self._active.get(key)
        if flow is None or timestamp - flow.last_timestamp > self._idle_timeout_seconds:
            if len(self._flows) >= self._maximum_tracked_flows:
                self._omitted_udp_packet_count += 1
                return
            flow = _DatagramFlow(
                initiator_ip=source[0],
                initiator_port=source[1],
                responder_ip=destination[0],
                responder_port=destination[1],
                first_timestamp=timestamp,
                last_timestamp=timestamp,
            )
            self._active[key] = flow
            self._flows.append(flow)
        else:
            flow.elapsed_microseconds += round(
                max(0.0, timestamp - flow.last_timestamp) * 1_000_000
            )
            flow.last_timestamp = max(flow.last_timestamp, timestamp)
        direction: Literal["initiator", "responder"] = (
            "initiator" if source == (flow.initiator_ip, flow.initiator_port) else "responder"
        )
        payload = bytes(udp.data)
        if len(flow.datagrams) >= self._maximum_datagrams_per_flow:
            flow.issue("flow exceeds the datagram analysis limit")
            return
        if flow.stored_payload_bytes + len(payload) > self._maximum_payload_bytes_per_flow:
            flow.issue("flow payload exceeds the per-flow analysis limit")
            return
        if self._stored_payload_bytes + len(payload) > self._maximum_total_payload_bytes:
            flow.issue("capture payload exceeds the total datagram analysis limit")
            return
        flow.datagrams.append(Datagram(direction, flow.elapsed_microseconds, payload))
        flow.stored_payload_bytes += len(payload)
        self._stored_payload_bytes += len(payload)

    def finish(self) -> DatagramCaptureAnalysis | None:
        if not self._flows and not self._omitted_udp_packet_count:
            return None
        analyzed = [(flow, self._analysis(flow)) for flow in self._flows]
        analyzed.sort(key=lambda item: item[1].id)
        templates: dict[str, tuple[_DatagramFlow, CapturedDatagramFlowAnalysis, int]] = {}
        for flow, analysis in analyzed:
            if not analysis.replayable:
                continue
            digest = self._template_digest(flow)
            current = templates.get(digest)
            if current is None:
                templates[digest] = (flow, analysis, 1)
            else:
                templates[digest] = (current[0], current[1], current[2] + 1)
        workload_templates = sorted(
            (
                DatagramWorkloadTemplateAnalysis(
                    id="udptemplate_" + digest.removeprefix("sha256:")[:24],
                    digest=digest,
                    representativeFlowId=analysis.id,
                    representativeFlowDigest=analysis.digest,
                    responderPort=flow.responder_port,
                    datagramCount=len(flow.datagrams),
                    initiatorDatagramCount=sum(
                        item.direction == "initiator" for item in flow.datagrams
                    ),
                    responderDatagramCount=sum(
                        item.direction == "responder" for item in flow.datagrams
                    ),
                    initiatorPayloadBytes=sum(
                        len(item.payload)
                        for item in flow.datagrams
                        if item.direction == "initiator"
                    ),
                    responderPayloadBytes=sum(
                        len(item.payload)
                        for item in flow.datagrams
                        if item.direction == "responder"
                    ),
                    durationMicroseconds=flow.elapsed_microseconds,
                    l1BytesPerFlow=self._l1_bytes(flow),
                    occurrenceCount=count,
                )
                for digest, (flow, analysis, count) in templates.items()
            ),
            key=lambda item: item.id,
        )
        incomplete = self._omitted_udp_packet_count > 0 or any(
            not analysis.replayable for _, analysis in analyzed
        )
        workload_datagram_count = sum(item.datagram_count for item in workload_templates)
        published_templates = workload_templates[: self._maximum_workload_templates]
        representative_ids = {item.representative_flow_id for item in published_templates}
        reported_flows = [
            analysis for _, analysis in analyzed if analysis.id in representative_ids
        ]
        reported_flows.extend(
            analysis for _, analysis in analyzed if analysis.id not in representative_ids
        )
        return DatagramCaptureAnalysis(
            udpFlowCount=len(analyzed),
            replayableFlowCount=sum(analysis.replayable for _, analysis in analyzed),
            reportedFlowCount=min(len(analyzed), self._maximum_reported_flows),
            idleTimeoutSeconds=self._idle_timeout_seconds,
            analysisTruncated=incomplete,
            omittedUdpPacketCount=self._omitted_udp_packet_count,
            workloadComplete=(
                not incomplete
                and len(workload_templates) <= self._maximum_workload_templates
                and workload_datagram_count <= self._maximum_workload_datagrams
            ),
            workloadTemplateCount=len(workload_templates),
            workloadDatagramCount=workload_datagram_count,
            workloadTemplates=published_templates,
            flows=reported_flows[: self._maximum_reported_flows],
            semanticDifferences=[
                "datagram payload direction, order, and relative offsets are preserved",
                (
                    "addresses and initiator ports are normalized to LabPath roles and "
                    "representative flows; capture-wide timing and network jitter are not restored"
                ),
            ],
        )

    def extract(self, flow_id: str) -> DatagramTemplate:
        for flow in self._flows:
            analysis = self._analysis(flow)
            if analysis.id == flow_id and analysis.replayable:
                return DatagramTemplate(
                    id=analysis.id,
                    digest=analysis.digest,
                    template_digest=self._template_digest(flow),
                    initiator_port=flow.initiator_port,
                    responder_port=flow.responder_port,
                    datagrams=tuple(flow.datagrams),
                )
        raise ValueError(f"capture has no replayable datagram flow {flow_id}")

    @staticmethod
    def _flow_digest(flow: _DatagramFlow) -> str:
        identity = hashlib.sha256()
        identity.update(flow.initiator_ip)
        identity.update(flow.initiator_port.to_bytes(2, "big"))
        identity.update(flow.responder_ip)
        identity.update(flow.responder_port.to_bytes(2, "big"))
        DatagramFlowAnalyzer._update_datagrams(identity, flow)
        return "sha256:" + identity.hexdigest()

    @staticmethod
    def _template_digest(flow: _DatagramFlow) -> str:
        identity = hashlib.sha256()
        identity.update(flow.responder_port.to_bytes(2, "big"))
        DatagramFlowAnalyzer._update_datagrams(identity, flow)
        return "sha256:" + identity.hexdigest()

    @staticmethod
    def _update_datagrams(identity: object, flow: _DatagramFlow) -> None:
        assert hasattr(identity, "update")
        for datagram in flow.datagrams:
            identity.update(b"i" if datagram.direction == "initiator" else b"r")
            identity.update(datagram.offset_microseconds.to_bytes(8, "big"))
            identity.update(len(datagram.payload).to_bytes(8, "big"))
            identity.update(datagram.payload)

    def _analysis(self, flow: _DatagramFlow) -> CapturedDatagramFlowAnalysis:
        digest = self._flow_digest(flow)
        return CapturedDatagramFlowAnalysis(
            id="udpflow_" + digest.removeprefix("sha256:")[:24],
            digest=digest,
            initiator=DatagramEndpoint(
                ipv4=str(ipaddress.IPv4Address(flow.initiator_ip)),
                port=flow.initiator_port,
            ),
            responder=DatagramEndpoint(
                ipv4=str(ipaddress.IPv4Address(flow.responder_ip)),
                port=flow.responder_port,
            ),
            datagramCount=len(flow.datagrams),
            initiatorDatagramCount=sum(item.direction == "initiator" for item in flow.datagrams),
            responderDatagramCount=sum(item.direction == "responder" for item in flow.datagrams),
            initiatorPayloadBytes=sum(
                len(item.payload) for item in flow.datagrams if item.direction == "initiator"
            ),
            responderPayloadBytes=sum(
                len(item.payload) for item in flow.datagrams if item.direction == "responder"
            ),
            durationMicroseconds=flow.elapsed_microseconds,
            l1BytesPerFlow=self._l1_bytes(flow),
            replayable=bool(flow.datagrams) and not flow.issues,
            issues=flow.issues,
        )

    @staticmethod
    def _l1_bytes(flow: _DatagramFlow) -> int:
        return sum(max(64, 46 + len(item.payload)) + 20 for item in flow.datagrams)


def extract_datagram_template(path: Path, flow_id: str) -> DatagramTemplate:
    analyzer = DatagramFlowAnalyzer()
    with path.open("rb") as source:
        capture = dpkt.pcap.Reader(source)
        for timestamp, packet in capture:
            analyzer.observe(float(timestamp), dpkt.ethernet.Ethernet(packet))
    return analyzer.extract(flow_id)
