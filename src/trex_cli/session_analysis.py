from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import dpkt  # type: ignore[import-untyped]
from pydantic import Field

from trex_cli.models import StrictModel


class SessionEndpoint(StrictModel):
    ipv4: str
    port: int = Field(ge=1, le=65_535)


class CapturedSessionAnalysis(StrictModel):
    id: str = Field(pattern=r"^session_[0-9a-f]{24}$")
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    transport: Literal["tcp"] = "tcp"
    protocol: Literal["http", "tcp"]
    client: SessionEndpoint
    server: SessionEndpoint
    packet_count: int = Field(alias="packetCount", ge=1)
    client_payload_bytes: int = Field(alias="clientPayloadBytes", ge=0)
    server_payload_bytes: int = Field(alias="serverPayloadBytes", ge=0)
    exchange_count: int = Field(alias="exchangeCount", ge=0)
    reconstructible: bool
    issues: list[str]


class WorkloadTemplateAnalysis(StrictModel):
    id: str = Field(pattern=r"^template_[0-9a-f]{24}$")
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    representative_session_id: str = Field(
        alias="representativeSessionId", pattern=r"^session_[0-9a-f]{24}$"
    )
    representative_session_digest: str = Field(
        alias="representativeSessionDigest", pattern=r"^sha256:[0-9a-f]{64}$"
    )
    protocol: Literal["http", "tcp"]
    server_port: int = Field(alias="serverPort", ge=1, le=65_535)
    client_payload_bytes: int = Field(alias="clientPayloadBytes", ge=0)
    server_payload_bytes: int = Field(alias="serverPayloadBytes", ge=0)
    exchange_count: int = Field(alias="exchangeCount", ge=1)
    occurrence_count: int = Field(alias="occurrenceCount", ge=1)


class StatefulCaptureAnalysis(StrictModel):
    tcp_session_count: int = Field(alias="tcpSessionCount", ge=0)
    reconstructible_session_count: int = Field(alias="reconstructibleSessionCount", ge=0)
    reported_session_count: int = Field(alias="reportedSessionCount", ge=0)
    analysis_truncated: bool = Field(default=False, alias="analysisTruncated")
    omitted_tcp_packet_count: int = Field(default=0, alias="omittedTcpPacketCount", ge=0)
    workload_complete: bool = Field(default=True, alias="workloadComplete")
    workload_template_count: int = Field(default=0, alias="workloadTemplateCount", ge=0)
    workload_templates: list[WorkloadTemplateAnalysis] = Field(
        default_factory=list, alias="workloadTemplates"
    )
    sessions: list[CapturedSessionAnalysis]
    semantic_differences: list[str] = Field(alias="semanticDifferences")


@dataclass(frozen=True, slots=True)
class SessionTemplate:
    id: str
    digest: str
    template_digest: str
    exchanges: tuple[tuple[Literal["client", "server"], bytes], ...]


@dataclass(slots=True)
class _Flow:
    client_ip: bytes
    client_port: int
    server_ip: bytes
    server_port: int
    generation: int = 0
    closed: bool = False
    initial_sequence: int | None = None
    packet_count: int = 0
    saw_syn: bool = False
    saw_syn_ack: bool = False
    next_client_sequence: int | None = None
    next_server_sequence: int | None = None
    exchanges: list[tuple[Literal["client", "server"], bytes]] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    client_payload_bytes: int = 0
    server_payload_bytes: int = 0
    stored_payload_bytes: int = 0

    def issue(self, value: str) -> None:
        if value not in self.issues:
            self.issues.append(value)


class StatefulSessionAnalyzer:
    """Derive bounded, stable session facts while Capture Analysis scans packets once."""

    def __init__(
        self,
        *,
        maximum_reported_sessions: int = 256,
        maximum_workload_templates: int = 256,
        maximum_tracked_sessions: int = 4_096,
        maximum_payload_bytes_per_session: int = 4 * 1024 * 1024,
        maximum_total_payload_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self._flows: dict[tuple[tuple[bytes, int], tuple[bytes, int]], _Flow] = {}
        self._completed_flows: list[_Flow] = []
        self._maximum_reported_sessions = maximum_reported_sessions
        self._maximum_workload_templates = maximum_workload_templates
        self._maximum_tracked_sessions = maximum_tracked_sessions
        self._maximum_payload_bytes_per_session = maximum_payload_bytes_per_session
        self._maximum_total_payload_bytes = maximum_total_payload_bytes
        self._stored_payload_bytes = 0
        self._omitted_tcp_packet_count = 0

    def observe(self, ethernet: dpkt.ethernet.Ethernet) -> None:
        ip = ethernet.data
        if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.tcp.TCP):
            return
        tcp = ip.data
        source = (bytes(ip.src), int(tcp.sport))
        destination = (bytes(ip.dst), int(tcp.dport))
        ordered = sorted((source, destination))
        key = (ordered[0], ordered[1])
        flow = self._flows.get(key)
        initial_syn = bool(tcp.flags & dpkt.tcp.TH_SYN) and not bool(tcp.flags & dpkt.tcp.TH_ACK)
        generation = 0
        if flow is not None and initial_syn:
            if (
                flow.closed
                or flow.saw_syn_ack
                or flow.exchanges
                or flow.initial_sequence != int(tcp.seq)
            ):
                generation = flow.generation + 1
                self._completed_flows.append(flow)
                del self._flows[key]
                flow = None
        if flow is None:
            if len(self._flows) + len(self._completed_flows) >= self._maximum_tracked_sessions:
                self._omitted_tcp_packet_count += 1
                return
            flow = _Flow(
                client_ip=source[0],
                client_port=source[1],
                server_ip=destination[0],
                server_port=destination[1],
                generation=generation,
            )
            self._flows[key] = flow
            if not initial_syn:
                flow.issue("capture does not start with the client SYN")
        flow.packet_count += 1
        if tcp.flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST):
            flow.closed = True
        client_to_server = source == (flow.client_ip, flow.client_port)
        if initial_syn:
            if not client_to_server:
                flow.issue("conflicting client direction")
            flow.saw_syn = True
            flow.initial_sequence = int(tcp.seq)
            flow.next_client_sequence = int(tcp.seq) + 1
        elif tcp.flags & dpkt.tcp.TH_SYN and tcp.flags & dpkt.tcp.TH_ACK:
            if client_to_server:
                flow.issue("SYN-ACK is in the client direction")
            flow.saw_syn_ack = True
            flow.next_server_sequence = int(tcp.seq) + 1

        payload = bytes(tcp.data)
        if not payload:
            return
        direction: Literal["client", "server"] = "client" if client_to_server else "server"
        if client_to_server:
            flow.client_payload_bytes += len(payload)
        else:
            flow.server_payload_bytes += len(payload)
        expected = flow.next_client_sequence if client_to_server else flow.next_server_sequence
        if expected is None:
            flow.issue(f"{direction} payload appears before the TCP handshake")
        elif int(tcp.seq) < expected:
            flow.issue(f"{direction} retransmission or overlapping payload")
        elif int(tcp.seq) > expected:
            flow.issue(f"{direction} payload gap or out-of-order segment")
        else:
            if client_to_server:
                flow.next_client_sequence = expected + len(payload)
            else:
                flow.next_server_sequence = expected + len(payload)
        if flow.stored_payload_bytes + len(payload) > self._maximum_payload_bytes_per_session:
            flow.issue("session payload exceeds the per-session analysis limit")
            return
        if self._stored_payload_bytes + len(payload) > self._maximum_total_payload_bytes:
            flow.issue("capture payload exceeds the total session analysis limit")
            return
        flow.stored_payload_bytes += len(payload)
        self._stored_payload_bytes += len(payload)
        if flow.exchanges and flow.exchanges[-1][0] == direction:
            previous_direction, previous_payload = flow.exchanges[-1]
            flow.exchanges[-1] = (previous_direction, previous_payload + payload)
        else:
            flow.exchanges.append((direction, payload))

    def finish(self) -> StatefulCaptureAnalysis | None:
        if not self._flows and not self._completed_flows:
            return None
        analyzed = [
            (flow, self._session(flow))
            for flow in (*self._completed_flows, *self._flows.values())
        ]
        analyzed.sort(key=lambda item: item[1].id)
        sessions = [session for _, session in analyzed]
        reported = sessions[: self._maximum_reported_sessions]
        workload: dict[str, tuple[_Flow, CapturedSessionAnalysis, int]] = {}
        for flow, session in analyzed:
            if not session.reconstructible:
                continue
            digest = self._template_digest(flow)
            current = workload.get(digest)
            workload[digest] = (flow, session, 1 if current is None else current[2] + 1)
        workload_templates = sorted(
            (
                WorkloadTemplateAnalysis(
                    id="template_" + digest.removeprefix("sha256:")[:24],
                    digest=digest,
                    representativeSessionId=session.id,
                    representativeSessionDigest=session.digest,
                    protocol=session.protocol,
                    serverPort=session.server.port,
                    clientPayloadBytes=session.client_payload_bytes,
                    serverPayloadBytes=session.server_payload_bytes,
                    exchangeCount=session.exchange_count,
                    occurrenceCount=count,
                )
                for digest, (_flow, session, count) in workload.items()
            ),
            key=lambda template: template.id,
        )
        reported_workload = workload_templates[: self._maximum_workload_templates]
        return StatefulCaptureAnalysis(
            tcpSessionCount=len(sessions),
            reconstructibleSessionCount=sum(session.reconstructible for session in sessions),
            reportedSessionCount=len(reported),
            analysisTruncated=self._omitted_tcp_packet_count > 0,
            omittedTcpPacketCount=self._omitted_tcp_packet_count,
            workloadComplete=(
                self._omitted_tcp_packet_count == 0
                and len(workload_templates) <= self._maximum_workload_templates
            ),
            workloadTemplateCount=len(workload_templates),
            workloadTemplates=reported_workload,
            sessions=reported,
            semanticDifferences=[
                "application payload order is preserved",
                (
                    "packet timing, TCP sequence numbers, acknowledgements, retransmissions, "
                    "and network jitter are regenerated"
                ),
            ],
        )

    def template(self, session_id: str) -> SessionTemplate:
        for flow in (*self._completed_flows, *self._flows.values()):
            session = self._session(flow)
            if session.id == session_id:
                if not session.reconstructible:
                    raise ValueError("session is not reconstructible: " + ", ".join(session.issues))
                return SessionTemplate(
                    id=session.id,
                    digest=session.digest,
                    template_digest=self._template_digest(flow),
                    exchanges=tuple(flow.exchanges),
                )
        raise ValueError(f"capture has no session {session_id}")

    @staticmethod
    def _template_digest(flow: _Flow) -> str:
        identity = hashlib.sha256()
        identity.update(flow.server_port.to_bytes(2, "big"))
        for direction, payload in flow.exchanges:
            identity.update(b"c" if direction == "client" else b"s")
            identity.update(len(payload).to_bytes(8, "big"))
            identity.update(payload)
        return "sha256:" + identity.hexdigest()

    @staticmethod
    def _session(flow: _Flow) -> CapturedSessionAnalysis:
        issues = list(flow.issues)
        if not flow.saw_syn:
            issues.append("client SYN is missing")
        if not flow.saw_syn_ack:
            issues.append("server SYN-ACK is missing")
        if not flow.exchanges:
            issues.append("application payload is missing")
        identity = hashlib.sha256()
        identity.update(flow.client_ip)
        identity.update(flow.client_port.to_bytes(2, "big"))
        identity.update(flow.server_ip)
        identity.update(flow.server_port.to_bytes(2, "big"))
        if flow.generation:
            identity.update(b"generation:" + flow.generation.to_bytes(8, "big"))
        for direction, payload in flow.exchanges:
            identity.update(b"c" if direction == "client" else b"s")
            identity.update(len(payload).to_bytes(8, "big"))
            identity.update(payload)
        protocol: Literal["http", "tcp"] = (
            "http"
            if flow.server_port in {80, 8080}
            or any(
                payload.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"HTTP/"))
                for _, payload in flow.exchanges
            )
            else "tcp"
        )
        return CapturedSessionAnalysis(
            id="session_" + identity.hexdigest()[:24],
            digest="sha256:" + identity.hexdigest(),
            protocol=protocol,
            client=SessionEndpoint(
                ipv4=str(ipaddress.IPv4Address(flow.client_ip)), port=flow.client_port
            ),
            server=SessionEndpoint(
                ipv4=str(ipaddress.IPv4Address(flow.server_ip)), port=flow.server_port
            ),
            packetCount=flow.packet_count,
            clientPayloadBytes=flow.client_payload_bytes,
            serverPayloadBytes=flow.server_payload_bytes,
            exchangeCount=len(flow.exchanges),
            reconstructible=not issues,
            issues=issues,
        )


def extract_session_template(path: Path, session_id: str) -> SessionTemplate:
    analyzer = StatefulSessionAnalyzer(maximum_reported_sessions=0)
    try:
        with path.open("rb") as source:
            capture = dpkt.pcap.Reader(source)
            if capture.datalink() != dpkt.pcap.DLT_EN10MB:
                raise ValueError("only Ethernet PCAP is supported")
            for _, packet in capture:
                analyzer.observe(dpkt.ethernet.Ethernet(packet))
    except (dpkt.NeedData, dpkt.UnpackError) as error:
        raise ValueError(f"invalid PCAP while extracting session: {error}") from error
    return analyzer.template(session_id)
