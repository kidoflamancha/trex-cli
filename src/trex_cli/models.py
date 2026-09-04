from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    TypeAdapter,
    field_validator,
    model_validator,
)

from trex_cli.arp_storm import ARP_REQUEST_WIRE_SIZE, arp_sender_ipv4_end, arp_sender_mac_end
from trex_cli.dhcp_storm import (
    dhcp_client_mac_end,
    dhcp_discover_wire_size,
    encode_dhcp_discover,
)
from trex_cli.dns_storm import dns_query_wire_size, encode_dns_query


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


_DURATION_RE = re.compile(r"^(\d+)(ms|s|m|h)$")


def _parse_duration(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError("duration cannot be a boolean")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("duration must be non-negative")
        return value
    if not isinstance(value, str):
        raise ValueError("duration must be an integer millisecond value or a duration string")
    match = _DURATION_RE.fullmatch(value)
    if match is None:
        raise ValueError("duration must use ms, s, m, or h")
    number = int(match.group(1))
    multiplier = {"ms": 1, "s": 1_000, "m": 60_000, "h": 3_600_000}[match.group(2)]
    return number * multiplier


type DurationMs = Annotated[int, BeforeValidator(_parse_duration), Field(ge=0)]


class JobState(StrEnum):
    ACCEPTED = "ACCEPTED"
    VALIDATING = "VALIDATING"
    WAITING_FOR_PORTS = "WAITING_FOR_PORTS"
    PREPARING = "PREPARING"
    WARMING_UP = "WARMING_UP"
    RUNNING = "RUNNING"
    DRAINING = "DRAINING"
    COLLECTING = "COLLECTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    @property
    def terminal(self) -> bool:
        return self in {self.SUCCEEDED, self.FAILED, self.CANCELLED}


class Verdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INVALID = "INVALID"
    NO_ASSERTION = "NO_ASSERTION"


class Role(StrEnum):
    OPERATOR = "operator"
    READ_ONLY = "read-only"


class ArtifactCleanupBody(StrictModel):
    dry_run: bool = Field(default=True, alias="dryRun")
    delete_orphans: bool = Field(default=False, alias="deleteOrphans")


class Problem(StrictModel):
    code: str
    category: Literal["INPUT", "POLICY", "RESOURCE", "ENGINE", "OBSERVATION", "INTERNAL"]
    retryable: bool = False
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class SafetyDeclaration(StrictModel):
    isolated_lab: Literal[True] = Field(alias="isolatedLab")


class Ports(StrictModel):
    tx: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    rx: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    direction: Literal["unidirectional", "bidirectional"] = "unidirectional"

    @model_validator(mode="after")
    def distinct_ports(self) -> Ports:
        if self.tx == self.rx:
            raise ValueError("tx and rx must be different logical ports")
        return self


class Limits(StrictModel):
    port_wait_timeout: DurationMs = Field(default=300_000, alias="portWaitTimeout")
    job_timeout: DurationMs = Field(default=600_000, alias="jobTimeout")

    @model_validator(mode="after")
    def positive_limits(self) -> Limits:
        if self.port_wait_timeout <= 0 or self.job_timeout <= 0:
            raise ValueError("timeouts must be greater than zero")
        return self


class VariationMode(StrEnum):
    INCREMENT = "increment"
    DECREMENT = "decrement"
    RANDOM = "random"


class StringVariation(StrictModel):
    start: str
    end: str
    mode: VariationMode


class IntegerVariation(StrictModel):
    start: int = Field(ge=0, le=65_535)
    end: int = Field(ge=0, le=65_535)
    mode: VariationMode

    @model_validator(mode="after")
    def ordered(self) -> IntegerVariation:
        if self.start > self.end:
            raise ValueError("variation start must not exceed end")
        return self


type StringOrVariation = str | StringVariation
type PortOrVariation = Annotated[int, Field(ge=0, le=65_535)] | IntegerVariation


def _parse_mac(value: str) -> int:
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value) is None:
        raise ValueError("invalid MAC address")
    parsed = int(value.replace(":", ""), 16)
    if value.lower() == "ff:ff:ff:ff:ff:ff" or parsed >> 40 & 1:
        raise ValueError("multicast and broadcast MAC addresses are not allowed by v1")
    return parsed


class MacVariation(StrictModel):
    start: str
    end: str
    mode: VariationMode

    @model_validator(mode="after")
    def valid_range(self) -> MacVariation:
        start = _parse_mac(self.start)
        end = _parse_mac(self.end)
        if start > end:
            raise ValueError("MAC variation start must not exceed end")
        if start >> 32 != end >> 32:
            raise ValueError("MAC variations must stay within one 16-bit prefix")
        self.start = self.start.lower()
        self.end = self.end.lower()
        return self


type MacOrVariation = str | MacVariation


class EthernetHeader(StrictModel):
    src: MacOrVariation
    dst: MacOrVariation

    @field_validator("src", "dst")
    @classmethod
    def valid_mac(cls, value: MacOrVariation) -> MacOrVariation:
        if isinstance(value, MacVariation):
            return value
        _parse_mac(value)
        return value.lower()


class VlanHeader(StrictModel):
    id: int = Field(ge=1, le=4094)
    priority: int = Field(default=0, ge=0, le=7)


def _validate_ip_value(value: StringOrVariation, version: int) -> StringOrVariation:
    values = [value] if isinstance(value, str) else [value.start, value.end]
    parsed = [ipaddress.ip_address(item) for item in values]
    if any(item.version != version for item in parsed):
        raise ValueError(f"expected IPv{version} address")
    if len(parsed) == 2 and int(parsed[0]) > int(parsed[1]):
        raise ValueError("address variation start must not exceed end")
    return value


class IPv4Header(StrictModel):
    src: StringOrVariation
    dst: StringOrVariation
    ttl: int = Field(default=64, ge=1, le=255)

    @field_validator("src", "dst")
    @classmethod
    def valid_ipv4(cls, value: StringOrVariation) -> StringOrVariation:
        return _validate_ip_value(value, 4)


class IPv6Header(StrictModel):
    src: StringOrVariation
    dst: StringOrVariation
    hop_limit: int = Field(default=64, alias="hopLimit", ge=1, le=255)

    @field_validator("src", "dst")
    @classmethod
    def valid_ipv6(cls, value: StringOrVariation) -> StringOrVariation:
        return _validate_ip_value(value, 6)


class UdpHeader(StrictModel):
    src_port: PortOrVariation = Field(alias="srcPort")
    dst_port: PortOrVariation = Field(alias="dstPort")


class TcpHeader(UdpHeader):
    flags: str = Field(default="S", pattern=r"^[FSRPAUEC]+$")


class IcmpHeader(StrictModel):
    type: int = Field(default=8, ge=0, le=255)
    code: int = Field(default=0, ge=0, le=255)


class PacketHeaders(StrictModel):
    ethernet: EthernetHeader
    vlan: VlanHeader | None = None
    ipv4: IPv4Header | None = None
    ipv6: IPv6Header | None = None
    udp: UdpHeader | None = None
    tcp: TcpHeader | None = None
    icmp: IcmpHeader | None = None
    payload_hex: str | None = Field(
        default=None, alias="payloadHex", pattern=r"^(?:[0-9a-fA-F]{2})*$"
    )

    @model_validator(mode="after")
    def valid_stack(self) -> PacketHeaders:
        network_count = int(self.ipv4 is not None) + int(self.ipv6 is not None)
        transport_count = (
            int(self.udp is not None) + int(self.tcp is not None) + int(self.icmp is not None)
        )
        if network_count > 1:
            raise ValueError("packet cannot contain both IPv4 and IPv6")
        if transport_count > 1:
            raise ValueError("packet can contain only one transport header")
        if transport_count and network_count == 0:
            raise ValueError("transport header requires IPv4 or IPv6")
        return self


class Packet(PacketHeaders):
    frame_size: int = Field(alias="frameSize", ge=64, le=9_216)


class Rate(StrictModel):
    unit: Literal["percent_l1", "bps_l1", "bps_l2", "pps"]
    value: float = Field(gt=0)

    @model_validator(mode="after")
    def valid_percent(self) -> Rate:
        if self.unit == "percent_l1" and self.value > 100:
            raise ValueError("percent_l1 cannot exceed 100")
        return self


class TrafficAssertions(StrictModel):
    max_loss_percent: float = Field(alias="maxLossPercent", ge=0, le=100)


class ResolvedTrafficStream(StrictModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
    tx: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    rx: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    packet: Packet
    rate: Rate

    @model_validator(mode="after")
    def distinct_ports(self) -> ResolvedTrafficStream:
        if self.tx == self.rx:
            raise ValueError("stream tx and rx must be different logical ports")
        return self


class StatelessTrafficSpec(StrictModel):
    safety: SafetyDeclaration
    ports: Ports
    limits: Limits = Field(default_factory=Limits)
    packet: Packet
    rate: Rate
    duration: DurationMs | None = None
    burst_packets: int | None = Field(default=None, alias="burstPackets", ge=1)
    assertions: TrafficAssertions | None = None
    streams: list[ResolvedTrafficStream] = Field(default_factory=list, max_length=256)

    @model_validator(mode="after")
    def duration_or_burst(self) -> StatelessTrafficSpec:
        if (self.duration is None) == (self.burst_packets is None):
            raise ValueError("exactly one of duration or burstPackets is required")
        if self.duration is not None and self.duration <= 0:
            raise ValueError("duration must be greater than zero")
        if self.streams:
            if self.burst_packets is not None:
                raise ValueError("resolved streams currently require duration mode")
            names = [stream.name for stream in self.streams]
            if len(set(names)) != len(names):
                raise ValueError("resolved stream names must be unique")
        return self

    def logical_ports(self) -> set[str]:
        if not self.streams:
            return {self.ports.tx, self.ports.rx}
        return {port for stream in self.streams for port in (stream.tx, stream.rx)}


class RfcPacket(PacketHeaders):
    """A frame-size-independent packet template used by RFC2544 trials."""

    @model_validator(mode="after")
    def requires_network_header(self) -> RfcPacket:
        if self.ipv4 is None and self.ipv6 is None:
            raise ValueError("RFC2544 packet requires IPv4 or IPv6 for isolated flow statistics")
        return self


class ThroughputAssertion(StrictModel):
    minimum_percent_line_rate: dict[str, float] = Field(alias="minimumPercentLineRate")

    @field_validator("minimum_percent_line_rate")
    @classmethod
    def valid_thresholds(cls, value: dict[str, float]) -> dict[str, float]:
        if not value:
            raise ValueError("minimumPercentLineRate cannot be empty")
        for frame_size, threshold in value.items():
            if not frame_size.isdigit() or not 64 <= int(frame_size) <= 9_216:
                raise ValueError(f"invalid frame size threshold: {frame_size}")
            if not 0 <= threshold <= 100:
                raise ValueError("throughput threshold must be between 0 and 100")
        return value


class DutReportContext(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    hardware: str = Field(min_length=1, max_length=256)
    software_version: str = Field(alias="softwareVersion", min_length=1, max_length=256)
    configuration_digest: str = Field(alias="configurationDigest", pattern=r"^sha256:[0-9a-f]{64}$")
    configuration_artifact: str = Field(alias="configurationArtifact", min_length=1, max_length=512)


class Rfc2544ReportContext(StrictModel):
    dut: DutReportContext
    topology: str = Field(min_length=1, max_length=1024)
    medium: str = Field(min_length=1, max_length=256)
    protocol: str = Field(min_length=1, max_length=256)
    stream_type: str = Field(alias="streamType", min_length=1, max_length=256)
    isolation_statement: str = Field(alias="isolationStatement", min_length=1, max_length=1024)
    modifiers: list[str] = Field(default_factory=list)


class Rfc2544ThroughputSpec(StrictModel):
    safety: SafetyDeclaration
    ports: Ports
    mode: Literal["strict", "fast"]
    packet: RfcPacket
    limits: Limits = Field(default_factory=lambda: Limits(jobTimeout=28_800_000))
    frame_sizes: list[int] | None = Field(default=None, alias="frameSizes")
    assertion: ThroughputAssertion | None = None
    direction_mode: (
        Literal["unidirectional", "bidirectional-simultaneous", "unidirectional-each"] | None
    ) = Field(default=None, alias="directionMode")
    reverse_packet: RfcPacket | None = Field(default=None, alias="reversePacket")

    @model_validator(mode="after")
    def valid_frame_sizes(self) -> Rfc2544ThroughputSpec:
        if self.mode == "strict" and self.frame_sizes is not None:
            raise ValueError("strict mode uses fixed RFC2544 frame sizes")
        if self.mode == "fast" and self.frame_sizes is not None:
            allowed = {64, 512, 1518}
            if not self.frame_sizes or len(set(self.frame_sizes)) != len(self.frame_sizes):
                raise ValueError("fast frameSizes must be non-empty and unique")
            if not set(self.frame_sizes) <= allowed:
                raise ValueError("fast frameSizes must be chosen from 64, 512, 1518")
        if self.direction_mode == "unidirectional":
            if self.ports.direction != "unidirectional" or self.reverse_packet is not None:
                raise ValueError("unidirectional requires one packet and unidirectional ports")
        elif self.direction_mode in {
            "bidirectional-simultaneous",
            "unidirectional-each",
        }:
            if self.ports.direction != "bidirectional" or self.reverse_packet is None:
                raise ValueError(
                    "explicit two-direction RFC2544 requires bidirectional ports and reversePacket"
                )
        return self


class Metadata(StrictModel):
    name: str | None = Field(default=None, max_length=128)
    labels: dict[str, str] = Field(default_factory=dict)


class StatelessTrafficDocument(StrictModel):
    api_version: Literal["trex.example.io/v1"] = Field(alias="apiVersion")
    kind: Literal["StatelessTraffic"]
    metadata: Metadata = Field(default_factory=Metadata)
    spec: StatelessTrafficSpec


class CaptureBinding(StrictModel):
    name: str = Field(min_length=1, max_length=256)
    revision: int = Field(ge=1)
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    size: int = Field(ge=0)
    packet_count: int = Field(alias="packetCount", ge=0)
    duration_seconds: float = Field(alias="durationSeconds", ge=0)
    normalized_duration_seconds: float = Field(alias="normalizedDurationSeconds", ge=0)
    non_monotonic_timestamp_count: int = Field(alias="nonMonotonicTimestampCount", ge=0)
    maximum_backward_jump_seconds: float = Field(alias="maximumBackwardJumpSeconds", ge=0)
    mac_endpoints: list[str] = Field(alias="macEndpoints")
    ipv4_endpoints: list[str] = Field(alias="ipv4Endpoints")
    has_broadcast: bool = Field(alias="hasBroadcast")
    has_multicast: bool = Field(alias="hasMulticast")


class ReplayRewriteAddress(StrictModel):
    mode: Literal["rewrite"] = "rewrite"
    source_role: str = Field(alias="sourceRole")
    destination_role: str = Field(alias="destinationRole")
    source_mac: str = Field(alias="sourceMac")
    destination_mac: str = Field(alias="destinationMac")
    source_ipv4: str = Field(alias="sourceIpv4")
    destination_ipv4: str = Field(alias="destinationIpv4")


class ReplayPreserveAddress(StrictModel):
    mode: Literal["preserve"] = "preserve"
    policy_version: str = Field(alias="policyVersion", min_length=1)


type ReplayAddress = Annotated[
    ReplayRewriteAddress | ReplayPreserveAddress, Field(discriminator="mode")
]


class ReplayCaptureTiming(StrictModel):
    mode: Literal["capture"] = "capture"
    multiplier: float = Field(default=1, gt=0, le=1_000)
    timestamp_policy: Literal["reject", "normalize"] = Field(
        default="reject", alias="timestampPolicy"
    )
    normalized_timestamp_count: int = Field(default=0, alias="normalizedTimestampCount", ge=0)


class ReplayFixedRateTiming(StrictModel):
    mode: Literal["fixed-rate"] = "fixed-rate"
    rate: Rate


class ReplayTopSpeedTiming(StrictModel):
    mode: Literal["top-speed"] = "top-speed"


type ReplayTiming = Annotated[
    ReplayCaptureTiming | ReplayFixedRateTiming | ReplayTopSpeedTiming,
    Field(discriminator="mode"),
]


class PcapReplaySpec(StrictModel):
    safety: SafetyDeclaration
    ports: Ports
    limits: Limits = Field(default_factory=Limits)
    capture: CaptureBinding
    address: ReplayAddress
    timing: ReplayTiming

    def logical_ports(self) -> set[str]:
        return {self.ports.tx, self.ports.rx}


class PcapReplayDocument(StrictModel):
    api_version: Literal["trex.example.io/v1"] = Field(alias="apiVersion")
    kind: Literal["PcapReplay"]
    metadata: Metadata = Field(default_factory=Metadata)
    spec: PcapReplaySpec


class StatefulSessionBinding(StrictModel):
    id: str = Field(pattern=r"^session_[0-9a-f]{24}$")
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    protocol: Literal["http", "tcp"]
    server_port: int = Field(alias="serverPort", ge=1, le=65_535)
    client_payload_bytes: int = Field(alias="clientPayloadBytes", ge=0)
    server_payload_bytes: int = Field(alias="serverPayloadBytes", ge=0)
    exchange_count: int = Field(alias="exchangeCount", ge=1)


class StatefulWorkloadTemplateBinding(StrictModel):
    id: str = Field(pattern=r"^template_[0-9a-f]{24}$")
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    representative_session: StatefulSessionBinding = Field(alias="representativeSession")
    occurrence_count: int = Field(alias="occurrenceCount", ge=1)
    weight: float = Field(gt=0, le=1)
    cps: float = Field(gt=0)
    max_active_connections: int = Field(alias="maxActiveConnections", ge=1)


class CaptureWorkloadBinding(StrictModel):
    selection: Literal["all-reconstructible"] = "all-reconstructible"
    source_session_count: int = Field(alias="sourceSessionCount", ge=1)
    template_count: int = Field(alias="templateCount", ge=1, le=256)
    templates: list[StatefulWorkloadTemplateBinding] = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def consistent_aggregation(self) -> CaptureWorkloadBinding:
        if self.template_count != len(self.templates):
            raise ValueError("workload templateCount must equal the number of templates")
        if self.source_session_count != sum(item.occurrence_count for item in self.templates):
            raise ValueError("workload sourceSessionCount must equal template occurrences")
        if abs(sum(item.weight for item in self.templates) - 1) > 1e-9:
            raise ValueError("workload template weights must sum to one")
        return self


class Ipv4Pool(StrictModel):
    start: str
    end: str

    @model_validator(mode="after")
    def ordered_ipv4_range(self) -> Ipv4Pool:
        if ipaddress.IPv4Address(self.end) < ipaddress.IPv4Address(self.start):
            raise ValueError("IPv4 pool end must not precede start")
        return self

    @property
    def cardinality(self) -> int:
        return int(ipaddress.IPv4Address(self.end)) - int(ipaddress.IPv4Address(self.start)) + 1


class TransportPortPool(StrictModel):
    start: int = Field(default=1024, ge=1024, le=65_535)
    end: int = Field(default=65_535, ge=1024, le=65_535)

    @model_validator(mode="after")
    def ordered_port_range(self) -> TransportPortPool:
        if self.end < self.start:
            raise ValueError("transport port pool end must not precede start")
        return self

    @property
    def cardinality(self) -> int:
        return self.end - self.start + 1


class StatefulClientBinding(StrictModel):
    role: str
    port: str
    ipv4_pool: Ipv4Pool = Field(alias="ipv4Pool")
    transport_port_pool: TransportPortPool = Field(
        default_factory=TransportPortPool, alias="transportPortPool"
    )


class StatefulServerBinding(StrictModel):
    role: str
    port: str
    ipv4_pool: Ipv4Pool = Field(alias="ipv4Pool")


class StatefulReplayRun(StrictModel):
    cps: float = Field(gt=0)
    max_active_connections: int = Field(alias="maxActiveConnections", ge=1)
    duration: DurationMs

    @model_validator(mode="after")
    def positive_duration(self) -> StatefulReplayRun:
        if self.duration <= 0:
            raise ValueError("stateful replay duration must be greater than zero")
        return self


class StatefulReplaySpec(StrictModel):
    safety: SafetyDeclaration
    limits: Limits = Field(default_factory=Limits)
    capture: CaptureBinding
    session: StatefulSessionBinding | None = None
    workload: CaptureWorkloadBinding | None = None
    client: StatefulClientBinding
    server: StatefulServerBinding
    run: StatefulReplayRun
    semantic_differences: list[str] = Field(alias="semanticDifferences", min_length=1)

    @model_validator(mode="after")
    def exactly_one_replay_shape(self) -> StatefulReplaySpec:
        if (self.session is None) == (self.workload is None):
            raise ValueError("stateful replay requires exactly one of session or workload")
        return self

    def logical_ports(self) -> set[str]:
        return {self.client.port, self.server.port}


class StatefulReplayDocument(StrictModel):
    api_version: Literal["trex.example.io/v1"] = Field(alias="apiVersion")
    kind: Literal["StatefulReplay"]
    metadata: Metadata = Field(default_factory=Metadata)
    spec: StatefulReplaySpec


class DatagramFlowBinding(StrictModel):
    id: str = Field(pattern=r"^udpflow_[0-9a-f]{24}$")
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    initiator_port: int = Field(alias="initiatorPort", ge=1, le=65_535)
    responder_port: int = Field(alias="responderPort", ge=1, le=65_535)
    datagram_count: int = Field(alias="datagramCount", ge=1)
    initiator_datagram_count: int = Field(alias="initiatorDatagramCount", ge=0)
    responder_datagram_count: int = Field(alias="responderDatagramCount", ge=0)
    initiator_payload_bytes: int = Field(alias="initiatorPayloadBytes", ge=0)
    responder_payload_bytes: int = Field(alias="responderPayloadBytes", ge=0)
    duration_microseconds: int = Field(alias="durationMicroseconds", ge=0)
    l1_bytes_per_flow: int = Field(alias="l1BytesPerFlow", ge=1)


class DatagramWorkloadTemplateBinding(StrictModel):
    id: str = Field(pattern=r"^udptemplate_[0-9a-f]{24}$")
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    representative_flow: DatagramFlowBinding = Field(alias="representativeFlow")
    occurrence_count: int = Field(alias="occurrenceCount", ge=1)
    weight: float = Field(gt=0, le=1)
    fps: float = Field(gt=0)


class DatagramWorkloadBinding(StrictModel):
    selection: Literal["all-datagram-flows"] = "all-datagram-flows"
    source_flow_count: int = Field(alias="sourceFlowCount", ge=1)
    template_count: int = Field(alias="templateCount", ge=1, le=256)
    templates: list[DatagramWorkloadTemplateBinding] = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def consistent_aggregation(self) -> DatagramWorkloadBinding:
        if self.template_count != len(self.templates):
            raise ValueError("datagram workload templateCount must equal its templates")
        if self.source_flow_count != sum(item.occurrence_count for item in self.templates):
            raise ValueError("datagram workload sourceFlowCount must equal template occurrences")
        if abs(sum(item.weight for item in self.templates) - 1) > 1e-9:
            raise ValueError("datagram workload template weights must sum to one")
        return self


class DatagramReplayRole(StrictModel):
    role: str
    port: str
    mac: str
    ipv4: str


class UdpWorkloadRun(StrictModel):
    fps: float = Field(gt=0)
    estimated_pps: float = Field(alias="estimatedPps", gt=0)
    estimated_bps_l1: float = Field(alias="estimatedBpsL1", gt=0)
    duration: DurationMs

    @model_validator(mode="after")
    def positive_duration(self) -> UdpWorkloadRun:
        if self.duration <= 0:
            raise ValueError("UDP workload duration must be greater than zero")
        return self


class UdpWorkloadSpec(StrictModel):
    safety: SafetyDeclaration
    limits: Limits = Field(default_factory=Limits)
    capture: CaptureBinding
    workload: DatagramWorkloadBinding
    initiator: DatagramReplayRole
    responder: DatagramReplayRole
    run: UdpWorkloadRun
    semantic_differences: list[str] = Field(alias="semanticDifferences", min_length=1)

    def logical_ports(self) -> set[str]:
        return {self.initiator.port, self.responder.port}


class UdpWorkloadDocument(StrictModel):
    api_version: Literal["trex.example.io/v1"] = Field(alias="apiVersion")
    kind: Literal["UdpWorkload"]
    metadata: Metadata = Field(default_factory=Metadata)
    spec: UdpWorkloadSpec


class DnsQuestion(StrictModel):
    name: str = Field(min_length=2, max_length=254, pattern=r"^[A-Za-z0-9_.-]+\.$")
    type: Literal["A", "AAAA"]
    dns_class: Literal["IN"] = Field(default="IN", alias="class")
    recursion_desired: bool = Field(default=True, alias="recursionDesired")


class DnsStormClient(StrictModel):
    role: str
    port: str
    mac: str
    ipv4: str
    udp_source_port_start: int = Field(alias="udpSourcePortStart", ge=1024, le=65_535)
    udp_source_port_end: int = Field(alias="udpSourcePortEnd", ge=1024, le=65_535)

    @model_validator(mode="after")
    def ordered_source_ports(self) -> DnsStormClient:
        if self.udp_source_port_start > self.udp_source_port_end:
            raise ValueError("DNS source port start must not exceed end")
        return self

    @property
    def source_port_count(self) -> int:
        return self.udp_source_port_end - self.udp_source_port_start + 1


class DnsStormServer(StrictModel):
    role: str
    port: str
    mac: str
    ipv4: str
    udp_port: Literal[53] = Field(default=53, alias="udpPort")


class PacketStormRun(StrictModel):
    pps: float = Field(gt=0)
    wire_size: int = Field(alias="wireSize", ge=64, le=512)
    estimated_bps_l1: float = Field(alias="estimatedBpsL1", gt=0)
    duration: DurationMs

    @model_validator(mode="after")
    def positive_duration(self) -> PacketStormRun:
        if self.duration <= 0:
            raise ValueError("Packet Storm duration must be greater than zero")
        derived_bps_l1 = self.pps * (self.wire_size + 20) * 8
        if abs(self.estimated_bps_l1 - derived_bps_l1) > max(1e-6, derived_bps_l1 * 1e-9):
            raise ValueError("Packet Storm estimatedBpsL1 is inconsistent with pps and wireSize")
        return self


class StormObservation(StrictModel):
    query_delivery: Literal["flow-stats"] = Field(
        default="flow-stats", alias="queryDelivery"
    )
    responses: Literal["unavailable"] = "unavailable"


class DhcpStormClients(StrictModel):
    role: str
    port: str
    mac_start: str = Field(alias="macStart")
    mac_end: str = Field(alias="macEnd")
    count: int = Field(ge=1)

    @model_validator(mode="after")
    def consistent_pool(self) -> DhcpStormClients:
        expected_end = dhcp_client_mac_end(self.mac_start, self.count)
        if self.mac_end.lower() != expected_end:
            raise ValueError("DHCP client MAC pool is inconsistent with count")
        return self


class DhcpStormServer(StrictModel):
    role: str
    port: str


class DhcpMessage(StrictModel):
    type: Literal["discover"] = "discover"
    client_port: Literal[68] = Field(default=68, alias="clientPort")
    server_port: Literal[67] = Field(default=67, alias="serverPort")
    broadcast_reply_requested: Literal[True] = Field(default=True, alias="broadcastReplyRequested")


class DhcpNetwork(StrictModel):
    broadcast_domain: Literal[True] = Field(default=True, alias="broadcastDomain")
    ethernet_destination: Literal["ff:ff:ff:ff:ff:ff"] = Field(
        default="ff:ff:ff:ff:ff:ff", alias="ethernetDestination"
    )
    ipv4_source: Literal["0.0.0.0"] = Field(default="0.0.0.0", alias="ipv4Source")
    ipv4_destination: Literal["255.255.255.255"] = Field(
        default="255.255.255.255", alias="ipv4Destination"
    )


class DhcpStormObservation(StrictModel):
    discover_delivery: Literal["flow-stats"] = Field(default="flow-stats", alias="discoverDelivery")
    offers: Literal["unavailable"] = "unavailable"


class ArpStormSenders(StrictModel):
    role: str
    port: str
    mac_start: str = Field(alias="macStart")
    mac_end: str = Field(alias="macEnd")
    ipv4_start: str = Field(alias="ipv4Start")
    ipv4_end: str = Field(alias="ipv4End")
    count: int = Field(ge=1)

    @model_validator(mode="after")
    def consistent_pool(self) -> ArpStormSenders:
        if self.mac_end.lower() != arp_sender_mac_end(self.mac_start, self.count):
            raise ValueError("ARP sender identity pool has an inconsistent MAC range")
        if self.ipv4_end != arp_sender_ipv4_end(self.ipv4_start, self.count):
            raise ValueError("ARP sender identity pool has an inconsistent IPv4 range")
        return self


class ArpStormTarget(StrictModel):
    role: str
    port: str
    ipv4: str

    @field_validator("ipv4")
    @classmethod
    def valid_ipv4(cls, value: str) -> str:
        try:
            return str(ipaddress.IPv4Address(value))
        except ipaddress.AddressValueError as error:
            raise ValueError("ARP target IPv4 must be a valid IPv4 address") from error


class ArpMessage(StrictModel):
    operation: Literal["request"] = "request"
    hardware_type: Literal["ethernet"] = Field(default="ethernet", alias="hardwareType")
    protocol_type: Literal["ipv4"] = Field(default="ipv4", alias="protocolType")


class ArpNetwork(StrictModel):
    broadcast_domain: Literal[True] = Field(default=True, alias="broadcastDomain")
    ethernet_destination: Literal["ff:ff:ff:ff:ff:ff"] = Field(
        default="ff:ff:ff:ff:ff:ff", alias="ethernetDestination"
    )


class ArpStormObservation(StrictModel):
    request_transmission: Literal["hardware-port-counter"] = Field(
        default="hardware-port-counter", alias="requestTransmission"
    )
    request_delivery: Literal["unavailable"] = Field(
        default="unavailable", alias="requestDelivery"
    )
    replies: Literal["unavailable"] = "unavailable"
    limitation: Literal["hardware-flow-stats-unsupported-for-arp"] = (
        "hardware-flow-stats-unsupported-for-arp"
    )


class DnsStormSpec(StrictModel):
    protocol: Literal["dns"] = "dns"
    safety: SafetyDeclaration
    limits: Limits = Field(default_factory=Limits)
    client: DnsStormClient
    server: DnsStormServer
    question: DnsQuestion
    run: PacketStormRun
    observation: StormObservation = Field(default_factory=StormObservation)

    @model_validator(mode="after")
    def distinct_ports(self) -> DnsStormSpec:
        if self.client.port == self.server.port:
            raise ValueError("DNS storm client and server must use different ports")
        payload = encode_dns_query(
            self.question.name,
            self.question.type,
            recursion_desired=self.question.recursion_desired,
        )
        if self.run.wire_size != dns_query_wire_size(payload):
            raise ValueError("DNS query wire size does not match the typed question")
        return self

    def logical_ports(self) -> set[str]:
        return {self.client.port, self.server.port}


class DhcpStormSpec(StrictModel):
    protocol: Literal["dhcp"] = "dhcp"
    safety: SafetyDeclaration
    limits: Limits = Field(default_factory=Limits)
    clients: DhcpStormClients
    server: DhcpStormServer
    message: DhcpMessage = Field(default_factory=DhcpMessage)
    network: DhcpNetwork = Field(default_factory=DhcpNetwork)
    run: PacketStormRun
    observation: DhcpStormObservation = Field(default_factory=DhcpStormObservation)

    @model_validator(mode="after")
    def distinct_ports(self) -> DhcpStormSpec:
        if self.clients.port == self.server.port:
            raise ValueError("DHCP storm client and server must use different ports")
        payload = encode_dhcp_discover(self.clients.mac_start)
        if self.run.wire_size != dhcp_discover_wire_size(payload):
            raise ValueError("DHCP Discover wire size does not match the closed template")
        return self

    def logical_ports(self) -> set[str]:
        return {self.clients.port, self.server.port}


class ArpStormSpec(StrictModel):
    protocol: Literal["arp"] = "arp"
    safety: SafetyDeclaration
    limits: Limits = Field(default_factory=Limits)
    senders: ArpStormSenders
    target: ArpStormTarget
    message: ArpMessage = Field(default_factory=ArpMessage)
    network: ArpNetwork = Field(default_factory=ArpNetwork)
    run: PacketStormRun
    observation: ArpStormObservation = Field(default_factory=ArpStormObservation)

    @model_validator(mode="after")
    def closed_template(self) -> ArpStormSpec:
        if self.senders.port == self.target.port:
            raise ValueError("ARP storm sender and target must use different ports")
        if self.run.wire_size != ARP_REQUEST_WIRE_SIZE:
            raise ValueError("ARP Request wire size does not match the closed template")
        return self

    def logical_ports(self) -> set[str]:
        return {self.senders.port, self.target.port}


type PacketStormSpec = Annotated[
    DnsStormSpec | DhcpStormSpec | ArpStormSpec, Field(discriminator="protocol")
]


class PacketStormDocument(StrictModel):
    api_version: Literal["trex.example.io/v1"] = Field(alias="apiVersion")
    kind: Literal["PacketStorm"]
    metadata: Metadata = Field(default_factory=Metadata)
    spec: PacketStormSpec


class Rfc2544ThroughputDocument(StrictModel):
    api_version: Literal["trex.example.io/v1"] = Field(alias="apiVersion")
    kind: Literal["Rfc2544Throughput"]
    metadata: Metadata = Field(default_factory=Metadata)
    spec: Rfc2544ThroughputSpec


type Rfc2544TestName = Literal["throughput", "latency", "frame-loss", "back-to-back"]


class Rfc2544LatencySettings(StrictModel):
    definition: Literal["store-and-forward", "bit-forwarding"]
    scenarios: list[Literal["same-destination", "new-destination"]]
    repetitions: int = Field(default=20, ge=20)
    trial_seconds: float = Field(default=120, alias="trialSeconds", ge=120)
    tag_after_seconds: float = Field(default=60, alias="tagAfterSeconds", ge=60)
    new_destination_packet: RfcPacket | None = Field(default=None, alias="newDestinationPacket")

    @field_validator("scenarios")
    @classmethod
    def unique_scenarios(
        cls, value: list[Literal["same-destination", "new-destination"]]
    ) -> list[Literal["same-destination", "new-destination"]]:
        if len(set(value)) != len(value):
            raise ValueError("latency scenarios must be unique")
        return value


class Rfc9004BackToBackSettings(StrictModel):
    repetitions: int = Field(default=20, ge=1)
    minimum_step_frames: int = Field(default=1, alias="minimumStepFrames", ge=1)
    maximum_burst_frames: int = Field(alias="maximumBurstFrames", ge=2)
    maximum_burst_seconds: float = Field(default=30, alias="maximumBurstSeconds", ge=30)
    buffer_depletion_seconds: float = Field(default=2, alias="bufferDepletionSeconds", ge=2)


class Rfc2544SuiteSpec(Rfc2544ThroughputSpec):
    tests: list[Rfc2544TestName] = Field(min_length=1)
    report_context: Rfc2544ReportContext | None = Field(default=None, alias="reportContext")
    latency: Rfc2544LatencySettings | None = None
    back_to_back: Rfc9004BackToBackSettings | None = Field(default=None, alias="backToBack")

    @field_validator("tests")
    @classmethod
    def unique_tests(cls, value: list[Rfc2544TestName]) -> list[Rfc2544TestName]:
        if len(set(value)) != len(value):
            raise ValueError("RFC2544 suite tests must be unique")
        return value

    @model_validator(mode="after")
    def assertion_targets_throughput(self) -> Rfc2544SuiteSpec:
        if self.assertion is not None and "throughput" not in self.tests:
            raise ValueError("throughput assertion requires the throughput suite test")
        if "latency" in self.tests:
            if self.latency is None:
                raise ValueError("latency settings are required by the latency suite test")
            if "throughput" not in self.tests or self.tests.index("throughput") > self.tests.index(
                "latency"
            ):
                raise ValueError("throughput must run before latency")
            if self.mode == "strict" and set(self.latency.scenarios) != {
                "same-destination",
                "new-destination",
            }:
                raise ValueError("strict latency requires both destination scenarios")
        elif self.latency is not None:
            raise ValueError("latency settings require the latency suite test")
        if "back-to-back" in self.tests:
            if self.back_to_back is None:
                raise ValueError("back-to-back settings are required by the suite test")
            if "throughput" not in self.tests or self.tests.index("throughput") > self.tests.index(
                "back-to-back"
            ):
                raise ValueError("throughput must run before back-to-back")
        elif self.back_to_back is not None:
            raise ValueError("back-to-back settings require the back-to-back suite test")
        return self


class Rfc2544SuiteDocument(StrictModel):
    api_version: Literal["trex.example.io/v1"] = Field(alias="apiVersion")
    kind: Literal["Rfc2544Suite"]
    metadata: Metadata = Field(default_factory=Metadata)
    spec: Rfc2544SuiteSpec


type JobDocument = Annotated[
    StatelessTrafficDocument
    | PcapReplayDocument
    | StatefulReplayDocument
    | UdpWorkloadDocument
    | PacketStormDocument
    | Rfc2544ThroughputDocument
    | Rfc2544SuiteDocument,
    Field(discriminator="kind"),
]
JOB_DOCUMENT_ADAPTER: TypeAdapter[JobDocument] = TypeAdapter(JobDocument)


class SubmitBody(StrictModel):
    document: JobDocument
    retry_of: str | None = Field(default=None, alias="retryOf", pattern=r"^job_[0-9A-Z]+$")


class CancelBody(StrictModel):
    cancel_request_id: str = Field(alias="cancelRequestId", min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=512)


class ArtifactRef(StrictModel):
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    media_type: str = Field(alias="mediaType")
    size: int = Field(ge=0)
    name: str


class Provenance(StrictModel):
    submitted_spec_digest: str = Field(alias="submittedSpecDigest")
    resolved_spec_digest: str = Field(alias="resolvedSpecDigest")
    policy_version: str = Field(alias="policyVersion")
    agent_version: str = Field(alias="agentVersion")
    simulated: bool
    engine: str
    trex_version: str | None = Field(default=None, alias="trexVersion")


class JobResult(StrictModel):
    verdict: Verdict
    methodology: str
    summary: dict[str, Any]
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    provenance: Provenance
    warnings: list[Problem] = Field(default_factory=list)


class Phase(StrictModel):
    name: str
    detail: dict[str, Any] = Field(default_factory=dict)


class Progress(StrictModel):
    completed: int = Field(ge=0)
    total: int | None = Field(default=None, ge=0)


class JobSnapshot(StrictModel):
    job_id: str = Field(alias="jobId")
    revision: int = Field(ge=1)
    state: JobState
    kind: Literal[
        "StatelessTraffic",
        "PcapReplay",
        "StatefulReplay",
        "UdpWorkload",
        "PacketStorm",
        "Rfc2544Throughput",
        "Rfc2544Suite",
    ]
    submitted_spec_digest: str = Field(alias="submittedSpecDigest")
    resolved_spec_digest: str | None = Field(default=None, alias="resolvedSpecDigest")
    retry_of: str | None = Field(default=None, alias="retryOf")
    submitted_at: datetime = Field(alias="submittedAt")
    started_at: datetime | None = Field(default=None, alias="startedAt")
    finished_at: datetime | None = Field(default=None, alias="finishedAt")
    phase: Phase | None = None
    progress: Progress | None = None
    cancel_requested: bool = Field(default=False, alias="cancelRequested")
    result: JobResult | None = None
    problem: Problem | None = None


class Principal(StrictModel):
    name: str
    role: Role


def utc_now() -> datetime:
    return datetime.now(tz=UTC)


def canonical_document(document: JobDocument) -> str:
    payload = document.model_dump(mode="json", by_alias=True, exclude_none=True)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def snapshot_json(snapshot: JobSnapshot) -> str:
    return snapshot.model_dump_json(by_alias=True, exclude_none=True)
