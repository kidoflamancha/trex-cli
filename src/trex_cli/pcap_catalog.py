from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Literal

import dpkt  # type: ignore[import-untyped]
from pydantic import Field

from trex_cli.datagram_analysis import DatagramCaptureAnalysis, DatagramFlowAnalyzer
from trex_cli.models import StrictModel
from trex_cli.session_analysis import StatefulCaptureAnalysis, StatefulSessionAnalyzer

_RESOURCE_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}(?:/[A-Za-z0-9][A-Za-z0-9_.-]{0,127})*$"
CATALOG_API_VERSION: Literal["trex.example.io/catalog/v1"] = "trex.example.io/catalog/v1"


class CaptureMetadata(StrictModel):
    name: str = Field(min_length=1, max_length=256, pattern=_RESOURCE_NAME_PATTERN)
    revision: int = Field(ge=1)
    description: str | None = Field(default=None, max_length=512)


class CaptureAnalysis(StrictModel):
    link_type: Literal["ethernet"] = Field(alias="linkType")
    packet_count: int = Field(alias="packetCount", ge=0)
    captured_bytes: int = Field(alias="capturedBytes", ge=0)
    first_timestamp_seconds: float | None = Field(alias="firstTimestampSeconds")
    last_timestamp_seconds: float | None = Field(alias="lastTimestampSeconds")
    duration_seconds: float = Field(alias="durationSeconds", ge=0)
    normalized_duration_seconds: float = Field(alias="normalizedDurationSeconds", ge=0)
    non_monotonic_timestamp_count: int = Field(alias="nonMonotonicTimestampCount", ge=0)
    maximum_backward_jump_seconds: float = Field(alias="maximumBackwardJumpSeconds", ge=0)
    protocols: dict[str, int]
    mac_endpoints: list[str] = Field(alias="macEndpoints")
    ipv4_endpoints: list[str] = Field(alias="ipv4Endpoints")
    vlan_ids: list[int] = Field(alias="vlanIds")
    broadcast_packets: int = Field(alias="broadcastPackets", ge=0)
    multicast_packets: int = Field(alias="multicastPackets", ge=0)
    safety: CaptureSafetySummary
    stateful: StatefulCaptureAnalysis | None = None
    datagram: DatagramCaptureAnalysis | None = None


class CaptureSafetySummary(StrictModel):
    benchmark_ipv4_endpoints: list[str] = Field(alias="benchmarkIpv4Endpoints")
    private_ipv4_endpoints: list[str] = Field(alias="privateIpv4Endpoints")
    public_ipv4_endpoints: list[str] = Field(alias="publicIpv4Endpoints")
    has_broadcast: bool = Field(alias="hasBroadcast")
    has_multicast: bool = Field(alias="hasMulticast")


class CaptureResourceDocument(StrictModel):
    api_version: Literal[
        "trex.example.io/catalog/v1", "trex.example.io/v2alpha1"
    ] = Field(alias="apiVersion")
    kind: Literal["CaptureResource"]
    metadata: CaptureMetadata
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    size: int = Field(ge=0)
    analysis: CaptureAnalysis


@dataclass(frozen=True, slots=True)
class CaptureResource:
    document: CaptureResourceDocument

    @property
    def name(self) -> str:
        return self.document.metadata.name

    @property
    def revision(self) -> int:
        return self.document.metadata.revision

    @property
    def ref(self) -> str:
        return f"{self.name}@{self.revision}"

    @property
    def digest(self) -> str:
        return self.document.digest


class CaptureCatalog:
    """Publishes and analyzes immutable captures behind one catalog interface."""

    def __init__(self, root: Path, *, maximum_bytes: int = 1_073_741_824) -> None:
        self._root = root
        self._maximum_bytes = maximum_bytes
        self._lock = threading.RLock()

    def publish(
        self,
        *,
        name: str,
        source: BinaryIO,
        description: str | None = None,
    ) -> CaptureResource:
        CaptureMetadata(name=name, revision=1, description=description)
        with self._lock:
            objects = self._root / "objects"
            objects.mkdir(parents=True, exist_ok=True)
            descriptor_root = self._root / "resources"
            descriptor_root.mkdir(parents=True, exist_ok=True)
            descriptor, digest, size = self._stage(source, objects)
            try:
                existing = self._latest(name)
                if existing is not None and existing.digest == digest:
                    return existing
                analysis = analyze_capture(descriptor)
                revision = 1 if existing is None else existing.revision + 1
                document = CaptureResourceDocument(
                    apiVersion=CATALOG_API_VERSION,
                    kind="CaptureResource",
                    metadata=CaptureMetadata(
                        name=name,
                        revision=revision,
                        description=description,
                    ),
                    digest=digest,
                    size=size,
                    analysis=analysis,
                )
                object_path = self.object_path(digest)
                object_path.parent.mkdir(parents=True, exist_ok=True)
                if object_path.exists():
                    descriptor.unlink()
                else:
                    os.replace(descriptor, object_path)
                self._write_descriptor(document)
                return CaptureResource(document)
            finally:
                if descriptor.exists():
                    descriptor.unlink()

    def search(self, query: str = "") -> list[CaptureResource]:
        latest: dict[str, CaptureResource] = {}
        for path in (self._root / "resources").rglob("*.json"):
            resource = self._read_descriptor(path)
            current = latest.get(resource.name)
            if current is None or resource.revision > current.revision:
                latest[resource.name] = resource
        folded = query.casefold()
        return sorted(
            (
                resource
                for resource in latest.values()
                if folded in resource.name.casefold()
                or (
                    resource.document.metadata.description is not None
                    and folded in resource.document.metadata.description.casefold()
                )
            ),
            key=lambda resource: (resource.name, resource.revision),
        )

    def describe(self, ref: str) -> CaptureResource:
        name, revision = _parse_ref(ref)
        if revision is None:
            resource = self._latest(name)
            if resource is None:
                raise ValueError(f"Capture Resource not found: {ref}")
            return resource
        path = self._descriptor_path(name, revision)
        if not path.exists():
            raise ValueError(f"Capture Resource not found: {ref}")
        return self._read_descriptor(path)

    def object_path(self, digest: str) -> Path:
        digest_hex = digest.removeprefix("sha256:")
        return self._root / "objects" / digest_hex[:2] / digest_hex

    def _stage(self, source: BinaryIO, objects: Path) -> tuple[Path, str, int]:
        descriptor, temporary = tempfile.mkstemp(prefix=".capture-", dir=objects)
        digest = hashlib.sha256()
        size = 0
        try:
            with os.fdopen(descriptor, "wb") as output:
                while chunk := source.read(1024 * 1024):
                    size += len(chunk)
                    if size > self._maximum_bytes:
                        raise ValueError(
                            f"Capture Resource exceeds {self._maximum_bytes} byte limit"
                        )
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            return Path(temporary), f"sha256:{digest.hexdigest()}", size
        except Exception:
            Path(temporary).unlink(missing_ok=True)
            raise

    def _latest(self, name: str) -> CaptureResource | None:
        candidates = []
        parent = self._descriptor_path(name, 1).parent
        prefix = Path(name).name + "@"
        for path in parent.glob(f"{prefix}*.json"):
            candidates.append(self._read_descriptor(path))
        return max(candidates, key=lambda resource: resource.revision, default=None)

    def _descriptor_path(self, name: str, revision: int) -> Path:
        resource_name = Path(name)
        return (
            self._root
            / "resources"
            / resource_name.parent
            / f"{resource_name.name}@{revision}.json"
        )

    def _write_descriptor(self, document: CaptureResourceDocument) -> None:
        path = self._descriptor_path(document.metadata.name, document.metadata.revision)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = document.model_dump_json(by_alias=True, indent=2).encode("utf-8")
        descriptor, temporary = tempfile.mkstemp(prefix=".resource-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)

    @staticmethod
    def _read_descriptor(path: Path) -> CaptureResource:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return CaptureResource(CaptureResourceDocument.model_validate(raw))


def analyze_capture(path: Path) -> CaptureAnalysis:
    protocols: dict[str, int] = {}
    endpoints: set[str] = set()
    mac_endpoints: set[str] = set()
    vlan_ids: set[int] = set()
    packet_count = 0
    captured_bytes = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    previous_timestamp: float | None = None
    minimum_timestamp: float | None = None
    maximum_timestamp: float | None = None
    non_monotonic = 0
    maximum_backward_jump = 0.0
    normalized_duration = 0.0
    broadcast_packets = 0
    multicast_packets = 0
    session_analyzer = StatefulSessionAnalyzer()
    datagram_analyzer = DatagramFlowAnalyzer()
    try:
        with path.open("rb") as source:
            capture = dpkt.pcap.Reader(source)
            if capture.datalink() != dpkt.pcap.DLT_EN10MB:
                raise ValueError("only Ethernet PCAP is supported")
            for timestamp, packet in capture:
                current_timestamp = float(timestamp)
                if first_timestamp is None:
                    first_timestamp = current_timestamp
                if previous_timestamp is not None and current_timestamp < previous_timestamp:
                    non_monotonic += 1
                    maximum_backward_jump = max(
                        maximum_backward_jump,
                        previous_timestamp - current_timestamp,
                    )
                if previous_timestamp is not None:
                    normalized_duration += max(0.0, current_timestamp - previous_timestamp)
                previous_timestamp = current_timestamp
                last_timestamp = current_timestamp
                minimum_timestamp = (
                    current_timestamp
                    if minimum_timestamp is None
                    else min(minimum_timestamp, current_timestamp)
                )
                maximum_timestamp = (
                    current_timestamp
                    if maximum_timestamp is None
                    else max(maximum_timestamp, current_timestamp)
                )
                packet_count += 1
                captured_bytes += len(packet)
                _increment(protocols, "ethernet")
                ethernet = dpkt.ethernet.Ethernet(packet)
                session_analyzer.observe(ethernet)
                datagram_analyzer.observe(current_timestamp, ethernet)
                mac_endpoints.add(ethernet.src.hex(":"))
                mac_endpoints.add(ethernet.dst.hex(":"))
                if ethernet.dst == b"\xff" * 6:
                    broadcast_packets += 1
                elif ethernet.dst[0] & 1:
                    multicast_packets += 1
                for tag in getattr(ethernet, "vlan_tags", ()):
                    vlan_ids.add(int(tag.id))
                payload = ethernet.data
                if isinstance(payload, dpkt.ip.IP):
                    _increment(protocols, "ipv4")
                    endpoints.add(str(ipaddress.IPv4Address(payload.src)))
                    endpoints.add(str(ipaddress.IPv4Address(payload.dst)))
                    if isinstance(payload.data, dpkt.udp.UDP):
                        _increment(protocols, "udp")
                    elif isinstance(payload.data, dpkt.tcp.TCP):
                        _increment(protocols, "tcp")
                    elif isinstance(payload.data, dpkt.icmp.ICMP):
                        _increment(protocols, "icmp")
                elif isinstance(payload, dpkt.arp.ARP):
                    _increment(protocols, "arp")
                    if payload.pro != dpkt.ethernet.ETH_TYPE_IP or payload.pln != 4:
                        _increment(protocols, "unsupported-network")
                    else:
                        endpoints.add(str(ipaddress.IPv4Address(payload.spa)))
                        endpoints.add(str(ipaddress.IPv4Address(payload.tpa)))
                else:
                    _increment(protocols, "unsupported-network")
    except (dpkt.NeedData, dpkt.UnpackError, ValueError) as error:
        raise ValueError(f"invalid or unsupported PCAP: {error}") from error
    duration = (
        0.0
        if minimum_timestamp is None or maximum_timestamp is None
        else maximum_timestamp - minimum_timestamp
    )
    benchmark_network = ipaddress.IPv4Network("198.18.0.0/15")
    private_networks = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    ordered_endpoints = sorted(endpoints, key=ipaddress.IPv4Address)
    benchmark_endpoints = [
        endpoint
        for endpoint in ordered_endpoints
        if ipaddress.IPv4Address(endpoint) in benchmark_network
    ]
    private_endpoints = [
        endpoint
        for endpoint in ordered_endpoints
        if any(ipaddress.IPv4Address(endpoint) in network for network in private_networks)
    ]
    public_endpoints = [
        endpoint
        for endpoint in ordered_endpoints
        if endpoint not in benchmark_endpoints and endpoint not in private_endpoints
    ]
    return CaptureAnalysis(
        linkType="ethernet",
        packetCount=packet_count,
        capturedBytes=captured_bytes,
        firstTimestampSeconds=first_timestamp,
        lastTimestampSeconds=last_timestamp,
        durationSeconds=duration,
        normalizedDurationSeconds=normalized_duration,
        nonMonotonicTimestampCount=non_monotonic,
        maximumBackwardJumpSeconds=maximum_backward_jump,
        protocols=protocols,
        macEndpoints=sorted(mac_endpoints),
        ipv4Endpoints=ordered_endpoints,
        vlanIds=sorted(vlan_ids),
        broadcastPackets=broadcast_packets,
        multicastPackets=multicast_packets,
        safety=CaptureSafetySummary(
            benchmarkIpv4Endpoints=benchmark_endpoints,
            privateIpv4Endpoints=private_endpoints,
            publicIpv4Endpoints=public_endpoints,
            hasBroadcast=broadcast_packets > 0,
            hasMulticast=multicast_packets > 0,
        ),
        stateful=session_analyzer.finish(),
        datagram=datagram_analyzer.finish(),
    )


def _increment(values: dict[str, int], name: str) -> None:
    values[name] = values.get(name, 0) + 1


def _parse_ref(ref: str) -> tuple[str, int | None]:
    name, separator, raw_revision = ref.rpartition("@")
    if not separator:
        return ref, None
    if not raw_revision.isdigit() or int(raw_revision) < 1:
        raise ValueError("Capture Resource revision must be a positive integer")
    return name, int(raw_revision)
