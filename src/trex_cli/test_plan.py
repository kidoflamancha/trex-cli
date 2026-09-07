from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Literal, cast

from pydantic import Field, ValidationError, field_validator, model_validator

from trex_cli.address_policy import ipv4_range_allowed, mac_range_allowed
from trex_cli.arp_storm import ARP_REQUEST_WIRE_SIZE, arp_sender_ipv4_end, arp_sender_mac_end
from trex_cli.config import SafetyPolicy
from trex_cli.dhcp_storm import (
    dhcp_client_mac_end,
    dhcp_discover_wire_size,
    encode_dhcp_discover,
)
from trex_cli.dns_storm import dns_query_wire_size, encode_dns_query, normalize_dns_name
from trex_cli.models import (
    ArpStormSpec,
    DnsStormSpec,
    PacketStormDocument,
    PcapReplayDocument,
    Rate,
    Rfc2544ReportContext,
    Rfc2544SuiteDocument,
    Rfc2544TestName,
    RfcPacket,
    StatefulReplayDocument,
    StatelessTrafficDocument,
    StrictModel,
    UdpWorkloadDocument,
    canonical_document,
    sha256_text,
)
from trex_cli.pcap_catalog import CaptureCatalog, CaptureResourceDocument
from trex_cli.yaml_loader import load_yaml

_RESOURCE_NAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}(?:/[A-Za-z0-9][A-Za-z0-9_.-]{0,127})*$"
)
_PLAN_ID_RE = re.compile(r"^plan_[0-9a-f]{24}$")
_REFERENCE_RE = re.compile(r"^\$\{(param|role)\.([^}.]+)(?:\.([^}]+))?\}$")
_RATE_RE = re.compile(r"^(\d+(?:\.\d+)?)(%|pps|[kmg]?bps)$", re.IGNORECASE)
CATALOG_API_VERSION = "trex.example.io/catalog/v1"
LEGACY_CATALOG_API_VERSION = "trex.example.io/v2alpha1"
TEST_PLAN_API_VERSION = "trex.example.io/test-plan/v1"
LEGACY_TEST_PLAN_API_VERSION = "trex.example.io/plan/v2alpha1"


class TestPlanError(ValueError):
    pass


def _weighted_integer_allocation(total: int, weights: dict[str, int]) -> dict[str, int]:
    if total < len(weights):
        raise ValueError("total allocation is smaller than the number of weights")
    denominator = sum(weights.values())
    distributable = total - len(weights)
    allocation = {
        name: 1 + distributable * weight // denominator for name, weight in weights.items()
    }
    remaining = total - sum(allocation.values())
    priority = sorted(
        weights,
        key=lambda name: (-(distributable * weights[name] % denominator), name),
    )
    for name in priority[:remaining]:
        allocation[name] += 1
    return allocation


class ResourceMetadata(StrictModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    description: str | None = Field(default=None, max_length=512)
    revision: int = Field(default=1, ge=1)


class ParameterDefinition(StrictModel):
    type: Literal["integer", "number", "string", "boolean"]
    default: Any | None = None
    required: bool = False
    minimum: float | None = None
    maximum: float | None = None
    description: str | None = Field(default=None, max_length=512)


class FrameSizeWeight(StrictModel):
    wire_size: Any = Field(alias="wireSize")
    weight: int = Field(default=1, ge=1)


class FrameTemplate(StrictModel):
    wire_size: Any | None = Field(default=None, alias="wireSize")
    sizes: list[FrameSizeWeight] = Field(default_factory=list)

    @model_validator(mode="after")
    def one_sizing_mode(self) -> FrameTemplate:
        if (self.wire_size is None) == (not self.sizes):
            raise ValueError("frame requires exactly one of wireSize or sizes")
        return self


class FlowTemplate(StrictModel):
    from_role: str = Field(alias="from", min_length=1, max_length=128)
    to_role: str = Field(alias="to", min_length=1, max_length=128)
    weight: int = Field(default=1, ge=1)
    frame: FrameTemplate
    packet: dict[str, Any]


class TrafficProfileDocument(StrictModel):
    api_version: Literal[
        "trex.example.io/catalog/v1", "trex.example.io/v2alpha1"
    ] = Field(alias="apiVersion")
    kind: Literal["TrafficProfile"]
    metadata: ResourceMetadata
    parameters: dict[str, ParameterDefinition] = Field(default_factory=dict)
    flows: dict[str, FlowTemplate]

    @field_validator("parameters")
    @classmethod
    def valid_parameter_names(
        cls, value: dict[str, ParameterDefinition]
    ) -> dict[str, ParameterDefinition]:
        for name in value:
            if _RESOURCE_NAME_RE.fullmatch(name) is None:
                raise ValueError(f"invalid name: {name}")
        return value

    @field_validator("flows")
    @classmethod
    def valid_flow_names(cls, value: dict[str, FlowTemplate]) -> dict[str, FlowTemplate]:
        if not value:
            raise ValueError("TrafficProfile must define at least one flow")
        for name in value:
            if _RESOURCE_NAME_RE.fullmatch(name) is None:
                raise ValueError(f"invalid name: {name}")
        return value


class LabRole(StrictModel):
    port: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    mac: str | None = None
    ipv4: str | None = None
    ipv6: str | None = None


class LabSafety(StrictModel):
    isolated_lab: Literal[True] = Field(alias="isolatedLab")
    broadcast_domain: bool = Field(default=False, alias="broadcastDomain")


class LabRunDefaults(StrictModel):
    port_wait_timeout: str = Field(default="30s", alias="portWaitTimeout")
    traffic_job_timeout: str = Field(default="10m", alias="trafficJobTimeout")
    benchmark_job_timeout: str = Field(default="120m", alias="benchmarkJobTimeout")


class LabPathDocument(StrictModel):
    api_version: Literal[
        "trex.example.io/catalog/v1", "trex.example.io/v2alpha1"
    ] = Field(alias="apiVersion")
    kind: Literal["LabPath"]
    metadata: ResourceMetadata
    roles: dict[str, LabRole]
    safety: LabSafety
    report_context: Rfc2544ReportContext | None = Field(default=None, alias="reportContext")
    run_defaults: LabRunDefaults = Field(default_factory=LabRunDefaults, alias="runDefaults")

    @field_validator("roles")
    @classmethod
    def valid_roles(cls, value: dict[str, LabRole]) -> dict[str, LabRole]:
        if len(value) < 2:
            raise ValueError("LabPath must define at least two roles")
        for name in value:
            if _RESOURCE_NAME_RE.fullmatch(name) is None:
                raise ValueError(f"invalid role name: {name}")
        return value


@dataclass(frozen=True, slots=True)
class TrafficProfileResource:
    name: str
    revision: int
    digest: str
    document: TrafficProfileDocument

    @property
    def ref(self) -> str:
        return f"{self.name}@{self.revision}"


@dataclass(frozen=True, slots=True)
class LabPathResource:
    name: str
    revision: int
    digest: str
    document: LabPathDocument

    @property
    def ref(self) -> str:
        return f"{self.name}@{self.revision}"


@dataclass(frozen=True, slots=True)
class CatalogResource:
    kind: Literal["TrafficProfile", "LabPath", "CaptureResource"]
    name: str
    revision: int
    digest: str
    description: str | None
    document: TrafficProfileDocument | LabPathDocument | CaptureResourceDocument

    @property
    def ref(self) -> str:
        return f"{self.name}@{self.revision}"


@dataclass(frozen=True, slots=True)
class IntentPlan:
    plan_id: str
    profile_name: str
    profile_revision: int
    profile_digest: str
    path_name: str
    path_revision: int
    path_digest: str
    flow_names: tuple[str, ...]
    parameters: dict[str, Any]
    rate_input: str
    duration_input: str
    wire_sizes: tuple[int, ...]
    document: StatelessTrafficDocument

    def payload(self) -> dict[str, Any]:
        return {
            "apiVersion": TEST_PLAN_API_VERSION,
            "planId": self.plan_id,
            "intent": "traffic",
            "resources": {
                "profile": {
                    "name": self.profile_name,
                    "revision": self.profile_revision,
                    "ref": f"{self.profile_name}@{self.profile_revision}",
                    "digest": self.profile_digest,
                },
                "path": {
                    "name": self.path_name,
                    "revision": self.path_revision,
                    "ref": f"{self.path_name}@{self.path_revision}",
                    "digest": self.path_digest,
                },
            },
            "parameters": self.parameters,
            "flows": list(self.flow_names),
            "load": {"scope": "per-egress", "requested": self.rate_input},
            "duration": self.duration_input,
            "resolvedStreams": [
                {
                    "name": stream.name,
                    "tx": stream.tx,
                    "rx": stream.rx,
                    "rate": stream.rate.model_dump(mode="json", by_alias=True),
                    "frame": {
                        "wireSizeBytes": stream.packet.frame_size,
                        "generatedSizeBytes": stream.packet.frame_size - 4,
                        "l1SizeBytes": stream.packet.frame_size + 20,
                    },
                }
                for stream in self.document.spec.streams
            ],
            "document": self.document.model_dump(mode="json", by_alias=True, exclude_none=True),
        }


@dataclass(frozen=True, slots=True)
class Rfc2544IntentPlan:
    plan_id: str
    profile_name: str
    profile_revision: int
    profile_digest: str
    path_name: str
    path_revision: int
    path_digest: str
    flow_name: str
    reverse_flow_name: str | None
    latency_new_destination_flow_name: str | None
    parameters: dict[str, Any]
    mode: Literal["strict", "fast"]
    direction_mode: Literal["unidirectional", "bidirectional-simultaneous", "unidirectional-each"]
    tests: tuple[Rfc2544TestName, ...]
    document: Rfc2544SuiteDocument

    def payload(self) -> dict[str, Any]:
        frame_sizes = (
            [64, 128, 256, 512, 1024, 1280, 1518]
            if self.mode == "strict"
            else (self.document.spec.frame_sizes or [64, 512, 1518])
        )
        return {
            "apiVersion": TEST_PLAN_API_VERSION,
            "planId": self.plan_id,
            "intent": "benchmark-rfc2544",
            "resources": {
                "profile": {
                    "name": self.profile_name,
                    "revision": self.profile_revision,
                    "ref": f"{self.profile_name}@{self.profile_revision}",
                    "digest": self.profile_digest,
                },
                "path": {
                    "name": self.path_name,
                    "revision": self.path_revision,
                    "ref": f"{self.path_name}@{self.path_revision}",
                    "digest": self.path_digest,
                },
            },
            "parameters": self.parameters,
            "method": {
                "suite": "rfc2544",
                "tests": list(self.tests),
                "mode": self.mode,
                "directionMode": self.direction_mode,
                "flow": self.flow_name,
                **(
                    {
                        "latency": self.document.spec.latency.model_dump(
                            mode="json", by_alias=True, exclude_none=True
                        )
                    }
                    if self.document.spec.latency is not None
                    else {}
                ),
                **(
                    {
                        "backToBack": self.document.spec.back_to_back.model_dump(
                            mode="json", by_alias=True, exclude_none=True
                        )
                    }
                    if self.document.spec.back_to_back is not None
                    else {}
                ),
                **(
                    {"reverseFlow": self.reverse_flow_name}
                    if self.reverse_flow_name is not None
                    else {}
                ),
                **(
                    {"latencyNewDestinationFlow": (self.latency_new_destination_flow_name)}
                    if self.latency_new_destination_flow_name is not None
                    else {}
                ),
            },
            "resolvedFrameSizes": {
                "source": "method",
                "profileValueOverridden": True,
                "values": frame_sizes,
            },
            "document": self.document.model_dump(mode="json", by_alias=True, exclude_none=True),
        }


@dataclass(frozen=True, slots=True)
class PcapReplayPlan:
    plan_id: str
    capture_name: str
    capture_revision: int
    capture_digest: str
    path_name: str
    path_revision: int
    path_digest: str
    document: PcapReplayDocument

    def payload(self) -> dict[str, Any]:
        return {
            "apiVersion": TEST_PLAN_API_VERSION,
            "planId": self.plan_id,
            "intent": "pcap-replay",
            "resources": {
                "capture": {
                    "name": self.capture_name,
                    "revision": self.capture_revision,
                    "ref": f"{self.capture_name}@{self.capture_revision}",
                    "digest": self.capture_digest,
                },
                "path": {
                    "name": self.path_name,
                    "revision": self.path_revision,
                    "ref": f"{self.path_name}@{self.path_revision}",
                    "digest": self.path_digest,
                },
            },
            "safety": self.document.spec.safety.model_dump(mode="json", by_alias=True),
            "address": self.document.spec.address.model_dump(
                mode="json", by_alias=True, exclude_none=True
            ),
            "timing": self.document.spec.timing.model_dump(
                mode="json", by_alias=True, exclude_none=True
            ),
            "document": self.document.model_dump(mode="json", by_alias=True, exclude_none=True),
        }


@dataclass(frozen=True, slots=True)
class StatefulReplayPlan:
    plan_id: str
    capture_name: str
    capture_revision: int
    capture_digest: str
    path_name: str
    path_revision: int
    path_digest: str
    document: StatefulReplayDocument

    def payload(self) -> dict[str, Any]:
        workload = self.document.spec.workload
        return {
            "apiVersion": TEST_PLAN_API_VERSION,
            "planId": self.plan_id,
            "intent": ("pcap-capture-workload" if workload is not None else "pcap-stateful-replay"),
            "resources": {
                "capture": {
                    "name": self.capture_name,
                    "revision": self.capture_revision,
                    "ref": f"{self.capture_name}@{self.capture_revision}",
                    "digest": self.capture_digest,
                },
                "path": {
                    "name": self.path_name,
                    "revision": self.path_revision,
                    "ref": f"{self.path_name}@{self.path_revision}",
                    "digest": self.path_digest,
                },
            },
            "safety": self.document.spec.safety.model_dump(mode="json", by_alias=True),
            **(
                {"session": self.document.spec.session.model_dump(mode="json", by_alias=True)}
                if self.document.spec.session is not None
                else {
                    "workload": workload.model_dump(mode="json", by_alias=True)
                    if workload is not None
                    else None
                }
            ),
            "run": self.document.spec.run.model_dump(mode="json", by_alias=True),
            "document": self.document.model_dump(mode="json", by_alias=True, exclude_none=True),
        }


@dataclass(frozen=True, slots=True)
class UdpWorkloadPlan:
    plan_id: str
    capture_name: str
    capture_revision: int
    capture_digest: str
    path_name: str
    path_revision: int
    path_digest: str
    document: UdpWorkloadDocument

    def payload(self) -> dict[str, Any]:
        return {
            "apiVersion": TEST_PLAN_API_VERSION,
            "planId": self.plan_id,
            "intent": "pcap-udp-workload",
            "resources": {
                "capture": {
                    "name": self.capture_name,
                    "revision": self.capture_revision,
                    "ref": f"{self.capture_name}@{self.capture_revision}",
                    "digest": self.capture_digest,
                },
                "path": {
                    "name": self.path_name,
                    "revision": self.path_revision,
                    "ref": f"{self.path_name}@{self.path_revision}",
                    "digest": self.path_digest,
                },
            },
            "safety": self.document.spec.safety.model_dump(mode="json", by_alias=True),
            "workload": self.document.spec.workload.model_dump(mode="json", by_alias=True),
            "run": self.document.spec.run.model_dump(mode="json", by_alias=True),
            "document": self.document.model_dump(mode="json", by_alias=True, exclude_none=True),
        }


@dataclass(frozen=True, slots=True)
class DnsStormPlan:
    plan_id: str
    path_name: str
    path_revision: int
    path_digest: str
    document: PacketStormDocument

    def payload(self) -> dict[str, Any]:
        assert isinstance(self.document.spec, DnsStormSpec)
        return {
            "apiVersion": TEST_PLAN_API_VERSION,
            "planId": self.plan_id,
            "intent": "dns-storm",
            "resources": {
                "path": {
                    "name": self.path_name,
                    "revision": self.path_revision,
                    "ref": f"{self.path_name}@{self.path_revision}",
                    "digest": self.path_digest,
                }
            },
            "safety": self.document.spec.safety.model_dump(mode="json", by_alias=True),
            "question": self.document.spec.question.model_dump(mode="json", by_alias=True),
            "run": self.document.spec.run.model_dump(mode="json", by_alias=True),
            "document": self.document.model_dump(mode="json", by_alias=True, exclude_none=True),
        }


@dataclass(frozen=True, slots=True)
class DhcpStormPlan:
    plan_id: str
    path_name: str
    path_revision: int
    path_digest: str
    document: PacketStormDocument

    def payload(self) -> dict[str, Any]:
        return {
            "apiVersion": TEST_PLAN_API_VERSION,
            "planId": self.plan_id,
            "intent": "dhcp-storm",
            "resources": {
                "path": {
                    "name": self.path_name,
                    "revision": self.path_revision,
                    "ref": f"{self.path_name}@{self.path_revision}",
                    "digest": self.path_digest,
                }
            },
            "safety": self.document.spec.safety.model_dump(mode="json", by_alias=True),
            "run": self.document.spec.run.model_dump(mode="json", by_alias=True),
            "document": self.document.model_dump(mode="json", by_alias=True, exclude_none=True),
        }


@dataclass(frozen=True, slots=True)
class ArpStormPlan:
    plan_id: str
    path_name: str
    path_revision: int
    path_digest: str
    document: PacketStormDocument

    def payload(self) -> dict[str, Any]:
        return {
            "apiVersion": TEST_PLAN_API_VERSION,
            "planId": self.plan_id,
            "intent": "arp-storm",
            "resources": {
                "path": {
                    "name": self.path_name,
                    "revision": self.path_revision,
                    "ref": f"{self.path_name}@{self.path_revision}",
                    "digest": self.path_digest,
                }
            },
            "safety": self.document.spec.safety.model_dump(mode="json", by_alias=True),
            "run": self.document.spec.run.model_dump(mode="json", by_alias=True),
            "document": self.document.model_dump(mode="json", by_alias=True, exclude_none=True),
        }


class TestPlanModule:
    """Compiles high-level test intent into an immutable executable plan."""

    def __init__(
        self,
        profile_root: Path,
        path_root: Path,
        plan_root: Path,
        capture_root: Path | None = None,
        safety_policy: SafetyPolicy | None = None,
    ) -> None:
        self._profile_root = profile_root
        self._path_root = path_root
        self._plan_root = plan_root
        self._captures = CaptureCatalog(capture_root or plan_root.parent / ".trex-captures")
        self._safety_policy = safety_policy

    def plan_traffic(
        self,
        *,
        profile_name: str,
        path_name: str,
        parameters: list[str] | tuple[str, ...] = (),
        rate: str,
        duration: str,
        flow_name: str | None = None,
        flow_names: list[str] | tuple[str, ...] = (),
    ) -> IntentPlan:
        profile = self._load_profile(profile_name)
        path = self._load_path(path_name)
        values = _resolve_parameters(profile.document, parameters)
        if flow_name is not None and flow_names:
            raise TestPlanError("flow_name and flow_names cannot be used together")
        requested_flows = tuple(flow_names) or ((flow_name,) if flow_name is not None else ())
        selected = _select_flows(profile.document, requested_flows)

        context = {
            "param": values,
            "role": {
                name: role.model_dump(mode="python", exclude_none=True)
                for name, role in path.document.roles.items()
            },
        }
        resolved_rate = _parse_rate(rate)
        source_weights: dict[str, int] = {}
        for _, flow in selected:
            source_weights[flow.from_role] = source_weights.get(flow.from_role, 0) + flow.weight
        resolved_streams: list[dict[str, Any]] = []
        all_wire_sizes: list[int] = []
        for selected_name, flow in selected:
            if flow.from_role not in path.document.roles:
                raise TestPlanError(f"LabPath {path_name} has no role {flow.from_role}")
            if flow.to_role not in path.document.roles:
                raise TestPlanError(f"LabPath {path_name} has no role {flow.to_role}")
            source_role = path.document.roles[flow.from_role]
            destination_role = path.document.roles[flow.to_role]
            if source_role.port == destination_role.port:
                raise TestPlanError("flow source and destination roles must use different ports")
            frame_entries = (
                [(flow.frame.wire_size, 1)]
                if flow.frame.wire_size is not None
                else [(entry.wire_size, entry.weight) for entry in flow.frame.sizes]
            )
            frame_weight_total = sum(item[1] for item in frame_entries)
            packet_template = _resolve_value(flow.packet, context)
            if not isinstance(packet_template, dict):
                raise TestPlanError("resolved packet must be an object")
            for raw_wire_size, frame_weight in frame_entries:
                wire_size = _resolve_value(raw_wire_size, context)
                if isinstance(wire_size, bool) or not isinstance(wire_size, int):
                    raise TestPlanError("resolved frame wireSize must be an integer")
                stream_rate = _scaled_rate(
                    resolved_rate,
                    flow.weight
                    / source_weights[flow.from_role]
                    * frame_weight
                    / frame_weight_total,
                )
                stream_name = (
                    selected_name if len(frame_entries) == 1 else f"{selected_name}/{wire_size}"
                )
                resolved_streams.append(
                    {
                        "name": stream_name,
                        "tx": source_role.port,
                        "rx": destination_role.port,
                        "packet": {"frameSize": wire_size, **packet_template},
                        "rate": stream_rate.model_dump(
                            mode="json", by_alias=True, exclude_none=True
                        ),
                    }
                )
                all_wire_sizes.append(wire_size)
        first_stream = resolved_streams[0]
        try:
            document = StatelessTrafficDocument.model_validate(
                {
                    "apiVersion": "trex.example.io/v1",
                    "kind": "StatelessTraffic",
                    "metadata": {
                        "name": f"{profile_name}-traffic",
                        "labels": {
                            "intent": "traffic",
                            "profile": profile_name,
                            "path": path_name,
                            "flows": ",".join(name for name, _ in selected),
                        },
                    },
                    "spec": {
                        "safety": {"isolatedLab": path.document.safety.isolated_lab},
                        "ports": {
                            "tx": first_stream["tx"],
                            "rx": first_stream["rx"],
                            "direction": "unidirectional",
                        },
                        "limits": {
                            "portWaitTimeout": path.document.run_defaults.port_wait_timeout,
                            "jobTimeout": path.document.run_defaults.traffic_job_timeout,
                        },
                        "packet": first_stream["packet"],
                        "rate": resolved_rate.model_dump(
                            mode="json", by_alias=True, exclude_none=True
                        ),
                        "duration": duration,
                        "streams": resolved_streams,
                    },
                }
            )
        except ValidationError as error:
            raise TestPlanError(str(error)) from error

        identity = json.dumps(
            {
                "profile": profile.digest,
                "path": path.digest,
                "flows": [name for name, _ in selected],
                "parameters": values,
                "rate": rate.lower(),
                "duration": duration,
                "document": json.loads(canonical_document(document)),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        plan = IntentPlan(
            plan_id="plan_" + sha256_text(identity).removeprefix("sha256:")[:24],
            profile_name=profile.name,
            profile_revision=profile.revision,
            profile_digest=profile.digest,
            path_name=path.name,
            path_revision=path.revision,
            path_digest=path.digest,
            flow_names=tuple(name for name, _ in selected),
            parameters=values,
            rate_input=rate.lower(),
            duration_input=duration,
            wire_sizes=tuple(all_wire_sizes),
            document=document,
        )
        self._persist(plan)
        return plan

    def plan_pcap_replay(
        self,
        *,
        capture_name: str,
        path_name: str,
        source_role: str,
        destination_role: str,
        address_mode: Literal["rewrite", "preserve"] = "rewrite",
        timing_mode: Literal["capture", "fixed-rate", "top-speed"] = "capture",
        multiplier: float = 1,
        timestamp_policy: Literal["reject", "normalize"] = "reject",
        rate: str | None = None,
    ) -> PcapReplayPlan:
        try:
            capture = self._captures.describe(capture_name)
        except ValueError as error:
            raise TestPlanError(str(error)) from error
        path = self._load_path(path_name)
        if source_role not in path.document.roles:
            raise TestPlanError(f"LabPath {path_name} has no role {source_role}")
        if destination_role not in path.document.roles:
            raise TestPlanError(f"LabPath {path_name} has no role {destination_role}")
        source = path.document.roles[source_role]
        destination = path.document.roles[destination_role]
        if source.port == destination.port:
            raise TestPlanError("replay source and destination roles must use different ports")

        analysis = capture.document.analysis
        if address_mode == "rewrite":
            if analysis.protocols.get("unsupported-network", 0):
                raise TestPlanError("replay cannot safely authorize this network protocol")
            if any(
                value is None
                for value in (source.mac, destination.mac, source.ipv4, destination.ipv4)
            ):
                raise TestPlanError("rewrite requires MAC and IPv4 values on both LabPath roles")
            address: dict[str, Any] = {
                "mode": "rewrite",
                "sourceRole": source_role,
                "destinationRole": destination_role,
                "sourceMac": source.mac,
                "destinationMac": destination.mac,
                "sourceIpv4": source.ipv4,
                "destinationIpv4": destination.ipv4,
            }
        else:
            self._validate_preserved_capture(capture.document)
            assert self._safety_policy is not None
            address = {
                "mode": "preserve",
                "policyVersion": self._safety_policy.version,
            }

        if timing_mode == "capture":
            if analysis.non_monotonic_timestamp_count and timestamp_policy == "reject":
                raise TestPlanError(
                    "capture contains non-monotonic timestamps; choose timestampPolicy normalize"
                )
            timing: dict[str, Any] = {
                "mode": "capture",
                "multiplier": multiplier,
                "timestampPolicy": timestamp_policy,
                "normalizedTimestampCount": (
                    analysis.non_monotonic_timestamp_count if timestamp_policy == "normalize" else 0
                ),
            }
        elif timing_mode == "fixed-rate":
            if rate is None:
                raise TestPlanError("fixed-rate timing requires rate")
            resolved_rate = _parse_rate(rate)
            if resolved_rate.unit == "percent_l1":
                raise TestPlanError("fixed-rate PCAP replay does not support percent_l1")
            timing = {
                "mode": "fixed-rate",
                "rate": resolved_rate.model_dump(mode="json", by_alias=True),
            }
        else:
            if rate is not None:
                raise TestPlanError("rate is only valid with fixed-rate timing")
            timing = {"mode": "top-speed"}

        try:
            document = PcapReplayDocument.model_validate(
                {
                    "apiVersion": "trex.example.io/v1",
                    "kind": "PcapReplay",
                    "metadata": {
                        "name": f"{Path(capture.name).name}-replay",
                        "labels": {
                            "intent": "pcap-replay",
                            "capture": capture.name,
                            "path": path.name,
                        },
                    },
                    "spec": {
                        "safety": {"isolatedLab": path.document.safety.isolated_lab},
                        "ports": {
                            "tx": source.port,
                            "rx": destination.port,
                            "direction": "unidirectional",
                        },
                        "limits": {
                            "portWaitTimeout": path.document.run_defaults.port_wait_timeout,
                            "jobTimeout": path.document.run_defaults.traffic_job_timeout,
                        },
                        "capture": {
                            "name": capture.name,
                            "revision": capture.revision,
                            "digest": capture.digest,
                            "size": capture.document.size,
                            "packetCount": analysis.packet_count,
                            "durationSeconds": analysis.duration_seconds,
                            "normalizedDurationSeconds": analysis.normalized_duration_seconds,
                            "nonMonotonicTimestampCount": analysis.non_monotonic_timestamp_count,
                            "maximumBackwardJumpSeconds": analysis.maximum_backward_jump_seconds,
                            "macEndpoints": analysis.mac_endpoints,
                            "ipv4Endpoints": analysis.ipv4_endpoints,
                            "hasBroadcast": analysis.safety.has_broadcast,
                            "hasMulticast": analysis.safety.has_multicast,
                        },
                        "address": address,
                        "timing": timing,
                    },
                }
            )
        except ValidationError as error:
            raise TestPlanError(str(error)) from error
        identity = json.dumps(
            {
                "capture": capture.digest,
                "path": path.digest,
                "document": json.loads(canonical_document(document)),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        plan = PcapReplayPlan(
            plan_id="plan_" + sha256_text(identity).removeprefix("sha256:")[:24],
            capture_name=capture.name,
            capture_revision=capture.revision,
            capture_digest=capture.digest,
            path_name=path.name,
            path_revision=path.revision,
            path_digest=path.digest,
            document=document,
        )
        self._persist(plan)
        return plan

    def plan_dns_storm(
        self,
        *,
        path_name: str,
        client_role: str,
        server_role: str,
        name: str,
        query_type: Literal["A", "AAAA"],
        recursion_desired: bool,
        source_port_start: int,
        source_port_end: int,
        pps: float,
        duration: str,
    ) -> DnsStormPlan:
        policy = self._safety_policy
        if policy is None:
            raise TestPlanError("DNS storm requires a configured SafetyPolicy")
        path = self._load_path(path_name)
        if not path.document.safety.isolated_lab:
            raise TestPlanError("DNS storm requires an isolated LabPath")
        if client_role not in path.document.roles or server_role not in path.document.roles:
            raise TestPlanError("LabPath does not define both DNS storm roles")
        client = path.document.roles[client_role]
        server = path.document.roles[server_role]
        if client.port == server.port:
            raise TestPlanError("DNS storm roles must use different ports")
        if any(value is None for value in (client.mac, client.ipv4, server.mac, server.ipv4)):
            raise TestPlanError("DNS storm roles require MAC and IPv4 addresses")
        assert client.mac is not None
        assert client.ipv4 is not None
        assert server.mac is not None
        assert server.ipv4 is not None
        if source_port_start > source_port_end:
            raise TestPlanError("DNS source port start must not exceed end")
        source_port_count = source_port_end - source_port_start + 1
        if source_port_count > policy.max_address_pool_size:
            raise TestPlanError("DNS source port range exceeds maxAddressPoolSize")
        allowed_networks = [
            ipaddress.ip_network(cidr, strict=False) for cidr in policy.allowed_cidrs
        ]
        for label, address in (("client", client.ipv4), ("server", server.ipv4)):
            if not any(ipaddress.ip_address(address) in network for network in allowed_networks):
                raise TestPlanError(f"DNS storm {label} IPv4 is outside allowedCidrs")
        if not policy.allow_arbitrary_unicast_mac:
            prefixes = [prefix.lower() for prefix in policy.allowed_mac_prefixes]
            for label, address in (("client", client.mac), ("server", server.mac)):
                if not any(address.lower().startswith(prefix) for prefix in prefixes):
                    raise TestPlanError(f"DNS storm {label} MAC is outside allowedMacPrefixes")
        try:
            normalized_name = normalize_dns_name(name)
            payload = encode_dns_query(
                normalized_name,
                query_type,
                recursion_desired=recursion_desired,
            )
        except ValueError as error:
            raise TestPlanError(str(error)) from error
        wire_size = dns_query_wire_size(payload)
        estimated_bps_l1 = pps * (wire_size + 20) * 8
        if pps > policy.max_pps:
            raise TestPlanError("DNS storm pps exceeds the SafetyPolicy maximum")
        if estimated_bps_l1 > policy.max_bps_l1:
            raise TestPlanError("DNS storm estimatedBpsL1 exceeds the SafetyPolicy maximum")
        try:
            document = PacketStormDocument.model_validate(
                {
                    "apiVersion": "trex.example.io/v1",
                    "kind": "PacketStorm",
                    "metadata": {"name": "dns-query-storm"},
                    "spec": {
                        "protocol": "dns",
                        "safety": {"isolatedLab": True},
                        "limits": {
                            "portWaitTimeout": path.document.run_defaults.port_wait_timeout,
                            "jobTimeout": path.document.run_defaults.traffic_job_timeout,
                        },
                        "client": {
                            "role": client_role,
                            "port": client.port,
                            "mac": client.mac,
                            "ipv4": client.ipv4,
                            "udpSourcePortStart": source_port_start,
                            "udpSourcePortEnd": source_port_end,
                        },
                        "server": {
                            "role": server_role,
                            "port": server.port,
                            "mac": server.mac,
                            "ipv4": server.ipv4,
                            "udpPort": 53,
                        },
                        "question": {
                            "name": normalized_name,
                            "type": query_type,
                            "class": "IN",
                            "recursionDesired": recursion_desired,
                        },
                        "run": {
                            "pps": pps,
                            "wireSize": wire_size,
                            "estimatedBpsL1": estimated_bps_l1,
                            "duration": duration,
                        },
                        "observation": {
                            "queryDelivery": "flow-stats",
                            "responses": "unavailable",
                        },
                    },
                }
            )
        except ValidationError as error:
            raise TestPlanError(str(error)) from error
        if document.spec.run.duration > policy.max_run_duration:
            raise TestPlanError("DNS storm duration exceeds the SafetyPolicy maximum")
        identity = canonical_document(document)
        plan = DnsStormPlan(
            plan_id="plan_" + sha256_text(identity).removeprefix("sha256:")[:24],
            path_name=path.name,
            path_revision=path.revision,
            path_digest=path.digest,
            document=document,
        )
        self._persist(plan)
        return plan

    def plan_dhcp_storm(
        self,
        *,
        path_name: str,
        client_role: str,
        server_role: str,
        clients: int,
        pps: float,
        duration: str,
    ) -> DhcpStormPlan:
        policy = self._safety_policy
        if policy is None:
            raise TestPlanError("DHCP storm requires a configured SafetyPolicy")
        if not policy.allow_broadcast_storms:
            raise TestPlanError("DHCP storm requires allowBroadcastStorms")
        path = self._load_path(path_name)
        if not path.document.safety.isolated_lab:
            raise TestPlanError("DHCP storm requires an isolated LabPath")
        if not path.document.safety.broadcast_domain:
            raise TestPlanError("DHCP storm requires a Layer-2 broadcast domain LabPath")
        if client_role not in path.document.roles or server_role not in path.document.roles:
            raise TestPlanError("LabPath does not define both DHCP storm roles")
        client = path.document.roles[client_role]
        server = path.document.roles[server_role]
        if client.port == server.port:
            raise TestPlanError("DHCP storm roles must use different ports")
        if client.mac is None:
            raise TestPlanError("DHCP storm client role requires a MAC address")
        if clients > policy.max_address_pool_size:
            raise TestPlanError("DHCP client identity pool exceeds maxAddressPoolSize")
        try:
            mac_end = dhcp_client_mac_end(client.mac, clients)
            payload = encode_dhcp_discover(client.mac)
        except ValueError as error:
            raise TestPlanError(str(error)) from error
        if not policy.allow_arbitrary_unicast_mac:
            prefixes = [prefix.lower() for prefix in policy.allowed_mac_prefixes]
            if not mac_range_allowed(client.mac, mac_end, prefixes):
                raise TestPlanError("DHCP client identity pool is outside allowedMacPrefixes")
        wire_size = dhcp_discover_wire_size(payload)
        estimated_bps_l1 = pps * (wire_size + 20) * 8
        if pps > policy.max_pps:
            raise TestPlanError("DHCP storm pps exceeds the SafetyPolicy maximum")
        if estimated_bps_l1 > policy.max_bps_l1:
            raise TestPlanError("DHCP storm estimatedBpsL1 exceeds the SafetyPolicy maximum")
        try:
            document = PacketStormDocument.model_validate(
                {
                    "apiVersion": "trex.example.io/v1",
                    "kind": "PacketStorm",
                    "metadata": {"name": "dhcp-discover-storm"},
                    "spec": {
                        "protocol": "dhcp",
                        "safety": {"isolatedLab": True},
                        "limits": {
                            "portWaitTimeout": path.document.run_defaults.port_wait_timeout,
                            "jobTimeout": path.document.run_defaults.traffic_job_timeout,
                        },
                        "clients": {
                            "role": client_role,
                            "port": client.port,
                            "macStart": client.mac,
                            "macEnd": mac_end,
                            "count": clients,
                        },
                        "server": {"role": server_role, "port": server.port},
                        "message": {
                            "type": "discover",
                            "clientPort": 68,
                            "serverPort": 67,
                            "broadcastReplyRequested": True,
                        },
                        "network": {
                            "broadcastDomain": True,
                            "ethernetDestination": "ff:ff:ff:ff:ff:ff",
                            "ipv4Source": "0.0.0.0",
                            "ipv4Destination": "255.255.255.255",
                        },
                        "run": {
                            "pps": pps,
                            "wireSize": wire_size,
                            "estimatedBpsL1": estimated_bps_l1,
                            "duration": duration,
                        },
                        "observation": {
                            "discoverDelivery": "flow-stats",
                            "offers": "unavailable",
                        },
                    },
                }
            )
        except ValidationError as error:
            raise TestPlanError(str(error)) from error
        if document.spec.run.duration > policy.max_run_duration:
            raise TestPlanError("DHCP storm duration exceeds the SafetyPolicy maximum")
        identity = canonical_document(document)
        plan = DhcpStormPlan(
            plan_id="plan_" + sha256_text(identity).removeprefix("sha256:")[:24],
            path_name=path.name,
            path_revision=path.revision,
            path_digest=path.digest,
            document=document,
        )
        self._persist(plan)
        return plan

    def plan_arp_storm(
        self,
        *,
        path_name: str,
        sender_role: str,
        target_role: str,
        senders: int,
        pps: float,
        duration: str,
    ) -> ArpStormPlan:
        policy = self._safety_policy
        if policy is None:
            raise TestPlanError("ARP storm requires a configured SafetyPolicy")
        if not policy.allow_broadcast_storms:
            raise TestPlanError("ARP storm requires allowBroadcastStorms")
        path = self._load_path(path_name)
        if not path.document.safety.isolated_lab:
            raise TestPlanError("ARP storm requires an isolated LabPath")
        if not path.document.safety.broadcast_domain:
            raise TestPlanError("ARP storm requires a Layer-2 broadcast domain LabPath")
        if sender_role not in path.document.roles or target_role not in path.document.roles:
            raise TestPlanError("LabPath does not define both ARP storm roles")
        sender = path.document.roles[sender_role]
        target = path.document.roles[target_role]
        if sender.port == target.port:
            raise TestPlanError("ARP storm roles must use different ports")
        if sender.mac is None or sender.ipv4 is None or target.ipv4 is None:
            raise TestPlanError("ARP storm roles require sender MAC/IPv4 and target IPv4")
        if senders > policy.max_address_pool_size:
            raise TestPlanError("ARP sender identity pool exceeds maxAddressPoolSize")
        try:
            mac_end = arp_sender_mac_end(sender.mac, senders)
            ipv4_end = arp_sender_ipv4_end(sender.ipv4, senders)
        except ValueError as error:
            raise TestPlanError(str(error)) from error
        if not policy.allow_arbitrary_unicast_mac:
            prefixes = [prefix.lower() for prefix in policy.allowed_mac_prefixes]
            if not mac_range_allowed(sender.mac, mac_end, prefixes):
                raise TestPlanError("ARP sender identity pool is outside allowedMacPrefixes")
        networks = [ipaddress.ip_network(cidr, strict=False) for cidr in policy.allowed_cidrs]
        sender_range_allowed = any(
            ipaddress.ip_address(sender.ipv4) in network
            and ipaddress.ip_address(ipv4_end) in network
            for network in networks
        )
        if not sender_range_allowed:
            raise TestPlanError("ARP sender identity pool is outside allowedCidrs")
        if not any(ipaddress.ip_address(target.ipv4) in network for network in networks):
            raise TestPlanError("ARP target IPv4 is outside allowedCidrs")
        estimated_bps_l1 = pps * (ARP_REQUEST_WIRE_SIZE + 20) * 8
        if pps > policy.max_pps:
            raise TestPlanError("ARP storm pps exceeds the SafetyPolicy maximum")
        if estimated_bps_l1 > policy.max_bps_l1:
            raise TestPlanError("ARP storm estimatedBpsL1 exceeds the SafetyPolicy maximum")
        try:
            document = PacketStormDocument.model_validate(
                {
                    "apiVersion": "trex.example.io/v1",
                    "kind": "PacketStorm",
                    "metadata": {"name": "arp-request-storm"},
                    "spec": {
                        "protocol": "arp",
                        "safety": {"isolatedLab": True},
                        "limits": {
                            "portWaitTimeout": path.document.run_defaults.port_wait_timeout,
                            "jobTimeout": path.document.run_defaults.traffic_job_timeout,
                        },
                        "senders": {
                            "role": sender_role,
                            "port": sender.port,
                            "macStart": sender.mac,
                            "macEnd": mac_end,
                            "ipv4Start": sender.ipv4,
                            "ipv4End": ipv4_end,
                            "count": senders,
                        },
                        "target": {
                            "role": target_role,
                            "port": target.port,
                            "ipv4": target.ipv4,
                        },
                        "message": {
                            "operation": "request",
                            "hardwareType": "ethernet",
                            "protocolType": "ipv4",
                        },
                        "network": {
                            "broadcastDomain": True,
                            "ethernetDestination": "ff:ff:ff:ff:ff:ff",
                        },
                        "run": {
                            "pps": pps,
                            "wireSize": ARP_REQUEST_WIRE_SIZE,
                            "estimatedBpsL1": estimated_bps_l1,
                            "duration": duration,
                        },
                    },
                }
            )
        except ValidationError as error:
            raise TestPlanError(str(error)) from error
        if document.spec.run.duration > policy.max_run_duration:
            raise TestPlanError("ARP storm duration exceeds the SafetyPolicy maximum")
        identity = canonical_document(document)
        plan = ArpStormPlan(
            plan_id="plan_" + sha256_text(identity).removeprefix("sha256:")[:24],
            path_name=path.name,
            path_revision=path.revision,
            path_digest=path.digest,
            document=document,
        )
        self._persist(plan)
        return plan

    def plan_udp_workload(
        self,
        *,
        capture_name: str,
        path_name: str,
        initiator_role: str,
        responder_role: str,
        fps: float,
        duration: str,
    ) -> UdpWorkloadPlan:
        policy = self._safety_policy
        if policy is None:
            raise TestPlanError("UDP workload requires a configured SafetyPolicy")
        try:
            capture = self._captures.describe(capture_name)
        except ValueError as error:
            raise TestPlanError(str(error)) from error
        datagram = capture.document.analysis.datagram
        if datagram is None or not datagram.workload_templates:
            raise TestPlanError("capture contains no replayable UDP flows")
        if not datagram.workload_complete:
            raise TestPlanError(
                "DATAGRAM_WORKLOAD_TRUNCATED: all-datagram-flows requires complete analysis"
            )
        path = self._load_path(path_name)
        if initiator_role not in path.document.roles or responder_role not in path.document.roles:
            raise TestPlanError("LabPath does not define both UDP workload roles")
        initiator = path.document.roles[initiator_role]
        responder = path.document.roles[responder_role]
        if initiator.port == responder.port:
            raise TestPlanError("UDP workload roles must use different ports")
        if any(
            value is None
            for value in (initiator.mac, responder.mac, initiator.ipv4, responder.ipv4)
        ):
            raise TestPlanError("UDP workload roles require MAC and IPv4 addresses")
        assert initiator.mac is not None
        assert responder.mac is not None
        assert initiator.ipv4 is not None
        assert responder.ipv4 is not None
        allowed_networks = [
            ipaddress.ip_network(cidr, strict=False) for cidr in policy.allowed_cidrs
        ]
        for label, address in (("initiator", initiator.ipv4), ("responder", responder.ipv4)):
            if not any(ipaddress.ip_address(address) in network for network in allowed_networks):
                raise TestPlanError(f"UDP workload {label} IPv4 is outside allowedCidrs")
        if not policy.allow_arbitrary_unicast_mac:
            prefixes = [prefix.lower() for prefix in policy.allowed_mac_prefixes]
            for label, address in (("initiator", initiator.mac), ("responder", responder.mac)):
                if not any(address.lower().startswith(prefix) for prefix in prefixes):
                    raise TestPlanError(f"UDP workload {label} MAC is outside allowedMacPrefixes")
        source_flow_count = sum(
            template.occurrence_count for template in datagram.workload_templates
        )
        flows_by_id = {flow.id: flow for flow in datagram.flows}
        workload_templates = []
        estimated_pps = 0.0
        estimated_bps_l1 = 0.0
        for template in datagram.workload_templates:
            template_fps = fps * template.occurrence_count / source_flow_count
            estimated_pps += template_fps * template.datagram_count
            estimated_bps_l1 += template_fps * template.l1_bytes_per_flow * 8
            flow = flows_by_id.get(template.representative_flow_id)
            if flow is None:
                raise TestPlanError("capture datagram workload analysis is inconsistent")
            workload_templates.append(
                {
                    "id": template.id,
                    "digest": template.digest,
                    "representativeFlow": {
                        "id": template.representative_flow_id,
                        "digest": template.representative_flow_digest,
                        "initiatorPort": flow.initiator.port,
                        "responderPort": flow.responder.port,
                        "datagramCount": template.datagram_count,
                        "initiatorDatagramCount": template.initiator_datagram_count,
                        "responderDatagramCount": template.responder_datagram_count,
                        "initiatorPayloadBytes": template.initiator_payload_bytes,
                        "responderPayloadBytes": template.responder_payload_bytes,
                        "durationMicroseconds": template.duration_microseconds,
                        "l1BytesPerFlow": template.l1_bytes_per_flow,
                    },
                    "occurrenceCount": template.occurrence_count,
                    "weight": template.occurrence_count / source_flow_count,
                    "fps": template_fps,
                }
            )
        if estimated_pps > policy.max_pps:
            raise TestPlanError("UDP workload estimatedPps exceeds the SafetyPolicy maximum")
        if estimated_bps_l1 > policy.max_bps_l1:
            raise TestPlanError("UDP workload estimatedBpsL1 exceeds the SafetyPolicy maximum")
        analysis = capture.document.analysis
        capture_binding = {
            "name": capture.name,
            "revision": capture.revision,
            "digest": capture.digest,
            "size": capture.document.size,
            "packetCount": analysis.packet_count,
            "durationSeconds": analysis.duration_seconds,
            "normalizedDurationSeconds": analysis.normalized_duration_seconds,
            "nonMonotonicTimestampCount": analysis.non_monotonic_timestamp_count,
            "maximumBackwardJumpSeconds": analysis.maximum_backward_jump_seconds,
            "macEndpoints": analysis.mac_endpoints,
            "ipv4Endpoints": analysis.ipv4_endpoints,
            "hasBroadcast": analysis.safety.has_broadcast,
            "hasMulticast": analysis.safety.has_multicast,
        }
        try:
            document = UdpWorkloadDocument.model_validate(
                {
                    "apiVersion": "trex.example.io/v1",
                    "kind": "UdpWorkload",
                    "metadata": {"name": f"{Path(capture.name).name}-udp-workload"},
                    "spec": {
                        "safety": {"isolatedLab": path.document.safety.isolated_lab},
                        "limits": {
                            "portWaitTimeout": path.document.run_defaults.port_wait_timeout,
                            "jobTimeout": path.document.run_defaults.traffic_job_timeout,
                        },
                        "capture": capture_binding,
                        "workload": {
                            "selection": "all-datagram-flows",
                            "sourceFlowCount": source_flow_count,
                            "templateCount": len(workload_templates),
                            "templates": workload_templates,
                        },
                        "initiator": {
                            "role": initiator_role,
                            "port": initiator.port,
                            "mac": initiator.mac,
                            "ipv4": initiator.ipv4,
                        },
                        "responder": {
                            "role": responder_role,
                            "port": responder.port,
                            "mac": responder.mac,
                            "ipv4": responder.ipv4,
                        },
                        "run": {
                            "fps": fps,
                            "estimatedPps": estimated_pps,
                            "estimatedBpsL1": estimated_bps_l1,
                            "duration": duration,
                        },
                        "semanticDifferences": datagram.semantic_differences,
                    },
                }
            )
        except ValidationError as error:
            raise TestPlanError("capture datagram workload analysis is inconsistent") from error
        latest_datagram_offset = max(
            template.representative_flow.duration_microseconds
            for template in document.spec.workload.templates
        )
        if document.spec.run.duration * 1_000 <= latest_datagram_offset:
            raise TestPlanError(
                "UDP workload duration must exceed the latest template datagram offset"
            )
        if document.spec.run.duration > policy.max_run_duration:
            raise TestPlanError("duration exceeds the configured SafetyPolicy maximum")
        identity = canonical_document(document)
        plan = UdpWorkloadPlan(
            plan_id="plan_" + sha256_text(identity).removeprefix("sha256:")[:24],
            capture_name=capture.name,
            capture_revision=capture.revision,
            capture_digest=capture.digest,
            path_name=path.name,
            path_revision=path.revision,
            path_digest=path.digest,
            document=document,
        )
        self._persist(plan)
        return plan

    def plan_stateful_replay(
        self,
        *,
        capture_name: str,
        session_id: str,
        path_name: str,
        client_role: str,
        server_role: str,
        cps: float,
        max_active_connections: int,
        duration: str,
        client_ipv4_start: str | None = None,
        client_ipv4_end: str | None = None,
        server_ipv4_start: str | None = None,
        server_ipv4_end: str | None = None,
        client_port_start: int = 1024,
        client_port_end: int = 65_535,
    ) -> StatefulReplayPlan:
        if self._safety_policy is None:
            raise TestPlanError("stateful replay requires a configured SafetyPolicy")
        try:
            capture = self._captures.describe(capture_name)
        except ValueError as error:
            raise TestPlanError(str(error)) from error
        analysis = capture.document.analysis
        if analysis.stateful is None:
            raise TestPlanError("capture contains no TCP sessions")
        session = next(
            (candidate for candidate in analysis.stateful.sessions if candidate.id == session_id),
            None,
        )
        if session is None:
            raise TestPlanError(f"capture has no reported session {session_id}")
        if not session.reconstructible:
            raise TestPlanError("session is not reconstructible: " + ", ".join(session.issues))
        path = self._load_path(path_name)
        if client_role not in path.document.roles or server_role not in path.document.roles:
            raise TestPlanError("LabPath does not define both stateful replay roles")
        client = path.document.roles[client_role]
        server = path.document.roles[server_role]
        if client.port == server.port:
            raise TestPlanError("client and server roles must use different ports")
        if client.ipv4 is None or server.ipv4 is None:
            raise TestPlanError("stateful replay roles require IPv4 addresses")
        client_start = client_ipv4_start or client.ipv4
        client_end = client_ipv4_end or client_start
        server_start = server_ipv4_start or server.ipv4
        server_end = server_ipv4_end or server_start
        policy = self._safety_policy
        if cps > policy.max_cps:
            raise TestPlanError("cps exceeds the configured SafetyPolicy maximum")
        if max_active_connections > policy.max_active_connections:
            raise TestPlanError("maxActiveConnections exceeds the configured SafetyPolicy maximum")
        for label, start, end in (
            ("client", client_start, client_end),
            ("server", server_start, server_end),
        ):
            first = ipaddress.IPv4Address(start)
            last = ipaddress.IPv4Address(end)
            if last < first:
                raise TestPlanError(f"{label} IPv4 pool end precedes start")
            cardinality = int(last) - int(first) + 1
            if cardinality > policy.max_address_pool_size:
                raise TestPlanError(f"{label} IPv4 pool exceeds maxAddressPoolSize")
            if not ipv4_range_allowed(start, end, policy.allowed_cidrs):
                raise TestPlanError(f"{label} IPv4 pool is outside allowedCidrs")
        if client_port_end < client_port_start:
            raise TestPlanError("client transport port pool end precedes start")
        client_addresses = (
            int(ipaddress.IPv4Address(client_end)) - int(ipaddress.IPv4Address(client_start)) + 1
        )
        port_count = client_port_end - client_port_start + 1
        if max_active_connections > client_addresses * port_count:
            raise TestPlanError(
                "PORT_POOL_EXHAUSTED: maxActiveConnections exceeds client address/port capacity"
            )
        capture_binding = {
            "name": capture.name,
            "revision": capture.revision,
            "digest": capture.digest,
            "size": capture.document.size,
            "packetCount": analysis.packet_count,
            "durationSeconds": analysis.duration_seconds,
            "normalizedDurationSeconds": analysis.normalized_duration_seconds,
            "nonMonotonicTimestampCount": analysis.non_monotonic_timestamp_count,
            "maximumBackwardJumpSeconds": analysis.maximum_backward_jump_seconds,
            "macEndpoints": analysis.mac_endpoints,
            "ipv4Endpoints": analysis.ipv4_endpoints,
            "hasBroadcast": analysis.safety.has_broadcast,
            "hasMulticast": analysis.safety.has_multicast,
        }
        try:
            document = StatefulReplayDocument.model_validate(
                {
                    "apiVersion": "trex.example.io/v1",
                    "kind": "StatefulReplay",
                    "metadata": {"name": f"{Path(capture.name).name}-stateful"},
                    "spec": {
                        "safety": {"isolatedLab": path.document.safety.isolated_lab},
                        "limits": {
                            "portWaitTimeout": path.document.run_defaults.port_wait_timeout,
                            "jobTimeout": path.document.run_defaults.traffic_job_timeout,
                        },
                        "capture": capture_binding,
                        "session": {
                            "id": session.id,
                            "digest": session.digest,
                            "protocol": session.protocol,
                            "serverPort": session.server.port,
                            "clientPayloadBytes": session.client_payload_bytes,
                            "serverPayloadBytes": session.server_payload_bytes,
                            "exchangeCount": session.exchange_count,
                        },
                        "client": {
                            "role": client_role,
                            "port": client.port,
                            "ipv4Pool": {"start": client_start, "end": client_end},
                            "transportPortPool": {
                                "start": client_port_start,
                                "end": client_port_end,
                            },
                        },
                        "server": {
                            "role": server_role,
                            "port": server.port,
                            "ipv4Pool": {"start": server_start, "end": server_end},
                        },
                        "run": {
                            "cps": cps,
                            "maxActiveConnections": max_active_connections,
                            "duration": duration,
                        },
                        "semanticDifferences": analysis.stateful.semantic_differences,
                    },
                }
            )
        except ValidationError as error:
            raise TestPlanError(str(error)) from error
        if document.spec.run.duration > policy.max_run_duration:
            raise TestPlanError("duration exceeds the configured SafetyPolicy maximum")
        identity = canonical_document(document)
        plan = StatefulReplayPlan(
            plan_id="plan_" + sha256_text(identity).removeprefix("sha256:")[:24],
            capture_name=capture.name,
            capture_revision=capture.revision,
            capture_digest=capture.digest,
            path_name=path.name,
            path_revision=path.revision,
            path_digest=path.digest,
            document=document,
        )
        self._persist(plan)
        return plan

    def plan_capture_workload(
        self,
        *,
        capture_name: str,
        path_name: str,
        client_role: str,
        server_role: str,
        cps: float,
        max_active_connections: int,
        duration: str,
        client_ipv4_start: str | None = None,
        client_ipv4_end: str | None = None,
        server_ipv4_start: str | None = None,
        server_ipv4_end: str | None = None,
        client_port_start: int = 1024,
        client_port_end: int = 65_535,
    ) -> StatefulReplayPlan:
        if self._safety_policy is None:
            raise TestPlanError("capture workload requires a configured SafetyPolicy")
        try:
            capture = self._captures.describe(capture_name)
        except ValueError as error:
            raise TestPlanError(str(error)) from error
        analysis = capture.document.analysis
        stateful = analysis.stateful
        if stateful is None or not stateful.workload_templates:
            raise TestPlanError("capture contains no reconstructible TCP sessions")
        if not stateful.workload_complete:
            raise TestPlanError(
                "WORKLOAD_TRUNCATED: all-reconstructible requires complete session analysis"
            )
        if max_active_connections < len(stateful.workload_templates):
            raise TestPlanError(
                "WORKLOAD_CAPACITY_EXHAUSTED: maxActiveConnections is smaller than templateCount"
            )
        path = self._load_path(path_name)
        if client_role not in path.document.roles or server_role not in path.document.roles:
            raise TestPlanError("LabPath does not define both capture workload roles")
        client = path.document.roles[client_role]
        server = path.document.roles[server_role]
        if client.port == server.port:
            raise TestPlanError("client and server roles must use different ports")
        if client.ipv4 is None or server.ipv4 is None:
            raise TestPlanError("capture workload roles require IPv4 addresses")
        client_start = client_ipv4_start or client.ipv4
        client_end = client_ipv4_end or client_start
        server_start = server_ipv4_start or server.ipv4
        server_end = server_ipv4_end or server_start
        policy = self._safety_policy
        if cps > policy.max_cps:
            raise TestPlanError("cps exceeds the configured SafetyPolicy maximum")
        if max_active_connections > policy.max_active_connections:
            raise TestPlanError("maxActiveConnections exceeds the configured SafetyPolicy maximum")
        for label, start, end in (
            ("client", client_start, client_end),
            ("server", server_start, server_end),
        ):
            first = ipaddress.IPv4Address(start)
            last = ipaddress.IPv4Address(end)
            if last < first:
                raise TestPlanError(f"{label} IPv4 pool end precedes start")
            cardinality = int(last) - int(first) + 1
            if cardinality > policy.max_address_pool_size:
                raise TestPlanError(f"{label} IPv4 pool exceeds maxAddressPoolSize")
            if not ipv4_range_allowed(start, end, policy.allowed_cidrs):
                raise TestPlanError(f"{label} IPv4 pool is outside allowedCidrs")
        if client_port_end < client_port_start:
            raise TestPlanError("client transport port pool end precedes start")
        client_addresses = (
            int(ipaddress.IPv4Address(client_end)) - int(ipaddress.IPv4Address(client_start)) + 1
        )
        port_count = client_port_end - client_port_start + 1
        if max_active_connections > client_addresses * port_count:
            raise TestPlanError(
                "PORT_POOL_EXHAUSTED: maxActiveConnections exceeds client address/port capacity"
            )
        occurrence_counts = {
            template.id: template.occurrence_count for template in stateful.workload_templates
        }
        source_session_count = sum(occurrence_counts.values())
        active_allocations = _weighted_integer_allocation(
            max_active_connections,
            occurrence_counts,
        )
        workload_templates = []
        for template in stateful.workload_templates:
            workload_templates.append(
                {
                    "id": template.id,
                    "digest": template.digest,
                    "representativeSession": {
                        "id": template.representative_session_id,
                        "digest": template.representative_session_digest,
                        "protocol": template.protocol,
                        "serverPort": template.server_port,
                        "clientPayloadBytes": template.client_payload_bytes,
                        "serverPayloadBytes": template.server_payload_bytes,
                        "exchangeCount": template.exchange_count,
                    },
                    "occurrenceCount": template.occurrence_count,
                    "weight": template.occurrence_count / source_session_count,
                    "cps": cps * template.occurrence_count / source_session_count,
                    "maxActiveConnections": active_allocations[template.id],
                }
            )
        capture_binding = {
            "name": capture.name,
            "revision": capture.revision,
            "digest": capture.digest,
            "size": capture.document.size,
            "packetCount": analysis.packet_count,
            "durationSeconds": analysis.duration_seconds,
            "normalizedDurationSeconds": analysis.normalized_duration_seconds,
            "nonMonotonicTimestampCount": analysis.non_monotonic_timestamp_count,
            "maximumBackwardJumpSeconds": analysis.maximum_backward_jump_seconds,
            "macEndpoints": analysis.mac_endpoints,
            "ipv4Endpoints": analysis.ipv4_endpoints,
            "hasBroadcast": analysis.safety.has_broadcast,
            "hasMulticast": analysis.safety.has_multicast,
        }
        try:
            document = StatefulReplayDocument.model_validate(
                {
                    "apiVersion": "trex.example.io/v1",
                    "kind": "StatefulReplay",
                    "metadata": {"name": f"{Path(capture.name).name}-workload"},
                    "spec": {
                        "safety": {"isolatedLab": path.document.safety.isolated_lab},
                        "limits": {
                            "portWaitTimeout": path.document.run_defaults.port_wait_timeout,
                            "jobTimeout": path.document.run_defaults.traffic_job_timeout,
                        },
                        "capture": capture_binding,
                        "workload": {
                            "selection": "all-reconstructible",
                            "sourceSessionCount": source_session_count,
                            "templateCount": len(workload_templates),
                            "templates": workload_templates,
                        },
                        "client": {
                            "role": client_role,
                            "port": client.port,
                            "ipv4Pool": {"start": client_start, "end": client_end},
                            "transportPortPool": {
                                "start": client_port_start,
                                "end": client_port_end,
                            },
                        },
                        "server": {
                            "role": server_role,
                            "port": server.port,
                            "ipv4Pool": {"start": server_start, "end": server_end},
                        },
                        "run": {
                            "cps": cps,
                            "maxActiveConnections": max_active_connections,
                            "duration": duration,
                        },
                        "semanticDifferences": stateful.semantic_differences,
                    },
                }
            )
        except ValidationError as error:
            raise TestPlanError(str(error)) from error
        if document.spec.run.duration > policy.max_run_duration:
            raise TestPlanError("duration exceeds the configured SafetyPolicy maximum")
        identity = canonical_document(document)
        plan = StatefulReplayPlan(
            plan_id="plan_" + sha256_text(identity).removeprefix("sha256:")[:24],
            capture_name=capture.name,
            capture_revision=capture.revision,
            capture_digest=capture.digest,
            path_name=path.name,
            path_revision=path.revision,
            path_digest=path.digest,
            document=document,
        )
        self._persist(plan)
        return plan

    def _validate_preserved_capture(self, capture: CaptureResourceDocument) -> None:
        policy = self._safety_policy
        if policy is None:
            raise TestPlanError("preserve requires a configured SafetyPolicy")
        analysis = capture.analysis
        if analysis.protocols.get("unsupported-network", 0):
            raise TestPlanError("replay cannot safely authorize this network protocol")
        if analysis.safety.has_broadcast or analysis.safety.has_multicast:
            raise TestPlanError(
                "preserve rejects captures containing broadcast or multicast packets"
            )
        allowed_networks = [
            ipaddress.ip_network(cidr, strict=False) for cidr in policy.allowed_cidrs
        ]
        outside = [
            value
            for value in analysis.ipv4_endpoints
            if not any(ipaddress.ip_address(value) in network for network in allowed_networks)
        ]
        if outside:
            raise TestPlanError(
                "preserve rejects IPv4 endpoints outside configured allowedCidrs: "
                + ", ".join(outside[:5])
            )
        if not policy.allow_arbitrary_unicast_mac:
            prefixes = [prefix.lower() for prefix in policy.allowed_mac_prefixes]
            outside_macs = [
                value
                for value in analysis.mac_endpoints
                if not any(value.lower().startswith(prefix) for prefix in prefixes)
            ]
            if outside_macs:
                raise TestPlanError(
                    "preserve rejects MAC endpoints outside configured allowedMacPrefixes: "
                    + ", ".join(outside_macs[:5])
                )

    def plan_rfc2544_throughput(
        self,
        *,
        profile_name: str,
        path_name: str,
        parameters: list[str] | tuple[str, ...] = (),
        mode: Literal["strict", "fast"] = "fast",
        flow_name: str | None = None,
        reverse_flow_name: str | None = None,
        direction_mode: Literal[
            "unidirectional", "bidirectional-simultaneous", "unidirectional-each"
        ] = "unidirectional",
        frame_sizes: list[int] | None = None,
        tests: tuple[Literal["throughput", "frame-loss"], ...] = ("throughput",),
    ) -> Rfc2544IntentPlan:
        """Compatibility entry point; new callers should use plan_rfc2544_suite."""
        return self.plan_rfc2544_suite(
            profile_name=profile_name,
            path_name=path_name,
            parameters=parameters,
            mode=mode,
            flow_name=flow_name,
            reverse_flow_name=reverse_flow_name,
            direction_mode=direction_mode,
            frame_sizes=frame_sizes,
            tests=tests,
        )

    def plan_rfc2544_suite(
        self,
        *,
        profile_name: str,
        path_name: str,
        parameters: list[str] | tuple[str, ...] = (),
        mode: Literal["strict", "fast"] = "fast",
        flow_name: str | None = None,
        reverse_flow_name: str | None = None,
        direction_mode: Literal[
            "unidirectional", "bidirectional-simultaneous", "unidirectional-each"
        ] = "unidirectional",
        frame_sizes: list[int] | None = None,
        tests: tuple[Rfc2544TestName, ...] = ("throughput",),
        latency: dict[str, Any] | None = None,
        latency_new_destination_flow_name: str | None = None,
        back_to_back: dict[str, Any] | None = None,
    ) -> Rfc2544IntentPlan:
        profile = self._load_profile(profile_name)
        path = self._load_path(path_name)
        values = _resolve_parameters(profile.document, parameters)
        if flow_name is None:
            if len(profile.document.flows) != 1:
                raise TestPlanError("RFC2544 requires an explicit --forward flow")
            selected_name, flow = next(iter(profile.document.flows.items()))
        else:
            selected_name, flow = _select_flows(profile.document, (flow_name,))[0]
        reverse_name: str | None = None
        reverse_flow: FlowTemplate | None = None
        latency_new_destination_name: str | None = None
        latency_new_destination_flow: FlowTemplate | None = None
        if direction_mode == "unidirectional":
            if reverse_flow_name is not None:
                raise TestPlanError("unidirectional mode does not accept --reverse")
        else:
            if reverse_flow_name is None:
                raise TestPlanError(f"{direction_mode} requires an explicit --reverse flow")
            reverse_name, reverse_flow = _select_flows(profile.document, (reverse_flow_name,))[0]
            if flow.from_role != reverse_flow.to_role or flow.to_role != reverse_flow.from_role:
                raise TestPlanError("forward and reverse flows must use mirrored roles")
        if latency_new_destination_flow_name is not None:
            if latency is None or "new-destination" not in latency.get("scenarios", []):
                raise TestPlanError(
                    "latency new destination flow requires the new-destination scenario"
                )
            latency_new_destination_name, latency_new_destination_flow = _select_flows(
                profile.document, (latency_new_destination_flow_name,)
            )[0]
            if latency_new_destination_flow.from_role != flow.from_role:
                raise TestPlanError("latency new destination flow must use the same source role")
        if flow.from_role not in path.document.roles:
            raise TestPlanError(f"LabPath {path_name} has no role {flow.from_role}")
        if flow.to_role not in path.document.roles:
            raise TestPlanError(f"LabPath {path_name} has no role {flow.to_role}")
        if (
            latency_new_destination_flow is not None
            and latency_new_destination_flow.to_role not in path.document.roles
        ):
            raise TestPlanError(
                f"LabPath {path_name} has no role {latency_new_destination_flow.to_role}"
            )
        source_role = path.document.roles[flow.from_role]
        destination_role = path.document.roles[flow.to_role]
        context = {
            "param": values,
            "role": {
                name: role.model_dump(mode="python", exclude_none=True)
                for name, role in path.document.roles.items()
            },
        }
        packet_raw = _resolve_value(flow.packet, context)
        if not isinstance(packet_raw, dict):
            raise TestPlanError("resolved packet must be an object")
        reverse_packet_raw = (
            _resolve_value(reverse_flow.packet, context) if reverse_flow is not None else None
        )
        if reverse_packet_raw is not None and not isinstance(reverse_packet_raw, dict):
            raise TestPlanError("resolved reverse packet must be an object")
        latency_new_destination_packet_raw = (
            _resolve_value(latency_new_destination_flow.packet, context)
            if latency_new_destination_flow is not None
            else None
        )
        if latency_new_destination_packet_raw is not None and not isinstance(
            latency_new_destination_packet_raw, dict
        ):
            raise TestPlanError("resolved latency new destination packet must be an object")
        try:
            packet = RfcPacket.model_validate(packet_raw)
            reverse_packet = (
                RfcPacket.model_validate(reverse_packet_raw)
                if reverse_packet_raw is not None
                else None
            )
            latency_new_destination_packet = (
                RfcPacket.model_validate(latency_new_destination_packet_raw)
                if latency_new_destination_packet_raw is not None
                else None
            )
            resolved_latency = dict(latency) if latency is not None else None
            if latency_new_destination_packet is not None:
                assert resolved_latency is not None
                if "newDestinationPacket" in resolved_latency:
                    raise TestPlanError(
                        "latency new destination packet and flow cannot both be supplied"
                    )
                resolved_latency["newDestinationPacket"] = (
                    latency_new_destination_packet.model_dump(
                        mode="json", by_alias=True, exclude_none=True
                    )
                )
            document = Rfc2544SuiteDocument.model_validate(
                {
                    "apiVersion": "trex.example.io/v1",
                    "kind": "Rfc2544Suite",
                    "metadata": {
                        "name": f"{profile_name}-{selected_name}-rfc2544",
                        "labels": {
                            "intent": "benchmark-rfc2544",
                            "profile": profile_name,
                            "path": path_name,
                            "flow": selected_name,
                        },
                    },
                    "spec": {
                        "safety": {"isolatedLab": path.document.safety.isolated_lab},
                        "ports": {
                            "tx": source_role.port,
                            "rx": destination_role.port,
                            "direction": (
                                "unidirectional"
                                if direction_mode == "unidirectional"
                                else "bidirectional"
                            ),
                        },
                        "limits": {
                            "portWaitTimeout": path.document.run_defaults.port_wait_timeout,
                            "jobTimeout": path.document.run_defaults.benchmark_job_timeout,
                        },
                        "mode": mode,
                        "tests": list(tests),
                        **(
                            {
                                "reportContext": path.document.report_context.model_dump(
                                    mode="json", by_alias=True, exclude_none=True
                                )
                            }
                            if path.document.report_context is not None
                            else {}
                        ),
                        **({"latency": resolved_latency} if resolved_latency is not None else {}),
                        **({"backToBack": back_to_back} if back_to_back is not None else {}),
                        "directionMode": direction_mode,
                        "packet": packet.model_dump(mode="json", by_alias=True, exclude_none=True),
                        **(
                            {
                                "reversePacket": reverse_packet.model_dump(
                                    mode="json", by_alias=True, exclude_none=True
                                )
                            }
                            if reverse_packet is not None
                            else {}
                        ),
                        **({"frameSizes": frame_sizes} if frame_sizes is not None else {}),
                    },
                }
            )
        except ValidationError as error:
            raise TestPlanError(str(error)) from error
        identity = json.dumps(
            {
                "intent": "benchmark-rfc2544",
                "profile": profile.digest,
                "path": path.digest,
                "flow": selected_name,
                "reverseFlow": reverse_name,
                "latencyNewDestinationFlow": latency_new_destination_name,
                "parameters": values,
                "mode": mode,
                "directionMode": direction_mode,
                "tests": list(tests),
                "document": json.loads(canonical_document(document)),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        plan = Rfc2544IntentPlan(
            plan_id="plan_" + sha256_text(identity).removeprefix("sha256:")[:24],
            profile_name=profile.name,
            profile_revision=profile.revision,
            profile_digest=profile.digest,
            path_name=path.name,
            path_revision=path.revision,
            path_digest=path.digest,
            flow_name=selected_name,
            reverse_flow_name=reverse_name,
            latency_new_destination_flow_name=latency_new_destination_name,
            parameters=values,
            mode=mode,
            direction_mode=direction_mode,
            tests=tests,
            document=document,
        )
        self._persist(plan)
        return plan

    def get(
        self, plan_id: str
    ) -> (
        IntentPlan
        | Rfc2544IntentPlan
        | PcapReplayPlan
        | StatefulReplayPlan
        | UdpWorkloadPlan
        | DnsStormPlan
        | DhcpStormPlan
        | ArpStormPlan
    ):
        if _PLAN_ID_RE.fullmatch(plan_id) is None:
            raise TestPlanError("invalid plan id")
        path = self._plan_root / f"{plan_id}.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as error:
            raise TestPlanError(f"plan not found: {plan_id}") from error
        except json.JSONDecodeError as error:
            raise TestPlanError(f"stored plan is not valid JSON: {plan_id}") from error
        if not isinstance(raw, dict) or raw.get("apiVersion") not in {
            TEST_PLAN_API_VERSION,
            LEGACY_TEST_PLAN_API_VERSION,
        }:
            raise TestPlanError(f"stored plan has an unsupported format: {plan_id}")
        if raw.get("intent") == "benchmark-rfc2544":
            return self._get_rfc2544(plan_id, raw)
        if raw.get("intent") == "pcap-replay":
            return self._get_pcap_replay(plan_id, raw)
        if raw.get("intent") == "pcap-udp-workload":
            return self._get_udp_workload(plan_id, raw)
        if raw.get("intent") == "dns-storm":
            return self._get_dns_storm(plan_id, raw)
        if raw.get("intent") == "dhcp-storm":
            return self._get_dhcp_storm(plan_id, raw)
        if raw.get("intent") == "arp-storm":
            return self._get_arp_storm(plan_id, raw)
        if raw.get("intent") in {"pcap-stateful-replay", "pcap-capture-workload"}:
            return self._get_stateful_replay(plan_id, raw)
        try:
            resources = raw["resources"]
            document = StatelessTrafficDocument.model_validate(raw["document"])
            plan = IntentPlan(
                plan_id=str(raw["planId"]),
                profile_name=str(resources["profile"]["name"]),
                profile_revision=int(resources["profile"].get("revision", 1)),
                profile_digest=str(resources["profile"]["digest"]),
                path_name=str(resources["path"]["name"]),
                path_revision=int(resources["path"].get("revision", 1)),
                path_digest=str(resources["path"]["digest"]),
                flow_names=tuple(str(item) for item in raw["flows"]),
                parameters=dict(raw.get("parameters", {})),
                rate_input=str(raw["load"]["requested"]),
                duration_input=str(raw["duration"]),
                wire_sizes=tuple(
                    int(item["frame"]["wireSizeBytes"]) for item in raw["resolvedStreams"]
                ),
                document=document,
            )
        except (KeyError, IndexError, TypeError, ValidationError, ValueError) as error:
            raise TestPlanError(f"stored plan is malformed: {plan_id}") from error
        if plan.plan_id != plan_id:
            raise TestPlanError(f"stored plan id does not match its filename: {plan_id}")
        return plan

    def _get_pcap_replay(self, plan_id: str, raw: dict[str, Any]) -> PcapReplayPlan:
        try:
            resources = raw["resources"]
            document = PcapReplayDocument.model_validate(raw["document"])
            plan = PcapReplayPlan(
                plan_id=str(raw["planId"]),
                capture_name=str(resources["capture"]["name"]),
                capture_revision=int(resources["capture"]["revision"]),
                capture_digest=str(resources["capture"]["digest"]),
                path_name=str(resources["path"]["name"]),
                path_revision=int(resources["path"]["revision"]),
                path_digest=str(resources["path"]["digest"]),
                document=document,
            )
        except (KeyError, TypeError, ValidationError, ValueError) as error:
            raise TestPlanError(f"stored plan is malformed: {plan_id}") from error
        if plan.plan_id != plan_id:
            raise TestPlanError(f"stored plan id does not match its filename: {plan_id}")
        return plan

    def _get_stateful_replay(self, plan_id: str, raw: dict[str, Any]) -> StatefulReplayPlan:
        try:
            resources = raw["resources"]
            document = StatefulReplayDocument.model_validate(raw["document"])
            plan = StatefulReplayPlan(
                plan_id=str(raw["planId"]),
                capture_name=str(resources["capture"]["name"]),
                capture_revision=int(resources["capture"]["revision"]),
                capture_digest=str(resources["capture"]["digest"]),
                path_name=str(resources["path"]["name"]),
                path_revision=int(resources["path"]["revision"]),
                path_digest=str(resources["path"]["digest"]),
                document=document,
            )
        except (KeyError, TypeError, ValueError, ValidationError) as error:
            raise TestPlanError(f"stored stateful replay plan is invalid: {plan_id}") from error
        if plan.plan_id != plan_id:
            raise TestPlanError(f"stored plan id does not match its filename: {plan_id}")
        return plan

    def _get_udp_workload(self, plan_id: str, raw: dict[str, Any]) -> UdpWorkloadPlan:
        try:
            resources = raw["resources"]
            document = UdpWorkloadDocument.model_validate(raw["document"])
            plan = UdpWorkloadPlan(
                plan_id=str(raw["planId"]),
                capture_name=str(resources["capture"]["name"]),
                capture_revision=int(resources["capture"]["revision"]),
                capture_digest=str(resources["capture"]["digest"]),
                path_name=str(resources["path"]["name"]),
                path_revision=int(resources["path"]["revision"]),
                path_digest=str(resources["path"]["digest"]),
                document=document,
            )
        except (KeyError, TypeError, ValueError, ValidationError) as error:
            raise TestPlanError(f"stored UDP workload plan is invalid: {plan_id}") from error
        if plan.plan_id != plan_id:
            raise TestPlanError(f"stored plan id does not match its filename: {plan_id}")
        return plan

    def _get_dns_storm(self, plan_id: str, raw: dict[str, Any]) -> DnsStormPlan:
        try:
            resources = raw["resources"]
            document = PacketStormDocument.model_validate(raw["document"])
            if document.spec.protocol != "dns":
                raise ValueError("stored PacketStorm is not DNS")
            plan = DnsStormPlan(
                plan_id=str(raw["planId"]),
                path_name=str(resources["path"]["name"]),
                path_revision=int(resources["path"]["revision"]),
                path_digest=str(resources["path"]["digest"]),
                document=document,
            )
        except (KeyError, TypeError, ValueError, ValidationError) as error:
            raise TestPlanError(f"stored DNS storm plan is invalid: {plan_id}") from error
        if plan.plan_id != plan_id:
            raise TestPlanError(f"stored plan id does not match its filename: {plan_id}")
        return plan

    def _get_dhcp_storm(self, plan_id: str, raw: dict[str, Any]) -> DhcpStormPlan:
        try:
            resources = raw["resources"]
            document = PacketStormDocument.model_validate(raw["document"])
            if document.spec.protocol != "dhcp":
                raise ValueError("stored PacketStorm is not DHCP")
            plan = DhcpStormPlan(
                plan_id=str(raw["planId"]),
                path_name=str(resources["path"]["name"]),
                path_revision=int(resources["path"]["revision"]),
                path_digest=str(resources["path"]["digest"]),
                document=document,
            )
        except (KeyError, TypeError, ValueError, ValidationError) as error:
            raise TestPlanError(f"stored DHCP storm plan is invalid: {plan_id}") from error
        if plan.plan_id != plan_id:
            raise TestPlanError(f"stored plan id does not match its filename: {plan_id}")
        return plan

    def _get_arp_storm(self, plan_id: str, raw: dict[str, Any]) -> ArpStormPlan:
        try:
            resources = raw["resources"]
            document = PacketStormDocument.model_validate(raw["document"])
            if not isinstance(document.spec, ArpStormSpec):
                raise ValueError("stored PacketStorm is not ARP")
            plan = ArpStormPlan(
                plan_id=str(raw["planId"]),
                path_name=str(resources["path"]["name"]),
                path_revision=int(resources["path"]["revision"]),
                path_digest=str(resources["path"]["digest"]),
                document=document,
            )
        except (KeyError, TypeError, ValueError, ValidationError) as error:
            raise TestPlanError(f"stored ARP storm plan is invalid: {plan_id}") from error
        if plan.plan_id != plan_id:
            raise TestPlanError(f"stored plan id does not match its filename: {plan_id}")
        return plan

    def _get_rfc2544(self, plan_id: str, raw: dict[str, Any]) -> Rfc2544IntentPlan:
        try:
            resources = raw["resources"]
            method = raw["method"]
            document = Rfc2544SuiteDocument.model_validate(raw["document"])
            plan = Rfc2544IntentPlan(
                plan_id=str(raw["planId"]),
                profile_name=str(resources["profile"]["name"]),
                profile_revision=int(resources["profile"].get("revision", 1)),
                profile_digest=str(resources["profile"]["digest"]),
                path_name=str(resources["path"]["name"]),
                path_revision=int(resources["path"].get("revision", 1)),
                path_digest=str(resources["path"]["digest"]),
                flow_name=str(method["flow"]),
                reverse_flow_name=(str(method["reverseFlow"]) if "reverseFlow" in method else None),
                latency_new_destination_flow_name=(
                    str(method["latencyNewDestinationFlow"])
                    if "latencyNewDestinationFlow" in method
                    else None
                ),
                parameters=dict(raw.get("parameters", {})),
                mode=cast(Literal["strict", "fast"], str(method["mode"])),
                direction_mode=cast(
                    Literal[
                        "unidirectional",
                        "bidirectional-simultaneous",
                        "unidirectional-each",
                    ],
                    str(method["directionMode"]),
                ),
                tests=tuple(cast(Rfc2544TestName, str(item)) for item in method["tests"]),
                document=document,
            )
        except (KeyError, TypeError, ValidationError, ValueError) as error:
            raise TestPlanError(f"stored plan is malformed: {plan_id}") from error
        if plan.plan_id != plan_id:
            raise TestPlanError(f"stored plan id does not match its filename: {plan_id}")
        return plan

    def _load_profile(self, name: str) -> TrafficProfileResource:
        raw, resolved_name, revision = _load_named_yaml(self._profile_root, name, "TrafficProfile")
        try:
            document = TrafficProfileDocument.model_validate(raw)
        except ValidationError as error:
            raise TestPlanError(str(error)) from error
        _validate_resource_identity(document.metadata, resolved_name, revision, "TrafficProfile")
        return TrafficProfileResource(resolved_name, revision, _resource_digest(document), document)

    def _load_path(self, name: str) -> LabPathResource:
        raw, resolved_name, revision = _load_named_yaml(self._path_root, name, "LabPath")
        try:
            document = LabPathDocument.model_validate(raw)
        except ValidationError as error:
            raise TestPlanError(str(error)) from error
        _validate_resource_identity(document.metadata, resolved_name, revision, "LabPath")
        return LabPathResource(resolved_name, revision, _resource_digest(document), document)

    def search_resources(
        self,
        *,
        query: str = "",
        kinds: set[Literal["TrafficProfile", "LabPath", "CaptureResource"]] | None = None,
    ) -> list[CatalogResource]:
        selected = kinds if kinds is not None else {"TrafficProfile", "LabPath", "CaptureResource"}
        resources: list[CatalogResource] = []
        roots: tuple[tuple[Literal["TrafficProfile", "LabPath"], Path], ...] = (
            ("TrafficProfile", self._profile_root),
            ("LabPath", self._path_root),
        )
        for kind, root in roots:
            if kind not in selected:
                continue
            for name in _resource_names(root):
                resource: TrafficProfileResource | LabPathResource
                if kind == "TrafficProfile":
                    resource = self._load_profile(name)
                else:
                    resource = self._load_path(name)
                if query.casefold() not in resource.name.casefold() and (
                    resource.document.metadata.description is None
                    or query.casefold() not in resource.document.metadata.description.casefold()
                ):
                    continue
                resources.append(
                    CatalogResource(
                        kind=kind,
                        name=resource.name,
                        revision=resource.revision,
                        digest=resource.digest,
                        description=resource.document.metadata.description,
                        document=resource.document,
                    )
                )
        if "CaptureResource" in selected:
            for capture in self._captures.search(query):
                resources.append(
                    CatalogResource(
                        kind="CaptureResource",
                        name=capture.name,
                        revision=capture.revision,
                        digest=capture.digest,
                        description=capture.document.metadata.description,
                        document=capture.document,
                    )
                )
        return sorted(resources, key=lambda item: (item.kind, item.name, item.revision))

    def describe_resource(self, kind: str, ref: str) -> CatalogResource:
        if kind == "TrafficProfile":
            profile = self._load_profile(ref)
            return CatalogResource(
                kind="TrafficProfile",
                name=profile.name,
                revision=profile.revision,
                digest=profile.digest,
                description=profile.document.metadata.description,
                document=profile.document,
            )
        elif kind == "LabPath":
            path = self._load_path(ref)
            return CatalogResource(
                kind="LabPath",
                name=path.name,
                revision=path.revision,
                digest=path.digest,
                description=path.document.metadata.description,
                document=path.document,
            )
        elif kind == "CaptureResource":
            try:
                capture = self._captures.describe(ref)
            except ValueError as error:
                raise TestPlanError(str(error)) from error
            return CatalogResource(
                kind="CaptureResource",
                name=capture.name,
                revision=capture.revision,
                digest=capture.digest,
                description=capture.document.metadata.description,
                document=capture.document,
            )
        else:
            raise TestPlanError(f"unsupported resource kind: {kind}")

    def publish_capture(
        self,
        *,
        name: str,
        source: BinaryIO,
        description: str | None = None,
    ) -> CatalogResource:
        try:
            capture = self._captures.publish(
                name=name,
                source=source,
                description=description,
            )
        except ValueError as error:
            raise TestPlanError(str(error)) from error
        return CatalogResource(
            kind="CaptureResource",
            name=capture.name,
            revision=capture.revision,
            digest=capture.digest,
            description=capture.document.metadata.description,
            document=capture.document,
        )

    def _persist(
        self,
        plan: (
            IntentPlan
            | Rfc2544IntentPlan
            | PcapReplayPlan
            | StatefulReplayPlan
            | UdpWorkloadPlan
            | DnsStormPlan
            | DhcpStormPlan
            | ArpStormPlan
        ),
    ) -> None:
        self._plan_root.mkdir(parents=True, exist_ok=True)
        path = self._plan_root / f"{plan.plan_id}.json"
        payload = json.dumps(
            plan.payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        if path.exists():
            existing = path.read_text(encoding="utf-8")
            if existing == payload:
                return
            try:
                existing_document = json.loads(existing)
                expected_document = json.loads(payload)
            except json.JSONDecodeError as error:
                raise TestPlanError(f"stored plan is not valid JSON: {plan.plan_id}") from error
            if (
                isinstance(existing_document, dict)
                and existing_document.get("apiVersion") == LEGACY_TEST_PLAN_API_VERSION
            ):
                existing_document["apiVersion"] = TEST_PLAN_API_VERSION
            if existing_document != expected_document:
                raise TestPlanError(f"plan id collision: {plan.plan_id}")
            return
        path.write_text(payload, encoding="utf-8")


def _load_named_yaml(root: Path, ref: str, kind: str) -> tuple[Any, str, int]:
    name, requested_revision = _split_resource_ref(ref, kind)
    if _RESOURCE_NAME_RE.fullmatch(name) is None:
        raise TestPlanError(f"invalid {kind} name: {name}")
    candidates = _resource_files(root, name)
    if requested_revision is not None:
        candidates = [item for item in candidates if item[0] == requested_revision]
    if not candidates:
        raise TestPlanError(f"{kind} not found: {ref}")
    revision, path = max(candidates, key=lambda item: item[0])
    try:
        return load_yaml(path.read_text(encoding="utf-8")), name, revision
    except FileNotFoundError as error:
        raise TestPlanError(f"{kind} not found: {ref}") from error


def _split_resource_ref(ref: str, kind: str) -> tuple[str, int | None]:
    if "@" not in ref:
        return ref, None
    name, revision_text = ref.rsplit("@", 1)
    if not revision_text.isdigit() or int(revision_text) < 1:
        raise TestPlanError(f"invalid {kind} revision: {ref}")
    return name, int(revision_text)


def _resource_files(root: Path, name: str) -> list[tuple[int, Path]]:
    paths: list[tuple[int, Path]] = []
    legacy = root / f"{name}.yaml"
    if legacy.is_file():
        paths.append((1, legacy))
    parent = (root / name).parent
    stem = Path(name).name
    if parent.is_dir():
        for path in parent.glob(f"{stem}@*.yaml"):
            revision_text = path.stem.rsplit("@", 1)[-1]
            if revision_text.isdigit() and int(revision_text) >= 1:
                paths.append((int(revision_text), path))
    return paths


def _resource_names(root: Path) -> list[str]:
    names: set[str] = set()
    if not root.is_dir():
        return []
    for path in root.rglob("*.yaml"):
        relative = path.relative_to(root).with_suffix("").as_posix()
        name = relative.rsplit("@", 1)[0] if "@" in relative else relative
        if _RESOURCE_NAME_RE.fullmatch(name) is not None:
            names.add(name)
    return sorted(names)


def _validate_resource_identity(
    metadata: ResourceMetadata, name: str, revision: int, kind: str
) -> None:
    if metadata.name != name:
        raise TestPlanError(
            f"{kind} metadata.name {metadata.name!r} does not match resource name {name!r}"
        )
    if metadata.revision != revision:
        raise TestPlanError(
            f"{kind} metadata.revision {metadata.revision} does not match @{revision}"
        )


def _resource_digest(document: StrictModel) -> str:
    canonical = json.dumps(
        document.model_dump(mode="json", by_alias=True, exclude_none=True),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256_text(canonical)


def _resolve_parameters(
    profile: TrafficProfileDocument, assignments: list[str] | tuple[str, ...]
) -> dict[str, Any]:
    supplied: dict[str, Any] = {}
    for assignment in assignments:
        if "=" not in assignment:
            raise TestPlanError("parameter must use name=value")
        name, raw_value = assignment.split("=", 1)
        if name in supplied:
            raise TestPlanError(f"parameter supplied more than once: {name}")
        if name not in profile.parameters:
            raise TestPlanError(f"unknown profile parameter: {name}")
        supplied[name] = load_yaml(raw_value)

    resolved: dict[str, Any] = {}
    for name, definition in profile.parameters.items():
        if name in supplied:
            value = supplied[name]
        elif definition.default is not None:
            value = definition.default
        elif definition.required:
            raise TestPlanError(f"required profile parameter is missing: {name}")
        else:
            value = None
        _validate_parameter(name, definition, value)
        resolved[name] = value
    return resolved


def _validate_parameter(name: str, definition: ParameterDefinition, value: Any) -> None:
    valid = {
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, int | float) and not isinstance(value, bool),
        "string": isinstance(value, str),
        "boolean": isinstance(value, bool),
    }[definition.type]
    if not valid:
        raise TestPlanError(f"profile parameter {name} must be {definition.type}")
    if isinstance(value, int | float) and not isinstance(value, bool):
        if definition.minimum is not None and value < definition.minimum:
            raise TestPlanError(f"profile parameter {name} is below its minimum")
        if definition.maximum is not None and value > definition.maximum:
            raise TestPlanError(f"profile parameter {name} exceeds its maximum")


def _select_flows(
    profile: TrafficProfileDocument, requested: tuple[str, ...]
) -> list[tuple[str, FlowTemplate]]:
    if not requested:
        return list(profile.flows.items())
    if len(set(requested)) != len(requested):
        raise TestPlanError("a flow may be selected only once")
    selected: list[tuple[str, FlowTemplate]] = []
    for name in requested:
        try:
            selected.append((name, profile.flows[name]))
        except KeyError as error:
            raise TestPlanError(f"TrafficProfile has no flow {name}") from error
    return selected


def _resolve_value(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {key: _resolve_value(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_value(item, context) for item in value]
    if not isinstance(value, str):
        return value
    match = _REFERENCE_RE.fullmatch(value)
    if match is None:
        if "${" in value:
            raise TestPlanError("references must occupy the complete YAML scalar")
        return value
    namespace, name, field = match.groups()
    if namespace == "param":
        if field is not None or name not in context["param"]:
            raise TestPlanError(f"unknown parameter reference: {value}")
        return context["param"][name]
    if field is None:
        raise TestPlanError(f"role reference must select a field: {value}")
    try:
        return context["role"][name][field]
    except KeyError as error:
        raise TestPlanError(f"unresolved role reference: {value}") from error


def _parse_rate(value: str) -> Rate:
    match = _RATE_RE.fullmatch(value)
    if match is None:
        raise TestPlanError("rate must use %, pps, bps, kbps, mbps, or gbps")
    number = float(match.group(1))
    suffix = match.group(2).lower()
    if suffix == "%":
        unit, multiplier = "percent_l1", 1.0
    elif suffix == "pps":
        unit, multiplier = "pps", 1.0
    else:
        unit = "bps_l1"
        multiplier = {"bps": 1.0, "kbps": 1_000.0, "mbps": 1_000_000.0, "gbps": 1_000_000_000.0}[
            suffix
        ]
    try:
        return Rate.model_validate({"unit": unit, "value": number * multiplier})
    except ValidationError as error:
        raise TestPlanError(str(error)) from error


def _scaled_rate(rate: Rate, share: float) -> Rate:
    return Rate.model_validate({"unit": rate.unit, "value": rate.value * share})
