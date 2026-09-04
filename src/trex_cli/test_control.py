from __future__ import annotations

import asyncio
import json
from typing import Any, BinaryIO, Literal

from pydantic import Field

from trex_cli.async_compat import to_thread
from trex_cli.jobs import TestJobs
from trex_cli.models import (
    JobSnapshot,
    Principal,
    Rfc2544LatencySettings,
    Rfc2544TestName,
    Rfc9004BackToBackSettings,
    Role,
    StrictModel,
    SubmitBody,
)
from trex_cli.test_plan import (
    ArpStormPlan,
    DhcpStormPlan,
    DnsStormPlan,
    IntentPlan,
    PcapReplayPlan,
    Rfc2544IntentPlan,
    StatefulReplayPlan,
    TestPlanError,
    TestPlanModule,
    UdpWorkloadPlan,
)

type ResourceKind = Literal["TrafficProfile", "LabPath", "CaptureResource"]


class CatalogItem(StrictModel):
    kind: ResourceKind
    name: str
    revision: int = Field(ge=1)
    ref: str
    digest: str
    description: str | None = None


class CatalogSearchResult(StrictModel):
    items: list[CatalogItem]


class ResourceDescription(CatalogItem):
    document: dict[str, Any]


class ResourceIdentity(StrictModel):
    kind: ResourceKind
    name: str
    revision: int = Field(ge=1)
    ref: str
    digest: str


class TrafficTestIntent(StrictModel):
    kind: Literal["traffic"] = "traffic"
    profile: str
    path: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    rate: str
    duration: str
    flows: list[str] = Field(default_factory=list)


class Rfc2544TestIntent(StrictModel):
    kind: Literal["benchmark-rfc2544"] = "benchmark-rfc2544"
    profile: str
    path: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    mode: Literal["strict", "fast"] = "fast"
    flow: str | None = None
    reverse_flow: str | None = Field(default=None, alias="reverseFlow")
    direction_mode: Literal[
        "unidirectional", "bidirectional-simultaneous", "unidirectional-each"
    ] = Field(default="unidirectional", alias="directionMode")
    frame_sizes: list[int] | None = Field(default=None, alias="frameSizes")
    tests: tuple[Rfc2544TestName, ...] = ("throughput",)
    latency: Rfc2544LatencySettings | None = None
    latency_new_destination_flow: str | None = Field(
        default=None, alias="latencyNewDestinationFlow"
    )
    back_to_back: Rfc9004BackToBackSettings | None = Field(default=None, alias="backToBack")


class PcapReplayIntent(StrictModel):
    kind: Literal["pcap-replay"] = "pcap-replay"
    capture: str
    path: str
    source_role: str = Field(alias="sourceRole")
    destination_role: str = Field(alias="destinationRole")
    address_mode: Literal["rewrite", "preserve"] = Field(default="rewrite", alias="addressMode")
    timing_mode: Literal["capture", "fixed-rate", "top-speed"] = Field(
        default="capture", alias="timingMode"
    )
    multiplier: float = Field(default=1, gt=0, le=1_000)
    timestamp_policy: Literal["reject", "normalize"] = Field(
        default="reject", alias="timestampPolicy"
    )
    rate: str | None = None


class StatefulReplayIntent(StrictModel):
    kind: Literal["pcap-stateful-replay"] = "pcap-stateful-replay"
    capture: str
    session_id: str = Field(alias="sessionId")
    path: str
    client_role: str = Field(alias="clientRole")
    server_role: str = Field(alias="serverRole")
    cps: float = Field(gt=0)
    max_active_connections: int = Field(alias="maxActiveConnections", ge=1)
    duration: str
    client_ipv4_start: str | None = Field(default=None, alias="clientIpv4Start")
    client_ipv4_end: str | None = Field(default=None, alias="clientIpv4End")
    server_ipv4_start: str | None = Field(default=None, alias="serverIpv4Start")
    server_ipv4_end: str | None = Field(default=None, alias="serverIpv4End")
    client_port_start: int = Field(default=1024, alias="clientPortStart", ge=1024, le=65_535)
    client_port_end: int = Field(default=65_535, alias="clientPortEnd", ge=1024, le=65_535)


class CaptureWorkloadIntent(StrictModel):
    kind: Literal["pcap-capture-workload"] = "pcap-capture-workload"
    capture: str
    path: str
    client_role: str = Field(alias="clientRole")
    server_role: str = Field(alias="serverRole")
    cps: float = Field(gt=0)
    max_active_connections: int = Field(alias="maxActiveConnections", ge=1)
    duration: str
    client_ipv4_start: str | None = Field(default=None, alias="clientIpv4Start")
    client_ipv4_end: str | None = Field(default=None, alias="clientIpv4End")
    server_ipv4_start: str | None = Field(default=None, alias="serverIpv4Start")
    server_ipv4_end: str | None = Field(default=None, alias="serverIpv4End")
    client_port_start: int = Field(default=1024, alias="clientPortStart", ge=1024, le=65_535)
    client_port_end: int = Field(default=65_535, alias="clientPortEnd", ge=1024, le=65_535)


class UdpWorkloadIntent(StrictModel):
    kind: Literal["pcap-udp-workload"] = "pcap-udp-workload"
    capture: str
    path: str
    initiator_role: str = Field(alias="initiatorRole")
    responder_role: str = Field(alias="responderRole")
    fps: float = Field(gt=0)
    duration: str


class DnsStormIntent(StrictModel):
    kind: Literal["dns-storm"] = "dns-storm"
    path: str
    client_role: str = Field(alias="clientRole")
    server_role: str = Field(alias="serverRole")
    name: str
    query_type: Literal["A", "AAAA"] = Field(alias="queryType")
    recursion_desired: bool = Field(default=True, alias="recursionDesired")
    source_port_start: int = Field(default=1024, alias="sourcePortStart", ge=1024, le=65_535)
    source_port_end: int = Field(default=65_535, alias="sourcePortEnd", ge=1024, le=65_535)
    pps: float = Field(gt=0)
    duration: str


class DhcpStormIntent(StrictModel):
    kind: Literal["dhcp-storm"] = "dhcp-storm"
    path: str
    client_role: str = Field(alias="clientRole")
    server_role: str = Field(alias="serverRole")
    clients: int = Field(default=1, ge=1)
    pps: float = Field(gt=0)
    duration: str


class ArpStormIntent(StrictModel):
    kind: Literal["arp-storm"] = "arp-storm"
    path: str
    sender_role: str = Field(alias="senderRole")
    target_role: str = Field(alias="targetRole")
    senders: int = Field(default=1, ge=1)
    pps: float = Field(gt=0)
    duration: str


type TestIntent = (
    TrafficTestIntent
    | Rfc2544TestIntent
    | PcapReplayIntent
    | StatefulReplayIntent
    | CaptureWorkloadIntent
    | UdpWorkloadIntent
    | DnsStormIntent
    | DhcpStormIntent
    | ArpStormIntent
)


class PlannedTest(StrictModel):
    plan_id: str = Field(alias="planId")
    intent: Literal[
        "traffic",
        "benchmark-rfc2544",
        "pcap-replay",
        "pcap-stateful-replay",
        "pcap-capture-workload",
        "pcap-udp-workload",
        "dns-storm",
        "dhcp-storm",
        "arp-storm",
    ]
    resources: dict[str, ResourceIdentity]
    safety: dict[str, Any]
    plan: dict[str, Any]


class CancelTest(StrictModel):
    action: Literal["cancel"] = "cancel"
    request_id: str = Field(alias="requestId", min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=512)


class TestControl:
    """Task-level Interface shared by in-process, CLI, and future MCP adapters."""

    def __init__(self, *, plans: TestPlanModule, jobs: TestJobs, principal: Principal) -> None:
        self._plans = plans
        self._jobs = jobs
        self._principal = principal

    async def search_catalog(
        self,
        query: str = "",
        kinds: set[ResourceKind] | None = None,
    ) -> CatalogSearchResult:
        resources = self._plans.search_resources(query=query, kinds=kinds)
        return CatalogSearchResult(
            items=[
                CatalogItem(
                    kind=item.kind,
                    name=item.name,
                    revision=item.revision,
                    ref=item.ref,
                    digest=item.digest,
                    description=item.description,
                )
                for item in resources
            ]
        )

    async def describe_resource(self, resource_ref: str) -> ResourceDescription:
        try:
            kind, ref = resource_ref.split("/", 1)
        except ValueError as error:
            raise TestPlanError("resource ref must use Kind/name@revision") from error
        resource = self._plans.describe_resource(kind, ref)
        return ResourceDescription(
            kind=resource.kind,
            name=resource.name,
            revision=resource.revision,
            ref=resource.ref,
            digest=resource.digest,
            description=resource.description,
            document=resource.document.model_dump(mode="json", by_alias=True, exclude_none=True),
        )

    async def publish_capture(
        self,
        *,
        name: str,
        source: BinaryIO,
        description: str | None = None,
    ) -> ResourceDescription:
        if self._principal.role != Role.OPERATOR:
            raise TestPlanError("operator role is required to publish a Capture Resource")
        resource = await to_thread(
            self._plans.publish_capture,
            name=name,
            source=source,
            description=description,
        )
        return ResourceDescription(
            kind=resource.kind,
            name=resource.name,
            revision=resource.revision,
            ref=resource.ref,
            digest=resource.digest,
            description=resource.description,
            document=resource.document.model_dump(mode="json", by_alias=True, exclude_none=True),
        )

    async def plan_test(self, intent: TestIntent) -> PlannedTest:
        plan: (
            IntentPlan
            | Rfc2544IntentPlan
            | PcapReplayPlan
            | StatefulReplayPlan
            | UdpWorkloadPlan
            | DnsStormPlan
            | DhcpStormPlan
            | ArpStormPlan
        )
        if isinstance(intent, TrafficTestIntent):
            assignments = _parameter_assignments(intent.parameters)
            plan = self._plans.plan_traffic(
                profile_name=intent.profile,
                path_name=intent.path,
                parameters=assignments,
                rate=intent.rate,
                duration=intent.duration,
                flow_names=intent.flows,
            )
        elif isinstance(intent, Rfc2544TestIntent):
            assignments = _parameter_assignments(intent.parameters)
            plan = self._plans.plan_rfc2544_suite(
                profile_name=intent.profile,
                path_name=intent.path,
                parameters=assignments,
                mode=intent.mode,
                flow_name=intent.flow,
                reverse_flow_name=intent.reverse_flow,
                direction_mode=intent.direction_mode,
                frame_sizes=intent.frame_sizes,
                tests=intent.tests,
                latency=(
                    intent.latency.model_dump(mode="json", by_alias=True, exclude_none=True)
                    if intent.latency is not None
                    else None
                ),
                latency_new_destination_flow_name=(intent.latency_new_destination_flow),
                back_to_back=(
                    intent.back_to_back.model_dump(mode="json", by_alias=True, exclude_none=True)
                    if intent.back_to_back is not None
                    else None
                ),
            )
        elif isinstance(intent, PcapReplayIntent):
            plan = self._plans.plan_pcap_replay(
                capture_name=intent.capture,
                path_name=intent.path,
                source_role=intent.source_role,
                destination_role=intent.destination_role,
                address_mode=intent.address_mode,
                timing_mode=intent.timing_mode,
                multiplier=intent.multiplier,
                timestamp_policy=intent.timestamp_policy,
                rate=intent.rate,
            )
        elif isinstance(intent, StatefulReplayIntent):
            plan = self._plans.plan_stateful_replay(
                capture_name=intent.capture,
                session_id=intent.session_id,
                path_name=intent.path,
                client_role=intent.client_role,
                server_role=intent.server_role,
                cps=intent.cps,
                max_active_connections=intent.max_active_connections,
                duration=intent.duration,
                client_ipv4_start=intent.client_ipv4_start,
                client_ipv4_end=intent.client_ipv4_end,
                server_ipv4_start=intent.server_ipv4_start,
                server_ipv4_end=intent.server_ipv4_end,
                client_port_start=intent.client_port_start,
                client_port_end=intent.client_port_end,
            )
        elif isinstance(intent, CaptureWorkloadIntent):
            plan = self._plans.plan_capture_workload(
                capture_name=intent.capture,
                path_name=intent.path,
                client_role=intent.client_role,
                server_role=intent.server_role,
                cps=intent.cps,
                max_active_connections=intent.max_active_connections,
                duration=intent.duration,
                client_ipv4_start=intent.client_ipv4_start,
                client_ipv4_end=intent.client_ipv4_end,
                server_ipv4_start=intent.server_ipv4_start,
                server_ipv4_end=intent.server_ipv4_end,
                client_port_start=intent.client_port_start,
                client_port_end=intent.client_port_end,
            )
        elif isinstance(intent, UdpWorkloadIntent):
            plan = self._plans.plan_udp_workload(
                capture_name=intent.capture,
                path_name=intent.path,
                initiator_role=intent.initiator_role,
                responder_role=intent.responder_role,
                fps=intent.fps,
                duration=intent.duration,
            )
        elif isinstance(intent, DnsStormIntent):
            plan = self._plans.plan_dns_storm(
                path_name=intent.path,
                client_role=intent.client_role,
                server_role=intent.server_role,
                name=intent.name,
                query_type=intent.query_type,
                recursion_desired=intent.recursion_desired,
                source_port_start=intent.source_port_start,
                source_port_end=intent.source_port_end,
                pps=intent.pps,
                duration=intent.duration,
            )
        elif isinstance(intent, DhcpStormIntent):
            plan = self._plans.plan_dhcp_storm(
                path_name=intent.path,
                client_role=intent.client_role,
                server_role=intent.server_role,
                clients=intent.clients,
                pps=intent.pps,
                duration=intent.duration,
            )
        else:
            plan = self._plans.plan_arp_storm(
                path_name=intent.path,
                sender_role=intent.sender_role,
                target_role=intent.target_role,
                senders=intent.senders,
                pps=intent.pps,
                duration=intent.duration,
            )
        return _planned_test(plan)

    async def start_test(self, plan_id: str) -> JobSnapshot:
        if self._principal.role != Role.OPERATOR:
            raise TestPlanError("operator role is required to start a test")
        plan = self._plans.get(plan_id)
        return await self._jobs.submit(
            SubmitBody(document=plan.document),
            principal=self._principal,
            idempotency_key=plan_id,
        )

    async def get_test(
        self,
        job_id: str,
        *,
        after_revision: int | None = None,
        wait_seconds: float = 0,
    ) -> JobSnapshot:
        current = await self._jobs.get(job_id)
        if (
            after_revision is None
            or current.revision > after_revision
            or current.state.terminal
            or wait_seconds <= 0
        ):
            return current
        try:
            async with asyncio.timeout(wait_seconds):
                async for snapshot in self._jobs.observe(job_id, after_revision):
                    return snapshot
        except TimeoutError:
            pass
        return await self._jobs.get(job_id)

    async def control_test(self, job_id: str, command: CancelTest) -> JobSnapshot:
        if self._principal.role != Role.OPERATOR:
            raise TestPlanError("operator role is required to control a test")
        return await self._jobs.cancel(
            job_id,
            command.request_id,
            command.reason,
            principal=self._principal,
        )


def _parameter_assignments(parameters: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        f"{name}={json.dumps(value, separators=(',', ':'), ensure_ascii=False)}"
        for name, value in parameters.items()
    )


def _planned_test(
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
) -> PlannedTest:
    payload = plan.payload()
    resources = {
        name: ResourceIdentity(
            kind=(
                "CaptureResource"
                if name == "capture"
                else "TrafficProfile"
                if name == "profile"
                else "LabPath"
            ),
            **identity,
        )
        for name, identity in payload["resources"].items()
    }
    return PlannedTest(
        planId=plan.plan_id,
        intent=payload["intent"],
        resources=resources,
        safety={
            "isolatedLab": plan.document.spec.safety.isolated_lab,
            "logicalPorts": sorted(plan.document.spec.logical_ports())
            if isinstance(
                plan,
                (
                    IntentPlan,
                    StatefulReplayPlan,
                    UdpWorkloadPlan,
                    DnsStormPlan,
                    DhcpStormPlan,
                    ArpStormPlan,
                ),
            )
            else sorted((plan.document.spec.ports.tx, plan.document.spec.ports.rx)),
            "jobTimeoutMs": plan.document.spec.limits.job_timeout,
        },
        plan=payload,
    )
