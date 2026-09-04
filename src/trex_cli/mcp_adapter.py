from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field, TypeAdapter

from trex_cli.test_control import (
    ArpStormIntent,
    CancelTest,
    CaptureWorkloadIntent,
    DhcpStormIntent,
    DnsStormIntent,
    PcapReplayIntent,
    ResourceKind,
    Rfc2544TestIntent,
    StatefulReplayIntent,
    TestControl,
    TrafficTestIntent,
    UdpWorkloadIntent,
)

_INTENT_ADAPTER: TypeAdapter[
    TrafficTestIntent
    | Rfc2544TestIntent
    | PcapReplayIntent
    | StatefulReplayIntent
    | CaptureWorkloadIntent
    | UdpWorkloadIntent
    | DnsStormIntent
    | DhcpStormIntent
    | ArpStormIntent
] = TypeAdapter(
    Annotated[
        TrafficTestIntent
        | Rfc2544TestIntent
        | PcapReplayIntent
        | StatefulReplayIntent
        | CaptureWorkloadIntent
        | UdpWorkloadIntent
        | DnsStormIntent
        | DhcpStormIntent
        | ArpStormIntent,
        Field(discriminator="kind"),
    ]
)
_KINDS_ADAPTER: TypeAdapter[list[ResourceKind]] = TypeAdapter(list[ResourceKind])


class McpTestControlAdapter:
    """Framework-neutral MCP tool implementation with closed, JSON-safe inputs."""

    def __init__(self, control: TestControl) -> None:
        self._control = control

    async def search_catalog(
        self, *, query: str = "", kinds: list[str] | None = None
    ) -> dict[str, Any]:
        selected = set(_KINDS_ADAPTER.validate_python(kinds)) if kinds is not None else None
        result = await self._control.search_catalog(query=query, kinds=selected)
        return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    async def describe_resource(self, *, ref: str) -> dict[str, Any]:
        result = await self._control.describe_resource(ref)
        return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    async def plan_test(self, *, intent: dict[str, Any]) -> dict[str, Any]:
        parsed = _INTENT_ADAPTER.validate_python(intent)
        result = await self._control.plan_test(parsed)
        return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    async def start_test(self, *, plan_id: str) -> dict[str, Any]:
        result = await self._control.start_test(plan_id)
        return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    async def get_test(
        self,
        *,
        job_id: str,
        after_revision: int | None = None,
        wait_seconds: float = 0,
    ) -> dict[str, Any]:
        result = await self._control.get_test(
            job_id,
            after_revision=after_revision,
            wait_seconds=wait_seconds,
        )
        return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    async def control_test(
        self,
        *,
        job_id: str,
        action: str,
        request_id: str,
        reason: str,
    ) -> dict[str, Any]:
        command = CancelTest.model_validate(
            {"action": action, "requestId": request_id, "reason": reason}
        )
        result = await self._control.control_test(job_id, command)
        return result.model_dump(mode="json", by_alias=True, exclude_none=True)
