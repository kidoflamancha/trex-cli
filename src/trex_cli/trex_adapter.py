from __future__ import annotations

import asyncio
import importlib
import ipaddress
import os
import sys
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trex_cli.async_compat import to_thread
from trex_cli.config import RemoteTrexEngineConfig, SafetyPolicy
from trex_cli.datagram_analysis import DatagramTemplate, extract_datagram_template
from trex_cli.dhcp_storm import encode_dhcp_discover
from trex_cli.dns_storm import encode_dns_query
from trex_cli.engine import (
    EngineMeasurement,
    EngineStatus,
    ExecutionMarker,
    ReconcileResult,
    RunHandle,
)
from trex_cli.errors import TrexCliError
from trex_cli.models import (
    ArpStormSpec,
    DatagramWorkloadTemplateBinding,
    DhcpStormSpec,
    DnsStormSpec,
    IntegerVariation,
    JobDocument,
    MacVariation,
    Packet,
    PacketStormDocument,
    PcapReplayDocument,
    Rate,
    ReplayFixedRateTiming,
    Rfc2544SuiteDocument,
    Rfc2544ThroughputDocument,
    StatefulReplayDocument,
    StatelessTrafficDocument,
    StringVariation,
    UdpWorkloadDocument,
    Verdict,
    utc_now,
)
from trex_cli.pcap_catalog import CaptureCatalog
from trex_cli.pcap_replay import ReplayCompilation, compile_replay
from trex_cli.publication import assess_rfc2544_publication
from trex_cli.rfc2544 import (
    BackToBackObservation,
    BackToBackSettings,
    LatencyObservation,
    LatencySettings,
    LatencyTrialFunction,
    TrialObservation,
    frame_loss_settings_for,
    measure_back_to_back,
    measure_frame_loss,
    measure_latency,
    search_frame,
    settings_for,
)


@dataclass(frozen=True, slots=True)
class _Direction:
    name: str
    tx_port: int
    rx_port: int
    pg_id: int
    packet: Packet
    rate: Rate
    reverse: bool = False


@dataclass(frozen=True, slots=True)
class _UdpStream:
    template_id: str
    template_digest: str
    occurrence_count: int
    weight: float
    fps: float
    direction: str
    tx_port: int
    rx_port: int
    pg_id: int
    payload_bytes: int


@dataclass(slots=True)
class _Session:
    client: Any
    document: JobDocument
    ports: list[int]
    traffic_ports: list[int]
    pg_ids: list[int]
    line_rates_bps: dict[int, float]
    ieee1588_supported: dict[int, bool]
    port_environment: dict[str, dict[str, Any]]
    owner: str
    version: str
    uses_flow_stats: bool
    directions: list[_Direction]
    udp_streams: list[_UdpStream] | None = None
    replay: ReplayCompilation | None = None
    replay_remote_path: str | None = None
    measurement: EngineMeasurement | None = None
    baseline_clean: bool = True


class RemoteTrexStlEngine:
    """Owns the official TRex client lifecycle without exposing its types to TestJobs."""

    mode = "remote-trex"
    simulated = False

    def __init__(
        self,
        config: RemoteTrexEngineConfig,
        *,
        policy: SafetyPolicy | None = None,
        capture_root: Path | None = None,
        client_factory: Callable[..., Any] | None = None,
        client_api: Any | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._config = config
        self._policy = policy
        self._capture_root = capture_root
        self._sessions: dict[str, _Session] = {}
        self._client_factory = client_factory
        self._api: Any | None = client_api
        self._sleep = sleep

    async def probe(self) -> EngineStatus:
        try:
            return await to_thread(self._probe_sync)
        except Exception as error:
            return EngineStatus(
                available=False,
                details={"mode": self.mode, "error": str(error)},
            )

    async def validate(self, document: JobDocument) -> None:
        if isinstance(document, StatefulReplayDocument):
            raise TrexCliError(
                code="CAPABILITY_MISMATCH",
                category="ENGINE",
                message="stateful replay requires a remote-astf engine",
            )
        if isinstance(document, PcapReplayDocument):
            if self._capture_root is None:
                raise TrexCliError(
                    code="CAPABILITY_MISMATCH",
                    category="ENGINE",
                    message="PCAP replay requires an Agent captureRoot",
                )
            source = CaptureCatalog(self._capture_root).object_path(document.spec.capture.digest)
            if not source.is_file() or source.stat().st_size != document.spec.capture.size:
                raise TrexCliError(
                    code="CAPABILITY_MISMATCH",
                    category="RESOURCE",
                    message="the frozen Capture Resource object is unavailable or changed",
                )
            if (
                isinstance(document.spec.timing, ReplayFixedRateTiming)
                and document.spec.timing.rate.unit == "percent_l1"
            ):
                raise TrexCliError(
                    code="CAPABILITY_MISMATCH",
                    category="ENGINE",
                    message="fixed-rate PCAP replay does not support percent_l1",
                )
            return
        if isinstance(document, UdpWorkloadDocument):
            if self._capture_root is None:
                raise TrexCliError(
                    code="CAPABILITY_MISMATCH",
                    category="ENGINE",
                    message="UDP workload requires an Agent captureRoot",
                )
            source = CaptureCatalog(self._capture_root).object_path(document.spec.capture.digest)
            if not source.is_file() or source.stat().st_size != document.spec.capture.size:
                raise TrexCliError(
                    code="CAPABILITY_MISMATCH",
                    category="RESOURCE",
                    message="the frozen Capture Resource object is unavailable or changed",
                )
            return
        if isinstance(document, PacketStormDocument):
            return
        packets = (
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
        if (
            isinstance(document, StatelessTrafficDocument)
            and len(document.spec.streams) > 1
            and any(packet.ipv4 is None and packet.ipv6 is None for packet in packets)
        ):
            raise TrexCliError(
                code="CAPABILITY_MISMATCH",
                category="ENGINE",
                message="multi-stream bare Ethernet requires per-stream counters not available",
            )
        for packet in packets:
            if packet.ipv6 and packet.icmp:
                raise TrexCliError(
                    code="CAPABILITY_MISMATCH",
                    category="ENGINE",
                    message="IPv6 with the v1 ICMP header is not supported by the remote adapter",
                )
            if packet.ipv6:
                for value in (packet.ipv6.src, packet.ipv6.dst):
                    if isinstance(value, StringVariation):
                        start = int(ipaddress.IPv6Address(value.start))
                        end = int(ipaddress.IPv6Address(value.end))
                        if start >> 64 != end >> 64:
                            raise TrexCliError(
                                code="CAPABILITY_MISMATCH",
                                category="ENGINE",
                                message="IPv6 variations must stay within one 64-bit prefix",
                            )
        if isinstance(document, StatelessTrafficDocument):
            estimated_seconds = self._estimated_run_seconds(document)
            if estimated_seconds > document.spec.limits.job_timeout / 1_000:
                raise TrexCliError(
                    code="UNSAFE_REQUEST",
                    category="POLICY",
                    message="the estimated burst duration exceeds jobTimeout",
                    details={"estimatedDurationSeconds": estimated_seconds},
                )

    async def prepare(self, marker: ExecutionMarker, document: JobDocument) -> RunHandle:
        await self.validate(document)
        handle = RunHandle(f"{marker.job_id}:{uuid.uuid4().hex}")
        try:
            session = await to_thread(self._prepare_sync, marker, document)
        except TrexCliError:
            raise
        except Exception as error:
            raise self._client_error("could not prepare the TRex ports", error) from error
        self._sessions[handle.id] = session
        return handle

    async def reconcile(self, marker: ExecutionMarker, document: JobDocument) -> ReconcileResult:
        remaining = (marker.hard_deadline - utc_now()).total_seconds()
        if remaining > 0:
            await asyncio.sleep(remaining)
        try:
            return await to_thread(self._reconcile_sync, marker, document)
        except Exception as error:
            return ReconcileResult(
                confirmed_idle=False,
                details={"reason": "reconcile-error", "cause": str(error)},
            )

    async def warmup(self, handle: RunHandle) -> None:
        self._session(handle)

    async def run(
        self,
        handle: RunHandle,
        *,
        report_progress: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> EngineMeasurement:
        session = self._session(handle)
        loop = asyncio.get_running_loop()

        async def report_async(update: dict[str, Any]) -> None:
            if report_progress is not None:
                await report_progress(update)

        def report_sync(update: dict[str, Any]) -> None:
            if report_progress is None:
                return
            asyncio.run_coroutine_threadsafe(report_async(update), loop).result()

        try:
            measurement = await to_thread(self._run_sync, session, report_sync)
        except Exception as error:
            raise self._client_error("TRex traffic execution failed", error) from error
        session.measurement = measurement
        return measurement

    async def stop(self, handle: RunHandle, *, force: bool = False) -> None:
        session = self._sessions.get(handle.id)
        if session is None:
            return
        try:
            await to_thread(self._stop_sync, session, force)
        except Exception as error:
            raise self._client_error("could not stop TRex traffic", error) from error

    async def cleanup(self, handle: RunHandle) -> None:
        session = self._sessions.get(handle.id)
        if session is None:
            return
        try:
            await to_thread(self._cleanup_sync, session)
        except Exception as error:
            raise self._client_error("could not release the TRex ports", error) from error
        self._sessions.pop(handle.id, None)

    def _prepare_sync(self, marker: ExecutionMarker, document: JobDocument) -> _Session:
        if isinstance(document, StatefulReplayDocument):
            raise TrexCliError(
                code="CAPABILITY_MISMATCH",
                category="ENGINE",
                message="stateful replay requires a remote-astf engine",
            )
        api = self._load_api()
        client = self._new_client(api, username=self._owner(marker))
        logical_ports = (
            sorted(document.spec.logical_ports())
            if (
                (isinstance(document, StatelessTrafficDocument) and document.spec.streams)
                or isinstance(document, UdpWorkloadDocument)
                or isinstance(document, PacketStormDocument)
            )
            else [document.spec.ports.tx, document.spec.ports.rx]
        )
        ports = [self._config.port_mapping[name] for name in logical_ports]
        acquired = False
        try:
            client.connect()
            if max(ports) >= client.get_port_count():
                raise TrexCliError(
                    code="CAPABILITY_MISMATCH",
                    category="RESOURCE",
                    message="engine.portMapping references a TRex port that does not exist",
                )
            down = [port for port in ports if not client.get_port(port).is_up()]
            if down:
                raise TrexCliError(
                    code="LINK_DOWN",
                    category="ENGINE",
                    retryable=True,
                    message="one or more selected TRex links are down",
                    details={"ports": down},
                )
            client.acquire(ports=ports, force=False)
            acquired = True
            client.reset(ports=ports)
            udp_templates = (
                self._udp_templates(document) if isinstance(document, UdpWorkloadDocument) else []
            )
            direction_count = (
                len(document.spec.streams)
                if isinstance(document, StatelessTrafficDocument) and document.spec.streams
                else sum(len(template.datagrams) for _, template in udp_templates)
                if isinstance(document, UdpWorkloadDocument)
                else 1
                if isinstance(document, PacketStormDocument)
                else (2 if document.spec.ports.direction == "bidirectional" else 1)
            )
            pg_ids = self._pg_ids(ports, count=direction_count)
            storm_traffic = (
                self._packet_storm_traffic_document(document)
                if isinstance(document, PacketStormDocument)
                else None
            )
            directions = (
                self._directions(document, pg_ids)
                if isinstance(document, StatelessTrafficDocument)
                else self._directions(storm_traffic, pg_ids)
                if storm_traffic is not None
                else []
            )
            uses_flow_stats = (
                False
                if isinstance(document, PcapReplayDocument)
                else (
                    not directions
                    or all(
                        direction.packet.ipv4 is not None or direction.packet.ipv6 is not None
                        for direction in directions
                    )
                )
            )
            replay: ReplayCompilation | None = None
            replay_remote_path: str | None = None
            udp_streams: list[_UdpStream] = []
            if isinstance(document, StatelessTrafficDocument):
                self._install_streams(api, client, document, directions, uses_flow_stats)
            elif isinstance(document, PcapReplayDocument):
                assert self._capture_root is not None
                source = CaptureCatalog(self._capture_root).object_path(
                    document.spec.capture.digest
                )
                replay = compile_replay(
                    source,
                    self._capture_root / "compiled",
                    document,
                )
                if self._config.pcap_remote_root is not None:
                    replay_remote_path = str(self._config.pcap_remote_root / replay.path.name)
                else:
                    profile = api.STLProfile.load_pcap(
                        str(replay.path),
                        loop_count=1,
                        src_mac_pcap=True,
                        dst_mac_pcap=True,
                    )
                    client.add_streams(profile.get_streams(), ports=[ports[0]])
            elif isinstance(document, UdpWorkloadDocument):
                udp_streams = self._install_udp_streams(
                    api,
                    client,
                    document,
                    udp_templates,
                    pg_ids,
                )
            elif isinstance(document, PacketStormDocument):
                assert storm_traffic is not None
                if isinstance(document.spec, DnsStormSpec):
                    self._install_dns_stream(api, client, document, storm_traffic, directions[0])
                elif isinstance(document.spec, DhcpStormSpec):
                    self._install_dhcp_stream(api, client, document, directions[0])
                else:
                    self._install_arp_stream(api, client, document, directions[0])
            version_data = client.get_server_version()
            version = str(version_data.get("Version", version_data.get("version", "unknown")))
            traffic_ports = (
                sorted({direction.tx_port for direction in directions})
                if directions
                else ports
                if isinstance(document, (UdpWorkloadDocument, PacketStormDocument))
                else (ports if document.spec.ports.direction == "bidirectional" else [ports[0]])
            )
            port_info = client.get_port_info(ports=ports)
            line_rates = {
                port: float(info.get("speed", 10)) * 1_000_000_000
                for port, info in zip(ports, port_info, strict=True)
            }
            ieee1588_supported = {
                port: info.get("is_ieee1588_supported") in {True, "yes"}
                for port, info in zip(ports, port_info, strict=True)
            }
            port_environment = {
                str(port): {
                    "lineRateBps": line_rates[port],
                    "driver": info.get("driver"),
                    "description": info.get("description"),
                    "ieee1588": ieee1588_supported[port],
                }
                for port, info in zip(ports, port_info, strict=True)
            }
            return _Session(
                client,
                document,
                ports,
                traffic_ports,
                pg_ids,
                line_rates,
                ieee1588_supported,
                port_environment,
                self._owner(marker),
                version,
                uses_flow_stats,
                directions,
                udp_streams,
                replay,
                replay_remote_path,
            )
        except Exception:
            if acquired:
                try:
                    client.release(ports=ports)
                except Exception:
                    pass
            try:
                client.disconnect()
            except Exception:
                pass
            raise

    def _udp_templates(
        self, document: UdpWorkloadDocument
    ) -> list[tuple[DatagramWorkloadTemplateBinding, DatagramTemplate]]:
        assert self._capture_root is not None
        capture_path = CaptureCatalog(self._capture_root).object_path(document.spec.capture.digest)
        extracted = []
        for binding in document.spec.workload.templates:
            template = extract_datagram_template(
                capture_path,
                binding.representative_flow.id,
            )
            if template.digest != binding.representative_flow.digest:
                raise TrexCliError(
                    code="RESOURCE_CHANGED",
                    category="RESOURCE",
                    message="a representative Datagram Flow digest does not match the Plan",
                    details={"templateId": binding.id},
                )
            if template.template_digest != binding.digest:
                raise TrexCliError(
                    code="RESOURCE_CHANGED",
                    category="RESOURCE",
                    message="an extracted Datagram Template digest does not match the Plan",
                    details={"templateId": binding.id},
                )
            extracted.append((binding, template))
        return extracted

    def _install_udp_streams(
        self,
        api: Any,
        client: Any,
        document: UdpWorkloadDocument,
        templates: list[tuple[DatagramWorkloadTemplateBinding, DatagramTemplate]],
        pg_ids: list[int],
    ) -> list[_UdpStream]:
        initiator_port = self._config.port_mapping[document.spec.initiator.port]
        responder_port = self._config.port_mapping[document.spec.responder.port]
        compiled: list[_UdpStream] = []
        pg_index = 0
        for binding, template in templates:
            for datagram in template.datagrams:
                initiator_direction = datagram.direction == "initiator"
                source = document.spec.initiator if initiator_direction else document.spec.responder
                destination = (
                    document.spec.responder if initiator_direction else document.spec.initiator
                )
                tx_port = initiator_port if initiator_direction else responder_port
                rx_port = responder_port if initiator_direction else initiator_port
                source_udp_port = (
                    template.initiator_port if initiator_direction else template.responder_port
                )
                destination_udp_port = (
                    template.responder_port if initiator_direction else template.initiator_port
                )
                packet = (
                    api.Ether(src=source.mac, dst=destination.mac)
                    / api.IP(src=source.ipv4, dst=destination.ipv4)
                    / api.UDP(sport=source_udp_port, dport=destination_udp_port)
                    / api.Raw(load=datagram.payload)
                )
                pg_id = pg_ids[pg_index]
                pg_index += 1
                stream = api.STLStream(
                    packet=api.STLPktBuilder(pkt=packet, vm=[]),
                    mode=api.STLTXCont(pps=binding.fps),
                    flow_stats=api.STLFlowStats(pg_id=pg_id),
                    isg=float(datagram.offset_microseconds),
                )
                client.add_streams(stream, ports=[tx_port])
                compiled.append(
                    _UdpStream(
                        template_id=binding.id,
                        template_digest=binding.digest,
                        occurrence_count=binding.occurrence_count,
                        weight=binding.weight,
                        fps=binding.fps,
                        direction=(
                            "initiator-to-responder"
                            if initiator_direction
                            else "responder-to-initiator"
                        ),
                        tx_port=tx_port,
                        rx_port=rx_port,
                        pg_id=pg_id,
                        payload_bytes=len(datagram.payload),
                    )
                )
        return compiled

    @staticmethod
    def _dns_traffic_document(document: PacketStormDocument) -> StatelessTrafficDocument:
        spec = document.spec
        assert isinstance(spec, DnsStormSpec)
        payload = encode_dns_query(
            spec.question.name,
            spec.question.type,
            recursion_desired=spec.question.recursion_desired,
        )
        return StatelessTrafficDocument.model_validate(
            {
                "apiVersion": "trex.example.io/v1",
                "kind": "StatelessTraffic",
                "metadata": {"name": "dns-query-storm-compiled"},
                "spec": {
                    "safety": spec.safety.model_dump(mode="json", by_alias=True),
                    "ports": {"tx": spec.client.port, "rx": spec.server.port},
                    "limits": spec.limits.model_dump(mode="json", by_alias=True),
                    "packet": {
                        "frameSize": spec.run.wire_size,
                        "ethernet": {"src": spec.client.mac, "dst": spec.server.mac},
                        "ipv4": {"src": spec.client.ipv4, "dst": spec.server.ipv4},
                        "udp": {
                            "srcPort": spec.client.udp_source_port_start,
                            "dstPort": spec.server.udp_port,
                        },
                        "payloadHex": payload.hex(),
                    },
                    "rate": {"unit": "pps", "value": spec.run.pps},
                    "duration": spec.run.duration,
                },
            }
        )

    @classmethod
    def _packet_storm_traffic_document(
        cls, document: PacketStormDocument
    ) -> StatelessTrafficDocument:
        if isinstance(document.spec, DnsStormSpec):
            return cls._dns_traffic_document(document)
        spec = document.spec
        if isinstance(spec, ArpStormSpec):
            tx_port, rx_port = spec.senders.port, spec.target.port
            name = "arp-request-storm-port-mapping"
        else:
            tx_port, rx_port = spec.clients.port, spec.server.port
            name = "dhcp-discover-storm-observation"
        return StatelessTrafficDocument.model_validate(
            {
                "apiVersion": "trex.example.io/v1",
                "kind": "StatelessTraffic",
                "metadata": {"name": name},
                "spec": {
                    "safety": spec.safety.model_dump(mode="json", by_alias=True),
                    "ports": {"tx": tx_port, "rx": rx_port},
                    "limits": spec.limits.model_dump(mode="json", by_alias=True),
                    "packet": {
                        "frameSize": spec.run.wire_size,
                        "ethernet": {
                            "src": "00:00:00:00:00:01",
                            "dst": "00:00:00:00:00:02",
                        },
                        "ipv4": {"src": "198.18.0.1", "dst": "198.18.0.2"},
                        "udp": {"srcPort": 68, "dstPort": 67},
                    },
                    "rate": {"unit": "pps", "value": spec.run.pps},
                    "duration": spec.run.duration,
                },
            }
        )

    def _install_dns_stream(
        self,
        api: Any,
        client: Any,
        document: PacketStormDocument,
        traffic: StatelessTrafficDocument,
        direction: _Direction,
    ) -> None:
        assert isinstance(document.spec, DnsStormSpec)
        packet, vm = self._packet_plan_for(
            api,
            traffic.spec.packet,
            reverse=False,
            variable_prefix="dns",
        )
        if document.spec.client.udp_source_port_start != document.spec.client.udp_source_port_end:
            vm.extend(
                self._flow_variable(
                    api,
                    name="dns_udp_source_port",
                    start=document.spec.client.udp_source_port_start,
                    end=document.spec.client.udp_source_port_end,
                    size=2,
                    mode="increment",
                    offset=14 + 20,
                    split_to_cores=False,
                )
            )
        vm.extend(
            self._flow_variable(
                api,
                name="dns_transaction_id",
                start=0,
                end=65_535,
                size=2,
                mode="increment",
                offset=14 + 20 + 8,
                split_to_cores=False,
            )
        )
        vm.append(
            api.STLVmFixChecksumHw(
                l3_offset=14,
                l4_offset=14 + 20,
                l4_type=api.CTRexVmInsFixHwCs.L4_TYPE_UDP,
            )
        )
        stream = api.STLStream(
            packet=api.STLPktBuilder(pkt=packet, vm=vm),
            mode=api.STLTXCont(pps=document.spec.run.pps),
            flow_stats=api.STLFlowStats(pg_id=direction.pg_id),
        )
        client.add_streams(stream, ports=[direction.tx_port])

    def _install_dhcp_stream(
        self,
        api: Any,
        client: Any,
        document: PacketStormDocument,
        direction: _Direction,
    ) -> None:
        spec = document.spec
        assert isinstance(spec, DhcpStormSpec)
        packet = (
            api.Ether(src=spec.clients.mac_start, dst=spec.network.ethernet_destination)
            / api.IP(
                src=spec.network.ipv4_source,
                dst=spec.network.ipv4_destination,
                ttl=64,
            )
            / api.UDP(sport=spec.message.client_port, dport=spec.message.server_port)
            / api.Raw(load=encode_dhcp_discover(spec.clients.mac_start))
        )
        vm: list[Any] = []
        if spec.clients.count > 1:
            name = "dhcp_client_identity"
            vm.append(
                api.STLVmFlowVar(
                    name=name,
                    min_value=int(spec.clients.mac_start.replace(":", ""), 16) & 0xFFFF_FFFF,
                    max_value=int(spec.clients.mac_end.replace(":", ""), 16) & 0xFFFF_FFFF,
                    size=4,
                    op="inc",
                    split_to_cores=False,
                )
            )
            for offset in (8, 72):
                vm.append(
                    api.STLVmWrFlowVar(
                        fv_name=name,
                        pkt_offset=offset,
                        offset_fixup=0,
                        is_big=True,
                    )
                )
        vm.extend(
            self._flow_variable(
                api,
                name="dhcp_transaction_id",
                start=0,
                end=0xFFFF_FFFF,
                size=4,
                mode="increment",
                offset=46,
                split_to_cores=False,
            )
        )
        vm.append(
            api.STLVmFixChecksumHw(
                l3_offset=14,
                l4_offset=34,
                l4_type=api.CTRexVmInsFixHwCs.L4_TYPE_UDP,
            )
        )
        stream = api.STLStream(
            packet=api.STLPktBuilder(pkt=packet, vm=vm),
            mode=api.STLTXCont(pps=spec.run.pps),
            flow_stats=api.STLFlowStats(pg_id=direction.pg_id),
        )
        client.add_streams(stream, ports=[direction.tx_port])

    def _install_arp_stream(
        self,
        api: Any,
        client: Any,
        document: PacketStormDocument,
        direction: _Direction,
    ) -> None:
        spec = document.spec
        assert isinstance(spec, ArpStormSpec)
        packet = (
            api.Ether(src=spec.senders.mac_start, dst=spec.network.ethernet_destination)
            / api.ARP(
                hwtype=1,
                ptype=0x0800,
                hwlen=6,
                plen=4,
                op=1,
                hwsrc=spec.senders.mac_start,
                psrc=spec.senders.ipv4_start,
                hwdst="00:00:00:00:00:00",
                pdst=spec.target.ipv4,
            )
            / api.Raw(load=b"\x00" * 18)
        )
        vm: list[Any] = []
        if spec.senders.count > 1:
            mac_name = "arp_sender_mac"
            vm.append(
                api.STLVmFlowVar(
                    name=mac_name,
                    min_value=int(spec.senders.mac_start.replace(":", ""), 16) & 0xFFFF_FFFF,
                    max_value=int(spec.senders.mac_end.replace(":", ""), 16) & 0xFFFF_FFFF,
                    size=4,
                    op="inc",
                    split_to_cores=False,
                )
            )
            for offset in (8, 24):
                vm.append(
                    api.STLVmWrFlowVar(
                        fv_name=mac_name,
                        pkt_offset=offset,
                        offset_fixup=0,
                        is_big=True,
                    )
                )
            vm.extend(
                self._flow_variable(
                    api,
                    name="arp_sender_ipv4",
                    start=int(ipaddress.IPv4Address(spec.senders.ipv4_start)),
                    end=int(ipaddress.IPv4Address(spec.senders.ipv4_end)),
                    size=4,
                    mode="increment",
                    offset=28,
                    split_to_cores=False,
                )
            )
        stream = api.STLStream(
            packet=api.STLPktBuilder(pkt=packet, vm=vm),
            mode=api.STLTXCont(pps=spec.run.pps),
        )
        client.add_streams(stream, ports=[direction.tx_port])

    def _new_client(self, api: Any, *, username: str | None = None) -> Any:
        factory = self._client_factory or api.STLClient
        return factory(
            server=self._config.server,
            sync_port=self._config.sync_port,
            async_port=self._config.async_port,
            username=username or f"{self._config.username[:24]}-probe",
            verbose_level="error",
            sync_timeout=self._config.timeout_seconds,
        )

    def _reconcile_sync(self, marker: ExecutionMarker, document: JobDocument) -> ReconcileResult:
        api = self._load_api()
        expected_owner = self._owner(marker)
        client = self._new_client(api, username=expected_owner)
        ports = [self._config.port_mapping[name] for name in marker.logical_ports]
        acquired = False
        connected = False
        try:
            client.connect()
            connected = True
            if any(port >= client.get_port_count() for port in ports):
                return ReconcileResult(
                    confirmed_idle=False,
                    details={"reason": "port-mapping-invalid", "ports": ports},
                )
            owners = {str(port): str(client.get_port(port).get_owner() or "") for port in ports}
            foreign = {
                port: owner for port, owner in owners.items() if owner not in {"", expected_owner}
            }
            if foreign:
                return ReconcileResult(
                    confirmed_idle=False,
                    details={"reason": "owner-mismatch", "owners": owners},
                )
            force = any(owner == expected_owner for owner in owners.values())
            client.acquire(ports=ports, force=force)
            acquired = True
            active = [port for port in ports if client.get_port(port).is_active()]
            if active:
                client.stop(ports=active)
            client.reset(ports=ports)
            still_active = [port for port in ports if client.get_port(port).is_active()]
            if still_active:
                return ReconcileResult(
                    confirmed_idle=False,
                    details={"reason": "traffic-still-active", "ports": still_active},
                )
            client.release(ports=ports)
            acquired = False
            return ReconcileResult(
                confirmed_idle=True,
                details={
                    "reason": "stopped-and-reset",
                    "owners": owners,
                    "ports": ports,
                    "kind": document.kind,
                },
            )
        finally:
            if acquired:
                try:
                    client.release(ports=ports)
                except Exception:
                    pass
            if connected:
                try:
                    client.disconnect()
                except Exception:
                    pass

    def _owner(self, marker: ExecutionMarker) -> str:
        return f"{self._config.username[:24]}-{marker.session_id.replace('-', '')[:32]}"

    def _probe_sync(self) -> EngineStatus:
        api = self._load_api()
        client = self._new_client(api)
        connected = False
        try:
            client.connect()
            connected = True
            version_data = client.get_server_version()
            version = str(version_data.get("Version", version_data.get("version", "unknown")))
            port_count = int(client.get_port_count())
            mapped = sorted(set(self._config.port_mapping.values()))
            invalid = [port for port in mapped if port >= port_count]
            links = {
                str(port): "up" if port < port_count and client.get_port(port).is_up() else "down"
                for port in mapped
                if port not in invalid
            }
            port_info = client.get_port_info(ports=[port for port in mapped if port not in invalid])
            port_speeds = {
                str(port): float(info["speed"])
                for port, info in zip(
                    [port for port in mapped if port not in invalid], port_info, strict=True
                )
            }
            port_capabilities = {
                str(port): {
                    "ieee1588": (
                        True
                        if info.get("is_ieee1588_supported") in {True, "yes"}
                        else False
                        if info.get("is_ieee1588_supported") in {False, "no"}
                        else None
                    ),
                    "driver": info.get("driver"),
                    "description": info.get("description"),
                }
                for port, info in zip(
                    [port for port in mapped if port not in invalid],
                    port_info,
                    strict=True,
                )
            }
            return EngineStatus(
                available=not invalid and all(value == "up" for value in links.values()),
                details={
                    "mode": self.mode,
                    "trexVersion": version,
                    "portCount": port_count,
                    "links": links,
                    "portSpeedsGbps": port_speeds,
                    "portCapabilities": port_capabilities,
                    "invalidPorts": invalid,
                },
            )
        finally:
            if connected:
                try:
                    client.disconnect()
                except Exception:
                    pass

    def _run_sync(
        self, session: _Session, report_progress: Callable[[dict[str, Any]], None] | None = None
    ) -> EngineMeasurement:
        if isinstance(session.document, Rfc2544SuiteDocument):
            return self._run_rfc2544_suite_sync(session, report_progress)
        if isinstance(session.document, Rfc2544ThroughputDocument):
            return self._run_rfc2544_sync(session, report_progress)
        if isinstance(session.document, PcapReplayDocument):
            return self._run_pcap_replay_sync(session, report_progress)
        if isinstance(session.document, UdpWorkloadDocument):
            return self._run_udp_workload_sync(session, report_progress)
        if isinstance(session.document, PacketStormDocument):
            if isinstance(session.document.spec, DnsStormSpec):
                return self._run_dns_storm_sync(session)
            if isinstance(session.document.spec, DhcpStormSpec):
                return self._run_dhcp_storm_sync(session)
            return self._run_arp_storm_sync(session)
        return self._run_stateless_sync(session)

    def _run_pcap_replay_sync(
        self,
        session: _Session,
        report_progress: Callable[[dict[str, Any]], None] | None = None,
    ) -> EngineMeasurement:
        document = session.document
        replay = session.replay
        assert isinstance(document, PcapReplayDocument)
        assert replay is not None
        client = session.client
        tx_port = self._config.port_mapping[document.spec.ports.tx]
        rx_port = self._config.port_mapping[document.spec.ports.rx]
        client.clear_stats(ports=session.ports)
        session.baseline_clean = self._baseline_clean(client, session.ports)
        if session.replay_remote_path is not None:
            client.push_remote(
                session.replay_remote_path,
                ports=[tx_port],
                count=1,
                force=False,
                src_mac_pcap=True,
                dst_mac_pcap=True,
            )
        else:
            client.start(ports=[tx_port], mult="1")
        client.wait_on_traffic(
            ports=[tx_port],
            timeout=max(30, replay.effective_duration_seconds + 30),
            rx_delay_ms=2_000,
        )
        stats = client.get_stats(ports=session.ports)
        tx_frames = int(stats[tx_port].get("opackets", 0))
        rx_frames = int(stats[rx_port].get("ipackets", 0))
        surplus_rx_frames = max(0, rx_frames - tx_frames)
        observation_valid = session.baseline_clean and surplus_rx_frames == 0
        loss_frames = max(0, tx_frames - rx_frames) if observation_valid else None
        if report_progress is not None:
            report_progress(
                {
                    "completedFrames": tx_frames,
                    "totalFrames": replay.packet_count,
                }
            )
        warnings = [str(item) for item in client.get_warnings()]
        return EngineMeasurement(
            verdict=Verdict.NO_ASSERTION,
            methodology="trex-stl-pcap-replay/v1",
            summary={
                "simulated": False,
                "capture": {
                    "name": document.spec.capture.name,
                    "revision": document.spec.capture.revision,
                    "digest": document.spec.capture.digest,
                    "compiledDigest": replay.digest,
                },
                "address": document.spec.address.model_dump(
                    mode="json", by_alias=True, exclude_none=True
                ),
                "timing": document.spec.timing.model_dump(
                    mode="json", by_alias=True, exclude_none=True
                ),
                "effectiveDurationSeconds": replay.effective_duration_seconds,
                "normalizedTimestampCount": replay.normalized_timestamp_count,
                "txFrames": tx_frames,
                "rxFrames": rx_frames,
                "lossFrames": loss_frames,
                "lossPercent": (
                    loss_frames / tx_frames * 100 if loss_frames is not None and tx_frames else None
                ),
                "surplusRxFrames": surplus_rx_frames,
                "observationValid": observation_valid,
                "counterSource": "exclusive-port",
                "baselineClean": session.baseline_clean,
                "warnings": warnings,
                "portEnvironment": session.port_environment,
            },
            provenance={"engine": self.mode, "trexVersion": session.version},
        )

    def _run_dns_storm_sync(self, session: _Session) -> EngineMeasurement:
        document = session.document
        assert isinstance(document, PacketStormDocument)
        assert isinstance(document.spec, DnsStormSpec)
        traffic = self._dns_traffic_document(document)
        client = session.client
        api = self._load_api()
        client.remove_all_streams(ports=session.ports)
        self._learn_switch_paths(api, client, session.directions)
        self._install_dns_stream(api, client, document, traffic, session.directions[0])
        client.clear_stats(ports=session.ports)
        session.baseline_clean = self._baseline_clean(client, session.ports)
        duration = document.spec.run.duration / 1_000
        client.start(ports=session.traffic_ports, mult="1", duration=duration)
        client.wait_on_traffic(
            ports=session.traffic_ports,
            timeout=max(5, duration + 5),
            rx_delay_ms=2_000,
        )
        observation = self._observe_trial(session, traffic)
        loss_percent = (
            0.0
            if observation.tx_frames == 0
            else observation.loss_frames * 100 / observation.tx_frames
        )
        question = document.spec.question
        return EngineMeasurement(
            verdict=Verdict.NO_ASSERTION if observation.valid else Verdict.INVALID,
            methodology="trex-stl-dns-query-storm/v1",
            summary={
                "simulated": False,
                "protocol": document.spec.protocol,
                "question": {
                    "name": question.name,
                    "type": question.type,
                    "class": question.dns_class,
                },
                "queriesTx": observation.tx_frames,
                "queriesRx": observation.rx_frames,
                "lostQueries": observation.loss_frames,
                "lossPercent": loss_percent,
                "observationValid": observation.valid,
                "validity": observation.details,
                "targetRateReached": observation.target_rate_reached,
                "counterSource": document.spec.observation.query_delivery,
                "responseObservation": document.spec.observation.responses,
                "portEnvironment": session.port_environment,
            },
            provenance={"engine": self.mode, "trexVersion": session.version},
        )

    def _run_dhcp_storm_sync(self, session: _Session) -> EngineMeasurement:
        document = session.document
        assert isinstance(document, PacketStormDocument)
        assert isinstance(document.spec, DhcpStormSpec)
        traffic = self._packet_storm_traffic_document(document)
        client = session.client
        client.clear_stats(ports=session.ports)
        session.baseline_clean = self._baseline_clean(client, session.ports)
        duration = document.spec.run.duration / 1_000
        client.start(ports=session.traffic_ports, mult="1", duration=duration)
        client.wait_on_traffic(
            ports=session.traffic_ports,
            timeout=max(5, duration + 5),
            rx_delay_ms=2_000,
        )
        observation = self._observe_trial(session, traffic)
        loss_percent = (
            0.0
            if observation.tx_frames == 0
            else observation.loss_frames * 100 / observation.tx_frames
        )
        return EngineMeasurement(
            verdict=Verdict.NO_ASSERTION if observation.valid else Verdict.INVALID,
            methodology="trex-stl-dhcp-discover-storm/v1",
            summary={
                "simulated": False,
                "protocol": document.spec.protocol,
                "messageType": document.spec.message.type,
                "clientIdentities": document.spec.clients.count,
                "discoversTx": observation.tx_frames,
                "discoversRx": observation.rx_frames,
                "lostDiscovers": observation.loss_frames,
                "lossPercent": loss_percent,
                "observationValid": observation.valid,
                "validity": observation.details,
                "targetRateReached": observation.target_rate_reached,
                "counterSource": document.spec.observation.discover_delivery,
                "offerObservation": document.spec.observation.offers,
                "portEnvironment": session.port_environment,
            },
            provenance={"engine": self.mode, "trexVersion": session.version},
        )

    def _run_arp_storm_sync(self, session: _Session) -> EngineMeasurement:
        document = session.document
        assert isinstance(document, PacketStormDocument)
        assert isinstance(document.spec, ArpStormSpec)
        client = session.client
        client.clear_stats(ports=session.ports)
        duration = document.spec.run.duration / 1_000
        client.start(ports=session.traffic_ports, mult="1", duration=duration)
        client.wait_on_traffic(
            ports=session.traffic_ports,
            timeout=max(5, duration + 5),
            rx_delay_ms=2_000,
        )
        stats = client.get_stats(ports=session.ports)
        tx_port = self._config.port_mapping[document.spec.senders.port]
        requests_tx = int(stats[tx_port].get("opackets", 0))
        output_errors = int(stats[tx_port].get("oerrors", 0))
        expected_requests = document.spec.run.pps * duration
        transmission_valid = requests_tx > 0 and output_errors == 0
        return EngineMeasurement(
            verdict=Verdict.NO_ASSERTION if transmission_valid else Verdict.INVALID,
            methodology="trex-stl-arp-request-storm/v1",
            summary={
                "simulated": False,
                "protocol": document.spec.protocol,
                "messageType": document.spec.message.operation,
                "senderIdentities": document.spec.senders.count,
                "targetIpv4": document.spec.target.ipv4,
                "requestsTx": requests_tx,
                "expectedRequests": expected_requests,
                "achievedPps": requests_tx / duration,
                "transmissionValid": transmission_valid,
                "targetRateReached": requests_tx >= expected_requests * 0.99,
                "outputErrors": output_errors,
                "counterSource": document.spec.observation.request_transmission,
                "requestDeliveryObservation": document.spec.observation.request_delivery,
                "replyObservation": document.spec.observation.replies,
                "limitation": document.spec.observation.limitation,
                "warnings": [str(item) for item in client.get_warnings()],
                "portEnvironment": session.port_environment,
            },
            provenance={"engine": self.mode, "trexVersion": session.version},
        )

    def _run_udp_workload_sync(
        self,
        session: _Session,
        report_progress: Callable[[dict[str, Any]], None] | None = None,
    ) -> EngineMeasurement:
        document = session.document
        assert isinstance(document, UdpWorkloadDocument)
        streams = session.udp_streams
        assert streams is not None
        client = session.client
        duration = document.spec.run.duration / 1_000
        client.clear_stats(ports=session.ports)
        session.baseline_clean = self._baseline_clean(client, session.ports)
        client.start(ports=session.traffic_ports, mult="1", duration=duration)
        client.wait_on_traffic(
            ports=session.traffic_ports,
            timeout=max(30, duration + 30),
            rx_delay_ms=2_000,
        )
        pgid = client.get_pgid_stats(session.pg_ids)
        flow_stats = pgid.get("flow_stats", {})
        stream_results = []
        for stream in streams:
            flow = flow_stats.get(stream.pg_id) or flow_stats.get(str(stream.pg_id)) or {}
            tx_datagrams = self._port_counter(flow.get("tx_pkts", {}), stream.tx_port)
            rx_datagrams = self._port_counter(flow.get("rx_pkts", {}), stream.rx_port)
            stream_results.append((stream, tx_datagrams, rx_datagrams))
        directions: dict[str, dict[str, int]] = {
            "initiator-to-responder": {
                "txDatagrams": 0,
                "rxDatagrams": 0,
                "lossDatagrams": 0,
            },
            "responder-to-initiator": {
                "txDatagrams": 0,
                "rxDatagrams": 0,
                "lossDatagrams": 0,
            },
        }
        template_results = []
        for binding in document.spec.workload.templates:
            selected = [item for item in stream_results if item[0].template_id == binding.id]
            tx_datagrams = sum(item[1] for item in selected)
            rx_datagrams = sum(item[2] for item in selected)
            flow_instances = min((item[1] for item in selected), default=0)
            initiator_bytes = sum(
                item[1] * item[0].payload_bytes
                for item in selected
                if item[0].direction == "initiator-to-responder"
            )
            responder_bytes = sum(
                item[1] * item[0].payload_bytes
                for item in selected
                if item[0].direction == "responder-to-initiator"
            )
            template_results.append(
                {
                    "id": binding.id,
                    "digest": binding.digest,
                    "occurrenceCount": binding.occurrence_count,
                    "weight": binding.weight,
                    "fps": binding.fps,
                    "flowInstances": flow_instances,
                    "txDatagrams": tx_datagrams,
                    "rxDatagrams": rx_datagrams,
                    "lossDatagrams": max(0, tx_datagrams - rx_datagrams),
                    "initiatorPayloadBytes": initiator_bytes,
                    "responderPayloadBytes": responder_bytes,
                }
            )
        for stream, tx_datagrams, rx_datagrams in stream_results:
            direction = directions[stream.direction]
            direction["txDatagrams"] += tx_datagrams
            direction["rxDatagrams"] += rx_datagrams
            direction["lossDatagrams"] += max(0, tx_datagrams - rx_datagrams)
        tx_total = sum(item[1] for item in stream_results)
        rx_total = sum(item[2] for item in stream_results)
        if report_progress is not None:
            report_progress(
                {
                    "completedFrames": tx_total,
                    "totalFrames": int(document.spec.run.estimated_pps * duration),
                }
            )
        warnings = [str(item) for item in client.get_warnings()]
        links_up = all(client.get_port(port).is_up() for port in session.ports)
        ownership_held = all(
            client.get_port(port).get_owner() == session.owner for port in session.ports
        )
        flow_stats_complete = all(
            bool(flow_stats.get(item.pg_id) or flow_stats.get(str(item.pg_id))) for item in streams
        )
        observation_valid = (
            session.baseline_clean
            and links_up
            and ownership_held
            and flow_stats_complete
            and not warnings
        )
        return EngineMeasurement(
            verdict=Verdict.NO_ASSERTION,
            methodology="trex-stl-datagram-workload/v1",
            summary={
                "simulated": False,
                "selection": document.spec.workload.selection,
                "sourceFlowCount": document.spec.workload.source_flow_count,
                "templateCount": document.spec.workload.template_count,
                "flowInstances": sum(item["flowInstances"] for item in template_results),
                "txDatagrams": tx_total,
                "rxDatagrams": rx_total,
                "lossDatagrams": max(0, tx_total - rx_total),
                "observationValid": observation_valid,
                "counterSource": "flow-stats",
                "directions": directions,
                "templates": template_results,
                "semanticDifferences": document.spec.semantic_differences,
                "warnings": warnings,
                "portEnvironment": session.port_environment,
            },
            provenance={"engine": self.mode, "trexVersion": session.version},
        )

    def _run_rfc2544_suite_sync(
        self,
        session: _Session,
        report_progress: Callable[[dict[str, Any]], None] | None = None,
    ) -> EngineMeasurement:
        suite = session.document
        assert isinstance(suite, Rfc2544SuiteDocument)
        document = self._throughput_document(suite)
        measurements: dict[str, EngineMeasurement] = {}
        for index, test_name in enumerate(suite.spec.tests):

            def method_progress(
                update: dict[str, Any],
                current_test: str = test_name,
                test_index: int = index,
            ) -> None:
                if report_progress is not None:
                    local_total = update.get("totalFrames")
                    local_completed = update.get("completedFrames")
                    suite_progress: dict[str, Any] = {}
                    if isinstance(local_total, int) and isinstance(local_completed, int):
                        suite_progress = {
                            "completedFrames": test_index * local_total + local_completed,
                            "totalFrames": len(suite.spec.tests) * local_total,
                        }
                    report_progress(
                        {
                            "test": current_test,
                            "testIndex": test_index,
                            "totalTests": len(suite.spec.tests),
                            **update,
                            **suite_progress,
                        }
                    )

            if test_name == "throughput":
                measurements[test_name] = self._run_rfc2544_sync(
                    session, method_progress, document=document
                )
            elif test_name == "frame-loss":
                measurements[test_name] = self._run_frame_loss_sync(
                    session, document, method_progress
                )
            elif test_name == "back-to-back":
                measurements[test_name] = self._run_back_to_back_sync(
                    session,
                    document,
                    measurements.get("throughput"),
                    method_progress,
                )
            else:
                measurements[test_name] = self._run_latency_sync(
                    session,
                    document,
                    measurements.get("throughput"),
                    method_progress,
                )

        verdicts = {measurement.verdict for measurement in measurements.values()}
        if Verdict.INVALID in verdicts:
            verdict = Verdict.INVALID
        elif Verdict.FAIL in verdicts:
            verdict = Verdict.FAIL
        elif Verdict.PASS in verdicts:
            verdict = Verdict.PASS
        else:
            verdict = Verdict.NO_ASSERTION
        summary: dict[str, Any] = {
            "simulated": False,
            "mode": suite.spec.mode,
            "directionMode": suite.spec.direction_mode or suite.spec.ports.direction,
            "reportContext": (
                suite.spec.report_context.model_dump(mode="json", by_alias=True, exclude_none=True)
                if suite.spec.report_context is not None
                else None
            ),
            "testEnvironment": {
                "trexVersion": session.version,
                "ports": session.port_environment,
            },
            "tests": {
                name: {
                    "methodology": measurement.methodology,
                    "verdict": measurement.verdict,
                    **measurement.summary,
                }
                for name, measurement in measurements.items()
            },
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
                "rfc2544-suite-strict/v1"
                if suite.spec.mode == "strict"
                else "engineering-rfc2544-suite/v1"
            ),
            summary=summary,
            provenance={"engine": self.mode, "trexVersion": session.version},
        )

    @staticmethod
    def _throughput_document(suite: Rfc2544SuiteDocument) -> Rfc2544ThroughputDocument:
        spec = suite.spec.model_dump(mode="json", by_alias=True, exclude_none=True)
        spec.pop("tests")
        spec.pop("latency", None)
        spec.pop("backToBack", None)
        spec.pop("reportContext", None)
        return Rfc2544ThroughputDocument.model_validate(
            {
                "apiVersion": suite.api_version,
                "kind": "Rfc2544Throughput",
                "metadata": suite.metadata.model_dump(
                    mode="json", by_alias=True, exclude_none=True
                ),
                "spec": spec,
            }
        )

    def _run_stateless_sync(self, session: _Session) -> EngineMeasurement:
        document = session.document
        assert isinstance(document, StatelessTrafficDocument)
        client = session.client
        api = self._load_api()
        client.remove_all_streams(ports=session.ports)
        self._learn_switch_paths(api, client, session.directions)
        self._install_streams(api, client, document, session.directions, session.uses_flow_stats)
        client.clear_stats(ports=session.ports)
        session.baseline_clean = self._baseline_clean(client, session.ports)
        duration = document.spec.duration / 1_000 if document.spec.duration is not None else -1
        client.start(ports=session.traffic_ports, mult="1", duration=duration)
        wait_seconds = self._estimated_run_seconds(document) + 5
        client.wait_on_traffic(ports=session.traffic_ports, timeout=max(wait_seconds, 5))
        observation = self._observe_trial(
            session,
            document,
            allow_port_fallback=not session.uses_flow_stats,
        )
        loss_percent = (
            0.0
            if observation.tx_frames == 0
            else observation.loss_frames * 100 / observation.tx_frames
        )
        if not observation.valid:
            verdict = Verdict.INVALID
        elif document.spec.assertions is None:
            verdict = Verdict.NO_ASSERTION
        else:
            verdict = (
                Verdict.PASS
                if loss_percent <= document.spec.assertions.max_loss_percent
                else Verdict.FAIL
            )
        return EngineMeasurement(
            verdict=verdict,
            methodology="trex-stl-stateless/v1",
            summary={
                "simulated": False,
                "valid": observation.valid,
                "validity": observation.details,
                "targetRateReached": observation.target_rate_reached,
                "txFrames": observation.tx_frames,
                "rxFrames": observation.rx_frames,
                "lossFrames": observation.loss_frames,
                "lossPercent": loss_percent,
            },
            provenance={"engine": self.mode, "trexVersion": session.version},
        )

    def _run_rfc2544_sync(
        self,
        session: _Session,
        report_progress: Callable[[dict[str, Any]], None] | None = None,
        *,
        document: Rfc2544ThroughputDocument | None = None,
    ) -> EngineMeasurement:
        if document is None:
            assert isinstance(session.document, Rfc2544ThroughputDocument)
            document = session.document
        frame_sizes = (
            [64, 128, 256, 512, 1024, 1280, 1518]
            if document.spec.mode == "strict"
            else (document.spec.frame_sizes or [64, 512, 1518])
        )
        ceiling = self._policy.max_percent_l1 if self._policy else 100.0
        settings = settings_for(document.spec.mode, ceiling)
        if document.spec.direction_mode == "unidirectional-each":
            return self._run_rfc2544_each_sync(
                session, document, frame_sizes, ceiling, report_progress
            )
        results = []
        for frame_index, frame_size in enumerate(frame_sizes):
            if report_progress is not None:
                report_progress(
                    {
                        "frameSize": frame_size,
                        "completedFrames": frame_index,
                        "totalFrames": len(frame_sizes),
                        "stage": "search",
                    }
                )

            def on_observation(
                record: dict[str, object],
                current_frame_size: int = frame_size,
                completed_frames: int = frame_index,
            ) -> None:
                if report_progress is None:
                    return
                report_progress(
                    {
                        "frameSize": current_frame_size,
                        "completedFrames": completed_frames,
                        "totalFrames": len(frame_sizes),
                        "stage": record["phase"],
                        "ratePercentL1": record["ratePercentL1"],
                        "durationSeconds": record["durationSeconds"],
                        "valid": record["valid"],
                        "lossFrames": record["lossFrames"],
                    }
                )

            result = search_frame(
                frame_size,
                ceiling,
                settings,
                lambda size, rate, duration: self._rfc_trial_sync(
                    session, document, size, rate, duration
                ),
                on_observation,
            )
            results.append(result)
            if report_progress is not None:
                report_progress(
                    {
                        "frameSize": frame_size,
                        "completedFrames": frame_index + 1,
                        "totalFrames": len(frame_sizes),
                        "stage": "frame-completed",
                    }
                )

        throughput = {str(item.frame_size): item.throughput_percent_l1 for item in results}
        all_valid = all(item.valid and item.throughput_percent_l1 is not None for item in results)
        assertion = document.spec.assertion
        if not all_valid:
            verdict = Verdict.INVALID
        elif assertion is None:
            verdict = Verdict.NO_ASSERTION
        else:
            passed = True
            for threshold_frame, threshold in assertion.minimum_percent_line_rate.items():
                measured = throughput.get(threshold_frame)
                if measured is None or measured < threshold:
                    passed = False
                    break
            verdict = Verdict.PASS if passed else Verdict.FAIL

        line_rate = min(session.line_rates_bps.values())
        rates: dict[str, dict[str, float | None]] = {}
        for item in results:
            frame = item.frame_size
            percent = item.throughput_percent_l1
            theoretical_fps = line_rate / ((frame + 20) * 8)
            fps = None if percent is None else theoretical_fps * percent / 100
            rates[str(frame)] = {
                "percentL1": percent,
                "fps": fps,
                "bpsL1": None if percent is None else line_rate * percent / 100,
                "bpsL2": None if fps is None else fps * frame * 8,
                "theoreticalMaxFps": theoretical_fps,
            }
        frames = {
            str(item.frame_size): {
                "valid": item.valid,
                **rates[str(item.frame_size)],
                "trials": item.trials,
            }
            for item in results
        }
        return EngineMeasurement(
            verdict=verdict,
            methodology=(
                "rfc2544-throughput-strict/v1"
                if document.spec.mode == "strict"
                else "engineering-throughput-estimate/v1"
            ),
            summary={
                "simulated": False,
                "mode": document.spec.mode,
                "directionMode": document.spec.direction_mode or document.spec.ports.direction,
                "standardConformance": (
                    "rfc2544-throughput-methodology"
                    if document.spec.mode == "strict"
                    else "engineering-estimate-not-rfc2544"
                ),
                "ceilingPercentL1": ceiling,
                "resolutionPercentL1": settings.resolution,
                "rates": rates,
                "trials": {str(item.frame_size): item.trials for item in results},
                "frames": frames,
            },
            provenance={"engine": self.mode, "trexVersion": session.version},
        )

    def _run_frame_loss_sync(
        self,
        session: _Session,
        document: Rfc2544ThroughputDocument,
        report_progress: Callable[[dict[str, Any]], None] | None = None,
    ) -> EngineMeasurement:
        frame_sizes = (
            [64, 128, 256, 512, 1024, 1280, 1518]
            if document.spec.mode == "strict"
            else (document.spec.frame_sizes or [64, 512, 1518])
        )
        ceiling = self._policy.max_percent_l1 if self._policy else 100.0
        settings = frame_loss_settings_for(document.spec.mode, ceiling)
        selected_directions: list[str | None] = (
            ["forward", "reverse"]
            if document.spec.direction_mode == "unidirectional-each"
            else [None]
        )
        by_direction: dict[str, dict[str, Any]] = {}
        total_frames = len(frame_sizes) * len(selected_directions)
        for direction_index, direction in enumerate(selected_directions):
            frame_results = []
            for frame_index, frame_size in enumerate(frame_sizes):
                completed = direction_index * len(frame_sizes) + frame_index

                def on_observation(
                    record: dict[str, object],
                    current_frame: int = frame_size,
                    completed_frames: int = completed,
                    current_direction: str | None = direction,
                ) -> None:
                    if report_progress is None:
                        return
                    report_progress(
                        {
                            **(
                                {"direction": current_direction}
                                if current_direction is not None
                                else {}
                            ),
                            "frameSize": current_frame,
                            "completedFrames": completed_frames,
                            "totalFrames": total_frames,
                            "stage": record["phase"],
                            "ratePercentL1": record["ratePercentL1"],
                            "durationSeconds": record["durationSeconds"],
                            "valid": record["valid"],
                            "lossFrames": record["lossFrames"],
                            "lossPercent": record["lossPercent"],
                        }
                    )

                frame_results.append(
                    measure_frame_loss(
                        frame_size,
                        ceiling,
                        settings,
                        lambda size, rate, duration, selected=direction: self._rfc_trial_sync(
                            session, document, size, rate, duration, selected
                        ),
                        on_observation,
                    )
                )
                if report_progress is not None:
                    report_progress(
                        {
                            **({"direction": direction} if direction is not None else {}),
                            "frameSize": frame_size,
                            "completedFrames": completed + 1,
                            "totalFrames": total_frames,
                            "stage": "frame-completed",
                        }
                    )
            by_direction[direction or "combined"] = {
                "frames": {
                    str(item.frame_size): {
                        "valid": item.valid,
                        "stoppedAfterTwoZeroLossTrials": (item.stopped_after_consecutive_zero_loss),
                        "points": item.trials,
                    }
                    for item in frame_results
                }
            }

        all_frames = [
            frame
            for direction_result in by_direction.values()
            for frame in direction_result["frames"].values()
        ]
        verdict = (
            Verdict.NO_ASSERTION if all(frame["valid"] for frame in all_frames) else Verdict.INVALID
        )
        conformance = (
            "rfc2544-frame-loss-methodology"
            if document.spec.mode == "strict" and ceiling == 100
            else (
                "rfc2544-frame-loss-partial-range"
                if document.spec.mode == "strict"
                else "engineering-estimate-not-rfc2544"
            )
        )
        summary: dict[str, Any] = {
            "simulated": False,
            "mode": document.spec.mode,
            "directionMode": document.spec.direction_mode or document.spec.ports.direction,
            "standardConformance": conformance,
            "ceilingPercentL1": ceiling,
            "stepPercentL1": settings.step_percent,
            "trialDurationSeconds": settings.trial_seconds,
        }
        if selected_directions == [None]:
            summary.update(by_direction["combined"])
        else:
            summary["directions"] = by_direction
        return EngineMeasurement(
            verdict=verdict,
            methodology=(
                "rfc2544-frame-loss-strict/v1"
                if document.spec.mode == "strict"
                else "engineering-frame-loss-curve/v1"
            ),
            summary=summary,
            provenance={"engine": self.mode, "trexVersion": session.version},
        )

    def _run_latency_sync(
        self,
        session: _Session,
        document: Rfc2544ThroughputDocument,
        throughput: EngineMeasurement | None,
        report_progress: Callable[[dict[str, Any]], None] | None = None,
    ) -> EngineMeasurement:
        suite = session.document
        assert isinstance(suite, Rfc2544SuiteDocument)
        configured = suite.spec.latency
        calibration = self._config.latency_timestamp_calibration
        calibration_valid = (
            configured is not None
            and calibration is not None
            and calibration.measured_at <= utc_now() <= calibration.valid_until
            and configured.definition in calibration.correction_microseconds
            and all(session.ieee1588_supported.values())
        )
        rates = throughput.summary.get("rates") if throughput is not None else None
        if configured is None or not calibration_valid or not isinstance(rates, dict):
            calibration_id = calibration.calibration_id if calibration is not None else None
            return EngineMeasurement(
                verdict=Verdict.INVALID,
                methodology="rfc2544-latency-unavailable/v1",
                summary={
                    "simulated": False,
                    "definition": configured.definition if configured is not None else None,
                    "standardConformance": "latency-timestamp-calibration-required",
                    "timestampCalibration": {
                        "valid": False,
                        "calibrationId": calibration_id,
                    },
                    "frames": {},
                    "issues": [
                        (
                            "one or more selected TRex ports do not support IEEE 1588 timestamps"
                            if not all(session.ieee1588_supported.values())
                            else (
                                "the remote engine has no current calibrated RFC 1242 "
                                "timestamp source"
                            )
                        )
                    ],
                },
                provenance={"engine": self.mode, "trexVersion": session.version},
            )
        assert calibration is not None
        corrections = calibration.correction_microseconds[configured.definition]
        settings = LatencySettings(
            trial_seconds=configured.trial_seconds,
            tag_after_seconds=configured.tag_after_seconds,
            repetitions=configured.repetitions,
        )
        frame_results: dict[str, Any] = {}
        all_valid = True

        def trial_for(selected_packet: Any, selected_correction: float) -> LatencyTrialFunction:
            def latency_trial(
                frame_size: int,
                rate_percent: float,
                duration_seconds: float,
                tag_after_seconds: float,
            ) -> LatencyObservation:
                return self._latency_trial_sync(
                    session,
                    document,
                    selected_packet,
                    frame_size,
                    rate_percent,
                    duration_seconds,
                    tag_after_seconds,
                    selected_correction,
                    calibration.calibration_id,
                )

            return latency_trial

        for frame_index, (frame_size, rate) in enumerate(rates.items()):
            if not isinstance(rate, dict) or not isinstance(rate.get("percentL1"), int | float):
                all_valid = False
                continue
            frame_number = int(frame_size)
            correction = corrections.get(frame_number)
            scenarios: dict[str, Any] = {}
            for scenario_name in configured.scenarios:
                packet = (
                    document.spec.packet
                    if scenario_name == "same-destination"
                    else configured.new_destination_packet
                )
                if packet is None or correction is None:
                    all_valid = False
                    scenarios[scenario_name] = {
                        "valid": False,
                        "samplesMicroseconds": [],
                        "averageMicroseconds": None,
                        "trials": [],
                        "issues": [
                            "new destination packet or frame calibration correction is missing"
                        ],
                    }
                    continue
                if report_progress is not None:
                    report_progress(
                        {
                            "frameSize": frame_number,
                            "scenario": scenario_name,
                            "completedFrames": frame_index,
                            "totalFrames": len(rates),
                            "stage": "tagged-trials",
                        }
                    )

                result = measure_latency(
                    frame_number,
                    float(rate["percentL1"]),
                    settings,
                    trial_for(packet, float(correction)),
                    definition=configured.definition,
                )
                all_valid = all_valid and result.valid
                scenarios[scenario_name] = {
                    "valid": result.valid,
                    "throughputPercentL1": result.throughput_percent_l1,
                    "samplesMicroseconds": result.samples_microseconds,
                    "averageMicroseconds": result.average_microseconds,
                    "trials": result.trials,
                }
            frame_results[frame_size] = scenarios
            if report_progress is not None:
                report_progress(
                    {
                        "frameSize": frame_number,
                        "completedFrames": frame_index + 1,
                        "totalFrames": len(rates),
                        "stage": "frame-completed",
                    }
                )
        conforming = suite.spec.mode == "strict" and all_valid and bool(frame_results)
        return EngineMeasurement(
            verdict=Verdict.NO_ASSERTION if all_valid else Verdict.INVALID,
            methodology=(
                "rfc2544-latency-strict/v1" if conforming else "rfc2544-latency-partial/v1"
            ),
            summary={
                "simulated": False,
                "definition": configured.definition,
                "standardConformance": (
                    "rfc2544-latency-methodology" if conforming else "rfc2544-latency-partial"
                ),
                "timestampCalibration": {
                    "valid": True,
                    "calibrationId": calibration.calibration_id,
                    "calibrationDigest": calibration.calibration_digest,
                    "calibrationArtifact": calibration.calibration_artifact,
                    "timestampMode": calibration.timestamp_mode,
                    "measuredAt": calibration.measured_at.isoformat(),
                    "validUntil": calibration.valid_until.isoformat(),
                    "maximumUncertaintyMicroseconds": (
                        calibration.maximum_uncertainty_microseconds
                    ),
                },
                "trialDurationSeconds": configured.trial_seconds,
                "tagAfterSeconds": configured.tag_after_seconds,
                "repetitions": configured.repetitions,
                "frames": frame_results,
            },
            provenance={"engine": self.mode, "trexVersion": session.version},
        )

    def _latency_trial_sync(
        self,
        session: _Session,
        document: Rfc2544ThroughputDocument,
        packet: Any,
        frame_size: int,
        rate_percent: float,
        duration_seconds: float,
        tag_after_seconds: float,
        correction_microseconds: float,
        calibration_id: str,
    ) -> LatencyObservation:
        raw_document = document.model_dump(mode="json", by_alias=True, exclude_none=True)
        raw_document["spec"]["packet"] = packet.model_dump(
            mode="json", by_alias=True, exclude_none=True
        )
        selected_document = Rfc2544ThroughputDocument.model_validate(raw_document)
        trial_document = self._rfc_trial_document(
            selected_document, frame_size, rate_percent, duration_seconds
        )
        directions = self._directions(trial_document, session.pg_ids)
        if len(directions) != 1:
            return LatencyObservation(
                False,
                None,
                {"reason": "calibrated latency currently requires one unidirectional stream"},
            )
        direction = directions[0]
        client = session.client
        api = self._load_api()
        latency_pg_id = max(session.pg_ids) + 128
        client.remove_all_streams(ports=session.ports)
        self._learn_switch_paths(api, client, directions)
        self._install_streams(api, client, trial_document, directions, True)
        tagged_packet, tagged_vm = self._packet_plan_for(
            api,
            direction.packet,
            reverse=direction.reverse,
            variable_prefix="latency_tagged",
        )
        tagged_stream = api.STLStream(
            packet=api.STLPktBuilder(pkt=tagged_packet, vm=tagged_vm),
            mode=api.STLTXSingleBurst(total_pkts=1, pps=1),
            isg=tag_after_seconds * 1_000_000,
            flow_stats=api.STLFlowLatencyStats(pg_id=latency_pg_id, ieee_1588=True),
        )
        client.add_streams(tagged_stream, ports=[direction.tx_port])
        client.clear_stats(ports=session.ports)
        session.baseline_clean = self._baseline_clean(client, session.ports)
        client.start(ports=[direction.tx_port], mult="1", duration=duration_seconds)
        client.wait_on_traffic(
            ports=[direction.tx_port],
            timeout=duration_seconds + 5,
            rx_delay_ms=2_000,
        )
        background = self._observe_trial(
            session,
            trial_document,
            allow_port_fallback=document.spec.mode == "fast",
        )
        stats = client.get_pgid_stats([latency_pg_id])
        flow_stats = stats.get("flow_stats", {})
        latency_stats = stats.get("latency", {})
        flow = flow_stats.get(latency_pg_id) or flow_stats.get(str(latency_pg_id)) or {}
        latency = latency_stats.get(latency_pg_id) or latency_stats.get(str(latency_pg_id)) or {}
        tx_frames = self._port_counter(flow.get("tx_pkts", {}), direction.tx_port)
        rx_frames = self._port_counter(flow.get("rx_pkts", {}), direction.rx_port)
        latency_values = latency.get("latency", {})
        raw_sample = latency_values.get("average")
        errors = self._nested_counter_total(latency.get("err_cntrs", {}))
        valid = (
            background.valid
            and tx_frames == 1
            and rx_frames == 1
            and errors == 0
            and isinstance(raw_sample, int | float)
        )
        corrected = float(raw_sample) + correction_microseconds if valid else None
        self._sleep(5)
        return LatencyObservation(
            valid and corrected is not None and corrected >= 0,
            corrected,
            {
                "timestampMode": "ieee1588",
                "calibrationId": calibration_id,
                "rawLatencyMicroseconds": raw_sample,
                "correctionMicroseconds": correction_microseconds,
                "txTaggedFrames": tx_frames,
                "rxTaggedFrames": rx_frames,
                "latencyErrors": errors,
                "background": background.details,
            },
        )

    def _run_back_to_back_sync(
        self,
        session: _Session,
        document: Rfc2544ThroughputDocument,
        throughput: EngineMeasurement | None,
        report_progress: Callable[[dict[str, Any]], None] | None = None,
    ) -> EngineMeasurement:
        suite = session.document
        assert isinstance(suite, Rfc2544SuiteDocument)
        configured = suite.spec.back_to_back
        if configured is None or throughput is None:
            return EngineMeasurement(
                verdict=Verdict.INVALID,
                methodology="rfc9004-back-to-back-invalid/v1",
                summary={
                    "standardConformance": "rfc9004-back-to-back-prerequisite-missing",
                    "frames": {},
                },
                provenance={"engine": self.mode, "trexVersion": session.version},
            )
        rates = throughput.summary.get("rates")
        if not isinstance(rates, dict):
            rates = {}
        policy_maximum = (
            self._policy.max_burst_packets
            if self._policy is not None
            else configured.maximum_burst_frames
        )
        maximum_burst_frames = min(configured.maximum_burst_frames, policy_maximum)
        settings = BackToBackSettings(
            repetitions=configured.repetitions,
            minimum_step_frames=configured.minimum_step_frames,
            maximum_burst_frames=maximum_burst_frames,
        )
        frame_results: dict[str, Any] = {}
        for frame_index, (frame_size, rate) in enumerate(rates.items()):
            if not isinstance(rate, dict):
                continue
            theoretical_fps = rate.get("theoreticalMaxFps")
            throughput_fps = rate.get("fps")
            if not isinstance(theoretical_fps, int | float) or not isinstance(
                throughput_fps, int | float
            ):
                continue
            if report_progress is not None:
                report_progress(
                    {
                        "frameSize": int(frame_size),
                        "completedFrames": frame_index,
                        "totalFrames": len(rates),
                        "stage": "independent-searches",
                    }
                )
            if float(throughput_fps) >= float(theoretical_fps):
                frame_results[frame_size] = {
                    "valid": True,
                    "applicability": ("not-applicable-throughput-equals-theoretical"),
                    "throughputFps": float(throughput_fps),
                    "theoreticalMaxFps": float(theoretical_fps),
                    "searches": [],
                }
                if report_progress is not None:
                    report_progress(
                        {
                            "frameSize": int(frame_size),
                            "completedFrames": frame_index + 1,
                            "totalFrames": len(rates),
                            "stage": "not-applicable",
                        }
                    )
                continue
            result = measure_back_to_back(
                int(frame_size),
                theoretical_fps=float(theoretical_fps),
                throughput_fps=float(throughput_fps),
                settings=settings,
                trial=lambda size, frames, theoretical=float(theoretical_fps): (
                    self._back_to_back_trial_sync(
                        session,
                        document,
                        size,
                        frames,
                        theoretical,
                        configured.buffer_depletion_seconds,
                    )
                ),
            )
            frame_results[frame_size] = {
                "valid": result.valid,
                "repetitions": configured.repetitions,
                "minimumStepFrames": configured.minimum_step_frames,
                "maximumBurstFrames": maximum_burst_frames,
                "longestZeroLossBursts": result.longest_zero_loss_bursts,
                "averageFrames": result.average_frames,
                "minimumFrames": result.minimum_frames,
                "maximumFrames": result.maximum_frames,
                "standardDeviationFrames": result.standard_deviation_frames,
                "impliedBufferSeconds": result.implied_buffer_seconds,
                "correctedBufferSeconds": result.corrected_buffer_seconds,
                "searches": result.searches,
            }
            if report_progress is not None:
                report_progress(
                    {
                        "frameSize": int(frame_size),
                        "completedFrames": frame_index + 1,
                        "totalFrames": len(rates),
                        "stage": "frame-completed",
                    }
                )
        complete_range = all(
            isinstance(rate, dict)
            and isinstance(rate.get("theoreticalMaxFps"), int | float)
            and isinstance(rate.get("fps"), int | float)
            and (
                float(rate["fps"]) >= float(rate["theoreticalMaxFps"])
                or maximum_burst_frames
                >= float(rate["theoreticalMaxFps"]) * configured.maximum_burst_seconds
            )
            for rate in rates.values()
        )
        all_valid = bool(frame_results) and all(
            isinstance(frame, dict) and frame.get("valid") is True
            for frame in frame_results.values()
        )
        conforming = suite.spec.mode == "strict" and complete_range and all_valid
        return EngineMeasurement(
            verdict=Verdict.NO_ASSERTION if all_valid else Verdict.INVALID,
            methodology=(
                "rfc9004-back-to-back-strict/v1"
                if conforming
                else "rfc9004-back-to-back-partial/v1"
            ),
            summary={
                "simulated": False,
                "standardConformance": (
                    "rfc9004-back-to-back-methodology"
                    if conforming
                    else "rfc9004-back-to-back-partial-range"
                ),
                "maximumBurstSeconds": configured.maximum_burst_seconds,
                "bufferDepletionSeconds": configured.buffer_depletion_seconds,
                "frames": frame_results,
            },
            provenance={"engine": self.mode, "trexVersion": session.version},
        )

    def _back_to_back_trial_sync(
        self,
        session: _Session,
        document: Rfc2544ThroughputDocument,
        frame_size: int,
        burst_frames: int,
        theoretical_fps: float,
        buffer_depletion_seconds: float,
    ) -> BackToBackObservation:
        duration_seconds = burst_frames / theoretical_fps
        trial_document = self._rfc_trial_document(
            document, frame_size, 100, max(duration_seconds, 0.001)
        )
        client = session.client
        api = self._load_api()
        directions = self._directions(trial_document, session.pg_ids)
        client.remove_all_streams(ports=session.ports)
        self._learn_switch_paths(api, client, directions)
        for index, direction in enumerate(directions):
            packet, vm = self._packet_plan_for(
                api,
                direction.packet,
                reverse=direction.reverse,
                variable_prefix=f"back_to_back_{index}",
            )
            stream = api.STLStream(
                packet=api.STLPktBuilder(pkt=packet, vm=vm),
                mode=api.STLTXSingleBurst(total_pkts=burst_frames, percentage=100),
                flow_stats=api.STLFlowStats(pg_id=direction.pg_id),
            )
            client.add_streams(stream, ports=[direction.tx_port])
        client.clear_stats(ports=session.ports)
        session.baseline_clean = self._baseline_clean(client, session.ports)
        traffic_ports = sorted({direction.tx_port for direction in directions})
        client.start(ports=traffic_ports, mult="1")
        client.wait_on_traffic(
            ports=traffic_ports,
            timeout=max(duration_seconds + buffer_depletion_seconds + 5, 5),
            rx_delay_ms=round(max(duration_seconds, 2) * 1_000),
        )
        observation = self._observe_trial(session, trial_document)
        self._sleep(max(buffer_depletion_seconds, 5))
        return BackToBackObservation(
            valid=observation.valid,
            tx_frames=observation.tx_frames,
            rx_frames=observation.rx_frames,
            details=observation.details,
        )

    def _run_rfc2544_each_sync(
        self,
        session: _Session,
        document: Rfc2544ThroughputDocument,
        frame_sizes: list[int],
        ceiling: float,
        report_progress: Callable[[dict[str, Any]], None] | None,
    ) -> EngineMeasurement:
        settings = settings_for(document.spec.mode, ceiling)
        directional_results: dict[str, list[Any]] = {}
        total_units = len(frame_sizes) * 2
        for direction_index, direction in enumerate(("forward", "reverse")):
            results = []
            for frame_index, frame_size in enumerate(frame_sizes):
                completed = direction_index * len(frame_sizes) + frame_index
                if report_progress is not None:
                    report_progress(
                        {
                            "direction": direction,
                            "frameSize": frame_size,
                            "completedFrames": completed,
                            "totalFrames": total_units,
                            "stage": "search",
                        }
                    )

                def on_observation(
                    record: dict[str, object],
                    current_direction: str = direction,
                    current_frame_size: int = frame_size,
                    completed_frames: int = completed,
                ) -> None:
                    if report_progress is None:
                        return
                    report_progress(
                        {
                            "direction": current_direction,
                            "frameSize": current_frame_size,
                            "completedFrames": completed_frames,
                            "totalFrames": total_units,
                            "stage": record["phase"],
                            "ratePercentL1": record["ratePercentL1"],
                            "durationSeconds": record["durationSeconds"],
                            "valid": record["valid"],
                            "lossFrames": record["lossFrames"],
                        }
                    )

                results.append(
                    search_frame(
                        frame_size,
                        ceiling,
                        settings,
                        lambda size, rate, duration, selected_direction=direction: (
                            self._rfc_trial_sync(
                                session,
                                document,
                                size,
                                rate,
                                duration,
                                selected_direction,
                            )
                        ),
                        on_observation,
                    )
                )
            directional_results[direction] = results

        all_results = [item for results in directional_results.values() for item in results]
        all_valid = all(
            item.valid and item.throughput_percent_l1 is not None for item in all_results
        )
        assertion = document.spec.assertion
        if not all_valid:
            verdict = Verdict.INVALID
        elif assertion is None:
            verdict = Verdict.NO_ASSERTION
        else:
            passed = all(
                item.throughput_percent_l1 is not None
                and item.throughput_percent_l1
                >= assertion.minimum_percent_line_rate.get(str(item.frame_size), 0)
                for item in all_results
            )
            verdict = Verdict.PASS if passed else Verdict.FAIL

        line_rate = min(session.line_rates_bps.values())
        directions_summary: dict[str, dict[str, Any]] = {}
        for direction, results in directional_results.items():
            rates: dict[str, dict[str, float | None]] = {}
            for item in results:
                frame = item.frame_size
                percent = item.throughput_percent_l1
                theoretical_fps = line_rate / ((frame + 20) * 8)
                fps = None if percent is None else theoretical_fps * percent / 100
                rates[str(frame)] = {
                    "percentL1": percent,
                    "fps": fps,
                    "bpsL1": None if percent is None else line_rate * percent / 100,
                    "bpsL2": None if fps is None else fps * frame * 8,
                    "theoreticalMaxFps": theoretical_fps,
                }
            directions_summary[direction] = {
                "rates": rates,
                "trials": {str(item.frame_size): item.trials for item in results},
            }
        conservative_rates: dict[str, dict[str, float | None]] = {}
        combined_trials: dict[str, list[dict[str, Any]]] = {}
        for frame_size in frame_sizes:
            frame_key = str(frame_size)
            candidates = [
                directions_summary[direction]["rates"][frame_key]
                for direction in ("forward", "reverse")
            ]
            conservative_rates[frame_key] = min(
                candidates,
                key=lambda item: (
                    float("-inf") if item["percentL1"] is None else float(item["percentL1"])
                ),
            )
            combined_trials[frame_key] = [
                trial
                for direction in ("forward", "reverse")
                for trial in directions_summary[direction]["trials"][frame_key]
            ]
        return EngineMeasurement(
            verdict=verdict,
            methodology=(
                "rfc2544-throughput-strict/v1"
                if document.spec.mode == "strict"
                else "engineering-throughput-estimate/v1"
            ),
            summary={
                "simulated": False,
                "mode": document.spec.mode,
                "directionMode": "unidirectional-each",
                "standardConformance": (
                    "rfc2544-throughput-methodology"
                    if document.spec.mode == "strict"
                    else "engineering-estimate-not-rfc2544"
                ),
                "ceilingPercentL1": ceiling,
                "resolutionPercentL1": settings.resolution,
                "rates": conservative_rates,
                "trials": combined_trials,
                "directions": directions_summary,
            },
            provenance={"engine": self.mode, "trexVersion": session.version},
        )

    def _rfc_trial_sync(
        self,
        session: _Session,
        document: Rfc2544ThroughputDocument,
        frame_size: int,
        rate_percent: float,
        duration_seconds: float,
        direction: str | None = None,
    ) -> TrialObservation:
        trial_document = self._rfc_trial_document(
            document, frame_size, rate_percent, duration_seconds, direction
        )
        client = session.client
        client.remove_all_streams(ports=session.ports)
        api = self._load_api()
        directions = self._directions(trial_document, session.pg_ids)
        self._learn_switch_paths(api, client, directions)
        self._install_streams(api, client, trial_document, directions, True)
        client.clear_stats(ports=session.ports)
        session.baseline_clean = self._baseline_clean(client, session.ports)
        traffic_ports = sorted({item.tx_port for item in directions})
        client.start(ports=traffic_ports, mult="1", duration=duration_seconds)
        client.wait_on_traffic(
            ports=traffic_ports,
            timeout=duration_seconds + 7,
            rx_delay_ms=2_000,
        )
        observation = self._observe_trial(
            session,
            trial_document,
            allow_port_fallback=document.spec.mode == "fast",
        )
        if document.spec.mode == "strict":
            self._sleep(5)
        return observation

    def _learn_switch_path(
        self,
        api: Any,
        client: Any,
        document: StatelessTrafficDocument,
        ports: list[int],
    ) -> None:
        reverse, reverse_vm = self._packet_plan(api, document, reverse=True)
        learning_stream = api.STLStream(
            packet=api.STLPktBuilder(pkt=reverse, vm=reverse_vm),
            mode=api.STLTXSingleBurst(total_pkts=10, pps=1000),
        )
        client.add_streams(learning_stream, ports=[ports[1]])
        try:
            client.start(ports=[ports[1]])
            client.wait_on_traffic(ports=[ports[1]], timeout=5)
        finally:
            client.remove_all_streams(ports=[ports[1]])

    def _learn_switch_paths(self, api: Any, client: Any, directions: list[_Direction]) -> None:
        learning_ports: set[int] = set()
        for index, direction in enumerate(directions):
            reverse, reverse_vm = self._packet_plan_for(
                api,
                direction.packet,
                reverse=not direction.reverse,
                variable_prefix=f"learn_{index}",
            )
            learning_stream = api.STLStream(
                packet=api.STLPktBuilder(pkt=reverse, vm=reverse_vm),
                mode=api.STLTXSingleBurst(total_pkts=10, pps=1000),
            )
            client.add_streams(learning_stream, ports=[direction.rx_port])
            learning_ports.add(direction.rx_port)
        ports = sorted(learning_ports)
        try:
            client.start(ports=ports)
            client.wait_on_traffic(ports=ports, timeout=5)
        finally:
            client.remove_all_streams(ports=ports)

    def _observe_trial(
        self,
        session: _Session,
        document: StatelessTrafficDocument,
        *,
        allow_port_fallback: bool = False,
    ) -> TrialObservation:
        client = session.client
        port_stats = client.get_stats(ports=session.ports)
        pgid_stats = client.get_pgid_stats(session.pg_ids)
        flow_stats = pgid_stats.get("flow_stats", {})
        global_flow = flow_stats.get("global", {})
        warnings = [str(item) for item in client.get_warnings()]
        directions: list[dict[str, object]] = []
        tx_total = 0
        rx_total = 0
        targets_reached = True
        flow_stats_present = True
        classification_reliable = True
        resolved_directions = session.directions or self._directions(document, session.pg_ids)
        classified_tx_by_port: dict[int, int] = {}
        classified_rx_by_port: dict[int, int] = {}
        for direction in resolved_directions:
            flow = flow_stats.get(direction.pg_id) or flow_stats.get(str(direction.pg_id))
            if not flow:
                continue
            classified_tx_by_port[direction.tx_port] = classified_tx_by_port.get(
                direction.tx_port, 0
            ) + self._port_counter(flow.get("tx_pkts", {}), direction.tx_port)
            classified_rx_by_port[direction.rx_port] = classified_rx_by_port.get(
                direction.rx_port, 0
            ) + self._port_counter(flow.get("rx_pkts", {}), direction.rx_port)
        for direction in resolved_directions:
            tx_port, rx_port, pg_id = (
                direction.tx_port,
                direction.rx_port,
                direction.pg_id,
            )
            flow = flow_stats.get(pg_id) or flow_stats.get(str(pg_id))
            if not flow:
                flow_stats_present = False
                tx_frames = 0
                rx_frames = 0
            else:
                tx_frames = self._port_counter(flow.get("tx_pkts", {}), tx_port)
                rx_frames = self._port_counter(flow.get("rx_pkts", {}), rx_port)
            raw_tx = int(port_stats[tx_port].get("opackets", 0))
            raw_rx = int(port_stats[rx_port].get("ipackets", 0))
            counter_source = "flow-stats"
            unclassified_rx = max(0, raw_rx - classified_rx_by_port.get(rx_port, 0))
            marker_loss = max(0, tx_frames - rx_frames)
            port_counters_support_flow = (
                raw_tx == classified_tx_by_port.get(tx_port, 0)
                and raw_rx >= classified_rx_by_port.get(rx_port, 0)
                and rx_frames <= tx_frames
            )
            classified_tx = sum(
                self._port_counter(
                    (flow_stats.get(item.pg_id) or flow_stats.get(str(item.pg_id)) or {}).get(
                        "tx_pkts", {}
                    ),
                    item.tx_port,
                )
                for item in resolved_directions
                if item.rx_port == rx_port
            )
            marker_loss_supported_by_port = marker_loss == 0 or raw_rx < classified_tx
            flow_consistent = (
                bool(flow) and port_counters_support_flow and marker_loss_supported_by_port
            )
            if not flow_consistent:
                classification_reliable = False
                if allow_port_fallback:
                    tx_frames = raw_tx
                    rx_frames = raw_rx
                    counter_source = "exclusive-port-fallback"
            expected = self._expected_stream_frames(
                document,
                direction.packet,
                direction.rate,
                session.line_rates_bps[tx_port],
            )
            reached = tx_frames >= max(1, expected * 0.995)
            targets_reached = targets_reached and reached
            tx_total += tx_frames
            rx_total += rx_frames
            directions.append(
                {
                    "name": direction.name,
                    "txPort": tx_port,
                    "rxPort": rx_port,
                    "pgId": pg_id,
                    "expectedTxFrames": expected,
                    "txFrames": tx_frames,
                    "rxFrames": rx_frames,
                    "lossFrames": max(0, tx_frames - rx_frames),
                    "targetRateReached": reached,
                    "counterSource": counter_source,
                    "flowStatsConsistent": flow_consistent,
                    "unclassifiedRxFrames": unclassified_rx,
                    "portCountersSupportFlowStats": port_counters_support_flow,
                    "markerLossSupportedByPortCounters": marker_loss_supported_by_port,
                }
            )
        links_up = all(client.get_port(port).is_up() for port in session.ports)
        ownership_held = all(
            client.get_port(port).get_owner() == session.owner for port in session.ports
        )
        port_errors = sum(
            int(port_stats[port].get("ierrors", 0)) + int(port_stats[port].get("oerrors", 0))
            for port in session.ports
        )
        flow_errors = self._nested_counter_total(
            global_flow.get("rx_err", {})
        ) + self._nested_counter_total(global_flow.get("tx_err", {}))
        checks = {
            "ownershipHeld": ownership_held,
            "linksUp": links_up,
            "targetRateReached": targets_reached,
            "trexErrorsAbsent": not warnings and port_errors == 0 and flow_errors == 0,
            "flowStatsPresent": flow_stats_present or allow_port_fallback,
            "testFramesIsolated": classification_reliable or allow_port_fallback,
            "countersReset": session.baseline_clean,
            "receivePathHealthy": port_errors == 0,
        }
        valid = all(checks.values())
        return TrialObservation(
            valid=valid,
            loss_frames=max(0, tx_total - rx_total),
            tx_frames=tx_total,
            rx_frames=rx_total,
            target_rate_reached=targets_reached,
            details={
                "checks": checks,
                "directions": directions,
                "warnings": warnings,
                "portErrors": port_errors,
                "flowStatErrors": flow_errors,
                "portFallbackAllowed": allow_port_fallback,
            },
        )

    @staticmethod
    def _port_counter(values: Any, port: int) -> int:
        if not isinstance(values, dict):
            return 0
        value = values.get(port, values.get(str(port), 0))
        return 0 if value is None else int(value)

    @staticmethod
    def _nested_counter_total(values: Any) -> int:
        if isinstance(values, dict):
            return sum(
                RemoteTrexStlEngine._nested_counter_total(value) for value in values.values()
            )
        return int(values) if isinstance(values, (int, float)) else 0

    @staticmethod
    def _baseline_clean(client: Any, ports: list[int]) -> bool:
        stats = client.get_stats(ports=ports)
        return all(
            int(stats[port].get("opackets", 0)) == 0 and int(stats[port].get("ipackets", 0)) == 0
            for port in ports
        )

    @staticmethod
    def _rfc_trial_document(
        document: Rfc2544ThroughputDocument,
        frame_size: int,
        rate_percent: float,
        duration_seconds: float,
        direction: str | None = None,
    ) -> StatelessTrafficDocument:
        forward_packet = document.spec.packet.model_dump(
            mode="json", by_alias=True, exclude_none=True
        )
        forward_packet["frameSize"] = frame_size
        reverse_packet = (
            document.spec.reverse_packet.model_dump(mode="json", by_alias=True, exclude_none=True)
            if document.spec.reverse_packet is not None
            else None
        )
        if reverse_packet is not None:
            reverse_packet["frameSize"] = frame_size
        ports = document.spec.ports.model_dump(mode="json", by_alias=True)
        streams: list[dict[str, Any]] = []
        packet = forward_packet
        if direction == "forward":
            ports["direction"] = "unidirectional"
            streams = [
                {
                    "name": "forward",
                    "tx": ports["tx"],
                    "rx": ports["rx"],
                    "packet": forward_packet,
                    "rate": {"unit": "percent_l1", "value": rate_percent},
                }
            ]
        elif direction == "reverse":
            if reverse_packet is None:
                raise TrexCliError(
                    code="INVALID_DOCUMENT",
                    category="INPUT",
                    message="reverse RFC2544 direction requires reversePacket",
                )
            ports = {"tx": ports["rx"], "rx": ports["tx"], "direction": "unidirectional"}
            packet = reverse_packet
            streams = [
                {
                    "name": "reverse",
                    "tx": ports["tx"],
                    "rx": ports["rx"],
                    "packet": reverse_packet,
                    "rate": {"unit": "percent_l1", "value": rate_percent},
                }
            ]
        elif document.spec.direction_mode == "bidirectional-simultaneous":
            assert reverse_packet is not None
            streams = [
                {
                    "name": "forward",
                    "tx": ports["tx"],
                    "rx": ports["rx"],
                    "packet": forward_packet,
                    "rate": {"unit": "percent_l1", "value": rate_percent},
                },
                {
                    "name": "reverse",
                    "tx": ports["rx"],
                    "rx": ports["tx"],
                    "packet": reverse_packet,
                    "rate": {"unit": "percent_l1", "value": rate_percent},
                },
            ]
        return StatelessTrafficDocument.model_validate(
            {
                "apiVersion": document.api_version,
                "kind": "StatelessTraffic",
                "metadata": document.metadata.model_dump(
                    mode="json", by_alias=True, exclude_none=True
                ),
                "spec": {
                    "safety": document.spec.safety.model_dump(mode="json", by_alias=True),
                    "ports": ports,
                    "limits": document.spec.limits.model_dump(mode="json", by_alias=True),
                    "packet": packet,
                    "rate": {"unit": "percent_l1", "value": rate_percent},
                    "duration": max(1, round(duration_seconds * 1_000)),
                    "assertions": {"maxLossPercent": 0},
                    **({"streams": streams} if streams else {}),
                },
            }
        )

    def _stop_sync(self, session: _Session, force: bool) -> None:
        active = [port for port in session.ports if session.client.get_port(port).is_active()]
        if active:
            session.client.stop(ports=active)
        if force:
            session.client.reset(ports=session.ports)

    @staticmethod
    def _cleanup_sync(session: _Session) -> None:
        try:
            session.client.remove_all_streams(ports=session.ports)
        finally:
            try:
                session.client.release(ports=session.ports)
            finally:
                session.client.disconnect()

    def _streams(
        self,
        api: Any,
        document: StatelessTrafficDocument,
        pg_ids: list[int] | None = None,
        *,
        include_flow_stats: bool = True,
    ) -> list[Any]:
        resolved_pg_ids = pg_ids or [1, 2]
        forward, forward_vm = self._packet_plan(api, document, reverse=False)
        streams = [
            api.STLStream(
                packet=api.STLPktBuilder(pkt=forward, vm=forward_vm),
                mode=self._mode(api, document),
                flow_stats=(
                    api.STLFlowStats(pg_id=resolved_pg_ids[0]) if include_flow_stats else None
                ),
            )
        ]
        if document.spec.ports.direction == "bidirectional":
            reverse, reverse_vm = self._packet_plan(api, document, reverse=True)
            streams.append(
                api.STLStream(
                    packet=api.STLPktBuilder(pkt=reverse, vm=reverse_vm),
                    mode=self._mode(api, document),
                    flow_stats=(
                        api.STLFlowStats(pg_id=resolved_pg_ids[1]) if include_flow_stats else None
                    ),
                )
            )
        return streams

    @staticmethod
    def _pg_ids(
        ports: list[int], direction: str | None = None, *, count: int | None = None
    ) -> list[int]:
        first = 1 + min(ports) * 4096 + max(ports) * 2
        resolved_count = count if count is not None else (2 if direction == "bidirectional" else 1)
        return [first + index for index in range(resolved_count)]

    def _directions(
        self, document: StatelessTrafficDocument, pg_ids: list[int]
    ) -> list[_Direction]:
        if document.spec.streams:
            return [
                _Direction(
                    name=stream.name,
                    tx_port=self._config.port_mapping[stream.tx],
                    rx_port=self._config.port_mapping[stream.rx],
                    pg_id=pg_ids[index],
                    packet=stream.packet,
                    rate=stream.rate,
                )
                for index, stream in enumerate(document.spec.streams)
            ]
        forward = _Direction(
            name="forward",
            tx_port=self._config.port_mapping[document.spec.ports.tx],
            rx_port=self._config.port_mapping[document.spec.ports.rx],
            pg_id=pg_ids[0],
            packet=document.spec.packet,
            rate=document.spec.rate,
        )
        if document.spec.ports.direction == "unidirectional":
            return [forward]
        return [
            forward,
            _Direction(
                name="reverse",
                tx_port=forward.rx_port,
                rx_port=forward.tx_port,
                pg_id=pg_ids[1],
                packet=document.spec.packet,
                rate=document.spec.rate,
                reverse=True,
            ),
        ]

    def _install_streams(
        self,
        api: Any,
        client: Any,
        document: StatelessTrafficDocument,
        directions: list[_Direction],
        include_flow_stats: bool,
    ) -> None:
        for index, direction in enumerate(directions):
            packet, vm = self._packet_plan_for(
                api,
                direction.packet,
                reverse=direction.reverse,
                variable_prefix=f"stream_{index}",
            )
            stream = api.STLStream(
                packet=api.STLPktBuilder(pkt=packet, vm=vm),
                mode=self._mode_for(api, direction.rate, document.spec.burst_packets),
                flow_stats=(
                    api.STLFlowStats(pg_id=direction.pg_id) if include_flow_stats else None
                ),
            )
            client.add_streams(stream, ports=[direction.tx_port])

    def _packet_plan(
        self, api: Any, document: StatelessTrafficDocument, *, reverse: bool
    ) -> tuple[Any, list[Any]]:
        return self._packet_plan_for(
            api,
            document.spec.packet,
            reverse=reverse,
            variable_prefix="rev" if reverse else "fwd",
        )

    def _packet_plan_for(
        self,
        api: Any,
        packet: Packet,
        *,
        reverse: bool,
        variable_prefix: str,
    ) -> tuple[Any, list[Any]]:
        src_mac, dst_mac = packet.ethernet.src, packet.ethernet.dst
        if reverse:
            src_mac, dst_mac = dst_mac, src_mac
        built = api.Ether(
            src=self._initial_value(src_mac),
            dst=self._initial_value(dst_mac),
        )
        if packet.vlan:
            built /= api.Dot1Q(vlan=packet.vlan.id, prio=packet.vlan.priority)
        network = packet.ipv4 or packet.ipv6
        if network:
            src, dst = network.src, network.dst
            if reverse:
                src, dst = dst, src
            initial_src = self._initial_value(src)
            initial_dst = self._initial_value(dst)
            if packet.ipv4:
                built /= api.IP(src=initial_src, dst=initial_dst, ttl=packet.ipv4.ttl)
            else:
                assert packet.ipv6 is not None
                built /= api.IPv6(src=initial_src, dst=initial_dst, hlim=packet.ipv6.hop_limit)
        transport = packet.udp or packet.tcp
        if transport:
            src_port, dst_port = transport.src_port, transport.dst_port
            if reverse:
                src_port, dst_port = dst_port, src_port
            initial_src_port = self._initial_value(src_port)
            initial_dst_port = self._initial_value(dst_port)
            if packet.udp:
                built /= api.UDP(sport=initial_src_port, dport=initial_dst_port)
            else:
                assert packet.tcp is not None
                built /= api.TCP(
                    sport=initial_src_port,
                    dport=initial_dst_port,
                    flags=packet.tcp.flags,
                )
        elif packet.icmp:
            built /= api.ICMP(type=packet.icmp.type, code=packet.icmp.code)
        payload = bytes.fromhex(packet.payload_hex or "")
        target_without_fcs = packet.frame_size - 4
        padding = target_without_fcs - len(built) - len(payload)
        if padding < 0:
            raise TrexCliError(
                code="INVALID_DOCUMENT",
                category="INPUT",
                message="packet headers and payload exceed frameSize",
            )
        if payload or padding:
            built /= api.Raw(load=payload + bytes(padding))
        vm = self._variation_vm_for(api, packet, reverse=reverse, variable_prefix=variable_prefix)
        return built, vm

    def _variation_vm(
        self, api: Any, document: StatelessTrafficDocument, *, reverse: bool
    ) -> list[Any]:
        return self._variation_vm_for(
            api,
            document.spec.packet,
            reverse=reverse,
            variable_prefix="rev" if reverse else "fwd",
        )

    def _variation_vm_for(
        self,
        api: Any,
        packet: Packet,
        *,
        reverse: bool,
        variable_prefix: str,
    ) -> list[Any]:
        instructions: list[Any] = []
        has_network_variation = False
        has_transport_variation = False
        l3_offset = 14 + (4 if packet.vlan else 0)
        l4_offset = l3_offset + (20 if packet.ipv4 else 40)

        ethernet_values = {"src": packet.ethernet.src, "dst": packet.ethernet.dst}
        if reverse:
            ethernet_values = {"src": packet.ethernet.dst, "dst": packet.ethernet.src}
        for field, mac_value in ethernet_values.items():
            if not isinstance(mac_value, MacVariation):
                continue
            name = f"{variable_prefix}_ethernet_{field}"
            instructions.extend(
                self._flow_variable(
                    api,
                    name=name,
                    start=int(mac_value.start.replace(":", ""), 16) & 0xFFFFFFFF,
                    end=int(mac_value.end.replace(":", ""), 16) & 0xFFFFFFFF,
                    size=4,
                    mode=mac_value.mode.value,
                    offset=(6 if field == "src" else 0) + 2,
                )
            )

        if packet.ipv4 or packet.ipv6:
            network = packet.ipv4 or packet.ipv6
            assert network is not None
            network_values = {"src": network.src, "dst": network.dst}
            if reverse:
                network_values = {"src": network.dst, "dst": network.src}
            layer = "ip" if packet.ipv4 else "ipv6"
            for field, network_value in network_values.items():
                if not isinstance(network_value, StringVariation):
                    continue
                has_network_variation = True
                version = ipaddress.ip_address(network_value.start).version
                start = int(ipaddress.ip_address(network_value.start))
                end = int(ipaddress.ip_address(network_value.end))
                size = 4 if version == 4 else 8
                if version == 6:
                    start &= (1 << 64) - 1
                    end &= (1 << 64) - 1
                name = f"{variable_prefix}_{layer}_{field}"
                if packet.ipv4:
                    field_offset = l3_offset + (12 if field == "src" else 16)
                else:
                    field_offset = l3_offset + (16 if field == "src" else 32)
                instructions.extend(
                    self._flow_variable(
                        api,
                        name=name,
                        start=start,
                        end=end,
                        size=size,
                        mode=network_value.mode.value,
                        offset=field_offset,
                    )
                )

        transport = packet.udp or packet.tcp
        if transport:
            transport_values: dict[str, int | IntegerVariation] = {
                "sport": transport.src_port,
                "dport": transport.dst_port,
            }
            if reverse:
                transport_values = {
                    "sport": transport.dst_port,
                    "dport": transport.src_port,
                }
            layer = "udp" if packet.udp else "tcp"
            for field, transport_value in transport_values.items():
                if not isinstance(transport_value, IntegerVariation):
                    continue
                has_transport_variation = True
                name = f"{variable_prefix}_{layer}_{field}"
                instructions.extend(
                    self._flow_variable(
                        api,
                        name=name,
                        start=transport_value.start,
                        end=transport_value.end,
                        size=2,
                        mode=transport_value.mode.value,
                        offset=l4_offset + (0 if field == "sport" else 2),
                    )
                )

        if has_transport_variation or (has_network_variation and transport):
            assert transport is not None
            l4_type = (
                api.CTRexVmInsFixHwCs.L4_TYPE_UDP
                if packet.udp
                else api.CTRexVmInsFixHwCs.L4_TYPE_TCP
            )
            instructions.append(
                api.STLVmFixChecksumHw(
                    l3_offset=l3_offset,
                    l4_offset=l4_offset,
                    l4_type=l4_type,
                )
            )
        elif has_network_variation and packet.ipv4:
            instructions.append(api.STLVmFixIpv4(offset=l3_offset))
        return instructions

    @staticmethod
    def _flow_variable(
        api: Any,
        *,
        name: str,
        start: int,
        end: int,
        size: int,
        mode: str,
        offset: int,
        offset_fixup: int = 0,
        split_to_cores: bool = True,
    ) -> list[Any]:
        operation = {"increment": "inc", "decrement": "dec", "random": "random"}[mode]
        return [
            api.STLVmFlowVar(
                name=name,
                min_value=start,
                max_value=end,
                size=size,
                op=operation,
                split_to_cores=split_to_cores,
            ),
            api.STLVmWrFlowVar(
                fv_name=name,
                pkt_offset=offset,
                offset_fixup=offset_fixup,
                is_big=True,
            ),
        ]

    @staticmethod
    def _initial_value(value: Any) -> str | int:
        if isinstance(value, MacVariation):
            return value.end if value.mode.value == "decrement" else value.start
        if isinstance(value, StringVariation):
            return value.end if value.mode.value == "decrement" else value.start
        if isinstance(value, IntegerVariation):
            return value.end if value.mode.value == "decrement" else value.start
        assert isinstance(value, (str, int))
        return value

    @staticmethod
    def _mode(api: Any, document: StatelessTrafficDocument) -> Any:
        return RemoteTrexStlEngine._mode_for(api, document.spec.rate, document.spec.burst_packets)

    @staticmethod
    def _mode_for(api: Any, rate: Rate, burst_packets: int | None) -> Any:
        key = {
            "percent_l1": "percentage",
            "bps_l1": "bps_L1",
            "bps_l2": "bps_L2",
            "pps": "pps",
        }[rate.unit]
        arguments = {key: rate.value}
        if burst_packets is not None:
            return api.STLTXSingleBurst(total_pkts=burst_packets, **arguments)
        return api.STLTXCont(**arguments)

    @staticmethod
    def _expected_direction_frames(
        document: StatelessTrafficDocument, line_rate_bps: float
    ) -> float:
        return RemoteTrexStlEngine._expected_stream_frames(
            document,
            document.spec.packet,
            document.spec.rate,
            line_rate_bps,
        )

    @staticmethod
    def _expected_stream_frames(
        document: StatelessTrafficDocument,
        packet: Packet,
        rate: Rate,
        line_rate_bps: float,
    ) -> float:
        if document.spec.burst_packets is not None:
            return float(document.spec.burst_packets)
        seconds = (document.spec.duration or 0) / 1_000
        pps = RemoteTrexStlEngine._rate_pps_for(packet, rate, line_rate_bps)
        return pps * seconds

    @staticmethod
    def _rate_pps(
        document: StatelessTrafficDocument, line_rate_bps: float = 10_000_000_000
    ) -> float:
        return RemoteTrexStlEngine._rate_pps_for(
            document.spec.packet, document.spec.rate, line_rate_bps
        )

    @staticmethod
    def _rate_pps_for(packet: Packet, rate: Rate, line_rate_bps: float) -> float:
        if rate.unit == "pps":
            return rate.value
        if rate.unit == "bps_l2":
            return rate.value / (packet.frame_size * 8)
        if rate.unit == "bps_l1":
            return rate.value / ((packet.frame_size + 20) * 8)
        return rate.value / 100 * line_rate_bps / ((packet.frame_size + 20) * 8)

    @staticmethod
    def _estimated_run_seconds(document: StatelessTrafficDocument) -> float:
        if document.spec.duration is not None:
            return document.spec.duration / 1_000
        assert document.spec.burst_packets is not None
        return document.spec.burst_packets / RemoteTrexStlEngine._rate_pps(document)

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
        self._api = importlib.import_module("trex.stl.api")
        return self._api

    def _session(self, handle: RunHandle) -> _Session:
        try:
            return self._sessions[handle.id]
        except KeyError as error:
            raise TrexCliError(
                code="LEASE_LOST",
                category="ENGINE",
                message="the TRex run handle is no longer active",
            ) from error

    @staticmethod
    def _client_error(message: str, error: Exception) -> TrexCliError:
        cause = str(error)
        lowered = cause.lower()
        if "acquir" in lowered or "owned" in lowered:
            return TrexCliError(
                code="PORT_BUSY",
                category="RESOURCE",
                retryable=True,
                message=message,
                details={"cause": cause},
            )
        if "timeout" in lowered or "timed out" in lowered:
            return TrexCliError(
                code="TREX_TIMEOUT",
                category="ENGINE",
                retryable=True,
                message=message,
                details={"cause": cause},
            )
        return TrexCliError(
            code="TREX_UNAVAILABLE",
            category="ENGINE",
            retryable=True,
            message=message,
            details={"cause": cause},
        )
