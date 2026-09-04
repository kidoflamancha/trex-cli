from __future__ import annotations

import struct
from io import BytesIO
from pathlib import Path
from typing import Any, ClassVar

import pytest

from trex_cli.config import RemoteTrexEngineConfig, SafetyPolicy
from trex_cli.engine import ExecutionMarker
from trex_cli.errors import TrexCliError
from trex_cli.models import (
    PacketStormDocument,
    PcapReplayDocument,
    StatelessTrafficDocument,
    UdpWorkloadDocument,
    Verdict,
    utc_now,
)
from trex_cli.pcap_catalog import CaptureCatalog
from trex_cli.test_plan import TestPlanModule as PlanModule
from trex_cli.trex_adapter import RemoteTrexStlEngine

from .conftest import make_config, stateless_document, submit_body
from .test_test_control import _dns_workload_pcap, _write_resources


class FakePacket:
    def __init__(self, size: int) -> None:
        self.size = size

    def __truediv__(self, other: FakePacket) -> FakePacket:
        return FakePacket(self.size + other.size)

    def __len__(self) -> int:
        return self.size


class FakePort:
    def __init__(self) -> None:
        self.up = True
        self.active = False
        self.owner = ""

    def is_up(self) -> bool:
        return self.up

    def is_active(self) -> bool:
        return self.active

    def get_owner(self) -> str:
        return self.owner


class FakeClient:
    def __init__(
        self,
        *,
        acquire_error: Exception | None = None,
        flow_stats_available: bool = True,
        port_tx_frames: int = 1,
        port_rx_frames: int = 1,
        flow_tx_frames: int = 1,
        flow_rx_frames: int = 1,
        ieee1588_supported: bool = True,
    ) -> None:
        self.ports = [FakePort(), FakePort()]
        self.acquire_error = acquire_error
        self.calls: list[tuple[str, Any]] = []
        self.username = "fake"
        self.streams: list[Any] = []
        self.flow_stats_available = flow_stats_available
        self.port_tx_frames = port_tx_frames
        self.port_rx_frames = port_rx_frames
        self.flow_tx_frames = flow_tx_frames
        self.flow_rx_frames = flow_rx_frames
        self.ieee1588_supported = ieee1588_supported
        self.traffic_completed = False

    def connect(self) -> None:
        self.calls.append(("connect", None))

    def disconnect(self) -> None:
        self.calls.append(("disconnect", None))

    def get_port_count(self) -> int:
        return len(self.ports)

    def get_port(self, port: int) -> FakePort:
        return self.ports[port]

    def get_server_version(self) -> dict[str, str]:
        return {"Version": "v3.08-fake"}

    def get_port_info(self, *, ports: list[int]) -> list[dict[str, Any]]:
        return [
            {
                "speed": 10.0,
                "is_ieee1588_supported": ("yes" if self.ieee1588_supported else "no"),
                "driver": "fake-driver",
                "description": "fake-nic",
            }
            for _ in ports
        ]

    def acquire(self, *, ports: list[int], force: bool) -> None:
        self.calls.append(("acquire", (ports, force)))
        if self.acquire_error:
            raise self.acquire_error
        for port in ports:
            self.ports[port].owner = self.username

    def reset(self, *, ports: list[int]) -> None:
        self.calls.append(("reset", ports))
        for port in ports:
            self.ports[port].active = False

    def add_streams(self, stream: Any, *, ports: list[int]) -> None:
        self.calls.append(("add_streams", ports))
        self.streams.append(stream)

    def clear_stats(self, *, ports: list[int]) -> None:
        self.calls.append(("clear_stats", ports))
        self.traffic_completed = False

    def start(self, *, ports: list[int], mult: str = "1", duration: float = -1) -> None:
        self.calls.append(("start", (ports, mult, duration)))
        for port in ports:
            self.ports[port].active = True

    def push_remote(self, path: str, *, ports: list[int], **values: Any) -> None:
        self.calls.append(("push_remote", {"path": path, "ports": ports, **values}))
        for port in ports:
            self.ports[port].active = True

    def wait_on_traffic(
        self, *, ports: list[int], timeout: float, rx_delay_ms: int | None = None
    ) -> None:
        self.calls.append(("wait_on_traffic", (ports, timeout, rx_delay_ms)))
        for port in ports:
            self.ports[port].active = False
        self.traffic_completed = True

    def get_stats(self, *, ports: list[int]) -> dict[int, dict[str, int]]:
        tx_count = self.port_tx_frames if self.traffic_completed else 0
        rx_count = self.port_rx_frames if self.traffic_completed else 0
        return {
            0: {"opackets": tx_count, "ipackets": 0, "ierrors": 0, "oerrors": 0},
            1: {"opackets": 0, "ipackets": rx_count, "ierrors": 0, "oerrors": 0},
        }

    def get_pgid_stats(self, pg_ids: list[int]) -> dict[str, Any]:
        if not self.flow_stats_available:
            return {"flow_stats": {}}
        return {
            "flow_stats": {
                pg_id: {
                    "tx_pkts": {
                        0 if index % 2 == 0 else 1: self.flow_tx_frames,
                    },
                    "rx_pkts": {
                        1 if index % 2 == 0 else 0: self.flow_rx_frames,
                    },
                }
                for index, pg_id in enumerate(pg_ids)
            }
        }

    def get_warnings(self) -> list[str]:
        return []

    def stop(self, *, ports: list[int]) -> None:
        self.calls.append(("stop", ports))
        for port in ports:
            self.ports[port].active = False

    def remove_all_streams(self, *, ports: list[int]) -> None:
        self.calls.append(("remove_all_streams", ports))

    def release(self, *, ports: list[int]) -> None:
        self.calls.append(("release", ports))
        for port in ports:
            self.ports[port].owner = ""


class FakeApi:
    STLClient = FakeClient
    ether_values: ClassVar[list[dict[str, Any]]] = []
    udp_values: ClassVar[list[dict[str, Any]]] = []
    raw_values: ClassVar[list[bytes]] = []
    ip_values: ClassVar[list[dict[str, Any]]] = []
    arp_values: ClassVar[list[dict[str, Any]]] = []

    @classmethod
    def Ether(cls, **values: Any) -> FakePacket:
        cls.ether_values.append(values)
        return FakePacket(14)

    @staticmethod
    def Dot1Q(**_: Any) -> FakePacket:
        return FakePacket(4)

    @classmethod
    def IP(cls, **values: Any) -> FakePacket:
        cls.ip_values.append(values)
        return FakePacket(20)

    @classmethod
    def ARP(cls, **values: Any) -> FakePacket:
        cls.arp_values.append(values)
        return FakePacket(28)

    @staticmethod
    def IPv6(**_: Any) -> FakePacket:
        return FakePacket(40)

    @classmethod
    def UDP(cls, **values: Any) -> FakePacket:
        cls.udp_values.append(values)
        return FakePacket(8)

    @staticmethod
    def TCP(**_: Any) -> FakePacket:
        return FakePacket(20)

    @staticmethod
    def ICMP(**_: Any) -> FakePacket:
        return FakePacket(8)

    @classmethod
    def Raw(cls, *, load: bytes) -> FakePacket:
        cls.raw_values.append(load)
        return FakePacket(len(load))

    @staticmethod
    def STLPktBuilder(*, pkt: FakePacket, vm: list[Any]) -> dict[str, Any]:
        return {"packet": pkt, "vm": vm}

    @staticmethod
    def STLTXCont(**values: Any) -> dict[str, Any]:
        return values

    @staticmethod
    def STLTXSingleBurst(**values: Any) -> dict[str, Any]:
        return values

    @staticmethod
    def STLStream(
        *, packet: Any, mode: Any, flow_stats: Any | None = None, isg: float | None = None
    ) -> dict[str, Any]:
        return {"packet": packet, "mode": mode, "flow_stats": flow_stats, "isg": isg}

    @staticmethod
    def STLFlowStats(*, pg_id: int) -> dict[str, int]:
        return {"pg_id": pg_id}

    @staticmethod
    def STLFlowLatencyStats(*, pg_id: int, ieee_1588: bool) -> dict[str, Any]:
        return {"pg_id": pg_id, "ieee_1588": ieee_1588, "latency": True}

    @staticmethod
    def STLVmFlowVar(**values: Any) -> tuple[str, dict[str, Any]]:
        return "flow-var", values

    @staticmethod
    def STLVmWrFlowVar(**values: Any) -> tuple[str, dict[str, Any]]:
        return "write-var", values

    @staticmethod
    def STLVmFixIpv4(**values: Any) -> tuple[str, dict[str, Any]]:
        return "fix-ipv4", values

    @staticmethod
    def STLVmFixChecksumHw(**values: Any) -> tuple[str, dict[str, Any]]:
        return "fix-checksum-hw", values

    class CTRexVmInsFixHwCs:
        L4_TYPE_UDP = 11
        L4_TYPE_TCP = 13

    class STLProfile:
        loaded: ClassVar[list[dict[str, Any]]] = []

        def __init__(self, path: str) -> None:
            self.path = path

        @classmethod
        def load_pcap(cls, path: str, **values: Any) -> FakeApi.STLProfile:
            cls.loaded.append({"path": path, **values})
            return cls(path)

        def get_streams(self) -> list[dict[str, str]]:
            return [{"compiledPcap": self.path}]


def remote_config(tmp_path: Path) -> RemoteTrexEngineConfig:
    return RemoteTrexEngineConfig.model_validate(
        {
            "mode": "remote-trex",
            "server": "127.0.0.1",
            "clientPath": str(tmp_path),
            "externalLibsPath": str(tmp_path),
            "portMapping": {"lab-west": 0, "lab-east": 1},
        }
    )


def udp_workload_document(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> UdpWorkloadDocument:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    plans = PlanModule(
        profile_root,
        path_root,
        plan_root,
        tmp_path / "captures",
        config.safety,
    )
    plans.publish_capture(
        name="regression/dns-workload",
        source=BytesIO(_dns_workload_pcap()),
    )
    return plans.plan_udp_workload(
        capture_name="regression/dns-workload",
        path_name="cc-switch",
        initiator_role="client",
        responder_role="server",
        fps=30,
        duration="1s",
    ).document


def dns_storm_document(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> PacketStormDocument:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    return PlanModule(
        profile_root,
        path_root,
        plan_root,
        tmp_path / "captures",
        config.safety,
    ).plan_dns_storm(
        path_name="cc-switch",
        client_role="client",
        server_role="server",
        name="www.example.test",
        query_type="A",
        recursion_desired=True,
        source_port_start=40000,
        source_port_end=40003,
        pps=100,
        duration="3s",
    ).document


def dhcp_storm_document(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> PacketStormDocument:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    config.safety.allow_broadcast_storms = True
    return (
        PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        )
        .plan_dhcp_storm(
            path_name="cc-switch",
            client_role="client",
            server_role="server",
            clients=4,
            pps=100,
            duration="3s",
        )
        .document
    )


def arp_storm_document(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> PacketStormDocument:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    config.safety.allow_broadcast_storms = True
    return (
        PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        )
        .plan_arp_storm(
            path_name="cc-switch",
            sender_role="client",
            target_role="server",
            senders=4,
            pps=100,
            duration="3s",
        )
        .document
    )


def one_packet_document() -> StatelessTrafficDocument:
    raw = stateless_document()
    raw["spec"]["rate"] = {"unit": "pps", "value": 1}
    raw["spec"]["duration"] = "1s"
    document = submit_body(raw).document
    assert isinstance(document, StatelessTrafficDocument)
    return document


def execution_marker() -> ExecutionMarker:
    return ExecutionMarker(
        marker_id="marker_TEST",
        job_id="job_TEST",
        session_id="0123456789abcdef0123456789abcdef",
        logical_ports=("lab-west", "lab-east"),
        fence={"lab-west": 1, "lab-east": 1},
        hard_deadline=utc_now(),
    )


def replay_document(capture_root: Path) -> PcapReplayDocument:
    ethernet = bytes.fromhex(
        "00000000000200000000000108004500001c0000000040110000c6120001c6130001c000000700080000"
    )
    pcap = (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
        + struct.pack("<IIII", 1, 0, len(ethernet), len(ethernet))
        + ethernet
        + struct.pack("<IIII", 1, 1000, len(ethernet), len(ethernet))
        + ethernet
    )
    capture = CaptureCatalog(capture_root).publish(name="regression/replay", source=BytesIO(pcap))
    analysis = capture.document.analysis
    return PcapReplayDocument.model_validate(
        {
            "apiVersion": "trex.example.io/v1",
            "kind": "PcapReplay",
            "spec": {
                "safety": {"isolatedLab": True},
                "ports": {"tx": "lab-west", "rx": "lab-east"},
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
                "address": {
                    "mode": "rewrite",
                    "sourceRole": "client",
                    "destinationRole": "server",
                    "sourceMac": "00:00:00:00:00:01",
                    "destinationMac": "00:00:00:00:00:02",
                    "sourceIpv4": "198.18.0.1",
                    "destinationIpv4": "198.19.0.1",
                },
                "timing": {"mode": "capture"},
            },
        }
    )


@pytest.mark.asyncio
async def test_remote_engine_compiles_loads_and_measures_pcap_replay(tmp_path: Path) -> None:
    capture_root = tmp_path / "captures"
    document = replay_document(capture_root)
    client = FakeClient(port_tx_frames=2, port_rx_frames=2)
    engine = RemoteTrexStlEngine(
        remote_config(tmp_path),
        capture_root=capture_root,
        client_factory=lambda **_: client,
        client_api=FakeApi,
    )

    handle = await engine.prepare(execution_marker(), document)
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    assert measurement.methodology == "trex-stl-pcap-replay/v1"
    assert measurement.summary["txFrames"] == 2
    assert measurement.summary["rxFrames"] == 2
    assert measurement.summary["lossFrames"] == 0
    assert measurement.summary["surplusRxFrames"] == 0
    assert measurement.summary["observationValid"] is True
    loaded = FakeApi.STLProfile.loaded[-1]
    assert loaded["src_mac_pcap"] is True
    assert loaded["dst_mac_pcap"] is True
    assert Path(loaded["path"]).is_file()  # noqa: ASYNC240
    assert [values for name, values in client.calls if name == "add_streams"] == [[0]]


@pytest.mark.asyncio
async def test_remote_engine_runs_weighted_bidirectional_datagram_templates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    FakeApi.ether_values.clear()
    document = udp_workload_document(tmp_path, monkeypatch)
    client = FakeClient(
        port_tx_frames=10,
        port_rx_frames=10,
        flow_tx_frames=5,
        flow_rx_frames=5,
    )
    engine = RemoteTrexStlEngine(
        remote_config(tmp_path),
        policy=make_config(tmp_path, monkeypatch).safety,
        capture_root=tmp_path / "captures",
        client_factory=lambda **_: client,
        client_api=FakeApi,
    )

    handle = await engine.prepare(execution_marker(), document)
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    assert len(client.streams) == 4
    assert sorted(stream["mode"]["pps"] for stream in client.streams) == [10, 10, 20, 20]
    assert sorted(stream["isg"] for stream in client.streams) == [0, 0, 2000, 2000]
    assert [values for name, values in client.calls if name == "add_streams"].count([0]) == 2
    assert [values for name, values in client.calls if name == "add_streams"].count([1]) == 2
    assert {values["src"] for values in FakeApi.ether_values} == {
        "00:00:00:00:00:01",
        "00:00:00:00:00:02",
    }
    assert measurement.methodology == "trex-stl-datagram-workload/v1"
    assert measurement.summary["txDatagrams"] == 20
    assert measurement.summary["rxDatagrams"] == 20
    assert measurement.summary["directions"]["initiator-to-responder"]["txDatagrams"] == 10
    assert measurement.summary["directions"]["responder-to-initiator"]["txDatagrams"] == 10
    assert all(item["flowInstances"] == 5 for item in measurement.summary["templates"])


@pytest.mark.asyncio
async def test_remote_engine_generates_and_measures_a_dns_query_storm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    FakeApi.udp_values.clear()
    FakeApi.raw_values.clear()
    document = dns_storm_document(tmp_path, monkeypatch)
    client = FakeClient(
        port_tx_frames=300,
        port_rx_frames=300,
        flow_tx_frames=300,
        flow_rx_frames=300,
    )

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        return client

    engine = RemoteTrexStlEngine(
        remote_config(tmp_path),
        policy=make_config(tmp_path, monkeypatch).safety,
        client_factory=factory,
        client_api=FakeApi,
    )

    handle = await engine.prepare(execution_marker(), document)
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    query_streams = [stream for stream in client.streams if stream["mode"].get("pps") == 100]
    assert len(query_streams) == 2
    query_stream = query_streams[-1]
    assert len(query_stream["packet"]["packet"]) == 76
    flow_variables = [
        values
        for kind, values in query_stream["packet"]["vm"]
        if kind == "flow-var"
    ]
    assert {(item["min_value"], item["max_value"], item["size"]) for item in flow_variables} == {
        (40000, 40003, 2),
        (0, 65_535, 2),
    }
    assert FakeApi.udp_values[-1] == {"sport": 40000, "dport": 53}
    assert FakeApi.raw_values[-1][:4] == b"\x00\x00\x01\x00"
    assert measurement.methodology == "trex-stl-dns-query-storm/v1"
    assert measurement.summary["queriesTx"] == 300
    assert measurement.summary["queriesRx"] == 300
    assert measurement.summary["lostQueries"] == 0
    assert measurement.summary["observationValid"] is True
    assert measurement.summary["responseObservation"] == "unavailable"


@pytest.mark.asyncio
async def test_remote_engine_generates_and_measures_a_dhcp_discover_storm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    FakeApi.ether_values.clear()
    FakeApi.ip_values.clear()
    FakeApi.udp_values.clear()
    FakeApi.raw_values.clear()
    document = dhcp_storm_document(tmp_path, monkeypatch)
    client = FakeClient(
        port_tx_frames=300,
        port_rx_frames=300,
        flow_tx_frames=300,
        flow_rx_frames=300,
    )
    policy = make_config(tmp_path, monkeypatch).safety
    policy.allow_broadcast_storms = True

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        return client

    engine = RemoteTrexStlEngine(
        remote_config(tmp_path),
        policy=policy,
        client_factory=factory,
        client_api=FakeApi,
    )

    handle = await engine.prepare(execution_marker(), document)
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    storm_streams = [stream for stream in client.streams if stream["mode"].get("pps") == 100]
    assert len(storm_streams) == 1
    stream = storm_streams[0]
    assert len(stream["packet"]["packet"]) == 286
    flow_variables = [values for kind, values in stream["packet"]["vm"] if kind == "flow-var"]
    assert {(item["min_value"], item["max_value"], item["size"]) for item in flow_variables} == {
        (1, 4, 4),
        (0, 0xFFFF_FFFF, 4),
    }
    writes = [values for kind, values in stream["packet"]["vm"] if kind == "write-var"]
    assert {item["pkt_offset"] for item in writes} == {8, 46, 72}
    assert FakeApi.ether_values[-1] == {
        "src": "00:00:00:00:00:01",
        "dst": "ff:ff:ff:ff:ff:ff",
    }
    assert FakeApi.ip_values[-1]["src"] == "0.0.0.0"
    assert FakeApi.ip_values[-1]["dst"] == "255.255.255.255"
    assert FakeApi.udp_values[-1] == {"sport": 68, "dport": 67}
    assert FakeApi.raw_values[-1][0:4] == b"\x01\x01\x06\x00"
    assert FakeApi.raw_values[-1][236:] == b"\x63\x82\x53\x63\x35\x01\x01\xff"
    assert measurement.methodology == "trex-stl-dhcp-discover-storm/v1"
    assert measurement.summary["discoversTx"] == 300
    assert measurement.summary["discoversRx"] == 300
    assert measurement.summary["lostDiscovers"] == 0
    assert measurement.summary["observationValid"] is True, measurement.summary["validity"]
    assert measurement.summary["offerObservation"] == "unavailable"


@pytest.mark.asyncio
async def test_remote_engine_generates_arp_requests_with_transmission_only_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    FakeApi.ether_values.clear()
    FakeApi.arp_values.clear()
    FakeApi.raw_values.clear()
    document = arp_storm_document(tmp_path, monkeypatch)
    client = FakeClient(port_tx_frames=300, port_rx_frames=300)
    policy = make_config(tmp_path, monkeypatch).safety
    policy.allow_broadcast_storms = True

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        return client

    engine = RemoteTrexStlEngine(
        remote_config(tmp_path),
        policy=policy,
        client_factory=factory,
        client_api=FakeApi,
    )

    handle = await engine.prepare(execution_marker(), document)
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    stream = next(stream for stream in client.streams if stream["mode"].get("pps") == 100)
    assert len(stream["packet"]["packet"]) == 60
    assert stream["flow_stats"] is None
    flow_variables = [values for kind, values in stream["packet"]["vm"] if kind == "flow-var"]
    assert {(item["min_value"], item["max_value"], item["size"]) for item in flow_variables} == {
        (1, 4, 4),
        (int.from_bytes(bytes([198, 18, 0, 1])), int.from_bytes(bytes([198, 18, 0, 4])), 4),
    }
    writes = [values for kind, values in stream["packet"]["vm"] if kind == "write-var"]
    assert {item["pkt_offset"] for item in writes} == {8, 24, 28}
    assert FakeApi.ether_values[-1] == {
        "src": "00:00:00:00:00:01",
        "dst": "ff:ff:ff:ff:ff:ff",
    }
    assert FakeApi.arp_values[-1]["op"] == 1
    assert FakeApi.arp_values[-1]["psrc"] == "198.18.0.1"
    assert FakeApi.arp_values[-1]["pdst"] == "198.19.0.1"
    assert measurement.methodology == "trex-stl-arp-request-storm/v1"
    assert measurement.summary["requestsTx"] == 300
    assert measurement.summary["transmissionValid"] is True
    assert measurement.summary["requestDeliveryObservation"] == "unavailable"
    assert "requestsRx" not in measurement.summary


@pytest.mark.asyncio
async def test_remote_engine_uses_server_visible_root_for_large_pcap_replay(
    tmp_path: Path,
) -> None:
    capture_root = tmp_path / "captures"
    document = replay_document(capture_root)
    client = FakeClient(port_tx_frames=2, port_rx_frames=5)
    config = remote_config(tmp_path)
    config.pcap_remote_root = Path("/srv/trex-captures")
    engine = RemoteTrexStlEngine(
        config,
        capture_root=capture_root,
        client_factory=lambda **_: client,
        client_api=FakeApi,
    )

    handle = await engine.prepare(execution_marker(), document)
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    assert measurement.summary["txFrames"] == 2
    assert measurement.summary["observationValid"] is False
    assert measurement.summary["surplusRxFrames"] == 3
    assert measurement.summary["lossFrames"] is None
    pushed = [values for name, values in client.calls if name == "push_remote"]
    assert len(pushed) == 1
    assert pushed[0]["path"].startswith("/srv/trex-captures/")
    assert pushed[0]["src_mac_pcap"] is True
    assert pushed[0]["dst_mac_pcap"] is True
    assert not [values for name, values in client.calls if name == "add_streams"]


@pytest.mark.asyncio
async def test_remote_engine_contract_runs_and_releases_ports(tmp_path: Path) -> None:
    client = FakeClient()

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        return client

    engine = RemoteTrexStlEngine(
        remote_config(tmp_path), client_factory=factory, client_api=FakeApi
    )

    status = await engine.probe()
    assert status.available is True
    assert status.details["links"] == {"0": "up", "1": "up"}
    assert status.details["portSpeedsGbps"] == {"0": 10.0, "1": 10.0}
    assert status.details["portCapabilities"] == {
        "0": {
            "ieee1588": True,
            "driver": "fake-driver",
            "description": "fake-nic",
        },
        "1": {
            "ieee1588": True,
            "driver": "fake-driver",
            "description": "fake-nic",
        },
    }

    handle = await engine.prepare(execution_marker(), one_packet_document())
    await engine.warmup(handle)
    measurement = await engine.run(handle)
    await engine.stop(handle)
    await engine.cleanup(handle)

    assert measurement.verdict == Verdict.PASS
    assert measurement.summary["txFrames"] == 1
    assert measurement.summary["rxFrames"] == 1
    names = [name for name, _ in client.calls]
    assert names.count("acquire") == 1
    assert names.count("release") == 1
    assert [values[0] for name, values in client.calls if name == "start"] == [[1], [0]]
    assert names[-1] == "disconnect"


@pytest.mark.asyncio
async def test_remote_engine_installs_each_resolved_weighted_stream(tmp_path: Path) -> None:
    raw = stateless_document()
    raw["spec"]["rate"] = {"unit": "pps", "value": 1000}
    raw["spec"]["duration"] = "1s"
    first_packet = raw["spec"]["packet"]
    first_packet["frameSize"] = 64
    second_packet = {**first_packet, "frameSize": 512}
    raw["spec"]["streams"] = [
        {
            "name": "web/64",
            "tx": "lab-west",
            "rx": "lab-east",
            "packet": first_packet,
            "rate": {"unit": "pps", "value": 600},
        },
        {
            "name": "web/512",
            "tx": "lab-west",
            "rx": "lab-east",
            "packet": second_packet,
            "rate": {"unit": "pps", "value": 400},
        },
    ]
    document = submit_body(raw).document
    assert isinstance(document, StatelessTrafficDocument)
    client = FakeClient()
    engine = RemoteTrexStlEngine(
        remote_config(tmp_path), client_factory=lambda **_: client, client_api=FakeApi
    )

    handle = await engine.prepare(execution_marker(), document)
    await engine.cleanup(handle)

    installed = client.streams[:2]
    assert [stream["mode"]["pps"] for stream in installed] == [600, 400]
    assert [len(stream["packet"]["packet"]) for stream in installed] == [60, 508]
    assert [values for name, values in client.calls if name == "add_streams"] == [[0], [0]]


@pytest.mark.asyncio
async def test_remote_engine_runs_weighted_streams_with_per_stream_evidence(tmp_path: Path) -> None:
    class WeightedClient(FakeClient):
        def get_stats(self, *, ports: list[int]) -> dict[int, dict[str, int]]:
            total = 1000 if self.traffic_completed else 0
            return {
                0: {"opackets": total, "ipackets": 0, "ierrors": 0, "oerrors": 0},
                1: {"opackets": 0, "ipackets": total, "ierrors": 0, "oerrors": 0},
            }

        def get_pgid_stats(self, pg_ids: list[int]) -> dict[str, Any]:
            counts = [600, 400]
            return {
                "flow_stats": {
                    pg_id: {
                        "tx_pkts": {0: counts[index]},
                        "rx_pkts": {1: counts[index]},
                    }
                    for index, pg_id in enumerate(pg_ids)
                }
            }

    raw = stateless_document()
    raw["spec"]["rate"] = {"unit": "pps", "value": 1000}
    raw["spec"]["duration"] = "1s"
    packet_64 = {**raw["spec"]["packet"], "frameSize": 64}
    packet_512 = {**raw["spec"]["packet"], "frameSize": 512}
    raw["spec"]["streams"] = [
        {
            "name": "web/64",
            "tx": "lab-west",
            "rx": "lab-east",
            "packet": packet_64,
            "rate": {"unit": "pps", "value": 600},
        },
        {
            "name": "web/512",
            "tx": "lab-west",
            "rx": "lab-east",
            "packet": packet_512,
            "rate": {"unit": "pps", "value": 400},
        },
    ]
    document = submit_body(raw).document
    assert isinstance(document, StatelessTrafficDocument)
    client = WeightedClient()

    def factory(**values: Any) -> WeightedClient:
        client.username = values["username"]
        return client

    engine = RemoteTrexStlEngine(
        remote_config(tmp_path), client_factory=factory, client_api=FakeApi
    )

    handle = await engine.prepare(execution_marker(), document)
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    assert measurement.verdict == Verdict.PASS
    assert measurement.summary["txFrames"] == 1000
    assert measurement.summary["rxFrames"] == 1000
    directions = measurement.summary["validity"]["directions"]
    assert [(item["name"], item["txFrames"]) for item in directions] == [
        ("web/64", 600),
        ("web/512", 400),
    ]
    assert [item["unclassifiedRxFrames"] for item in directions] == [0, 0]


@pytest.mark.asyncio
async def test_remote_engine_maps_port_ownership_error(tmp_path: Path) -> None:
    client = FakeClient(acquire_error=RuntimeError("port already acquired by another user"))
    engine = RemoteTrexStlEngine(
        remote_config(tmp_path), client_factory=lambda **_: client, client_api=FakeApi
    )

    with pytest.raises(TrexCliError) as raised:
        await engine.prepare(execution_marker(), one_packet_document())

    assert raised.value.code == "PORT_BUSY"
    assert raised.value.retryable is True
    assert client.calls[-1][0] == "disconnect"


@pytest.mark.asyncio
async def test_remote_engine_rejects_burst_longer_than_job_timeout(tmp_path: Path) -> None:
    raw = stateless_document()
    raw["spec"].pop("duration")
    raw["spec"]["burstPackets"] = 100
    raw["spec"]["rate"] = {"unit": "pps", "value": 1}
    raw["spec"]["limits"] = {"jobTimeout": "60s", "portWaitTimeout": "30s"}
    document = submit_body(raw).document
    engine = RemoteTrexStlEngine(remote_config(tmp_path), client_api=FakeApi)

    with pytest.raises(TrexCliError) as raised:
        await engine.validate(document)

    assert raised.value.code == "UNSAFE_REQUEST"
    assert raised.value.details["estimatedDurationSeconds"] == 100


@pytest.mark.asyncio
async def test_remote_probe_reports_unavailable_without_raising(tmp_path: Path) -> None:
    class UnavailableClient(FakeClient):
        def connect(self) -> None:
            raise RuntimeError("connection timed out")

    engine = RemoteTrexStlEngine(
        remote_config(tmp_path),
        client_factory=lambda **_: UnavailableClient(),
        client_api=FakeApi,
    )

    status = await engine.probe()

    assert status.available is False
    assert "timed out" in status.details["error"]


@pytest.mark.asyncio
async def test_reconcile_stops_only_matching_owner(tmp_path: Path) -> None:
    client = FakeClient()

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        for port in client.ports:
            port.owner = client.username
            port.active = True
        return client

    engine = RemoteTrexStlEngine(
        remote_config(tmp_path), client_factory=factory, client_api=FakeApi
    )

    result = await engine.reconcile(execution_marker(), one_packet_document())

    assert result.confirmed_idle is True
    names = [name for name, _ in client.calls]
    assert "stop" in names
    assert "reset" in names
    assert "release" in names


@pytest.mark.asyncio
async def test_reconcile_refuses_foreign_owner(tmp_path: Path) -> None:
    client = FakeClient()

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        for port in client.ports:
            port.owner = "another-controller"
            port.active = True
        return client

    engine = RemoteTrexStlEngine(
        remote_config(tmp_path), client_factory=factory, client_api=FakeApi
    )

    result = await engine.reconcile(execution_marker(), one_packet_document())

    assert result.confirmed_idle is False
    assert result.details["reason"] == "owner-mismatch"
    assert "acquire" not in [name for name, _ in client.calls]


@pytest.mark.asyncio
async def test_remote_engine_compiles_ipv4_and_udp_variations(tmp_path: Path) -> None:
    raw = stateless_document()
    raw["spec"]["rate"] = {"unit": "pps", "value": 1}
    raw["spec"]["duration"] = "1s"
    raw["spec"]["packet"]["ipv4"]["src"] = {
        "start": "198.18.0.1",
        "end": "198.18.0.4",
        "mode": "increment",
    }
    raw["spec"]["packet"]["udp"]["srcPort"] = {
        "start": 49152,
        "end": 49155,
        "mode": "random",
    }
    document = submit_body(raw).document
    client = FakeClient()
    engine = RemoteTrexStlEngine(
        remote_config(tmp_path), client_factory=lambda **_: client, client_api=FakeApi
    )

    handle = await engine.prepare(execution_marker(), document)
    await engine.cleanup(handle)

    vm = client.streams[0]["packet"]["vm"]
    kinds = [instruction[0] for instruction in vm]
    assert kinds == [
        "flow-var",
        "write-var",
        "flow-var",
        "write-var",
        "fix-checksum-hw",
    ]
    assert vm[0][1]["size"] == 4
    assert vm[0][1]["op"] == "inc"
    assert vm[2][1]["size"] == 2
    assert vm[2][1]["op"] == "random"


@pytest.mark.asyncio
async def test_remote_engine_compiles_bidirectional_mac_variations(tmp_path: Path) -> None:
    raw = stateless_document()
    raw["spec"]["ports"]["direction"] = "bidirectional"
    raw["spec"]["packet"]["ethernet"]["src"] = {
        "start": "00:00:00:00:00:01",
        "end": "00:00:00:00:00:04",
        "mode": "increment",
    }
    document = submit_body(raw).document
    client = FakeClient()
    engine = RemoteTrexStlEngine(
        remote_config(tmp_path), client_factory=lambda **_: client, client_api=FakeApi
    )
    FakeApi.ether_values.clear()

    handle = await engine.prepare(execution_marker(), document)
    await engine.cleanup(handle)

    forward_vm = client.streams[0]["packet"]["vm"]
    reverse_vm = client.streams[1]["packet"]["vm"]
    forward_mac = forward_vm[:2]
    reverse_mac = reverse_vm[:2]
    assert forward_mac[0][1]["size"] == 4
    assert forward_mac[0][1]["min_value"] == 1
    assert forward_mac[0][1]["max_value"] == 4
    assert forward_mac[1][1]["pkt_offset"] == 8
    assert reverse_mac[1][1]["pkt_offset"] == 2
    assert FakeApi.ether_values == [
        {"src": "00:00:00:00:00:01", "dst": "00:00:00:00:00:02"},
        {"src": "00:00:00:00:00:02", "dst": "00:00:00:00:00:01"},
    ]


@pytest.mark.asyncio
async def test_remote_engine_rejects_ipv6_variation_across_64_bit_prefix(
    tmp_path: Path,
) -> None:
    raw = stateless_document()
    raw["spec"]["packet"].pop("ipv4")
    raw["spec"]["packet"]["ipv6"] = {
        "src": {
            "start": "2001:db8:1::1",
            "end": "2001:db8:2::1",
            "mode": "increment",
        },
        "dst": "2001:db8:3::1",
    }
    document = submit_body(raw).document
    engine = RemoteTrexStlEngine(remote_config(tmp_path), client_api=FakeApi)

    with pytest.raises(TrexCliError) as raised:
        await engine.validate(document)

    assert raised.value.code == "CAPABILITY_MISMATCH"
    assert "64-bit prefix" in raised.value.message


@pytest.mark.asyncio
async def test_bidirectional_variations_are_written_to_reverse_destination_fields(
    tmp_path: Path,
) -> None:
    raw = stateless_document()
    raw["spec"]["ports"]["direction"] = "bidirectional"
    raw["spec"]["packet"]["ipv4"]["src"] = {
        "start": "198.18.0.1",
        "end": "198.18.0.4",
        "mode": "increment",
    }
    raw["spec"]["packet"]["udp"]["srcPort"] = {
        "start": 49152,
        "end": 49155,
        "mode": "increment",
    }
    document = submit_body(raw).document
    client = FakeClient()
    engine = RemoteTrexStlEngine(
        remote_config(tmp_path), client_factory=lambda **_: client, client_api=FakeApi
    )

    handle = await engine.prepare(execution_marker(), document)
    await engine.cleanup(handle)

    assert len(client.streams) == 2
    forward_vm = client.streams[0]["packet"]["vm"]
    reverse_vm = client.streams[1]["packet"]["vm"]
    forward_offsets = [item[1]["pkt_offset"] for item in forward_vm if item[0] == "write-var"]
    reverse_offsets = [item[1]["pkt_offset"] for item in reverse_vm if item[0] == "write-var"]
    assert forward_offsets == [26, 34]
    assert reverse_offsets == [30, 36]


@pytest.mark.asyncio
async def test_ipv6_variation_uses_low_64_bits_and_udp_checksum(tmp_path: Path) -> None:
    raw = stateless_document()
    raw["spec"]["packet"].pop("ipv4")
    raw["spec"]["packet"]["ipv6"] = {
        "src": {
            "start": "2001:db8:1::1",
            "end": "2001:db8:1::4",
            "mode": "decrement",
        },
        "dst": "2001:db8:2::1",
    }
    document = submit_body(raw).document
    client = FakeClient()
    engine = RemoteTrexStlEngine(
        remote_config(tmp_path), client_factory=lambda **_: client, client_api=FakeApi
    )

    handle = await engine.prepare(execution_marker(), document)
    await engine.cleanup(handle)

    vm = client.streams[0]["packet"]["vm"]
    flow = next(item for item in vm if item[0] == "flow-var")
    write = next(item for item in vm if item[0] == "write-var")
    assert flow[1]["size"] == 8
    assert flow[1]["op"] == "dec"
    assert write[1]["pkt_offset"] == 30
    assert vm[-1][0] == "fix-checksum-hw"


@pytest.mark.asyncio
async def test_remote_engine_runs_initial_fast_rfc2544(tmp_path: Path) -> None:
    raw = {
        "apiVersion": "trex.example.io/v1",
        "kind": "Rfc2544Throughput",
        "metadata": {"name": "initial-fast"},
        "spec": {
            "safety": {"isolatedLab": True},
            "ports": {"tx": "lab-west", "rx": "lab-east"},
            "mode": "fast",
            "frameSizes": [64],
            "packet": {
                "ethernet": {
                    "src": {
                        "start": "00:00:00:00:00:01",
                        "end": "00:00:00:00:00:04",
                        "mode": "increment",
                    },
                    "dst": "00:00:00:00:00:02",
                },
                "vlan": {"id": 100, "priority": 3},
                "ipv4": {
                    "src": {
                        "start": "198.18.0.1",
                        "end": "198.18.0.4",
                        "mode": "increment",
                    },
                    "dst": "198.19.0.1",
                },
                "tcp": {
                    "srcPort": {
                        "start": 49152,
                        "end": 49155,
                        "mode": "increment",
                    },
                    "dstPort": 7,
                    "flags": "S",
                },
                "payloadHex": "aabb",
            },
            "assertion": {"minimumPercentLineRate": {"64": 0}},
        },
    }
    document = submit_body(raw).document
    client = FakeClient()

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        return client

    policy = SafetyPolicy.model_validate(
        {
            "version": "rfc-test",
            "allowedCidrs": ["198.18.0.0/15"],
            "allowedMacPrefixes": ["00:00:00"],
            "maxPercentL1": 0.0000005,
        }
    )
    engine = RemoteTrexStlEngine(
        remote_config(tmp_path),
        policy=policy,
        client_factory=factory,
        client_api=FakeApi,
    )

    handle = await engine.prepare(execution_marker(), document)
    measurement = await engine.run(handle)
    await engine.stop(handle)
    await engine.cleanup(handle)

    assert measurement.verdict == Verdict.PASS
    assert measurement.methodology == "engineering-throughput-estimate/v1"
    assert measurement.summary["rates"]["64"]["percentL1"] == 0.0000005
    assert len(measurement.summary["trials"]["64"]) == 2
    assert any(
        any(
            item[0] == "flow-var" and "ethernet" in item[1]["name"]
            for item in stream["packet"]["vm"]
        )
        for stream in client.streams
        if stream.get("flow_stats") is not None
    )
    assert [values[0] for name, values in client.calls if name == "start"] == [
        [1],
        [0],
        [1],
        [0],
    ]


@pytest.mark.asyncio
async def test_remote_engine_runs_rfc2544_suite_with_frame_loss(tmp_path: Path) -> None:
    raw = {
        "apiVersion": "trex.example.io/v1",
        "kind": "Rfc2544Suite",
        "metadata": {"name": "fast-suite"},
        "spec": {
            "safety": {"isolatedLab": True},
            "ports": {"tx": "lab-west", "rx": "lab-east"},
            "mode": "fast",
            "tests": ["throughput", "frame-loss"],
            "frameSizes": [64],
            "packet": {
                "ethernet": {
                    "src": "00:00:00:00:00:01",
                    "dst": "00:00:00:00:00:02",
                },
                "ipv4": {"src": "198.18.0.1", "dst": "198.19.0.1"},
                "udp": {"srcPort": 49152, "dstPort": 7},
            },
        },
    }
    document = submit_body(raw).document
    client = FakeClient()
    policy = SafetyPolicy.model_validate(
        {
            "version": "rfc-suite-test",
            "allowedCidrs": ["198.18.0.0/15"],
            "allowedMacPrefixes": ["00:00:00"],
            "maxPercentL1": 0.0000005,
        }
    )

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        return client

    engine = RemoteTrexStlEngine(
        remote_config(tmp_path),
        policy=policy,
        client_factory=factory,
        client_api=FakeApi,
    )

    handle = await engine.prepare(execution_marker(), document)
    progress: list[dict[str, Any]] = []

    async def report(update: dict[str, Any]) -> None:
        progress.append(update)

    measurement = await engine.run(handle, report_progress=report)
    await engine.cleanup(handle)

    assert measurement.methodology == "engineering-rfc2544-suite/v1"
    assert list(measurement.summary["tests"]) == ["throughput", "frame-loss"]
    frame_loss = measurement.summary["tests"]["frame-loss"]
    assert frame_loss["frames"]["64"]["stoppedAfterTwoZeroLossTrials"] is True
    assert len(frame_loss["frames"]["64"]["points"]) == 2
    assert {item["test"] for item in progress} == {"throughput", "frame-loss"}
    completed = [item["completedFrames"] for item in progress]
    assert completed == sorted(completed)
    assert progress[-1]["totalFrames"] == 2


@pytest.mark.asyncio
async def test_remote_engine_runs_rfc9004_back_to_back_as_an_independent_method(
    tmp_path: Path,
) -> None:
    from trex_cli.rfc2544 import BackToBackObservation

    class BackToBackEngine(RemoteTrexStlEngine):
        def _back_to_back_trial_sync(
            self,
            session: Any,
            document: Any,
            frame_size: int,
            burst_frames: int,
            theoretical_fps: float,
            buffer_depletion_seconds: float,
        ) -> BackToBackObservation:
            del session, document, frame_size, theoretical_fps, buffer_depletion_seconds
            return BackToBackObservation(
                True,
                burst_frames,
                min(burst_frames, 8),
                {"counterSource": "flow-stats"},
            )

    raw = {
        "apiVersion": "trex.example.io/v1",
        "kind": "Rfc2544Suite",
        "metadata": {"name": "back-to-back-suite"},
        "spec": {
            "safety": {"isolatedLab": True},
            "ports": {"tx": "lab-west", "rx": "lab-east"},
            "mode": "fast",
            "tests": ["throughput", "back-to-back"],
            "frameSizes": [64],
            "backToBack": {"repetitions": 3, "maximumBurstFrames": 16},
            "packet": {
                "ethernet": {
                    "src": "00:00:00:00:00:01",
                    "dst": "00:00:00:00:00:02",
                },
                "ipv4": {"src": "198.18.0.1", "dst": "198.19.0.1"},
                "udp": {"srcPort": 49152, "dstPort": 7},
            },
        },
    }
    document = submit_body(raw).document
    client = FakeClient()
    policy = SafetyPolicy.model_validate(
        {
            "version": "rfc9004-test",
            "allowedCidrs": ["198.18.0.0/15"],
            "allowedMacPrefixes": ["00:00:00"],
            "maxPercentL1": 0.0000005,
        }
    )

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        return client

    engine = BackToBackEngine(
        remote_config(tmp_path),
        policy=policy,
        client_factory=factory,
        client_api=FakeApi,
        sleep=lambda _seconds: None,
    )
    handle = await engine.prepare(execution_marker(), document)
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    result = measurement.summary["tests"]["back-to-back"]
    assert result["methodology"] == "rfc9004-back-to-back-partial/v1"
    assert result["frames"]["64"]["longestZeroLossBursts"] == [8, 8, 8]
    assert len(result["frames"]["64"]["searches"]) == 3


@pytest.mark.asyncio
async def test_remote_engine_runs_twenty_calibrated_latency_trials_per_scenario(
    tmp_path: Path,
) -> None:
    from trex_cli.rfc2544 import LatencyObservation

    destinations: list[str] = []

    class LatencyEngine(RemoteTrexStlEngine):
        def _latency_trial_sync(
            self,
            session: Any,
            document: Any,
            packet: Any,
            frame_size: int,
            rate_percent: float,
            duration_seconds: float,
            tag_after_seconds: float,
            correction_microseconds: float,
            calibration_id: str,
        ) -> LatencyObservation:
            del session, document, frame_size, rate_percent
            assert packet.ipv4 is not None
            destinations.append(str(packet.ipv4.dst))
            return LatencyObservation(
                True,
                10 + correction_microseconds,
                {
                    "durationSeconds": duration_seconds,
                    "tagAfterSeconds": tag_after_seconds,
                    "calibrationId": calibration_id,
                },
            )

    raw = {
        "apiVersion": "trex.example.io/v1",
        "kind": "Rfc2544Suite",
        "metadata": {"name": "latency-suite"},
        "spec": {
            "safety": {"isolatedLab": True},
            "ports": {"tx": "lab-west", "rx": "lab-east"},
            "mode": "fast",
            "tests": ["throughput", "latency"],
            "frameSizes": [64],
            "latency": {
                "definition": "store-and-forward",
                "scenarios": ["same-destination", "new-destination"],
                "newDestinationPacket": {
                    "ethernet": {
                        "src": "00:00:00:00:00:01",
                        "dst": "00:00:00:00:00:03",
                    },
                    "ipv4": {"src": "198.18.0.1", "dst": "198.19.1.1"},
                    "udp": {"srcPort": 49152, "dstPort": 7},
                },
            },
            "packet": {
                "ethernet": {
                    "src": "00:00:00:00:00:01",
                    "dst": "00:00:00:00:00:02",
                },
                "ipv4": {"src": "198.18.0.1", "dst": "198.19.0.1"},
                "udp": {"srcPort": 49152, "dstPort": 7},
            },
        },
    }
    document = submit_body(raw).document
    config = RemoteTrexEngineConfig.model_validate(
        {
            "mode": "remote-trex",
            "server": "127.0.0.1",
            "clientPath": str(tmp_path),
            "externalLibsPath": str(tmp_path),
            "portMapping": {"lab-west": 0, "lab-east": 1},
            "latencyTimestampCalibration": {
                "calibrationId": "cal_X550_test",
                "timestampMode": "ieee1588",
                "measuredAt": "2026-08-29T00:00:00Z",
                "validUntil": "2027-08-29T00:00:00Z",
                "maximumUncertaintyMicroseconds": 0.2,
                "correctionMicroseconds": {"store-and-forward": {"64": -0.25}},
            },
        }
    )
    policy = SafetyPolicy.model_validate(
        {
            "version": "latency-test",
            "allowedCidrs": ["198.18.0.0/15"],
            "allowedMacPrefixes": ["00:00:00"],
            "maxPercentL1": 0.0000005,
        }
    )
    unsupported_client = FakeClient(ieee1588_supported=False)
    unsupported_engine = LatencyEngine(
        config,
        policy=policy,
        client_factory=lambda **_: unsupported_client,
        client_api=FakeApi,
    )
    unsupported_handle = await unsupported_engine.prepare(execution_marker(), document)
    unsupported = await unsupported_engine.run(unsupported_handle)
    await unsupported_engine.cleanup(unsupported_handle)

    unsupported_latency = unsupported.summary["tests"]["latency"]
    assert unsupported_latency["timestampCalibration"]["valid"] is False
    assert "do not support IEEE 1588" in unsupported_latency["issues"][0]

    client = FakeClient()

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        return client

    engine = LatencyEngine(
        config,
        policy=policy,
        client_factory=factory,
        client_api=FakeApi,
    )
    handle = await engine.prepare(execution_marker(), document)
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    result = measurement.summary["tests"]["latency"]
    assert result["timestampCalibration"]["valid"] is True
    assert result["frames"]["64"]["same-destination"]["samplesMicroseconds"] == [9.75] * 20
    assert destinations == ["198.19.0.1"] * 20 + ["198.19.1.1"] * 20


@pytest.mark.asyncio
async def test_remote_latency_uses_delayed_ieee1588_tagged_frames(tmp_path: Path) -> None:
    class Ieee1588Client(FakeClient):
        def get_pgid_stats(self, pg_ids: list[int]) -> dict[str, Any]:
            if pg_ids and pg_ids[0] >= 128:
                pg_id = pg_ids[0]
                return {
                    "flow_stats": {pg_id: {"tx_pkts": {0: 1}, "rx_pkts": {1: 1}}},
                    "latency": {
                        pg_id: {
                            "latency": {"average": 10.0},
                            "err_cntrs": {"dropped": 0, "dup": 0, "out_of_order": 0},
                        }
                    },
                }
            return super().get_pgid_stats(pg_ids)

    raw = {
        "apiVersion": "trex.example.io/v1",
        "kind": "Rfc2544Suite",
        "metadata": {"name": "ieee1588-latency"},
        "spec": {
            "safety": {"isolatedLab": True},
            "ports": {"tx": "lab-west", "rx": "lab-east"},
            "mode": "fast",
            "tests": ["throughput", "latency"],
            "frameSizes": [64],
            "latency": {
                "definition": "store-and-forward",
                "scenarios": ["same-destination"],
            },
            "packet": {
                "ethernet": {
                    "src": "00:00:00:00:00:01",
                    "dst": "00:00:00:00:00:02",
                },
                "ipv4": {"src": "198.18.0.1", "dst": "198.19.0.1"},
                "udp": {"srcPort": 49152, "dstPort": 7},
            },
        },
    }
    document = submit_body(raw).document
    config = RemoteTrexEngineConfig.model_validate(
        {
            "mode": "remote-trex",
            "server": "127.0.0.1",
            "clientPath": str(tmp_path),
            "externalLibsPath": str(tmp_path),
            "portMapping": {"lab-west": 0, "lab-east": 1},
            "latencyTimestampCalibration": {
                "calibrationId": "cal_ieee1588_test",
                "timestampMode": "ieee1588",
                "measuredAt": "2026-08-29T00:00:00Z",
                "validUntil": "2027-08-29T00:00:00Z",
                "maximumUncertaintyMicroseconds": 0.2,
                "correctionMicroseconds": {"store-and-forward": {"64": -0.25}},
            },
        }
    )
    client = Ieee1588Client(
        port_tx_frames=100,
        port_rx_frames=100,
        flow_tx_frames=100,
        flow_rx_frames=100,
    )
    recovery_waits: list[float] = []

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        return client

    engine = RemoteTrexStlEngine(
        config,
        policy=SafetyPolicy.model_validate(
            {
                "version": "latency-stream-test",
                "allowedCidrs": ["198.18.0.0/15"],
                "allowedMacPrefixes": ["00:00:00"],
                "maxPercentL1": 0.0000005,
            }
        ),
        client_factory=factory,
        client_api=FakeApi,
        sleep=recovery_waits.append,
    )
    handle = await engine.prepare(execution_marker(), document)
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    latency_streams = [
        stream
        for stream in client.streams
        if isinstance(stream["flow_stats"], dict) and stream["flow_stats"].get("latency")
    ]
    assert len(latency_streams) == 20
    assert all(stream["isg"] == 60_000_000 for stream in latency_streams)
    assert all(stream["flow_stats"]["ieee_1588"] is True for stream in latency_streams)
    assert recovery_waits == [5] * 20
    samples = measurement.summary["tests"]["latency"]["frames"]["64"]["same-destination"][
        "samplesMicroseconds"
    ]
    trials = measurement.summary["tests"]["latency"]["frames"]["64"]["same-destination"]["trials"]
    assert all(trials[0]["details"]["background"]["checks"].values()), trials[0]["details"][
        "background"
    ]["checks"]
    assert trials[0]["details"]["txTaggedFrames"] == 1
    assert trials[0]["details"]["rxTaggedFrames"] == 1
    assert trials[0]["details"]["rawLatencyMicroseconds"] == 10
    assert samples == [9.75] * 20, trials[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("direction_mode", ["bidirectional-simultaneous", "unidirectional-each"])
async def test_remote_engine_runs_explicit_rfc2544_direction_modes(
    tmp_path: Path, direction_mode: str
) -> None:
    class DirectionClient(FakeClient):
        def get_stats(self, *, ports: list[int]) -> dict[int, dict[str, int]]:
            count = 1 if self.traffic_completed else 0
            return {
                0: {"opackets": count, "ipackets": count, "ierrors": 0, "oerrors": 0},
                1: {"opackets": count, "ipackets": count, "ierrors": 0, "oerrors": 0},
            }

        def get_pgid_stats(self, pg_ids: list[int]) -> dict[str, Any]:
            starts = [value[0] for name, value in self.calls if name == "start"]
            active_ports = starts[-1]
            if active_ports == [1]:
                pairs = [(1, 0)]
            elif active_ports == [0, 1]:
                pairs = [(0, 1), (1, 0)]
            else:
                pairs = [(0, 1)]
            return {
                "flow_stats": {
                    pg_id: {
                        "tx_pkts": {pairs[index][0]: 1},
                        "rx_pkts": {pairs[index][1]: 1},
                    }
                    for index, pg_id in enumerate(pg_ids[: len(pairs)])
                }
            }

    raw = {
        "apiVersion": "trex.example.io/v1",
        "kind": "Rfc2544Throughput",
        "metadata": {"name": "explicit-directions"},
        "spec": {
            "safety": {"isolatedLab": True},
            "ports": {
                "tx": "lab-west",
                "rx": "lab-east",
                "direction": "bidirectional",
            },
            "mode": "fast",
            "directionMode": direction_mode,
            "frameSizes": [64],
            "packet": {
                "ethernet": {
                    "src": "00:00:00:00:00:01",
                    "dst": "00:00:00:00:00:02",
                },
                "ipv4": {"src": "198.18.0.1", "dst": "198.19.0.1"},
                "udp": {"srcPort": 49152, "dstPort": 7},
            },
            "reversePacket": {
                "ethernet": {
                    "src": "00:00:00:00:00:02",
                    "dst": "00:00:00:00:00:01",
                },
                "ipv4": {"src": "198.19.0.1", "dst": "198.18.0.1"},
                "udp": {"srcPort": 7, "dstPort": 49152},
            },
        },
    }
    document = submit_body(raw).document
    client = DirectionClient()

    def factory(**values: Any) -> DirectionClient:
        client.username = values["username"]
        return client

    policy = SafetyPolicy.model_validate(
        {
            "version": "rfc-directions-test",
            "allowedCidrs": ["198.18.0.0/15"],
            "allowedMacPrefixes": ["00:00:00"],
            "maxPercentL1": 0.0000005,
        }
    )
    engine = RemoteTrexStlEngine(
        remote_config(tmp_path),
        policy=policy,
        client_factory=factory,
        client_api=FakeApi,
    )

    handle = await engine.prepare(execution_marker(), document)
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    assert measurement.verdict == Verdict.NO_ASSERTION
    assert measurement.summary["directionMode"] == direction_mode
    if direction_mode == "bidirectional-simultaneous":
        trial = measurement.summary["trials"]["64"][0]
        assert [item["name"] for item in trial["details"]["directions"]] == [
            "forward",
            "reverse",
        ]
    else:
        assert set(measurement.summary["directions"]) == {"forward", "reverse"}
        assert (
            measurement.summary["directions"]["forward"]["trials"]["64"][0]["details"][
                "directions"
            ][0]["name"]
            == "forward"
        )
        assert (
            measurement.summary["directions"]["reverse"]["trials"]["64"][0]["details"][
                "directions"
            ][0]["name"]
            == "reverse"
        )
        assert measurement.summary["directions"]["forward"]["rates"]["64"]["percentL1"] == 0.0000005
        assert measurement.summary["directions"]["reverse"]["rates"]["64"]["percentL1"] == 0.0000005


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("unit", "value"),
    [
        ("pps", 1),
        ("bps_l2", 1024),
        ("bps_l1", 1184),
        ("percent_l1", 0.00001184),
    ],
)
async def test_all_rate_units_reach_the_same_one_packet_target(
    tmp_path: Path, unit: str, value: float
) -> None:
    raw = stateless_document()
    raw["spec"]["rate"] = {"unit": unit, "value": value}
    raw["spec"]["duration"] = "1s"
    document = submit_body(raw).document
    client = FakeClient()

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        return client

    engine = RemoteTrexStlEngine(
        remote_config(tmp_path), client_factory=factory, client_api=FakeApi
    )
    handle = await engine.prepare(execution_marker(), document)
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    assert measurement.summary["valid"] is True
    assert measurement.summary["validity"]["directions"][0]["expectedTxFrames"] == 1


@pytest.mark.asyncio
async def test_missing_flow_statistics_invalidates_trial(tmp_path: Path) -> None:
    client = FakeClient(flow_stats_available=False)

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        return client

    engine = RemoteTrexStlEngine(
        remote_config(tmp_path), client_factory=factory, client_api=FakeApi
    )
    handle = await engine.prepare(execution_marker(), one_packet_document())
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    assert measurement.verdict == Verdict.INVALID
    assert measurement.summary["validity"]["checks"]["flowStatsPresent"] is False


@pytest.mark.asyncio
async def test_bare_l2_uses_exclusive_port_counter_fallback(tmp_path: Path) -> None:
    raw = stateless_document()
    raw["spec"]["packet"].pop("ipv4")
    raw["spec"]["packet"].pop("udp")
    raw["spec"]["packet"]["ethernet"]["src"] = {
        "start": "00:00:00:00:00:01",
        "end": "00:00:00:00:00:04",
        "mode": "increment",
    }
    raw["spec"]["rate"] = {"unit": "pps", "value": 1}
    raw["spec"]["duration"] = "1s"
    document = submit_body(raw).document
    client = FakeClient(flow_stats_available=False)

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        return client

    engine = RemoteTrexStlEngine(
        remote_config(tmp_path), client_factory=factory, client_api=FakeApi
    )

    handle = await engine.prepare(execution_marker(), document)
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    assert client.streams[0]["flow_stats"] is None
    assert measurement.verdict == Verdict.PASS
    direction = measurement.summary["validity"]["directions"][0]
    assert direction["counterSource"] == "exclusive-port-fallback"
    assert [values[0] for name, values in client.calls if name == "start"] == [[1], [0]]


@pytest.mark.asyncio
async def test_marker_zero_loss_allows_unclassified_switch_frames(tmp_path: Path) -> None:
    client = FakeClient(
        port_tx_frames=10,
        port_rx_frames=11,
        flow_tx_frames=10,
        flow_rx_frames=10,
    )

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        return client

    engine = RemoteTrexStlEngine(
        remote_config(tmp_path), client_factory=factory, client_api=FakeApi
    )

    handle = await engine.prepare(execution_marker(), one_packet_document())
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    direction = measurement.summary["validity"]["directions"][0]
    assert measurement.summary["valid"] is True
    assert direction["flowStatsConsistent"] is True
    assert direction["unclassifiedRxFrames"] == 1


@pytest.mark.asyncio
async def test_marker_loss_with_complete_port_rx_is_invalid(tmp_path: Path) -> None:
    client = FakeClient(
        port_tx_frames=10,
        port_rx_frames=10,
        flow_tx_frames=10,
        flow_rx_frames=9,
    )

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        return client

    engine = RemoteTrexStlEngine(
        remote_config(tmp_path), client_factory=factory, client_api=FakeApi
    )

    handle = await engine.prepare(execution_marker(), one_packet_document())
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    assert measurement.verdict == Verdict.INVALID
    assert measurement.summary["validity"]["checks"]["testFramesIsolated"] is False


@pytest.mark.asyncio
async def test_marker_and_port_loss_is_a_valid_dut_failure(tmp_path: Path) -> None:
    client = FakeClient(
        port_tx_frames=10,
        port_rx_frames=9,
        flow_tx_frames=10,
        flow_rx_frames=9,
    )

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        return client

    engine = RemoteTrexStlEngine(
        remote_config(tmp_path), client_factory=factory, client_api=FakeApi
    )

    handle = await engine.prepare(execution_marker(), one_packet_document())
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    assert measurement.summary["valid"] is True
    assert measurement.verdict == Verdict.FAIL


@pytest.mark.asyncio
async def test_remote_engine_strict_rfc2544_path_is_runnable(tmp_path: Path) -> None:
    raw = {
        "apiVersion": "trex.example.io/v1",
        "kind": "Rfc2544Throughput",
        "metadata": {"name": "initial-strict"},
        "spec": {
            "safety": {"isolatedLab": True},
            "ports": {"tx": "lab-west", "rx": "lab-east"},
            "mode": "strict",
            "packet": {
                "ethernet": {
                    "src": "00:00:00:00:00:01",
                    "dst": "00:00:00:00:00:02",
                },
                "ipv4": {"src": "198.18.0.1", "dst": "198.19.0.1"},
                "udp": {"srcPort": 49152, "dstPort": 7},
            },
            "assertion": {"minimumPercentLineRate": {"64": 0, "1518": 0}},
        },
    }
    document = submit_body(raw).document
    client = FakeClient()

    def factory(**values: Any) -> FakeClient:
        client.username = values["username"]
        return client

    policy = SafetyPolicy.model_validate(
        {
            "version": "rfc-test",
            "allowedCidrs": ["198.18.0.0/15"],
            "allowedMacPrefixes": ["00:00:00"],
            "maxPercentL1": 0.0000001,
        }
    )
    recovery_waits: list[float] = []
    engine = RemoteTrexStlEngine(
        remote_config(tmp_path),
        policy=policy,
        client_factory=factory,
        client_api=FakeApi,
        sleep=recovery_waits.append,
    )

    handle = await engine.prepare(execution_marker(), document)
    measurement = await engine.run(handle)
    await engine.cleanup(handle)

    assert measurement.verdict == Verdict.PASS
    assert measurement.methodology == "rfc2544-throughput-strict/v1"
    assert set(measurement.summary["rates"]) == {
        "64",
        "128",
        "256",
        "512",
        "1024",
        "1280",
        "1518",
    }
    trial_waits = [
        value for name, value in client.calls if name == "wait_on_traffic" and value[1] > 5
    ]
    assert trial_waits
    assert all(value[2] == 2_000 for value in trial_waits)
    assert recovery_waits
    assert set(recovery_waits) == {5}


@pytest.mark.asyncio
async def test_back_to_back_trial_waits_for_rx_and_dut_recovery(tmp_path: Path) -> None:
    raw = {
        "apiVersion": "trex.example.io/v1",
        "kind": "Rfc2544Suite",
        "metadata": {"name": "back-to-back-recovery"},
        "spec": {
            "safety": {"isolatedLab": True},
            "ports": {"tx": "lab-west", "rx": "lab-east"},
            "mode": "fast",
            "tests": ["throughput", "back-to-back"],
            "frameSizes": [64],
            "backToBack": {"maximumBurstFrames": 100},
            "packet": {
                "ethernet": {
                    "src": "00:00:00:00:00:01",
                    "dst": "00:00:00:00:00:02",
                },
                "ipv4": {"src": "198.18.0.1", "dst": "198.19.0.1"},
                "udp": {"srcPort": 49152, "dstPort": 7},
            },
        },
    }
    document = submit_body(raw).document
    client = FakeClient()
    recovery_waits: list[float] = []
    engine = RemoteTrexStlEngine(
        remote_config(tmp_path),
        client_factory=lambda **_: client,
        client_api=FakeApi,
        sleep=recovery_waits.append,
    )
    handle = await engine.prepare(execution_marker(), document)
    session = engine._sessions[handle.id]
    throughput_document = engine._throughput_document(document)

    engine._back_to_back_trial_sync(session, throughput_document, 64, 10, 1_000, 2)

    wait = next(value for name, value in reversed(client.calls) if name == "wait_on_traffic")
    assert wait[2] == 2_000
    assert recovery_waits == [5]

    recovery_waits.clear()
    engine._back_to_back_trial_sync(session, throughput_document, 64, 10, 1_000, 7)
    assert recovery_waits == [7]
    await engine.cleanup(handle)
