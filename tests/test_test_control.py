from __future__ import annotations

import json
import struct
from io import BytesIO
from pathlib import Path

import dpkt  # type: ignore[import-untyped]
import pytest

from trex_cli.mcp_adapter import McpTestControlAdapter
from trex_cli.models import (
    Principal,
    Rfc2544LatencySettings,
    Rfc9004BackToBackSettings,
    Role,
)
from trex_cli.session_analysis import StatefulSessionAnalyzer
from trex_cli.test_control import (
    ArpStormIntent,
    CaptureWorkloadIntent,
    DhcpStormIntent,
    DnsStormIntent,
    PcapReplayIntent,
    Rfc2544TestIntent,
    StatefulReplayIntent,
    TrafficTestIntent,
    UdpWorkloadIntent,
)
from trex_cli.test_control import TestControl as ControlModule
from trex_cli.test_plan import TestPlanError as PlanError
from trex_cli.test_plan import TestPlanModule as PlanModule

from .conftest import build_jobs, make_config, wait_terminal


def test_reused_tcp_endpoints_keep_distinct_sessions_and_template_weight() -> None:
    packets = [
        dpkt.ethernet.Ethernet(raw) for _, raw in dpkt.pcap.Reader(BytesIO(_http_session_pcap()))
    ]
    analyzer = StatefulSessionAnalyzer()
    for _ in range(2):
        for packet in packets:
            analyzer.observe(packet)
    result = analyzer.finish()
    assert result is not None
    assert result.tcp_session_count == result.reconstructible_session_count == 2
    assert len({session.id for session in result.sessions}) == 2
    assert result.workload_templates[0].occurrence_count == 2
    assert all(session.exchange_count == 2 for session in result.sessions)
    for session in result.sessions:
        assert len(analyzer.template(session.id).exchanges) == 2


def test_retransmitted_syn_before_syn_ack_stays_in_the_same_session() -> None:
    analyzer = StatefulSessionAnalyzer()
    packets = list(dpkt.pcap.Reader(BytesIO(_http_session_pcap())))
    analyzer.observe(dpkt.ethernet.Ethernet(packets[0][1]))
    for _, raw in packets:
        analyzer.observe(dpkt.ethernet.Ethernet(raw))
    result = analyzer.finish()
    assert result is not None
    assert result.tcp_session_count == 1
    assert result.reconstructible_session_count == 1
    assert result.sessions[0].issues == []


def _one_packet_pcap() -> bytes:
    ethernet = bytes.fromhex(
        "00000000000200000000000108004500001c0000000040110000c6120001c6130001c000000700080000"
    )
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
        + struct.pack("<IIII", 1, 250_000, len(ethernet), len(ethernet))
        + ethernet
    )


def _non_monotonic_pcap() -> bytes:
    original = _one_packet_pcap()
    packet = original[24 + 16 :]
    return (
        original[:24]
        + struct.pack("<IIII", 2, 0, len(packet), len(packet))
        + packet
        + struct.pack("<IIII", 1, 500_000, len(packet), len(packet))
        + packet
    )


def _http_session_pcap() -> bytes:
    output = BytesIO()
    writer = dpkt.pcap.Writer(output)
    client_ip = bytes([198, 18, 0, 1])
    server_ip = bytes([198, 19, 0, 1])
    client_mac = bytes.fromhex("000000000001")
    server_mac = bytes.fromhex("000000000002")

    def packet(
        *,
        client_to_server: bool,
        flags: int,
        sequence: int,
        acknowledgement: int,
        payload: bytes = b"",
    ) -> bytes:
        tcp = dpkt.tcp.TCP(
            sport=49152 if client_to_server else 80,
            dport=80 if client_to_server else 49152,
            seq=sequence,
            ack=acknowledgement,
            flags=flags,
            data=payload,
        )
        ip = dpkt.ip.IP(
            src=client_ip if client_to_server else server_ip,
            dst=server_ip if client_to_server else client_ip,
            p=dpkt.ip.IP_PROTO_TCP,
            ttl=64,
            data=tcp,
        )
        ethernet = dpkt.ethernet.Ethernet(
            src=client_mac if client_to_server else server_mac,
            dst=server_mac if client_to_server else client_mac,
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip,
        )
        return bytes(ethernet)

    request = b"GET /health HTTP/1.1\r\nHost: dut\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    writer.writepkt(
        packet(client_to_server=True, flags=dpkt.tcp.TH_SYN, sequence=100, acknowledgement=0),
        1.0,
    )
    writer.writepkt(
        packet(
            client_to_server=False,
            flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK,
            sequence=500,
            acknowledgement=101,
        ),
        1.001,
    )
    writer.writepkt(
        packet(
            client_to_server=True,
            flags=dpkt.tcp.TH_ACK,
            sequence=101,
            acknowledgement=501,
        ),
        1.002,
    )
    writer.writepkt(
        packet(
            client_to_server=True,
            flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
            sequence=101,
            acknowledgement=501,
            payload=request,
        ),
        1.003,
    )
    writer.writepkt(
        packet(
            client_to_server=False,
            flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
            sequence=501,
            acknowledgement=101 + len(request),
            payload=response,
        ),
        1.004,
    )
    return output.getvalue()


def _http_workload_pcap(
    request_paths: tuple[bytes, ...] = (b"/health", b"/health", b"/readyx"),
) -> bytes:
    source_packets = list(dpkt.pcap.Reader(BytesIO(_http_session_pcap())))
    output = BytesIO()
    writer = dpkt.pcap.Writer(output)
    for flow_index, request_path in enumerate(request_paths):
        client_port = 49152 + flow_index
        for timestamp, packet in source_packets:
            ethernet = dpkt.ethernet.Ethernet(packet)
            ip = ethernet.data
            assert isinstance(ip, dpkt.ip.IP)
            tcp = ip.data
            assert isinstance(tcp, dpkt.tcp.TCP)
            if tcp.sport == 49152:
                tcp.sport = client_port
            if tcp.dport == 49152:
                tcp.dport = client_port
            if tcp.data.startswith(b"GET "):
                tcp.data = bytes(tcp.data).replace(b"/health", request_path)
            ip.len = 0
            ip.sum = 0
            tcp.sum = 0
            writer.writepkt(bytes(ethernet), float(timestamp) + flow_index)
    return output.getvalue()


def _dns_workload_pcap(
    exchanges: tuple[tuple[int, bytes, bytes], ...] = (
        (53000, b"query-a", b"answer-a"),
        (53001, b"query-a", b"answer-a"),
        (53002, b"query-b", b"answer-b"),
    ),
) -> bytes:
    output = BytesIO()
    writer = dpkt.pcap.Writer(output)
    initiator_ip = bytes([198, 18, 0, 1])
    responder_ip = bytes([198, 19, 0, 1])
    initiator_mac = bytes.fromhex("000000000001")
    responder_mac = bytes.fromhex("000000000002")
    for index, (initiator_port, query, answer) in enumerate(exchanges):
        for offset, initiator_to_responder, payload in (
            (0.0, True, query),
            (0.002, False, answer),
        ):
            udp = dpkt.udp.UDP(
                sport=initiator_port if initiator_to_responder else 53,
                dport=53 if initiator_to_responder else initiator_port,
                data=payload,
            )
            udp.ulen = len(udp)
            ip = dpkt.ip.IP(
                src=initiator_ip if initiator_to_responder else responder_ip,
                dst=responder_ip if initiator_to_responder else initiator_ip,
                p=dpkt.ip.IP_PROTO_UDP,
                ttl=64,
                data=udp,
            )
            ethernet = dpkt.ethernet.Ethernet(
                src=initiator_mac if initiator_to_responder else responder_mac,
                dst=responder_mac if initiator_to_responder else initiator_mac,
                type=dpkt.ethernet.ETH_TYPE_IP,
                data=ip,
            )
            writer.writepkt(bytes(ethernet), 1.0 + index + offset)
    return output.getvalue()


def test_stateful_analysis_bounds_retained_session_payload() -> None:
    analyzer = StatefulSessionAnalyzer(
        maximum_payload_bytes_per_session=32,
        maximum_total_payload_bytes=32,
    )
    capture = dpkt.pcap.Reader(BytesIO(_http_session_pcap()))
    for _, packet in capture:
        analyzer.observe(dpkt.ethernet.Ethernet(packet))

    analysis = analyzer.finish()

    assert analysis is not None
    assert analysis.tcp_session_count == 1
    assert analysis.reconstructible_session_count == 0
    assert analysis.sessions[0].client_payload_bytes == 35
    assert analysis.sessions[0].server_payload_bytes == 40
    assert "session payload exceeds the per-session analysis limit" in analysis.sessions[0].issues


def _write_resources(root: Path) -> tuple[Path, Path, Path]:
    profile_root = root / "traffic-profiles"
    path_root = root / "lab-paths"
    plan_root = root / "plans"
    profile_root.mkdir()
    path_root.mkdir()
    profile = {
        "apiVersion": "trex.example.io/v2alpha1",
        "kind": "TrafficProfile",
        "metadata": {"name": "ipv4-udp", "revision": 3},
        "parameters": {},
        "flows": {
            "client-to-server": {
                "from": "client",
                "to": "server",
                "frame": {"wireSize": 128},
                "packet": {
                    "ethernet": {
                        "src": "${role.client.mac}",
                        "dst": "${role.server.mac}",
                    },
                    "ipv4": {
                        "src": "${role.client.ipv4}",
                        "dst": "${role.server.ipv4}",
                    },
                    "udp": {"srcPort": 49152, "dstPort": 7},
                },
            }
        },
    }
    path = {
        "apiVersion": "trex.example.io/v2alpha1",
        "kind": "LabPath",
        "metadata": {"name": "cc-switch", "revision": 2},
        "roles": {
            "client": {
                "port": "lab-west",
                "mac": "00:00:00:00:00:01",
                "ipv4": "198.18.0.1",
            },
            "server": {
                "port": "lab-east",
                "mac": "00:00:00:00:00:02",
                "ipv4": "198.19.0.1",
            },
        },
        "safety": {"isolatedLab": True, "broadcastDomain": True},
    }
    (profile_root / "ipv4-udp@3.yaml").write_text(json.dumps(profile), encoding="utf-8")
    (path_root / "cc-switch@2.yaml").write_text(json.dumps(path), encoding="utf-8")
    return profile_root, path_root, plan_root


async def test_control_discovers_freezes_and_starts_a_revisioned_plan(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    jobs = await build_jobs(make_config(tmp_path, monkeypatch))
    control = ControlModule(
        plans=PlanModule(profile_root, path_root, plan_root),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        found = await control.search_catalog(query="ipv4", kinds={"TrafficProfile"})
        assert [(item.ref, item.kind) for item in found.items] == [("ipv4-udp@3", "TrafficProfile")]

        described = await control.describe_resource("TrafficProfile/ipv4-udp@3")
        assert described.ref == "ipv4-udp@3"
        assert described.digest.startswith("sha256:")

        mcp = McpTestControlAdapter(control)
        discovered = await mcp.search_catalog(query="ipv4", kinds=["TrafficProfile"])
        assert discovered["items"][0]["ref"] == "ipv4-udp@3"

        planned = await control.plan_test(
            TrafficTestIntent(
                profile="ipv4-udp",
                path="cc-switch",
                rate="1000pps",
                duration="1s",
            )
        )
        assert planned.resources["profile"].ref == "ipv4-udp@3"
        assert planned.resources["path"].ref == "cc-switch@2"
        assert planned.resources["profile"].digest == described.digest

        first = await control.start_test(planned.plan_id)
        second = await control.start_test(planned.plan_id)
        assert second.job_id == first.job_id

        terminal = await wait_terminal(jobs, first.job_id)
        assert terminal.state == "SUCCEEDED"
    finally:
        await jobs.stop()


async def test_control_publishes_analyzes_and_discovers_an_immutable_capture(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    jobs = await build_jobs(make_config(tmp_path, monkeypatch))
    control = ControlModule(
        plans=PlanModule(profile_root, path_root, plan_root),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        first = await control.publish_capture(
            name="regression/smoke",
            source=BytesIO(_one_packet_pcap()),
            description="One packet capture",
        )
        repeated = await control.publish_capture(
            name="regression/smoke",
            source=BytesIO(_one_packet_pcap()),
            description="One packet capture",
        )

        assert first.ref == "regression/smoke@1"
        assert repeated.ref == first.ref
        assert repeated.digest == first.digest
        analysis = dict(first.document["analysis"])
        datagram = analysis.pop("datagram")
        assert analysis == {
            "linkType": "ethernet",
            "packetCount": 1,
            "capturedBytes": 42,
            "firstTimestampSeconds": 1.25,
            "lastTimestampSeconds": 1.25,
            "durationSeconds": 0.0,
            "normalizedDurationSeconds": 0.0,
            "nonMonotonicTimestampCount": 0,
            "maximumBackwardJumpSeconds": 0.0,
            "protocols": {"ethernet": 1, "ipv4": 1, "udp": 1},
            "macEndpoints": ["00:00:00:00:00:01", "00:00:00:00:00:02"],
            "ipv4Endpoints": ["198.18.0.1", "198.19.0.1"],
            "vlanIds": [],
            "broadcastPackets": 0,
            "multicastPackets": 0,
            "safety": {
                "benchmarkIpv4Endpoints": ["198.18.0.1", "198.19.0.1"],
                "privateIpv4Endpoints": [],
                "publicIpv4Endpoints": [],
                "hasBroadcast": False,
                "hasMulticast": False,
            },
        }
        assert datagram["udpFlowCount"] == 1
        assert datagram["workloadTemplateCount"] == 1
        assert datagram["flows"][0]["datagramCount"] == 1

        found = await control.search_catalog(kinds={"CaptureResource"})
        assert [(item.ref, item.kind) for item in found.items] == [
            ("regression/smoke@1", "CaptureResource")
        ]
        described = await control.describe_resource("CaptureResource/regression/smoke@1")
        assert described.digest == first.digest
        assert described.document == first.document
    finally:
        await jobs.stop()


async def test_capture_analysis_reports_backward_timestamp_magnitude(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    jobs = await build_jobs(make_config(tmp_path, monkeypatch))
    control = ControlModule(
        plans=PlanModule(profile_root, path_root, plan_root),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        published = await control.publish_capture(
            name="regression/non-monotonic",
            source=BytesIO(_non_monotonic_pcap()),
        )

        analysis = published.document["analysis"]
        assert analysis["packetCount"] == 2
        assert analysis["firstTimestampSeconds"] == 2.0
        assert analysis["lastTimestampSeconds"] == 1.5
        assert analysis["durationSeconds"] == 0.5
        assert analysis["nonMonotonicTimestampCount"] == 1
        assert analysis["maximumBackwardJumpSeconds"] == 0.5
    finally:
        await jobs.stop()


async def test_capture_analysis_identifies_a_reconstructible_http_session(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    jobs = await build_jobs(make_config(tmp_path, monkeypatch))
    control = ControlModule(
        plans=PlanModule(profile_root, path_root, plan_root),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        published = await control.publish_capture(
            name="regression/http-session",
            source=BytesIO(_http_session_pcap()),
        )

        stateful = published.document["analysis"]["stateful"]
        assert stateful["tcpSessionCount"] == 1
        assert stateful["reconstructibleSessionCount"] == 1
        assert stateful["semanticDifferences"] == [
            "application payload order is preserved",
            (
                "packet timing, TCP sequence numbers, acknowledgements, retransmissions, "
                "and network jitter are regenerated"
            ),
        ]
        session = stateful["sessions"][0]
        assert session["id"].startswith("session_")
        assert session["protocol"] == "http"
        assert session["client"] == {"ipv4": "198.18.0.1", "port": 49152}
        assert session["server"] == {"ipv4": "198.19.0.1", "port": 80}
        assert session["clientPayloadBytes"] == 35
        assert session["serverPayloadBytes"] == 40
        assert session["exchangeCount"] == 2
        assert session["reconstructible"] is True
        assert session["issues"] == []
    finally:
        await jobs.stop()


async def test_capture_analysis_deduplicates_reconstructible_flows_into_a_workload(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    jobs = await build_jobs(make_config(tmp_path, monkeypatch))
    control = ControlModule(
        plans=PlanModule(profile_root, path_root, plan_root),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        published = await control.publish_capture(
            name="regression/http-workload",
            source=BytesIO(_http_workload_pcap()),
        )

        stateful = published.document["analysis"]["stateful"]
        assert stateful["tcpSessionCount"] == 3
        assert stateful["reconstructibleSessionCount"] == 3
        assert stateful["workloadComplete"] is True
        assert stateful["workloadTemplateCount"] == 2
        assert sorted(
            template["occurrenceCount"] for template in stateful["workloadTemplates"]
        ) == [1, 2]
        assert all(
            template["representativeSessionId"].startswith("session_")
            for template in stateful["workloadTemplates"]
        )
    finally:
        await jobs.stop()


async def test_capture_analysis_builds_a_weighted_datagram_workload(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        published = await control.publish_capture(
            name="regression/dns-workload",
            source=BytesIO(_dns_workload_pcap()),
        )

        datagram = published.document["analysis"]["datagram"]
        assert datagram["udpFlowCount"] == 3
        assert datagram["workloadComplete"] is True
        assert datagram["workloadTemplateCount"] == 2
        assert sorted(
            template["occurrenceCount"] for template in datagram["workloadTemplates"]
        ) == [1, 2]
        assert sorted(
            (flow["initiator"]["port"], flow["responder"]["port"]) for flow in datagram["flows"]
        ) == [(53000, 53), (53001, 53), (53002, 53)]
    finally:
        await jobs.stop()


async def test_datagram_analysis_reports_every_workload_representative(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        exchanges = tuple(
            (
                50000 + index,
                b"common-query" if index < 299 else b"distinct-query",
                b"common-answer" if index < 299 else b"distinct-answer",
            )
            for index in range(300)
        )
        published = await control.publish_capture(
            name="regression/large-deduplicated-udp-workload",
            source=BytesIO(_dns_workload_pcap(exchanges)),
        )

        datagram = published.document["analysis"]["datagram"]
        reported_ids = {flow["id"] for flow in datagram["flows"]}
        representative_ids = {
            template["representativeFlowId"] for template in datagram["workloadTemplates"]
        }
        assert datagram["udpFlowCount"] == 300
        assert datagram["reportedFlowCount"] == 256
        assert datagram["workloadComplete"] is True
        assert representative_ids <= reported_ids
    finally:
        await jobs.stop()


async def test_control_plans_all_datagram_flows_as_a_weighted_workload(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        await control.publish_capture(
            name="regression/dns-workload",
            source=BytesIO(_dns_workload_pcap()),
        )
        mcp_planned = await McpTestControlAdapter(control).plan_test(
            intent={
                "kind": "pcap-udp-workload",
                "capture": "regression/dns-workload",
                "path": "cc-switch",
                "initiatorRole": "client",
                "responderRole": "server",
                "fps": 30,
                "duration": "3s",
            }
        )
        assert mcp_planned["intent"] == "pcap-udp-workload"
        planned = await control.plan_test(
            UdpWorkloadIntent(
                capture="regression/dns-workload",
                path="cc-switch",
                initiatorRole="client",
                responderRole="server",
                fps=30,
                duration="3s",
            )
        )

        assert planned.intent == "pcap-udp-workload"
        document = planned.plan["document"]
        assert document["kind"] == "UdpWorkload"
        workload = document["spec"]["workload"]
        assert workload["selection"] == "all-datagram-flows"
        assert workload["sourceFlowCount"] == 3
        assert workload["templateCount"] == 2
        assert document["spec"]["run"] == {
            "fps": 30.0,
            "estimatedPps": 60.0,
            "estimatedBpsL1": 40320.0,
            "duration": 3000,
        }
        allocations = {
            template["occurrenceCount"]: (template["weight"], template["fps"])
            for template in workload["templates"]
        }
        assert allocations == {1: (1 / 3, 10.0), 2: (2 / 3, 20.0)}
        assert document["spec"]["initiator"] == {
            "role": "client",
            "port": "lab-west",
            "mac": "00:00:00:00:00:01",
            "ipv4": "198.18.0.1",
        }
        assert document["spec"]["responder"] == {
            "role": "server",
            "port": "lab-east",
            "mac": "00:00:00:00:00:02",
            "ipv4": "198.19.0.1",
        }
    finally:
        await jobs.stop()


async def test_control_plans_a_bounded_dns_query_storm(tmp_path: Path, monkeypatch) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        mcp_planned = await McpTestControlAdapter(control).plan_test(
            intent={
                "kind": "dns-storm",
                "path": "cc-switch",
                "clientRole": "client",
                "serverRole": "server",
                "name": "www.example.test",
                "queryType": "A",
                "pps": 100,
                "duration": "3s",
            }
        )
        assert mcp_planned["intent"] == "dns-storm"
        planned = await control.plan_test(
            DnsStormIntent(
                path="cc-switch",
                clientRole="client",
                serverRole="server",
                name="www.example.test",
                queryType="A",
                recursionDesired=True,
                sourcePortStart=40000,
                sourcePortEnd=40003,
                pps=100,
                duration="3s",
            )
        )

        assert planned.intent == "dns-storm"
        assert planned.resources["path"].ref == "cc-switch@2"
        document = planned.plan["document"]
        assert document["kind"] == "PacketStorm"
        assert document["spec"]["protocol"] == "dns"
        assert document["spec"]["question"] == {
            "name": "www.example.test.",
            "type": "A",
            "class": "IN",
            "recursionDesired": True,
        }
        assert document["spec"]["client"] == {
            "role": "client",
            "port": "lab-west",
            "mac": "00:00:00:00:00:01",
            "ipv4": "198.18.0.1",
            "udpSourcePortStart": 40000,
            "udpSourcePortEnd": 40003,
        }
        assert document["spec"]["server"] == {
            "role": "server",
            "port": "lab-east",
            "mac": "00:00:00:00:00:02",
            "ipv4": "198.19.0.1",
            "udpPort": 53,
        }
        assert document["spec"]["run"] == {
            "pps": 100.0,
            "wireSize": 80,
            "estimatedBpsL1": 80000.0,
            "duration": 3000,
        }
        assert document["spec"]["observation"] == {
            "queryDelivery": "flow-stats",
            "responses": "unavailable",
        }
    finally:
        await jobs.stop()


async def test_control_plans_a_bounded_dhcp_discover_storm(tmp_path: Path, monkeypatch) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    config.safety.allow_broadcast_storms = True
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        mcp_planned = await McpTestControlAdapter(control).plan_test(
            intent={
                "kind": "dhcp-storm",
                "path": "cc-switch",
                "clientRole": "client",
                "serverRole": "server",
                "clients": 4,
                "pps": 100,
                "duration": "3s",
            }
        )
        assert mcp_planned["intent"] == "dhcp-storm"
        planned = await control.plan_test(
            DhcpStormIntent(
                path="cc-switch",
                clientRole="client",
                serverRole="server",
                clients=4,
                pps=100,
                duration="3s",
            )
        )

        assert planned.intent == "dhcp-storm"
        assert planned.resources["path"].ref == "cc-switch@2"
        document = planned.plan["document"]
        assert document["kind"] == "PacketStorm"
        assert document["spec"]["protocol"] == "dhcp"
        assert document["spec"]["message"] == {
            "type": "discover",
            "clientPort": 68,
            "serverPort": 67,
            "broadcastReplyRequested": True,
        }
        assert document["spec"]["clients"] == {
            "role": "client",
            "port": "lab-west",
            "macStart": "00:00:00:00:00:01",
            "macEnd": "00:00:00:00:00:04",
            "count": 4,
        }
        assert document["spec"]["server"] == {
            "role": "server",
            "port": "lab-east",
        }
        assert document["spec"]["network"] == {
            "broadcastDomain": True,
            "ethernetDestination": "ff:ff:ff:ff:ff:ff",
            "ipv4Source": "0.0.0.0",
            "ipv4Destination": "255.255.255.255",
        }
        assert document["spec"]["run"] == {
            "pps": 100.0,
            "wireSize": 290,
            "estimatedBpsL1": 248000.0,
            "duration": 3000,
        }
        assert document["spec"]["observation"] == {
            "discoverDelivery": "flow-stats",
            "offers": "unavailable",
        }
    finally:
        await jobs.stop()


async def test_control_plans_and_runs_a_bounded_arp_request_storm(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    config.safety.allow_broadcast_storms = True
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        planned = await control.plan_test(
            ArpStormIntent(
                path="cc-switch",
                senderRole="client",
                targetRole="server",
                senders=4,
                pps=100,
                duration="3s",
            )
        )
        assert planned.intent == "arp-storm"
        spec = planned.plan["document"]["spec"]
        assert spec["protocol"] == "arp"
        assert spec["senders"] == {
            "role": "client",
            "port": "lab-west",
            "macStart": "00:00:00:00:00:01",
            "macEnd": "00:00:00:00:00:04",
            "ipv4Start": "198.18.0.1",
            "ipv4End": "198.18.0.4",
            "count": 4,
        }
        assert spec["target"] == {
            "role": "server",
            "port": "lab-east",
            "ipv4": "198.19.0.1",
        }
        assert spec["run"] == {
            "pps": 100.0,
            "wireSize": 64,
            "estimatedBpsL1": 67200.0,
            "duration": 3000,
        }
        assert spec["observation"] == {
            "requestTransmission": "hardware-port-counter",
            "requestDelivery": "unavailable",
            "replies": "unavailable",
            "limitation": "hardware-flow-stats-unsupported-for-arp",
        }

        started = await control.start_test(planned.plan_id)
        terminal = await wait_terminal(jobs, started.job_id)
        assert terminal.result is not None
        assert terminal.result.verdict.value == "NO_ASSERTION"
        assert terminal.result.methodology == "simulated-arp-request-storm/v1"
        assert terminal.result.summary["requestsTx"] == 300
        assert terminal.result.summary["requestDeliveryObservation"] == "unavailable"
        assert "requestsRx" not in terminal.result.summary
    finally:
        await jobs.stop()


async def test_arp_request_storm_requires_broadcast_opt_in_and_bounded_sender_pool(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    plans = PlanModule(
        profile_root,
        path_root,
        plan_root,
        tmp_path / "captures",
        config.safety,
    )
    control = ControlModule(
        plans=plans,
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        intent = ArpStormIntent(
            path="cc-switch",
            senderRole="client",
            targetRole="server",
            senders=1,
            pps=1,
            duration="1s",
        )
        with pytest.raises(PlanError, match="allowBroadcastStorms"):
            await control.plan_test(intent)

        config.safety.allow_broadcast_storms = True
        config.safety.max_address_pool_size = 2
        with pytest.raises(PlanError, match="maxAddressPoolSize"):
            await control.plan_test(intent.model_copy(update={"senders": 3}))
    finally:
        await jobs.stop()


async def test_control_runs_a_dhcp_discover_storm_without_claiming_offers(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    config.safety.allow_broadcast_storms = True
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        planned = await control.plan_test(
            DhcpStormIntent(
                path="cc-switch",
                clientRole="client",
                serverRole="server",
                clients=4,
                pps=100,
                duration="3s",
            )
        )
        started = await control.start_test(planned.plan_id)
        terminal = await wait_terminal(jobs, started.job_id)

        assert terminal.state.value == "SUCCEEDED"
        assert terminal.result is not None
        assert terminal.result.verdict.value == "NO_ASSERTION"
        assert terminal.result.methodology == "simulated-dhcp-discover-storm/v1"
        assert terminal.result.summary == {
            "simulated": True,
            "protocol": "dhcp",
            "messageType": "discover",
            "clientIdentities": 4,
            "discoversTx": 300,
            "discoversRx": 300,
            "lostDiscovers": 0,
            "lossPercent": 0.0,
            "observationValid": True,
            "counterSource": "flow-stats",
            "offerObservation": "unavailable",
        }
    finally:
        await jobs.stop()


async def test_dhcp_discover_storm_requires_explicit_broadcast_safety(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        with pytest.raises(PlanError, match="allowBroadcastStorms"):
            await control.plan_test(
                DhcpStormIntent(
                    path="cc-switch",
                    clientRole="client",
                    serverRole="server",
                    clients=1,
                    pps=1,
                    duration="1s",
                )
            )

        config.safety.allow_broadcast_storms = True
        config.safety.max_address_pool_size = 2
        with pytest.raises(PlanError, match="maxAddressPoolSize"):
            await control.plan_test(
                DhcpStormIntent(
                    path="cc-switch",
                    clientRole="client",
                    serverRole="server",
                    clients=3,
                    pps=1,
                    duration="1s",
                )
            )

        config.safety.max_address_pool_size = 4
        config.safety.max_bps_l1 = 1_000
        with pytest.raises(PlanError, match="estimatedBpsL1"):
            await control.plan_test(
                DhcpStormIntent(
                    path="cc-switch",
                    clientRole="client",
                    serverRole="server",
                    clients=1,
                    pps=1,
                    duration="1s",
                )
            )
    finally:
        await jobs.stop()


async def test_control_runs_a_dns_query_storm_without_claiming_responses(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        planned = await control.plan_test(
            DnsStormIntent(
                path="cc-switch",
                clientRole="client",
                serverRole="server",
                name="www.example.test.",
                queryType="AAAA",
                pps=100,
                duration="3s",
            )
        )
        started = await control.start_test(planned.plan_id)
        terminal = await wait_terminal(jobs, started.job_id)

        assert terminal.kind == "PacketStorm"
        assert terminal.result is not None
        assert terminal.result.verdict.value == "NO_ASSERTION"
        assert terminal.result.methodology == "simulated-dns-query-storm/v1"
        assert terminal.result.summary == {
            "simulated": True,
            "protocol": "dns",
            "question": {"name": "www.example.test.", "type": "AAAA", "class": "IN"},
            "queriesTx": 300,
            "queriesRx": 300,
            "lostQueries": 0,
            "lossPercent": 0.0,
            "observationValid": True,
            "counterSource": "flow-stats",
            "responseObservation": "unavailable",
        }
    finally:
        await jobs.stop()


async def test_dns_query_storm_rejects_invalid_names_and_unsafe_load(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        with pytest.raises(PlanError, match="valid ASCII host labels"):
            await control.plan_test(
                DnsStormIntent(
                    path="cc-switch",
                    clientRole="client",
                    serverRole="server",
                    name="invalid..example",
                    queryType="A",
                    pps=1,
                    duration="1s",
                )
            )
        with pytest.raises(PlanError, match="pps exceeds"):
            await control.plan_test(
                DnsStormIntent(
                    path="cc-switch",
                    clientRole="client",
                    serverRole="server",
                    name="www.example.test",
                    queryType="A",
                    pps=1_000_000_000,
                    duration="1s",
                )
            )
        config.safety.max_pps = 1_000_000_000
        config.safety.max_bps_l1 = 100
        with pytest.raises(PlanError, match="estimatedBpsL1"):
            await control.plan_test(
                DnsStormIntent(
                    path="cc-switch",
                    clientRole="client",
                    serverRole="server",
                    name="www.example.test",
                    queryType="A",
                    pps=1,
                    duration="1s",
                )
            )
    finally:
        await jobs.stop()


async def test_control_runs_a_datagram_workload_with_directional_results(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        await control.publish_capture(
            name="regression/dns-workload",
            source=BytesIO(_dns_workload_pcap()),
        )
        planned = await control.plan_test(
            UdpWorkloadIntent(
                capture="regression/dns-workload",
                path="cc-switch",
                initiatorRole="client",
                responderRole="server",
                fps=30,
                duration="3s",
            )
        )
        started = await control.start_test(planned.plan_id)
        terminal = await wait_terminal(jobs, started.job_id)

        assert terminal.result is not None
        assert terminal.result.methodology == "simulated-stl-datagram-workload/v1"
        assert terminal.result.summary["flowInstances"] == 90
        assert terminal.result.summary["txDatagrams"] == 180
        assert terminal.result.summary["directions"] == {
            "initiator-to-responder": {"txDatagrams": 90, "rxDatagrams": 90},
            "responder-to-initiator": {"txDatagrams": 90, "rxDatagrams": 90},
        }
        assert {
            item["occurrenceCount"]: item["flowInstances"]
            for item in terminal.result.summary["templates"]
        } == {1: 30, 2: 60}
    finally:
        await jobs.stop()


async def test_udp_workload_rejects_truncated_analysis_and_unsafe_packet_rate(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        unique_exchanges = tuple(
            (
                50000 + index,
                f"query-{index:04x}".encode(),
                f"answer-{index:04x}".encode(),
            )
            for index in range(257)
        )
        published = await control.publish_capture(
            name="regression/oversized-udp-workload",
            source=BytesIO(_dns_workload_pcap(unique_exchanges)),
        )
        assert published.document["analysis"]["datagram"]["workloadComplete"] is False
        with pytest.raises(PlanError, match="DATAGRAM_WORKLOAD_TRUNCATED"):
            await control.plan_test(
                UdpWorkloadIntent(
                    capture="regression/oversized-udp-workload",
                    path="cc-switch",
                    initiatorRole="client",
                    responderRole="server",
                    fps=1,
                    duration="1s",
                )
            )

        await control.publish_capture(
            name="regression/dns-workload",
            source=BytesIO(_dns_workload_pcap()),
        )
        with pytest.raises(PlanError, match="estimatedPps"):
            await control.plan_test(
                UdpWorkloadIntent(
                    capture="regression/dns-workload",
                    path="cc-switch",
                    initiatorRole="client",
                    responderRole="server",
                    fps=60_000_000,
                    duration="1s",
                )
            )
        with pytest.raises(PlanError, match="duration must exceed"):
            await control.plan_test(
                UdpWorkloadIntent(
                    capture="regression/dns-workload",
                    path="cc-switch",
                    initiatorRole="client",
                    responderRole="server",
                    fps=1,
                    duration="1ms",
                )
            )
        config.safety.allowed_mac_prefixes = ["02:ff:ff"]
        with pytest.raises(PlanError, match="allowedMacPrefixes"):
            await control.plan_test(
                UdpWorkloadIntent(
                    capture="regression/dns-workload",
                    path="cc-switch",
                    initiatorRole="client",
                    responderRole="server",
                    fps=1,
                    duration="1s",
                )
            )
    finally:
        await jobs.stop()


async def test_control_plans_all_reconstructible_flows_as_a_weighted_workload(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        await control.publish_capture(
            name="regression/http-workload",
            source=BytesIO(_http_workload_pcap()),
        )

        mcp_planned = await McpTestControlAdapter(control).plan_test(
            intent={
                "kind": "pcap-capture-workload",
                "capture": "regression/http-workload",
                "path": "cc-switch",
                "clientRole": "client",
                "serverRole": "server",
                "cps": 30,
                "maxActiveConnections": 20,
                "duration": "3s",
                "clientIpv4Start": "198.18.0.1",
                "clientIpv4End": "198.18.0.4",
                "serverIpv4Start": "198.19.0.1",
                "serverIpv4End": "198.19.0.8",
            }
        )
        assert mcp_planned["intent"] == "pcap-capture-workload"

        planned = await control.plan_test(
            CaptureWorkloadIntent(
                capture="regression/http-workload",
                path="cc-switch",
                clientRole="client",
                serverRole="server",
                cps=30,
                maxActiveConnections=20,
                duration="3s",
                clientIpv4Start="198.18.0.1",
                clientIpv4End="198.18.0.4",
                serverIpv4Start="198.19.0.1",
                serverIpv4End="198.19.0.8",
            )
        )

        assert planned.intent == "pcap-capture-workload"
        document = planned.plan["document"]
        assert document["kind"] == "StatefulReplay"
        assert "session" not in document["spec"]
        workload = document["spec"]["workload"]
        assert workload["selection"] == "all-reconstructible"
        assert workload["sourceSessionCount"] == 3
        assert workload["templateCount"] == 2
        allocations = {
            template["occurrenceCount"]: (
                template["weight"],
                template["cps"],
                template["maxActiveConnections"],
            )
            for template in workload["templates"]
        }
        assert allocations == {
            1: (1 / 3, 10.0, 7),
            2: (2 / 3, 20.0, 13),
        }
    finally:
        await jobs.stop()


async def test_capture_workload_reserves_capacity_for_every_template(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        await control.publish_capture(
            name="regression/skewed-workload",
            source=BytesIO(_http_workload_pcap((b"/health",) * 11 + (b"/readyx",))),
        )
        planned = await control.plan_test(
            CaptureWorkloadIntent(
                capture="regression/skewed-workload",
                path="cc-switch",
                clientRole="client",
                serverRole="server",
                cps=12,
                maxActiveConnections=2,
                duration="1s",
            )
        )

        assert sorted(
            template["maxActiveConnections"]
            for template in planned.plan["document"]["spec"]["workload"]["templates"]
        ) == [1, 1]
    finally:
        await jobs.stop()


async def test_capture_workload_rejects_analysis_with_omitted_templates(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        unique_paths = tuple(f"/{index:06x}".encode() for index in range(257))
        published = await control.publish_capture(
            name="regression/oversized-workload",
            source=BytesIO(_http_workload_pcap(unique_paths)),
        )
        assert published.document["analysis"]["stateful"]["workloadComplete"] is False

        with pytest.raises(PlanError, match="WORKLOAD_TRUNCATED"):
            await control.plan_test(
                CaptureWorkloadIntent(
                    capture="regression/oversized-workload",
                    path="cc-switch",
                    clientRole="client",
                    serverRole="server",
                    cps=257,
                    maxActiveConnections=257,
                    duration="1s",
                )
            )
    finally:
        await jobs.stop()


async def test_control_runs_a_capture_workload_with_per_template_results(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        await control.publish_capture(
            name="regression/http-workload",
            source=BytesIO(_http_workload_pcap()),
        )
        planned = await control.plan_test(
            CaptureWorkloadIntent(
                capture="regression/http-workload",
                path="cc-switch",
                clientRole="client",
                serverRole="server",
                cps=30,
                maxActiveConnections=20,
                duration="3s",
                clientIpv4Start="198.18.0.1",
                clientIpv4End="198.18.0.4",
                serverIpv4Start="198.19.0.1",
                serverIpv4End="198.19.0.8",
            )
        )

        started = await control.start_test(planned.plan_id)
        terminal = await wait_terminal(jobs, started.job_id)

        assert terminal.result is not None
        assert terminal.result.methodology == "simulated-astf-capture-workload/v1"
        assert terminal.result.summary["sourceSessionCount"] == 3
        assert terminal.result.summary["templateCount"] == 2
        assert terminal.result.summary["attemptedConnections"] == 90
        by_occurrence = {
            template["occurrenceCount"]: template["attemptedConnections"]
            for template in terminal.result.summary["templates"]
        }
        assert by_occurrence == {1: 30, 2: 60}
    finally:
        await jobs.stop()


async def test_control_plans_and_runs_a_bounded_stateful_http_replay(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    plans = PlanModule(
        profile_root,
        path_root,
        plan_root,
        tmp_path / "captures",
        config.safety,
    )
    control = ControlModule(
        plans=plans,
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        published = await control.publish_capture(
            name="regression/http-session",
            source=BytesIO(_http_session_pcap()),
        )
        session = published.document["analysis"]["stateful"]["sessions"][0]

        planned = await control.plan_test(
            StatefulReplayIntent(
                capture=published.ref,
                sessionId=session["id"],
                path="cc-switch",
                clientRole="client",
                serverRole="server",
                cps=10,
                maxActiveConnections=20,
                duration="1s",
            )
        )

        assert planned.intent == "pcap-stateful-replay"
        assert planned.resources["capture"].ref == published.ref
        document = planned.plan["document"]
        assert document["kind"] == "StatefulReplay"
        assert document["spec"]["session"] == {
            "id": session["id"],
            "digest": session["digest"],
            "protocol": "http",
            "serverPort": 80,
            "clientPayloadBytes": 35,
            "serverPayloadBytes": 40,
            "exchangeCount": 2,
        }
        assert document["spec"]["client"] == {
            "role": "client",
            "port": "lab-west",
            "ipv4Pool": {"start": "198.18.0.1", "end": "198.18.0.1"},
            "transportPortPool": {"start": 1024, "end": 65535},
        }
        assert document["spec"]["server"] == {
            "role": "server",
            "port": "lab-east",
            "ipv4Pool": {"start": "198.19.0.1", "end": "198.19.0.1"},
        }
        assert document["spec"]["run"] == {
            "cps": 10.0,
            "maxActiveConnections": 20,
            "duration": 1000,
        }
        assert document["spec"]["semanticDifferences"] == [
            "application payload order is preserved",
            (
                "packet timing, TCP sequence numbers, acknowledgements, retransmissions, "
                "and network jitter are regenerated"
            ),
        ]

        started = await control.start_test(planned.plan_id)
        terminal = await wait_terminal(jobs, started.job_id)
        assert terminal.state == "SUCCEEDED"
        assert terminal.result is not None
        assert terminal.result.methodology == "simulated-astf-stateful-replay/v1"
        assert terminal.result.summary["attemptedConnections"] == 10
        assert terminal.result.summary["establishedConnections"] == 10
        assert terminal.result.summary["failedConnections"] == 0
        assert terminal.result.summary["closedConnections"] == 10
        assert terminal.result.summary["applicationTxBytes"] == 350
        assert terminal.result.summary["applicationRxBytes"] == 400
    finally:
        await jobs.stop()


async def test_stateful_replay_rejects_exhausted_or_unauthorized_address_pools(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    control = ControlModule(
        plans=PlanModule(
            profile_root,
            path_root,
            plan_root,
            tmp_path / "captures",
            config.safety,
        ),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        published = await control.publish_capture(
            name="regression/http-session",
            source=BytesIO(_http_session_pcap()),
        )
        session_id = published.document["analysis"]["stateful"]["sessions"][0]["id"]
        with pytest.raises(PlanError, match="PORT_POOL_EXHAUSTED"):
            await control.plan_test(
                StatefulReplayIntent(
                    capture=published.ref,
                    sessionId=session_id,
                    path="cc-switch",
                    clientRole="client",
                    serverRole="server",
                    cps=10,
                    maxActiveConnections=2,
                    duration="1s",
                    clientPortStart=65_535,
                    clientPortEnd=65_535,
                )
            )
        with pytest.raises(PlanError, match="outside allowedCidrs"):
            await control.plan_test(
                StatefulReplayIntent(
                    capture=published.ref,
                    sessionId=session_id,
                    path="cc-switch",
                    clientRole="client",
                    serverRole="server",
                    cps=10,
                    maxActiveConnections=20,
                    duration="1s",
                    clientIpv4Start="8.8.8.8",
                    clientIpv4End="8.8.8.8",
                )
            )
    finally:
        await jobs.stop()


async def test_control_freezes_rewrite_and_normalized_capture_timing(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    plans = PlanModule(
        profile_root,
        path_root,
        plan_root,
        tmp_path / "captures",
        config.safety,
    )
    control = ControlModule(
        plans=plans,
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        capture = await control.publish_capture(
            name="regression/non-monotonic",
            source=BytesIO(_non_monotonic_pcap()),
        )
        with pytest.raises(PlanError, match="non-monotonic timestamps"):
            await control.plan_test(
                PcapReplayIntent(
                    capture=capture.ref,
                    path="cc-switch",
                    sourceRole="client",
                    destinationRole="server",
                )
            )

        planned = await control.plan_test(
            PcapReplayIntent(
                capture=capture.ref,
                path="cc-switch",
                sourceRole="client",
                destinationRole="server",
                multiplier=2,
                timestampPolicy="normalize",
            )
        )

        assert planned.intent == "pcap-replay"
        assert planned.resources["capture"].ref == "regression/non-monotonic@1"
        assert planned.plan["address"] == {
            "mode": "rewrite",
            "sourceRole": "client",
            "destinationRole": "server",
            "sourceMac": "00:00:00:00:00:01",
            "destinationMac": "00:00:00:00:00:02",
            "sourceIpv4": "198.18.0.1",
            "destinationIpv4": "198.19.0.1",
        }
        assert planned.plan["timing"] == {
            "mode": "capture",
            "multiplier": 2.0,
            "timestampPolicy": "normalize",
            "normalizedTimestampCount": 1,
        }
        assert planned.plan["document"]["spec"]["capture"]["digest"] == capture.digest
        assert plans.get(planned.plan_id).payload() == planned.plan

        started = await control.start_test(planned.plan_id)
        terminal = await wait_terminal(jobs, started.job_id)
        assert terminal.state == "SUCCEEDED"
        assert terminal.result is not None
        assert terminal.result.methodology == "simulated-pcap-replay/v1"
        assert terminal.result.summary["txFrames"] == 2
        assert terminal.result.summary["timing"]["normalizedTimestampCount"] == 1
        assert terminal.result.artifacts
    finally:
        await jobs.stop()


async def test_preserve_replay_requires_capture_to_match_the_safety_policy(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    jobs = await build_jobs(config)
    plans = PlanModule(
        profile_root,
        path_root,
        plan_root,
        tmp_path / "captures",
        config.safety,
    )
    control = ControlModule(
        plans=plans,
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        safe = await control.publish_capture(
            name="regression/safe-preserve",
            source=BytesIO(_one_packet_pcap()),
        )
        preserved = await control.plan_test(
            PcapReplayIntent(
                capture=safe.ref,
                path="cc-switch",
                sourceRole="client",
                destinationRole="server",
                addressMode="preserve",
                timingMode="fixed-rate",
                rate="1000pps",
            )
        )
        assert preserved.plan["address"] == {
            "mode": "preserve",
            "policyVersion": "test-policy-1",
        }
        assert preserved.plan["timing"] == {
            "mode": "fixed-rate",
            "rate": {"unit": "pps", "value": 1000.0},
        }

        public_packet = _one_packet_pcap().replace(bytes.fromhex("c6120001"), bytes([8, 8, 8, 8]))
        public = await control.publish_capture(
            name="regression/public",
            source=BytesIO(public_packet),
        )
        with pytest.raises(PlanError, match="outside configured allowedCidrs"):
            await control.plan_test(
                PcapReplayIntent(
                    capture=public.ref,
                    path="cc-switch",
                    sourceRole="client",
                    destinationRole="server",
                    addressMode="preserve",
                    timingMode="top-speed",
                )
            )

        broadcast_packet = _one_packet_pcap().replace(
            bytes.fromhex("000000000002"), bytes.fromhex("ffffffffffff"), 1
        )
        broadcast = await control.publish_capture(
            name="regression/broadcast",
            source=BytesIO(broadcast_packet),
        )
        with pytest.raises(PlanError, match="broadcast or multicast"):
            await control.plan_test(
                PcapReplayIntent(
                    capture=broadcast.ref,
                    path="cc-switch",
                    sourceRole="client",
                    destinationRole="server",
                    addressMode="preserve",
                    timingMode="top-speed",
                )
            )
    finally:
        await jobs.stop()


async def test_control_plans_a_complete_publishable_rfc2544_suite(
    tmp_path: Path, monkeypatch
) -> None:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    profile_path = profile_root / "ipv4-udp@3.yaml"
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    profile["flows"]["client-to-new-network"] = {
        "from": "client",
        "to": "server",
        "frame": {"wireSize": 128},
        "packet": {
            "ethernet": {
                "src": "${role.client.mac}",
                "dst": "00:00:00:00:00:03",
            },
            "ipv4": {"src": "${role.client.ipv4}", "dst": "198.19.1.1"},
            "udp": {"srcPort": 49152, "dstPort": 7},
        },
    }
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    jobs = await build_jobs(make_config(tmp_path, monkeypatch))
    control = ControlModule(
        plans=PlanModule(profile_root, path_root, plan_root),
        jobs=jobs,
        principal=Principal(name="operator", role=Role.OPERATOR),
    )
    try:
        planned = await control.plan_test(
            Rfc2544TestIntent(
                profile="ipv4-udp",
                path="cc-switch",
                flow="client-to-server",
                mode="strict",
                tests=("throughput", "latency", "frame-loss", "back-to-back"),
                latency=Rfc2544LatencySettings(
                    definition="store-and-forward",
                    scenarios=["same-destination", "new-destination"],
                ),
                latencyNewDestinationFlow="client-to-new-network",
                backToBack=Rfc9004BackToBackSettings(maximumBurstFrames=1000000),
            )
        )

        document = planned.plan["document"]
        assert document["spec"]["latency"]["repetitions"] == 20
        assert document["spec"]["latency"]["newDestinationPacket"]["ipv4"]["dst"] == "198.19.1.1"
        assert document["spec"]["backToBack"]["maximumBurstFrames"] == 1000000
    finally:
        await jobs.stop()
