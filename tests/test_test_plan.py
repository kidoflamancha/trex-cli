from __future__ import annotations

import json
from pathlib import Path

import pytest

from trex_cli.test_plan import TestPlanError as PlanError
from trex_cli.test_plan import TestPlanModule as PlanModule


def _profile() -> dict[str, object]:
    return {
        "apiVersion": "trex.example.io/v2alpha1",
        "kind": "TrafficProfile",
        "metadata": {"name": "ipv4-udp"},
        "parameters": {
            "frame-size": {
                "type": "integer",
                "default": 128,
                "minimum": 64,
                "maximum": 1518,
            }
        },
        "flows": {
            "client-to-server": {
                "from": "client",
                "to": "server",
                "frame": {"wireSize": "${param.frame-size}"},
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


def _path() -> dict[str, object]:
    return {
        "apiVersion": "trex.example.io/v2alpha1",
        "kind": "LabPath",
        "metadata": {"name": "cc-switch"},
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
        "safety": {"isolatedLab": True},
        "reportContext": {
            "dut": {
                "name": "cc-switch",
                "hardware": "switch-rev-a",
                "softwareVersion": "1.0.0",
                "configurationDigest": "sha256:" + "b" * 64,
                "configurationArtifact": "cc-switch-config.txt",
            },
            "topology": "lab-west -> DUT -> lab-east",
            "medium": "10GBASE-SR",
            "protocol": "IPv4/UDP",
            "streamType": "single unidirectional stream",
            "isolationStatement": "Dedicated test lab",
        },
    }


def _module(tmp_path: Path, profile: dict[str, object] | None = None) -> PlanModule:
    profile_root = tmp_path / "traffic-profiles"
    path_root = tmp_path / "lab-paths"
    profile_root.mkdir()
    path_root.mkdir()
    (profile_root / "ipv4-udp.yaml").write_text(json.dumps(profile or _profile()), encoding="utf-8")
    (path_root / "cc-switch.yaml").write_text(json.dumps(_path()), encoding="utf-8")
    return PlanModule(profile_root, path_root, tmp_path / "plans")


def test_traffic_intent_compiles_to_an_immutable_executable_plan(tmp_path: Path) -> None:
    module = _module(tmp_path)

    plan = module.plan_traffic(
        profile_name="ipv4-udp",
        path_name="cc-switch",
        parameters=["frame-size=256"],
        rate="1gbps",
        duration="30s",
    )
    repeated = module.plan_traffic(
        profile_name="ipv4-udp",
        path_name="cc-switch",
        parameters=["frame-size=256"],
        rate="1gbps",
        duration="30s",
    )

    assert repeated.plan_id == plan.plan_id
    assert plan.payload()["apiVersion"] == "trex.example.io/test-plan/v1"
    assert plan.payload()["load"] == {"scope": "per-egress", "requested": "1gbps"}
    assert plan.payload()["resolvedStreams"][0]["frame"] == {
        "wireSizeBytes": 256,
        "generatedSizeBytes": 252,
        "l1SizeBytes": 276,
    }
    assert plan.document.spec.ports.tx == "lab-west"
    assert plan.document.spec.ports.rx == "lab-east"
    assert plan.document.spec.packet.ethernet.src == "00:00:00:00:00:01"
    assert plan.document.spec.packet.ipv4 is not None
    assert plan.document.spec.packet.ipv4.dst == "198.19.0.1"
    assert plan.document.spec.rate.unit == "bps_l1"
    assert plan.document.spec.rate.value == 1_000_000_000
    assert module.get(plan.plan_id).payload() == plan.payload()


def test_legacy_alpha_plan_is_read_compatible_without_rewriting_history(
    tmp_path: Path,
) -> None:
    module = _module(tmp_path)
    plan = module.plan_traffic(
        profile_name="ipv4-udp",
        path_name="cc-switch",
        parameters=["frame-size=256"],
        rate="1gbps",
        duration="30s",
    )
    path = tmp_path / "plans" / f"{plan.plan_id}.json"
    legacy = json.loads(path.read_text(encoding="utf-8"))
    legacy["apiVersion"] = "trex.example.io/plan/v2alpha1"
    path.write_text(
        json.dumps(legacy, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    repeated = module.plan_traffic(
        profile_name="ipv4-udp",
        path_name="cc-switch",
        parameters=["frame-size=256"],
        rate="1gbps",
        duration="30s",
    )

    assert repeated.plan_id == plan.plan_id
    assert json.loads(path.read_text(encoding="utf-8"))["apiVersion"] == (
        "trex.example.io/plan/v2alpha1"
    )
    assert module.get(plan.plan_id).payload()["apiVersion"] == (
        "trex.example.io/test-plan/v1"
    )


def test_rfc2544_plan_freezes_generic_dut_report_context(tmp_path: Path) -> None:
    module = _module(tmp_path)

    plan = module.plan_rfc2544_suite(
        profile_name="ipv4-udp",
        path_name="cc-switch",
        mode="fast",
    )

    context = plan.document.spec.report_context
    assert context is not None
    assert context.dut.name == "cc-switch"
    assert context.topology == "lab-west -> DUT -> lab-east"


def test_traffic_intent_rejects_undeclared_or_out_of_range_parameters(tmp_path: Path) -> None:
    module = _module(tmp_path)

    with pytest.raises(PlanError, match="unknown profile parameter"):
        module.plan_traffic(
            profile_name="ipv4-udp",
            path_name="cc-switch",
            parameters=["packet.frameSize=256"],
            rate="1gbps",
            duration="30s",
        )
    with pytest.raises(PlanError, match="exceeds its maximum"):
        module.plan_traffic(
            profile_name="ipv4-udp",
            path_name="cc-switch",
            parameters=["frame-size=9000"],
            rate="1gbps",
            duration="30s",
        )


def test_multiple_flows_share_per_egress_rate_without_implicit_reversal(tmp_path: Path) -> None:
    profile = _profile()
    flows = profile["flows"]
    assert isinstance(flows, dict)
    flows["second-flow"] = flows["client-to-server"]
    module = _module(tmp_path, profile)

    plan = module.plan_traffic(
        profile_name="ipv4-udp",
        path_name="cc-switch",
        rate="1000pps",
        duration="1s",
    )

    assert plan.flow_names == ("client-to-server", "second-flow")
    assert [stream.rate.value for stream in plan.document.spec.streams] == [500, 500]
    assert [stream.tx for stream in plan.document.spec.streams] == ["lab-west", "lab-west"]


def test_frame_distribution_and_explicit_reverse_flow_expand_to_weighted_streams(
    tmp_path: Path,
) -> None:
    profile = _profile()
    flows = profile["flows"]
    assert isinstance(flows, dict)
    forward = flows["client-to-server"]
    assert isinstance(forward, dict)
    forward["frame"] = {
        "sizes": [
            {"wireSize": 64, "weight": 60},
            {"wireSize": 512, "weight": 40},
        ]
    }
    flows["server-to-client"] = {
        "from": "server",
        "to": "client",
        "frame": {"wireSize": 128},
        "packet": {
            "ethernet": {
                "src": "${role.server.mac}",
                "dst": "${role.client.mac}",
            },
            "ipv4": {
                "src": "${role.server.ipv4}",
                "dst": "${role.client.ipv4}",
            },
            "udp": {"srcPort": 7, "dstPort": 49152},
        },
    }
    module = _module(tmp_path, profile)

    plan = module.plan_traffic(
        profile_name="ipv4-udp",
        path_name="cc-switch",
        rate="1000pps",
        duration="10s",
    )

    streams = plan.document.spec.streams
    assert [(item.name, item.tx, item.rx) for item in streams] == [
        ("client-to-server/64", "lab-west", "lab-east"),
        ("client-to-server/512", "lab-west", "lab-east"),
        ("server-to-client", "lab-east", "lab-west"),
    ]
    assert [item.rate.value for item in streams] == [600, 400, 1000]
    assert streams[2].packet.ethernet.src == "00:00:00:00:00:02"
    assert streams[2].packet.udp is not None
    assert streams[2].packet.udp.src_port == 7


def test_rfc2544_plan_selects_one_flow_and_method_overrides_profile_frame_sizes(
    tmp_path: Path,
) -> None:
    module = _module(tmp_path)

    plan = module.plan_rfc2544_throughput(
        profile_name="ipv4-udp",
        path_name="cc-switch",
        parameters=["frame-size=256"],
        mode="fast",
        frame_sizes=[64, 512],
    )

    assert plan.document.spec.packet.ipv4 is not None
    assert plan.document.spec.frame_sizes == [64, 512]
    assert plan.payload()["resolvedFrameSizes"] == {
        "source": "method",
        "profileValueOverridden": True,
        "values": [64, 512],
    }
    assert module.get(plan.plan_id).payload() == plan.payload()


def test_rfc2544_plan_compiles_an_ordered_suite(tmp_path: Path) -> None:
    module = _module(tmp_path)

    plan = module.plan_rfc2544_throughput(
        profile_name="ipv4-udp",
        path_name="cc-switch",
        mode="fast",
        frame_sizes=[64],
        tests=("throughput", "frame-loss"),
    )

    assert plan.document.kind == "Rfc2544Suite"
    assert plan.document.spec.tests == ["throughput", "frame-loss"]
    assert plan.payload()["method"]["tests"] == ["throughput", "frame-loss"]
    assert module.get(plan.plan_id).payload() == plan.payload()


def test_rfc2544_plan_freezes_complete_suite_method_settings(tmp_path: Path) -> None:
    profile = _profile()
    flows = profile["flows"]
    assert isinstance(flows, dict)
    flows["client-to-new-network"] = {
        "from": "client",
        "to": "server",
        "frame": {"wireSize": "${param.frame-size}"},
        "packet": {
            "ethernet": {
                "src": "${role.client.mac}",
                "dst": "00:00:00:00:00:03",
            },
            "ipv4": {
                "src": "${role.client.ipv4}",
                "dst": "198.19.1.1",
            },
            "udp": {"srcPort": 49152, "dstPort": 7},
        },
    }
    module = _module(tmp_path, profile)

    plan = module.plan_rfc2544_suite(
        profile_name="ipv4-udp",
        path_name="cc-switch",
        flow_name="client-to-server",
        mode="strict",
        tests=("throughput", "latency", "frame-loss", "back-to-back"),
        latency={
            "definition": "store-and-forward",
            "scenarios": ["same-destination", "new-destination"],
        },
        latency_new_destination_flow_name="client-to-new-network",
        back_to_back={"maximumBurstFrames": 1000000},
    )

    assert plan.document.spec.latency is not None
    assert plan.document.spec.latency.repetitions == 20
    assert plan.document.spec.latency.new_destination_packet is not None
    assert plan.document.spec.latency.new_destination_packet.ipv4 is not None
    assert plan.document.spec.latency.new_destination_packet.ipv4.dst == "198.19.1.1"
    assert plan.payload()["method"]["latencyNewDestinationFlow"] == ("client-to-new-network")
    assert plan.document.spec.back_to_back is not None
    assert plan.document.spec.back_to_back.maximum_burst_frames == 1000000
    assert module.get(plan.plan_id).payload() == plan.payload()


def test_rfc2544_requires_an_explicit_flow_for_a_multi_flow_profile(tmp_path: Path) -> None:
    profile = _profile()
    flows = profile["flows"]
    assert isinstance(flows, dict)
    flows["second-flow"] = flows["client-to-server"]
    module = _module(tmp_path, profile)

    with pytest.raises(PlanError, match="explicit --forward"):
        module.plan_rfc2544_throughput(
            profile_name="ipv4-udp",
            path_name="cc-switch",
        )


@pytest.mark.parametrize("direction_mode", ["bidirectional-simultaneous", "unidirectional-each"])
def test_rfc2544_two_direction_modes_require_explicit_mirrored_flows(
    tmp_path: Path, direction_mode: str
) -> None:
    profile = _profile()
    flows = profile["flows"]
    assert isinstance(flows, dict)
    flows["server-to-client"] = {
        "from": "server",
        "to": "client",
        "frame": {"wireSize": 128},
        "packet": {
            "ethernet": {
                "src": "${role.server.mac}",
                "dst": "${role.client.mac}",
            },
            "ipv4": {
                "src": "${role.server.ipv4}",
                "dst": "${role.client.ipv4}",
            },
            "udp": {"srcPort": 7, "dstPort": 49152},
        },
    }
    module = _module(tmp_path, profile)

    plan = module.plan_rfc2544_throughput(
        profile_name="ipv4-udp",
        path_name="cc-switch",
        flow_name="client-to-server",
        reverse_flow_name="server-to-client",
        direction_mode=direction_mode,  # type: ignore[arg-type]
        mode="fast",
        frame_sizes=[64],
    )

    assert plan.direction_mode == direction_mode
    assert plan.document.spec.ports.direction == "bidirectional"
    assert plan.document.spec.reverse_packet is not None
    assert plan.document.spec.reverse_packet.ethernet.src == "00:00:00:00:00:02"
    assert plan.payload()["method"]["reverseFlow"] == "server-to-client"
