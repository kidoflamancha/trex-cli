from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from trex_cli.cli import app

from .conftest import stateless_document


def test_cli_exposes_expected_commands() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "run" in result.stdout
    assert "job" in result.stdout
    assert "artifact" in result.stdout
    assert "auth" in result.stdout
    assert "profile" in result.stdout
    assert "plan" in result.stdout
    assert "traffic" in result.stdout
    assert "benchmark" in result.stdout
    assert "pcap" in result.stdout

    storm = CliRunner().invoke(app, ["traffic", "storm", "dns", "--help"])
    assert storm.exit_code == 0
    assert "plan" in storm.stdout
    assert "run" in storm.stdout

    dhcp_storm = CliRunner().invoke(app, ["traffic", "storm", "dhcp", "--help"])
    assert dhcp_storm.exit_code == 0
    assert "plan" in dhcp_storm.stdout
    assert "run" in dhcp_storm.stdout

    pcap = CliRunner().invoke(app, ["pcap", "--help"])
    assert pcap.exit_code == 0
    assert "workload-plan" in pcap.stdout
    assert "workload-run" in pcap.stdout
    assert "udp-workload-plan" in pcap.stdout
    assert "udp-workload-run" in pcap.stdout


def test_cli_reloads_agent_authentication(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[httpx.Request] = []

    class FakeClient:
        def __init__(self, **_: object) -> None: ...

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_: object) -> None: ...

        def post(self, url: str, **kwargs: object) -> httpx.Response:
            request = httpx.Request("POST", url, headers=kwargs["headers"])
            requests.append(request)
            return httpx.Response(
                200,
                request=request,
                json={
                    "status": "reloaded",
                    "credentials": [{"name": "operator", "role": "operator"}],
                },
            )

    monkeypatch.setattr("trex_cli.cli.httpx.Client", FakeClient)
    result = CliRunner().invoke(
        app,
        ["--token", "old-secret", "auth", "reload", "--output", "json"],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "reloaded"
    assert requests[0].url.path == "/v1/maintenance/auth:reload"
    assert requests[0].headers["Authorization"] == "Bearer old-secret"


def test_cli_artifact_cleanup_is_a_dry_run_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[httpx.Request] = []

    class FakeClient:
        def __init__(self, **_: object) -> None: ...

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_: object) -> None: ...

        def post(self, url: str, **kwargs: object) -> httpx.Response:
            request = httpx.Request("POST", url, headers=kwargs["headers"], json=kwargs["json"])
            requests.append(request)
            payload = json.loads(request.content)
            return httpx.Response(
                200,
                request=request,
                json={
                    "dryRun": payload["dryRun"],
                    "expiredRecords": 2,
                    "deletedRecords": 0,
                    "missingFiles": 0,
                    "orphanFiles": 1,
                    "deletedOrphans": 0,
                    "reclaimedBytes": 0,
                    "failures": [],
                },
            )

    monkeypatch.setattr("trex_cli.cli.httpx.Client", FakeClient)
    result = CliRunner().invoke(
        app,
        ["--token", "secret", "artifact", "cleanup", "--output", "json"],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["dryRun"] is True
    assert requests[0].url.path == "/v1/maintenance/artifacts:cleanup"
    assert json.loads(requests[0].content) == {"dryRun": True, "deleteOrphans": False}

    applied = CliRunner().invoke(
        app,
        [
            "--token",
            "secret",
            "artifact",
            "cleanup",
            "--apply",
            "--delete-orphans",
            "--yes",
            "--output",
            "json",
        ],
    )
    assert applied.exit_code == 0
    assert json.loads(requests[1].content) == {"dryRun": False, "deleteOrphans": True}


def test_cli_plans_a_udp_capture_workload(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[httpx.Request] = []

    class FakeClient:
        def __init__(self, **_: object) -> None: ...

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_: object) -> None: ...

        def post(self, url: str, **kwargs: object) -> httpx.Response:
            request = httpx.Request("POST", url, headers=kwargs["headers"], json=kwargs["json"])
            requests.append(request)
            return httpx.Response(
                201,
                request=request,
                json={
                    "planId": "plan_0123456789abcdef01234567",
                    "intent": "pcap-udp-workload",
                    "resources": {
                        "capture": {
                            "kind": "CaptureResource",
                            "name": "regression/dns",
                            "revision": 1,
                            "ref": "regression/dns@1",
                            "digest": "sha256:" + "1" * 64,
                        },
                        "path": {
                            "kind": "LabPath",
                            "name": "cc-switch",
                            "revision": 1,
                            "ref": "cc-switch@1",
                            "digest": "sha256:" + "2" * 64,
                        },
                    },
                    "safety": {"isolatedLab": True},
                    "plan": {"document": {"kind": "UdpWorkload"}},
                },
            )

    monkeypatch.setattr("trex_cli.cli.httpx.Client", FakeClient)
    result = CliRunner().invoke(
        app,
        [
            "--token",
            "secret",
            "pcap",
            "udp-workload-plan",
            "--capture",
            "regression/dns",
            "--path",
            "cc-switch",
            "--initiator",
            "client",
            "--responder",
            "server",
            "--fps",
            "30",
            "--duration",
            "3s",
            "--output",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["intent"] == "pcap-udp-workload"
    assert json.loads(requests[0].content) == {
        "kind": "pcap-udp-workload",
        "capture": "regression/dns",
        "path": "cc-switch",
        "initiatorRole": "client",
        "responderRole": "server",
        "fps": 30.0,
        "duration": "3s",
    }


def test_cli_plans_a_dns_query_storm(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[httpx.Request] = []

    class FakeClient:
        def __init__(self, **_: object) -> None: ...

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_: object) -> None: ...

        def post(self, url: str, **kwargs: object) -> httpx.Response:
            request = httpx.Request("POST", url, headers=kwargs["headers"], json=kwargs["json"])
            requests.append(request)
            return httpx.Response(
                201,
                request=request,
                json={
                    "planId": "plan_0123456789abcdef01234567",
                    "intent": "dns-storm",
                    "resources": {
                        "path": {
                            "kind": "LabPath",
                            "name": "cc-switch",
                            "revision": 1,
                            "ref": "cc-switch@1",
                            "digest": "sha256:" + "2" * 64,
                        }
                    },
                    "safety": {"isolatedLab": True},
                    "plan": {"document": {"kind": "PacketStorm"}},
                },
            )

    monkeypatch.setattr("trex_cli.cli.httpx.Client", FakeClient)
    result = CliRunner().invoke(
        app,
        [
            "--token",
            "secret",
            "traffic",
            "storm",
            "dns",
            "plan",
            "--path",
            "cc-switch",
            "--client",
            "client",
            "--server",
            "server",
            "--name",
            "www.example.test",
            "--type",
            "AAAA",
            "--source-port-start",
            "40000",
            "--source-port-end",
            "40003",
            "--pps",
            "100",
            "--duration",
            "3s",
            "--output",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["intent"] == "dns-storm"
    assert json.loads(requests[0].content) == {
        "kind": "dns-storm",
        "path": "cc-switch",
        "clientRole": "client",
        "serverRole": "server",
        "name": "www.example.test",
        "queryType": "AAAA",
        "recursionDesired": True,
        "sourcePortStart": 40000,
        "sourcePortEnd": 40003,
        "pps": 100.0,
        "duration": "3s",
    }


def test_cli_plans_a_dhcp_discover_storm(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[httpx.Request] = []

    class FakeClient:
        def __init__(self, **_: object) -> None: ...

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_: object) -> None: ...

        def post(self, url: str, **kwargs: object) -> httpx.Response:
            request = httpx.Request("POST", url, headers=kwargs["headers"], json=kwargs["json"])
            requests.append(request)
            return httpx.Response(
                201,
                request=request,
                json={
                    "planId": "plan_0123456789abcdef01234567",
                    "intent": "dhcp-storm",
                    "resources": {
                        "path": {
                            "kind": "LabPath",
                            "name": "cc-switch",
                            "revision": 1,
                            "ref": "cc-switch@1",
                            "digest": "sha256:" + "2" * 64,
                        }
                    },
                    "safety": {"isolatedLab": True},
                    "plan": {"document": {"kind": "PacketStorm"}},
                },
            )

    monkeypatch.setattr("trex_cli.cli.httpx.Client", FakeClient)
    result = CliRunner().invoke(
        app,
        [
            "--token",
            "secret",
            "traffic",
            "storm",
            "dhcp",
            "plan",
            "--path",
            "cc-switch",
            "--client",
            "client",
            "--server",
            "server",
            "--clients",
            "4",
            "--pps",
            "100",
            "--duration",
            "3s",
            "--output",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["intent"] == "dhcp-storm"
    assert json.loads(requests[0].content) == {
        "kind": "dhcp-storm",
        "path": "cc-switch",
        "clientRole": "client",
        "serverRole": "server",
        "clients": 4,
        "pps": 100.0,
        "duration": "3s",
    }


def test_cli_plans_an_arp_request_storm(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[httpx.Request] = []

    class FakeClient:
        def __init__(self, **_: object) -> None: ...

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_: object) -> None: ...

        def post(self, url: str, **kwargs: object) -> httpx.Response:
            request = httpx.Request("POST", url, headers=kwargs["headers"], json=kwargs["json"])
            requests.append(request)
            return httpx.Response(
                201,
                request=request,
                json={
                    "planId": "plan_0123456789abcdef01234567",
                    "intent": "arp-storm",
                    "resources": {
                        "path": {
                            "kind": "LabPath",
                            "name": "cc-switch",
                            "revision": 1,
                            "ref": "cc-switch@1",
                            "digest": "sha256:" + "2" * 64,
                        }
                    },
                    "safety": {"isolatedLab": True},
                    "plan": {"document": {"kind": "PacketStorm"}},
                },
            )

    monkeypatch.setattr("trex_cli.cli.httpx.Client", FakeClient)
    result = CliRunner().invoke(
        app,
        [
            "--token",
            "secret",
            "traffic",
            "storm",
            "arp",
            "plan",
            "--path",
            "cc-switch",
            "--sender",
            "client",
            "--target",
            "server",
            "--senders",
            "4",
            "--pps",
            "100",
            "--duration",
            "3s",
            "--output",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["intent"] == "arp-storm"
    assert json.loads(requests[0].content) == {
        "kind": "arp-storm",
        "path": "cc-switch",
        "senderRole": "client",
        "targetRole": "server",
        "senders": 4,
        "pps": 100.0,
        "duration": "3s",
    }


def test_cli_plans_all_reconstructible_capture_flows(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[httpx.Request] = []

    class FakeClient:
        def __init__(self, **_: object) -> None:
            pass

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def post(self, url: str, **kwargs: object) -> httpx.Response:
            request = httpx.Request(
                "POST",
                url,
                headers=kwargs["headers"],
                json=kwargs["json"],
            )
            requests.append(request)
            return httpx.Response(
                201,
                request=request,
                json={
                    "planId": "plan_0123456789abcdef01234567",
                    "intent": "pcap-capture-workload",
                    "resources": {
                        "capture": {
                            "kind": "CaptureResource",
                            "name": "regression/http",
                            "revision": 1,
                            "ref": "regression/http@1",
                            "digest": "sha256:" + "1" * 64,
                        },
                        "path": {
                            "kind": "LabPath",
                            "name": "cc-switch",
                            "revision": 1,
                            "ref": "cc-switch@1",
                            "digest": "sha256:" + "2" * 64,
                        },
                    },
                    "safety": {"isolatedLab": True},
                    "plan": {"document": {"kind": "StatefulReplay"}},
                },
            )

    monkeypatch.setattr("trex_cli.cli.httpx.Client", FakeClient)
    result = CliRunner().invoke(
        app,
        [
            "--token",
            "secret",
            "pcap",
            "workload-plan",
            "--capture",
            "regression/http",
            "--path",
            "cc-switch",
            "--client",
            "client",
            "--server",
            "server",
            "--cps",
            "30",
            "--max-active",
            "20",
            "--duration",
            "3s",
            "--output",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["intent"] == "pcap-capture-workload"
    request_body = json.loads(requests[0].content)
    assert request_body["kind"] == "pcap-capture-workload"
    assert "sessionId" not in request_body


def test_cli_streams_a_capture_to_the_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "smoke.pcap"
    source.write_bytes(b"pcap payload")
    requests: list[httpx.Request] = []

    class FakeClient:
        def __init__(self, **_: object) -> None:
            pass

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def post(self, url: str, **kwargs: object) -> httpx.Response:
            content = kwargs["content"]
            assert hasattr(content, "read")
            request = httpx.Request(
                "POST",
                url,
                headers=kwargs["headers"],
                params=kwargs["params"],
                content=content.read(),
            )
            requests.append(request)
            return httpx.Response(
                201,
                request=request,
                json={
                    "kind": "CaptureResource",
                    "name": "regression/smoke",
                    "revision": 1,
                    "ref": "regression/smoke@1",
                    "digest": "sha256:" + "1" * 64,
                    "document": {"analysis": {"packetCount": 1}},
                },
            )

    monkeypatch.setattr("trex_cli.cli.httpx.Client", FakeClient)
    result = CliRunner().invoke(
        app,
        [
            "--token",
            "secret",
            "pcap",
            "publish",
            str(source),
            "--name",
            "regression/smoke",
            "--output",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["ref"] == "regression/smoke@1"
    assert requests[0].url.path == "/v1/catalog/captures"
    assert requests[0].url.params["name"] == "regression/smoke"
    assert requests[0].content == b"pcap payload"


def test_cli_creates_a_plan_without_agent_credentials(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir()
    (profile_dir / "cc-switch.yaml").write_text(json.dumps(stateless_document()), encoding="utf-8")
    plans_dir = tmp_path / "plans"

    result = CliRunner().invoke(
        app,
        [
            "plan",
            "stateless",
            "--profile",
            "cc-switch",
            "--profile-dir",
            str(profile_dir),
            "--plans-dir",
            str(plans_dir),
            "--set",
            "packet.frameSize=256",
        ],
    )

    assert result.exit_code == 0
    assert "Plan: plan_" in result.stdout
    assert (plans_dir / f"{result.stdout.splitlines()[0].removeprefix('Plan: ')}.json").exists()


def test_cli_plans_typed_traffic_intent_without_agent_credentials(tmp_path: Path) -> None:
    profile_dir = tmp_path / "traffic-profiles"
    path_dir = tmp_path / "lab-paths"
    plans_dir = tmp_path / "plans"
    profile_dir.mkdir()
    path_dir.mkdir()
    source_root = Path(__file__).parents[1]
    (profile_dir / "ipv4-udp.yaml").write_text(
        (source_root / "traffic-profiles" / "ipv4-udp.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (path_dir / "cc-switch.yaml").write_text(
        (source_root / "lab-paths" / "cc-switch.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "traffic",
            "plan",
            "--profile",
            "ipv4-udp",
            "--path",
            "cc-switch",
            "--rate",
            "1gbps",
            "--duration",
            "30s",
            "--param",
            "frame-size=256",
            "--profile-dir",
            str(profile_dir),
            "--path-dir",
            str(path_dir),
            "--plans-dir",
            str(plans_dir),
        ],
    )

    assert result.exit_code == 0
    assert "Intent: traffic" in result.stdout
    assert "Rate: 1gbps per-egress" in result.stdout
    assert "Frames: 256B wire/252B generated/276B L1" in result.stdout


def test_cli_plans_rfc2544_from_the_same_traffic_profile(tmp_path: Path) -> None:
    profile_dir = tmp_path / "traffic-profiles"
    path_dir = tmp_path / "lab-paths"
    plans_dir = tmp_path / "plans"
    profile_dir.mkdir()
    path_dir.mkdir()
    source_root = Path(__file__).parents[1]
    (profile_dir / "ipv4-udp.yaml").write_text(
        (source_root / "traffic-profiles" / "ipv4-udp.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (path_dir / "cc-switch.yaml").write_text(
        (source_root / "lab-paths" / "cc-switch.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            "rfc2544",
            "plan",
            "--profile",
            "ipv4-udp",
            "--path",
            "cc-switch",
            "--mode",
            "fast",
            "--frame-size",
            "64",
            "--frame-size",
            "512",
            "--profile-dir",
            str(profile_dir),
            "--path-dir",
            str(path_dir),
            "--plans-dir",
            str(plans_dir),
        ],
    )

    assert result.exit_code == 0
    assert "Intent: benchmark-rfc2544" in result.stdout
    assert "Tests: throughput" in result.stdout
    assert "Frame sizes (wire/FCS included): 64, 512" in result.stdout


def test_cli_plans_throughput_and_frame_loss_suite(tmp_path: Path) -> None:
    profile_dir = tmp_path / "traffic-profiles"
    path_dir = tmp_path / "lab-paths"
    plans_dir = tmp_path / "plans"
    profile_dir.mkdir()
    path_dir.mkdir()
    source_root = Path(__file__).parents[1]
    (profile_dir / "ipv4-udp.yaml").write_text(
        (source_root / "traffic-profiles" / "ipv4-udp.yaml").read_text(),
        encoding="utf-8",
    )
    (path_dir / "cc-switch.yaml").write_text(
        (source_root / "lab-paths" / "cc-switch.yaml").read_text(),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            "rfc2544",
            "plan",
            "--profile",
            "ipv4-udp",
            "--path",
            "cc-switch",
            "--frame-size",
            "64",
            "--test",
            "throughput",
            "--test",
            "frame-loss",
            "--profile-dir",
            str(profile_dir),
            "--path-dir",
            str(path_dir),
            "--plans-dir",
            str(plans_dir),
        ],
    )

    assert result.exit_code == 0
    assert "Tests: throughput, frame-loss" in result.stdout


def test_cli_plans_complete_publishable_rfc2544_suite(tmp_path: Path) -> None:
    profile_dir = tmp_path / "traffic-profiles"
    path_dir = tmp_path / "lab-paths"
    plans_dir = tmp_path / "plans"
    profile_dir.mkdir()
    path_dir.mkdir()
    source_root = Path(__file__).parents[1]
    profile_text = (source_root / "traffic-profiles" / "ipv4-udp.yaml").read_text()
    profile_text += """
  client-to-new-network:
    from: client
    to: server
    frame:
      wireSize: "${param.frame-size}"
    packet:
      ethernet:
        src: "${role.client.mac}"
        dst: "00:00:00:00:00:03"
      ipv4:
        src: "${role.client.ipv4}"
        dst: "198.19.1.1"
      udp:
        srcPort: 49152
        dstPort: 7
"""
    (profile_dir / "ipv4-udp.yaml").write_text(profile_text, encoding="utf-8")
    (path_dir / "cc-switch.yaml").write_text(
        (source_root / "lab-paths" / "cc-switch.yaml").read_text(),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            "rfc2544",
            "plan",
            "--profile",
            "ipv4-udp",
            "--path",
            "cc-switch",
            "--forward",
            "client-to-server",
            "--mode",
            "strict",
            "--test",
            "throughput",
            "--test",
            "latency",
            "--test",
            "frame-loss",
            "--test",
            "back-to-back",
            "--latency-definition",
            "store-and-forward",
            "--latency-scenario",
            "same-destination",
            "--latency-scenario",
            "new-destination",
            "--latency-new-destination-flow",
            "client-to-new-network",
            "--back-to-back-max-burst-frames",
            "1000000",
            "--profile-dir",
            str(profile_dir),
            "--path-dir",
            str(path_dir),
            "--plans-dir",
            str(plans_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Tests: throughput, latency, frame-loss, back-to-back" in result.stdout


def test_cli_plans_explicit_simultaneous_rfc2544_flows(tmp_path: Path) -> None:
    profile_dir = tmp_path / "traffic-profiles"
    path_dir = tmp_path / "lab-paths"
    plans_dir = tmp_path / "plans"
    profile_dir.mkdir()
    path_dir.mkdir()
    source_root = Path(__file__).parents[1]
    (profile_dir / "bidirectional-imix.yaml").write_text(
        (source_root / "traffic-profiles" / "bidirectional-imix.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (path_dir / "cc-switch.yaml").write_text(
        (source_root / "lab-paths" / "cc-switch.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            "rfc2544",
            "plan",
            "--profile",
            "bidirectional-imix",
            "--path",
            "cc-switch",
            "--direction-mode",
            "bidirectional-simultaneous",
            "--forward",
            "client-to-server",
            "--reverse",
            "server-to-client",
            "--frame-size",
            "64",
            "--profile-dir",
            str(profile_dir),
            "--path-dir",
            str(path_dir),
            "--plans-dir",
            str(plans_dir),
        ],
    )

    assert result.exit_code == 0
    assert "Flow: client-to-server" in result.stdout
    assert "Reverse flow: server-to-client" in result.stdout
    assert "Direction mode: bidirectional-simultaneous" in result.stdout


def test_authenticated_intent_cli_plans_through_http_test_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[httpx.Request] = []

    class FakeClient:
        def __init__(self, **_: object) -> None:
            pass

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def post(
            self, url: str, *, headers: dict[str, str], json: dict[str, object]
        ) -> httpx.Response:
            request = httpx.Request("POST", url, headers=headers, json=json)
            requests.append(request)
            return httpx.Response(
                201,
                request=request,
                json={
                    "planId": "plan_0123456789abcdef01234567",
                    "intent": "traffic",
                    "resources": {
                        "profile": {
                            "kind": "TrafficProfile",
                            "name": "ipv4-udp",
                            "revision": 1,
                            "ref": "ipv4-udp@1",
                            "digest": "sha256:" + "1" * 64,
                        },
                        "path": {
                            "kind": "LabPath",
                            "name": "cc-switch",
                            "revision": 1,
                            "ref": "cc-switch@1",
                            "digest": "sha256:" + "2" * 64,
                        },
                    },
                    "safety": {"isolatedLab": True},
                    "plan": {"load": {"scope": "per-egress", "requested": "1000pps"}},
                },
            )

    monkeypatch.setattr("trex_cli.cli.httpx.Client", FakeClient)

    result = CliRunner().invoke(
        app,
        [
            "--token",
            "secret",
            "traffic",
            "plan",
            "--profile",
            "ipv4-udp",
            "--path",
            "cc-switch",
            "--rate",
            "1000pps",
            "--duration",
            "1s",
            "--output",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["resources"]["profile"]["ref"] == "ipv4-udp@1"
    assert requests[0].url.path == "/v1/plans"
    assert json.loads(requests[0].content)["kind"] == "traffic"
