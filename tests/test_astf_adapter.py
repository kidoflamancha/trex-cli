from __future__ import annotations

import asyncio
import time
from io import BytesIO
from pathlib import Path
from typing import Any, ClassVar

import pytest

from trex_cli.astf_adapter import RemoteTrexAstfEngine
from trex_cli.config import RemoteTrexAstfEngineConfig
from trex_cli.engine import ExecutionMarker
from trex_cli.errors import TrexCliError
from trex_cli.models import StatefulReplayDocument, utc_now
from trex_cli.test_plan import TestPlanModule as PlanModule

from .conftest import make_config
from .test_test_control import _http_session_pcap, _http_workload_pcap, _write_resources


class FakeProgram:
    instances: ClassVar[list[FakeProgram]] = []

    def __init__(self) -> None:
        self.commands: list[tuple[str, bytes | int]] = []
        self.instances.append(self)

    def send(self, payload: bytes) -> None:
        self.commands.append(("send", payload))

    def recv(self, size: int) -> None:
        self.commands.append(("recv", size))


class Record:
    def __init__(self, **values: Any) -> None:
        self.values = values


class FakeApi:
    ASTFProgram = FakeProgram
    ASTFIPGenDist = Record
    ASTFIPGenGlobal = Record
    ASTFIPGen = Record
    ASTFTCPClientTemplate = Record
    ASTFAssociationRule = Record
    ASTFTCPServerTemplate = Record
    ASTFTemplate = Record
    ASTFProfile = Record


class FakeAstfClient:
    def __init__(self, **values: Any) -> None:
        self.values = values
        self.loaded: Any | None = None
        self.started: dict[str, Any] | None = None
        self.stopped = False
        self.released = False
        self.disconnected = False

    def connect(self) -> None: ...

    def acquire(self, force: bool = False) -> None:
        assert force is False

    def get_port_count(self) -> int:
        return 2

    def get_port_info(self) -> list[dict[str, Any]]:
        return [{"speed": 2.5}, {"speed": 2.5}]

    def get_server_version(self) -> dict[str, str]:
        return {"Version": "v3.08"}

    def load_profile(self, profile: Any) -> None:
        self.loaded = profile

    def clear_stats(self) -> None: ...

    def start(self, **values: Any) -> None:
        self.started = values

    def get_stats(self) -> dict[str, Any]:
        return {
            "traffic": {
                "client": {
                    "tcps_connattempt": 10,
                    "tcps_connects": 9,
                    "tcps_closed": 9,
                    "tcps_sndbyte": 315,
                    "tcps_rcvbyte": 360,
                },
                "server": {"tcps_sndbyte": 360, "tcps_rcvbyte": 315},
            }
        }

    def get_warnings(self) -> list[str]:
        return []

    def get_traffic_tg_stats(self, tg_names: list[str]) -> dict[str, Any]:
        return {
            name: {
                "client": {
                    "tcps_connattempt": 5,
                    "tcps_connects": 4,
                    "tcps_closed": 4,
                    "tcps_sndbyte": 175,
                    "tcps_rcvbyte": 200,
                },
                "server": {"tcps_sndbyte": 200, "tcps_rcvbyte": 175},
            }
            for name in tg_names
        }

    def stop(self, block: bool = True) -> None:
        self.stopped = True

    def clear_profile(self, block: bool = True) -> None: ...

    def release(self, force: bool = False) -> None:
        self.released = True

    def disconnect(self) -> None:
        self.disconnected = True


def _document(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    client_ipv4_end: str = "198.18.0.4",
    server_ipv4_end: str = "198.19.0.4",
) -> StatefulReplayDocument:
    profile_root, path_root, plan_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    plans = PlanModule(
        profile_root,
        path_root,
        plan_root,
        tmp_path / "captures",
        config.safety,
    )
    capture = plans.publish_capture(
        name="regression/http-session", source=BytesIO(_http_session_pcap())
    )
    stateful = capture.document.analysis.stateful
    assert stateful is not None
    session = stateful.sessions[0]
    return plans.plan_stateful_replay(
        capture_name=capture.ref,
        session_id=session.id,
        path_name="cc-switch",
        client_role="client",
        server_role="server",
        cps=10,
        max_active_connections=20,
        duration="1s",
        client_ipv4_start="198.18.0.1",
        client_ipv4_end=client_ipv4_end,
        server_ipv4_start="198.19.0.1",
        server_ipv4_end=server_ipv4_end,
    ).document


def _workload_document(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> StatefulReplayDocument:
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
        name="regression/http-workload",
        source=BytesIO(_http_workload_pcap()),
    )
    return plans.plan_capture_workload(
        capture_name="regression/http-workload",
        path_name="cc-switch",
        client_role="client",
        server_role="server",
        cps=30,
        max_active_connections=20,
        duration="1s",
        client_ipv4_start="198.18.0.1",
        client_ipv4_end="198.18.0.4",
        server_ipv4_start="198.19.0.1",
        server_ipv4_end="198.19.0.8",
    ).document


@pytest.mark.asyncio
async def test_remote_astf_engine_builds_runs_and_measures_a_session_template(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    FakeProgram.instances.clear()
    client = FakeAstfClient()
    config = RemoteTrexAstfEngineConfig.model_validate(
        {
            "mode": "remote-astf",
            "server": "127.0.0.1",
            "clientPath": str(tmp_path),
            "externalLibsPath": str(tmp_path),
            "username": "test-astf",
            "portMapping": {"lab-west": 0, "lab-east": 1},
        }
    )
    document = _document(tmp_path, monkeypatch)
    engine = RemoteTrexAstfEngine(
        config,
        capture_root=tmp_path / "captures",
        client_factory=lambda **_: client,
        client_api=FakeApi,
        sleep=lambda _: _no_sleep(),
    )

    await engine.validate(document)
    handle = await engine.prepare(
        ExecutionMarker(
            marker_id="marker_test",
            job_id="job_test",
            session_id="agent_session",
            logical_ports=("lab-east", "lab-west"),
            fence={"lab-east": 1, "lab-west": 1},
            hard_deadline=utc_now(),
        ),
        document,
    )
    await engine.warmup(handle)
    measurement = await engine.run(handle)

    request = b"GET /health HTTP/1.1\r\nHost: dut\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    assert FakeProgram.instances[0].commands == [("send", request), ("recv", len(response))]
    assert FakeProgram.instances[1].commands == [("recv", len(request)), ("send", response)]
    assert client.loaded is not None
    assert client.started == {
        "mult": 1,
        "duration": 1.0,
        "nc": False,
        "e_duration": 20.0,
        "t_duration": 20.0,
        "block": False,
    }
    assert measurement.methodology == "trex-astf-stateful-replay/v1"
    assert measurement.summary["attemptedConnections"] == 10
    assert measurement.summary["establishedConnections"] == 9
    assert measurement.summary["failedConnections"] == 1
    assert measurement.summary["closedConnections"] == 9
    assert measurement.summary["applicationTxBytes"] == 315
    assert measurement.summary["applicationRxBytes"] == 360
    assert measurement.summary["throughputBps"] == 5400.0
    assert measurement.summary["semanticDifferences"] == document.spec.semantic_differences
    assert measurement.provenance == {"engine": "remote-astf", "trexVersion": "v3.08"}

    await engine.stop(handle)
    await engine.cleanup(handle)
    assert client.stopped is True
    assert client.released is True
    assert client.disconnected is True


@pytest.mark.asyncio
async def test_remote_astf_engine_runs_weighted_templates_with_traffic_group_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    FakeProgram.instances.clear()
    client = FakeAstfClient()
    config = RemoteTrexAstfEngineConfig.model_validate(
        {
            "mode": "remote-astf",
            "server": "127.0.0.1",
            "clientPath": str(tmp_path),
            "externalLibsPath": str(tmp_path),
            "username": "test-astf",
            "portMapping": {"lab-west": 0, "lab-east": 1},
        }
    )
    document = _workload_document(tmp_path, monkeypatch)
    engine = RemoteTrexAstfEngine(
        config,
        capture_root=tmp_path / "captures",
        client_factory=lambda **_: client,
        client_api=FakeApi,
        sleep=lambda _: _no_sleep(),
    )

    handle = await engine.prepare(
        ExecutionMarker(
            marker_id="marker_workload",
            job_id="job_workload",
            session_id="agent_session",
            logical_ports=("lab-east", "lab-west"),
            fence={"lab-east": 1, "lab-west": 1},
            hard_deadline=utc_now(),
        ),
        document,
    )
    measurement = await engine.run(handle)

    assert client.loaded is not None
    templates = client.loaded.values["templates"]
    assert len(templates) == 2
    assert sorted(template.values["client_template"].values["cps"] for template in templates) == [
        10.0,
        20.0,
    ]
    assert sorted(template.values["client_template"].values["limit"] for template in templates) == [
        7,
        13,
    ]
    associations = [
        template.values["server_template"].values["assoc"].values for template in templates
    ]
    assert associations[0]["ip_end"] < associations[1]["ip_start"]
    assert all(template.values["tg_name"].startswith("tg_") for template in templates)
    assert measurement.methodology == "trex-astf-capture-workload/v1"
    assert measurement.summary["templateCount"] == 2
    assert len(measurement.summary["templates"]) == 2
    assert all(item["attemptedConnections"] == 5 for item in measurement.summary["templates"])
    assert all(item["establishedConnections"] == 4 for item in measurement.summary["templates"])


@pytest.mark.asyncio
async def test_remote_astf_engine_rejects_pools_too_small_for_data_path_threads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class TwoThreadClient(FakeAstfClient):
        def get_port_info(self) -> list[dict[str, Any]]:
            return [
                {"speed": 2.5, "cores": [0, 1]},
                {"speed": 2.5, "cores": [0, 1]},
            ]

    client = TwoThreadClient()
    config = RemoteTrexAstfEngineConfig.model_validate(
        {
            "mode": "remote-astf",
            "server": "127.0.0.1",
            "clientPath": str(tmp_path),
            "externalLibsPath": str(tmp_path),
            "username": "test-astf",
            "portMapping": {"lab-west": 0, "lab-east": 1},
        }
    )
    document = _document(
        tmp_path,
        monkeypatch,
        client_ipv4_end="198.18.0.1",
        server_ipv4_end="198.19.0.1",
    )
    engine = RemoteTrexAstfEngine(
        config,
        capture_root=tmp_path / "captures",
        client_factory=lambda **_: client,
        client_api=FakeApi,
    )

    with pytest.raises(TrexCliError) as raised:
        await engine.prepare(
            ExecutionMarker(
                marker_id="marker_small_pool",
                job_id="job_small_pool",
                session_id="agent_session",
                logical_ports=("lab-east", "lab-west"),
                fence={"lab-east": 1, "lab-west": 1},
                hard_deadline=utc_now(),
            ),
            document,
        )

    assert raised.value.code == "ADDRESS_POOL_EXHAUSTED"
    assert client.loaded is None
    assert client.disconnected is True


@pytest.mark.asyncio
async def test_remote_astf_stop_timeout_fails_closed_without_overlapping_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class SlowStopClient(FakeAstfClient):
        def stop(self, block: bool = True) -> None:
            time.sleep(0.05)
            super().stop(block)

    client = SlowStopClient()
    config = RemoteTrexAstfEngineConfig.model_validate(
        {
            "mode": "remote-astf",
            "server": "127.0.0.1",
            "clientPath": str(tmp_path),
            "externalLibsPath": str(tmp_path),
            "username": "test-astf",
            "timeoutSeconds": 0.01,
            "portMapping": {"lab-west": 0, "lab-east": 1},
        }
    )
    engine = RemoteTrexAstfEngine(
        config,
        capture_root=tmp_path / "captures",
        client_factory=lambda **_: client,
        client_api=FakeApi,
    )
    handle = await engine.prepare(
        ExecutionMarker(
            marker_id="marker_stop_timeout",
            job_id="job_stop_timeout",
            session_id="agent_session",
            logical_ports=("lab-east", "lab-west"),
            fence={"lab-east": 1, "lab-west": 1},
            hard_deadline=utc_now(),
        ),
        _document(tmp_path, monkeypatch),
    )

    with pytest.raises(TrexCliError) as stop_error:
        await engine.stop(handle, force=True)
    with pytest.raises(TrexCliError) as cleanup_error:
        await engine.cleanup(handle)
    await asyncio.sleep(0.06)

    assert stop_error.value.code == "TREX_TIMEOUT"
    assert cleanup_error.value.code == "TREX_TIMEOUT"
    assert client.released is False
    assert client.disconnected is False


async def _no_sleep() -> None:
    return None
