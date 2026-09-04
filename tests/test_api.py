from __future__ import annotations

import asyncio
import sqlite3
import struct
from pathlib import Path

import httpx
import pytest

from trex_cli.api import create_app
from trex_cli.config import AgentConfig, SafetyPolicy
from trex_cli.test_plan import TestPlanModule as PlanModule

from .conftest import config_data, make_config, stateless_document


def _capture_bytes() -> bytes:
    ethernet = bytes.fromhex(
        "00000000000200000000000108004500001c0000000040110000c6120001c6130001c000000700080000"
    )
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
        + struct.pack("<IIII", 1, 250_000, len(ethernet), len(ethernet))
        + ethernet
    )


def _intent_plans(tmp_path: Path, safety: SafetyPolicy | None = None) -> PlanModule:
    source_root = Path(__file__).parents[1]
    profile_root = tmp_path / "traffic-profiles"
    path_root = tmp_path / "lab-paths"
    profile_root.mkdir()
    path_root.mkdir()
    (profile_root / "ipv4-udp.yaml").write_text(
        (source_root / "traffic-profiles" / "ipv4-udp.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (path_root / "cc-switch.yaml").write_text(
        (source_root / "lab-paths" / "cc-switch.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return PlanModule(profile_root, path_root, tmp_path / "plans", safety_policy=safety)


@pytest.mark.asyncio
async def test_auth_roles_readiness_and_job_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = create_app(make_config(tmp_path, monkeypatch))
    transport = httpx.ASGITransport(app=application)
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            ready = await client.get("/readyz")
            assert ready.json()["transportSecurity"] == "insecure-http"
            assert ready.json()["simulated"] is True
            assert ready.json()["engineAvailable"] is True
            assert ready.json()["ports"]["lab-west"]["status"] == "AVAILABLE"
            assert ready.json()["databaseSchemaVersion"] == 1

            calibrations = await client.get(
                "/v1/calibrations",
                headers={"Authorization": "Bearer reader-secret"},
            )
            assert calibrations.status_code == 200
            assert calibrations.json() == {"items": []}

            unauthenticated = await client.get("/v1/jobs/job_UNKNOWN")
            assert unauthenticated.status_code == 401

            reader_submit = await client.post(
                "/v1/jobs",
                headers={
                    "Authorization": "Bearer reader-secret",
                    "Idempotency-Key": "reader-key",
                },
                json={"document": stateless_document()},
            )
            assert reader_submit.status_code == 403

            submitted = await client.post(
                "/v1/jobs",
                headers={
                    "Authorization": "Bearer operator-secret",
                    "Idempotency-Key": "api-key",
                },
                json={"document": stateless_document()},
            )
            assert submitted.status_code == 202
            job_id = submitted.json()["jobId"]

            for _ in range(100):
                response = await client.get(
                    f"/v1/jobs/{job_id}",
                    headers={"Authorization": "Bearer reader-secret"},
                )
                if response.json()["state"] == "SUCCEEDED":
                    break
                await asyncio.sleep(0.01)
            assert response.json()["result"]["provenance"]["simulated"] is True

            artifact = response.json()["result"]["artifacts"][0]
            downloaded = await client.get(
                f"/v1/artifacts/{artifact['digest']}",
                headers={"Authorization": "Bearer reader-secret"},
            )
            assert downloaded.status_code == 200
            assert len(downloaded.content) == artifact["size"]

            metrics = await client.get(
                "/metrics",
                headers={"Authorization": "Bearer reader-secret"},
            )
            assert 'trex_agent_jobs{state="SUCCEEDED"} 1' in metrics.text
            assert (
                'trex_agent_job_transitions_total{current="SUCCEEDED",event="JOB_SUCCEEDED",'
                'kind="StatelessTraffic",previous="COLLECTING"} 1'
            ) in metrics.text
            artifact_count = next(
                line
                for line in metrics.text.splitlines()
                if line.startswith("trex_agent_artifacts ")
            )
            assert int(artifact_count.split()[1]) > 0


@pytest.mark.asyncio
async def test_artifact_cleanup_is_operator_only_and_defaults_to_dry_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = create_app(make_config(tmp_path, monkeypatch))
    transport = httpx.ASGITransport(app=application)
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            reader = await client.post(
                "/v1/maintenance/artifacts:cleanup",
                headers={"Authorization": "Bearer reader-secret"},
                json={},
            )
            response = await client.post(
                "/v1/maintenance/artifacts:cleanup",
                headers={"Authorization": "Bearer operator-secret"},
                json={},
            )

    assert reader.status_code == 403
    assert response.status_code == 200
    assert response.json() == {
        "dryRun": True,
        "expiredRecords": 0,
        "deletedRecords": 0,
        "missingFiles": 0,
        "orphanFiles": 0,
        "deletedOrphans": 0,
        "reclaimedBytes": 0,
        "failures": [],
    }


@pytest.mark.asyncio
async def test_metrics_require_authentication_and_use_route_templates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = create_app(make_config(tmp_path, monkeypatch))
    transport = httpx.ASGITransport(app=application)
    reader = {"Authorization": "Bearer reader-secret", "X-Request-ID": "request-123"}
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            missing = await client.get("/v1/jobs/job_NOT_FOUND", headers=reader)
            unauthenticated = await client.get("/metrics")
            ready = await client.get("/readyz")
            invalid_request_id = await client.get(
                "/healthz", headers={"X-Request-ID": "invalid request id"}
            )
            metrics = await client.get("/metrics", headers=reader)

    assert missing.status_code == 404
    assert missing.headers["X-Request-ID"] == "request-123"
    assert unauthenticated.status_code == 401
    assert ready.status_code == 200
    assert invalid_request_id.headers["X-Request-ID"] != "invalid request id"
    assert len(invalid_request_id.headers["X-Request-ID"]) == 32
    assert metrics.status_code == 200
    assert metrics.headers["content-type"].startswith("text/plain")
    assert "job_NOT_FOUND" not in metrics.text
    assert (
        'trex_agent_http_requests_total{method="GET",route="/v1/jobs/{job_id}",'
        'status_class="4xx"} 1'
    ) in metrics.text
    assert "trex_agent_engine_available 1" in metrics.text
    assert 'trex_agent_logical_ports{status="AVAILABLE"} 4' in metrics.text


@pytest.mark.asyncio
async def test_file_credentials_reload_atomically_and_version_is_machine_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    operator_file = tmp_path / "operator.token"
    reader_file = tmp_path / "reader.token"
    operator_file.write_text("operator-old\n", encoding="utf-8")
    reader_file.write_text("reader-secret\n", encoding="utf-8")
    operator_file.chmod(0o600)
    reader_file.chmod(0o600)
    data = config_data(tmp_path)
    data["auth"] = {
        "tokens": [
            {"name": "operator", "role": "operator", "file": str(operator_file)},
            {"name": "reader", "role": "read-only", "file": str(reader_file)},
        ]
    }
    config = AgentConfig.model_validate(data)
    config.resolve_secrets()
    application = create_app(config)
    transport = httpx.ASGITransport(app=application)

    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            version = await client.get(
                "/version", headers={"Authorization": "Bearer operator-old"}
            )
            operator_file.write_text("operator-new\n", encoding="utf-8")
            reloaded = await client.post(
                "/v1/maintenance/auth:reload",
                headers={"Authorization": "Bearer operator-old"},
            )
            old = await client.get(
                "/version", headers={"Authorization": "Bearer operator-old"}
            )
            new = await client.get(
                "/version", headers={"Authorization": "Bearer operator-new"}
            )

            reader_file.chmod(0o640)
            failed_reload = await client.post(
                "/v1/maintenance/auth:reload",
                headers={"Authorization": "Bearer operator-new"},
            )
            still_valid = await client.get(
                "/version", headers={"Authorization": "Bearer operator-new"}
            )

    assert version.status_code == 200
    assert version.json()["httpApiVersions"] == ["v1"]
    assert version.json()["catalogApiVersions"] == ["trex.example.io/catalog/v1"]
    assert version.json()["testPlanApiVersions"] == ["trex.example.io/test-plan/v1"]
    assert version.json()["legacyReadApiVersions"] == [
        "trex.example.io/v2alpha1",
        "trex.example.io/plan/v2alpha1",
    ]
    assert version.json()["databaseSchemaVersion"] == 1
    assert version.headers["Trex-Agent-Version"] == version.json()["agentVersion"]
    assert reloaded.status_code == 200
    assert old.status_code == 401
    assert new.status_code == 200
    assert failed_reload.status_code == 503
    assert failed_reload.json()["code"] == "CREDENTIAL_RELOAD_FAILED"
    assert still_valid.status_code == 200


@pytest.mark.asyncio
async def test_database_migration_failure_keeps_agent_alive_but_unready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path, monkeypatch)
    incompatible = sqlite3.connect(config.database_path)
    incompatible.execute("CREATE TABLE jobs (job_id TEXT PRIMARY KEY)")
    incompatible.close()
    application = create_app(config)
    transport = httpx.ASGITransport(app=application)

    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            health = await client.get("/healthz")
            ready = await client.get("/readyz")
            unauthenticated = await client.post(
                "/v1/jobs",
                headers={"Idempotency-Key": "unauthenticated"},
                json={"document": stateless_document()},
            )
            submit = await client.post(
                "/v1/jobs",
                headers={
                    "Authorization": "Bearer operator-secret",
                    "Idempotency-Key": "blocked-by-migration",
                },
                json={"document": stateless_document()},
            )

    assert health.status_code == 200
    assert ready.status_code == 503
    assert ready.json()["status"] == "not-ready"
    assert ready.json()["reason"] == "DATABASE_MIGRATION_FAILED"
    assert Path(ready.json()["details"]["backupPath"]).is_file()  # noqa: ASYNC240
    assert unauthenticated.status_code == 401
    assert submit.status_code == 503
    assert submit.json()["code"] == "AGENT_NOT_READY"


@pytest.mark.asyncio
async def test_http_idempotency_conflict_is_problem_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = create_app(make_config(tmp_path, monkeypatch))
    transport = httpx.ASGITransport(app=application)
    headers = {
        "Authorization": "Bearer operator-secret",
        "Idempotency-Key": "same",
    }
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            first = await client.post(
                "/v1/jobs", headers=headers, json={"document": stateless_document()}
            )
            assert first.status_code == 202
            changed = stateless_document()
            changed["spec"]["rate"]["value"] = 20
            conflict = await client.post("/v1/jobs", headers=headers, json={"document": changed})
            assert conflict.status_code == 409
            assert conflict.headers["content-type"].startswith("application/problem+json")
            assert conflict.json()["code"] == "IDEMPOTENCY_CONFLICT"


@pytest.mark.asyncio
async def test_http_test_control_discovers_plans_starts_and_gets_a_test(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = create_app(make_config(tmp_path, monkeypatch), plans=_intent_plans(tmp_path))
    transport = httpx.ASGITransport(app=application)
    reader = {"Authorization": "Bearer reader-secret"}
    operator = {"Authorization": "Bearer operator-secret"}

    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            catalog = await client.get(
                "/v1/catalog",
                params={"query": "ipv4", "kind": "TrafficProfile"},
                headers=reader,
            )
            assert catalog.status_code == 200
            assert catalog.json()["items"][0]["ref"] == "ipv4-udp@1"

            planned = await client.post(
                "/v1/plans",
                headers=operator,
                json={
                    "kind": "traffic",
                    "profile": "ipv4-udp",
                    "path": "cc-switch",
                    "rate": "1000pps",
                    "duration": "1s",
                },
            )
            assert planned.status_code == 201
            plan_id = planned.json()["planId"]
            assert planned.json()["resources"]["profile"]["ref"] == "ipv4-udp@1"

            first = await client.post(f"/v1/plans/{plan_id}:start", headers=operator)
            repeated = await client.post(f"/v1/plans/{plan_id}:start", headers=operator)
            assert first.status_code == repeated.status_code == 202
            assert repeated.json()["jobId"] == first.json()["jobId"]

            observed = await client.get(f"/v1/tests/{first.json()['jobId']}", headers=reader)
            assert observed.status_code == 200
            assert observed.json()["kind"] == "StatelessTraffic"


@pytest.mark.asyncio
async def test_http_plans_a_dns_query_storm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path, monkeypatch)
    config.safety.allowed_mac_prefixes.append("a0:36:9f")
    application = create_app(config, plans=_intent_plans(tmp_path, config.safety))
    transport = httpx.ASGITransport(app=application)
    operator = {"Authorization": "Bearer operator-secret"}

    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            planned = await client.post(
                "/v1/plans",
                headers=operator,
                json={
                    "kind": "dns-storm",
                    "path": "cc-switch",
                    "clientRole": "client",
                    "serverRole": "server",
                    "name": "www.example.test",
                    "queryType": "A",
                    "pps": 100,
                    "duration": "3s",
                },
            )

            assert planned.status_code == 201, planned.text
            assert planned.json()["intent"] == "dns-storm"
            assert planned.json()["plan"]["document"]["kind"] == "PacketStorm"


@pytest.mark.asyncio
async def test_http_plans_a_dhcp_discover_storm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path, monkeypatch)
    config.safety.allowed_mac_prefixes.append("a0:36:9f")
    config.safety.allow_broadcast_storms = True
    application = create_app(config, plans=_intent_plans(tmp_path, config.safety))
    transport = httpx.ASGITransport(app=application)
    operator = {"Authorization": "Bearer operator-secret"}

    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            planned = await client.post(
                "/v1/plans",
                headers=operator,
                json={
                    "kind": "dhcp-storm",
                    "path": "cc-switch",
                    "clientRole": "client",
                    "serverRole": "server",
                    "clients": 4,
                    "pps": 100,
                    "duration": "3s",
                },
            )

            assert planned.status_code == 201, planned.text
            assert planned.json()["intent"] == "dhcp-storm"
            assert planned.json()["plan"]["document"]["spec"]["protocol"] == "dhcp"


@pytest.mark.asyncio
async def test_http_plans_an_arp_request_storm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path, monkeypatch)
    config.safety.allowed_mac_prefixes.append("a0:36:9f")
    config.safety.allow_broadcast_storms = True
    application = create_app(config, plans=_intent_plans(tmp_path, config.safety))
    transport = httpx.ASGITransport(app=application)
    operator = {"Authorization": "Bearer operator-secret"}

    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            planned = await client.post(
                "/v1/plans",
                headers=operator,
                json={
                    "kind": "arp-storm",
                    "path": "cc-switch",
                    "senderRole": "client",
                    "targetRole": "server",
                    "senders": 4,
                    "pps": 100,
                    "duration": "3s",
                },
            )

            assert planned.status_code == 201, planned.text
            assert planned.json()["intent"] == "arp-storm"
            assert planned.json()["plan"]["document"]["spec"]["protocol"] == "arp"


@pytest.mark.asyncio
async def test_http_publishes_and_discovers_capture_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path, monkeypatch)
    config.safety.allowed_mac_prefixes.append("a0:36:9f")
    application = create_app(config, plans=_intent_plans(tmp_path))
    transport = httpx.ASGITransport(app=application)
    reader = {"Authorization": "Bearer reader-secret"}
    operator = {"Authorization": "Bearer operator-secret"}

    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            forbidden = await client.post(
                "/v1/catalog/captures",
                params={"name": "regression/smoke"},
                headers=reader,
                content=_capture_bytes(),
            )
            assert forbidden.status_code == 403

            published = await client.post(
                "/v1/catalog/captures",
                params={"name": "regression/smoke", "description": "One packet"},
                headers={**operator, "Content-Type": "application/vnd.tcpdump.pcap"},
                content=_capture_bytes(),
            )
            assert published.status_code == 201
            assert published.json()["ref"] == "regression/smoke@1"
            assert published.json()["document"]["apiVersion"] == (
                "trex.example.io/catalog/v1"
            )
            assert published.json()["document"]["analysis"]["packetCount"] == 1

            catalog = await client.get(
                "/v1/catalog", params={"kind": "CaptureResource"}, headers=reader
            )
            assert catalog.status_code == 200
            assert catalog.json()["items"][0]["ref"] == "regression/smoke@1"

            described = await client.get(
                "/v1/catalog/CaptureResource/regression/smoke@1", headers=reader
            )
            assert described.status_code == 200
            assert described.json()["digest"] == published.json()["digest"]

            planned = await client.post(
                "/v1/plans",
                headers=operator,
                json={
                    "kind": "pcap-replay",
                    "capture": "regression/smoke@1",
                    "path": "cc-switch",
                    "sourceRole": "client",
                    "destinationRole": "server",
                    "timingMode": "fixed-rate",
                    "rate": "1000pps",
                },
            )
            assert planned.status_code == 201
            assert planned.json()["intent"] == "pcap-replay"
            started = await client.post(
                f"/v1/plans/{planned.json()['planId']}:start", headers=operator
            )
            assert started.status_code == 202
            for _ in range(100):
                observed = await client.get(f"/v1/tests/{started.json()['jobId']}", headers=reader)
                if observed.json()["state"] == "SUCCEEDED":
                    break
                await asyncio.sleep(0.01)
            assert observed.json()["result"]["methodology"] == "simulated-pcap-replay/v1"
