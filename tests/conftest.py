from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from trex_cli.artifacts import ArtifactStore
from trex_cli.config import AgentConfig
from trex_cli.engine import SimulatedEngine
from trex_cli.jobs import TestJobs
from trex_cli.models import JobSnapshot, Principal, Role, SubmitBody
from trex_cli.storage import SqliteStore


def config_data(tmp_path: Path, *, step_delay_ms: int = 0) -> dict[str, Any]:
    return {
        "bindHost": "127.0.0.1",
        "bindPort": 8080,
        "databasePath": str(tmp_path / "jobs.sqlite3"),
        "artifactRoot": str(tmp_path / "artifacts"),
        "logicalPorts": ["lab-west", "lab-east", "lab-north", "lab-south"],
        "engine": {"mode": "simulated", "stepDelayMs": step_delay_ms},
        "safety": {
            "version": "test-policy-1",
            "allowedCidrs": ["198.18.0.0/15"],
            "allowedMacPrefixes": ["00:00:00"],
            "maxConcurrentJobs": 4,
            "maxJobTimeout": "8h",
            "maxPortWaitTimeout": "10m",
            "maxRunDuration": "120s",
            "simulatedThroughputPercent": 97,
        },
        "auth": {
            "tokens": [
                {"name": "operator", "role": "operator", "env": "TEST_OPERATOR_TOKEN"},
                {"name": "reader", "role": "read-only", "env": "TEST_READER_TOKEN"},
            ]
        },
    }


def make_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, step_delay_ms: int = 0
) -> AgentConfig:
    monkeypatch.setenv("TEST_OPERATOR_TOKEN", "operator-secret")
    monkeypatch.setenv("TEST_READER_TOKEN", "reader-secret")
    config = AgentConfig.model_validate(config_data(tmp_path, step_delay_ms=step_delay_ms))
    config.resolve_secrets()
    return config


def stateless_document(*, max_loss: float | None = 0) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "safety": {"isolatedLab": True},
        "ports": {"tx": "lab-west", "rx": "lab-east"},
        "packet": {
            "frameSize": 128,
            "ethernet": {
                "src": "00:00:00:00:00:01",
                "dst": "00:00:00:00:00:02",
            },
            "ipv4": {"src": "198.18.0.1", "dst": "198.19.0.1"},
            "udp": {"srcPort": 49152, "dstPort": 53},
        },
        "rate": {"unit": "percent_l1", "value": 10},
        "duration": "30s",
    }
    if max_loss is not None:
        spec["assertions"] = {"maxLossPercent": max_loss}
    return {
        "apiVersion": "trex.example.io/v1",
        "kind": "StatelessTraffic",
        "metadata": {"name": "test"},
        "spec": spec,
    }


def rfc_document(*, threshold: float | None = 95) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "safety": {"isolatedLab": True},
        "ports": {
            "tx": "lab-west",
            "rx": "lab-east",
            "direction": "bidirectional",
        },
        "mode": "strict",
        "packet": {
            "ethernet": {
                "src": "00:00:00:00:00:01",
                "dst": "00:00:00:00:00:02",
            },
            "ipv4": {"src": "198.18.0.1", "dst": "198.19.0.1"},
            "udp": {"srcPort": 49152, "dstPort": 7},
        },
    }
    if threshold is not None:
        spec["assertion"] = {"minimumPercentLineRate": {"64": threshold}}
    return {
        "apiVersion": "trex.example.io/v1",
        "kind": "Rfc2544Throughput",
        "metadata": {"name": "rfc-test"},
        "spec": spec,
    }


async def build_jobs(config: AgentConfig) -> TestJobs:
    database = SqliteStore(config.database_path)
    artifacts = ArtifactStore(config.artifact_root, database)
    engine = SimulatedEngine(config.safety, config.engine.step_delay_ms)
    jobs = TestJobs(config, database, artifacts, engine)
    await jobs.start()
    return jobs


async def wait_terminal(jobs: TestJobs, job_id: str) -> JobSnapshot:
    async for snapshot in jobs.observe(job_id, after_revision=0):
        if snapshot.state.terminal:
            return snapshot
    raise AssertionError("observe ended without a terminal snapshot")


@pytest.fixture
def operator() -> Principal:
    return Principal(name="operator", role=Role.OPERATOR)


@pytest.fixture
async def jobs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[TestJobs]:
    instance = await build_jobs(make_config(tmp_path, monkeypatch))
    yield instance
    await instance.stop()


def submit_body(document: dict[str, Any], retry_of: str | None = None) -> SubmitBody:
    value: dict[str, Any] = {"document": document}
    if retry_of is not None:
        value["retryOf"] = retry_of
    return SubmitBody.model_validate(value)
