from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from trex_cli.config import AgentConfig

from .conftest import config_data


def test_artifact_retention_defaults_and_duration_are_typed(tmp_path: Path) -> None:
    defaults = AgentConfig.model_validate(config_data(tmp_path))
    assert defaults.artifact_retention_days == 90
    assert defaults.artifact_orphan_grace_period == 86_400_000

    customized = config_data(tmp_path)
    customized["artifactRetentionDays"] = 30
    customized["artifactOrphanGracePeriod"] = "2h"
    config = AgentConfig.model_validate(customized)
    assert config.artifact_retention_days == 30
    assert config.artifact_orphan_grace_period == 7_200_000


def test_log_level_is_closed_and_defaults_to_info(tmp_path: Path) -> None:
    defaults = AgentConfig.model_validate(config_data(tmp_path))
    assert defaults.log_level == "INFO"

    customized = config_data(tmp_path)
    customized["logLevel"] = "DEBUG"
    assert AgentConfig.model_validate(customized).log_level == "DEBUG"

    customized["logLevel"] = "TRACE"
    with pytest.raises(ValueError, match="logLevel"):
        AgentConfig.model_validate(customized)


def test_file_tokens_require_private_permissions_and_are_stored_as_digests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_file = tmp_path / "operator.token"
    token_file.write_text("file-operator-secret\n", encoding="utf-8")
    token_file.chmod(0o600)
    data = config_data(tmp_path)
    data["auth"]["tokens"][0] = {
        "name": "operator",
        "role": "operator",
        "file": str(token_file),
    }
    monkeypatch.setenv("TEST_READER_TOKEN", "reader-secret")
    config = AgentConfig.model_validate(data)
    config.resolve_secrets()

    digest, role = config.token_digests["operator"]
    assert digest == hashlib.sha256(b"file-operator-secret").digest()
    assert b"file-operator-secret" not in digest
    assert role == "operator"

    token_file.chmod(0o640)
    with pytest.raises(ValueError, match="group or others"):
        config.resolve_secrets()


def test_token_requires_exactly_one_source_and_an_operator(tmp_path: Path) -> None:
    conflicting = config_data(tmp_path)
    conflicting["auth"]["tokens"][0]["file"] = str(tmp_path / "token")
    with pytest.raises(ValueError, match="exactly one"):
        AgentConfig.model_validate(conflicting)

    reader_only = config_data(tmp_path)
    reader_only["auth"]["tokens"] = [
        {"name": "reader", "role": "read-only", "env": "TEST_READER_TOKEN"}
    ]
    with pytest.raises(ValueError, match="at least one operator"):
        AgentConfig.model_validate(reader_only)


def test_duplicate_token_values_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = config_data(tmp_path)
    monkeypatch.setenv("TEST_OPERATOR_TOKEN", "shared-secret")
    monkeypatch.setenv("TEST_READER_TOKEN", "shared-secret")
    config = AgentConfig.model_validate(data)

    with pytest.raises(ValueError, match="use the same token"):
        config.resolve_secrets()


def test_tls_requires_a_client_ca_when_mtls_is_enabled(tmp_path: Path) -> None:
    data = config_data(tmp_path)
    data["tls"] = {
        "certFile": str(tmp_path / "server.crt"),
        "keyFile": str(tmp_path / "server.key"),
        "requireClientCertificate": True,
    }
    with pytest.raises(ValueError, match="clientCaFile"):
        AgentConfig.model_validate(data)


def test_missing_token_environment_variable_is_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TEST_OPERATOR_TOKEN", raising=False)
    monkeypatch.delenv("TEST_READER_TOKEN", raising=False)
    config = AgentConfig.model_validate(config_data(tmp_path))
    with pytest.raises(ValueError, match="TEST_OPERATOR_TOKEN"):
        config.resolve_secrets()


def test_remote_engine_requires_an_exact_unique_port_mapping(tmp_path: Path) -> None:
    data = config_data(tmp_path)
    data["engine"] = {
        "mode": "remote-trex",
        "server": "127.0.0.1",
        "clientPath": str(tmp_path / "client"),
        "externalLibsPath": str(tmp_path / "libs"),
        "portMapping": {"lab-west": 0, "lab-east": 0},
    }
    with pytest.raises(ValueError, match="every logicalPort"):
        AgentConfig.model_validate(data)


def test_remote_engine_configuration_is_accepted(tmp_path: Path) -> None:
    data = config_data(tmp_path)
    data["engine"] = {
        "mode": "remote-trex",
        "server": "127.0.0.1",
        "syncPort": 14501,
        "asyncPort": 14500,
        "clientPath": str(tmp_path / "client"),
        "externalLibsPath": str(tmp_path / "libs"),
        "portMapping": {
            "lab-west": 0,
            "lab-east": 1,
            "lab-north": 2,
            "lab-south": 3,
        },
    }
    config = AgentConfig.model_validate(data)
    assert config.engine.mode == "remote-trex"


def test_remote_latency_calibration_records_definition_specific_frame_corrections(
    tmp_path: Path,
) -> None:
    data = config_data(tmp_path)
    data["engine"] = {
        "mode": "remote-trex",
        "server": "127.0.0.1",
        "clientPath": str(tmp_path / "client"),
        "externalLibsPath": str(tmp_path / "libs"),
        "portMapping": {
            "lab-west": 0,
            "lab-east": 1,
            "lab-north": 2,
            "lab-south": 3,
        },
        "latencyTimestampCalibration": {
            "calibrationId": "cal_20260830_X550",
            "calibrationDigest": "sha256:" + "c" * 64,
            "calibrationArtifact": "x550-calibration.json",
            "timestampMode": "ieee1588",
            "measuredAt": "2026-08-30T00:00:00Z",
            "validUntil": "2027-08-30T00:00:00Z",
            "maximumUncertaintyMicroseconds": 0.2,
            "correctionMicroseconds": {"store-and-forward": {"64": -0.1, "1518": -0.2}},
        },
    }

    config = AgentConfig.model_validate(data)
    assert config.engine.mode == "remote-trex"
    calibration = config.engine.latency_timestamp_calibration
    assert calibration is not None
    assert calibration.calibration_artifact == "x550-calibration.json"
    assert calibration.correction_microseconds["store-and-forward"][64] == -0.1
