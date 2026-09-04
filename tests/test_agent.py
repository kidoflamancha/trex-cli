from __future__ import annotations

import ssl
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from trex_cli.agent import app
from trex_cli.config import AgentConfig

from .conftest import config_data


def test_agent_passes_native_tls_and_mtls_settings_to_uvicorn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = config_data(tmp_path)
    data["tls"] = {
        "certFile": str(tmp_path / "server.crt"),
        "keyFile": str(tmp_path / "server.key"),
        "clientCaFile": str(tmp_path / "clients-ca.crt"),
        "requireClientCertificate": True,
    }
    config = AgentConfig.model_validate(data)
    monkeypatch.setenv("TEST_OPERATOR_TOKEN", "operator-secret")
    monkeypatch.setenv("TEST_READER_TOKEN", "reader-secret")
    config.resolve_secrets()
    received: dict[str, Any] = {}

    def fake_run(application: object, **kwargs: Any) -> None:
        received.update(kwargs)

    monkeypatch.setattr("trex_cli.agent.load_config", lambda _: config)
    monkeypatch.setattr("trex_cli.agent.configure_logging", lambda _: None)
    monkeypatch.setattr("trex_cli.agent.uvicorn.run", fake_run)
    config_path = tmp_path / "config.yaml"
    config_path.touch()

    result = CliRunner().invoke(app, ["--config", str(config_path)])

    assert result.exit_code == 0
    assert received["ssl_certfile"] == str(tmp_path / "server.crt")
    assert received["ssl_keyfile"] == str(tmp_path / "server.key")
    assert received["ssl_ca_certs"] == str(tmp_path / "clients-ca.crt")
    assert received["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    assert received["workers"] == 1
    assert received["access_log"] is False
