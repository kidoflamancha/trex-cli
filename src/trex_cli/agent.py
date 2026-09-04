from __future__ import annotations

import logging
import ssl
from pathlib import Path

import typer
import uvicorn

from trex_cli.api import create_app
from trex_cli.config import load_config
from trex_cli.observability import configure_logging

_LOGGER = logging.getLogger(__name__)

app = typer.Typer(add_completion=False, help="Run the trex-cli Agent.")


@app.callback(invoke_without_command=True)
def main(
    config_path: Path = typer.Option(
        ..., "--config", exists=True, dir_okay=False, readable=True, resolve_path=True
    ),
) -> None:
    config = load_config(config_path)
    configure_logging(config.log_level)
    if config.tls is None:
        _LOGGER.warning(
            "insecure_http_enabled",
            extra={"bindHost": config.bind_host, "bindPort": config.bind_port},
        )
    else:
        _LOGGER.info(
            "tls_enabled",
            extra={
                "bindHost": config.bind_host,
                "bindPort": config.bind_port,
                "clientCertificateRequired": config.tls.require_client_certificate,
            },
        )
    uvicorn.run(
        create_app(config),
        host=config.bind_host,
        port=config.bind_port,
        workers=1,
        log_config=None,
        access_log=False,
        ssl_certfile=str(config.tls.cert_file) if config.tls is not None else None,
        ssl_keyfile=str(config.tls.key_file) if config.tls is not None else None,
        ssl_ca_certs=(
            str(config.tls.client_ca_file)
            if config.tls is not None and config.tls.client_ca_file is not None
            else None
        ),
        ssl_cert_reqs=(
            ssl.CERT_REQUIRED
            if config.tls is not None and config.tls.require_client_certificate
            else ssl.CERT_NONE
        ),
    )
