from __future__ import annotations

import hashlib
import ipaddress
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

from trex_cli.models import DurationMs, Role
from trex_cli.yaml_loader import load_yaml


class ConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class SimulatedEngineConfig(ConfigModel):
    mode: Literal["simulated"] = "simulated"
    step_delay_ms: int = Field(default=10, alias="stepDelayMs", ge=0, le=5_000)


class LatencyTimestampCalibration(ConfigModel):
    calibration_id: str = Field(alias="calibrationId", min_length=1)
    calibration_digest: str | None = Field(
        default=None,
        alias="calibrationDigest",
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    calibration_artifact: str | None = Field(
        default=None, alias="calibrationArtifact", min_length=1, max_length=512
    )
    timestamp_mode: Literal["ieee1588"] = Field(alias="timestampMode")
    measured_at: datetime = Field(alias="measuredAt")
    valid_until: datetime = Field(alias="validUntil")
    maximum_uncertainty_microseconds: float = Field(alias="maximumUncertaintyMicroseconds", ge=0)
    correction_microseconds: dict[
        Literal["store-and-forward", "bit-forwarding"], dict[int, float]
    ] = Field(alias="correctionMicroseconds", min_length=1)

    @model_validator(mode="after")
    def ordered_validity_window(self) -> LatencyTimestampCalibration:
        if self.valid_until <= self.measured_at:
            raise ValueError("latency calibration validUntil must follow measuredAt")
        return self


class RemoteTrexEngineConfig(ConfigModel):
    mode: Literal["remote-trex"]
    server: str = Field(min_length=1)
    sync_port: int = Field(default=4501, alias="syncPort", ge=1, le=65_535)
    async_port: int = Field(default=4500, alias="asyncPort", ge=1, le=65_535)
    client_path: Path = Field(alias="clientPath")
    external_libs_path: Path = Field(alias="externalLibsPath")
    username: str = Field(default="trex-cli", min_length=1, max_length=64)
    timeout_seconds: float = Field(default=5, alias="timeoutSeconds", gt=0, le=60)
    port_mapping: dict[str, int] = Field(alias="portMapping", min_length=2)
    pcap_remote_root: Path | None = Field(default=None, alias="pcapRemoteRoot")
    latency_timestamp_calibration: LatencyTimestampCalibration | None = Field(
        default=None, alias="latencyTimestampCalibration"
    )

    @model_validator(mode="after")
    def absolute_remote_capture_root(self) -> RemoteTrexEngineConfig:
        if self.pcap_remote_root is not None and not self.pcap_remote_root.is_absolute():
            raise ValueError("pcapRemoteRoot must be an absolute path visible to the TRex server")
        return self


class RemoteTrexAstfEngineConfig(ConfigModel):
    mode: Literal["remote-astf"]
    server: str = Field(min_length=1)
    sync_port: int = Field(default=4501, alias="syncPort", ge=1, le=65_535)
    async_port: int = Field(default=4500, alias="asyncPort", ge=1, le=65_535)
    client_path: Path = Field(alias="clientPath")
    external_libs_path: Path = Field(alias="externalLibsPath")
    username: str = Field(default="trex-cli-astf", min_length=1, max_length=64)
    timeout_seconds: float = Field(default=5, alias="timeoutSeconds", gt=0, le=60)
    port_mapping: dict[str, int] = Field(alias="portMapping", min_length=2)


type EngineConfig = Annotated[
    SimulatedEngineConfig | RemoteTrexEngineConfig | RemoteTrexAstfEngineConfig,
    Field(discriminator="mode"),
]


class SafetyPolicy(ConfigModel):
    version: str
    allowed_cidrs: list[str] = Field(alias="allowedCidrs", min_length=1)
    allowed_mac_prefixes: list[str] = Field(default_factory=list, alias="allowedMacPrefixes")
    allow_arbitrary_unicast_mac: bool = Field(default=False, alias="allowArbitraryUnicastMac")
    allow_broadcast_storms: bool = Field(default=False, alias="allowBroadcastStorms")
    max_concurrent_jobs: int = Field(default=4, alias="maxConcurrentJobs", ge=1, le=64)
    max_job_timeout: DurationMs = Field(default=28_800_000, alias="maxJobTimeout")
    max_port_wait_timeout: DurationMs = Field(default=600_000, alias="maxPortWaitTimeout")
    max_run_duration: DurationMs = Field(default=120_000, alias="maxRunDuration")
    max_burst_packets: int = Field(default=10_000_000, alias="maxBurstPackets", ge=1)
    max_percent_l1: float = Field(default=100, alias="maxPercentL1", gt=0, le=100)
    max_pps: float = Field(default=100_000_000, alias="maxPps", gt=0)
    max_bps_l1: float = Field(default=100_000_000_000, alias="maxBpsL1", gt=0)
    max_bps_l2: float = Field(default=100_000_000_000, alias="maxBpsL2", gt=0)
    max_cps: float = Field(default=1_000_000, alias="maxCps", gt=0)
    max_active_connections: int = Field(default=10_000_000, alias="maxActiveConnections", ge=1)
    max_address_pool_size: int = Field(default=65_536, alias="maxAddressPoolSize", ge=1)
    calibration_bootstrap_max_percent_l1: float = Field(
        default=0.01, alias="calibrationBootstrapMaxPercentL1", gt=0, le=100
    )
    max_calibration_growth_factor: float = Field(
        default=1, alias="maxCalibrationGrowthFactor", ge=1, le=10
    )
    max_calibration_age: DurationMs = Field(default=604_800_000, alias="maxCalibrationAge")
    simulated_throughput_percent: float = Field(
        default=100, alias="simulatedThroughputPercent", gt=0, le=100
    )

    @model_validator(mode="after")
    def valid_networks(self) -> SafetyPolicy:
        for cidr in self.allowed_cidrs:
            ipaddress.ip_network(cidr, strict=False)
        for prefix in self.allowed_mac_prefixes:
            if not 1 <= len(prefix.split(":")) <= 6 or any(
                len(octet) != 2 or any(char not in "0123456789abcdefABCDEF" for char in octet)
                for octet in prefix.split(":")
            ):
                raise ValueError(f"invalid allowed MAC prefix: {prefix}")
        if not self.allow_arbitrary_unicast_mac and not self.allowed_mac_prefixes:
            raise ValueError(
                "allowedMacPrefixes is required unless allowArbitraryUnicastMac is true"
            )
        return self

    def rate_ceiling(self, unit: str) -> float:
        return {
            "percent_l1": self.max_percent_l1,
            "pps": self.max_pps,
            "bps_l1": self.max_bps_l1,
            "bps_l2": self.max_bps_l2,
        }[unit]


class TokenConfig(ConfigModel):
    name: str = Field(min_length=1, max_length=64)
    role: Role
    env: str | None = Field(default=None, min_length=1, pattern=r"^[A-Z][A-Z0-9_]*$")
    file: Path | None = None

    @model_validator(mode="after")
    def exactly_one_secret_source(self) -> TokenConfig:
        if (self.env is None) == (self.file is None):
            raise ValueError("token must configure exactly one of env or file")
        return self


class AuthConfig(ConfigModel):
    tokens: list[TokenConfig] = Field(min_length=1)


class TlsConfig(ConfigModel):
    cert_file: Path = Field(alias="certFile")
    key_file: Path = Field(alias="keyFile")
    client_ca_file: Path | None = Field(default=None, alias="clientCaFile")
    require_client_certificate: bool = Field(default=False, alias="requireClientCertificate")

    @model_validator(mode="after")
    def client_ca_required_for_mtls(self) -> TlsConfig:
        if self.require_client_certificate and self.client_ca_file is None:
            raise ValueError("tls.clientCaFile is required when client certificates are required")
        return self


class AgentConfig(ConfigModel):
    bind_host: str = Field(default="127.0.0.1", alias="bindHost")
    bind_port: int = Field(default=8080, alias="bindPort", ge=1, le=65_535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO", alias="logLevel"
    )
    database_path: Path = Field(alias="databasePath")
    artifact_root: Path = Field(alias="artifactRoot")
    artifact_retention_days: int = Field(default=90, alias="artifactRetentionDays", ge=1)
    artifact_orphan_grace_period: DurationMs = Field(
        default=86_400_000, alias="artifactOrphanGracePeriod"
    )
    traffic_profile_root: Path = Field(default=Path("traffic-profiles"), alias="trafficProfileRoot")
    lab_path_root: Path = Field(default=Path("lab-paths"), alias="labPathRoot")
    plan_root: Path = Field(default=Path(".trex-plans"), alias="planRoot")
    capture_root: Path = Field(default=Path(".trex-captures"), alias="captureRoot")
    logical_ports: list[str] = Field(alias="logicalPorts", min_length=2)
    engine: EngineConfig
    safety: SafetyPolicy
    auth: AuthConfig
    tls: TlsConfig | None = None
    _token_digests: dict[str, tuple[bytes, Role]] = PrivateAttr(default_factory=dict)

    @model_validator(mode="after")
    def unique_ports_and_tokens(self) -> AgentConfig:
        if len(self.logical_ports) != len(set(self.logical_ports)):
            raise ValueError("logicalPorts must be unique")
        names = [token.name for token in self.auth.tokens]
        if len(names) != len(set(names)):
            raise ValueError("auth token names must be unique")
        if not any(token.role == Role.OPERATOR for token in self.auth.tokens):
            raise ValueError("auth.tokens must include at least one operator")
        if isinstance(self.engine, (RemoteTrexEngineConfig, RemoteTrexAstfEngineConfig)):
            if set(self.engine.port_mapping) != set(self.logical_ports):
                raise ValueError("engine.portMapping must map every logicalPort exactly once")
            values = list(self.engine.port_mapping.values())
            if any(port < 0 for port in values) or len(values) != len(set(values)):
                raise ValueError("engine.portMapping values must be unique non-negative ports")
        return self

    def resolve_secrets(self) -> None:
        values: dict[str, tuple[bytes, Role]] = {}
        names_by_digest: dict[bytes, str] = {}
        for token in self.auth.tokens:
            value = self._read_token(token)
            digest = hashlib.sha256(value.encode("utf-8")).digest()
            if digest in names_by_digest:
                raise ValueError(
                    f"credentials {names_by_digest[digest]} and {token.name} use the same token"
                )
            names_by_digest[digest] = token.name
            values[token.name] = (digest, token.role)
        self._token_digests = values

    @property
    def token_digests(self) -> dict[str, tuple[bytes, Role]]:
        if not self._token_digests:
            raise RuntimeError("configuration secrets have not been resolved")
        return dict(self._token_digests)

    @staticmethod
    def _read_token(token: TokenConfig) -> str:
        if token.env is not None:
            value = os.environ.get(token.env)
            if not value:
                raise ValueError(f"required token environment variable is missing: {token.env}")
            return value
        assert token.file is not None
        metadata = token.file.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"token file is not a regular file: {token.file}")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError(f"token file must not be accessible by group or others: {token.file}")
        value = token.file.read_text(encoding="utf-8").rstrip("\r\n")
        if not value or "\n" in value or "\r" in value:
            raise ValueError(f"token file must contain exactly one non-empty line: {token.file}")
        return value


def load_config(path: Path) -> AgentConfig:
    raw = load_yaml(path.read_text(encoding="utf-8"))
    config = AgentConfig.model_validate(raw)
    base = path.resolve().parent
    config.database_path = _resolve_path(base, config.database_path)
    config.artifact_root = _resolve_path(base, config.artifact_root)
    config.traffic_profile_root = _resolve_path(base, config.traffic_profile_root)
    config.lab_path_root = _resolve_path(base, config.lab_path_root)
    config.plan_root = _resolve_path(base, config.plan_root)
    config.capture_root = _resolve_path(base, config.capture_root)
    for token in config.auth.tokens:
        if token.file is not None:
            token.file = _resolve_path(base, token.file)
    if config.tls is not None:
        config.tls.cert_file = _resolve_path(base, config.tls.cert_file)
        config.tls.key_file = _resolve_path(base, config.tls.key_file)
        if config.tls.client_ca_file is not None:
            config.tls.client_ca_file = _resolve_path(base, config.tls.client_ca_file)
    if isinstance(config.engine, (RemoteTrexEngineConfig, RemoteTrexAstfEngineConfig)):
        config.engine.client_path = _resolve_path(base, config.engine.client_path)
        config.engine.external_libs_path = _resolve_path(base, config.engine.external_libs_path)
    config.resolve_secrets()
    return config


def _resolve_path(base: Path, value: Path) -> Path:
    return value if value.is_absolute() else (base / value).resolve()
