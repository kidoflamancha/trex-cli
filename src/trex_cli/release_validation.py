from __future__ import annotations

import argparse
import json
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from trex_cli import __version__
from trex_cli.config import AgentConfig
from trex_cli.models import JOB_DOCUMENT_ADAPTER
from trex_cli.profiles import Profiles
from trex_cli.test_plan import (
    CATALOG_API_VERSION,
    LabPathDocument,
    TestPlanModule,
    TrafficProfileDocument,
)
from trex_cli.yaml_loader import load_yaml


class ReleaseValidationError(ValueError):
    def __init__(self, failures: list[str]) -> None:
        self.failures = tuple(failures)
        super().__init__("release resource validation failed:\n- " + "\n- ".join(failures))


@dataclass(frozen=True, slots=True)
class ReleaseValidationReport:
    version: str
    config_count: int
    job_example_count: int
    legacy_profile_count: int
    traffic_profile_count: int
    lab_path_count: int
    schema_count: int
    deployment_asset_count: int


def validate_release_resources(root: Path) -> ReleaseValidationReport:
    """Validate all source-controlled resources required by a release wheel."""
    root = root.resolve()
    failures: list[str] = []
    config_count = _validate_files(
        [root / "config.example.yaml"],
        lambda raw: AgentConfig.model_validate(raw),
        failures,
    )
    job_example_count = _validate_files(
        sorted((root / "examples").glob("*.yaml")),
        JOB_DOCUMENT_ADAPTER.validate_python,
        failures,
    )

    legacy_profile_count = 0
    profile_root = root / "profiles"
    if not profile_root.is_dir():
        failures.append("profiles: directory is missing")
    else:
        profiles = Profiles(profile_root, root / ".release-validation-plans")
        names = profiles.list_profiles()
        if not names:
            failures.append("profiles: no YAML resources found")
        for name in names:
            try:
                profiles.show(name)
                legacy_profile_count += 1
            except (OSError, ValueError) as error:
                failures.append(f"profiles/{name}.yaml: {error}")

    traffic_profile_count, lab_path_count = _validate_catalog(root, failures)
    schema_count = _validate_schemas(failures)
    deployment_asset_count = _validate_deployment_assets(root, failures)
    _validate_version(root, failures)
    if failures:
        raise ReleaseValidationError(failures)
    return ReleaseValidationReport(
        version=__version__,
        config_count=config_count,
        job_example_count=job_example_count,
        legacy_profile_count=legacy_profile_count,
        traffic_profile_count=traffic_profile_count,
        lab_path_count=lab_path_count,
        schema_count=schema_count,
        deployment_asset_count=deployment_asset_count,
    )


def _validate_files(
    paths: list[Path],
    validator: Any,
    failures: list[str],
) -> int:
    valid = 0
    for path in paths:
        try:
            raw = load_yaml(path.read_text(encoding="utf-8"))
            validator(raw)
            valid += 1
        except (OSError, ValueError, ValidationError) as error:
            failures.append(f"{path.name}: {error}")
    if not paths:
        failures.append("release resources: expected at least one YAML file")
    return valid


def _validate_catalog(root: Path, failures: list[str]) -> tuple[int, int]:
    traffic_root = root / "traffic-profiles"
    path_root = root / "lab-paths"
    for label, path in (("traffic-profiles", traffic_root), ("lab-paths", path_root)):
        if not path.is_dir():
            failures.append(f"{label}: directory is missing")
    if not traffic_root.is_dir() or not path_root.is_dir():
        return 0, 0
    module = TestPlanModule(
        traffic_root,
        path_root,
        root / ".release-validation-plans",
        root / ".release-validation-captures",
    )
    traffic_count = 0
    path_count = 0
    try:
        resources = module.search_resources(kinds={"TrafficProfile", "LabPath"})
    except (OSError, ValueError) as error:
        failures.append(f"catalog: {error}")
        return 0, 0
    for resource in resources:
        if resource.document.api_version != CATALOG_API_VERSION:
            failures.append(
                f"{resource.kind} {resource.ref}: release resources must use "
                f"{CATALOG_API_VERSION}"
            )
            continue
        if resource.kind == "TrafficProfile":
            traffic_count += 1
        else:
            path_count += 1
    if traffic_count == 0:
        failures.append("traffic-profiles: no valid resources found")
    if path_count == 0:
        failures.append("lab-paths: no valid resources found")
    return traffic_count, path_count


def _validate_schemas(failures: list[str]) -> int:
    schemas = {
        "AgentConfig": AgentConfig.model_json_schema(),
        "JobDocument": JOB_DOCUMENT_ADAPTER.json_schema(),
        "TrafficProfile": TrafficProfileDocument.model_json_schema(),
        "LabPath": LabPathDocument.model_json_schema(),
    }
    for name, schema in schemas.items():
        try:
            json.dumps(schema, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as error:
            failures.append(f"schema {name}: {error}")
    return len(schemas)


def _validate_deployment_assets(root: Path, failures: list[str]) -> int:
    assets = {
        "LICENSE": ("Apache License", "Version 2.0, January 2004"),
        "CHANGELOG.md": ("1.0.0 - 2026-09-05",),
        "docs/compatibility.md": ("Compatibility policy", "GET /version"),
        "docs/operations.md": ("TLS deployment", "online rotation"),
        "docs/release-evaluation.md": ("Release evaluation", "TestControl task matrix"),
        "deploy/systemd/trex-agent.service": ("ExecStart=", "User=trex-agent"),
        "deploy/nginx/trex-agent.conf": ("ssl_protocols TLSv1.2 TLSv1.3", "proxy_pass"),
    }
    valid = 0
    for relative_path, required_fragments in assets.items():
        try:
            content = (root / relative_path).read_text(encoding="utf-8")
        except OSError as error:
            failures.append(f"{relative_path}: {error}")
            continue
        missing = [fragment for fragment in required_fragments if fragment not in content]
        if missing:
            failures.append(f"{relative_path}: missing required content: {', '.join(missing)}")
            continue
        valid += 1
    return valid


def _validate_version(root: Path, failures: list[str]) -> None:
    try:
        project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        packaged_version = str(project["version"])
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        failures.append(f"pyproject.toml: cannot read project version: {error}")
        return
    if packaged_version != __version__:
        failures.append(
            f"version mismatch: pyproject.toml={packaged_version}, trex_cli={__version__}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate trex-cli release resources")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    arguments = parser.parse_args()
    try:
        report = validate_release_resources(arguments.root)
    except ReleaseValidationError as error:
        parser.exit(1, f"{error}\n")
    print(json.dumps(asdict(report), sort_keys=True))


if __name__ == "__main__":
    main()
