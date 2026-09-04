from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from trex_cli.release_validation import ReleaseValidationError, validate_release_resources

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_release_resources_and_schemas_are_valid() -> None:
    report = validate_release_resources(REPOSITORY_ROOT)

    assert report.version == "1.0.0"
    assert report.config_count == 1
    assert report.job_example_count == 3
    assert report.legacy_profile_count == 1
    assert report.traffic_profile_count == 2
    assert report.lab_path_count == 1
    assert report.schema_count == 4
    assert report.deployment_asset_count == 7


def test_release_validation_reports_the_broken_resource(tmp_path: Path) -> None:
    for name in (
        "config.example.yaml",
        "pyproject.toml",
        "examples",
        "profiles",
        "traffic-profiles",
        "lab-paths",
        "LICENSE",
        "CHANGELOG.md",
        "docs",
        "deploy",
    ):
        source = REPOSITORY_ROOT / name
        destination = tmp_path / name
        if source.is_dir():
            shutil.copytree(source, destination)
        else:
            shutil.copy2(source, destination)
    (tmp_path / "examples" / "stateless.yaml").write_text(
        "apiVersion: trex.example.io/v1\nkind: UnknownJob\n",
        encoding="utf-8",
    )
    profile_path = tmp_path / "traffic-profiles" / "ipv4-udp.yaml"
    profile_path.write_text(
        profile_path.read_text(encoding="utf-8").replace(
            "trex.example.io/catalog/v1", "trex.example.io/v2alpha1"
        ),
        encoding="utf-8",
    )

    with pytest.raises(ReleaseValidationError) as raised:
        validate_release_resources(tmp_path)

    assert "stateless.yaml" in str(raised.value)
    assert "UnknownJob" in str(raised.value)
    assert "release resources must use trex.example.io/catalog/v1" in str(raised.value)
