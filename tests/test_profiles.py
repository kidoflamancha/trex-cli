from __future__ import annotations

import json
from pathlib import Path

import pytest

from trex_cli.profiles import ProfileError, Profiles

from .conftest import stateless_document


def write_profile(root: Path, name: str = "cc-switch") -> None:
    root.mkdir()
    (root / f"{name}.yaml").write_text(
        json.dumps(stateless_document()), encoding="utf-8"
    )


def test_profile_resolves_spec_relative_overrides_into_an_immutable_plan(tmp_path: Path) -> None:
    profile_root = tmp_path / "profiles"
    plan_root = tmp_path / "plans"
    write_profile(profile_root)
    profiles = Profiles(profile_root, plan_root)

    plan = profiles.create(
        "cc-switch",
        ["packet.frameSize=256", "packet.ipv4.src=198.18.0.10"],
        expected_kind="StatelessTraffic",
    )
    repeated = profiles.create(
        "cc-switch",
        ["packet.frameSize=256", "packet.ipv4.src=198.18.0.10"],
        expected_kind="StatelessTraffic",
    )

    assert plan.plan_id == repeated.plan_id
    assert plan.document.spec.packet.frame_size == 256
    assert plan.document.spec.packet.ipv4 is not None
    assert plan.document.spec.packet.ipv4.src == "198.18.0.10"
    assert profiles.get(plan.plan_id).payload() == plan.payload()
    assert profiles.list_profiles() == ["cc-switch"]
    assert profiles.list_plans() == [plan.plan_id]


def test_profile_rejects_unknown_override_paths_and_wrong_kind(tmp_path: Path) -> None:
    profile_root = tmp_path / "profiles"
    write_profile(profile_root)
    profiles = Profiles(profile_root, tmp_path / "plans")

    with pytest.raises(ProfileError, match="doesNotExist"):
        profiles.create("cc-switch", ["packet.doesNotExist=1"])
    with pytest.raises(ProfileError, match="expected Rfc2544Throughput"):
        profiles.create("cc-switch", expected_kind="Rfc2544Throughput")
