from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from trex_cli.models import (
    JOB_DOCUMENT_ADAPTER,
    JobDocument,
    canonical_document,
    sha256_text,
)
from trex_cli.yaml_loader import load_yaml

_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class ProfileError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Profile:
    name: str
    source_path: Path
    source_digest: str
    document: JobDocument


@dataclass(frozen=True, slots=True)
class TestPlan:
    plan_id: str
    profile_name: str
    profile_digest: str
    overrides: tuple[str, ...]
    document: JobDocument

    def payload(self) -> dict[str, Any]:
        return {
            "apiVersion": "trex.example.io/plan/v1",
            "planId": self.plan_id,
            "profile": {"name": self.profile_name, "digest": self.profile_digest},
            "overrides": list(self.overrides),
            "document": self.document.model_dump(mode="json", by_alias=True, exclude_none=True),
        }


class Profiles:
    """Resolves versioned profile defaults into immutable, locally stored test plans."""

    def __init__(self, profile_root: Path, plan_root: Path) -> None:
        self._profile_root = profile_root
        self._plan_root = plan_root

    def list_profiles(self) -> list[str]:
        if not self._profile_root.exists():
            return []
        return sorted(path.stem for path in self._profile_root.glob("*.yaml") if path.is_file())

    def show(self, name: str) -> Profile:
        return self._load_profile(name)

    def create(
        self,
        name: str,
        overrides: list[str] | tuple[str, ...] = (),
        *,
        expected_kind: str | None = None,
    ) -> TestPlan:
        profile = self._load_profile(name)
        resolved = profile.document.model_dump(mode="json", by_alias=True, exclude_none=True)
        normalized_overrides: list[str] = []
        for override in overrides:
            path, value = _parse_override(override)
            if path[0] not in {"apiVersion", "kind", "metadata", "spec"}:
                path = ("spec", *path)
            _set_path(resolved, path, value)
            normalized_overrides.append(override)
        document = _validate_document(resolved)
        if expected_kind is not None and document.kind != expected_kind:
            raise ProfileError(f"profile {name} is {document.kind}, expected {expected_kind}")
        identity = json.dumps(
            {
                "profile": {"name": profile.name, "digest": profile.source_digest},
                "document": json.loads(canonical_document(document)),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        plan = TestPlan(
            plan_id="plan_" + sha256_text(identity).removeprefix("sha256:")[:24],
            profile_name=profile.name,
            profile_digest=profile.source_digest,
            overrides=tuple(normalized_overrides),
            document=document,
        )
        self._persist(plan)
        return plan

    def list_plans(self) -> list[str]:
        if not self._plan_root.exists():
            return []
        return sorted(path.stem for path in self._plan_root.glob("plan_*.json") if path.is_file())

    def get(self, plan_id: str) -> TestPlan:
        if not re.fullmatch(r"plan_[0-9a-f]{24}", plan_id):
            raise ProfileError("invalid plan id")
        path = self._plan_root / f"{plan_id}.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as error:
            raise ProfileError(f"plan not found: {plan_id}") from error
        except json.JSONDecodeError as error:
            raise ProfileError(f"stored plan is not valid JSON: {plan_id}") from error
        if not isinstance(raw, dict) or raw.get("apiVersion") != "trex.example.io/plan/v1":
            raise ProfileError(f"stored plan has an unsupported format: {plan_id}")
        try:
            plan = TestPlan(
                plan_id=str(raw["planId"]),
                profile_name=str(raw["profile"]["name"]),
                profile_digest=str(raw["profile"]["digest"]),
                overrides=tuple(str(item) for item in raw.get("overrides", [])),
                document=_validate_document(raw["document"]),
            )
        except (KeyError, TypeError, ValidationError) as error:
            raise ProfileError(f"stored plan is malformed: {plan_id}") from error
        if plan.plan_id != plan_id:
            raise ProfileError(f"stored plan id does not match its filename: {plan_id}")
        return plan

    def _load_profile(self, name: str) -> Profile:
        if not _PROFILE_NAME_RE.fullmatch(name):
            raise ProfileError("profile name must use letters, numbers, dot, underscore, or hyphen")
        path = self._profile_root / f"{name}.yaml"
        try:
            raw = load_yaml(path.read_text(encoding="utf-8"))
        except FileNotFoundError as error:
            raise ProfileError(f"profile not found: {name}") from error
        document = _validate_document(raw)
        return Profile(name, path, sha256_text(canonical_document(document)), document)

    def _persist(self, plan: TestPlan) -> None:
        self._plan_root.mkdir(parents=True, exist_ok=True)
        path = self._plan_root / f"{plan.plan_id}.json"
        payload = json.dumps(
            plan.payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        if path.exists():
            existing = path.read_text(encoding="utf-8")
            if existing != payload:
                raise ProfileError(f"plan id collision: {plan.plan_id}")
            return
        path.write_text(payload, encoding="utf-8")


def _validate_document(raw: Any) -> JobDocument:
    try:
        return JOB_DOCUMENT_ADAPTER.validate_python(raw)
    except ValidationError as error:
        raise ProfileError(str(error)) from error


def _parse_override(value: str) -> tuple[tuple[str, ...], Any]:
    if "=" not in value:
        raise ProfileError("override must use path=value")
    raw_path, raw_value = value.split("=", 1)
    path = tuple(raw_path.split("."))
    if not path or any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", part) for part in path):
        raise ProfileError("override path must use dot-separated document field names")
    try:
        parsed = load_yaml(raw_value)
    except Exception as error:
        raise ProfileError(f"invalid override value for {raw_path}: {error}") from error
    return path, copy.deepcopy(parsed)


def _set_path(document: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    current: dict[str, Any] = document
    for part in path[:-1]:
        nested = current.get(part)
        if not isinstance(nested, dict):
            raise ProfileError(f"override path does not exist: {'.'.join(path)}")
        current = nested
    current[path[-1]] = value
