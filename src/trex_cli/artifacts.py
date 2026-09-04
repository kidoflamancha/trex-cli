from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import tempfile
from csv import DictWriter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from trex_cli.async_compat import to_thread
from trex_cli.models import ArtifactRef, JobResult, JobSnapshot, utc_now
from trex_cli.storage import SqliteStore

MEDIA_TYPES = {
    "manifest.json": "application/json",
    "submitted-spec.json": "application/json",
    "resolved-spec.json": "application/json",
    "result.json": "application/json",
    "environment.json": "application/json",
    "report.md": "text/markdown; charset=utf-8",
    "publication.json": "application/json",
    "measurements.csv": "text/csv; charset=utf-8",
    "trials.ndjson": "application/x-ndjson",
    "checksums.sha256": "text/plain; charset=utf-8",
}


class ArtifactStore:
    def __init__(
        self,
        root: Path,
        database: SqliteStore,
        *,
        retention_days: int = 90,
        orphan_grace_period_ms: int = 86_400_000,
    ) -> None:
        self._root = root
        self._database = database
        self._retention_days = retention_days
        self._orphan_grace_period = orphan_grace_period_ms / 1_000
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        await to_thread(self._root.mkdir, parents=True, exist_ok=True)

    async def write(
        self, name: str, content: bytes, media_type: str, *, retain_days: int | None = None
    ) -> ArtifactRef:
        async with self._lock:
            digest_hex = hashlib.sha256(content).hexdigest()
            digest = f"sha256:{digest_hex}"
            path = self._root / digest_hex[:2] / digest_hex
            await to_thread(self._write_atomic, path, content)
            days = self._retention_days if retain_days is None else retain_days
            retain_until = (utc_now() + timedelta(days=days)).isoformat()
            await self._database.record_artifact(
                digest, media_type, len(content), path, retain_until
            )
            return ArtifactRef(digest=digest, mediaType=media_type, size=len(content), name=name)

    @staticmethod
    def _write_atomic(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if hashlib.sha256(path.read_bytes()).digest() != hashlib.sha256(content).digest():
                raise RuntimeError(f"content-addressed Artifact mismatch at {path}")
            return
        descriptor, temporary = tempfile.mkstemp(prefix=".artifact-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    async def build_result_bundle(
        self,
        *,
        snapshot: JobSnapshot,
        submitted_document: dict[str, Any],
        resolved_document: dict[str, Any],
        result: JobResult,
    ) -> list[ArtifactRef]:
        supporting: dict[str, bytes] = {
            "submitted-spec.json": _json_bytes(submitted_document),
            "resolved-spec.json": _json_bytes(resolved_document),
            "environment.json": _json_bytes(
                {
                    "engine": result.provenance.engine,
                    "simulated": result.provenance.simulated,
                    "agentVersion": result.provenance.agent_version,
                    "trexVersion": result.provenance.trex_version,
                    "reportContext": result.summary.get("reportContext"),
                    "testEnvironment": result.summary.get("testEnvironment"),
                }
            ),
            "report.md": _render_report(snapshot, result).encode("utf-8"),
            "publication.json": _json_bytes(
                {
                    "version": 1,
                    "jobId": snapshot.job_id,
                    "status": result.summary.get("publicationStatus", "NOT_ASSESSED"),
                    "conformance": result.summary.get("standardConformance"),
                    "issues": result.summary.get("publicationIssues", []),
                    "standards": [
                        "RFC 1242",
                        "RFC 2544 with Errata 422, 423, and 5203",
                        "RFC 6815",
                        "RFC 9004",
                    ],
                }
            ),
            "measurements.csv": _measurement_csv(result.summary),
        }
        lines = _trial_lines(result.summary)
        if lines:
            supporting["trials.ndjson"] = ("\n".join(lines) + "\n").encode()
        refs: list[ArtifactRef] = []
        for name, content in supporting.items():
            refs.append(await self.write(name, content, MEDIA_TYPES[name]))

        canonical_result = result.model_copy(update={"artifacts": refs})
        result_ref = await self.write(
            "result.json",
            canonical_result.model_dump_json(by_alias=True, indent=2, exclude_none=True).encode(
                "utf-8"
            ),
            MEDIA_TYPES["result.json"],
        )
        refs.append(result_ref)

        checksums = "".join(f"{ref.digest.removeprefix('sha256:')}  {ref.name}\n" for ref in refs)
        checksums_ref = await self.write(
            "checksums.sha256", checksums.encode("utf-8"), MEDIA_TYPES["checksums.sha256"]
        )
        refs.append(checksums_ref)

        manifest = {
            "version": 2,
            "jobId": snapshot.job_id,
            "submittedAt": snapshot.submitted_at.isoformat(),
            "startedAt": snapshot.started_at.isoformat() if snapshot.started_at else None,
            "finishedAt": snapshot.finished_at.isoformat() if snapshot.finished_at else None,
            "simulated": result.provenance.simulated,
            "publicationStatus": result.summary.get("publicationStatus", "NOT_ASSESSED"),
            "standardConformance": result.summary.get("standardConformance"),
            "artifacts": [item.model_dump(by_alias=True) for item in refs],
        }
        manifest_ref = await self.write(
            "manifest.json", _json_bytes(manifest), MEDIA_TYPES["manifest.json"]
        )
        refs.append(manifest_ref)
        return refs

    async def locate(self, digest: str) -> tuple[Path, str, int]:
        return await self._database.artifact_path(digest)

    async def cleanup(
        self,
        *,
        now: datetime | None = None,
        dry_run: bool = True,
        delete_orphans: bool = False,
    ) -> ArtifactCleanupReport:
        effective_now = now or utc_now()
        now_iso = effective_now.isoformat()
        async with self._lock:
            expired = await self._database.expired_artifacts(now_iso)
            registered = await self._database.registered_artifact_paths()
            orphans = await to_thread(self._orphan_files, registered, effective_now.timestamp())
            report = ArtifactCleanupReport(
                dry_run=dry_run,
                expired_records=len(expired),
                orphan_files=len(orphans),
            )
            if dry_run:
                return report
            for digest, path, _declared_size in expired:
                if not self._valid_content_path(path, digest):
                    report.failures.append(f"unsafe registered path: {path}")
                    continue
                try:
                    size = await to_thread(self._file_size, path)
                    await to_thread(path.unlink, missing_ok=True)
                except OSError as error:
                    report.failures.append(f"{path}: {error}")
                    continue
                if await self._database.forget_expired_artifact(digest, now_iso):
                    report.deleted_records += 1
                    if size is None:
                        report.missing_files += 1
                    else:
                        report.reclaimed_bytes += size
            if delete_orphans:
                for path in orphans:
                    try:
                        size = await to_thread(self._required_file_size, path)
                        await to_thread(path.unlink)
                        report.deleted_orphans += 1
                        report.reclaimed_bytes += size
                    except OSError as error:
                        report.failures.append(f"{path}: {error}")
            return report

    @staticmethod
    def _file_size(path: Path) -> int | None:
        try:
            return path.stat().st_size
        except FileNotFoundError:
            return None

    @staticmethod
    def _required_file_size(path: Path) -> int:
        return path.stat().st_size

    def _orphan_files(self, registered: set[Path], now_timestamp: float) -> list[Path]:
        known = {path.resolve() for path in registered}
        cutoff = now_timestamp - self._orphan_grace_period
        result: list[Path] = []
        if not self._root.is_dir():
            return result
        for path in self._root.glob("*/*"):
            if (
                path.is_file()
                and path.resolve() not in known
                and self._valid_content_path(path, f"sha256:{path.name}")
                and path.stat().st_mtime < cutoff
            ):
                result.append(path)
        return sorted(result)

    def _valid_content_path(self, path: Path, digest: str) -> bool:
        digest_hex = digest.removeprefix("sha256:")
        try:
            relative = path.resolve().relative_to(self._root.resolve())
        except ValueError:
            return False
        return (
            len(digest_hex) == 64
            and all(character in "0123456789abcdef" for character in digest_hex)
            and relative.parts == (digest_hex[:2], digest_hex)
        )


@dataclass(slots=True)
class ArtifactCleanupReport:
    dry_run: bool
    expired_records: int = 0
    deleted_records: int = 0
    missing_files: int = 0
    orphan_files: int = 0
    deleted_orphans: int = 0
    reclaimed_bytes: int = 0
    failures: list[str] = field(default_factory=list)

    def payload(self) -> dict[str, Any]:
        return {
            "dryRun": self.dry_run,
            "expiredRecords": self.expired_records,
            "deletedRecords": self.deleted_records,
            "missingFiles": self.missing_files,
            "orphanFiles": self.orphan_files,
            "deletedOrphans": self.deleted_orphans,
            "reclaimedBytes": self.reclaimed_bytes,
            "failures": self.failures,
        }


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _render_report(snapshot: JobSnapshot, result: JobResult) -> str:
    title = "Simulated test result" if result.provenance.simulated else "TRex test result"
    warning = (
        "\n> This result validates control-plane behaviour only. It is not a TRex measurement.\n"
        if result.provenance.simulated
        else ""
    )
    base = (
        f"# {title}: {snapshot.job_id}\n\n"
        f"- Kind: `{snapshot.kind}`\n"
        f"- Verdict: `{result.verdict}`\n"
        f"- Methodology: `{result.methodology}`\n"
        f"- Submitted: `{snapshot.submitted_at.isoformat()}`\n"
        f"- Started: `{snapshot.started_at.isoformat() if snapshot.started_at else 'unknown'}`\n"
        f"- Finished: `{snapshot.finished_at.isoformat() if snapshot.finished_at else 'unknown'}`\n"
        f"- Engine: `{result.provenance.engine}`\n"
        f"- Simulated: `{str(result.provenance.simulated).lower()}`\n"
        f"{warning}"
    )
    publication_status = result.summary.get("publicationStatus")
    if publication_status is not None:
        issues = result.summary.get("publicationIssues")
        issue_lines = (
            "".join(f"- {issue}\n" for issue in issues)
            if isinstance(issues, list) and issues
            else "- None\n"
        )
        base += (
            "\n## Publication assessment\n\n"
            f"- Status: `{publication_status}`\n"
            f"- Conformance: `{result.summary.get('standardConformance')}`\n"
            "- Issues:\n"
            f"{issue_lines}"
        )
    base += _render_report_context(result.summary.get("reportContext"))
    base += _render_test_environment(result.summary.get("testEnvironment"))
    suite_tests = result.summary.get("tests")
    if isinstance(suite_tests, dict):
        sections = []
        for test_name, test_result in suite_tests.items():
            if isinstance(test_result, dict):
                sections.append(_render_method_report(str(test_name), test_result))
        return base + "".join(sections)
    return base + _render_method_report("throughput", result.summary)


def _render_report_context(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    dut = value.get("dut")
    if not isinstance(dut, dict):
        return ""
    modifiers = value.get("modifiers")
    rendered_modifiers = (
        ", ".join(str(item) for item in modifiers)
        if isinstance(modifiers, list) and modifiers
        else "None"
    )
    return (
        "\n## DUT and laboratory context\n\n"
        f"- DUT: `{dut.get('name')}`\n"
        f"- Hardware: `{dut.get('hardware')}`\n"
        f"- Software: `{dut.get('softwareVersion')}`\n"
        f"- Configuration digest: `{dut.get('configurationDigest')}`\n"
        f"- Configuration artifact: `{dut.get('configurationArtifact')}`\n"
        f"- Topology: {value.get('topology')}\n"
        f"- Medium: {value.get('medium')}\n"
        f"- Protocol: {value.get('protocol')}\n"
        f"- Stream type: {value.get('streamType')}\n"
        f"- Isolation: {value.get('isolationStatement')}\n"
        f"- Modifiers: {rendered_modifiers}\n"
    )


def _render_test_environment(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    ports = value.get("ports")
    if not isinstance(ports, dict):
        return ""
    rows = [
        "\n## TRex environment\n",
        f"- TRex version: `{value.get('trexVersion')}`\n",
        "| Port | Line rate bps | NIC | Driver | IEEE 1588 |",
        "| ---: | ---: | --- | --- | --- |",
    ]
    for port_id, port in ports.items():
        if isinstance(port, dict):
            rows.append(
                f"| {port_id} | {port.get('lineRateBps')} | "
                f"{port.get('description')} | {port.get('driver')} | "
                f"{port.get('ieee1588')} |"
            )
    return "\n".join(rows) + "\n"


def _render_method_report(name: str, summary: dict[str, Any]) -> str:
    if name == "frame-loss":
        frames = summary.get("frames")
        if not isinstance(frames, dict):
            return "\n## Frame loss\n\nNo directly comparable combined curve.\n"
        rows = [
            "\n## Frame loss\n",
            "| Frame size | Offered % L1 | Loss % | Lost frames |",
            "| ---: | ---: | ---: | ---: |",
        ]
        for frame_size, values in frames.items():
            if not isinstance(values, dict) or not isinstance(values.get("points"), list):
                continue
            for point in values["points"]:
                if isinstance(point, dict):
                    rows.append(
                        f"| {frame_size} | {point.get('ratePercentL1')} | "
                        f"{point.get('lossPercent')} | {point.get('lossFrames')} |"
                    )
        return "\n".join(rows) + "\n"

    if name == "latency":
        rows = [
            "\n## Latency\n",
            f"RFC 1242 definition: `{summary.get('definition')}`\n",
            "| Frame size | Destination scenario | Average microseconds |",
            "| ---: | --- | ---: |",
        ]
        frames = summary.get("frames")
        if isinstance(frames, dict):
            for frame_size, frame in frames.items():
                if not isinstance(frame, dict):
                    continue
                for scenario_name in ("same-destination", "new-destination"):
                    scenario = frame.get(scenario_name)
                    if isinstance(scenario, dict):
                        rows.append(
                            f"| {frame_size} | {scenario_name} | "
                            f"{scenario.get('averageMicroseconds')} |"
                        )
        return "\n".join(rows) + "\n"

    if name == "back-to-back":
        rows = [
            "\n## Back-to-Back (RFC 9004)\n",
            "| Frame size | Average frames | Min | Max | Stddev | Corrected buffer s |",
            "| ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
        frames = summary.get("frames")
        if isinstance(frames, dict):
            for frame_size, frame in frames.items():
                if not isinstance(frame, dict):
                    continue
                if frame.get("applicability"):
                    rows.append(
                        f"| {frame_size} | N/A | N/A | N/A | N/A | {frame.get('applicability')} |"
                    )
                    continue
                rows.append(
                    f"| {frame_size} | {frame.get('averageFrames')} | "
                    f"{frame.get('minimumFrames')} | {frame.get('maximumFrames')} | "
                    f"{frame.get('standardDeviationFrames')} | "
                    f"{frame.get('correctedBufferSeconds')} |"
                )
        return "\n".join(rows) + "\n"

    rates = summary.get("rates")
    if not isinstance(rates, dict):
        return ""
    rows = ["\n## Throughput\n", "| Frame size | % L1 | fps |", "| ---: | ---: | ---: |"]
    for frame_size, values in rates.items():
        if isinstance(values, dict):
            rows.append(f"| {frame_size} | {values.get('percentL1')} | {values.get('fps')} |")
    if summary.get("standardConformance") == "engineering-estimate-not-rfc2544":
        rows.extend(
            [
                "",
                "> This is an engineering throughput estimate, not a complete RFC2544 result.",
            ]
        )
    return "\n".join(rows) + "\n"


def _trial_lines(summary: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    trials = summary.get("trials")
    if isinstance(trials, dict):
        for frame_size, frame_trials in trials.items():
            if isinstance(frame_trials, list):
                for trial in frame_trials:
                    if isinstance(trial, dict):
                        lines.append(
                            json.dumps(
                                {"test": "throughput", "frameSize": int(frame_size), **trial},
                                sort_keys=True,
                                separators=(",", ":"),
                            )
                        )
    frames = summary.get("frames")
    if isinstance(frames, dict):
        for frame_size, frame_result in frames.items():
            if not isinstance(frame_result, dict):
                continue
            points = frame_result.get("points")
            if isinstance(points, list):
                for point in points:
                    if isinstance(point, dict):
                        lines.append(
                            json.dumps(
                                {"test": "frame-loss", "frameSize": int(frame_size), **point},
                                sort_keys=True,
                                separators=(",", ":"),
                            )
                        )
    tests = summary.get("tests")
    if isinstance(tests, dict):
        for test_name, test_summary in tests.items():
            if isinstance(test_summary, dict):
                if test_name == "latency":
                    lines.extend(_latency_trial_lines(test_summary))
                elif test_name == "back-to-back":
                    lines.extend(_back_to_back_trial_lines(test_summary))
                else:
                    lines.extend(_trial_lines(test_summary))
    return lines


def _measurement_csv(summary: dict[str, Any]) -> bytes:
    fields = [
        "method",
        "frameSize",
        "scenario",
        "percentL1",
        "fps",
        "averageLatencyMicroseconds",
        "offeredPercentL1",
        "lossPercent",
        "averageBurstFrames",
        "minimumBurstFrames",
        "maximumBurstFrames",
        "standardDeviationFrames",
        "correctedBufferSeconds",
    ]
    output = io.StringIO(newline="")
    writer = DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    tests = summary.get("tests")
    if not isinstance(tests, dict):
        tests = {"throughput": summary}
    for method, method_summary in tests.items():
        if not isinstance(method_summary, dict):
            continue
        if method == "throughput":
            rates = method_summary.get("rates")
            if not isinstance(rates, dict):
                continue
            for frame_size, rate in rates.items():
                if isinstance(rate, dict):
                    writer.writerow(
                        {
                            "method": method,
                            "frameSize": frame_size,
                            "percentL1": rate.get("percentL1"),
                            "fps": rate.get("fps"),
                        }
                    )
        elif method == "latency":
            frames = method_summary.get("frames")
            if not isinstance(frames, dict):
                continue
            for frame_size, frame in frames.items():
                if not isinstance(frame, dict):
                    continue
                for scenario_name, scenario in frame.items():
                    if isinstance(scenario, dict):
                        writer.writerow(
                            {
                                "method": method,
                                "frameSize": frame_size,
                                "scenario": scenario_name,
                                "averageLatencyMicroseconds": scenario.get("averageMicroseconds"),
                            }
                        )
        elif method == "frame-loss":
            frames = method_summary.get("frames")
            if not isinstance(frames, dict):
                continue
            for frame_size, frame in frames.items():
                points = frame.get("points") if isinstance(frame, dict) else None
                if not isinstance(points, list):
                    continue
                for point in points:
                    if isinstance(point, dict):
                        writer.writerow(
                            {
                                "method": method,
                                "frameSize": frame_size,
                                "offeredPercentL1": point.get("ratePercentL1"),
                                "lossPercent": point.get("lossPercent"),
                            }
                        )
        elif method == "back-to-back":
            frames = method_summary.get("frames")
            if not isinstance(frames, dict):
                continue
            for frame_size, frame in frames.items():
                if isinstance(frame, dict):
                    writer.writerow(
                        {
                            "method": method,
                            "frameSize": frame_size,
                            "averageBurstFrames": frame.get("averageFrames"),
                            "minimumBurstFrames": frame.get("minimumFrames"),
                            "maximumBurstFrames": frame.get("maximumFrames"),
                            "standardDeviationFrames": frame.get("standardDeviationFrames"),
                            "correctedBufferSeconds": frame.get("correctedBufferSeconds"),
                        }
                    )
    return output.getvalue().encode("utf-8")


def _latency_trial_lines(summary: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    frames = summary.get("frames")
    if not isinstance(frames, dict):
        return lines
    for frame_size, frame in frames.items():
        if not isinstance(frame, dict):
            continue
        for scenario_name, scenario in frame.items():
            trials = scenario.get("trials") if isinstance(scenario, dict) else None
            if not isinstance(trials, list):
                continue
            for trial in trials:
                if isinstance(trial, dict):
                    lines.append(
                        json.dumps(
                            {
                                "test": "latency",
                                "frameSize": int(frame_size),
                                "scenario": scenario_name,
                                **trial,
                            },
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                    )
    return lines


def _back_to_back_trial_lines(summary: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    frames = summary.get("frames")
    if not isinstance(frames, dict):
        return lines
    for frame_size, frame in frames.items():
        searches = frame.get("searches") if isinstance(frame, dict) else None
        if not isinstance(searches, list):
            continue
        for search in searches:
            if isinstance(search, dict):
                lines.append(
                    json.dumps(
                        {"test": "back-to-back", "frameSize": int(frame_size), **search},
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
    return lines
